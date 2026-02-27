use arcmint_core::lightning::backend::LightningBackend;
use arcmint_core::lightning::error::LightningError;
use arcmint_core::lightning::types::{
    ChannelBalance, InvoiceSettledEvent, InvoiceStatus, LnInvoice, LnPayment, PaymentStatus,
};
use futures::StreamExt;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codegen::http::Uri;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

pub mod lnrpc {
    tonic::include_proto!("lnrpc");
}

pub mod routerrpc {
    tonic::include_proto!("routerrpc");
}

use lnrpc::lightning_client::LightningClient;
use lnrpc::{
    AddInvoiceRequest, AddInvoiceResponse, ChannelBalanceRequest, ChannelBalanceResponse,
    GetInfoRequest, Invoice as LndInvoice, InvoiceState, InvoiceSubscription, LookupInvoiceRequest,
};
use routerrpc::router_client::RouterClient;
use routerrpc::{
    Payment as RouterPayment, PaymentStatus as RouterPaymentStatus, SendPaymentRequest,
};

#[derive(Clone, Debug)]
pub struct LndConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert_path: PathBuf,
    pub macaroon_path: PathBuf,
}

pub struct LndBackend {
    lightning_client: Arc<Mutex<LightningClient<Channel>>>,
    router_client: Arc<Mutex<RouterClient<Channel>>>,
    macaroon: AsciiMetadataValue,
}

impl LndBackend {
    pub async fn connect(config: LndConfig) -> Result<Self, LightningError> {
        let tls_bytes = fs::read(&config.tls_cert_path)
            .await
            .map_err(|e| LightningError::NodeUnavailable(e.to_string()))?;
        let ca_certificate = Certificate::from_pem(tls_bytes);
        let tls_config = ClientTlsConfig::new()
            .ca_certificate(ca_certificate)
            .domain_name(config.host.clone());

        let endpoint_uri = format!("https://{}:{}", config.host, config.port)
            .parse::<Uri>()
            .map_err(|e| LightningError::NodeUnavailable(e.to_string()))?;

        let endpoint = Endpoint::from(endpoint_uri)
            .tls_config(tls_config)
            .map_err(|e| LightningError::NodeUnavailable(e.to_string()))?;

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| LightningError::NodeUnavailable(e.to_string()))?;

        let macaroon_bytes = fs::read(&config.macaroon_path)
            .await
            .map_err(|e| LightningError::AuthError(e.to_string()))?;
        let macaroon_hex = hex::encode(macaroon_bytes);
        let macaroon = AsciiMetadataValue::from_str(&macaroon_hex)
            .map_err(|e| LightningError::AuthError(e.to_string()))?;

        let lightning_client = LightningClient::new(channel.clone());
        let router_client = RouterClient::new(channel);

        let backend = LndBackend {
            lightning_client: Arc::new(Mutex::new(lightning_client)),
            router_client: Arc::new(Mutex::new(router_client)),
            macaroon,
        };

        backend.check_connectivity().await?;

        Ok(backend)
    }

    fn map_status_for_invoice(err: Status) -> LightningError {
        match err.code() {
            tonic::Code::Unauthenticated => LightningError::AuthError(err.to_string()),
            tonic::Code::Unavailable => LightningError::NodeUnavailable(err.to_string()),
            _ => LightningError::InvoiceCreationFailed(err.to_string()),
        }
    }

    fn map_status_for_payment(err: Status) -> LightningError {
        match err.code() {
            tonic::Code::Unauthenticated => LightningError::AuthError(err.to_string()),
            tonic::Code::Unavailable => LightningError::NodeUnavailable(err.to_string()),
            _ => LightningError::PaymentFailed(err.to_string()),
        }
    }

    fn map_status_for_stream(err: Status) -> LightningError {
        match err.code() {
            tonic::Code::Unauthenticated => LightningError::AuthError(err.to_string()),
            tonic::Code::Unavailable => LightningError::NodeUnavailable(err.to_string()),
            _ => LightningError::StreamError(err.to_string()),
        }
    }

    fn map_status_generic(err: Status) -> LightningError {
        match err.code() {
            tonic::Code::Unauthenticated => LightningError::AuthError(err.to_string()),
            tonic::Code::Unavailable => LightningError::NodeUnavailable(err.to_string()),
            _ => LightningError::NodeUnavailable(err.to_string()),
        }
    }

    fn map_invoice_state(invoice: &LndInvoice) -> InvoiceStatus {
        let state = InvoiceState::try_from(invoice.state).unwrap_or(InvoiceState::Open);
        match state {
            InvoiceState::Open => InvoiceStatus::Open,
            InvoiceState::Settled => {
                let mut preimage = [0u8; 32];
                let src = invoice.r_preimage.as_slice();
                if src.len() == 32 {
                    preimage.copy_from_slice(src);
                }
                InvoiceStatus::Settled { preimage }
            }
            InvoiceState::Canceled => InvoiceStatus::Cancelled,
            InvoiceState::Accepted => InvoiceStatus::Accepted,
        }
    }

    fn map_router_status(status: i32) -> PaymentStatus {
        let state = RouterPaymentStatus::try_from(status).unwrap_or(RouterPaymentStatus::Unknown);
        match state {
            RouterPaymentStatus::InFlight => PaymentStatus::InFlight,
            RouterPaymentStatus::Succeeded => PaymentStatus::Succeeded,
            RouterPaymentStatus::Failed => PaymentStatus::Failed("payment failed".to_string()),
            _ => PaymentStatus::Failed("unknown payment status".to_string()),
        }
    }
}

#[async_trait::async_trait]
impl LightningBackend for LndBackend {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        memo: &str,
        expiry_secs: u64,
    ) -> Result<LnInvoice, LightningError> {
        let request = AddInvoiceRequest {
            memo: memo.to_string(),
            value_msat: amount_msat as i64,
            expiry: expiry_secs as i64,
        };

        let mut client = self.lightning_client.lock().await;
        let mut req = Request::new(request);
        req.metadata_mut().insert("macaroon", self.macaroon.clone());

        let response: AddInvoiceResponse = client
            .add_invoice(req)
            .await
            .map_err(Self::map_status_for_invoice)?
            .into_inner();

        let mut payment_hash = [0u8; 32];
        let src = response.r_hash.as_slice();
        if src.len() == 32 {
            payment_hash.copy_from_slice(src);
        }

        Ok(LnInvoice {
            payment_hash,
            payment_request: response.payment_request,
            add_index: response.add_index,
            expiry_secs,
        })
    }

    async fn pay_invoice(
        &self,
        payment_request: &str,
        max_fee_msat: u64,
    ) -> Result<LnPayment, LightningError> {
        let request = SendPaymentRequest {
            payment_request: payment_request.to_string(),
            timeout_seconds: 60,
            fee_limit_msat: max_fee_msat as i64,
        };

        let mut client = self.router_client.lock().await;
        let mut req = Request::new(request);
        req.metadata_mut().insert("macaroon", self.macaroon.clone());

        let mut stream = client
            .send_payment_v2(req)
            .await
            .map_err(Self::map_status_for_payment)?
            .into_inner();

        let mut last_payment: Option<RouterPayment> = None;

        while let Some(item) = stream.next().await {
            let payment = item.map_err(Self::map_status_for_payment)?;
            last_payment = Some(payment.clone());
            let state = RouterPaymentStatus::try_from(payment.status)
                .unwrap_or(RouterPaymentStatus::Unknown);
            match state {
                RouterPaymentStatus::InFlight => {}
                RouterPaymentStatus::Succeeded | RouterPaymentStatus::Failed => {
                    break;
                }
                _ => {}
            }
        }

        let payment = last_payment.ok_or_else(|| {
            LightningError::PaymentFailed("no payment response received".to_string())
        })?;

        let mut payment_hash = [0u8; 32];
        let hash_src = payment.payment_hash.as_slice();
        if hash_src.len() == 32 {
            payment_hash.copy_from_slice(hash_src);
        }

        let mut payment_preimage = [0u8; 32];
        let preimage_src = payment.payment_preimage.as_slice();
        if preimage_src.len() == 32 {
            payment_preimage.copy_from_slice(preimage_src);
        }

        let status = Self::map_router_status(payment.status);

        if let PaymentStatus::Failed(ref reason) = status {
            return Err(LightningError::PaymentFailed(reason.clone()));
        }

        Ok(LnPayment {
            payment_hash,
            payment_preimage,
            fee_msat: payment.fee_msat as u64,
            status,
        })
    }

    async fn lookup_invoice(
        &self,
        payment_hash: &[u8; 32],
    ) -> Result<InvoiceStatus, LightningError> {
        let request = LookupInvoiceRequest {
            r_hash: payment_hash.to_vec(),
        };

        let mut client = self.lightning_client.lock().await;
        let mut req = Request::new(request);
        req.metadata_mut().insert("macaroon", self.macaroon.clone());

        let invoice = client
            .lookup_invoice(req)
            .await
            .map_err(Self::map_status_generic)?
            .into_inner();

        Ok(Self::map_invoice_state(&invoice))
    }

    async fn subscribe_invoices(
        &self,
        settle_index: u64,
    ) -> Result<
        Pin<Box<dyn futures::Stream<Item = Result<InvoiceSettledEvent, LightningError>> + Send>>,
        LightningError,
    > {
        let request = InvoiceSubscription { settle_index };

        let mut client = self.lightning_client.lock().await;
        let mut req = Request::new(request);
        req.metadata_mut().insert("macaroon", self.macaroon.clone());

        let mut stream = client
            .subscribe_invoices(req)
            .await
            .map_err(Self::map_status_for_stream)?
            .into_inner();

        let (tx, rx) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            while let Some(item) = stream.next().await {
                let result = match item {
                    Ok(invoice) => {
                        let state =
                            InvoiceState::try_from(invoice.state).unwrap_or(InvoiceState::Open);
                        if state != InvoiceState::Settled {
                            continue;
                        }
                        let mut payment_hash = [0u8; 32];
                        let hash_src = invoice.r_hash.as_slice();
                        if hash_src.len() == 32 {
                            payment_hash.copy_from_slice(hash_src);
                        }
                        let mut preimage = [0u8; 32];
                        let preimage_src = invoice.r_preimage.as_slice();
                        if preimage_src.len() == 32 {
                            preimage.copy_from_slice(preimage_src);
                        }
                        Ok(InvoiceSettledEvent {
                            payment_hash,
                            amount_msat: invoice.value_msat as u64,
                            settle_index: invoice.settle_index,
                            preimage,
                        })
                    }
                    Err(status) => Err(Self::map_status_for_stream(status)),
                };

                if tx.send(result).await.is_err() {
                    break;
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    async fn get_channel_balance(&self) -> Result<ChannelBalance, LightningError> {
        let request = ChannelBalanceRequest {};

        let mut client = self.lightning_client.lock().await;
        let mut req = Request::new(request);
        req.metadata_mut().insert("macaroon", self.macaroon.clone());

        let response: ChannelBalanceResponse = client
            .channel_balance(req)
            .await
            .map_err(Self::map_status_generic)?
            .into_inner();

        Ok(ChannelBalance {
            local_msat: response.local_balance_msat as u64,
            remote_msat: response.remote_balance_msat as u64,
            pending_open_local_msat: response.pending_open_local_msat as u64,
            pending_open_remote_msat: response.pending_open_remote_msat as u64,
        })
    }

    async fn check_connectivity(&self) -> Result<(), LightningError> {
        let request = GetInfoRequest {};

        let mut client = self.lightning_client.lock().await;
        let mut req = Request::new(request);
        req.metadata_mut().insert("macaroon", self.macaroon.clone());

        client
            .get_info(req)
            .await
            .map_err(Self::map_status_generic)?;

        Ok(())
    }
}
