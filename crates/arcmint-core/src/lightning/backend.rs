use crate::lightning::error::LightningError;
use crate::lightning::types::{
    ChannelBalance, InvoiceSettledEvent, InvoiceStatus, LnInvoice, LnPayment,
};
use futures::Stream;
use std::pin::Pin;

#[async_trait::async_trait]
pub trait LightningBackend: Send + Sync + 'static {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        memo: &str,
        expiry_secs: u64,
    ) -> Result<LnInvoice, LightningError>;

    async fn pay_invoice(
        &self,
        payment_request: &str,
        max_fee_msat: u64,
    ) -> Result<LnPayment, LightningError>;

    async fn lookup_invoice(
        &self,
        payment_hash: &[u8; 32],
    ) -> Result<InvoiceStatus, LightningError>;

    async fn subscribe_invoices(
        &self,
        settle_index: u64,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<InvoiceSettledEvent, LightningError>> + Send>>,
        LightningError,
    >;

    async fn get_channel_balance(&self) -> Result<ChannelBalance, LightningError>;

    async fn check_connectivity(&self) -> Result<(), LightningError>;
}
