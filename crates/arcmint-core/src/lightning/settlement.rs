use crate::lightning::backend::LightningBackend;
use crate::lightning::error::LightningError;
use crate::lightning::types::InvoiceSettledEvent;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;
use tracing::error;

pub struct SettlementHandler {
    sender: broadcast::Sender<InvoiceSettledEvent>,
}

impl SettlementHandler {
    pub fn new() -> (Self, broadcast::Receiver<InvoiceSettledEvent>) {
        let (sender, receiver) = broadcast::channel(32);
        (SettlementHandler { sender }, receiver)
    }

    pub fn sender(&self) -> broadcast::Sender<InvoiceSettledEvent> {
        self.sender.clone()
    }

    pub async fn run(
        backend: Arc<dyn LightningBackend>,
        sender: broadcast::Sender<InvoiceSettledEvent>,
        start_index: u64,
    ) {
        let mut current_index = start_index;
        loop {
            let stream_result = backend.subscribe_invoices(current_index).await;
            let mut stream = match stream_result {
                Ok(s) => s,
                Err(e) => {
                    error!("settlement stream subscribe error: {e}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut last_index = current_index;

            loop {
                let next = stream.next().await;
                match next {
                    Some(Ok(event)) => {
                        last_index = event.settle_index;
                        let _ = sender.send(event);
                    }
                    Some(Err(e)) => {
                        error!("settlement stream item error: {e}");
                        current_index = last_index.saturating_add(1);
                        break;
                    }
                    None => {
                        current_index = last_index.saturating_add(1);
                        break;
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

pub async fn wait_for_settlement(
    receiver: &mut broadcast::Receiver<InvoiceSettledEvent>,
    payment_hash: &[u8; 32],
    timeout_secs: u64,
) -> Result<InvoiceSettledEvent, LightningError> {
    let duration = Duration::from_secs(timeout_secs);
    let result = timeout(duration, async {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if event.payment_hash == *payment_hash {
                        return Ok(event);
                    }
                }
                Err(e) => {
                    return Err::<InvoiceSettledEvent, LightningError>(
                        LightningError::StreamError(e.to_string()),
                    );
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(event)) => Ok(event),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(LightningError::StreamError(
            "settlement wait timed out".to_string(),
        )),
    }
}
