use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LnInvoice {
    pub payment_hash: [u8; 32],
    pub payment_request: String,
    pub add_index: u64,
    pub expiry_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LnPayment {
    pub payment_hash: [u8; 32],
    pub payment_preimage: [u8; 32],
    pub fee_msat: u64,
    pub status: PaymentStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaymentStatus {
    InFlight,
    Succeeded,
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InvoiceStatus {
    Open,
    Settled { preimage: [u8; 32] },
    Cancelled,
    Accepted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelBalance {
    pub local_msat: u64,
    pub remote_msat: u64,
    pub pending_open_local_msat: u64,
    pub pending_open_remote_msat: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvoiceSettledEvent {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub settle_index: u64,
    pub preimage: [u8; 32],
}
