//! Future authenticated QUIC protocol contracts.
use linkdrop_core::Transfer;
pub trait TransferProtocol {
    fn prepare(&self, transfer: &Transfer) -> Result<(), ProtocolError>;
}
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("network transfer is not available in Phase 1")]
    Unavailable,
}
