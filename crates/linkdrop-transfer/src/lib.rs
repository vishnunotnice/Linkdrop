//! Transfer state-machine boundary; no file I/O in Phase 1.
use linkdrop_core::TransferStatus;
#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error("invalid transfer transition from {from:?} to {to:?}")]
    Invalid {
        from: TransferStatus,
        to: TransferStatus,
    },
}
pub fn can_transition(from: TransferStatus, to: TransferStatus) -> bool {
    matches!(
        (from, to),
        (TransferStatus::Pending, TransferStatus::AwaitingApproval)
            | (TransferStatus::AwaitingApproval, TransferStatus::Connecting)
            | (TransferStatus::Connecting, TransferStatus::Transferring)
            | (TransferStatus::Transferring, TransferStatus::Completed)
            | (_, TransferStatus::Cancelled)
            | (_, TransferStatus::Failed)
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permits_cancel() {
        assert!(can_transition(
            TransferStatus::Paused,
            TransferStatus::Cancelled
        ));
    }
}
