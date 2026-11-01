//! Shared typed domain models for Linkdrop.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub display_name: String,
    pub operating_system: String,
    pub discovery_status: DiscoveryStatus,
    pub trust_status: TrustStatus,
    pub transport_address: Option<String>,
    pub transport_port: u16,
    pub pairing_port: u16,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryStatus {
    Offline,
    Discoverable,
    Found,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    Unknown,
    Trusted,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    pub id: String,
    pub sender_device_id: String,
    pub receiver_device_id: String,
    pub filename: String,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub status: TransferStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Pending,
    AwaitingApproval,
    Connecting,
    Transferring,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_status_serializes_as_contract() {
        let json = serde_json::to_string(&TransferStatus::AwaitingApproval).unwrap_or_default();
        assert_eq!(json, "\"awaiting_approval\"");
    }
}
