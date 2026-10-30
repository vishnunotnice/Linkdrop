//! Storage interfaces; desktop persists settings through Tauri's store plugin.
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub display_name: String,
    pub discoverable: bool,
    pub download_directory: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            display_name: "My Linkdrop".into(),
            discoverable: true,
            download_directory: None,
        }
    }
}
pub trait SettingsStore {
    fn read(&self) -> Result<Settings, StorageError>;
    fn write(&self, settings: &Settings) -> Result<(), StorageError>;
}
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage unavailable: {0}")]
    Unavailable(String),
}
