//! Storage interfaces; desktop persists settings through Tauri's store plugin.
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use linkdrop_identity::TrustedPeerRegistry;
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

/// Persistence boundary for the explicit trusted-peer allow-list.
pub trait TrustedPeerStore {
    fn read_peers(&self) -> Result<TrustedPeerRegistry, StorageError>;
    fn write_peers(&self, peers: &TrustedPeerRegistry) -> Result<(), StorageError>;
}

/// A small JSON-backed peer store suitable for the desktop adapter.
///
/// Certificate private keys are never written here: the registry stores only pinned public
/// identity and certificate-fingerprint data.
pub struct JsonTrustedPeerStore {
    path: PathBuf,
}

impl JsonTrustedPeerStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TrustedPeerStore for JsonTrustedPeerStore {
    fn read_peers(&self) -> Result<TrustedPeerRegistry, StorageError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                StorageError::Unavailable(format!("invalid peer registry: {error}"))
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Ok(TrustedPeerRegistry::default())
            }
            Err(error) => Err(StorageError::Unavailable(error.to_string())),
        }
    }

    fn write_peers(&self, peers: &TrustedPeerRegistry) -> Result<(), StorageError> {
        let parent = self.path.parent().ok_or_else(|| {
            StorageError::Unavailable("peer registry path has no parent directory".to_owned())
        })?;
        fs::create_dir_all(parent).map_err(|error| StorageError::Unavailable(error.to_string()))?;
        let contents = serde_json::to_vec_pretty(peers)
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, contents)
            .map_err(|error| StorageError::Unavailable(error.to_string()))?;
        fs::rename(temporary, &self.path)
            .map_err(|error| StorageError::Unavailable(error.to_string()))
    }
}
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage unavailable: {0}")]
    Unavailable(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use linkdrop_identity::{DeviceCertificate, DeviceIdentity, TrustedPeer};

    #[test]
    fn trusted_peer_registry_round_trips_without_private_material() {
        let identity = DeviceIdentity::generate();
        let certificate = DeviceCertificate::generate(&identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let peer = TrustedPeer::provision(&identity, &certificate);
        let path = std::env::temp_dir().join(format!("linkdrop-peers-{}.json", peer.device_id));
        let store = JsonTrustedPeerStore::new(&path);
        let mut peers = TrustedPeerRegistry::default();
        peers.insert(peer.clone());
        store
            .write_peers(&peers)
            .unwrap_or_else(|error| panic!("peer registry write failed: {error}"));
        let restored = store
            .read_peers()
            .unwrap_or_else(|error| panic!("peer registry read failed: {error}"));
        assert_eq!(
            restored
                .get(&peer.device_id)
                .map(|stored| &stored.public_key),
            Some(&peer.public_key)
        );
        let _ = fs::remove_file(path);
    }
}
