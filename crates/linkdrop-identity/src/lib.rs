//! Device identity generation and stable public identifiers.
//! Platform secret storage is performed by the desktop adapter in Phase 1.
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity bytes are invalid")]
    InvalidBytes,
}

pub struct DeviceIdentity {
    signing_key: SigningKey,
}
impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    pub fn device_id(&self) -> String {
        device_id_for(&self.public_key())
    }
}
pub fn device_id_for(public_key: &VerifyingKey) -> String {
    blake3::hash(public_key.as_bytes()).to_hex()[..24].to_string()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn id_survives_rehydration() {
        let identity = DeviceIdentity::generate();
        let restored = DeviceIdentity::from_bytes(&identity.secret_bytes());
        assert_eq!(identity.device_id(), restored.device_id());
    }
}
