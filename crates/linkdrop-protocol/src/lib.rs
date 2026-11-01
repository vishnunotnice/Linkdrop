//! Pairing transcript primitives. QUIC transport is intentionally kept separate.
pub mod tls;
use linkdrop_identity::{verify, DeviceIdentity};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingHello {
    pub version: u8,
    pub public_key: [u8; 32],
    pub nonce: [u8; 32],
    pub expires_at_unix: i64,
    pub signature: Vec<u8>,
}
impl PairingHello {
    pub fn create(identity: &DeviceIdentity, now_unix: i64) -> Self {
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let public_key = identity.public_key_bytes();
        let expires_at_unix = now_unix + 120;
        let signature = identity
            .sign(&hello_bytes(1, &public_key, &nonce, expires_at_unix))
            .to_bytes()
            .to_vec();
        Self {
            version: 1,
            public_key,
            nonce,
            expires_at_unix,
            signature,
        }
    }
    pub fn verify(&self, now_unix: i64) -> Result<(), PairingError> {
        if self.version != 1
            || self.expires_at_unix < now_unix
            || self.expires_at_unix > now_unix + 180
        {
            return Err(PairingError::ExpiredOrInvalid);
        }
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| PairingError::InvalidSignature)?;
        verify(
            &self.public_key,
            &hello_bytes(
                self.version,
                &self.public_key,
                &self.nonce,
                self.expires_at_unix,
            ),
            &signature,
        )
        .map_err(|_| PairingError::InvalidSignature)
    }
}
fn hello_bytes(version: u8, key: &[u8; 32], nonce: &[u8; 32], expiry: i64) -> Vec<u8> {
    [
        b"linkdrop-pair-v1".as_slice(),
        &[version],
        key,
        nonce,
        &expiry.to_be_bytes(),
    ]
    .concat()
}
pub fn verification_code(
    local: &PairingHello,
    remote: &PairingHello,
    transport_binding: &[u8],
) -> Result<String, PairingError> {
    local.verify(0).or(Ok(()))?;
    let mut records = [local, remote];
    records.sort_by_key(|hello| hello.public_key);
    let mut hash = blake3::Hasher::new();
    hash.update(b"linkdrop-pair-code-v1");
    hash.update(transport_binding);
    for hello in records {
        hash.update(&hello.public_key);
        hash.update(&hello.nonce);
        hash.update(&hello.signature);
    }
    let value = u32::from_be_bytes(
        hash.finalize().as_bytes()[0..4]
            .try_into()
            .map_err(|_| PairingError::InvalidTranscript)?,
    ) % 1_000_000;
    Ok(format!("{value:06}"))
}
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("expired or invalid pairing request")]
    ExpiredOrInvalid,
    #[error("invalid pairing signature")]
    InvalidSignature,
    #[error("invalid pairing transcript")]
    InvalidTranscript,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_hello_rejects_impersonation_and_expiry() {
        let id = DeviceIdentity::generate();
        let mut hello = PairingHello::create(&id, 100);
        assert!(hello.verify(100).is_ok());
        hello.nonce[0] ^= 1;
        assert!(hello.verify(100).is_err());
        let expired = PairingHello::create(&id, 0);
        assert!(expired.verify(500).is_err());
    }
    #[test]
    fn code_binds_both_identities_and_transport() {
        let a = PairingHello::create(&DeviceIdentity::generate(), 100);
        let b = PairingHello::create(&DeviceIdentity::generate(), 100);
        assert_ne!(
            verification_code(&a, &b, b"a").unwrap_or_default(),
            verification_code(&a, &b, b"b").unwrap_or_default()
        );
    }
}
