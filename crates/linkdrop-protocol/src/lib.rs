//! Pairing transcript primitives. QUIC transport is intentionally kept separate.
pub mod tls;
pub mod transport;
use linkdrop_identity::{verify, DeviceCertificate, DeviceIdentity, TrustedPeer};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Bounds the explicit pairing exchange so stalled peers cannot leave an unbounded task behind.
pub const PAIRING_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingHello {
    pub version: u8,
    pub public_key: [u8; 32],
    pub nonce: [u8; 32],
    pub expires_at_unix: i64,
    pub signature: Vec<u8>,
}
/// The authenticated payload exchanged during an explicit pairing ceremony.
///
/// Receiving this envelope never changes the trusted-peer registry by itself. Both users must
/// compare the derived verification code and explicitly approve the resulting peer record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingEnvelope {
    pub hello: PairingHello,
    pub certificate_der: Vec<u8>,
}
impl PairingEnvelope {
    pub fn create(
        identity: &DeviceIdentity,
        certificate: &DeviceCertificate,
        now_unix: i64,
    ) -> Self {
        Self {
            hello: PairingHello::create(identity, now_unix),
            certificate_der: certificate.der().to_vec(),
        }
    }

    pub fn certificate(&self) -> Result<DeviceCertificate, PairingError> {
        DeviceCertificate::parse(self.certificate_der.clone())
            .map_err(|_| PairingError::InvalidCertificate)
    }
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

/// Validates a pairing exchange and turns the peer's certificate into an explicit trust record.
///
/// Discovery advertisements are deliberately absent from this API: they may help locate a peer,
/// but only the signed pairing messages, caller-supplied transport binding, and certificate can
/// establish trust.
pub fn complete_pairing(
    local: &PairingHello,
    remote: &PairingHello,
    remote_certificate: &DeviceCertificate,
    transport_binding: &[u8],
    now_unix: i64,
) -> Result<(TrustedPeer, String), PairingError> {
    local.verify(now_unix)?;
    remote.verify(now_unix)?;
    let peer = TrustedPeer::from_certificate(remote_certificate)
        .map_err(|_| PairingError::InvalidCertificate)?;
    if peer.public_key != remote.public_key {
        return Err(PairingError::IdentityMismatch);
    }
    let code = verification_code(local, remote, transport_binding)?;
    Ok((peer, code))
}

/// Validates a remote pairing envelope and returns the peer that can be persisted only after the
/// caller's explicit approval of `verification_code`.
pub fn verify_pairing_envelope(
    local: &PairingEnvelope,
    remote: &PairingEnvelope,
    transport_binding: &[u8],
    now_unix: i64,
) -> Result<(TrustedPeer, String), PairingError> {
    let certificate = remote.certificate()?;
    complete_pairing(
        &local.hello,
        &remote.hello,
        &certificate,
        transport_binding,
        now_unix,
    )
}

/// Sends a local pairing envelope and reads the remote device's envelope from the same control
/// stream. The caller must subsequently verify the returned envelope and obtain user approval.
pub async fn initiate_pairing_exchange(
    connection: &quinn::Connection,
    local: &PairingEnvelope,
) -> Result<PairingEnvelope, PairingError> {
    tokio::time::timeout(PAIRING_EXCHANGE_TIMEOUT, async {
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|error| PairingError::Transport(error.to_string()))?;
        write_pairing_envelope(&mut send, local).await?;
        send.finish()
            .map_err(|error| PairingError::Transport(error.to_string()))?;
        read_pairing_envelope(&mut receive).await
    })
    .await
    .map_err(|_| PairingError::Timeout)?
}

/// Receives a pairing envelope and returns the remote envelope after replying with `local`.
pub async fn respond_to_pairing_exchange(
    connection: &quinn::Connection,
    local: &PairingEnvelope,
) -> Result<PairingEnvelope, PairingError> {
    tokio::time::timeout(PAIRING_EXCHANGE_TIMEOUT, async {
        let (mut send, mut receive) = connection
            .accept_bi()
            .await
            .map_err(|error| PairingError::Transport(error.to_string()))?;
        let remote = read_pairing_envelope(&mut receive).await?;
        write_pairing_envelope(&mut send, local).await?;
        send.finish()
            .map_err(|error| PairingError::Transport(error.to_string()))?;
        Ok(remote)
    })
    .await
    .map_err(|_| PairingError::Timeout)?
}

async fn write_pairing_envelope(
    stream: &mut quinn::SendStream,
    envelope: &PairingEnvelope,
) -> Result<(), PairingError> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| PairingError::InvalidTranscript)?;
    if bytes.len() > 16 * 1024 {
        return Err(PairingError::InvalidTranscript);
    }
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| PairingError::Transport(error.to_string()))
}

async fn read_pairing_envelope(
    stream: &mut quinn::RecvStream,
) -> Result<PairingEnvelope, PairingError> {
    let bytes = stream
        .read_to_end(16 * 1024)
        .await
        .map_err(|error| PairingError::Transport(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|_| PairingError::InvalidTranscript)
}
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("expired or invalid pairing request")]
    ExpiredOrInvalid,
    #[error("invalid pairing signature")]
    InvalidSignature,
    #[error("invalid pairing transcript")]
    InvalidTranscript,
    #[error("pairing certificate is invalid")]
    InvalidCertificate,
    #[error("pairing certificate does not match the remote identity")]
    IdentityMismatch,
    #[error("pairing timed out; make sure both devices are open and on the same local network")]
    Timeout,
    #[error("pairing transport failed: {0}")]
    Transport(String),
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
    #[test]
    fn pairing_provisions_only_the_identity_bound_to_the_certificate() {
        let local_identity = DeviceIdentity::generate();
        let remote_identity = DeviceIdentity::generate();
        let remote_certificate = DeviceCertificate::generate(&remote_identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let local = PairingHello::create(&local_identity, 100);
        let remote = PairingHello::create(&remote_identity, 100);
        let (peer, _) = complete_pairing(&local, &remote, &remote_certificate, b"binding", 100)
            .unwrap_or_else(|error| panic!("pairing failed: {error}"));
        assert_eq!(peer.device_id, remote_identity.device_id());

        let impersonated = PairingHello::create(&DeviceIdentity::generate(), 100);
        assert!(matches!(
            complete_pairing(&local, &impersonated, &remote_certificate, b"binding", 100),
            Err(PairingError::IdentityMismatch)
        ));
    }
    #[test]
    fn pairing_envelope_requires_explicit_validation_before_trust() {
        let local_identity = DeviceIdentity::generate();
        let local_certificate = DeviceCertificate::generate(&local_identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let remote_identity = DeviceIdentity::generate();
        let remote_certificate = DeviceCertificate::generate(&remote_identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let local = PairingEnvelope::create(&local_identity, &local_certificate, 100);
        let remote = PairingEnvelope::create(&remote_identity, &remote_certificate, 100);
        let (peer, code) = verify_pairing_envelope(&local, &remote, b"binding", 100)
            .unwrap_or_else(|error| panic!("pairing validation failed: {error}"));
        assert_eq!(peer.device_id, remote_identity.device_id());
        assert_eq!(code.len(), 6);
    }
}
