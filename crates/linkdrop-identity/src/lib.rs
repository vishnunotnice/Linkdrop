//! Device identity generation and stable public identifiers.
//! Platform secret storage is performed by the desktop adapter in Phase 1.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ED25519};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{collections::BTreeMap, fs, io, path::Path};
use x509_parser::{extensions::ParsedExtension, prelude::parse_x509_certificate};

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity bytes are invalid")]
    InvalidBytes,
}

#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("certificate encoding failed: {0}")]
    Encoding(String),
    #[error("certificate is malformed")]
    Malformed,
    #[error("certificate public key does not match device identity")]
    IdentityMismatch,
    #[error("certificate storage failed: {0}")]
    Storage(#[from] io::Error),
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
    /// RFC 8410 PKCS#8: OneAsymmetricKey wrapping the 32-byte Ed25519 seed.
    pub fn pkcs8_der(&self) -> Vec<u8> {
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&self.secret_bytes());
        der
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key().to_bytes()
    }
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
    pub fn device_id(&self) -> String {
        device_id_for(&self.public_key())
    }
}

#[derive(Clone, Debug)]
pub struct DeviceCertificate {
    der: Vec<u8>,
    fingerprint: String,
}
pub struct TlsKeyMaterial {
    pub certificate_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}
impl TlsKeyMaterial {
    pub fn from_identity(
        identity: &DeviceIdentity,
        certificate: &DeviceCertificate,
    ) -> Result<Self, CertificateError> {
        certificate.matches(identity)?;
        let pkcs8 = identity.pkcs8_der();
        if pkcs8.len() != 48 {
            return Err(CertificateError::Malformed);
        }
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));
        Ok(Self {
            certificate_chain: vec![CertificateDer::from(certificate.der().to_vec())],
            private_key: key,
        })
    }
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum TrustedPeerStatus {
    Trusted,
    Blocked,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TrustedPeer {
    pub device_id: String,
    pub public_key: [u8; 32],
    pub certificate_fingerprint: String,
    pub status: TrustedPeerStatus,
}

/// The persisted allow-list used for mutual TLS authentication.
///
/// Discovery records never add entries here: a peer becomes trusted only after a successful
/// pairing flow explicitly provisions its certificate and public key.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct TrustedPeerRegistry {
    peers: BTreeMap<String, TrustedPeer>,
}

impl TrustedPeerRegistry {
    pub fn insert(&mut self, peer: TrustedPeer) {
        self.peers.insert(peer.device_id.clone(), peer);
    }

    pub fn get(&self, device_id: &str) -> Option<&TrustedPeer> {
        self.peers.get(device_id)
    }

    pub fn trusted_peers(&self) -> Vec<TrustedPeer> {
        self.peers
            .values()
            .filter(|peer| peer.status == TrustedPeerStatus::Trusted)
            .cloned()
            .collect()
    }

    pub fn peers(&self) -> Vec<TrustedPeer> {
        self.peers.values().cloned().collect()
    }

    pub fn block(&mut self, device_id: &str) -> bool {
        let Some(peer) = self.peers.get_mut(device_id) else {
            return false;
        };
        peer.status = TrustedPeerStatus::Blocked;
        true
    }

    pub fn trust(&mut self, device_id: &str) -> bool {
        let Some(peer) = self.peers.get_mut(device_id) else {
            return false;
        };
        peer.status = TrustedPeerStatus::Trusted;
        true
    }
}

impl TrustedPeer {
    pub fn provision(identity: &DeviceIdentity, certificate: &DeviceCertificate) -> Self {
        Self {
            device_id: identity.device_id(),
            public_key: identity.public_key_bytes(),
            certificate_fingerprint: certificate.fingerprint().to_owned(),
            status: TrustedPeerStatus::Trusted,
        }
    }
    /// Creates a trusted peer from a certificate received during an authenticated pairing flow.
    pub fn from_certificate(certificate: &DeviceCertificate) -> Result<Self, CertificateError> {
        let (_, parsed) =
            parse_x509_certificate(certificate.der()).map_err(|_| CertificateError::Malformed)?;
        let public_key: [u8; 32] = parsed
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref()
            .try_into()
            .map_err(|_| CertificateError::Malformed)?;
        let peer = Self {
            device_id: blake3::hash(&public_key).to_hex()[..24].to_string(),
            public_key,
            certificate_fingerprint: certificate.fingerprint().to_owned(),
            status: TrustedPeerStatus::Trusted,
        };
        peer.verify_certificate(certificate)?;
        Ok(peer)
    }
    pub fn verify_certificate(
        &self,
        certificate: &DeviceCertificate,
    ) -> Result<(), CertificateError> {
        if self.status == TrustedPeerStatus::Blocked {
            return Err(CertificateError::IdentityMismatch);
        }
        let (_, parsed) =
            parse_x509_certificate(certificate.der()).map_err(|_| CertificateError::Malformed)?;
        if !parsed.validity().is_valid() {
            return Err(CertificateError::Malformed);
        }
        parsed
            .verify_signature(None)
            .map_err(|_| CertificateError::Malformed)?;
        let key_usage = parsed
            .key_usage()
            .map_err(|_| CertificateError::Malformed)?
            .ok_or(CertificateError::Malformed)?;
        if !key_usage.value.digital_signature() {
            return Err(CertificateError::Malformed);
        }
        let extended_usage = parsed
            .extended_key_usage()
            .map_err(|_| CertificateError::Malformed)?
            .ok_or(CertificateError::Malformed)?;
        if !extended_usage.value.server_auth
            || !extended_usage.value.client_auth
            || extended_usage.value.any
        {
            return Err(CertificateError::Malformed);
        }
        if parsed.extensions().iter().any(|extension| {
            extension.critical
                && matches!(
                    extension.parsed_extension(),
                    ParsedExtension::UnsupportedExtension { .. }
                        | ParsedExtension::ParseError { .. }
                )
        }) {
            return Err(CertificateError::Malformed);
        }
        if parsed
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref()
            != self.public_key
            || certificate.fingerprint() != self.certificate_fingerprint
        {
            return Err(CertificateError::IdentityMismatch);
        }
        Ok(())
    }
}
impl DeviceCertificate {
    pub fn parse(der: Vec<u8>) -> Result<Self, CertificateError> {
        parse_x509_certificate(&der).map_err(|_| CertificateError::Malformed)?;
        Ok(Self {
            fingerprint: blake3::hash(&der).to_hex().to_string(),
            der,
        })
    }
    pub fn generate(identity: &DeviceIdentity) -> Result<Self, CertificateError> {
        let pkcs8 = PrivatePkcs8KeyDer::from(identity.pkcs8_der());
        let key = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
            .map_err(|error| CertificateError::Encoding(error.to_string()))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| CertificateError::Encoding(error.to_string()))?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .self_signed(&key)
            .map_err(|error| CertificateError::Encoding(error.to_string()))?;
        let result = Self {
            der: certificate.der().to_vec(),
            fingerprint: String::new(),
        };
        result.matches(identity)?;
        Ok(Self {
            fingerprint: blake3::hash(&result.der).to_hex().to_string(),
            ..result
        })
    }
    pub fn from_der(der: Vec<u8>, identity: &DeviceIdentity) -> Result<Self, CertificateError> {
        let result = Self::parse(der)?;
        result.matches(identity)?;
        Ok(result)
    }
    pub fn der(&self) -> &[u8] {
        &self.der
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn matches(&self, identity: &DeviceIdentity) -> Result<(), CertificateError> {
        let (_, certificate) =
            parse_x509_certificate(&self.der).map_err(|_| CertificateError::Malformed)?;
        let subject_key = certificate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref();
        if subject_key != identity.public_key_bytes() {
            return Err(CertificateError::IdentityMismatch);
        }
        Ok(())
    }
    pub fn load_or_create(
        path: &Path,
        identity: &DeviceIdentity,
    ) -> Result<Self, CertificateError> {
        match fs::read(path) {
            Ok(der) => Self::from_der(der, identity),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let certificate = Self::generate(identity)?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, certificate.der())?;
                set_owner_only(path)?;
                Ok(certificate)
            }
            Err(error) => Err(CertificateError::Storage(error)),
        }
    }
}
#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), CertificateError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), CertificateError> {
    Ok(())
}
pub fn device_id_for(public_key: &VerifyingKey) -> String {
    blake3::hash(public_key.as_bytes()).to_hex()[..24].to_string()
}
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), IdentityError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidBytes)?;
    let signature = Signature::from_bytes(signature);
    key.verify(message, &signature)
        .map_err(|_| IdentityError::InvalidBytes)
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
    #[test]
    fn certificate_matches_identity_and_pkcs8() {
        let identity = DeviceIdentity::generate();
        assert_eq!(&identity.pkcs8_der()[16..], &identity.secret_bytes());
        let certificate = DeviceCertificate::generate(&identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        assert!(certificate.matches(&identity).is_ok());
        assert_eq!(certificate.fingerprint().len(), 64);
    }
    #[test]
    fn certificate_rejects_mismatch_and_malformed_der() {
        let identity = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let certificate = DeviceCertificate::generate(&identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        assert!(matches!(
            certificate.matches(&other),
            Err(CertificateError::IdentityMismatch)
        ));
        assert!(matches!(
            DeviceCertificate::from_der(vec![1, 2, 3], &identity),
            Err(CertificateError::Malformed)
        ));
    }
    #[test]
    fn certificate_persists_and_reloads() {
        let identity = DeviceIdentity::generate();
        let path = std::env::temp_dir().join(format!("linkdrop-cert-{}", identity.device_id()));
        let first = DeviceCertificate::load_or_create(&path, &identity)
            .unwrap_or_else(|error| panic!("certificate persistence failed: {error}"));
        let second = DeviceCertificate::load_or_create(&path, &identity)
            .unwrap_or_else(|error| panic!("certificate reload failed: {error}"));
        assert_eq!(first.fingerprint(), second.fingerprint());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn converts_identity_to_rustls_key_material() {
        let identity = DeviceIdentity::generate();
        let certificate = DeviceCertificate::generate(&identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let material = TlsKeyMaterial::from_identity(&identity, &certificate)
            .unwrap_or_else(|error| panic!("conversion failed: {error}"));
        assert_eq!(material.certificate_chain.len(), 1);
        assert!(TlsKeyMaterial::from_identity(&DeviceIdentity::generate(), &certificate).is_err());
    }
    #[test]
    fn registry_excludes_blocked_peers_from_server_allow_list() {
        let identity = DeviceIdentity::generate();
        let certificate = DeviceCertificate::generate(&identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let peer = TrustedPeer::provision(&identity, &certificate);
        let mut registry = TrustedPeerRegistry::default();
        registry.insert(peer.clone());
        assert_eq!(registry.trusted_peers().len(), 1);
        assert!(registry.block(&peer.device_id));
        assert!(registry.trusted_peers().is_empty());
        assert_eq!(
            registry.get(&peer.device_id).map(|stored| &stored.status),
            Some(&TrustedPeerStatus::Blocked)
        );
    }
    #[test]
    fn peer_can_be_provisioned_from_its_certificate() {
        let identity = DeviceIdentity::generate();
        let certificate = DeviceCertificate::generate(&identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let peer = TrustedPeer::from_certificate(&certificate)
            .unwrap_or_else(|error| panic!("certificate provisioning failed: {error}"));
        assert_eq!(peer.public_key, identity.public_key_bytes());
        assert_eq!(peer.device_id, identity.device_id());
    }
}
