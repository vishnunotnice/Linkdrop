//! Fail-closed, pinned mutual-TLS configuration for Linkdrop's QUIC transport.
use std::{fmt, sync::Arc};

use linkdrop_identity::{
    CertificateError, DeviceCertificate, DeviceIdentity, TlsKeyMaterial, TrustedPeer,
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, Error, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// The ALPN identifier accepted by Linkdrop peers.
pub const ALPN: &[u8] = b"linkdrop/1";
pub const PAIRING_ALPN: &[u8] = b"linkdrop-pair/1";

#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("local TLS key material is invalid: {0}")]
    KeyMaterial(#[from] CertificateError),
    #[error("rustls configuration failed: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("QUIC TLS configuration failed: {0}")]
    Quinn(String),
}

/// Builds a TLS-1.3-only QUIC server configuration.
///
/// Every connecting client must present a leaf certificate which exactly matches one of
/// `trusted_peers`. An empty registry is valid but, intentionally, accepts no clients.
pub fn build_server_config(
    identity: &DeviceIdentity,
    certificate: &DeviceCertificate,
    trusted_peers: &[TrustedPeer],
) -> Result<quinn::ServerConfig, TlsConfigError> {
    let TlsKeyMaterial {
        certificate_chain,
        private_key,
    } = TlsKeyMaterial::from_identity(identity, certificate)?;
    let mut rustls_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(Arc::new(PinnedClientVerifier::new(trusted_peers.to_vec())))
            .with_single_cert(certificate_chain, private_key)?;
    rustls_config.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|error| TlsConfigError::Quinn(error.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Builds a TLS-1.3-only QUIC client configuration for one explicitly pinned server.
///
/// The client always presents its own certificate, so the remote peer can require mutual
/// authentication. `server` is verified directly, including its certificate fingerprint and
/// blocked status; no WebPKI roots or hostname-based trust are consulted.
pub fn build_client_config(
    identity: &DeviceIdentity,
    certificate: &DeviceCertificate,
    server: TrustedPeer,
) -> Result<quinn::ClientConfig, TlsConfigError> {
    let TlsKeyMaterial {
        certificate_chain,
        private_key,
    } = TlsKeyMaterial::from_identity(identity, certificate)?;
    let mut rustls_config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(server)))
            .with_client_auth_cert(certificate_chain, private_key)?;
    rustls_config.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|error| TlsConfigError::Quinn(error.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// Builds the short-lived TLS configuration used only for explicit code-confirmed pairing.
/// It validates the remote self-signed certificate's structure and signature, but does not
/// trust it or persist it; persistence happens only after the user verifies the pairing code.
pub fn build_pairing_server_config(
    identity: &DeviceIdentity,
    certificate: &DeviceCertificate,
) -> Result<quinn::ServerConfig, TlsConfigError> {
    let TlsKeyMaterial {
        certificate_chain,
        private_key,
    } = TlsKeyMaterial::from_identity(identity, certificate)?;
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(Arc::new(PairingClientVerifier))
            .with_single_cert(certificate_chain, private_key)?;
    config.alpn_protocols = vec![PAIRING_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(config)
        .map_err(|error| TlsConfigError::Quinn(error.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

pub fn build_pairing_client_config(
    identity: &DeviceIdentity,
    certificate: &DeviceCertificate,
) -> Result<quinn::ClientConfig, TlsConfigError> {
    let TlsKeyMaterial {
        certificate_chain,
        private_key,
    } = TlsKeyMaterial::from_identity(identity, certificate)?;
    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PairingServerVerifier))
            .with_client_auth_cert(certificate_chain, private_key)?;
    config.alpn_protocols = vec![PAIRING_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config)
        .map_err(|error| TlsConfigError::Quinn(error.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

#[derive(Debug)]
struct PairingClientVerifier;
#[derive(Debug)]
struct PairingServerVerifier;
fn verify_pairing_certificate(
    cert: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<(), Error> {
    if !intermediates.is_empty() {
        return Err(Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));
    }
    let certificate = DeviceCertificate::parse(cert.as_ref().to_vec())
        .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    TrustedPeer::from_certificate(&certificate)
        .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    Ok(())
}
impl rustls::server::danger::ClientCertVerifier for PairingClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, Error> {
        verify_pairing_certificate(end, intermediates)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
impl ServerCertVerifier for PairingServerVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        verify_pairing_certificate(end, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct PinnedServerVerifier {
    peer: TrustedPeer,
}

pub struct PinnedClientVerifier {
    peers: Vec<TrustedPeer>,
}
impl PinnedClientVerifier {
    pub fn new(peers: Vec<TrustedPeer>) -> Self {
        Self { peers }
    }
}
impl fmt::Debug for PinnedClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedClientVerifier")
    }
}
impl rustls::server::danger::ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let certificate = DeviceCertificate::parse(end.as_ref().to_vec())
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if self
            .peers
            .iter()
            .any(|peer| peer.verify_certificate(&certificate).is_ok())
        {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
impl PinnedServerVerifier {
    pub fn new(peer: TrustedPeer) -> Self {
        Self { peer }
    }
}

impl fmt::Debug for PinnedServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedServerVerifier")
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !_intermediates.is_empty() {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let certificate = DeviceCertificate::parse(_end_entity.as_ref().to_vec())
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        self.peer
            .verify_certificate(&certificate)
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General(
            "TLS signature verification is not configured".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::server::danger::ClientCertVerifier;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn identity_and_certificate() -> (linkdrop_identity::DeviceIdentity, DeviceCertificate) {
        let identity = linkdrop_identity::DeviceIdentity::generate();
        let certificate = DeviceCertificate::generate(&identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        (identity, certificate)
    }

    #[test]
    fn placeholder_is_fail_closed() {
        let identity = linkdrop_identity::DeviceIdentity::generate();
        let device_certificate =
            DeviceCertificate::generate(&identity).unwrap_or_else(|_| unreachable!());
        let verifier =
            PinnedServerVerifier::new(TrustedPeer::provision(&identity, &device_certificate));
        let cert = CertificateDer::from(vec![0]);
        let server_name: ServerName<'static> =
            "localhost".try_into().unwrap_or_else(|_| unreachable!());
        assert!(verifier
            .verify_server_cert(
                &cert,
                &[],
                &server_name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO)
            )
            .is_err());
    }

    #[test]
    fn builders_create_tls13_mutual_auth_configs() {
        let (local_identity, local_certificate) = identity_and_certificate();
        let (remote_identity, remote_certificate) = identity_and_certificate();
        let remote_peer = TrustedPeer::provision(&remote_identity, &remote_certificate);

        assert!(build_server_config(
            &local_identity,
            &local_certificate,
            std::slice::from_ref(&remote_peer),
        )
        .is_ok());
        assert!(build_client_config(&local_identity, &local_certificate, remote_peer).is_ok());
    }

    #[test]
    fn blocked_peers_are_rejected_by_both_pinned_verifiers() {
        let (identity, certificate) = identity_and_certificate();
        let mut blocked = TrustedPeer::provision(&identity, &certificate);
        blocked.status = linkdrop_identity::TrustedPeerStatus::Blocked;
        let client_verifier = PinnedClientVerifier::new(vec![blocked.clone()]);
        let server_verifier = PinnedServerVerifier::new(blocked);
        let server_name: ServerName<'static> =
            "localhost".try_into().unwrap_or_else(|_| unreachable!());
        let now = UnixTime::since_unix_epoch(std::time::Duration::ZERO);

        assert!(client_verifier
            .verify_client_cert(&CertificateDer::from(certificate.der().to_vec()), &[], now,)
            .is_err());
        assert!(server_verifier
            .verify_server_cert(
                &CertificateDer::from(certificate.der().to_vec()),
                &[],
                &server_name,
                &[],
                now,
            )
            .is_err());
    }

    #[tokio::test]
    async fn pinned_peers_complete_a_mutual_tls_quic_handshake() {
        let (server_identity, server_certificate) = identity_and_certificate();
        let (client_identity, client_certificate) = identity_and_certificate();
        let server_peer = TrustedPeer::provision(&server_identity, &server_certificate);
        let client_peer = TrustedPeer::provision(&client_identity, &client_certificate);
        let server_config = build_server_config(
            &server_identity,
            &server_certificate,
            std::slice::from_ref(&client_peer),
        )
        .unwrap_or_else(|error| panic!("server config failed: {error}"));
        let client_config = build_client_config(&client_identity, &client_certificate, server_peer)
            .unwrap_or_else(|error| panic!("client config failed: {error}"));
        let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = quinn::Endpoint::server(server_config, localhost)
            .unwrap_or_else(|error| panic!("server endpoint failed: {error}"));
        let client = quinn::Endpoint::client(localhost)
            .unwrap_or_else(|error| panic!("client endpoint failed: {error}"));
        let server_addr = server
            .local_addr()
            .unwrap_or_else(|error| panic!("server address unavailable: {error}"));

        let connecting = client
            .connect_with(client_config, server_addr, "linkdrop")
            .unwrap_or_else(|error| panic!("client connect failed: {error}"));
        let incoming = server
            .accept()
            .await
            .expect("server did not receive a connection");
        let (client_connection, server_connection) = tokio::join!(connecting, incoming);
        assert!(client_connection.is_ok());
        assert!(server_connection.is_ok());

        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn unpaired_devices_complete_the_pairing_tls_handshake() {
        let (server_identity, server_certificate) = identity_and_certificate();
        let (client_identity, client_certificate) = identity_and_certificate();
        let server = quinn::Endpoint::server(
            build_pairing_server_config(&server_identity, &server_certificate)
                .unwrap_or_else(|error| panic!("pairing server config failed: {error}")),
            "127.0.0.1:0".parse().unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|error| panic!("pairing server bind failed: {error}"));
        let client =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap_or_else(|_| unreachable!()))
                .unwrap_or_else(|error| panic!("pairing client bind failed: {error}"));
        let connect = client
            .connect_with(
                build_pairing_client_config(&client_identity, &client_certificate)
                    .unwrap_or_else(|error| panic!("pairing client config failed: {error}")),
                server
                    .local_addr()
                    .unwrap_or_else(|error| panic!("server address failed: {error}")),
                "linkdrop",
            )
            .unwrap_or_else(|error| panic!("pairing connect failed: {error}"));
        let incoming = server.accept().await.expect("missing pairing connection");
        let (client_connection, server_connection) = tokio::join!(connect, incoming);
        assert!(client_connection.is_ok());
        assert!(server_connection.is_ok());
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
    }
}
