//! Fail-closed pinned-TLS verifier scaffolding. Not wired into a client config yet.
use std::fmt;

use linkdrop_identity::{DeviceCertificate, TrustedPeer};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, Error, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

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
}
