//! Endpoint lifecycle for Linkdrop's pinned mutual-TLS QUIC transport.

use std::net::SocketAddr;

use linkdrop_identity::{DeviceCertificate, DeviceIdentity, TrustedPeer};

use crate::tls::{
    build_client_config, build_pairing_client_config, build_pairing_server_config,
    build_server_config, TlsConfigError,
};

/// A QUIC endpoint that accepts only the configured trusted peers.
pub struct SecureEndpoint {
    endpoint: quinn::Endpoint,
}

/// A separate endpoint for the short-lived, explicit pairing ceremony.
#[derive(Clone)]
pub struct PairingEndpoint {
    endpoint: quinn::Endpoint,
}

impl PairingEndpoint {
    pub fn bind(
        bind_address: SocketAddr,
        identity: &DeviceIdentity,
        certificate: &DeviceCertificate,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            endpoint: quinn::Endpoint::server(
                build_pairing_server_config(identity, certificate)?,
                bind_address,
            )?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub async fn connect(
        &self,
        address: SocketAddr,
        server_name: &str,
        identity: &DeviceIdentity,
        certificate: &DeviceCertificate,
    ) -> Result<quinn::Connection, TransportError> {
        Ok(self
            .endpoint
            .connect_with(
                build_pairing_client_config(identity, certificate)?,
                address,
                server_name,
            )?
            .await?)
    }

    pub async fn accept(&self) -> Result<Option<quinn::Connection>, TransportError> {
        let Some(incoming) = self.endpoint.accept().await else {
            return Ok(None);
        };
        Ok(Some(incoming.accept()?.await?))
    }

    pub fn close(&self) {
        self.endpoint
            .close(0u32.into(), b"linkdrop pairing endpoint shutdown");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error(transparent)]
    Tls(#[from] TlsConfigError),
    #[error("could not bind the QUIC endpoint: {0}")]
    Bind(#[from] std::io::Error),
    #[error("could not start a QUIC connection: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC handshake failed: {0}")]
    Handshake(#[from] quinn::ConnectionError),
}

impl SecureEndpoint {
    /// Binds an endpoint that requires every inbound connection to authenticate as a trusted peer.
    pub fn bind(
        bind_address: SocketAddr,
        identity: &DeviceIdentity,
        certificate: &DeviceCertificate,
        trusted_peers: &[TrustedPeer],
    ) -> Result<Self, TransportError> {
        let config = build_server_config(identity, certificate, trusted_peers)?;
        Ok(Self {
            endpoint: quinn::Endpoint::server(config, bind_address)?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Applies an updated allow-list to future inbound connections without rebinding the socket.
    pub fn set_trusted_peers(
        &self,
        identity: &DeviceIdentity,
        certificate: &DeviceCertificate,
        trusted_peers: &[TrustedPeer],
    ) -> Result<(), TransportError> {
        let config = build_server_config(identity, certificate, trusted_peers)?;
        self.endpoint.set_server_config(Some(config));
        Ok(())
    }

    /// Connects only after constructing a client configuration pinned to `peer`.
    pub async fn connect(
        &self,
        address: SocketAddr,
        server_name: &str,
        identity: &DeviceIdentity,
        certificate: &DeviceCertificate,
        peer: TrustedPeer,
    ) -> Result<quinn::Connection, TransportError> {
        let config = build_client_config(identity, certificate, peer)?;
        Ok(self
            .endpoint
            .connect_with(config, address, server_name)?
            .await?)
    }

    /// Waits for and accepts one mutually authenticated inbound connection.
    pub async fn accept(&self) -> Result<Option<quinn::Connection>, TransportError> {
        let Some(incoming) = self.endpoint.accept().await else {
            return Ok(None);
        };
        Ok(Some(incoming.accept()?.await?))
    }

    pub fn close(&self) {
        self.endpoint
            .close(0u32.into(), b"linkdrop endpoint shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_and_certificate() -> (DeviceIdentity, DeviceCertificate) {
        let identity = DeviceIdentity::generate();
        let certificate = DeviceCertificate::generate(&identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        (identity, certificate)
    }

    #[tokio::test]
    async fn trusted_peers_connect_through_secure_endpoints() {
        let (server_identity, server_certificate) = identity_and_certificate();
        let (client_identity, client_certificate) = identity_and_certificate();
        let server_peer = TrustedPeer::provision(&server_identity, &server_certificate);
        let client_peer = TrustedPeer::provision(&client_identity, &client_certificate);
        let localhost = "127.0.0.1:0".parse().unwrap_or_else(|_| unreachable!());
        let server = SecureEndpoint::bind(
            localhost,
            &server_identity,
            &server_certificate,
            std::slice::from_ref(&client_peer),
        )
        .unwrap_or_else(|error| panic!("server bind failed: {error}"));
        let client = SecureEndpoint::bind(
            localhost,
            &client_identity,
            &client_certificate,
            std::slice::from_ref(&server_peer),
        )
        .unwrap_or_else(|error| panic!("client bind failed: {error}"));

        let connect = client.connect(
            server
                .local_addr()
                .unwrap_or_else(|error| panic!("server address unavailable: {error}")),
            "linkdrop",
            &client_identity,
            &client_certificate,
            server_peer,
        );
        let (client_result, server_result) = tokio::join!(connect, server.accept());
        assert!(client_result.is_ok());
        assert!(matches!(server_result, Ok(Some(_))));

        client.close();
        server.close();
    }
}
