//! Transfer state-machine boundary; no file I/O in Phase 1.
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use linkdrop_core::TransferStatus;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_CONTROL_MESSAGE_BYTES: usize = 16 * 1024;
const FILE_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_TRANSFER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const TRANSFER_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);

/// In-memory control for one active transfer. It intentionally does not survive restarts.
#[derive(Clone, Default)]
pub struct TransferControl {
    paused: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
}

impl TransferControl {
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
    }
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    async fn wait_until_active(&self) -> Result<(), TransferProtocolError> {
        while self.paused.load(Ordering::Acquire) {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(TransferProtocolError::Cancelled);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(TransferProtocolError::Cancelled);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferOffer {
    pub transfer_id: String,
    pub filename: String,
    pub total_bytes: u64,
    /// Lowercase BLAKE3 digest of the source file, computed before the receiver approves.
    pub checksum: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferDecision {
    pub transfer_id: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferProgress {
    pub transfer_id: String,
    pub transferred_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TransferProtocolError {
    #[error("transfer offer is invalid")]
    InvalidOffer,
    #[error("transfer offer exceeds the configured size limit")]
    SizeLimitExceeded,
    #[error("transfer timed out waiting for peer activity")]
    Timeout,
    #[error("transfer response does not match the offer")]
    MismatchedResponse,
    #[error("transfer control stream failed: {0}")]
    Stream(#[from] quinn::ConnectionError),
    #[error("transfer control message failed: {0}")]
    Message(String),
    #[error("file transfer failed: {0}")]
    File(String),
    #[error("received file size does not match the approved offer")]
    SizeMismatch,
    #[error("received file checksum does not match the approved offer")]
    ChecksumMismatch,
    #[error("transfer was cancelled")]
    Cancelled,
}

/// Computes the BLAKE3 digest of a regular source file without loading it into memory.
pub async fn checksum_file(source: &Path) -> Result<String, TransferProtocolError> {
    let mut source = tokio::fs::File::open(source)
        .await
        .map_err(|error| TransferProtocolError::File(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; FILE_CHUNK_BYTES];
    loop {
        let read = source
            .read(&mut buffer)
            .await
            .map_err(|error| TransferProtocolError::File(error.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Sends an authenticated transfer offer and waits for the peer's decision.
///
/// The caller must obtain `connection` from Linkdrop's pinned mTLS transport. This function
/// deliberately transfers no file bytes; it is the approval boundary preceding file I/O.
pub async fn request_transfer(
    connection: &quinn::Connection,
    offer: TransferOffer,
) -> Result<TransferDecision, TransferProtocolError> {
    validate_offer(&offer)?;
    let (mut send, mut receive) =
        tokio::time::timeout(TRANSFER_INACTIVITY_TIMEOUT, connection.open_bi())
            .await
            .map_err(|_| TransferProtocolError::Timeout)?
            .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
    write_message(&mut send, &offer).await?;
    send.finish()
        .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
    let decision: TransferDecision =
        tokio::time::timeout(TRANSFER_INACTIVITY_TIMEOUT, read_message(&mut receive))
            .await
            .map_err(|_| TransferProtocolError::Timeout)??;
    if decision.transfer_id != offer.transfer_id {
        return Err(TransferProtocolError::MismatchedResponse);
    }
    Ok(decision)
}

/// Receives one transfer offer and sends the caller's approval decision.
pub async fn respond_to_transfer(
    connection: &quinn::Connection,
    approve: impl FnOnce(&TransferOffer) -> bool,
) -> Result<TransferOffer, TransferProtocolError> {
    let (mut send, mut receive) = connection
        .accept_bi()
        .await
        .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
    let offer: TransferOffer = read_message(&mut receive).await?;
    validate_offer(&offer)?;
    let decision = TransferDecision {
        transfer_id: offer.transfer_id.clone(),
        accepted: approve(&offer),
    };
    write_message(&mut send, &decision).await?;
    send.finish()
        .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
    Ok(offer)
}

/// Reads a transfer offer but deliberately leaves the decision stream open.
///
/// Desktop receivers use this variant to show an explicit approval prompt before
/// sending a decision. No file stream is accepted until the user accepts.
pub async fn receive_transfer_offer(
    connection: &quinn::Connection,
) -> Result<(TransferOffer, quinn::SendStream), TransferProtocolError> {
    let (send, mut receive) =
        tokio::time::timeout(TRANSFER_INACTIVITY_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| TransferProtocolError::Timeout)?
            .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
    let offer: TransferOffer =
        tokio::time::timeout(TRANSFER_INACTIVITY_TIMEOUT, read_message(&mut receive))
            .await
            .map_err(|_| TransferProtocolError::Timeout)??;
    validate_offer(&offer)?;
    Ok((offer, send))
}

/// Sends the explicit user decision for an offer returned by [`receive_transfer_offer`].
pub async fn send_transfer_decision(
    send: &mut quinn::SendStream,
    offer: &TransferOffer,
    accepted: bool,
) -> Result<(), TransferProtocolError> {
    let decision = TransferDecision {
        transfer_id: offer.transfer_id.clone(),
        accepted,
    };
    write_message(send, &decision).await?;
    send.finish()
        .map_err(|error| TransferProtocolError::Message(error.to_string()))
}

/// Streams the approved source file over an authenticated QUIC unidirectional stream.
///
/// The caller must invoke this only after `request_transfer` receives an accepted decision.
pub async fn send_file(
    connection: &quinn::Connection,
    source: &Path,
    offer: &TransferOffer,
    report_progress: impl FnMut(TransferProgress),
) -> Result<(), TransferProtocolError> {
    send_file_controlled(connection, source, offer, None, report_progress).await
}

/// Streams an approved source file, observing an optional in-session control handle.
pub async fn send_file_controlled(
    connection: &quinn::Connection,
    source: &Path,
    offer: &TransferOffer,
    control: Option<&TransferControl>,
    mut report_progress: impl FnMut(TransferProgress),
) -> Result<(), TransferProtocolError> {
    validate_offer(offer)?;
    let metadata = tokio::fs::metadata(source)
        .await
        .map_err(|error| TransferProtocolError::File(error.to_string()))?;
    if !metadata.is_file() || metadata.len() != offer.total_bytes {
        return Err(TransferProtocolError::SizeMismatch);
    }
    let mut source = tokio::fs::File::open(source)
        .await
        .map_err(|error| TransferProtocolError::File(error.to_string()))?;
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
    let mut transferred_bytes = 0_u64;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; FILE_CHUNK_BYTES];
    loop {
        if let Some(control) = control {
            control.wait_until_active().await?;
        }
        let read = tokio::time::timeout(TRANSFER_INACTIVITY_TIMEOUT, source.read(&mut buffer))
            .await
            .map_err(|_| TransferProtocolError::Timeout)?
            .map_err(|error| TransferProtocolError::File(error.to_string()))?;
        if read == 0 {
            break;
        }
        tokio::time::timeout(
            TRANSFER_INACTIVITY_TIMEOUT,
            stream.write_all(&buffer[..read]),
        )
        .await
        .map_err(|_| TransferProtocolError::Timeout)?
        .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
        hasher.update(&buffer[..read]);
        transferred_bytes += read as u64;
        report_progress(TransferProgress {
            transfer_id: offer.transfer_id.clone(),
            transferred_bytes,
            total_bytes: offer.total_bytes,
        });
    }
    if transferred_bytes != offer.total_bytes {
        return Err(TransferProtocolError::SizeMismatch);
    }
    if hasher.finalize().to_hex().as_str() != offer.checksum {
        return Err(TransferProtocolError::ChecksumMismatch);
    }
    stream
        .finish()
        .map_err(|error| TransferProtocolError::Message(error.to_string()))
}

/// Receives an approved file into `directory`, reporting progress after every data chunk.
///
/// `filename` is validated before path construction and the destination is created with
/// `create_new`, so an existing local file is never overwritten.
pub async fn receive_file(
    connection: &quinn::Connection,
    directory: &Path,
    offer: &TransferOffer,
    report_progress: impl FnMut(TransferProgress),
) -> Result<PathBuf, TransferProtocolError> {
    receive_file_controlled(connection, directory, offer, None, report_progress).await
}

/// Receives an approved file while observing an optional in-session control handle.
pub async fn receive_file_controlled(
    connection: &quinn::Connection,
    directory: &Path,
    offer: &TransferOffer,
    control: Option<&TransferControl>,
    mut report_progress: impl FnMut(TransferProgress),
) -> Result<PathBuf, TransferProtocolError> {
    validate_offer(offer)?;
    tokio::fs::create_dir_all(directory)
        .await
        .map_err(|error| TransferProtocolError::File(error.to_string()))?;
    let (destination, mut destination_file) =
        create_destination_file(directory, &offer.filename).await?;
    let result = async {
        let mut stream = connection
            .accept_uni()
            .await
            .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
        let mut transferred_bytes = 0_u64;
        let mut hasher = blake3::Hasher::new();
        loop {
            if let Some(control) = control {
                control.wait_until_active().await?;
            }
            let Some(chunk) = tokio::time::timeout(
                TRANSFER_INACTIVITY_TIMEOUT,
                stream.read_chunk(FILE_CHUNK_BYTES, true),
            )
            .await
            .map_err(|_| TransferProtocolError::Timeout)?
            .map_err(|error| TransferProtocolError::Message(error.to_string()))?
            else {
                break;
            };
            if transferred_bytes + chunk.bytes.len() as u64 > offer.total_bytes {
                return Err(TransferProtocolError::SizeMismatch);
            }
            destination_file
                .write_all(&chunk.bytes)
                .await
                .map_err(|error| TransferProtocolError::File(error.to_string()))?;
            hasher.update(&chunk.bytes);
            transferred_bytes += chunk.bytes.len() as u64;
            report_progress(TransferProgress {
                transfer_id: offer.transfer_id.clone(),
                transferred_bytes,
                total_bytes: offer.total_bytes,
            });
        }
        destination_file
            .flush()
            .await
            .map_err(|error| TransferProtocolError::File(error.to_string()))?;
        if transferred_bytes != offer.total_bytes {
            return Err(TransferProtocolError::SizeMismatch);
        }
        if hasher.finalize().to_hex().as_str() != offer.checksum {
            return Err(TransferProtocolError::ChecksumMismatch);
        }
        Ok(())
    }
    .await;
    drop(destination_file);
    if let Err(error) = result {
        let _ = tokio::fs::remove_file(&destination).await;
        return Err(error);
    }
    Ok(destination)
}

async fn create_destination_file(
    directory: &Path,
    filename: &str,
) -> Result<(PathBuf, tokio::fs::File), TransferProtocolError> {
    let source = Path::new(filename);
    let stem = source
        .file_stem()
        .and_then(|part| part.to_str())
        .unwrap_or(filename);
    let extension = source.extension().and_then(|part| part.to_str());
    for index in 0..10_000_u32 {
        let candidate_name = if index == 0 {
            filename.to_owned()
        } else if let Some(extension) = extension {
            format!("{stem} ({index}).{extension}")
        } else {
            format!("{stem} ({index})")
        };
        let candidate = directory.join(candidate_name);
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(TransferProtocolError::File(error.to_string())),
        }
    }
    Err(TransferProtocolError::File(
        "could not allocate a safe unique destination filename".to_owned(),
    ))
}

async fn write_message<T: Serialize>(
    stream: &mut quinn::SendStream,
    message: &T,
) -> Result<(), TransferProtocolError> {
    let encoded = serde_json::to_vec(message)
        .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
    if encoded.len() > MAX_CONTROL_MESSAGE_BYTES {
        return Err(TransferProtocolError::InvalidOffer);
    }
    stream
        .write_all(&encoded)
        .await
        .map_err(|error| TransferProtocolError::Message(error.to_string()))
}

async fn read_message<T: for<'de> Deserialize<'de>>(
    stream: &mut quinn::RecvStream,
) -> Result<T, TransferProtocolError> {
    let encoded = stream
        .read_to_end(MAX_CONTROL_MESSAGE_BYTES)
        .await
        .map_err(|error| TransferProtocolError::Message(error.to_string()))?;
    serde_json::from_slice(&encoded)
        .map_err(|error| TransferProtocolError::Message(error.to_string()))
}

fn validate_offer(offer: &TransferOffer) -> Result<(), TransferProtocolError> {
    if offer.transfer_id.is_empty()
        || offer.transfer_id.len() > 128
        || offer.filename.is_empty()
        || offer.filename.len() > 255
        || offer.filename.contains(['/', '\\', '\0'])
        || offer.checksum.len() != 64
        || !offer.checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TransferProtocolError::InvalidOffer);
    }
    if offer.total_bytes > MAX_TRANSFER_BYTES {
        return Err(TransferProtocolError::SizeLimitExceeded);
    }
    Ok(())
}
#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error("invalid transfer transition from {from:?} to {to:?}")]
    Invalid {
        from: TransferStatus,
        to: TransferStatus,
    },
}
pub fn can_transition(from: TransferStatus, to: TransferStatus) -> bool {
    matches!(
        (from, to),
        (TransferStatus::Pending, TransferStatus::AwaitingApproval)
            | (TransferStatus::AwaitingApproval, TransferStatus::Connecting)
            | (TransferStatus::Connecting, TransferStatus::Transferring)
            | (TransferStatus::Transferring, TransferStatus::Completed)
            | (_, TransferStatus::Cancelled)
            | (_, TransferStatus::Failed)
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use linkdrop_identity::{DeviceCertificate, DeviceIdentity, TrustedPeer};
    use linkdrop_protocol::transport::SecureEndpoint;
    use std::sync::{Arc, Mutex};
    #[test]
    fn permits_cancel() {
        assert!(can_transition(
            TransferStatus::Paused,
            TransferStatus::Cancelled
        ));
    }

    #[tokio::test]
    async fn cancelled_control_stops_a_transfer_before_reading_more_bytes() {
        let control = TransferControl::default();
        control.cancel();
        assert!(matches!(
            control.wait_until_active().await,
            Err(TransferProtocolError::Cancelled)
        ));
    }
    #[test]
    fn rejects_unsafe_filenames_before_opening_a_stream() {
        assert!(matches!(
            validate_offer(&TransferOffer {
                transfer_id: "transfer-1".into(),
                filename: "../../unsafe".into(),
                total_bytes: 1,
                checksum: "0".repeat(64),
            }),
            Err(TransferProtocolError::InvalidOffer)
        ));
    }

    #[test]
    fn rejects_offers_over_the_transfer_size_limit() {
        assert!(matches!(
            validate_offer(&TransferOffer {
                transfer_id: "transfer-1".into(),
                filename: "large.bin".into(),
                total_bytes: MAX_TRANSFER_BYTES + 1,
                checksum: "0".repeat(64),
            }),
            Err(TransferProtocolError::SizeLimitExceeded)
        ));
    }

    #[tokio::test]
    async fn allocates_a_non_overwriting_destination_for_duplicate_filenames() {
        let root = std::env::temp_dir().join(format!(
            "linkdrop-transfer-destination-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&root)
            .await
            .unwrap_or_else(|error| panic!("temporary directory failed: {error}"));
        let original = root.join("photo.jpg");
        tokio::fs::write(&original, b"existing")
            .await
            .unwrap_or_else(|error| panic!("temporary file write failed: {error}"));
        let (duplicate, file) = create_destination_file(&root, "photo.jpg")
            .await
            .unwrap_or_else(|error| panic!("destination allocation failed: {error}"));
        drop(file);
        assert_eq!(
            duplicate.file_name().and_then(|name| name.to_str()),
            Some("photo (1).jpg")
        );
        assert_eq!(
            tokio::fs::read(&original)
                .await
                .unwrap_or_else(|error| panic!("existing file read failed: {error}")),
            b"existing"
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn trusted_connection_carries_an_approved_transfer_offer() {
        let server_identity = DeviceIdentity::generate();
        let server_certificate = DeviceCertificate::generate(&server_identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let client_identity = DeviceIdentity::generate();
        let client_certificate = DeviceCertificate::generate(&client_identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
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
        let (client_connection, server_connection) = tokio::join!(connect, server.accept());
        let client_connection =
            client_connection.unwrap_or_else(|error| panic!("connect failed: {error}"));
        let server_connection = server_connection
            .unwrap_or_else(|error| panic!("accept failed: {error}"))
            .expect("endpoint closed before accepting connection");
        let offer = TransferOffer {
            transfer_id: "transfer-1".into(),
            filename: "photo.jpg".into(),
            total_bytes: 42,
            checksum: "0".repeat(64),
        };

        let (decision, received) = tokio::join!(
            request_transfer(&client_connection, offer.clone()),
            respond_to_transfer(&server_connection, |_| true),
        );
        assert_eq!(
            received.unwrap_or_else(|error| panic!("receive failed: {error}")),
            offer
        );
        assert_eq!(
            decision.unwrap_or_else(|error| panic!("decision failed: {error}")),
            TransferDecision {
                transfer_id: "transfer-1".into(),
                accepted: true,
            }
        );
        client.close();
        server.close();
    }

    #[tokio::test]
    async fn approved_transfer_streams_file_bytes_and_reports_progress() {
        let server_identity = DeviceIdentity::generate();
        let server_certificate = DeviceCertificate::generate(&server_identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
        let client_identity = DeviceIdentity::generate();
        let client_certificate = DeviceCertificate::generate(&client_identity)
            .unwrap_or_else(|error| panic!("certificate generation failed: {error}"));
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
        let (client_connection, server_connection) = tokio::join!(connect, server.accept());
        let client_connection =
            client_connection.unwrap_or_else(|error| panic!("connect failed: {error}"));
        let server_connection = server_connection
            .unwrap_or_else(|error| panic!("accept failed: {error}"))
            .expect("endpoint closed before accepting connection");
        let payload = vec![0xA5; FILE_CHUNK_BYTES + 17];
        let root = std::env::temp_dir().join(format!(
            "linkdrop-transfer-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_nanos()
        ));
        let source = root.join("source.bin");
        let downloads = root.join("downloads");
        tokio::fs::create_dir_all(&root)
            .await
            .unwrap_or_else(|error| panic!("temporary directory failed: {error}"));
        tokio::fs::write(&source, &payload)
            .await
            .unwrap_or_else(|error| panic!("temporary source write failed: {error}"));
        let offer = TransferOffer {
            transfer_id: "transfer-file-1".into(),
            filename: "received.bin".into(),
            total_bytes: payload.len() as u64,
            checksum: blake3::hash(&payload).to_hex().to_string(),
        };
        let (decision, _) = tokio::join!(
            request_transfer(&client_connection, offer.clone()),
            respond_to_transfer(&server_connection, |_| true),
        );
        assert!(
            decision
                .unwrap_or_else(|error| panic!("decision failed: {error}"))
                .accepted
        );
        let sent_progress = Arc::new(Mutex::new(Vec::new()));
        let received_progress = Arc::new(Mutex::new(Vec::new()));
        let sent_events = Arc::clone(&sent_progress);
        let received_events = Arc::clone(&received_progress);
        let (sent, received) = tokio::join!(
            send_file(&client_connection, &source, &offer, move |progress| {
                if let Ok(mut events) = sent_events.lock() {
                    events.push(progress);
                }
            }),
            receive_file(&server_connection, &downloads, &offer, move |progress| {
                if let Ok(mut events) = received_events.lock() {
                    events.push(progress);
                }
            }),
        );
        sent.unwrap_or_else(|error| panic!("send failed: {error}"));
        let received = received.unwrap_or_else(|error| panic!("receive failed: {error}"));
        assert_eq!(
            tokio::fs::read(received)
                .await
                .unwrap_or_else(|error| panic!("received file read failed: {error}")),
            payload
        );
        assert_eq!(
            sent_progress
                .lock()
                .ok()
                .and_then(|events| events.last().cloned())
                .map(|progress| progress.transferred_bytes),
            Some(offer.total_bytes)
        );
        assert_eq!(
            received_progress
                .lock()
                .ok()
                .and_then(|events| events.last().cloned())
                .map(|progress| progress.transferred_bytes),
            Some(offer.total_bytes)
        );
        let _ = tokio::fs::remove_dir_all(root).await;
        client.close();
        server.close();
    }
}
