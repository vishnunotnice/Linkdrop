#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use linkdrop_core::{Device, TransferStatus, TrustStatus};
use linkdrop_discovery::{DiscoveryConfig, DiscoveryEngine, DiscoveryEvent};
use linkdrop_identity::{
    DeviceCertificate, DeviceIdentity, TrustedPeerRegistry, TrustedPeerStatus,
};
use linkdrop_protocol::{
    initiate_pairing_exchange, respond_to_pairing_exchange,
    transport::{PairingEndpoint, SecureEndpoint},
    verify_pairing_envelope, PairingEnvelope,
};
use linkdrop_storage::{JsonTrustedPeerStore, TrustedPeerStore};
use linkdrop_transfer::{
    receive_file, receive_transfer_offer, request_transfer, send_file, send_transfer_decision,
    TransferOffer,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tauri::{Emitter, Manager, State};

struct AppState {
    settings: Mutex<Settings>,
    device_id: String,
    identity: Arc<DeviceIdentity>,
    certificate: DeviceCertificate,
    peers: Mutex<TrustedPeerRegistry>,
    peer_store: JsonTrustedPeerStore,
    endpoint: SecureEndpoint,
    pairing_endpoint: PairingEndpoint,
    discovery: DiscoveryEngine,
    transfers: Mutex<HashMap<String, TransferInfo>>,
    pending_inbound: Mutex<HashMap<String, PendingInboundTransfer>>,
    next_transfer_id: AtomicU64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    display_name: String,
    discoverable: bool,
    download_directory: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            display_name: "My Linkdrop".to_owned(),
            discoverable: true,
            download_directory: None,
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    name: &'static str,
    version: &'static str,
    phase: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportInfo {
    device_id: String,
    certificate_fingerprint: String,
    port: u16,
    trusted_peer_count: usize,
    peer_registry_path: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrustedPeerInfo {
    device_id: String,
    certificate_fingerprint: String,
    status: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingRequest {
    local: PairingEnvelope,
    remote: PairingEnvelope,
    verification_code: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferInfo {
    id: String,
    sender_device_id: String,
    receiver_device_id: String,
    filename: String,
    total_bytes: u64,
    transferred_bytes: u64,
    status: TransferStatus,
    created_at: String,
    direction: String,
    saved_path: Option<String>,
    error: Option<String>,
}

struct PendingInboundTransfer {
    offer: TransferOffer,
    connection: quinn::Connection,
    decision_stream: quinn::SendStream,
}

fn publish_transfer(app: &tauri::AppHandle, state: &AppState, transfer: TransferInfo) {
    if let Ok(mut transfers) = state.transfers.lock() {
        transfers.insert(transfer.id.clone(), transfer.clone());
    } else {
        tracing::warn!(transfer_id = %transfer.id, "transfer state is temporarily unavailable");
    }
    if let Err(error) = app.emit("transfer-event", transfer) {
        tracing::warn!(%error, "failed to emit transfer event");
    }
}

fn update_transfer(
    app: &tauri::AppHandle,
    transfer_id: &str,
    update: impl FnOnce(&mut TransferInfo),
) {
    let state = app.state::<AppState>();
    let transfer = state.transfers.lock().ok().and_then(|mut transfers| {
        let transfer = transfers.get_mut(transfer_id)?;
        update(transfer);
        Some(transfer.clone())
    });
    if let Some(transfer) = transfer {
        if let Err(error) = app.emit("transfer-event", transfer) {
            tracing::warn!(%error, "failed to emit transfer event");
        }
    }
}

fn new_transfer_id(state: &AppState) -> String {
    let sequence = state.next_transfer_id.fetch_add(1, Ordering::Relaxed);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("transfer-{timestamp:x}-{sequence:x}")
}

fn unix_timestamp() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|_| "system clock is unavailable".to_owned())
}

#[tauri::command]
fn get_application_information() -> AppInfo {
    AppInfo {
        name: "Linkdrop",
        version: env!("CARGO_PKG_VERSION"),
        phase: "Phase 3",
    }
}
#[tauri::command]
fn get_local_device_display_name(state: State<'_, AppState>) -> Result<String, String> {
    state
        .settings
        .lock()
        .map(|s| s.display_name.clone())
        .map_err(|_| "settings are temporarily unavailable".to_owned())
}
#[tauri::command]
fn get_transport_information(state: State<'_, AppState>) -> Result<TransportInfo, String> {
    let port = state
        .endpoint
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    let trusted_peer_count = state
        .peers
        .lock()
        .map(|peers| peers.trusted_peers().len())
        .map_err(|_| "trusted peers are temporarily unavailable".to_owned())?;
    Ok(TransportInfo {
        device_id: state.identity.device_id(),
        certificate_fingerprint: state.certificate.fingerprint().to_owned(),
        port,
        trusted_peer_count,
        peer_registry_path: state.peer_store.path().display().to_string(),
    })
}
#[tauri::command]
fn list_trusted_peers(state: State<'_, AppState>) -> Result<Vec<TrustedPeerInfo>, String> {
    state
        .peers
        .lock()
        .map(|peers| {
            peers
                .peers()
                .into_iter()
                .map(|peer| TrustedPeerInfo {
                    device_id: peer.device_id,
                    certificate_fingerprint: peer.certificate_fingerprint,
                    status: match peer.status {
                        TrustedPeerStatus::Trusted => "trusted".to_owned(),
                        TrustedPeerStatus::Blocked => "blocked".to_owned(),
                    },
                })
                .collect()
        })
        .map_err(|_| "trusted peers are temporarily unavailable".to_owned())
}
#[tauri::command]
fn set_peer_trust(
    device_id: String,
    trusted: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut peers = state
        .peers
        .lock()
        .map_err(|_| "trusted peers are temporarily unavailable".to_owned())?;
    let updated = if trusted {
        peers.trust(&device_id)
    } else {
        peers.block(&device_id)
    };
    if !updated {
        return Err("device is not in the trusted-peer registry".to_owned());
    }
    state
        .peer_store
        .write_peers(&peers)
        .map_err(|error| error.to_string())?;
    state
        .endpoint
        .set_trusted_peers(&state.identity, &state.certificate, &peers.trusted_peers())
        .map_err(|error| error.to_string())
}
#[tauri::command]
fn approve_pairing(
    local: PairingEnvelope,
    remote: PairingEnvelope,
    transport_binding: Vec<u8>,
    verification_code: String,
    state: State<'_, AppState>,
) -> Result<TrustedPeerInfo, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is unavailable".to_owned())?
        .as_secs() as i64;
    let (peer, expected_code) = verify_pairing_envelope(&local, &remote, &transport_binding, now)
        .map_err(|error| error.to_string())?;
    if verification_code != expected_code {
        return Err("the pairing codes do not match".to_owned());
    }
    let result = TrustedPeerInfo {
        device_id: peer.device_id.clone(),
        certificate_fingerprint: peer.certificate_fingerprint.clone(),
        status: "trusted".to_owned(),
    };
    let mut peers = state
        .peers
        .lock()
        .map_err(|_| "trusted peers are temporarily unavailable".to_owned())?;
    peers.insert(peer);
    state
        .peer_store
        .write_peers(&peers)
        .map_err(|error| error.to_string())?;
    state
        .endpoint
        .set_trusted_peers(&state.identity, &state.certificate, &peers.trusted_peers())
        .map_err(|error| error.to_string())?;
    Ok(result)
}
#[tauri::command]
async fn begin_pairing(
    address: String,
    pairing_port: u16,
    state: State<'_, AppState>,
) -> Result<PairingRequest, String> {
    let address = format!("{address}:{pairing_port}")
        .parse()
        .map_err(|_| "the discovered pairing address is invalid".to_owned())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is unavailable".to_owned())?
        .as_secs() as i64;
    let local = PairingEnvelope::create(&state.identity, &state.certificate, now);
    let connection = state
        .pairing_endpoint
        .connect(address, "linkdrop", &state.identity, &state.certificate)
        .await
        .map_err(|error| error.to_string())?;
    let remote = initiate_pairing_exchange(&connection, &local)
        .await
        .map_err(|error| error.to_string())?;
    let (_, verification_code) = verify_pairing_envelope(&local, &remote, b"linkdrop-pair/1", now)
        .map_err(|error| error.to_string())?;
    connection.close(0u32.into(), b"pairing exchange complete");
    Ok(PairingRequest {
        local,
        remote,
        verification_code,
    })
}
#[tauri::command]
fn read_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    state
        .settings
        .lock()
        .map(|s| s.clone())
        .map_err(|_| "settings are temporarily unavailable".to_owned())
}
#[tauri::command]
fn update_settings(settings: Settings, state: State<'_, AppState>) -> Result<(), String> {
    let mut current = state
        .settings
        .lock()
        .map_err(|_| "settings are temporarily unavailable".to_owned())?;
    *current = settings;
    let config = DiscoveryConfig {
        device_id: state.device_id.clone(),
        display_name: current.display_name.clone(),
        discoverable: current.discoverable,
        transport_port: state
            .endpoint
            .local_addr()
            .map_err(|error| error.to_string())?
            .port(),
        pairing_port: state
            .pairing_endpoint
            .local_addr()
            .map_err(|error| error.to_string())?
            .port(),
    };
    state
        .discovery
        .start(config)
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
fn start_discovery(state: State<'_, AppState>) -> Result<(), String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "settings are temporarily unavailable".to_owned())?
        .clone();
    state
        .discovery
        .start(DiscoveryConfig {
            device_id: state.device_id.clone(),
            display_name: settings.display_name,
            discoverable: settings.discoverable,
            transport_port: state
                .endpoint
                .local_addr()
                .map_err(|error| error.to_string())?
                .port(),
            pairing_port: state
                .pairing_endpoint
                .local_addr()
                .map_err(|error| error.to_string())?
                .port(),
        })
        .map_err(|error| error.to_string())
}
#[tauri::command]
fn stop_discovery(state: State<'_, AppState>) {
    state.discovery.stop();
}
#[tauri::command]
fn nearby_devices(state: State<'_, AppState>) -> Vec<Device> {
    let peers = match state.peers.lock() {
        Ok(peers) => peers,
        Err(_) => return state.discovery.snapshot(),
    };
    state
        .discovery
        .snapshot()
        .into_iter()
        .map(|mut device| {
            if let Some(peer) = peers.get(&device.id) {
                device.trust_status = match peer.status {
                    TrustedPeerStatus::Trusted => TrustStatus::Trusted,
                    TrustedPeerStatus::Blocked => TrustStatus::Blocked,
                };
            }
            device
        })
        .collect()
}

#[tauri::command]
fn list_transfers(state: State<'_, AppState>) -> Result<Vec<TransferInfo>, String> {
    let mut transfers = state
        .transfers
        .lock()
        .map_err(|_| "transfer state is temporarily unavailable".to_owned())?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    transfers.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    Ok(transfers)
}

#[tauri::command]
async fn send_transfer(
    file_path: String,
    recipient_id: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<TransferInfo, String> {
    let source = PathBuf::from(file_path);
    let metadata = tokio::fs::metadata(&source)
        .await
        .map_err(|error| format!("could not read selected file: {error}"))?;
    if !metadata.is_file() {
        return Err("only regular files can be transferred".to_owned());
    }
    let filename = source
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "the selected file needs a valid Unicode filename".to_owned())?
        .to_owned();
    let recipient = state
        .discovery
        .snapshot()
        .into_iter()
        .find(|device| device.id == recipient_id)
        .ok_or_else(|| "recipient is no longer discoverable on this network".to_owned())?;
    let address: IpAddr = recipient
        .transport_address
        .as_deref()
        .ok_or_else(|| "recipient has no reachable transfer endpoint".to_owned())?
        .parse()
        .map_err(|_| "recipient transfer endpoint has an invalid address".to_owned())?;
    let peer = state
        .peers
        .lock()
        .map_err(|_| "trusted peers are temporarily unavailable".to_owned())?
        .get(&recipient_id)
        .filter(|peer| peer.status == TrustedPeerStatus::Trusted)
        .cloned()
        .ok_or_else(|| "only paired, trusted devices can receive files".to_owned())?;

    let id = new_transfer_id(&state);
    let transfer = TransferInfo {
        id: id.clone(),
        sender_device_id: state.identity.device_id(),
        receiver_device_id: recipient_id,
        filename: filename.clone(),
        total_bytes: metadata.len(),
        transferred_bytes: 0,
        status: TransferStatus::Pending,
        created_at: unix_timestamp()?.to_string(),
        direction: "sending".to_owned(),
        saved_path: None,
        error: None,
    };
    publish_transfer(&app, &state, transfer.clone());

    let endpoint = state.endpoint.clone();
    let identity = Arc::clone(&state.identity);
    let certificate = state.certificate.clone();
    let transfer_app = app.clone();
    let socket_address = SocketAddr::new(address, recipient.transport_port);
    tauri::async_runtime::spawn(async move {
        update_transfer(&transfer_app, &id, |transfer| {
            transfer.status = TransferStatus::Connecting
        });
        let result = async {
            let connection = endpoint
                .connect(socket_address, "linkdrop", &identity, &certificate, peer)
                .await
                .map_err(|error| error.to_string())?;
            let offer = TransferOffer {
                transfer_id: id.clone(),
                filename,
                total_bytes: metadata.len(),
            };
            update_transfer(&transfer_app, &id, |transfer| {
                transfer.status = TransferStatus::AwaitingApproval
            });
            let decision = request_transfer(&connection, offer.clone())
                .await
                .map_err(|error| error.to_string())?;
            if !decision.accepted {
                update_transfer(&transfer_app, &id, |transfer| {
                    transfer.status = TransferStatus::Cancelled
                });
                connection.close(0u32.into(), b"recipient rejected transfer");
                return Ok::<(), String>(());
            }
            update_transfer(&transfer_app, &id, |transfer| {
                transfer.status = TransferStatus::Transferring
            });
            let progress_app = transfer_app.clone();
            send_file(&connection, &source, &offer, move |progress| {
                update_transfer(&progress_app, &progress.transfer_id, |transfer| {
                    transfer.transferred_bytes = progress.transferred_bytes;
                    transfer.total_bytes = progress.total_bytes;
                });
            })
            .await
            .map_err(|error| error.to_string())?;
            update_transfer(&transfer_app, &id, |transfer| {
                transfer.transferred_bytes = transfer.total_bytes;
                transfer.status = TransferStatus::Completed;
            });
            connection.close(0u32.into(), b"transfer complete");
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(transfer_id = %id, %error, "outgoing transfer failed");
            update_transfer(&transfer_app, &id, |transfer| {
                transfer.status = TransferStatus::Failed;
                transfer.error = Some(error);
            });
        }
    });
    Ok(transfer)
}

#[tauri::command]
async fn decide_incoming_transfer(
    transfer_id: String,
    accept: bool,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut pending = state
        .pending_inbound
        .lock()
        .map_err(|_| "incoming offers are temporarily unavailable".to_owned())?
        .remove(&transfer_id)
        .ok_or_else(|| "this incoming offer is no longer awaiting a decision".to_owned())?;
    let downloads = if accept {
        match app.path().download_dir() {
            Ok(directory) => Some(directory),
            Err(error) => {
                let error = format!("could not resolve the Downloads folder: {error}");
                pending
                    .connection
                    .close(0u32.into(), b"Downloads folder unavailable");
                update_transfer(&app, &transfer_id, |transfer| {
                    transfer.status = TransferStatus::Failed;
                    transfer.error = Some(error.clone());
                });
                return Err(error);
            }
        }
    } else {
        None
    };
    if let Err(error) =
        send_transfer_decision(&mut pending.decision_stream, &pending.offer, accept).await
    {
        let error = error.to_string();
        update_transfer(&app, &transfer_id, |transfer| {
            transfer.status = TransferStatus::Failed;
            transfer.error = Some(error.clone());
        });
        return Err(error);
    }
    if !accept {
        pending
            .connection
            .close(0u32.into(), b"recipient rejected transfer");
        update_transfer(&app, &transfer_id, |transfer| {
            transfer.status = TransferStatus::Cancelled;
        });
        return Ok(());
    }
    let downloads = downloads.expect("Downloads folder is resolved before accepting a transfer");
    update_transfer(&app, &transfer_id, |transfer| {
        transfer.status = TransferStatus::Transferring;
    });
    tauri::async_runtime::spawn(async move {
        let offer = pending.offer;
        let progress_app = app.clone();
        let result = receive_file(&pending.connection, &downloads, &offer, move |progress| {
            update_transfer(&progress_app, &progress.transfer_id, |transfer| {
                transfer.transferred_bytes = progress.transferred_bytes;
                transfer.total_bytes = progress.total_bytes;
            });
        })
        .await;
        match result {
            Ok(path) => update_transfer(&app, &transfer_id, |transfer| {
                transfer.transferred_bytes = transfer.total_bytes;
                transfer.status = TransferStatus::Completed;
                transfer.saved_path = Some(path.display().to_string());
            }),
            Err(error) => {
                let error = error.to_string();
                tracing::warn!(transfer_id = %transfer_id, %error, "incoming transfer failed");
                update_transfer(&app, &transfer_id, |transfer| {
                    transfer.status = TransferStatus::Failed;
                    transfer.error = Some(error);
                });
            }
        }
        pending.connection.close(0u32.into(), b"transfer complete");
    });
    Ok(())
}

fn ensure_identity() -> DeviceIdentity {
    let entry = match keyring::Entry::new("org.linkdrop.desktop", "device-identity") {
        Ok(entry) => entry,
        Err(error) => {
            tracing::warn!(%error, "secure credential store unavailable; device identity will not persist");
            return DeviceIdentity::generate();
        }
    };
    match entry.get_secret() {
        Ok(bytes) if bytes.len() == 32 => match bytes.as_slice().try_into() {
            Ok(secret) => {
                let identity = DeviceIdentity::from_bytes(secret);
                let id = identity.device_id();
                tracing::info!(device_id = %id, "loaded device identity");
                return identity;
            }
            Err(_) => tracing::warn!("stored device identity has invalid length"),
        },
        Ok(_) | Err(keyring::Error::NoEntry) => {
            let identity = DeviceIdentity::generate();
            if let Err(error) = entry.set_secret(&identity.secret_bytes()) {
                tracing::warn!(%error, "could not persist device identity in secure credential store");
            } else {
                tracing::info!(device_id = %identity.device_id(), "created device identity");
            }
            return identity;
        }
        Err(error) => tracing::warn!(%error, "could not access secure credential store"),
    }
    DeviceIdentity::generate()
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("linkdrop=info,warn")
        .init();
    let identity = Arc::new(ensure_identity());
    tauri::Builder::default()
        .setup(move |app| {
            let app_config = app.path().app_config_dir()?;
            let certificate = DeviceCertificate::load_or_create(
                &app_config.join("device-certificate.der"),
                &identity,
            )?;
            let peer_store = JsonTrustedPeerStore::new(app_config.join("trusted-peers.json"));
            let peers = peer_store.read_peers()?;
            let endpoint = SecureEndpoint::bind(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                &identity,
                &certificate,
                &peers.trusted_peers(),
            )?;
            let pairing_endpoint = PairingEndpoint::bind(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                &identity,
                &certificate,
            )?;
            let pairing_listener = pairing_endpoint.clone();
            let pairing_identity = Arc::clone(&identity);
            let pairing_certificate = certificate.clone();
            tauri::async_runtime::spawn(async move {
                while let Ok(Some(connection)) = pairing_listener.accept().await {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_secs() as i64)
                        .unwrap_or_default();
                    let local =
                        PairingEnvelope::create(&pairing_identity, &pairing_certificate, now);
                    if let Err(error) = respond_to_pairing_exchange(&connection, &local).await {
                        tracing::warn!(%error, "pairing exchange failed");
                    }
                    connection.close(0u32.into(), b"pairing exchange complete");
                }
            });
            let device_id = identity.device_id();
            let handle = app.handle().clone();
            let discovery = DiscoveryEngine::new(move |event: DiscoveryEvent| {
                if let Err(error) = handle.emit("discovery-event", event) {
                    tracing::warn!(%error, "failed to emit discovery event");
                }
            });
            app.manage(AppState {
                settings: Mutex::new(Settings::default()),
                device_id,
                identity,
                certificate,
                peers: Mutex::new(peers),
                peer_store,
                endpoint,
                pairing_endpoint,
                discovery,
                transfers: Mutex::new(HashMap::new()),
                pending_inbound: Mutex::new(HashMap::new()),
                next_transfer_id: AtomicU64::new(1),
            });
            let transfer_listener = app.state::<AppState>().endpoint.clone();
            let transfer_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let connection = match transfer_listener.accept().await {
                        Ok(Some(connection)) => connection,
                        Ok(None) => break,
                        Err(error) => {
                            tracing::warn!(%error, "incoming QUIC connection failed authentication");
                            continue;
                        }
                    };
                    let app = transfer_handle.clone();
                    tauri::async_runtime::spawn(async move {
                        match receive_transfer_offer(&connection).await {
                            Ok((offer, decision_stream)) => {
                                let state = app.state::<AppState>();
                                let transfer = TransferInfo {
                                    id: offer.transfer_id.clone(),
                                    sender_device_id: "trusted-peer".to_owned(),
                                    receiver_device_id: state.identity.device_id(),
                                    filename: offer.filename.clone(),
                                    total_bytes: offer.total_bytes,
                                    transferred_bytes: 0,
                                    status: TransferStatus::AwaitingApproval,
                                    created_at: unix_timestamp().unwrap_or_default().to_string(),
                                    direction: "receiving".to_owned(),
                                    saved_path: None,
                                    error: None,
                                };
                                let Ok(mut pending) = state.pending_inbound.lock() else {
                                    connection.close(0u32.into(), b"receiver unavailable");
                                    return;
                                };
                                if pending.contains_key(&offer.transfer_id) {
                                    connection.close(0u32.into(), b"duplicate transfer id");
                                    return;
                                }
                                pending.insert(
                                    offer.transfer_id.clone(),
                                    PendingInboundTransfer {
                                        offer,
                                        connection,
                                        decision_stream,
                                    },
                                );
                                drop(pending);
                                publish_transfer(&app, &state, transfer);
                            }
                            Err(error) => {
                                tracing::warn!(%error, "incoming transfer offer failed");
                                connection.close(0u32.into(), b"invalid transfer offer");
                            }
                        }
                    });
                }
            });
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            get_application_information,
            get_local_device_display_name,
            get_transport_information,
            list_trusted_peers,
            set_peer_trust,
            approve_pairing,
            begin_pairing,
            read_settings,
            update_settings,
            start_discovery,
            stop_discovery,
            nearby_devices,
            list_transfers,
            send_transfer,
            decide_incoming_transfer
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| tracing::error!(%error, "failed to launch Linkdrop"));
}
