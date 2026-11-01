#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use linkdrop_core::{Device, TrustStatus};
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
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
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
    remote: PairingEnvelope,
    verification_code: String,
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
    remote: PairingEnvelope,
    transport_binding: Vec<u8>,
    verification_code: String,
    state: State<'_, AppState>,
) -> Result<TrustedPeerInfo, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is unavailable".to_owned())?
        .as_secs() as i64;
    let local = PairingEnvelope::create(&state.identity, &state.certificate, now);
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
            nearby_devices
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| tracing::error!(%error, "failed to launch Linkdrop"));
}
