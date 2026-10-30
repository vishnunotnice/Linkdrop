#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use linkdrop_core::Device;
use linkdrop_discovery::{DiscoveryConfig, DiscoveryEngine, DiscoveryEvent};
use linkdrop_identity::DeviceIdentity;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::{Emitter, Manager, State};

struct AppState {
    settings: Mutex<Settings>,
    device_id: String,
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

#[tauri::command]
fn get_application_information() -> AppInfo {
    AppInfo {
        name: "Linkdrop",
        version: env!("CARGO_PKG_VERSION"),
        phase: "Phase 2",
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
        })
        .map_err(|error| error.to_string())
}
#[tauri::command]
fn stop_discovery(state: State<'_, AppState>) {
    state.discovery.stop();
}
#[tauri::command]
fn nearby_devices(state: State<'_, AppState>) -> Vec<Device> {
    state.discovery.snapshot()
}

fn ensure_identity() -> String {
    let entry = match keyring::Entry::new("org.linkdrop.desktop", "device-identity") {
        Ok(entry) => entry,
        Err(error) => {
            tracing::warn!(%error, "secure credential store unavailable; device identity will not persist");
            return DeviceIdentity::generate().device_id();
        }
    };
    match entry.get_secret() {
        Ok(bytes) if bytes.len() == 32 => match bytes.as_slice().try_into() {
            Ok(secret) => {
                let id = DeviceIdentity::from_bytes(secret).device_id();
                tracing::info!(device_id = %id, "loaded device identity");
                return id;
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
        }
        Err(error) => tracing::warn!(%error, "could not access secure credential store"),
    }
    DeviceIdentity::generate().device_id()
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("linkdrop=info,warn")
        .init();
    let device_id = ensure_identity();
    tauri::Builder::default()
        .setup(move |app| {
            let handle = app.handle().clone();
            let discovery = DiscoveryEngine::new(move |event: DiscoveryEvent| {
                if let Err(error) = handle.emit("discovery-event", event) {
                    tracing::warn!(%error, "failed to emit discovery event");
                }
            });
            app.manage(AppState {
                settings: Mutex::new(Settings::default()),
                device_id: device_id.clone(),
                discovery,
            });
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            get_application_information,
            get_local_device_display_name,
            read_settings,
            update_settings,
            start_discovery,
            stop_discovery,
            nearby_devices
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| tracing::error!(%error, "failed to launch Linkdrop"));
}
