//! Discovery-only local-network mDNS. Advertisements are untrusted hints.
use chrono::{Duration, Utc};
use linkdrop_core::{Device, DiscoveryStatus, TrustStatus};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration as StdDuration,
};

pub const SERVICE_TYPE: &str = "_linkdrop._udp.local.";
const VERSION: &str = "1";
const MAX_DEVICES: usize = 128;
const STALE_SECONDS: i64 = 45;

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub device_id: String,
    pub display_name: String,
    pub discoverable: bool,
    /// UDP port of the local mutually-authenticated QUIC endpoint.
    pub transport_port: u16,
    pub pairing_port: u16,
}
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryState {
    Stopped,
    Starting,
    Searching,
    Disabled,
    Error,
}
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "payload")]
pub enum DiscoveryEvent {
    DeviceAdded(Device),
    DeviceUpdated(Device),
    DeviceRemoved {
        id: String,
    },
    Status {
        state: DiscoveryState,
        message: Option<String>,
    },
}
type Sink = Arc<dyn Fn(DiscoveryEvent) + Send + Sync>;

pub struct DiscoveryEngine {
    devices: Arc<Mutex<HashMap<String, Device>>>,
    names: Arc<Mutex<HashMap<String, String>>>,
    daemon: Mutex<Option<ServiceDaemon>>,
    running: Arc<AtomicBool>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
    sink: Sink,
}
impl DiscoveryEngine {
    pub fn new(sink: impl Fn(DiscoveryEvent) + Send + Sync + 'static) -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            names: Arc::new(Mutex::new(HashMap::new())),
            daemon: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
            worker: Mutex::new(None),
            sink: Arc::new(sink),
        }
    }
    pub fn start(&self, config: DiscoveryConfig) -> Result<(), DiscoveryError> {
        self.stop();
        if !config.discoverable {
            (self.sink)(DiscoveryEvent::Status {
                state: DiscoveryState::Disabled,
                message: None,
            });
            return Ok(());
        }
        if !valid_id(&config.device_id)
            || !valid_text(&config.display_name, 64)
            || config.transport_port == 0
            || config.pairing_port == 0
        {
            return Err(DiscoveryError::InvalidConfiguration);
        }
        (self.sink)(DiscoveryEvent::Status {
            state: DiscoveryState::Starting,
            message: None,
        });
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Network(e.to_string()))?;
        let pairing_port = config.pairing_port.to_string();
        let props = [
            ("id", config.device_id.as_str()),
            ("name", config.display_name.as_str()),
            ("os", std::env::consts::OS),
            ("version", VERSION),
            ("capabilities", "discovery"),
            ("pairing_port", pairing_port.as_str()),
        ];
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &format!("Linkdrop-{}", config.device_id),
            &format!("linkdrop-{}.local.", config.device_id),
            "",
            config.transport_port,
            &props[..],
        )
        .map_err(|e| DiscoveryError::Network(e.to_string()))?
        .enable_addr_auto();
        daemon
            .register(service)
            .map_err(|e| DiscoveryError::Network(e.to_string()))?;
        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Network(e.to_string()))?;
        self.running.store(true, Ordering::Release);
        let devices = Arc::clone(&self.devices);
        let names = Arc::clone(&self.names);
        let running = Arc::clone(&self.running);
        let sink = Arc::clone(&self.sink);
        let local_id = config.device_id;
        let worker = thread::spawn(move || {
            sink(DiscoveryEvent::Status {
                state: DiscoveryState::Searching,
                message: None,
            });
            while running.load(Ordering::Acquire) {
                if let Ok(event) = receiver.recv_timeout(StdDuration::from_secs(1)) {
                    match event {
                        ServiceEvent::ServiceResolved(info) => {
                            if let Some(device) = parse(&info, &local_id) {
                                let fullname = info.get_fullname().to_owned();
                                let id = device.id.clone();
                                let event = devices.lock().ok().and_then(|mut all| {
                                    if all.len() >= MAX_DEVICES && !all.contains_key(&id) {
                                        None
                                    } else {
                                        Some(if all.insert(id.clone(), device.clone()).is_some() {
                                            DiscoveryEvent::DeviceUpdated(device)
                                        } else {
                                            DiscoveryEvent::DeviceAdded(device)
                                        })
                                    }
                                });
                                if let Some(event) = event {
                                    if let Ok(mut by_name) = names.lock() {
                                        by_name.insert(fullname, id);
                                    }
                                    sink(event);
                                }
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            remove(&devices, &names, &sink, &fullname)
                        }
                        _ => {}
                    }
                }
                stale(&devices, &names, &sink);
            }
        });
        if let Ok(mut slot) = self.daemon.lock() {
            *slot = Some(daemon);
        }
        if let Ok(mut slot) = self.worker.lock() {
            *slot = Some(worker);
        }
        Ok(())
    }
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
        if let Ok(mut daemon) = self.daemon.lock() {
            if let Some(active) = daemon.take() {
                let _ = active.shutdown();
            }
        }
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(handle) = worker.take() {
                let _ = handle.join();
            }
        }
        if let Ok(mut all) = self.devices.lock() {
            all.clear();
        }
        if let Ok(mut all) = self.names.lock() {
            all.clear();
        }
        (self.sink)(DiscoveryEvent::Status {
            state: DiscoveryState::Stopped,
            message: None,
        });
    }
    pub fn snapshot(&self) -> Vec<Device> {
        self.devices
            .lock()
            .map(|all| all.values().cloned().collect())
            .unwrap_or_default()
    }
}
impl Drop for DiscoveryEngine {
    fn drop(&mut self) {
        self.stop();
    }
}
fn remove(
    devices: &Arc<Mutex<HashMap<String, Device>>>,
    names: &Arc<Mutex<HashMap<String, String>>>,
    sink: &Sink,
    fullname: &str,
) {
    let id = names.lock().ok().and_then(|mut n| n.remove(fullname));
    if let Some(id) = id {
        if devices
            .lock()
            .ok()
            .and_then(|mut d| d.remove(&id))
            .is_some()
        {
            sink(DiscoveryEvent::DeviceRemoved { id });
        }
    }
}
fn stale(
    devices: &Arc<Mutex<HashMap<String, Device>>>,
    names: &Arc<Mutex<HashMap<String, String>>>,
    sink: &Sink,
) {
    let cutoff = Utc::now() - Duration::seconds(STALE_SECONDS);
    let expired = devices
        .lock()
        .map(|all| {
            all.iter()
                .filter_map(|(id, d)| {
                    d.last_seen
                        .filter(|seen| *seen < cutoff)
                        .map(|_| id.clone())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for id in expired {
        if let Ok(mut all) = devices.lock() {
            all.remove(&id);
        }
        if let Ok(mut all) = names.lock() {
            all.retain(|_, v| v != &id);
        }
        sink(DiscoveryEvent::DeviceRemoved { id });
    }
}
fn parse(service: &ServiceInfo, local: &str) -> Option<Device> {
    let id = service.get_property_val_str("id")?.to_owned();
    let name = service.get_property_val_str("name")?.to_owned();
    let os = service.get_property_val_str("os")?.to_owned();
    let transport_address = service
        .get_addresses()
        .iter()
        .map(ToString::to_string)
        .min()?;
    let pairing_port = service
        .get_property_val_str("pairing_port")?
        .parse::<u16>()
        .ok()?;
    if id == local
        || !valid_id(&id)
        || !valid_text(&name, 64)
        || !valid_text(&os, 32)
        || service.get_property_val_str("version")? != VERSION
        || !valid_text(service.get_property_val_str("capabilities")?, 128)
        || service.get_port() == 0
        || pairing_port == 0
    {
        return None;
    }
    Some(Device {
        id,
        display_name: name,
        operating_system: os,
        discovery_status: DiscoveryStatus::Found,
        trust_status: TrustStatus::Unknown,
        transport_address: Some(transport_address),
        transport_port: service.get_port(),
        pairing_port,
        last_seen: Some(Utc::now()),
    })
}
fn valid_id(value: &str) -> bool {
    value.len() == 24 && value.bytes().all(|v| v.is_ascii_hexdigit())
}
fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.chars().all(|v| !v.is_control())
}
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("invalid discovery configuration")]
    InvalidConfiguration,
    #[error("mDNS error: {0}")]
    Network(String),
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_input() {
        assert!(valid_id("aabbccddeeff001122334455"));
        assert!(!valid_id("x"));
        assert!(!valid_text("bad\n", 64));
    }
    #[test]
    fn disabled_engine_has_no_devices() {
        let engine = DiscoveryEngine::new(|_| {});
        engine
            .start(DiscoveryConfig {
                device_id: "aabbccddeeff001122334455".into(),
                display_name: "test".into(),
                discoverable: false,
                transport_port: 1,
                pairing_port: 2,
            })
            .unwrap_or(());
        assert!(engine.snapshot().is_empty());
    }
}
