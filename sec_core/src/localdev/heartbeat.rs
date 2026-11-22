//! LocalDev Heartbeat & Remote Service Discovery (RSD) Keepalive
//! Keeps the connection to `lockdownd` alive indefinitely via `com.apple.mobile.heartbeat`
//! Supports iOS 15.0 - iOS 27.2.1

use super::pairing::PairingFile;
use super::tunnel::{read_plist, send_plist, LockdownClient, DEFAULT_LOCALDEV_IP, DEFAULT_LOCKDOWN_PORT};
use super::plist_util::PlistValue;
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct HeartbeatService {
    is_running: Arc<AtomicBool>,
}

impl HeartbeatService {
    pub fn new() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts heartbeat worker in a dedicated background thread
    pub fn start(&self, pairing: PairingFile, ip: String, port: u16) {
        if self.is_running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }

        let running = Arc::clone(&self.is_running);
        std::thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                match run_heartbeat_session(&pairing, &ip, port, &running) {
                    Ok(_) => {
                        // Clean exit or reconnect requested
                    }
                    Err(e) => {
                        // Connection dropped, wait 5s before reconnecting
                        std::thread::sleep(Duration::from_secs(5));
                    }
                }
            }
        });
    }

    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    pub fn is_active(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }
}

fn run_heartbeat_session(
    pairing: &PairingFile,
    ip: &str,
    port: u16,
    running: &Arc<AtomicBool>,
) -> Result<(), String> {
    // 1. Connect to lockdown
    let mut lockdown = LockdownClient::connect(ip, port, pairing)?;

    // 2. Start heartbeat service
    let (mut sock, _service_port, _ssl) = lockdown.start_service("com.apple.mobile.heartbeat")?;
    sock.set_read_timeout(Some(Duration::from_secs(20))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(10))).ok();

    // 3. Heartbeat Loop: Reply Marco -> Polo
    while running.load(Ordering::SeqCst) {
        match read_plist(&mut sock) {
            Ok(msg) => {
                let cmd = msg.get_string("Command").unwrap_or_default();
                if cmd == "Marco" {
                    let mut polo = HashMap::new();
                    polo.insert("Command".to_string(), PlistValue::String("Polo".to_string()));
                    send_plist(&mut sock, &polo)?;
                } else if cmd == "Polo" {
                    // Ping acknowledged
                }
            }
            Err(e) => {
                // If read timed out, actively send Marco to probe connection
                let mut ping = HashMap::new();
                ping.insert("Command".to_string(), PlistValue::String("Marco".to_string()));
                if let Err(_) = send_plist(&mut sock, &ping) {
                    return Err("Heartbeat disconnected".to_string());
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}

/// Checks if Remote Service Discovery (RSD) port (58783) is listening
pub fn is_rsd_tunnel_active(ip: &str) -> bool {
    LockdownClient::test_tunnel_reachability(ip, 58783)
}
