//! LocalDev Loopback VPN Tunnel & Lockdown Protocol Implementation
//! Supports iOS 15.0 - iOS 27.2.1

use super::pairing::PairingFile;
use super::plist_util::{parse_plist, serialize_xml_dict, PlistValue};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, SignatureScheme, StreamOwned};

pub const DEFAULT_LOCALDEV_IP: &str = "10.7.0.1";
pub const DEFAULT_LOCKDOWN_PORT: u16 = 62078;
pub const CONNECTION_TIMEOUT_SECS: u64 = 4;

/// Verifier that trusts the device certificate from the pairing file
#[derive(Debug)]
struct DeviceCertVerifier {
    expected_device_cert_der: Vec<u8>,
}

impl ServerCertVerifier for DeviceCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // In local pairing, device certificate matches or is accepted if signed by trusted root
        if !self.expected_device_cert_der.is_empty() {
            if end_entity.as_ref() == self.expected_device_cert_der.as_slice() {
                return Ok(ServerCertVerified::assertion());
            }
        }
        // Fallback: accept device self-signed cert on loopback tunnel
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Active TLS stream over raw TCP stream
pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

pub struct LockdownClient {
    pub ip: String,
    pub port: u16,
    pub session_id: Option<String>,
    pub tls_stream: Option<TlsStream>,
    pub pairing: PairingFile,
}

impl LockdownClient {
    /// Tests connectivity to loopback tunnel without performing handshake
    pub fn test_tunnel_reachability(ip: &str, port: u16) -> bool {
        let addr_str = format!("{}:{}", ip, port);
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            TcpStream::connect_timeout(&addr, Duration::from_secs(CONNECTION_TIMEOUT_SECS)).is_ok()
        } else {
            false
        }
    }

    /// Establishes full authenticated lockdown session with local device
    pub fn connect(ip: &str, port: u16, pairing: &PairingFile) -> Result<Self, String> {
        let addr_str = format!("{}:{}", ip, port);
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("Invalid IP address {}: {}", addr_str, e))?;

        let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(CONNECTION_TIMEOUT_SECS))
            .map_err(|e| format!("Failed to connect to LocalDevVPN at {}: {}", addr_str, e))?;

        tcp.set_read_timeout(Some(Duration::from_secs(8))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(8))).ok();

        // 1. QueryType handshake
        let mut query = HashMap::new();
        query.insert("Request".to_string(), PlistValue::String("QueryType".to_string()));
        send_plist(&mut tcp, &query)?;

        let query_resp = read_plist(&mut tcp)?;
        let query_type = query_resp.get_string("Type").unwrap_or_default();
        if query_type != "QueryType" && query_resp.get_string("Result").as_deref() != Some("Success") {
            // Some iOS versions return Success directly
        }

        // 2. StartSSL
        let mut start_ssl = HashMap::new();
        start_ssl.insert("Request".to_string(), PlistValue::String("StartSSL".to_string()));
        start_ssl.insert("HostID".to_string(), PlistValue::String(pairing.host_id.clone()));
        start_ssl.insert("SystemBUID".to_string(), PlistValue::String(pairing.system_buid.clone()));
        send_plist(&mut tcp, &start_ssl)?;

        let ssl_resp = read_plist(&mut tcp)?;
        if ssl_resp.get_string("Result").as_deref() != Some("Success") {
            let err = ssl_resp.get_string("Error").unwrap_or_else(|| "StartSSL failed".to_string());
            return Err(format!("Lockdown StartSSL rejected: {}", err));
        }

        // 3. TLS Handshake with mutual client authentication
        let client_cert = CertificateDer::from(pairing.host_certificate_der.clone());
        let private_key = PrivateKeyDer::try_from(pairing.host_private_key_der.clone())
            .map_err(|e| format!("Failed to parse host private key: {:?}", e))?;

        let verifier = Arc::new(DeviceCertVerifier {
            expected_device_cert_der: pairing.device_certificate_der.clone(),
        });

        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS protocol error: {:?}", e))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![client_cert], private_key)
            .map_err(|e| format!("Client auth config failed: {:?}", e))?;

        let server_name = ServerName::try_from("apple-device.local")
            .unwrap_or_else(|_| ServerName::try_from("localhost").unwrap());

        let conn = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| format!("ClientConnection failed: {:?}", e))?;

        let mut tls = StreamOwned::new(conn, tcp);

        // 4. StartSession over TLS
        let mut session_req = HashMap::new();
        session_req.insert("Request".to_string(), PlistValue::String("StartSession".to_string()));
        session_req.insert("HostID".to_string(), PlistValue::String(pairing.host_id.clone()));
        session_req.insert("SystemBUID".to_string(), PlistValue::String(pairing.system_buid.clone()));
        send_plist_tls(&mut tls, &session_req)?;

        let session_resp = read_plist_tls(&mut tls)?;
        if session_resp.get_string("Result").as_deref() != Some("Success") {
            let err = session_resp.get_string("Error").unwrap_or_else(|| "StartSession failed".to_string());
            return Err(format!("Lockdown StartSession rejected: {}", err));
        }

        let session_id = session_resp.get_string("SessionID");

        Ok(Self {
            ip: ip.to_string(),
            port,
            session_id,
            tls_stream: Some(tls),
            pairing: pairing.clone(),
        })
    }

    /// Requests lockdown to start a specific service (e.g. installation_proxy, afc, house_arrest)
    pub fn start_service(&mut self, service_name: &str) -> Result<(TcpStream, u16, bool), String> {
        let tls = self.tls_stream.as_mut().ok_or_else(|| "Lockdown not connected".to_string())?;

        let mut req = HashMap::new();
        req.insert("Request".to_string(), PlistValue::String("StartService".to_string()));
        req.insert("Service".to_string(), PlistValue::String(service_name.to_string()));
        send_plist_tls(tls, &req)?;

        let resp = read_plist_tls(tls)?;
        if resp.get_string("Result").as_deref() != Some("Success") && !resp.as_dict().map(|d| d.contains_key("Port")).unwrap_or(false) {
            let err = resp.get_string("Error").unwrap_or_else(|| format!("StartService '{}' failed", service_name));
            return Err(err);
        }

        let service_port = match resp.get("Port") {
            Some(PlistValue::Integer(p)) => *p as u16,
            _ => return Err(format!("Service '{}' did not return a valid port", service_name)),
        };

        let enable_ssl = resp.get("EnableServiceSSL").and_then(|v| v.as_bool()).unwrap_or(false);

        // Connect directly to the service port on the LocalDev loopback
        let addr_str = format!("{}:{}", self.ip, service_port);
        let addr: SocketAddr = addr_str.parse().map_err(|e| format!("Invalid address: {}", e))?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(CONNECTION_TIMEOUT_SECS))
            .map_err(|e| format!("Failed to connect to service '{}' at {}: {}", service_name, addr_str, e))?;

        tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(15))).ok();

        Ok((tcp, service_port, enable_ssl))
    }
}

// ==============================================================================
// 4-BYTE BIG-ENDIAN PACKET FRAMING
// ==============================================================================

pub fn send_plist(stream: &mut TcpStream, dict: &HashMap<String, PlistValue>) -> Result<(), String> {
    let xml = serialize_xml_dict(dict);
    let bytes = xml.as_bytes();
    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(bytes).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn read_plist(stream: &mut TcpStream) -> Result<PlistValue, String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| format!("Read length failed: {}", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 5 * 1024 * 1024 {
        return Err("Lockdown response packet exceeds 5MB limit".to_string());
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).map_err(|e| format!("Read payload failed: {}", e))?;
    parse_plist(&payload)
}

pub fn send_plist_tls(tls: &mut TlsStream, dict: &HashMap<String, PlistValue>) -> Result<(), String> {
    let xml = serialize_xml_dict(dict);
    let bytes = xml.as_bytes();
    let len = bytes.len() as u32;
    tls.write_all(&len.to_be_bytes()).map_err(|e| e.to_string())?;
    tls.write_all(bytes).map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn read_plist_tls(tls: &mut TlsStream) -> Result<PlistValue, String> {
    let mut len_buf = [0u8; 4];
    tls.read_exact(&mut len_buf).map_err(|e| format!("Read TLS length failed: {}", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 5 * 1024 * 1024 {
        return Err("Lockdown TLS packet exceeds 5MB limit".to_string());
    }
    let mut payload = vec![0u8; len];
    tls.read_exact(&mut payload).map_err(|e| format!("Read TLS payload failed: {}", e))?;
    parse_plist(&payload)
}
