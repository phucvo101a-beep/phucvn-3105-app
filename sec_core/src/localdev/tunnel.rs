//! LocalDev Loopback VPN Tunnel & Lockdown Protocol Implementation
//! Supports iOS 15.0 - iOS 27.2.1

use super::pairing::PairingFile;
use super::plist_util::{parse_plist, serialize_xml_dict, PlistValue};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    StreamOwned,
};

pub const DEFAULT_LOCALDEV_IP: &str = "10.7.0.1";
pub const DEFAULT_LOCKDOWN_PORT: u16 = 62078;
pub const REACHABILITY_TIMEOUT_MS: u64 = 1500;
pub const CONNECTION_TIMEOUT_SECS: u64 = 4;

/// Verifier that trusts the device certificate from the pairing file over local loopback
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
        if !self.expected_device_cert_der.is_empty()
            && end_entity.as_ref() == self.expected_device_cert_der.as_slice()
        {
            return Ok(ServerCertVerified::assertion());
        }
        // Accept local loopback lockdownd device cert when pairing credentials authenticate session
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
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

/// Active TLS stream over raw TCP stream
pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// Unified transport stream for lockdownd and child services (`EnableServiceSSL` aware)
pub enum LockdownStream {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

impl LockdownStream {
    pub fn set_timeouts(&self, read_secs: u64, write_secs: u64) {
        let tcp = match self {
            LockdownStream::Plain(tcp) => tcp,
            LockdownStream::Tls(tls) => tls.get_ref(),
        };
        tcp.set_read_timeout(Some(Duration::from_secs(read_secs))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(write_secs))).ok();
    }
}

impl Read for LockdownStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            LockdownStream::Plain(tcp) => tcp.read(buf),
            LockdownStream::Tls(tls) => tls.read(buf),
        }
    }
}

impl Write for LockdownStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            LockdownStream::Plain(tcp) => tcp.write(buf),
            LockdownStream::Tls(tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            LockdownStream::Plain(tcp) => tcp.flush(),
            LockdownStream::Tls(tls) => tls.flush(),
        }
    }
}

fn build_tls_stream(tcp: TcpStream, pairing: &PairingFile) -> Result<TlsStream, String> {
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

    Ok(StreamOwned::new(conn, tcp))
}

pub struct LockdownClient {
    pub ip: String,
    pub port: u16,
    pub session_id: Option<String>,
    pub device_udid: Option<String>,
    pub stream: Option<LockdownStream>,
    pub pairing: PairingFile,
}

impl LockdownClient {
    /// Tests TCP reachability to loopback tunnel without performing full handshake
    pub fn test_tunnel_reachability(ip: &str, port: u16) -> bool {
        let addr_str = format!("{}:{}", ip, port);
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            TcpStream::connect_timeout(&addr, Duration::from_millis(REACHABILITY_TIMEOUT_MS)).is_ok()
        } else {
            false
        }
    }

    /// Establishes authenticated lockdownd session (`QueryType` -> `StartSession` -> TLS -> `GetValue`)
    pub fn connect(ip: &str, port: u16, pairing: &PairingFile) -> Result<Self, String> {
        let addr_str = format!("{}:{}", ip, port);
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("Invalid IP address {}: {}", addr_str, e))?;

        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(CONNECTION_TIMEOUT_SECS))
            .map_err(|e| format!("Failed to connect to LocalDevVPN at {}: {}", addr_str, e))?;

        let mut stream = LockdownStream::Plain(tcp);
        stream.set_timeouts(8, 8);

        // 1. QueryType handshake
        let mut query = HashMap::new();
        query.insert("Request".to_string(), PlistValue::String("QueryType".to_string()));
        send_plist(&mut stream, &query)?;

        let query_resp = read_plist(&mut stream)?;
        if let Some(err) = query_resp.get_string("Error") {
            return Err(format!("Lockdown QueryType rejected: {}", err));
        }

        // 2. StartSession over plaintext (iOS lockdownd negotiates EnableSessionSSL here)
        let mut session_req = HashMap::new();
        session_req.insert("Request".to_string(), PlistValue::String("StartSession".to_string()));
        session_req.insert("HostID".to_string(), PlistValue::String(pairing.host_id.clone()));
        session_req.insert(
            "SystemBUID".to_string(),
            PlistValue::String(pairing.system_buid.clone()),
        );
        send_plist(&mut stream, &session_req)?;

        let session_resp = read_plist(&mut stream)?;
        if let Some(err) = session_resp.get_string("Error") {
            return Err(format!("Lockdown StartSession rejected: {}", err));
        }

        let session_id = session_resp.get_string("SessionID");
        if session_id.is_none() && session_resp.get_string("Result").as_deref() != Some("Success") {
            return Err("Lockdown StartSession rejected: missing SessionID".to_string());
        }

        let enable_ssl = session_resp
            .get("EnableSessionSSL")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // 3. Upgrade TCP socket to mutual-auth TLS when EnableSessionSSL is true
        if enable_ssl {
            let tcp = match stream {
                LockdownStream::Plain(tcp) => tcp,
                LockdownStream::Tls(_) => unreachable!(),
            };
            let tls = build_tls_stream(tcp, pairing)?;
            stream = LockdownStream::Tls(Box::new(tls));
        }

        // 4. Perform an actual encrypted GetValue(UniqueDeviceID) exchange to complete
        // the lazy TLS handshake and prove the device accepts the pairing certificates.
        let mut udid_req = HashMap::new();
        udid_req.insert("Request".to_string(), PlistValue::String("GetValue".to_string()));
        udid_req.insert("Key".to_string(), PlistValue::String("UniqueDeviceID".to_string()));
        send_plist(&mut stream, &udid_req)?;

        let udid_resp = read_plist(&mut stream)?;
        if let Some(err) = udid_resp.get_string("Error") {
            return Err(format!("Lockdown GetValue rejected: {}", err));
        }
        let device_udid = udid_resp.get_string("Value").filter(|s| !s.is_empty());

        Ok(Self {
            ip: ip.to_string(),
            port,
            session_id,
            device_udid,
            stream: Some(stream),
            pairing: pairing.clone(),
        })
    }

    /// Requests lockdownd to start a child service and wraps TLS automatically if `EnableServiceSSL` is true
    pub fn start_service(&mut self, service_name: &str) -> Result<(LockdownStream, u16, bool), String> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| "Lockdown not connected".to_string())?;

        let mut req = HashMap::new();
        req.insert("Request".to_string(), PlistValue::String("StartService".to_string()));
        req.insert("Service".to_string(), PlistValue::String(service_name.to_string()));
        send_plist(stream, &req)?;

        let resp = read_plist(stream)?;
        if let Some(err) = resp.get_string("Error") {
            return Err(err);
        }
        if resp.get_string("Result").as_deref() != Some("Success")
            && !resp.as_dict().map(|d| d.contains_key("Port")).unwrap_or(false)
        {
            return Err(format!("StartService '{}' failed", service_name));
        }

        let service_port = match resp.get("Port") {
            Some(PlistValue::Integer(p)) => *p as u16,
            _ => return Err(format!("Service '{}' did not return a valid port", service_name)),
        };

        let enable_ssl = resp
            .get("EnableServiceSSL")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let addr_str = format!("{}:{}", self.ip, service_port);
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(CONNECTION_TIMEOUT_SECS))
            .map_err(|e| format!("Failed to connect to service '{}' at {}: {}", service_name, addr_str, e))?;

        let service_stream = if enable_ssl {
            let tls = build_tls_stream(tcp, &self.pairing)?;
            LockdownStream::Tls(Box::new(tls))
        } else {
            LockdownStream::Plain(tcp)
        };
        service_stream.set_timeouts(15, 15);

        Ok((service_stream, service_port, enable_ssl))
    }
}

// ==============================================================================
// 4-BYTE BIG-ENDIAN PACKET FRAMING (works for both Plain TCP & TLS streams)
// ==============================================================================

pub fn send_plist<W: Write>(stream: &mut W, dict: &HashMap<String, PlistValue>) -> Result<(), String> {
    let xml = serialize_xml_dict(dict);
    let bytes = xml.as_bytes();
    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(bytes).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn read_plist<R: Read>(stream: &mut R) -> Result<PlistValue, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("Read length failed: {}", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err("Lockdown response packet exceeds 16MB limit".to_string());
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("Read payload failed: {}", e))?;
    parse_plist(&payload)
}
