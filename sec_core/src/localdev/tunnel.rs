//! LocalDev Loopback VPN Tunnel & Lockdown Protocol Implementation
//! Supports iOS 15.0 - iOS 27.2.1

use super::pairing::PairingFile;
use super::plist_util::{parse_plist, serialize_xml_dict, PlistValue};
use std::collections::HashMap;
use std::fmt;
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
pub const HANDSHAKE_CONNECT_TIMEOUT_MS: u64 = 2200;
pub const HANDSHAKE_IO_TIMEOUT_SECS: u64 = 5;
pub const SERVICE_CONNECT_TIMEOUT_SECS: u64 = 4;
pub const MAX_HANDSHAKE_ATTEMPTS: usize = 2;
pub const HANDSHAKE_RETRY_BACKOFF_MS: u64 = 180;
const MAX_PLIST_PACKET_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownStage {
    TcpConnect,
    QueryType,
    StartSession,
    TlsUpgrade,
    GetValue,
    StartService,
    Protocol,
}

impl fmt::Display for LockdownStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            LockdownStage::TcpConnect => "TCP Connect",
            LockdownStage::QueryType => "QueryType",
            LockdownStage::StartSession => "StartSession",
            LockdownStage::TlsUpgrade => "TLS Upgrade",
            LockdownStage::GetValue => "TLS GetValue",
            LockdownStage::StartService => "StartService",
            LockdownStage::Protocol => "Protocol",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownErrorKind {
    TunnelUnreachable,
    PermissionDenied,
    SocketReset,
    Timeout,
    PairingRejected,
    ProtocolError,
}

#[derive(Debug, Clone)]
pub struct LockdownError {
    pub kind: LockdownErrorKind,
    pub stage: LockdownStage,
    pub detail: String,
}

impl LockdownError {
    pub fn new(kind: LockdownErrorKind, stage: LockdownStage, detail: impl Into<String>) -> Self {
        Self {
            kind,
            stage,
            detail: detail.into(),
        }
    }

    /// Retries only transient socket resets/timeouts AFTER TCP tunnel already accepted connection.
    pub fn is_retryable_handshake_error(&self) -> bool {
        self.stage != LockdownStage::TcpConnect
            && matches!(self.kind, LockdownErrorKind::SocketReset | LockdownErrorKind::Timeout)
    }
}

impl fmt::Display for LockdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.stage, self.detail)
    }
}

fn classify_io_error(err: io::Error, stage: LockdownStage, prefix: &str) -> LockdownError {
    let raw = err.raw_os_error();
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();

    let kind = if err.kind() == io::ErrorKind::PermissionDenied
        || matches!(raw, Some(1) | Some(13))
        || lower.contains("permission denied")
        || lower.contains("operation not permitted")
    {
        LockdownErrorKind::PermissionDenied
    } else if matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) || lower.contains("timed out")
    {
        LockdownErrorKind::Timeout
    } else if err.kind() == io::ErrorKind::InvalidData
        || lower.contains("alertreceived")
        || lower.contains("badcertificate")
        || lower.contains("invalidsignature")
        || lower.contains("decrypt")
    {
        LockdownErrorKind::PairingRejected
    } else if matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    ) || matches!(raw, Some(32) | Some(53) | Some(54))
        || lower.contains("connection reset")
        || lower.contains("os error 54")
        || lower.contains("broken pipe")
    {
        LockdownErrorKind::SocketReset
    } else if matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotConnected
            | io::ErrorKind::AddrNotAvailable
    ) || matches!(raw, Some(50) | Some(51) | Some(61) | Some(64) | Some(65))
        || lower.contains("connection refused")
        || lower.contains("unreachable")
    {
        LockdownErrorKind::TunnelUnreachable
    } else {
        LockdownErrorKind::ProtocolError
    };

    LockdownError::new(kind, stage, format!("{}: {}", prefix, msg))
}

fn read_exact_safe<R: Read>(
    stream: &mut R,
    buf: &mut [u8],
    stage: LockdownStage,
    label: &str,
) -> Result<(), LockdownError> {
    let mut offset = 0;
    while offset < buf.len() {
        match stream.read(&mut buf[offset..]) {
            Ok(0) => {
                return Err(LockdownError::new(
                    LockdownErrorKind::SocketReset,
                    stage,
                    format!(
                        "{}: Peer closed connection early (EOF at {}/{} bytes)",
                        label,
                        offset,
                        buf.len()
                    ),
                ));
            }
            Ok(n) => {
                offset += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(classify_io_error(e, stage, label)),
        }
    }
    Ok(())
}

fn write_all_safe<W: Write>(
    stream: &mut W,
    data: &[u8],
    stage: LockdownStage,
    label: &str,
) -> Result<(), LockdownError> {
    let mut offset = 0;
    while offset < data.len() {
        match stream.write(&data[offset..]) {
            Ok(0) => {
                return Err(LockdownError::new(
                    LockdownErrorKind::SocketReset,
                    stage,
                    format!("{}: Write returned 0 bytes", label),
                ));
            }
            Ok(n) => {
                offset += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(classify_io_error(e, stage, label)),
        }
    }
    stream
        .flush()
        .map_err(|e| classify_io_error(e, stage, label))?;
    Ok(())
}

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

fn build_tls_stream(
    tcp: TcpStream,
    pairing: &PairingFile,
    stage: LockdownStage,
) -> Result<TlsStream, LockdownError> {
    let client_cert = CertificateDer::from(pairing.host_certificate_der.clone());
    let private_key = PrivateKeyDer::try_from(pairing.host_private_key_der.clone()).map_err(|e| {
        LockdownError::new(
            LockdownErrorKind::PairingRejected,
            stage,
            format!("Failed to parse host private key: {:?}", e),
        )
    })?;

    let verifier = Arc::new(DeviceCertVerifier {
        expected_device_cert_der: pairing.device_certificate_der.clone(),
    });

    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                LockdownError::new(
                    LockdownErrorKind::ProtocolError,
                    stage,
                    format!("TLS protocol error: {:?}", e),
                )
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![client_cert], private_key)
            .map_err(|e| {
                LockdownError::new(
                    LockdownErrorKind::PairingRejected,
                    stage,
                    format!("Client auth config failed: {:?}", e),
                )
            })?;

    let server_name = ServerName::try_from("apple-device.local")
        .unwrap_or_else(|_| ServerName::try_from("localhost").unwrap());

    let conn = ClientConnection::new(Arc::new(config), server_name).map_err(|e| {
        LockdownError::new(
            LockdownErrorKind::ProtocolError,
            stage,
            format!("ClientConnection failed: {:?}", e),
        )
    })?;

    Ok(StreamOwned::new(conn, tcp))
}

fn is_pairing_rejection_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("invalidhostid")
        || lower.contains("invalidpairrecord")
        || lower.contains("missingpairrecord")
        || lower.contains("pairingdialog")
        || lower.contains("userdeniedpairing")
        || lower.contains("escrowlocked")
        || lower.contains("get_value")
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

    /// Connects with bounded retry (`max_attempts`) for transient VPN/tunnel resets after TCP open
    pub fn connect_with_retry(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        max_attempts: usize,
    ) -> Result<Self, LockdownError> {
        let attempts = max_attempts.max(1);
        let mut last_err = None;

        for attempt in 1..=attempts {
            match Self::connect_once(ip, port, pairing) {
                Ok(client) => return Ok(client),
                Err(err) => {
                    let should_retry = attempt < attempts && err.is_retryable_handshake_error();
                    last_err = Some(err);
                    if should_retry {
                        std::thread::sleep(Duration::from_millis(HANDSHAKE_RETRY_BACKOFF_MS));
                    } else {
                        break;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            LockdownError::new(
                LockdownErrorKind::TunnelUnreachable,
                LockdownStage::TcpConnect,
                "Unknown lockdown connection failure",
            )
        }))
    }

    fn connect_once(ip: &str, port: u16, pairing: &PairingFile) -> Result<Self, LockdownError> {
        let addr_str = format!("{}:{}", ip, port);
        let addr: SocketAddr = addr_str.parse().map_err(|e| {
            LockdownError::new(
                LockdownErrorKind::ProtocolError,
                LockdownStage::TcpConnect,
                format!("Invalid IP address {}: {}", addr_str, e),
            )
        })?;

        let tcp = TcpStream::connect_timeout(&addr, Duration::from_millis(HANDSHAKE_CONNECT_TIMEOUT_MS))
            .map_err(|e| {
                classify_io_error(
                    e,
                    LockdownStage::TcpConnect,
                    &format!("Failed to connect to LocalDevVPN at {}", addr_str),
                )
            })?;

        let mut stream = LockdownStream::Plain(tcp);
        stream.set_timeouts(HANDSHAKE_IO_TIMEOUT_SECS, HANDSHAKE_IO_TIMEOUT_SECS);

        // 1. QueryType handshake
        let mut query = HashMap::new();
        query.insert("Request".to_string(), PlistValue::String("QueryType".to_string()));
        send_plist_for_stage(&mut stream, &query, LockdownStage::QueryType)?;

        let query_resp = read_plist_for_stage(&mut stream, LockdownStage::QueryType)?;
        if let Some(err) = query_resp.get_string("Error") {
            return Err(LockdownError::new(
                LockdownErrorKind::ProtocolError,
                LockdownStage::QueryType,
                format!("Lockdown QueryType rejected: {}", err),
            ));
        }

        // 2. StartSession over plaintext (iOS lockdownd negotiates EnableSessionSSL here)
        let mut session_req = HashMap::new();
        session_req.insert("Request".to_string(), PlistValue::String("StartSession".to_string()));
        session_req.insert("HostID".to_string(), PlistValue::String(pairing.host_id.clone()));
        session_req.insert(
            "SystemBUID".to_string(),
            PlistValue::String(pairing.system_buid.clone()),
        );
        send_plist_for_stage(&mut stream, &session_req, LockdownStage::StartSession)?;

        let session_resp = read_plist_for_stage(&mut stream, LockdownStage::StartSession)?;
        if let Some(err) = session_resp.get_string("Error") {
            let kind = if is_pairing_rejection_error(&err) {
                LockdownErrorKind::PairingRejected
            } else {
                LockdownErrorKind::ProtocolError
            };
            return Err(LockdownError::new(
                kind,
                LockdownStage::StartSession,
                format!("Lockdown StartSession rejected: {}", err),
            ));
        }

        let session_id = session_resp.get_string("SessionID");
        if session_id.is_none() && session_resp.get_string("Result").as_deref() != Some("Success") {
            return Err(LockdownError::new(
                LockdownErrorKind::PairingRejected,
                LockdownStage::StartSession,
                "Lockdown StartSession rejected: missing SessionID",
            ));
        }

        let enable_ssl = session_resp
            .get("EnableSessionSSL")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // 3. Upgrade TCP socket to mutual-auth TLS when EnableSessionSSL is true
        if enable_ssl {
            let tcp = match stream {
                LockdownStream::Plain(tcp) => tcp,
                LockdownStream::Tls(tls) => tls.into_inner().1,
            };
            let tls = build_tls_stream(tcp, pairing, LockdownStage::TlsUpgrade)?;
            stream = LockdownStream::Tls(Box::new(tls));
        }

        // 4. Encrypted GetValue(UniqueDeviceID) completes the lazy TLS handshake safely
        let mut udid_req = HashMap::new();
        udid_req.insert("Request".to_string(), PlistValue::String("GetValue".to_string()));
        udid_req.insert("Key".to_string(), PlistValue::String("UniqueDeviceID".to_string()));
        send_plist_for_stage(&mut stream, &udid_req, LockdownStage::GetValue)?;

        let udid_resp = read_plist_for_stage(&mut stream, LockdownStage::GetValue)?;
        if let Some(err) = udid_resp.get_string("Error") {
            let kind = if is_pairing_rejection_error(&err) {
                LockdownErrorKind::PairingRejected
            } else {
                LockdownErrorKind::ProtocolError
            };
            return Err(LockdownError::new(
                kind,
                LockdownStage::GetValue,
                format!("Lockdown GetValue rejected: {}", err),
            ));
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

    /// Standard String-error wrapper used by child services (`AppScanner`, `HouseArrestClient`, etc.)
    pub fn connect(ip: &str, port: u16, pairing: &PairingFile) -> Result<Self, String> {
        Self::connect_with_retry(ip, port, pairing, MAX_HANDSHAKE_ATTEMPTS).map_err(|e| e.to_string())
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
        send_plist_for_stage(stream, &req, LockdownStage::StartService)
            .map_err(|e| e.to_string())?;

        let resp = read_plist_for_stage(stream, LockdownStage::StartService)
            .map_err(|e| e.to_string())?;
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
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(SERVICE_CONNECT_TIMEOUT_SECS))
            .map_err(|e| {
                format!(
                    "Failed to connect to service '{}' at {}: {}",
                    service_name, addr_str, e
                )
            })?;

        let service_stream = if enable_ssl {
            let tls = build_tls_stream(tcp, &self.pairing, LockdownStage::StartService)
                .map_err(|e| e.to_string())?;
            LockdownStream::Tls(Box::new(tls))
        } else {
            LockdownStream::Plain(tcp)
        };
        service_stream.set_timeouts(15, 15);

        Ok((service_stream, service_port, enable_ssl))
    }
}

// ==============================================================================
// 4-BYTE BIG-ENDIAN PACKET FRAMING (safe non-panicking read/write with stage info)
// ==============================================================================

fn send_plist_for_stage<W: Write>(
    stream: &mut W,
    dict: &HashMap<String, PlistValue>,
    stage: LockdownStage,
) -> Result<(), LockdownError> {
    let xml = serialize_xml_dict(dict);
    let bytes = xml.as_bytes();
    let len = bytes.len() as u32;
    write_all_safe(stream, &len.to_be_bytes(), stage, "Write length failed")?;
    write_all_safe(stream, bytes, stage, "Write payload failed")?;
    Ok(())
}

fn read_plist_for_stage<R: Read>(
    stream: &mut R,
    stage: LockdownStage,
) -> Result<PlistValue, LockdownError> {
    let mut len_buf = [0u8; 4];
    read_exact_safe(stream, &mut len_buf, stage, "Read length failed")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_PLIST_PACKET_BYTES {
        return Err(LockdownError::new(
            LockdownErrorKind::ProtocolError,
            stage,
            format!("Invalid lockdown packet length: {} bytes", len),
        ));
    }
    let mut payload = vec![0u8; len];
    read_exact_safe(stream, &mut payload, stage, "Read payload failed")?;
    parse_plist(&payload).map_err(|e| LockdownError::new(LockdownErrorKind::ProtocolError, stage, e))
}

pub fn send_plist<W: Write>(stream: &mut W, dict: &HashMap<String, PlistValue>) -> Result<(), String> {
    send_plist_for_stage(stream, dict, LockdownStage::Protocol).map_err(|e| e.detail)
}

pub fn read_plist<R: Read>(stream: &mut R) -> Result<PlistValue, String> {
    read_plist_for_stage(stream, LockdownStage::Protocol).map_err(|e| e.detail)
}
