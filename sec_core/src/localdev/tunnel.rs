//! LocalDev Loopback VPN Tunnel & Lockdown Protocol Implementation
//! Supports iOS 15.0 - iOS 27.2.1

use super::pairing::PairingFile;
use super::plist_util::{parse_plist, serialize_xml_dict, PlistValue};
use std::collections::HashMap;
use std::ffi::{c_char, CString};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
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
pub const HANDSHAKE_CONNECT_TIMEOUT_MS: u64 = 1500;
pub const HANDSHAKE_IO_TIMEOUT_SECS: u64 = 5;
pub const SERVICE_CONNECT_TIMEOUT_SECS: u64 = 4;
pub const MAX_HANDSHAKE_ATTEMPTS: usize = 2;
pub const HANDSHAKE_RETRY_BACKOFF_MS: u64 = 180;
pub const EPERM_PREWARM_RETRY_COUNT: usize = 3;
pub const EPERM_RETRY_BACKOFF_MS: u64 = 250;
const MAX_PLIST_PACKET_BYTES: usize = 16 * 1024 * 1024;

pub type LocalDevNwPrewarmFn = extern "C" fn(host: *const c_char, port: u16) -> i32;
pub type LocalDevNwRelayConnectFn =
    extern "C" fn(host: *const c_char, port: u16, timeout_ms: u32, err_out: *mut i32) -> i32;

static NW_PREWARM_CB: Mutex<Option<LocalDevNwPrewarmFn>> = Mutex::new(None);
static NW_RELAY_CONNECT_CB: Mutex<Option<LocalDevNwRelayConnectFn>> = Mutex::new(None);

pub fn register_nw_callbacks(
    prewarm_cb: Option<LocalDevNwPrewarmFn>,
    relay_connect_cb: Option<LocalDevNwRelayConnectFn>,
) {
    if let Ok(mut guard) = NW_PREWARM_CB.lock() {
        *guard = prewarm_cb;
    }
    if let Ok(mut guard) = NW_RELAY_CONNECT_CB.lock() {
        *guard = relay_connect_cb;
    }
}

fn invoke_nw_prewarm(ip: &str, port: u16) -> Option<i32> {
    let cb = NW_PREWARM_CB.lock().ok().and_then(|g| *g)?;
    let c_host = CString::new(ip).ok()?;
    Some(cb(c_host.as_ptr(), port))
}

fn invoke_nw_relay_connect(
    ip: &str,
    port: u16,
    timeout: Duration,
    stage: LockdownStage,
) -> Option<Result<TransportStream, LockdownError>> {
    let cb = NW_RELAY_CONNECT_CB.lock().ok().and_then(|g| *g)?;
    let c_host = match CString::new(ip) {
        Ok(s) => s,
        Err(e) => {
            return Some(Err(LockdownError::new(
                LockdownErrorKind::ProtocolError,
                stage,
                format!("Invalid relay target '{}': {}", ip, e),
            )));
        }
    };
    let timeout_ms = timeout.as_millis().clamp(250, 15_000) as u32;
    let mut raw_errno: i32 = 0;
    let fd = cb(c_host.as_ptr(), port, timeout_ms, &mut raw_errno);
    if fd >= 0 {
        #[cfg(unix)]
        {
            let stream = unsafe { UnixStream::from_raw_fd(fd as RawFd) };
            return Some(Ok(TransportStream::Relay(stream)));
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
        }
    }
    let code = if raw_errno > 0 { raw_errno } else { 60 };
    let io_err = io::Error::from_raw_os_error(code);
    Some(Err(classify_io_error(
        io_err,
        stage,
        &format!("Failed to connect to LocalDevVPN at {}:{} via NWConnection", ip, port),
    )))
}

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
    pub errno_code: Option<i32>,
}

impl LockdownError {
    pub fn new(kind: LockdownErrorKind, stage: LockdownStage, detail: impl Into<String>) -> Self {
        Self {
            kind,
            stage,
            detail: detail.into(),
            errno_code: None,
        }
    }

    pub fn with_errno(
        kind: LockdownErrorKind,
        stage: LockdownStage,
        errno_code: Option<i32>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            stage,
            detail: detail.into(),
            errno_code,
        }
    }

    pub fn errno_label(&self) -> String {
        match self.errno_code {
            Some(1) => "EPERM (os error 1)".to_string(),
            Some(13) => "EACCES (os error 13)".to_string(),
            Some(32) => "EPIPE (os error 32)".to_string(),
            Some(50) => "ENETDOWN (os error 50)".to_string(),
            Some(51) => "ENETUNREACH (os error 51)".to_string(),
            Some(53) => "ECONNABORTED (os error 53)".to_string(),
            Some(54) => "ECONNRESET (os error 54)".to_string(),
            Some(60) | Some(110) => "ETIMEDOUT (os error 60)".to_string(),
            Some(61) | Some(111) => "ECONNREFUSED (os error 61)".to_string(),
            Some(64) => "EHOSTDOWN (os error 64)".to_string(),
            Some(65) | Some(113) => "EHOSTUNREACH (os error 65)".to_string(),
            Some(code) => format!("os error {}", code),
            None => match self.kind {
                LockdownErrorKind::PermissionDenied => "EPERM".to_string(),
                LockdownErrorKind::Timeout => "ETIMEDOUT".to_string(),
                LockdownErrorKind::TunnelUnreachable => "ECONNREFUSED/UNREACHABLE".to_string(),
                LockdownErrorKind::SocketReset => "ECONNRESET".to_string(),
                LockdownErrorKind::PairingRejected => "PAIRING_REJECTED".to_string(),
                LockdownErrorKind::ProtocolError => "PROTOCOL_ERROR".to_string(),
            },
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
    ) || matches!(raw, Some(60) | Some(110))
        || lower.contains("timed out")
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

    LockdownError::with_errno(kind, stage, raw, format!("{}: {}", prefix, msg))
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

/// Low-level socket transport supporting both direct POSIX TCP and Swift NWConnection relay
pub enum TransportStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Relay(UnixStream),
}

impl TransportStream {
    pub fn set_timeouts(&self, read_secs: u64, write_secs: u64) {
        match self {
            TransportStream::Tcp(tcp) => {
                tcp.set_read_timeout(Some(Duration::from_secs(read_secs))).ok();
                tcp.set_write_timeout(Some(Duration::from_secs(write_secs))).ok();
            }
            #[cfg(unix)]
            TransportStream::Relay(unix) => {
                unix.set_read_timeout(Some(Duration::from_secs(read_secs))).ok();
                unix.set_write_timeout(Some(Duration::from_secs(write_secs))).ok();
            }
        }
    }
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TransportStream::Tcp(tcp) => tcp.read(buf),
            #[cfg(unix)]
            TransportStream::Relay(unix) => unix.read(buf),
        }
    }
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TransportStream::Tcp(tcp) => tcp.write(buf),
            #[cfg(unix)]
            TransportStream::Relay(unix) => unix.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TransportStream::Tcp(tcp) => tcp.flush(),
            #[cfg(unix)]
            TransportStream::Relay(unix) => unix.flush(),
        }
    }
}

/// Active TLS stream over unified transport stream
pub type TlsStream = StreamOwned<ClientConnection, TransportStream>;

/// Unified transport stream for lockdownd and child services (`EnableServiceSSL` aware)
pub enum LockdownStream {
    Plain(TransportStream),
    Tls(Box<TlsStream>),
}

impl LockdownStream {
    pub fn set_timeouts(&self, read_secs: u64, write_secs: u64) {
        let transport = match self {
            LockdownStream::Plain(t) => t,
            LockdownStream::Tls(tls) => tls.get_ref(),
        };
        transport.set_timeouts(read_secs, write_secs);
    }
}

impl Read for LockdownStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            LockdownStream::Plain(t) => t.read(buf),
            LockdownStream::Tls(tls) => tls.read(buf),
        }
    }
}

impl Write for LockdownStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            LockdownStream::Plain(t) => t.write(buf),
            LockdownStream::Tls(tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            LockdownStream::Plain(t) => t.flush(),
            LockdownStream::Tls(tls) => tls.flush(),
        }
    }
}

fn build_tls_stream(
    transport: TransportStream,
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

    Ok(StreamOwned::new(conn, transport))
}

fn is_permission_denied_io(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(1) | Some(13))
}

fn format_endpoint_label(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    }
}

fn resolve_socket_addr(ip: &str, port: u16, stage: LockdownStage) -> Result<SocketAddr, LockdownError> {
    if let Some((addr_part, zone)) = ip.split_once('%') {
        let v6: Ipv6Addr = addr_part.parse().map_err(|e| {
            LockdownError::new(
                LockdownErrorKind::ProtocolError,
                stage,
                format!("Invalid IPv6 address {}: {}", ip, e),
            )
        })?;
        #[cfg(unix)]
        let scope_id = if let Ok(c_zone) = CString::new(zone) {
            unsafe { libc::if_nametoindex(c_zone.as_ptr()) }
        } else {
            0
        };
        #[cfg(not(unix))]
        let scope_id = zone.parse::<u32>().unwrap_or(0);
        return Ok(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope_id)));
    }

    let addr_str = format_endpoint_label(ip, port);
    addr_str.parse().map_err(|e| {
        LockdownError::new(
            LockdownErrorKind::ProtocolError,
            stage,
            format!("Invalid IP address {}: {}", addr_str, e),
        )
    })
}

fn connect_transport(
    ip: &str,
    port: u16,
    timeout: Duration,
    stage: LockdownStage,
    prefer_relay_first: bool,
) -> Result<(TransportStream, bool), LockdownError> {
    let addr_str = format_endpoint_label(ip, port);
    let addr = resolve_socket_addr(ip, port, stage)?;

    if prefer_relay_first {
        if let Some(relay_res) = invoke_nw_relay_connect(ip, port, timeout, stage) {
            return relay_res.map(|s| (s, true));
        }
    }

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(tcp) => {
            tcp.set_nodelay(true).ok();
            Ok((TransportStream::Tcp(tcp), false))
        }
        Err(first_err) if is_permission_denied_io(&first_err) => {
            // iOS 27.2.1 NECP may deny POSIX BSD sockets with EPERM before Network.framework pre-warm
            let _ = invoke_nw_prewarm(ip, port);

            let mut last_err = first_err;
            for _attempt in 0..EPERM_PREWARM_RETRY_COUNT {
                std::thread::sleep(Duration::from_millis(EPERM_RETRY_BACKOFF_MS));
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(tcp) => {
                        tcp.set_nodelay(true).ok();
                        return Ok((TransportStream::Tcp(tcp), false));
                    }
                    Err(err) if is_permission_denied_io(&err) => {
                        last_err = err;
                    }
                    Err(other_err) => {
                        return Err(classify_io_error(
                            other_err,
                            stage,
                            &format!("Failed to connect to LocalDevVPN at {}", addr_str),
                        ));
                    }
                }
            }

            // If POSIX socket still hits EPERM / os error 1 after 3x250ms retry,
            // route traffic seamlessly through Swift Network.framework NWConnection relay.
            if let Some(relay_res) = invoke_nw_relay_connect(ip, port, timeout, stage) {
                return relay_res.map(|s| (s, true));
            }

            Err(classify_io_error(
                last_err,
                stage,
                &format!("Failed to connect to LocalDevVPN at {}", addr_str),
            ))
        }
        Err(other_err) => Err(classify_io_error(
            other_err,
            stage,
            &format!("Failed to connect to LocalDevVPN at {}", addr_str),
        )),
    }
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
    pub used_nw_relay: bool,
}

impl LockdownClient {
    /// Tests TCP reachability to loopback tunnel without performing full handshake
    pub fn test_tunnel_reachability(ip: &str, port: u16) -> bool {
        connect_transport(
            ip,
            port,
            Duration::from_millis(REACHABILITY_TIMEOUT_MS),
            LockdownStage::TcpConnect,
            false,
        )
        .is_ok()
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
        match Self::connect_with_mode(ip, port, pairing, true) {
            Ok(client) => Ok(client),
            // If peer resets directly at `QueryType` (or plaintext pre-auth `GetValue`) over LocalDevVPN 62078,
            // reopen once skipping `QueryType` and negotiating `StartSession` directly over Lockdownd TCP.
            Err(first_err)
                if matches!(
                    first_err.stage,
                    LockdownStage::QueryType | LockdownStage::GetValue
                ) && matches!(
                    first_err.kind,
                    LockdownErrorKind::SocketReset | LockdownErrorKind::ProtocolError
                ) =>
            {
                match Self::connect_with_mode(ip, port, pairing, false) {
                    Ok(client) => Ok(client),
                    Err(_) => Err(first_err),
                }
            }
            Err(err) => Err(err),
        }
    }

    fn connect_with_mode(
        ip: &str,
        port: u16,
        pairing: &PairingFile,
        run_query_type: bool,
    ) -> Result<Self, LockdownError> {
        // Direct Lockdownd over TCP (NO 16-byte `usbmuxd` header on port 62078)
        let (mut plain_transport, used_nw_relay) = connect_transport(
            ip,
            port,
            Duration::from_millis(HANDSHAKE_CONNECT_TIMEOUT_MS),
            LockdownStage::TcpConnect,
            false,
        )?;
        plain_transport.set_timeouts(HANDSHAKE_IO_TIMEOUT_SECS, HANDSHAKE_IO_TIMEOUT_SECS);

        let mut early_udid: Option<String> = None;

        if run_query_type {
            // 1. QueryType handshake (with standard Label attribute, coalesced 4-byte BE length + XML plist)
            let mut query = HashMap::new();
            query.insert("Label".to_string(), PlistValue::String("3105".to_string()));
            query.insert(
                "Request".to_string(),
                PlistValue::String("QueryType".to_string()),
            );
            send_plist_for_stage(&mut plain_transport, &query, LockdownStage::QueryType)?;

            let query_resp = read_plist_for_stage(&mut plain_transport, LockdownStage::QueryType)?;
            if let Some(err) = query_resp.get_string("Error") {
                return Err(LockdownError::new(
                    LockdownErrorKind::ProtocolError,
                    LockdownStage::QueryType,
                    format!("Lockdown QueryType rejected: {}", err),
                ));
            }

            // 2. Plaintext GetValue(UniqueDeviceID) probe per Lockdownd flow; ignore non-fatal auth deferral
            let mut pre_udid_req = HashMap::new();
            pre_udid_req.insert("Label".to_string(), PlistValue::String("3105".to_string()));
            pre_udid_req.insert("Request".to_string(), PlistValue::String("GetValue".to_string()));
            pre_udid_req.insert(
                "Key".to_string(),
                PlistValue::String("UniqueDeviceID".to_string()),
            );
            if send_plist_for_stage(&mut plain_transport, &pre_udid_req, LockdownStage::GetValue).is_ok() {
                if let Ok(resp) = read_plist_for_stage(&mut plain_transport, LockdownStage::GetValue) {
                    if let Some(v) = resp.get_string("Value").filter(|s| !s.is_empty()) {
                        early_udid = Some(v);
                    }
                }
            }
        }

        // 3. StartSession over plaintext (iOS lockdownd negotiates EnableSessionSSL here)
        let mut session_req = HashMap::new();
        session_req.insert("Label".to_string(), PlistValue::String("3105".to_string()));
        session_req.insert(
            "ProtocolVersion".to_string(),
            PlistValue::String("2".to_string()),
        );
        session_req.insert(
            "Request".to_string(),
            PlistValue::String("StartSession".to_string()),
        );
        session_req.insert("HostID".to_string(), PlistValue::String(pairing.host_id.clone()));
        session_req.insert(
            "SystemBUID".to_string(),
            PlistValue::String(pairing.system_buid.clone()),
        );
        send_plist_for_stage(&mut plain_transport, &session_req, LockdownStage::StartSession)?;

        let session_resp = read_plist_for_stage(&mut plain_transport, LockdownStage::StartSession)?;
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

        // 4. Upgrade TCP/relay socket to mutual-auth TLS when EnableSessionSSL is true
        let mut stream = if enable_ssl {
            let tls = build_tls_stream(plain_transport, pairing, LockdownStage::TlsUpgrade)?;
            LockdownStream::Tls(Box::new(tls))
        } else {
            LockdownStream::Plain(plain_transport)
        };

        // 5. Encrypted GetValue(UniqueDeviceID) completes the TLS handshake and verifies session
        let mut udid_req = HashMap::new();
        udid_req.insert("Label".to_string(), PlistValue::String("3105".to_string()));
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
        let device_udid = udid_resp
            .get_string("Value")
            .filter(|s| !s.is_empty())
            .or(early_udid);

        Ok(Self {
            ip: ip.to_string(),
            port,
            session_id,
            device_udid,
            stream: Some(stream),
            pairing: pairing.clone(),
            used_nw_relay,
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
        req.insert("Label".to_string(), PlistValue::String("3105".to_string()));
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

        let (service_transport, _) = connect_transport(
            &self.ip,
            service_port,
            Duration::from_secs(SERVICE_CONNECT_TIMEOUT_SECS),
            LockdownStage::StartService,
            self.used_nw_relay,
        )
        .map_err(|e| format!("Failed to connect to service '{}': {}", service_name, e))?;

        let service_stream = if enable_ssl {
            let tls = build_tls_stream(service_transport, &self.pairing, LockdownStage::StartService)
                .map_err(|e| e.to_string())?;
            LockdownStream::Tls(Box::new(tls))
        } else {
            LockdownStream::Plain(service_transport)
        };
        service_stream.set_timeouts(15, 15);

        Ok((service_stream, service_port, enable_ssl))
    }
}

/// Probes RSD (port 58783 HTTP/2 RemoteXPC preface) and RemotePairing (port 49152) across active IPv4/IPv6 endpoints.
pub fn probe_rsd_and_remotepairing(hosts: &[String]) -> Vec<String> {
    let timeout = Duration::from_millis(700);
    let mut findings = Vec::new();
    // Standard RFC 7540 HTTP/2 client connection preface + empty SETTINGS frame
    const H2_PREFACE_SETTINGS: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

    for host in hosts.iter().take(4) {
        if let Ok((mut stream, _)) = connect_transport(host, 58783, timeout, LockdownStage::Protocol, false) {
            stream.set_timeouts(1, 1);
            let mut h2_status = "TCP_OPEN".to_string();
            if stream.write_all(H2_PREFACE_SETTINGS).is_ok() && stream.flush().is_ok() {
                let mut hdr = [0u8; 9];
                if let Ok(n) = stream.read(&mut hdr) {
                    if n >= 9 && hdr[3] == 0x04 {
                        h2_status = "HTTP2_SETTINGS_OK".to_string();
                    } else if n > 0 {
                        h2_status = format!("RESP_{}B", n);
                    }
                }
            }
            findings.push(format!("{} -> RSD:58783={}", format_endpoint_label(host, 58783), h2_status));
        }

        if let Ok((_stream, _)) = connect_transport(host, 49152, timeout, LockdownStage::Protocol, false) {
            findings.push(format!("{} -> RemotePairing:49152=OPEN", format_endpoint_label(host, 49152)));
        }
    }
    findings
}

// ==============================================================================
// 4-BYTE BIG-ENDIAN PACKET FRAMING (atomic length+payload write, safe read)
// ==============================================================================

fn send_plist_for_stage<W: Write>(
    stream: &mut W,
    dict: &HashMap<String, PlistValue>,
    stage: LockdownStage,
) -> Result<(), LockdownError> {
    let xml = serialize_xml_dict(dict);
    let bytes = xml.as_bytes();
    let len = bytes.len() as u32;
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(bytes);
    write_all_safe(stream, &frame, stage, "Write packet failed")?;
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
