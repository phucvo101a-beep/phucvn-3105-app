//! Pure-Rust RemotePairing (`49152`), RemoteXPC HTTP/2, and RSD (`RsdHandshake`) Tunnel Stack
//! Connects to `10.7.0.1:49152` over `utun` (`LocalDevVPN`), performs `verifyManualPairing` +
//! `createListener` + TLS-PSK `CDTunnel` + `jktcp` userspace TCP/IPv6 + `RsdHandshake`,
//! and provides synchronous `std::io::Read + Write` streams for HouseArrest, AFC, and InstallationProxy.

use super::apps::LocalDevAppInfo;
use super::pairing::RemotePairingFile;
use super::plist_util::{serialize_xml_dict, PlistValue};
use super::tls_psk::connect_cd_tunnel;
use super::tunnel::{connect_transport, format_endpoint_label, LockdownError, LockdownErrorKind, LockdownStage, TransportStream};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use jktcp::adapter::Adapter;
use jktcp::handle::{AdapterHandle, StreamHandle};
use obfstr::obfstr;
use rand::rngs::OsRng;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

const RPPAIRING_MAGIC: &[u8] = b"RPPairing";
const WIRE_PROTOCOL_VERSION: u8 = 19;
const HTTP2_MAGIC: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_FRAME_HEADER_LEN: usize = 9;
const H2_DEFAULT_WINDOW: i64 = 65535;
const XPC_WRAPPER_MAGIC: u32 = 0x29b0_0b92;
const XPC_WRAPPER_LEN: usize = 24;
const XPC_OBJECT_MAGIC: u32 = 0x4213_3742;
const XPC_OBJECT_VERSION: u32 = 5;
const XPC_ROOT_CHANNEL: u32 = 1;
const XPC_REPLY_CHANNEL: u32 = 3;

/// Shared multi-threaded Tokio runtime driving `jktcp::AdapterHandle`, RemotePairing, and RemoteXPC.
pub fn runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RT: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("ld-rsd")
            .enable_all()
            .build()
            .map_err(|e| format!("Tokio runtime init failed: {}", e))
    })
    .as_ref()
    .map_err(|e| e.clone())
}

/// Process-stable 16-byte host UUID presented in every RSD handshake.
/// Required on iOS 27.2+ so concurrent/subsequent RSD connections do not cause
/// the device to tear down previously advertised service listeners.
fn stable_handshake_uuid(seed_hint: Option<&str>) -> [u8; 16] {
    static HOST_UUID: OnceLock<[u8; 16]> = OnceLock::new();
    *HOST_UUID.get_or_init(|| {
        let mut h = Sha256::new();
        h.update(b"3105-rsd-host:");
        if let Some(hint) = seed_hint.filter(|s| !s.is_empty()) {
            h.update(hint.as_bytes());
        } else {
            #[cfg(unix)]
            {
                let mut buf = [0u8; 256];
                let ret = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
                if ret == 0 {
                    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                    h.update(&buf[..len]);
                }
            }
        }
        let digest = h.finalize();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&digest[..16]);
        // Set UUIDv4 variant/version bits cleanly
        uuid[6] = (uuid[6] & 0x0F) | 0x40;
        uuid[8] = (uuid[8] & 0x3F) | 0x80;
        uuid
    })
}

fn format_uuid_hyphenated(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

// ==============================================================================
// Async Transport Wrapper (bridging TCP & Swift NWConnection UnixStream)
// ==============================================================================

#[derive(Debug)]
pub enum AsyncTransport {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl AsyncTransport {
    fn from_sync(sync_stream: TransportStream) -> Result<Self, String> {
        match sync_stream {
            TransportStream::Tcp(tcp) => {
                tcp.set_nonblocking(true)
                    .map_err(|e| format!("TcpStream set_nonblocking failed: {}", e))?;
                let async_tcp = tokio::net::TcpStream::from_std(tcp)
                    .map_err(|e| format!("tokio TcpStream::from_std failed: {}", e))?;
                Ok(AsyncTransport::Tcp(async_tcp))
            }
            #[cfg(unix)]
            TransportStream::Relay(unix) => {
                unix.set_nonblocking(true)
                    .map_err(|e| format!("UnixStream set_nonblocking failed: {}", e))?;
                let async_unix = tokio::net::UnixStream::from_std(unix)
                    .map_err(|e| format!("tokio UnixStream::from_std failed: {}", e))?;
                Ok(AsyncTransport::Unix(async_unix))
            }
        }
    }
}

impl AsyncRead for AsyncTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AsyncTransport::Tcp(tcp) => Pin::new(tcp).poll_read(cx, buf),
            #[cfg(unix)]
            AsyncTransport::Unix(unix) => Pin::new(unix).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AsyncTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            AsyncTransport::Tcp(tcp) => Pin::new(tcp).poll_write(cx, buf),
            #[cfg(unix)]
            AsyncTransport::Unix(unix) => Pin::new(unix).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AsyncTransport::Tcp(tcp) => Pin::new(tcp).poll_flush(cx),
            #[cfg(unix)]
            AsyncTransport::Unix(unix) => Pin::new(unix).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AsyncTransport::Tcp(tcp) => Pin::new(tcp).poll_shutdown(cx),
            #[cfg(unix)]
            AsyncTransport::Unix(unix) => Pin::new(unix).poll_shutdown(cx),
        }
    }
}

async fn connect_async_transport(
    host: String,
    port: u16,
    timeout: Duration,
    stage: LockdownStage,
    prefer_relay_first: bool,
) -> Result<AsyncTransport, LockdownError> {
    let host_label = host.clone();
    let sync_res = tokio::task::spawn_blocking(move || {
        connect_transport(&host, port, timeout, stage, prefer_relay_first)
    })
    .await
    .map_err(|e| LockdownError::new(LockdownErrorKind::ProtocolError, stage, format!("spawn_blocking join: {}", e)))?;

    let (transport, _used_relay) = sync_res?;
    AsyncTransport::from_sync(transport).map_err(|e| {
        LockdownError::new(
            LockdownErrorKind::ProtocolError,
            stage,
            format!("Async transport wrap {}:{} failed: {}", host_label, port, e),
        )
    })
}

/// Synchronous `std::io::Read + Write` stream backed by an async `jktcp::StreamHandle`
/// or `AsyncTransport`, enabling seamless reuse of AFC / HouseArrest / InstallationProxy clients.
pub enum SyncTunnelStream {
    Jktcp {
        stream: StreamHandle,
        read_timeout_secs: Arc<AtomicU64>,
        write_timeout_secs: Arc<AtomicU64>,
    },
    Direct(AsyncTransport),
}

impl SyncTunnelStream {
    pub fn set_timeouts(&self, read_secs: u64, write_secs: u64) {
        if let SyncTunnelStream::Jktcp {
            read_timeout_secs,
            write_timeout_secs,
            ..
        } = self
        {
            read_timeout_secs.store(read_secs.max(1), Ordering::Relaxed);
            write_timeout_secs.store(write_secs.max(1), Ordering::Relaxed);
        }
    }

    fn with_timeouts(self, read_secs: u64, write_secs: u64) -> Self {
        self.set_timeouts(read_secs, write_secs);
        self
    }
}

impl std::io::Read for SyncTunnelStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rt = runtime().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        match self {
            SyncTunnelStream::Jktcp { stream, read_timeout_secs, .. } => {
                let dur = Duration::from_secs(read_timeout_secs.load(Ordering::Relaxed));
                rt.block_on(async {
                    match tokio::time::timeout(dur, stream.read(buf)).await {
                        Ok(res) => res,
                        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "jktcp read timeout")),
                    }
                })
            }
            SyncTunnelStream::Direct(transport) => rt.block_on(async {
                match tokio::time::timeout(Duration::from_secs(10), transport.read(buf)).await {
                    Ok(res) => res,
                    Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "direct RSD read timeout")),
                }
            }),
        }
    }
}

impl std::io::Write for SyncTunnelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let rt = runtime().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        match self {
            SyncTunnelStream::Jktcp { stream, write_timeout_secs, .. } => {
                let dur = Duration::from_secs(write_timeout_secs.load(Ordering::Relaxed));
                rt.block_on(async {
                    match tokio::time::timeout(dur, stream.write(buf)).await {
                        Ok(res) => res,
                        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "jktcp write timeout")),
                    }
                })
            }
            SyncTunnelStream::Direct(transport) => rt.block_on(async {
                match tokio::time::timeout(Duration::from_secs(10), transport.write(buf)).await {
                    Ok(res) => res,
                    Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "direct RSD write timeout")),
                }
            }),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let rt = runtime().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        match self {
            SyncTunnelStream::Jktcp { stream, .. } => rt.block_on(stream.flush()),
            SyncTunnelStream::Direct(transport) => rt.block_on(transport.flush()),
        }
    }
}

// ==============================================================================
// TLV8 Encoder/Decoder for Apple PairVerify (`verifyManualPairing`)
// ==============================================================================

mod tlv8 {
    pub const IDENTIFIER: u8 = 0x01;
    pub const PUBLIC_KEY: u8 = 0x03;
    pub const ENCRYPTED_DATA: u8 = 0x05;
    pub const STATE: u8 = 0x06;
    pub const ERROR_RESPONSE: u8 = 0x07;
    pub const SIGNATURE: u8 = 0x0A;

    pub fn encode(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(tag, data) in entries {
            if data.is_empty() {
                out.push(tag);
                out.push(0);
            } else {
                for chunk in data.chunks(255) {
                    out.push(tag);
                    out.push(chunk.len() as u8);
                    out.extend_from_slice(chunk);
                }
            }
        }
        out
    }

    pub fn decode(input: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, String> {
        let mut idx = 0;
        let mut out = Vec::new();
        while idx + 2 <= input.len() {
            let tag = input[idx];
            let len = input[idx + 1] as usize;
            idx += 2;
            if idx + len > input.len() {
                return Err("Malformed TLV8 length".to_string());
            }
            out.push((tag, input[idx..idx + len].to_vec()));
            idx += len;
        }
        Ok(out)
    }

    pub fn collect(entries: &[(u8, Vec<u8>)], tag: u8) -> Vec<u8> {
        let mut acc = Vec::new();
        for (t, v) in entries {
            if *t == tag {
                acc.extend_from_slice(v);
            }
        }
        acc
    }

    pub fn has(entries: &[(u8, Vec<u8>)], tag: u8) -> bool {
        entries.iter().any(|(t, _)| *t == tag)
    }
}

// ==============================================================================
// RemotePairing Control Client (`b"RPPairing" + u16_be(len) + json`)
// ==============================================================================

enum RpProtocolError {
    Transport(LockdownError),
    NotRpPairing(String),
    PairVerifyRejected(String),
    Protocol(String),
}

impl RpProtocolError {
    fn into_lockdown_error(self, stage: LockdownStage) -> LockdownError {
        match self {
            RpProtocolError::Transport(e) => e,
            RpProtocolError::NotRpPairing(msg) => {
                LockdownError::new(LockdownErrorKind::ProtocolError, stage, msg)
            }
            RpProtocolError::PairVerifyRejected(msg) => {
                LockdownError::new(LockdownErrorKind::PairingRejected, stage, msg)
            }
            RpProtocolError::Protocol(msg) => {
                LockdownError::new(LockdownErrorKind::ProtocolError, stage, msg)
            }
        }
    }
}

#[allow(dead_code)]
pub struct RpPairingControlClient {
    stream: AsyncTransport,
    sequence_number: u64,
    encrypted_sequence_number: u64,
    encryption_key: Vec<u8>,
    client_cipher: ChaCha20Poly1305,
    server_cipher: ChaCha20Poly1305,
    peer_udid: Option<String>,
    peer_name: Option<String>,
}

impl RpPairingControlClient {
    fn derive_main_ciphers(key: &[u8]) -> Result<(ChaCha20Poly1305, ChaCha20Poly1305), String> {
        let hk_c = Hkdf::<Sha512>::new(None, key);
        let mut c_key = [0u8; 32];
        hk_c.expand(b"ClientEncrypt-main", &mut c_key)
            .map_err(|e| e.to_string())?;
        let client_cipher = ChaCha20Poly1305::new_from_slice(&c_key).map_err(|e| e.to_string())?;

        let hk_s = Hkdf::<Sha512>::new(None, key);
        let mut s_key = [0u8; 32];
        hk_s.expand(b"ServerEncrypt-main", &mut s_key)
            .map_err(|e| e.to_string())?;
        let server_cipher = ChaCha20Poly1305::new_from_slice(&s_key).map_err(|e| e.to_string())?;

        Ok((client_cipher, server_cipher))
    }

    async fn new(stream: AsyncTransport) -> Result<Self, String> {
        let initial = vec![0u8; 32];
        let (cc, sc) = Self::derive_main_ciphers(&initial)?;
        Ok(Self {
            stream,
            sequence_number: 0,
            encrypted_sequence_number: 0,
            encryption_key: initial,
            client_cipher: cc,
            server_cipher: sc,
            peer_udid: None,
            peer_name: None,
        })
    }

    async fn send_frame(&mut self, envelope: JsonValue) -> Result<(), RpProtocolError> {
        let payload = serde_json::to_string(&envelope)
            .map_err(|e| RpProtocolError::Protocol(e.to_string()))?;
        let payload_bytes = payload.as_bytes();
        let len_u16 = u16::try_from(payload_bytes.len())
            .map_err(|_| RpProtocolError::Protocol("RPPairing frame exceeds 64KB".to_string()))?;

        let mut frame = Vec::with_capacity(RPPAIRING_MAGIC.len() + 2 + payload_bytes.len());
        frame.extend_from_slice(RPPAIRING_MAGIC);
        frame.extend_from_slice(&len_u16.to_be_bytes());
        frame.extend_from_slice(payload_bytes);

        tokio::time::timeout(Duration::from_secs(5), self.stream.write_all(&frame))
            .await
            .map_err(|_| {
                RpProtocolError::Transport(LockdownError::with_errno(
                    LockdownErrorKind::Timeout,
                    LockdownStage::Protocol,
                    Some(60),
                    "Timeout writing RPPairing frame",
                ))
            })?
            .map_err(|e| {
                let code = e.raw_os_error().unwrap_or(54);
                RpProtocolError::Transport(LockdownError::with_errno(
                    if code == 54 { LockdownErrorKind::SocketReset } else { LockdownErrorKind::ProtocolError },
                    LockdownStage::Protocol,
                    Some(code),
                    format!("RPPairing write failed: {}", e),
                ))
            })?;
        let _ = self.stream.flush().await;
        Ok(())
    }

    async fn send_plain(&mut self, value: JsonValue) -> Result<(), RpProtocolError> {
        let seq = self.sequence_number;
        self.sequence_number += 1;
        self.send_frame(json!({
            "message": { "plain": { "_0": value } },
            "originatedBy": "host",
            "sequenceNumber": seq
        }))
        .await
    }

    async fn recv_envelope(&mut self) -> Result<JsonValue, RpProtocolError> {
        let mut magic = vec![0u8; RPPAIRING_MAGIC.len()];
        tokio::time::timeout(Duration::from_secs(5), self.stream.read_exact(&mut magic))
            .await
            .map_err(|_| {
                RpProtocolError::Transport(LockdownError::with_errno(
                    LockdownErrorKind::Timeout,
                    LockdownStage::Protocol,
                    Some(60),
                    "Timeout waiting for RPPairing response header",
                ))
            })?
            .map_err(|e| {
                let code = e.raw_os_error().unwrap_or(54);
                RpProtocolError::Transport(LockdownError::with_errno(
                    if code == 54 { LockdownErrorKind::SocketReset } else { LockdownErrorKind::ProtocolError },
                    LockdownStage::Protocol,
                    Some(code),
                    format!("RPPairing magic read failed: {}", e),
                ))
            })?;

        if magic.as_slice() != RPPAIRING_MAGIC {
            return Err(RpProtocolError::NotRpPairing(format!(
                "Non-RPPairing response header: {:02x?}",
                magic
            )));
        }

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), self.stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| RpProtocolError::Protocol("Timeout reading RPPairing frame length".to_string()))?
            .map_err(|e| RpProtocolError::Protocol(format!("RPPairing length read failed: {}", e)))?;
        let packet_len = u16::from_be_bytes(len_buf) as usize;

        let mut body = vec![0u8; packet_len];
        tokio::time::timeout(Duration::from_secs(5), self.stream.read_exact(&mut body))
            .await
            .map_err(|_| RpProtocolError::Protocol("Timeout reading RPPairing frame body".to_string()))?
            .map_err(|e| RpProtocolError::Protocol(format!("RPPairing body read failed: {}", e)))?;

        serde_json::from_slice(&body)
            .map_err(|e| RpProtocolError::Protocol(format!("Invalid RPPairing JSON: {}", e)))
    }

    async fn recv_plain_inner(&mut self) -> Result<JsonValue, RpProtocolError> {
        let env = self.recv_envelope().await?;
        if let Some(plain) = env
            .get("message")
            .and_then(|m| m.get("plain"))
            .and_then(|p| p.get("_0"))
        {
            Ok(plain.clone())
        } else {
            Ok(env)
        }
    }

    async fn attempt_pair_verify(&mut self) -> Result<(), RpProtocolError> {
        self.send_plain(json!({
            "request": {
                "_0": {
                    "handshake": {
                        "_0": {
                            "hostOptions": { "attemptPairVerify": true },
                            "wireProtocolVersion": WIRE_PROTOCOL_VERSION
                        }
                    }
                }
            }
        }))
        .await?;

        let resp = self.recv_plain_inner().await?;
        let handshake = resp
            .get("response")
            .and_then(|r| r.get("_1"))
            .and_then(|r| r.get("handshake"))
            .and_then(|h| h.get("_0"))
            .ok_or_else(|| {
                RpProtocolError::Protocol("Missing response._1.handshake._0 in attemptPairVerify".to_string())
            })?;

        if let Some(info) = handshake.get("peerDeviceInfo") {
            if let Some(name) = info.get("name").and_then(|v| v.as_str()) {
                self.peer_name = Some(name.to_string());
            }
            if let Some(udid) = info
                .get("remotepairing_udid")
                .or_else(|| info.get("identifier"))
                .and_then(|v| v.as_str())
            {
                self.peer_udid = Some(udid.to_string());
            }
        }
        Ok(())
    }

    async fn send_pairing_event(&mut self, pairing_data: JsonValue) -> Result<(), RpProtocolError> {
        self.send_plain(json!({
            "event": {
                "_0": {
                    "pairingData": {
                        "_0": pairing_data
                    }
                }
            }
        }))
        .await
    }

    async fn recv_pairing_event(&mut self) -> Result<JsonValue, RpProtocolError> {
        let resp = self.recv_plain_inner().await?;
        resp.get("event")
            .and_then(|e| e.get("_0"))
            .and_then(|ev| ev.get("pairingData"))
            .and_then(|p| p.get("_0"))
            .cloned()
            .ok_or_else(|| RpProtocolError::Protocol("Missing event._0.pairingData._0".to_string()))
    }

    async fn send_pair_verify_failed(&mut self) {
        let _ = self
            .send_plain(json!({
                "event": { "_0": { "pairVerifyFailed": {} } }
            }))
            .await;
    }

    async fn validate_pairing(&mut self, rp: &RemotePairingFile) -> Result<(), RpProtocolError> {
        let x_priv = EphemeralSecret::random_from_rng(OsRng);
        let x_pub = X25519PublicKey::from(&x_priv);

        // Msg01: [State=0x01, PublicKey=x_pub]
        let tlv_m1 = tlv8::encode(&[
            (tlv8::STATE, &[0x01]),
            (tlv8::PUBLIC_KEY, x_pub.as_bytes()),
        ]);
        self.send_pairing_event(json!({
            "data": B64.encode(&tlv_m1),
            "kind": "verifyManualPairing",
            "startNewSession": true
        }))
        .await?;

        let m2_ev = self.recv_pairing_event().await?;
        let m2_b64 = m2_ev
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpProtocolError::Protocol("Missing data in verifyManualPairing M2".to_string()))?;
        let m2_bytes = B64
            .decode(m2_b64)
            .map_err(|e| RpProtocolError::Protocol(format!("Invalid base64 in M2: {}", e)))?;
        let m2_tlv = tlv8::decode(&m2_bytes).map_err(RpProtocolError::Protocol)?;

        if tlv8::has(&m2_tlv, tlv8::ERROR_RESPONSE) {
            self.send_pair_verify_failed().await;
            return Err(RpProtocolError::PairVerifyRejected(
                "iOS trả ErrorResponse ở verifyManualPairing M2 (pairing không khớp hoặc đã hủy tin cậy)".to_string(),
            ));
        }

        let dev_pub_bytes = tlv8::collect(&m2_tlv, tlv8::PUBLIC_KEY);
        let dev_pub_arr: [u8; 32] = dev_pub_bytes.try_into().map_err(|_| {
            RpProtocolError::Protocol("verifyManualPairing M2 missing 32-byte PublicKey".to_string())
        })?;
        let dev_pub = X25519PublicKey::from(dev_pub_arr);

        let shared_secret = x_priv.diffie_hellman(&dev_pub);
        self.encryption_key = shared_secret.as_bytes().to_vec();

        // Derive Pair-Verify AEAD key via HKDF-SHA512
        let hk = Hkdf::<Sha512>::new(Some(b"Pair-Verify-Encrypt-Salt"), shared_secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"Pair-Verify-Encrypt-Info", &mut okm)
            .map_err(|e| RpProtocolError::Protocol(e.to_string()))?;
        let cipher = ChaCha20Poly1305::new_from_slice(&okm)
            .map_err(|e| RpProtocolError::Protocol(e.to_string()))?;

        // Sign x_pub || identifier || dev_pub with Ed25519 private_key
        let signing_key = SigningKey::from_bytes(&rp.private_key);
        let mut signbuf = Vec::with_capacity(32 + rp.identifier.len() + 32);
        signbuf.extend_from_slice(x_pub.as_bytes());
        signbuf.extend_from_slice(rp.identifier.as_bytes());
        signbuf.extend_from_slice(dev_pub.as_bytes());
        let sig = signing_key.sign(&signbuf);

        let plaintext = tlv8::encode(&[
            (tlv8::IDENTIFIER, rp.identifier.as_bytes()),
            (tlv8::SIGNATURE, &sig.to_bytes()),
        ]);
        let nonce = Nonce::from_slice(b"\x00\x00\x00\x00PV-Msg03");
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: &plaintext, aad: &[] })
            .map_err(|e| RpProtocolError::Protocol(format!("PV-Msg03 encrypt failed: {:?}", e)))?;

        let tlv_m3 = tlv8::encode(&[
            (tlv8::STATE, &[0x03]),
            (tlv8::ENCRYPTED_DATA, &ciphertext),
        ]);
        self.send_pairing_event(json!({
            "data": B64.encode(&tlv_m3),
            "kind": "verifyManualPairing",
            "startNewSession": false
        }))
        .await?;

        let m4_ev = self.recv_pairing_event().await?;
        let m4_b64 = m4_ev
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpProtocolError::Protocol("Missing data in verifyManualPairing M4".to_string()))?;
        let m4_bytes = B64
            .decode(m4_b64)
            .map_err(|e| RpProtocolError::Protocol(format!("Invalid base64 in M4: {}", e)))?;
        let m4_tlv = tlv8::decode(&m4_bytes).map_err(RpProtocolError::Protocol)?;

        if tlv8::has(&m4_tlv, tlv8::ERROR_RESPONSE) {
            self.send_pair_verify_failed().await;
            return Err(RpProtocolError::PairVerifyRejected(
                "iOS từ chối chữ ký Remote Pairing (verifyManualPairing M4 ErrorResponse) — hãy tạo lại file Remote Pairing mới từ idevice_pair v1.2.0".to_string(),
            ));
        }

        let (cc, sc) = Self::derive_main_ciphers(&self.encryption_key)
            .map_err(RpProtocolError::Protocol)?;
        self.client_cipher = cc;
        self.server_cipher = sc;
        Ok(())
    }

    async fn send_receive_encrypted(&mut self, request: JsonValue) -> Result<JsonValue, RpProtocolError> {
        let plaintext = serde_json::to_vec(&request)
            .map_err(|e| RpProtocolError::Protocol(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.encrypted_sequence_number.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .client_cipher
            .encrypt(nonce, Payload { msg: &plaintext, aad: &[] })
            .map_err(|e| RpProtocolError::Protocol(format!("RPPairing encrypt failed: {:?}", e)))?;

        let seq = self.sequence_number;
        self.sequence_number += 1;
        self.send_frame(json!({
            "message": { "streamEncrypted": { "_0": B64.encode(&ciphertext) } },
            "originatedBy": "host",
            "sequenceNumber": seq
        }))
        .await?;

        let env = self.recv_envelope().await?;
        let enc_b64 = env
            .get("message")
            .and_then(|m| m.get("streamEncrypted"))
            .and_then(|s| s.get("_0"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RpProtocolError::Protocol("Missing streamEncrypted._0 in RPPairing response".to_string())
            })?;
        let enc_bytes = B64
            .decode(enc_b64)
            .map_err(|e| RpProtocolError::Protocol(format!("Invalid encrypted base64: {}", e)))?;

        let decrypted = self
            .server_cipher
            .decrypt(nonce, Payload { msg: &enc_bytes, aad: &[] })
            .map_err(|e| RpProtocolError::Protocol(format!("RPPairing decrypt failed: {:?}", e)))?;
        self.encrypted_sequence_number += 1;

        let val: JsonValue = serde_json::from_slice(&decrypted)
            .map_err(|e| RpProtocolError::Protocol(format!("Decrypted JSON parse failed: {}", e)))?;
        val.get("response")
            .and_then(|r| r.get("_1"))
            .cloned()
            .ok_or_else(|| RpProtocolError::Protocol("Missing response._1 in decrypted RPPairing reply".to_string()))
    }

    async fn create_tcp_listener(&mut self) -> Result<u16, RpProtocolError> {
        let resp = self
            .send_receive_encrypted(json!({
                "request": {
                    "_0": {
                        "createListener": {
                            "key": B64.encode(&self.encryption_key),
                            "transportProtocolType": "tcp"
                        }
                    }
                }
            }))
            .await?;

        let port = resp
            .get("createListener")
            .and_then(|c| c.get("port"))
            .and_then(|p| p.as_u64())
            .ok_or_else(|| {
                RpProtocolError::Protocol(format!("Missing createListener.port in reply: {}", resp))
            })?;
        u16::try_from(port).map_err(|_| RpProtocolError::Protocol("Invalid createListener port".to_string()))
    }
}

// ==============================================================================
// HTTP/2 & Apple RemoteXPC Framing (zero binary plist literal dependency)
// ==============================================================================

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum XpcValue {
    Null,
    Bool(bool),
    Dictionary(Vec<(String, XpcValue)>),
    Array(Vec<XpcValue>),
    Double(f64),
    Int64(i64),
    UInt64(u64),
    DateNanos(u64),
    String(String),
    Data(Vec<u8>),
    Uuid([u8; 16]),
}

#[allow(dead_code)]
impl XpcValue {
    fn type_tag(&self) -> &'static str {
        match self {
            XpcValue::Null => "Null",
            XpcValue::Bool(_) => "Bool",
            XpcValue::Dictionary(_) => "Dict",
            XpcValue::Array(_) => "Array",
            XpcValue::Double(_) => "Double",
            XpcValue::Int64(_) => "Int64",
            XpcValue::UInt64(_) => "UInt64",
            XpcValue::DateNanos(_) => "Date",
            XpcValue::String(_) => "String",
            XpcValue::Data(_) => "Data",
            XpcValue::Uuid(_) => "Uuid",
        }
    }

    fn dict_get(&self, key: &str) -> Option<&XpcValue> {
        match self {
            XpcValue::Dictionary(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn dict_get_ci(&self, candidates: &[&str]) -> Option<&XpcValue> {
        let entries = self.as_dict()?;
        for name in candidates {
            if let Some((_, v)) = entries.iter().find(|(k, _)| k == name) {
                return Some(v);
            }
        }
        for name in candidates {
            let target = name.to_ascii_lowercase();
            if let Some((_, v)) = entries.iter().find(|(k, _)| k.to_ascii_lowercase() == target) {
                return Some(v);
            }
        }
        None
    }

    fn summarize_dict_keys(&self) -> String {
        match self.as_dict() {
            Some(entries) => entries
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v.type_tag()))
                .collect::<Vec<_>>()
                .join(", "),
            None => self.type_tag().to_string(),
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            XpcValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_id_string(&self) -> Option<String> {
        match self {
            XpcValue::String(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
            }
            XpcValue::Uuid(bytes) => Some(format_uuid_hyphenated(bytes)),
            XpcValue::Data(bytes) => {
                if bytes.len() == 16 {
                    if let Ok(arr) = <[u8; 16]>::try_from(bytes.as_slice()) {
                        return Some(format_uuid_hyphenated(&arr));
                    }
                }
                std::str::from_utf8(bytes)
                    .ok()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            }
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            XpcValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            XpcValue::Int64(v) => Some(*v),
            XpcValue::UInt64(v) => i64::try_from(*v).ok(),
            XpcValue::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    fn as_u16(&self) -> Option<u16> {
        match self {
            XpcValue::UInt64(v) => u16::try_from(*v).ok(),
            XpcValue::Int64(v) => u16::try_from(*v).ok(),
            XpcValue::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[XpcValue]> {
        match self {
            XpcValue::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    fn as_dict(&self) -> Option<&[(String, XpcValue)]> {
        match self {
            XpcValue::Dictionary(entries) => Some(entries.as_slice()),
            _ => None,
        }
    }

    fn padding(len: usize) -> usize {
        (4 - (len % 4)) % 4
    }

    fn encode_root(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&XPC_OBJECT_MAGIC.to_le_bytes());
        buf.extend_from_slice(&XPC_OBJECT_VERSION.to_le_bytes());
        self.encode_object(&mut buf);
        buf
    }

    fn encode_object(&self, buf: &mut Vec<u8>) {
        match self {
            XpcValue::Null => buf.extend_from_slice(&0x0000_1000_u32.to_le_bytes()),
            XpcValue::Bool(val) => {
                buf.extend_from_slice(&0x0000_2000_u32.to_le_bytes());
                buf.push(if *val { 1 } else { 0 });
                buf.extend_from_slice(&[0u8; 3]);
            }
            XpcValue::Int64(num) => {
                buf.extend_from_slice(&0x0000_3000_u32.to_le_bytes());
                buf.extend_from_slice(&num.to_le_bytes());
            }
            XpcValue::UInt64(num) => {
                buf.extend_from_slice(&0x0000_4000_u32.to_le_bytes());
                buf.extend_from_slice(&num.to_le_bytes());
            }
            XpcValue::Double(num) => {
                buf.extend_from_slice(&0x0000_5000_u32.to_le_bytes());
                buf.extend_from_slice(&num.to_le_bytes());
            }
            XpcValue::DateNanos(ns) => {
                buf.extend_from_slice(&0x0000_7000_u32.to_le_bytes());
                buf.extend_from_slice(&ns.to_le_bytes());
            }
            XpcValue::Data(data) => {
                let len = data.len();
                buf.extend_from_slice(&0x0000_8000_u32.to_le_bytes());
                buf.extend_from_slice(&(len as u32).to_le_bytes());
                buf.extend_from_slice(data);
                buf.resize(buf.len() + Self::padding(len), 0u8);
            }
            XpcValue::String(s) => {
                let len = s.len() + 1;
                buf.extend_from_slice(&0x0000_9000_u32.to_le_bytes());
                buf.extend_from_slice(&(len as u32).to_le_bytes());
                buf.extend_from_slice(s.as_bytes());
                buf.push(0);
                buf.resize(buf.len() + Self::padding(len), 0u8);
            }
            XpcValue::Uuid(bytes) => {
                buf.extend_from_slice(&0x0000_a000_u32.to_le_bytes());
                buf.extend_from_slice(bytes);
            }
            XpcValue::Array(items) => {
                buf.extend_from_slice(&0x0000_e000_u32.to_le_bytes());
                let mut inner = Vec::new();
                inner.extend_from_slice(&(items.len() as u32).to_le_bytes());
                for item in items {
                    item.encode_object(&mut inner);
                }
                buf.extend_from_slice(&(inner.len() as u32).to_le_bytes());
                buf.extend_from_slice(&inner);
            }
            XpcValue::Dictionary(entries) => {
                buf.extend_from_slice(&0x0000_f000_u32.to_le_bytes());
                let mut inner = Vec::new();
                inner.extend_from_slice(&(entries.len() as u32).to_le_bytes());
                for (k, v) in entries {
                    let pad = Self::padding(k.len() + 1);
                    inner.extend_from_slice(k.as_bytes());
                    inner.push(0);
                    inner.resize(inner.len() + pad, 0u8);
                    v.encode_object(&mut inner);
                }
                buf.extend_from_slice(&(inner.len() as u32).to_le_bytes());
                buf.extend_from_slice(&inner);
            }
        }
    }

    fn decode_root(buf: &[u8]) -> Result<Self, String> {
        xpc_wire::decode_root(buf)
    }
}

/// Isolated sync XPC wire decoder so `tokio::io::AsyncReadExt` cannot collide
/// with `std::io::Read` on `std::io::Cursor<&[u8]>` (E0034).
mod xpc_wire {
    use super::{XpcValue, XPC_OBJECT_MAGIC, XPC_OBJECT_VERSION};
    use std::io::{BufRead, Cursor, Read};

    pub(super) fn decode_root(buf: &[u8]) -> Result<XpcValue, String> {
        if buf.len() < 8 {
            return Err("XPC object buffer too short".to_string());
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if magic != XPC_OBJECT_MAGIC || version != XPC_OBJECT_VERSION {
            return Err(format!("Invalid XPC header magic={:#x} ver={}", magic, version));
        }
        let mut cursor = Cursor::new(&buf[8..]);
        decode_object(&mut cursor)
    }

    fn decode_object(cursor: &mut Cursor<&[u8]>) -> Result<XpcValue, String> {
        let mut b4 = [0u8; 4];
        cursor.read_exact(&mut b4).map_err(|e| e.to_string())?;
        let xtype = u32::from_le_bytes(b4);
        match xtype {
            0x0000_1000 => Ok(XpcValue::Null),
            0x0000_2000 => {
                cursor.read_exact(&mut b4).map_err(|e| e.to_string())?;
                Ok(XpcValue::Bool(b4[0] != 0))
            }
            0x0000_3000 => {
                let mut b8 = [0u8; 8];
                cursor.read_exact(&mut b8).map_err(|e| e.to_string())?;
                Ok(XpcValue::Int64(i64::from_le_bytes(b8)))
            }
            0x0000_4000 => {
                let mut b8 = [0u8; 8];
                cursor.read_exact(&mut b8).map_err(|e| e.to_string())?;
                Ok(XpcValue::UInt64(u64::from_le_bytes(b8)))
            }
            0x0000_5000 => {
                let mut b8 = [0u8; 8];
                cursor.read_exact(&mut b8).map_err(|e| e.to_string())?;
                Ok(XpcValue::Double(f64::from_le_bytes(b8)))
            }
            0x0000_7000 => {
                let mut b8 = [0u8; 8];
                cursor.read_exact(&mut b8).map_err(|e| e.to_string())?;
                Ok(XpcValue::DateNanos(u64::from_le_bytes(b8)))
            }
            0x0000_8000 => {
                cursor.read_exact(&mut b4).map_err(|e| e.to_string())?;
                let len = u32::from_le_bytes(b4) as usize;
                let mut data = vec![0u8; len];
                cursor.read_exact(&mut data).map_err(|e| e.to_string())?;
                cursor.consume(XpcValue::padding(len));
                Ok(XpcValue::Data(data))
            }
            0x0000_9000 => {
                cursor.read_exact(&mut b4).map_err(|e| e.to_string())?;
                let len = u32::from_le_bytes(b4) as usize;
                let mut raw = vec![0u8; len];
                cursor.read_exact(&mut raw).map_err(|e| e.to_string())?;
                cursor.consume(XpcValue::padding(len));
                if raw.last() == Some(&0) {
                    raw.pop();
                }
                let s = String::from_utf8_lossy(&raw).into_owned();
                Ok(XpcValue::String(s))
            }
            0x0000_a000 => {
                let mut u = [0u8; 16];
                cursor.read_exact(&mut u).map_err(|e| e.to_string())?;
                Ok(XpcValue::Uuid(u))
            }
            0x0000_e000 => {
                cursor.read_exact(&mut b4).map_err(|e| e.to_string())?;
                let _byte_len = u32::from_le_bytes(b4);
                cursor.read_exact(&mut b4).map_err(|e| e.to_string())?;
                let count = u32::from_le_bytes(b4) as usize;
                let mut arr = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    arr.push(decode_object(cursor)?);
                }
                Ok(XpcValue::Array(arr))
            }
            0x0000_f000 => {
                cursor.read_exact(&mut b4).map_err(|e| e.to_string())?;
                let _byte_len = u32::from_le_bytes(b4);
                cursor.read_exact(&mut b4).map_err(|e| e.to_string())?;
                let count = u32::from_le_bytes(b4) as usize;
                let mut entries = Vec::with_capacity(count.min(256));
                for _ in 0..count {
                    let mut key_raw = Vec::new();
                    cursor.read_until(0, &mut key_raw).map_err(|e| e.to_string())?;
                    let raw_len = key_raw.len();
                    if key_raw.last() == Some(&0) {
                        key_raw.pop();
                    }
                    cursor.consume(XpcValue::padding(raw_len));
                    let key = String::from_utf8_lossy(&key_raw).into_owned();
                    let val = decode_object(cursor)?;
                    entries.push((key, val));
                }
                Ok(XpcValue::Dictionary(entries))
            }
            0x0001_a000 => {
                let mut msg_id_buf = [0u8; 8];
                cursor.read_exact(&mut msg_id_buf).map_err(|e| e.to_string())?;
                let inner = decode_object(cursor)?;
                Ok(inner)
            }
            other => Err(format!("Unsupported XPC type {:#x}", other)),
        }
    }
}

struct XpcMessage {
    flags: u32,
    message: Option<XpcValue>,
}

impl XpcMessage {
    fn encode(self, message_id: u64) -> Vec<u8> {
        let body = self.message.map(|m| m.encode_root()).unwrap_or_default();
        let mut out = Vec::with_capacity(XPC_WRAPPER_LEN + body.len());
        out.extend_from_slice(&XPC_WRAPPER_MAGIC.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(&message_id.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Attempts to decode one whole XPCMessage; returns `Ok(None)` if incomplete.
    fn try_decode(data: &[u8]) -> Result<Option<(Self, usize)>, String> {
        if data.len() < XPC_WRAPPER_LEN {
            return Ok(None);
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != XPC_WRAPPER_MAGIC {
            return Err(format!("Invalid XPC message magic {:#x}", magic));
        }
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let body_len = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]) as usize;
        let total = XPC_WRAPPER_LEN + body_len;
        if data.len() < total {
            return Ok(None);
        }
        let message = if body_len > 0 {
            Some(XpcValue::decode_root(&data[XPC_WRAPPER_LEN..total])?)
        } else {
            None
        };
        Ok(Some((Self { flags, message }, total)))
    }
}

enum H2Frame {
    Data { stream_id: u32, payload: Vec<u8> },
    Headers,
    RstStream,
    Settings { stream_id: u32, flags: u8, initial_window: Option<u32> },
    Ping { opaque: [u8; 8], ack: bool },
    GoAway(String),
    WindowUpdate { stream_id: u32, increment: u32 },
    Other,
}

impl H2Frame {
    fn parse(buf: &[u8]) -> Result<Option<(Self, usize)>, String> {
        if buf.len() < H2_FRAME_HEADER_LEN {
            return Ok(None);
        }
        let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
        let ftype = buf[3];
        let flags = buf[4];
        let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7FFF_FFFF;
        let total = H2_FRAME_HEADER_LEN + len;
        if buf.len() < total {
            return Ok(None);
        }
        let body = &buf[H2_FRAME_HEADER_LEN..total];
        let frame = match ftype {
            0x00 => H2Frame::Data { stream_id, payload: body.to_vec() },
            0x01 => H2Frame::Headers,
            0x03 => H2Frame::RstStream,
            0x04 => {
                let mut init_win = None;
                let mut i = 0;
                while i + 6 <= body.len() {
                    let id = u16::from_be_bytes([body[i], body[i + 1]]);
                    let val = u32::from_be_bytes([body[i + 2], body[i + 3], body[i + 4], body[i + 5]]);
                    if id == 0x04 {
                        init_win = Some(val);
                    }
                    i += 6;
                }
                H2Frame::Settings { stream_id, flags, initial_window: init_win }
            }
            0x06 => {
                let mut opaque = [0u8; 8];
                if body.len() >= 8 {
                    opaque.copy_from_slice(&body[..8]);
                }
                H2Frame::Ping { opaque, ack: (flags & 0x01) != 0 }
            }
            0x07 => {
                let msg = if body.len() > 8 {
                    String::from_utf8_lossy(&body[8..]).into_owned()
                } else {
                    "GOAWAY".to_string()
                };
                H2Frame::GoAway(msg)
            }
            0x08 => {
                if body.len() != 4 {
                    return Err("Invalid WINDOW_UPDATE frame size".to_string());
                }
                let increment = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7FFF_FFFF;
                H2Frame::WindowUpdate { stream_id, increment }
            }
            _ => H2Frame::Other,
        };
        Ok(Some((frame, total)))
    }

    fn serialize_settings(settings: &[(u16, u32)], stream_id: u32, flags: u8) -> Vec<u8> {
        let len = (settings.len() * 6) as u32;
        let b = len.to_be_bytes();
        let mut out = Vec::with_capacity(H2_FRAME_HEADER_LEN + len as usize);
        out.extend_from_slice(&[b[1], b[2], b[3], 0x04, flags]);
        out.extend_from_slice(&stream_id.to_be_bytes());
        for &(id, val) in settings {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&val.to_be_bytes());
        }
        out
    }

    fn serialize_window_update(stream_id: u32, increment: u32) -> Vec<u8> {
        let mut out = vec![0x00, 0x00, 0x04, 0x08, 0x00];
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(&increment.to_be_bytes());
        out
    }

    fn serialize_headers(stream_id: u32) -> Vec<u8> {
        let mut out = vec![0x00, 0x00, 0x00, 0x01, 0x04];
        out.extend_from_slice(&stream_id.to_be_bytes());
        out
    }

    fn serialize_data(stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() as u32).to_be_bytes();
        let mut out = Vec::with_capacity(H2_FRAME_HEADER_LEN + payload.len());
        out.extend_from_slice(&[len[1], len[2], len[3], 0x00, 0x00]);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn serialize_ping_ack(opaque: [u8; 8]) -> Vec<u8> {
        let mut out = vec![0x00, 0x00, 0x08, 0x06, 0x01, 0, 0, 0, 0];
        out.extend_from_slice(&opaque);
        out
    }
}

pub struct RemoteXpcConn<S> {
    inner: S,
    recv_buf: Vec<u8>,
    cache: HashMap<u32, VecDeque<Vec<u8>>>,
    partial_xpc: HashMap<u32, Vec<u8>>,
    conn_send_window: i64,
    stream_send_windows: HashMap<u32, i64>,
    peer_initial_window: i64,
    root_id: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> RemoteXpcConn<S> {
    pub async fn connect_and_handshake(mut inner: S) -> Result<Self, String> {
        tokio::time::timeout(Duration::from_secs(5), inner.write_all(HTTP2_MAGIC))
            .await
            .map_err(|_| "HTTP/2 magic write timeout".to_string())?
            .map_err(|e| format!("HTTP/2 magic write failed: {}", e))?;
        inner.flush().await.map_err(|e| e.to_string())?;

        let mut conn = Self {
            inner,
            recv_buf: Vec::new(),
            cache: HashMap::new(),
            partial_xpc: HashMap::new(),
            conn_send_window: H2_DEFAULT_WINDOW,
            stream_send_windows: HashMap::new(),
            peer_initial_window: H2_DEFAULT_WINDOW,
            root_id: 1,
        };

        // Standard RemoteXPC HTTP/2 setup sequence
        conn.write_raw(&H2Frame::serialize_settings(&[(0x03, 100), (0x04, 1_048_576)], 0, 0))
            .await?;
        conn.write_raw(&H2Frame::serialize_window_update(0, 983_041))
            .await?;
        conn.open_stream(XPC_ROOT_CHANNEL).await?;
        conn.send_channel(
            XPC_ROOT_CHANNEL,
            XpcMessage {
                flags: 0x0000_0001,
                message: Some(XpcValue::Dictionary(Vec::new())),
            }
            .encode(conn.root_id),
        )
        .await?;

        conn.open_stream(XPC_REPLY_CHANNEL).await?;
        conn.send_channel(
            XPC_REPLY_CHANNEL,
            XpcMessage {
                flags: 0x0040_0001, // InitHandshake | AlwaysSet
                message: None,
            }
            .encode(conn.root_id),
        )
        .await?;

        conn.send_channel(
            XPC_ROOT_CHANNEL,
            XpcMessage {
                flags: 0x0000_0201,
                message: None,
            }
            .encode(conn.root_id),
        )
        .await?;

        Ok(conn)
    }

    async fn write_raw(&mut self, bytes: &[u8]) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(5), self.inner.write_all(bytes))
            .await
            .map_err(|_| "RemoteXPC write timeout".to_string())?
            .map_err(|e| format!("RemoteXPC write failed: {}", e))?;
        self.inner.flush().await.map_err(|e| e.to_string())
    }

    async fn open_stream(&mut self, stream_id: u32) -> Result<(), String> {
        self.cache.entry(stream_id).or_default();
        self.write_raw(&H2Frame::serialize_headers(stream_id)).await
    }

    async fn pump(&mut self) -> Result<(), String> {
        let frame = loop {
            if let Some((frame, consumed)) = H2Frame::parse(&self.recv_buf)? {
                self.recv_buf.drain(..consumed);
                break frame;
            }
            let mut tmp = [0u8; 16384];
            let n = tokio::time::timeout(Duration::from_secs(6), self.inner.read(&mut tmp))
                .await
                .map_err(|_| "RemoteXPC HTTP/2 read timeout".to_string())?
                .map_err(|e| format!("RemoteXPC HTTP/2 read failed: {}", e))?;
            if n == 0 {
                return Err("RemoteXPC HTTP/2 connection closed by peer".to_string());
            }
            self.recv_buf.extend_from_slice(&tmp[..n]);
        };

        match frame {
            H2Frame::Settings { stream_id, flags, initial_window } if flags != 1 => {
                if let Some(new_w) = initial_window {
                    let delta = new_w as i64 - self.peer_initial_window;
                    self.peer_initial_window = new_w as i64;
                    for w in self.stream_send_windows.values_mut() {
                        *w += delta;
                    }
                }
                self.write_raw(&H2Frame::serialize_settings(&[], stream_id, 1))
                    .await?;
            }
            H2Frame::WindowUpdate { stream_id, increment } => {
                if stream_id == 0 {
                    self.conn_send_window += increment as i64;
                } else {
                    let init = self.peer_initial_window;
                    *self.stream_send_windows.entry(stream_id).or_insert(init) += increment as i64;
                }
            }
            H2Frame::Ping { opaque, ack: false } => {
                self.write_raw(&H2Frame::serialize_ping_ack(opaque)).await?;
            }
            H2Frame::GoAway(msg) => {
                return Err(format!("RemoteXPC GOAWAY: {}", msg));
            }
            H2Frame::RstStream => {
                return Err("RemoteXPC RST_STREAM".to_string());
            }
            H2Frame::Data { stream_id, payload } => {
                let len = payload.len() as u32;
                self.cache.entry(stream_id).or_default().push_back(payload);
                if len > 0 {
                    let mut upd = H2Frame::serialize_window_update(0, len);
                    upd.extend_from_slice(&H2Frame::serialize_window_update(stream_id, len));
                    self.write_raw(&upd).await?;
                }
            }
            H2Frame::Settings { .. } | H2Frame::Headers | H2Frame::Ping { .. } | H2Frame::Other => {}
        }
        Ok(())
    }

    async fn send_channel(&mut self, stream_id: u32, payload: Vec<u8>) -> Result<(), String> {
        const MAX_FRAME_SIZE: usize = 16384;
        let init_win = self.peer_initial_window;
        for chunk in payload.chunks(MAX_FRAME_SIZE) {
            let need = chunk.len() as i64;
            loop {
                let sw = *self.stream_send_windows.entry(stream_id).or_insert(init_win);
                if self.conn_send_window >= need && sw >= need {
                    break;
                }
                self.pump().await?;
            }
            let frame = H2Frame::serialize_data(stream_id, chunk);
            self.write_raw(&frame).await?;
            self.conn_send_window -= need;
            if let Some(w) = self.stream_send_windows.get_mut(&stream_id) {
                *w -= need;
            }
        }
        Ok(())
    }

    async fn send_object(&mut self, obj: XpcValue, expect_reply: bool) -> Result<(), String> {
        let mut flags = 0x0000_0101_u32; // DataFlag | AlwaysSet
        if expect_reply {
            flags |= 0x0001_0000; // WantingReply
        }
        let encoded = XpcMessage { flags, message: Some(obj) }.encode(self.root_id);
        self.send_channel(XPC_ROOT_CHANNEL, encoded).await
    }

    async fn recv_channel_xpc(&mut self, channel: u32) -> Result<XpcValue, String> {
        loop {
            {
                let buf = self.partial_xpc.entry(channel).or_default();
                if let Some((msg, consumed)) = XpcMessage::try_decode(buf)? {
                    buf.drain(..consumed);
                    let _ = msg.flags;
                    if let Some(inner) = msg.message {
                        if let Some(entries) = inner.as_dict() {
                            if entries.is_empty() {
                                continue;
                            }
                        }
                        return Ok(inner);
                    }
                    continue;
                }
            }
            self.cache.entry(channel).or_default();
            loop {
                if let Some(chunk) = self.cache.get_mut(&channel).and_then(|c| c.pop_front()) {
                    self.partial_xpc.entry(channel).or_default().extend_from_slice(&chunk);
                    break;
                }
                self.pump().await?;
            }
        }
    }

    async fn send_rsd_device_handshake(&mut self, host_uuid: [u8; 16]) -> Result<(), String> {
        let msg = XpcValue::Dictionary(vec![
            ("MessageType".to_string(), XpcValue::String("Handshake".to_string())),
            ("MessagingProtocolVersion".to_string(), XpcValue::UInt64(7)),
            ("UUID".to_string(), XpcValue::Uuid(host_uuid)),
            (
                "Properties".to_string(),
                XpcValue::Dictionary(vec![
                    ("RemoteXPCVersionFlags".to_string(), XpcValue::UInt64(0x0100_0000_0000_0006)),
                    ("SensitivePropertiesVisible".to_string(), XpcValue::Bool(true)),
                ]),
            ),
            ("Services".to_string(), XpcValue::Dictionary(Vec::new())),
        ]);
        self.send_object(msg, false).await
    }
}

// ==============================================================================
// RSD Service Table & Persistent Tunnel Session
// ==============================================================================

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RsdServiceInfo {
    pub port: u16,
    pub uses_remote_xpc: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RsdHandshakeData {
    pub services: HashMap<String, RsdServiceInfo>,
    pub uuid: String,
    pub product_type: Option<String>,
    pub os_version: Option<String>,
}

const RSD_UUID_KEY_CANDIDATES: &[&str] = &[
    "UUID",
    "uuid",
    "UniqueDeviceID",
    "DeviceID",
    "UDID",
    "udid",
    "identifier",
    "pairedUDID",
];

fn extract_rsd_device_id(root: &XpcValue, props: Option<&XpcValue>) -> Option<String> {
    if let Some(p) = props {
        for key in ["UniqueDeviceID", "DeviceID", "UDID", "udid", "pairedUDID", "UUID", "uuid", "identifier"] {
            if let Some(id) = p.dict_get_ci(&[key]).and_then(|v| v.as_id_string()) {
                return Some(id);
            }
        }
    }
    for key in RSD_UUID_KEY_CANDIDATES {
        if let Some(id) = root.dict_get_ci(&[key]).and_then(|v| v.as_id_string()) {
            return Some(id);
        }
    }
    None
}

async fn perform_rsd_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    uuid_seed: Option<&str>,
    fallback_udid: Option<&str>,
) -> Result<RsdHandshakeData, String> {
    let host_uuid = stable_handshake_uuid(uuid_seed);
    let mut xpc = RemoteXpcConn::connect_and_handshake(stream).await?;
    xpc.send_rsd_device_handshake(host_uuid).await?;

    let mut root = xpc.recv_channel_xpc(XPC_ROOT_CHANNEL).await?;
    for attempt in 0..3 {
        let msg_type = root
            .dict_get_ci(&["MessageType", "messageType"])
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let has_services = root.dict_get_ci(&["Services", "services"]).is_some();
        let props_summary = root
            .dict_get_ci(&["Properties", "properties"])
            .map(|p| p.summarize_dict_keys())
            .unwrap_or_default();
        eprintln!(
            "localdev: rsd handshake rx#{} msg_type={:?} keys=[{}] props=[{}]",
            attempt + 1,
            msg_type,
            root.summarize_dict_keys(),
            props_summary
        );
        if has_services
            || msg_type
                .as_deref()
                .map(|m| m.eq_ignore_ascii_case("Handshake"))
                .unwrap_or(false)
        {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(1200), xpc.recv_channel_xpc(XPC_ROOT_CHANNEL)).await {
            Ok(Ok(next_msg)) => root = next_msg,
            _ => break,
        }
    }

    let props = root.dict_get_ci(&["Properties", "properties"]);
    let uuid = extract_rsd_device_id(&root, props)
        .or_else(|| fallback_udid.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
        .or_else(|| uuid_seed.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
        .unwrap_or_else(|| format_uuid_hyphenated(&host_uuid));

    let product_type = props
        .and_then(|p| p.dict_get_ci(&["ProductType", "productType"]))
        .and_then(|v| v.as_id_string());
    let os_version = props
        .and_then(|p| p.dict_get_ci(&["OSVersion", "osVersion", "ProductVersion"]))
        .and_then(|v| v.as_id_string());

    let root_keys_diag = root.summarize_dict_keys();
    let services_dict = root
        .dict_get_ci(&["Services", "services"])
        .and_then(|v| v.as_dict())
        .or_else(|| {
            props
                .and_then(|p| p.dict_get_ci(&["Services", "services"]))
                .and_then(|v| v.as_dict())
        })
        .ok_or_else(|| {
            format!(
                "Missing Services dictionary in RSD Handshake response (keys: [{}])",
                root_keys_diag
            )
        })?;

    let mut services = HashMap::new();
    for (name, svc) in services_dict {
        let port = match svc.dict_get_ci(&["Port", "port"]).and_then(|v| v.as_u16()) {
            Some(p) => p,
            None => continue,
        };
        let uses_remote_xpc = svc
            .dict_get_ci(&["Properties", "properties"])
            .and_then(|p| p.dict_get_ci(&["UsesRemoteXPC", "usesRemoteXPC"]))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        services.insert(
            name.clone(),
            RsdServiceInfo {
                port,
                uses_remote_xpc,
            },
        );
    }

    Ok(RsdHandshakeData {
        services,
        uuid,
        product_type,
        os_version,
    })
}

#[allow(dead_code)]
pub enum RsdTransport {
    CdTunnel {
        handle: AdapterHandle,
        control: Arc<tokio::sync::Mutex<RpPairingControlClient>>,
    },
    DirectHost {
        host: String,
    },
}

#[allow(dead_code)]
pub struct RsdTunnelSession {
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub iface: Option<String>,
    pub udid: String,
    pub product_type: Option<String>,
    pub os_version: Option<String>,
    pub services: HashMap<String, RsdServiceInfo>,
    pub transport: RsdTransport,
}

impl RsdTunnelSession {
    /// Connects to `host:port` (typically `10.7.0.1:49152`), performs RPPairing
    /// `attemptPairVerify` + `verifyManualPairing` + `createListener` + TLS-PSK `CDTunnel`
    /// + `jktcp` TCP/IPv6 + `RsdHandshake`.
    pub fn connect_remote_pairing(
        host: &str,
        port: u16,
        iface: Option<String>,
        rp: &RemotePairingFile,
    ) -> Result<Self, LockdownError> {
        let rt = runtime().map_err(|e| {
            LockdownError::new(LockdownErrorKind::ProtocolError, LockdownStage::Protocol, e)
        })?;
        let host_owned = host.to_string();
        let rp_cloned = rp.clone();
        let iface_clone = iface.clone();

        rt.block_on(async move {
            let timeout = Duration::from_millis(2200);
            let ctrl_stream =
                connect_async_transport(host_owned.clone(), port, timeout, LockdownStage::TcpConnect, false)
                    .await?;
            let mut control = RpPairingControlClient::new(ctrl_stream)
                .await
                .map_err(|e| LockdownError::new(LockdownErrorKind::ProtocolError, LockdownStage::Protocol, e))?;

            if let Err(err) = control.attempt_pair_verify().await {
                if matches!(err, RpProtocolError::NotRpPairing(_)) {
                    // Some custom setups forward 49152 straight to HTTP/2 RSD
                    return Self::connect_direct_rsd_async(host_owned, port, iface_clone, Some(rp_cloned.identifier)).await;
                }
                return Err(err.into_lockdown_error(LockdownStage::Protocol));
            }

            control
                .validate_pairing(&rp_cloned)
                .await
                .map_err(|e| e.into_lockdown_error(LockdownStage::StartSession))?;

            let listener_port = control
                .create_tcp_listener()
                .await
                .map_err(|e| e.into_lockdown_error(LockdownStage::StartService))?;

            let tunnel_stream = connect_async_transport(
                host_owned.clone(),
                listener_port,
                Duration::from_millis(2500),
                LockdownStage::StartService,
                false,
            )
            .await?;

            let (tls_stream, tunnel_info) =
                connect_cd_tunnel(tunnel_stream, &control.encryption_key)
                    .await
                    .map_err(|e| {
                        LockdownError::new(
                            LockdownErrorKind::ProtocolError,
                            LockdownStage::TlsUpgrade,
                            format!("TLS-PSK/CDTunnel tại {}:{}: {}", host_owned, listener_port, e),
                        )
                    })?;

            let client_ip: IpAddr = tunnel_info.client_address.parse().map_err(|e| {
                LockdownError::new(LockdownErrorKind::ProtocolError, LockdownStage::StartSession, format!("Bad client IP: {}", e))
            })?;
            let server_ip: IpAddr = tunnel_info.server_address.parse().map_err(|e| {
                LockdownError::new(LockdownErrorKind::ProtocolError, LockdownStage::StartSession, format!("Bad server IP: {}", e))
            })?;

            let mut adapter = Adapter::new(Box::new(tls_stream), client_ip, server_ip);
            adapter.set_mss((tunnel_info.mtu as usize).saturating_sub(60).max(512));
            let mut handle = adapter.to_async_handle();

            let rsd_stream = tokio::time::timeout(
                Duration::from_secs(6),
                handle.connect(tunnel_info.server_rsd_port),
            )
            .await
            .map_err(|_| {
                LockdownError::with_errno(
                    LockdownErrorKind::Timeout,
                    LockdownStage::Protocol,
                    Some(60),
                    format!("jktcp connect RSD port {} timed out", tunnel_info.server_rsd_port),
                )
            })?
            .map_err(|e| {
                LockdownError::new(
                    LockdownErrorKind::ProtocolError,
                    LockdownStage::Protocol,
                    format!("jktcp connect RSD port {} failed: {}", tunnel_info.server_rsd_port, e),
                )
            })?;

            let fallback_id = control
                .peer_udid
                .clone()
                .or_else(|| rp_cloned.udid.clone())
                .unwrap_or_else(|| rp_cloned.identifier.clone());
            let rsd = perform_rsd_handshake(rsd_stream, Some(&rp_cloned.identifier), Some(&fallback_id))
                .await
                .map_err(|e| {
                    LockdownError::new(LockdownErrorKind::ProtocolError, LockdownStage::Protocol, e)
                })?;

            let resolved_udid = if !rsd.uuid.is_empty() {
                rsd.uuid
            } else {
                fallback_id
            };

            Ok(RsdTunnelSession {
                endpoint_host: host_owned,
                endpoint_port: port,
                iface: iface_clone,
                udid: resolved_udid,
                product_type: rsd.product_type,
                os_version: rsd.os_version,
                services: rsd.services,
                transport: RsdTransport::CdTunnel {
                    handle,
                    control: Arc::new(tokio::sync::Mutex::new(control)),
                },
            })
        })
    }

    pub fn connect_direct_rsd(
        host: &str,
        port: u16,
        iface: Option<String>,
    ) -> Result<Self, LockdownError> {
        let rt = runtime().map_err(|e| {
            LockdownError::new(LockdownErrorKind::ProtocolError, LockdownStage::Protocol, e)
        })?;
        let host_owned = host.to_string();
        rt.block_on(Self::connect_direct_rsd_async(host_owned, port, iface, None))
    }

    async fn connect_direct_rsd_async(
        host: String,
        port: u16,
        iface: Option<String>,
        uuid_seed: Option<String>,
    ) -> Result<Self, LockdownError> {
        let stream = connect_async_transport(
            host.clone(),
            port,
            Duration::from_millis(2000),
            LockdownStage::TcpConnect,
            false,
        )
        .await?;
        let rsd = perform_rsd_handshake(stream, uuid_seed.as_deref(), uuid_seed.as_deref())
            .await
            .map_err(|e| {
                LockdownError::new(
                    LockdownErrorKind::ProtocolError,
                    LockdownStage::Protocol,
                    format!("Direct RSD handshake {} failed: {}", format_endpoint_label(&host, port), e),
                )
            })?;

        Ok(RsdTunnelSession {
            endpoint_host: host.clone(),
            endpoint_port: port,
            iface,
            udid: rsd.uuid,
            product_type: rsd.product_type,
            os_version: rsd.os_version,
            services: rsd.services,
            transport: RsdTransport::DirectHost { host },
        })
    }

    pub fn endpoint_iface_label(&self) -> String {
        match &self.iface {
            Some(i) if !i.is_empty() => format!("{} · RSD", i),
            _ => "RSD".to_string(),
        }
    }

    fn connect_port_sync(&self, service_port: u16) -> Result<SyncTunnelStream, String> {
        let rt = runtime()?;
        match &self.transport {
            RsdTransport::CdTunnel { handle, .. } => {
                let mut h = handle.clone();
                let s = rt.block_on(async move {
                    tokio::time::timeout(Duration::from_secs(6), h.connect(service_port))
                        .await
                        .map_err(|_| format!("Tunnel connect port {} timeout", service_port))?
                        .map_err(|e| format!("Tunnel connect port {} failed: {}", service_port, e))
                })?;
                Ok(SyncTunnelStream::Jktcp {
                    stream: s,
                    read_timeout_secs: Arc::new(AtomicU64::new(12)),
                    write_timeout_secs: Arc::new(AtomicU64::new(12)),
                })
            }
            RsdTransport::DirectHost { host } => {
                let h = host.clone();
                let t = rt.block_on(connect_async_transport(
                    h,
                    service_port,
                    Duration::from_secs(4),
                    LockdownStage::StartService,
                    false,
                ))
                .map_err(|e| e.to_string())?;
                Ok(SyncTunnelStream::Direct(t))
            }
        }
    }

    /// Opens an RSD service port and performs the standard `RSDCheckin` + `StartService` exchange
    /// so lockdown-compatible plist/AFC protocols (HouseArrest, AFC, InstallationProxy, Heartbeat)
    /// run directly inside the encrypted CDTunnel without a second TLS layer.
    pub fn open_checked_in_service(&self, service_names: &[&str]) -> Result<SyncTunnelStream, String> {
        let mut last_err = String::new();
        for name in service_names {
            if let Some(info) = self.services.get(*name) {
                let mut stream = self
                    .connect_port_sync(info.port)?
                    .with_timeouts(12, 12);
                match perform_rsd_checkin(&mut stream) {
                    Ok(()) => return Ok(stream),
                    Err(e) => {
                        last_err = format!("{} (port {}): {}", name, info.port, e);
                    }
                }
            }
        }
        if last_err.is_empty() {
            let mut avail: Vec<&str> = self.services.keys().map(|s| s.as_str()).collect();
            avail.sort_unstable();
            Err(format!(
                "RSD chưa cung cấp dịch vụ {:?} (có {} services)",
                service_names,
                avail.len()
            ))
        } else {
            Err(last_err)
        }
    }

    /// Quick health check confirming the active CDTunnel & RSD listener still respond cleanly.
    pub fn verify_alive(&self) -> Result<(), String> {
        let ld = obfstr!("com.apple.mobile.lockdown.remote.trusted").to_string();
        if self.services.contains_key(ld.as_str()) {
            let mut stream = self
                .open_checked_in_service(&[ld.as_str()])?
                .with_timeouts(2, 2);
            let mut ping = HashMap::new();
            ping.insert("Label".to_string(), PlistValue::String("3105-x-PHUCVN".to_string()));
            ping.insert("Request".to_string(), PlistValue::String("QueryType".to_string()));
            super::tunnel::send_plist(&mut stream, &ping)?;
            let _ = super::tunnel::read_plist(&mut stream)?;
            return Ok(());
        }
        let hb = obfstr!("com.apple.mobile.heartbeat.shim.remote").to_string();
        let inst = obfstr!("com.apple.mobile.installation_proxy.shim.remote").to_string();
        let ha = obfstr!("com.apple.mobile.house_arrest.shim.remote").to_string();
        let _ = self.open_checked_in_service(&[hb.as_str(), inst.as_str(), ha.as_str()])?;
        Ok(())
    }

    /// Fetches installed apps via `com.apple.mobile.installation_proxy.shim.remote`
    /// or falls back to CoreDevice XPC `com.apple.coredevice.appservice` (`listapps`).
    pub fn scan_apps(&self) -> Result<Vec<LocalDevAppInfo>, String> {
        let inst_rsd = obfstr!("com.apple.mobile.installation_proxy.shim.remote").to_string();
        let inst_classic = obfstr!("com.apple.mobile.installation_proxy").to_string();
        let inst_candidates = [inst_rsd.as_str(), inst_classic.as_str()];

        let mut primary_apps: Option<Vec<LocalDevAppInfo>> = None;
        let mut inst_err: Option<String> = None;

        if let Ok(stream) = self.open_checked_in_service(&inst_candidates) {
            match super::apps::AppScanner::scan_user_apps_over_stream(
                super::tunnel::LockdownStream::RsdTunnel(stream),
            ) {
                Ok(list) if !list.is_empty() => {
                    primary_apps = Some(list);
                }
                Ok(_) => {}
                Err(e) => {
                    inst_err = Some(e);
                }
            }
        }

        if primary_apps.is_none() {
            if let Ok(stream) = self.open_checked_in_service(&inst_candidates) {
                match super::apps::AppScanner::lookup_user_apps_over_stream(
                    super::tunnel::LockdownStream::RsdTunnel(stream),
                ) {
                    Ok(list) if !list.is_empty() => {
                        primary_apps = Some(list);
                        inst_err = None;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        if inst_err.is_none() {
                            inst_err = Some(e);
                        }
                    }
                }
            }
        }

        let app_svc_name = obfstr!("com.apple.coredevice.appservice").to_string();
        let Some(info) = self.services.get(app_svc_name.as_str()) else {
            return primary_apps.ok_or_else(|| {
                inst_err.unwrap_or_else(|| {
                    "Không tìm thấy installation_proxy.shim.remote hoặc coredevice.appservice trong RSD"
                        .to_string()
                })
            });
        };
        let port = info.port;

        let core_device_req = |transport: &RsdTransport| -> Result<Vec<LocalDevAppInfo>, String> {
            let rt = runtime()?;
            match transport {
                RsdTransport::CdTunnel { handle, .. } => {
                    let mut h = handle.clone();
                    rt.block_on(async move {
                        let s = tokio::time::timeout(Duration::from_secs(6), h.connect(port))
                            .await
                            .map_err(|_| "AppService connect timeout".to_string())?
                            .map_err(|e| format!("AppService connect failed: {}", e))?;
                        tokio::time::timeout(Duration::from_secs(8), fetch_apps_via_coredevice_xpc(s))
                            .await
                            .map_err(|_| "AppService RPC timeout".to_string())?
                    })
                }
                RsdTransport::DirectHost { host } => {
                    let host_c = host.clone();
                    rt.block_on(async move {
                        let s = connect_async_transport(
                            host_c,
                            port,
                            Duration::from_secs(4),
                            LockdownStage::StartService,
                            false,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        tokio::time::timeout(Duration::from_secs(8), fetch_apps_via_coredevice_xpc(s))
                            .await
                            .map_err(|_| "AppService RPC timeout".to_string())?
                    })
                }
            }
        };

        let core_result = core_device_req(&self.transport);
        match (primary_apps, core_result) {
            (Some(mut list), Ok(extra)) => {
                // Giữ phân loại quyền chính xác từ installation_proxy, bổ sung các app/game còn thiếu từ CoreDevice listapps.
                let mut idx_by_bundle: HashMap<String, usize> = list
                    .iter()
                    .enumerate()
                    .map(|(i, a)| (a.bundle_id.clone(), i))
                    .collect();
                for app in extra {
                    if let Some(&idx) = idx_by_bundle.get(&app.bundle_id) {
                        if list[idx].display_name == list[idx].bundle_id && app.display_name != app.bundle_id {
                            list[idx].display_name = app.display_name;
                        }
                        if list[idx].bundle_path.is_none() {
                            list[idx].bundle_path = app.bundle_path;
                        }
                    } else {
                        idx_by_bundle.insert(app.bundle_id.clone(), list.len());
                        list.push(app);
                    }
                }
                list.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
                Ok(list)
            }
            (Some(list), Err(_)) => Ok(list),
            (None, Ok(extra)) => Ok(extra),
            (None, Err(core_err)) => Err(inst_err.unwrap_or(core_err)),
        }
    }

    pub fn close(self) {
        if let RsdTransport::CdTunnel { mut handle, .. } = self.transport {
            if let Ok(rt) = runtime() {
                let _ = rt.block_on(async move {
                    let _ = tokio::time::timeout(Duration::from_millis(250), handle.close()).await;
                });
            }
        }
    }
}

fn perform_rsd_checkin(stream: &mut SyncTunnelStream) -> Result<(), String> {
    let mut req = HashMap::new();
    req.insert("Label".to_string(), PlistValue::String("3105-x-PHUCVN".to_string()));
    req.insert("ProtocolVersion".to_string(), PlistValue::String("2".to_string()));
    req.insert("Request".to_string(), PlistValue::String("RSDCheckin".to_string()));

    let xml = serialize_xml_dict(&req);
    let bytes = xml.as_bytes();
    let len = bytes.len() as u32;
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(bytes);
    std::io::Write::write_all(stream, &frame)
        .map_err(|e| format!("RSDCheckin write failed: {}", e))?;
    std::io::Write::flush(stream).map_err(|e| e.to_string())?;

    let resp1 = super::tunnel::read_plist(stream)?;
    if resp1.get_string("Request").as_deref() != Some("RSDCheckin") {
        return Err("RSDCheckin reply mismatch".to_string());
    }
    let resp2 = super::tunnel::read_plist(stream)?;
    if resp2.get_string("Request").as_deref() != Some("StartService") {
        return Err("RSDCheckin StartService reply mismatch".to_string());
    }
    Ok(())
}

async fn fetch_apps_via_coredevice_xpc<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
) -> Result<Vec<LocalDevAppInfo>, String> {
    let mut xpc = RemoteXpcConn::connect_and_handshake(stream).await?;

    let input = XpcValue::Dictionary(vec![
        ("includeAppClips".to_string(), XpcValue::Bool(false)),
        ("includeRemovableApps".to_string(), XpcValue::Bool(true)),
        ("includeHiddenApps".to_string(), XpcValue::Bool(false)),
        ("includeInternalApps".to_string(), XpcValue::Bool(false)),
        ("includeDefaultApps".to_string(), XpcValue::Bool(false)),
        ("includeAppGroupIdentifiers".to_string(), XpcValue::Bool(false)),
        ("includeContainerPaths".to_string(), XpcValue::Bool(false)),
        ("requireContainerAccess".to_string(), XpcValue::Bool(false)),
    ]);

    let inv_id = format_uuid_hyphenated(&stable_handshake_uuid(Some("inv")));
    let dev_id = format_uuid_hyphenated(&stable_handshake_uuid(None));
    let req = XpcValue::Dictionary(vec![
        ("CoreDevice.CoreDeviceDDIProtocolVersion".to_string(), XpcValue::Int64(0)),
        ("CoreDevice.action".to_string(), XpcValue::Dictionary(Vec::new())),
        (
            "CoreDevice.coreDeviceVersion".to_string(),
            XpcValue::Dictionary(vec![
                ("components".to_string(), XpcValue::Array(vec![XpcValue::UInt64(629), XpcValue::UInt64(3)])),
                ("originalComponentsCount".to_string(), XpcValue::Int64(2)),
                ("stringValue".to_string(), XpcValue::String("629.3".to_string())),
            ]),
        ),
        ("CoreDevice.deviceIdentifier".to_string(), XpcValue::String(dev_id)),
        (
            "CoreDevice.featureIdentifier".to_string(),
            XpcValue::String("com.apple.coredevice.feature.listapps".to_string()),
        ),
        ("CoreDevice.input".to_string(), input),
        ("CoreDevice.invocationIdentifier".to_string(), XpcValue::String(inv_id)),
    ]);

    xpc.send_object(req, true).await?;
    let reply = xpc.recv_channel_xpc(XPC_REPLY_CHANNEL).await?;
    let output = reply
        .dict_get("CoreDevice.output")
        .ok_or_else(|| "CoreDevice listapps thiếu CoreDevice.output".to_string())?;
    let items = output
        .as_array()
        .ok_or_else(|| "CoreDevice.output không phải mảng".to_string())?;

    let mut apps = Vec::new();
    let mut seen = HashSet::new();
    for item in items {
        let Some(bundle_id) = item
            .dict_get("bundleIdentifier")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        if !seen.insert(bundle_id.to_string()) {
            continue;
        }
        let is_app_clip = item
            .dict_get("isAppClip")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if is_app_clip {
            continue;
        }
        let is_first_party = item
            .dict_get("isFirstParty")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let is_removable = item
            .dict_get("isRemovable")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if is_first_party && !is_removable {
            continue;
        }
        let display_name = item
            .dict_get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(bundle_id)
            .to_string();
        let version = item
            .dict_get("version")
            .or_else(|| item.dict_get("bundleVersion"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("1.0")
            .to_string();
        let bundle_path = item
            .dict_get("path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let is_dev = item
            .dict_get("isDeveloperApp")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let file_sharing = item
            .dict_get("fileSharingEnabled")
            .or_else(|| item.dict_get("isFileSharingEnabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let access_type = if is_dev {
            "FullContainer".to_string()
        } else if file_sharing {
            "DocumentsOnly".to_string()
        } else {
            "SandboxLocked".to_string()
        };
        apps.push(LocalDevAppInfo {
            bundle_id: bundle_id.to_string(),
            display_name,
            version,
            access_type,
            file_sharing_enabled: is_dev || file_sharing,
            container_path: None,
            bundle_path,
            is_developer_signed: is_dev,
        });
    }
    apps.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    Ok(apps)
}
