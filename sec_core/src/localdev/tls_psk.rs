//! Pure-Rust TLS 1.2 PSK (AES-256-CBC-SHA384 / AES-128-CBC-SHA) & CDTunnel Handshake
//! Compatible with `jktcp::ReadWrite` and iOS 17.4–27.2.1 `remotepairingd` CDTunnel.

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const TLS_12: [u8; 2] = [0x03, 0x03];
const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CT_ALERT: u8 = 0x15;
const CT_HANDSHAKE: u8 = 0x16;
const CT_APPLICATION_DATA: u8 = 0x17;
const TLS_MAX_PLAINTEXT: usize = 16384;

const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_SERVER_HELLO_DONE: u8 = 0x0E;
const HS_CLIENT_KEY_EXCHANGE: u8 = 0x10;
const HS_FINISHED: u8 = 0x14;

const PSK_CIPHER_SUITES: &[[u8; 2]] = &[
    [0x00, 0xAF], // TLS_PSK_WITH_AES_256_CBC_SHA384 (preferred by iOS)
    [0x00, 0x8C], // TLS_PSK_WITH_AES_128_CBC_SHA (fallback)
];

const CDTUNNEL_MAGIC: &[u8] = b"CDTunnel";
const DEFAULT_CDTUNNEL_MTU: u16 = 16000;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Negotiated CDTunnel network configuration returned by iOS after TLS-PSK handshake.
#[derive(Debug, Clone)]
pub struct CdTunnelInfo {
    pub client_address: String,
    pub netmask: String,
    pub server_address: String,
    pub mtu: u16,
    pub server_rsd_port: u16,
}

#[derive(Clone, Copy, Debug)]
enum CipherSuite {
    Aes128CbcSha,
    Aes256CbcSha384,
}

impl CipherSuite {
    fn from_bytes(b: [u8; 2]) -> Option<Self> {
        match b {
            [0x00, 0x8C] => Some(Self::Aes128CbcSha),
            [0x00, 0xAF] => Some(Self::Aes256CbcSha384),
            _ => None,
        }
    }

    fn enc_key_len(self) -> usize {
        match self {
            Self::Aes128CbcSha => 16,
            Self::Aes256CbcSha384 => 32,
        }
    }

    fn mac_key_len(self) -> usize {
        match self {
            Self::Aes128CbcSha => 20,
            Self::Aes256CbcSha384 => 48,
        }
    }
}

struct KeyBlock {
    client_mac_key: Vec<u8>,
    server_mac_key: Vec<u8>,
    client_write_key: Vec<u8>,
    server_write_key: Vec<u8>,
    suite: CipherSuite,
}

fn hmac_prf_hash(key: &[u8], data: &[u8], suite: CipherSuite) -> Result<Vec<u8>, String> {
    match suite {
        CipherSuite::Aes128CbcSha => {
            let mut mac = HmacSha256::new_from_slice(key).map_err(|e| e.to_string())?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CipherSuite::Aes256CbcSha384 => {
            let mut mac = HmacSha384::new_from_slice(key).map_err(|e| e.to_string())?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

fn prf(secret: &[u8], label: &[u8], seed: &[u8], len: usize, suite: CipherSuite) -> Result<Vec<u8>, String> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = hmac_prf_hash(secret, &label_seed, suite)?;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let mut input = Vec::with_capacity(a.len() + label_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_prf_hash(secret, &input, suite)?);
        a = hmac_prf_hash(secret, &a, suite)?;
    }
    out.truncate(len);
    Ok(out)
}

fn psk_premaster(psk: &[u8]) -> Vec<u8> {
    let psk_len = psk.len() as u16;
    let mut pm = Vec::with_capacity(4 + psk.len() * 2);
    pm.extend_from_slice(&psk_len.to_be_bytes());
    pm.resize(pm.len() + psk.len(), 0u8);
    pm.extend_from_slice(&psk_len.to_be_bytes());
    pm.extend_from_slice(psk);
    pm
}

fn derive_master_secret(
    psk: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: CipherSuite,
) -> Result<Vec<u8>, String> {
    let premaster = psk_premaster(psk);
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf(&premaster, b"master secret", &seed, 48, suite)
}

fn derive_key_block(
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: CipherSuite,
) -> Result<KeyBlock, String> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let mac_len = suite.mac_key_len();
    let key_len = suite.enc_key_len();
    let total = mac_len * 2 + key_len * 2;
    let kb = prf(master, b"key expansion", &seed, total, suite)?;

    let mut pos = 0;
    let client_mac_key = kb[pos..pos + mac_len].to_vec();
    pos += mac_len;
    let server_mac_key = kb[pos..pos + mac_len].to_vec();
    pos += mac_len;
    let client_write_key = kb[pos..pos + key_len].to_vec();
    pos += key_len;
    let server_write_key = kb[pos..pos + key_len].to_vec();

    Ok(KeyBlock {
        client_mac_key,
        server_mac_key,
        client_write_key,
        server_write_key,
        suite,
    })
}

fn compute_record_mac(
    mac_key: &[u8],
    seq: u64,
    ct: u8,
    data: &[u8],
    suite: CipherSuite,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(13 + data.len());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&[ct, 0x03, 0x03]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);

    match suite {
        CipherSuite::Aes128CbcSha => {
            let mut mac = HmacSha1::new_from_slice(mac_key).map_err(|e| e.to_string())?;
            mac.update(&buf);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        CipherSuite::Aes256CbcSha384 => {
            let mut mac = HmacSha384::new_from_slice(mac_key).map_err(|e| e.to_string())?;
            mac.update(&buf);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

fn encrypt_record(keys: &KeyBlock, seq: u64, ct: u8, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mac = compute_record_mac(&keys.client_mac_key, seq, ct, plaintext, keys.suite)?;
    let mut payload = Vec::with_capacity(plaintext.len() + mac.len() + 16);
    payload.extend_from_slice(plaintext);
    payload.extend_from_slice(&mac);

    let pad_len = 16 - (payload.len() % 16);
    payload.resize(payload.len() + pad_len, (pad_len as u8) - 1);

    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let ciphertext = match keys.suite {
        CipherSuite::Aes128CbcSha => {
            let enc = Aes128CbcEnc::new_from_slices(&keys.client_write_key[..16], &iv)
                .map_err(|e| e.to_string())?;
            enc.encrypt_padded_vec_mut::<NoPadding>(&payload)
        }
        CipherSuite::Aes256CbcSha384 => {
            let enc = Aes256CbcEnc::new_from_slices(&keys.client_write_key[..32], &iv)
                .map_err(|e| e.to_string())?;
            enc.encrypt_padded_vec_mut::<NoPadding>(&payload)
        }
    };

    let mut out = Vec::with_capacity(16 + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_record(
    keys: &KeyBlock,
    seq: u64,
    ct: u8,
    encrypted: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted.len() < 32 || (encrypted.len() - 16) % 16 != 0 {
        return Err("Invalid TLS CBC record length".to_string());
    }

    let iv = &encrypted[..16];
    let ciphertext = &encrypted[16..];

    let decrypted = match keys.suite {
        CipherSuite::Aes128CbcSha => {
            let dec = Aes128CbcDec::new_from_slices(&keys.server_write_key[..16], iv)
                .map_err(|e| e.to_string())?;
            dec.decrypt_padded_vec_mut::<NoPadding>(ciphertext)
                .map_err(|e| format!("CBC decrypt failed: {:?}", e))?
        }
        CipherSuite::Aes256CbcSha384 => {
            let dec = Aes256CbcDec::new_from_slices(&keys.server_write_key[..32], iv)
                .map_err(|e| e.to_string())?;
            dec.decrypt_padded_vec_mut::<NoPadding>(ciphertext)
                .map_err(|e| format!("CBC decrypt failed: {:?}", e))?
        }
    };

    let pad_byte = *decrypted.last().ok_or_else(|| "Empty TLS record".to_string())? as usize;
    let pad_total = pad_byte + 1;
    if pad_total > 16 || pad_total > decrypted.len() {
        return Err("Invalid TLS PKCS#7 padding".to_string());
    }
    let content_len = decrypted.len() - pad_total;
    let mac_len = keys.suite.mac_key_len();
    if content_len < mac_len {
        return Err("TLS record shorter than MAC".to_string());
    }

    let plaintext = &decrypted[..content_len - mac_len];
    let received_mac = &decrypted[content_len - mac_len..content_len];
    let expected_mac = compute_record_mac(&keys.server_mac_key, seq, ct, plaintext, keys.suite)?;
    if received_mac != expected_mac.as_slice() {
        return Err("TLS MAC verification failed".to_string());
    }
    Ok(plaintext.to_vec())
}

fn finished_verify_data(
    master: &[u8],
    label: &[u8],
    transcript: &[u8],
    suite: CipherSuite,
) -> Result<[u8; 12], String> {
    let hash: Vec<u8> = match suite {
        CipherSuite::Aes128CbcSha => Sha256::digest(transcript).to_vec(),
        CipherSuite::Aes256CbcSha384 => Sha384::digest(transcript).to_vec(),
    };
    let vd = prf(master, label, &hash, 12, suite)?;
    vd.try_into()
        .map_err(|_| "Unexpected Finished verify_data length".to_string())
}

fn make_record(ct: u8, payload: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + payload.len());
    rec.extend_from_slice(&[ct, 0x03, 0x03]);
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    rec
}

fn make_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(msg_type);
    let len = body.len() as u32;
    msg.extend_from_slice(&len.to_be_bytes()[1..]);
    msg.extend_from_slice(body);
    msg
}

async fn read_tls_record<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, Vec<u8>), String> {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("TLS header read failed: {}", e))?;
    let ct = header[0];
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| format!("TLS payload read failed: {}", e))?;
    Ok((ct, payload))
}

fn parse_handshake_messages(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut msgs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let msg_type = data[pos];
        let msg_len = u32::from_be_bytes([0, data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        if pos + 4 + msg_len > data.len() {
            break;
        }
        msgs.push((msg_type, data[pos..pos + 4 + msg_len].to_vec()));
        pos += 4 + msg_len;
    }
    msgs
}

/// Encrypted TLS 1.2 PSK stream compatible with `jktcp::ReadWrite`.
pub struct TlsPskStream<S> {
    inner: S,
    keys: KeyBlock,
    write_seq: u64,
    read_seq: u64,
    read_buf: Vec<u8>,
    pending_record: Vec<u8>,
    pending_record_total: usize,
    write_buf: Vec<u8>,
}

impl<S> std::fmt::Debug for TlsPskStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPskStream")
            .field("write_seq", &self.write_seq)
            .field("read_seq", &self.read_seq)
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> TlsPskStream<S> {
    pub async fn handshake(mut stream: S, psk: &[u8]) -> Result<Self, String> {
        let mut client_random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_random);
        let mut server_random = [0u8; 32];
        let mut selected_cipher = [0u8; 2];
        let mut transcript = Vec::new();

        // 1. ClientHello offering PSK cipher suites
        let mut ch_body = Vec::with_capacity(48);
        ch_body.extend_from_slice(&TLS_12);
        ch_body.extend_from_slice(&client_random);
        ch_body.push(0x00); // session_id_len = 0
        let suites_len = (PSK_CIPHER_SUITES.len() * 2) as u16;
        ch_body.extend_from_slice(&suites_len.to_be_bytes());
        for suite in PSK_CIPHER_SUITES {
            ch_body.extend_from_slice(suite);
        }
        ch_body.extend_from_slice(&[0x01, 0x00]); // null compression
        let ch = make_handshake(HS_CLIENT_HELLO, &ch_body);
        transcript.extend_from_slice(&ch);
        stream
            .write_all(&make_record(CT_HANDSHAKE, &ch))
            .await
            .map_err(|e| format!("TLS ClientHello write failed: {}", e))?;
        stream.flush().await.map_err(|e| e.to_string())?;

        // 2. Receive ServerHello .. ServerHelloDone
        let mut handshake_acc = Vec::new();
        let mut got_done = false;
        while !got_done {
            let (ct, payload) = read_tls_record(&mut stream).await?;
            if ct == CT_ALERT {
                let level = payload.first().copied().unwrap_or(0);
                let desc = payload.get(1).copied().unwrap_or(0);
                return Err(format!("TLS-PSK Alert during handshake: level={} desc={}", level, desc));
            }
            if ct != CT_HANDSHAKE {
                return Err(format!("Expected TLS handshake record, got ct={}", ct));
            }
            transcript.extend_from_slice(&payload);
            handshake_acc.extend_from_slice(&payload);

            let msgs = parse_handshake_messages(&handshake_acc);
            if msgs.is_empty() {
                continue;
            }
            let consumed: usize = msgs.iter().map(|(_, m)| m.len()).sum();
            handshake_acc.drain(..consumed);

            for (msg_type, msg_bytes) in msgs {
                match msg_type {
                    HS_SERVER_HELLO => {
                        if msg_bytes.len() >= 38 {
                            server_random.copy_from_slice(&msg_bytes[6..38]);
                            let sid_len = msg_bytes.get(38).copied().unwrap_or(0) as usize;
                            if msg_bytes.len() >= 39 + sid_len + 2 {
                                selected_cipher
                                    .copy_from_slice(&msg_bytes[39 + sid_len..39 + sid_len + 2]);
                            }
                        }
                    }
                    HS_SERVER_HELLO_DONE => {
                        got_done = true;
                    }
                    _ => {}
                }
            }
        }

        let suite = CipherSuite::from_bytes(selected_cipher).ok_or_else(|| {
            format!("Server picked unsupported PSK cipher suite {:02x?}", selected_cipher)
        })?;
        let master = derive_master_secret(psk, &client_random, &server_random, suite)?;
        let keys = derive_key_block(&master, &client_random, &server_random, suite)?;

        // 3. ClientKeyExchange (empty PSK identity) + ChangeCipherSpec + encrypted Finished
        let cke = make_handshake(HS_CLIENT_KEY_EXCHANGE, &[0x00, 0x00]);
        transcript.extend_from_slice(&cke);
        let mut out_flight = make_record(CT_HANDSHAKE, &cke);
        out_flight.extend_from_slice(&make_record(CT_CHANGE_CIPHER_SPEC, &[0x01]));

        let vd = finished_verify_data(&master, b"client finished", &transcript, suite)?;
        let fin = make_handshake(HS_FINISHED, &vd);
        let enc_fin = encrypt_record(&keys, 0, CT_HANDSHAKE, &fin)?;
        out_flight.extend_from_slice(&make_record(CT_HANDSHAKE, &enc_fin));

        stream
            .write_all(&out_flight)
            .await
            .map_err(|e| format!("TLS-PSK ClientKeyExchange/Finished write failed: {}", e))?;
        stream.flush().await.map_err(|e| e.to_string())?;

        // 4. Read Server ChangeCipherSpec + Server Finished
        let mut server_seq: u64 = 0;
        loop {
            let (ct, payload) = read_tls_record(&mut stream).await?;
            if ct == CT_ALERT {
                let level = payload.first().copied().unwrap_or(0);
                let desc = payload.get(1).copied().unwrap_or(0);
                return Err(format!("TLS-PSK Alert after Finished: level={} desc={}", level, desc));
            }
            match ct {
                CT_CHANGE_CIPHER_SPEC => {}
                CT_HANDSHAKE | CT_APPLICATION_DATA => {
                    let plain = decrypt_record(&keys, server_seq, CT_HANDSHAKE, &payload)?;
                    server_seq += 1;
                    if plain.len() >= 4 && plain[0] == HS_FINISHED {
                        break;
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            inner: stream,
            keys,
            write_seq: 1,
            read_seq: server_seq,
            read_buf: Vec::new(),
            pending_record: Vec::new(),
            pending_record_total: 0,
            write_buf: Vec::new(),
        })
    }

    pub async fn write_app_data(&mut self, data: &[u8]) -> Result<(), String> {
        for chunk in data.chunks(TLS_MAX_PLAINTEXT) {
            let enc = encrypt_record(&self.keys, self.write_seq, CT_APPLICATION_DATA, chunk)?;
            self.write_seq += 1;
            self.inner
                .write_all(&make_record(CT_APPLICATION_DATA, &enc))
                .await
                .map_err(|e| format!("TLS-PSK app data write failed: {}", e))?;
        }
        self.inner.flush().await.map_err(|e| e.to_string())
    }

    pub async fn read_app_data(&mut self) -> Result<Vec<u8>, String> {
        loop {
            let (ct, payload) = read_tls_record(&mut self.inner).await?;
            if ct == CT_ALERT {
                let level = payload.first().copied().unwrap_or(0);
                let desc = payload.get(1).copied().unwrap_or(0);
                return Err(format!("TLS-PSK Alert: level={} desc={}", level, desc));
            }
            if ct != CT_APPLICATION_DATA {
                continue;
            }
            let plain = decrypt_record(&self.keys, self.read_seq, CT_APPLICATION_DATA, &payload)?;
            self.read_seq += 1;
            return Ok(plain);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncRead for TlsPskStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.pending_record.len() >= 5 && this.pending_record_total == 0 {
                let body_len =
                    u16::from_be_bytes([this.pending_record[3], this.pending_record[4]]) as usize;
                this.pending_record_total = 5 + body_len;
            }

            if this.pending_record_total > 0
                && this.pending_record.len() >= this.pending_record_total
            {
                let ct = this.pending_record[0];
                let body = this.pending_record[5..this.pending_record_total].to_vec();
                this.pending_record.drain(..this.pending_record_total);
                this.pending_record_total = 0;

                if ct == CT_ALERT {
                    let desc = body.get(1).copied().unwrap_or(0);
                    if desc == 0 {
                        return Poll::Ready(Ok(())); // close_notify EOF
                    }
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        format!("TLS alert desc={}", desc),
                    )));
                }

                match decrypt_record(&this.keys, this.read_seq, ct, &body) {
                    Ok(plain) => {
                        this.read_seq += 1;
                        let n = buf.remaining().min(plain.len());
                        buf.put_slice(&plain[..n]);
                        if n < plain.len() {
                            this.read_buf.extend_from_slice(&plain[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Err(e) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e,
                        )));
                    }
                }
            }

            let mut tmp = [0u8; 16384];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.pending_record.extend_from_slice(&tmp[..n]);
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncWrite for TlsPskStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let chunk = &data[..data.len().min(TLS_MAX_PLAINTEXT)];
        let enc = match encrypt_record(&this.keys, this.write_seq, CT_APPLICATION_DATA, chunk) {
            Ok(v) => v,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                )));
            }
        };
        let record = make_record(CT_APPLICATION_DATA, &enc);
        this.write_seq += 1;

        match Pin::new(&mut this.inner).poll_write(cx, &record) {
            Poll::Ready(Ok(written)) => {
                if written < record.len() {
                    this.write_buf.extend_from_slice(&record[written..]);
                }
                Poll::Ready(Ok(chunk.len()))
            }
            Poll::Ready(Err(e)) => {
                this.write_seq -= 1;
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                this.write_buf = record;
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Performs TLS 1.2 PSK handshake followed by `CDTunnel` handshake, returning
/// the encrypted IPv6-packet tunnel stream plus negotiated tunnel configuration.
pub async fn connect_cd_tunnel<S: AsyncRead + AsyncWrite + Unpin + Send + Sync>(
    stream: S,
    psk: &[u8],
) -> Result<(TlsPskStream<S>, CdTunnelInfo), String> {
    let mut tls_stream = TlsPskStream::handshake(stream, psk).await?;

    let req_body = serde_json::to_vec(&serde_json::json!({
        "type": "clientHandshakeRequest",
        "mtu": DEFAULT_CDTUNNEL_MTU
    }))
    .map_err(|e| e.to_string())?;

    let mut pkt = Vec::with_capacity(CDTUNNEL_MAGIC.len() + 2 + req_body.len());
    pkt.extend_from_slice(CDTUNNEL_MAGIC);
    pkt.extend_from_slice(&(req_body.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&req_body);
    tls_stream.write_app_data(&pkt).await?;

    let resp_data = tls_stream.read_app_data().await?;
    let header_len = CDTUNNEL_MAGIC.len() + 2;
    if resp_data.len() < header_len || &resp_data[..CDTUNNEL_MAGIC.len()] != CDTUNNEL_MAGIC {
        return Err("Invalid CDTunnel handshake response header".to_string());
    }
    let body_len =
        u16::from_be_bytes([resp_data[CDTUNNEL_MAGIC.len()], resp_data[CDTUNNEL_MAGIC.len() + 1]])
            as usize;
    if resp_data.len() < header_len + body_len {
        return Err("Truncated CDTunnel handshake response".to_string());
    }
    let resp: JsonValue = serde_json::from_slice(&resp_data[header_len..header_len + body_len])
        .map_err(|e| format!("CDTunnel JSON parse failed: {}", e))?;

    let client_params = resp
        .get("clientParameters")
        .ok_or_else(|| "Missing clientParameters in CDTunnel response".to_string())?;
    let client_address = client_params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing clientParameters.address in CDTunnel response".to_string())?
        .to_string();
    let netmask = client_params
        .get("netmask")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mtu = client_params
        .get("mtu")
        .and_then(|v| v.as_u64())
        .unwrap_or(1500) as u16;
    let server_address = resp
        .get("serverAddress")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing serverAddress in CDTunnel response".to_string())?
        .to_string();
    let server_rsd_port = resp
        .get("serverRSDPort")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    if server_rsd_port == 0 {
        return Err("CDTunnel response reported serverRSDPort=0".to_string());
    }

    Ok((
        tls_stream,
        CdTunnelInfo {
            client_address,
            netmask,
            server_address,
            mtu,
            server_rsd_port,
        },
    ))
}
