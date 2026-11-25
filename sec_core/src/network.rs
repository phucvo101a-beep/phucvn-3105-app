//! Pure-Rust TLS Networking with SPKI Certificate Pinning & Chunked HTTP/1.1 Support

use obfstr::obfstr;
use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, SignatureScheme, Stream};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;

#[inline(always)]
pub fn is_localdev_vpn_allowed() -> bool {
    true
}

#[derive(Debug)]
pub struct SpkiPinningVerifier {
    pub primary_spki_pin: [u8; 32],
    pub backup_spki_pin: [u8; 32],
    pub expected_domain: String,
}

impl ServerCertVerifier for SpkiPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let name_str = match server_name {
            ServerName::DnsName(dns) => dns.as_ref(),
            _ => return Err(RustlsError::General(obfstr!("Non-DNS name rejected").to_string())),
        };
        if name_str != self.expected_domain {
            return Err(RustlsError::General(obfstr!("Hostname mismatch").to_string()));
        }

        let cert_der = end_entity.as_ref();
        let spki_bytes = extract_spki_der(cert_der)
            .ok_or_else(|| RustlsError::General(obfstr!("SPKI extraction failed").to_string()))?;
        let spki_hash = digest(&SHA256, spki_bytes);
        let cert_hash = digest(&SHA256, cert_der);

        let zero = [0u8; 32];
        let has_primary = !bool::from(self.primary_spki_pin.ct_eq(&zero));
        let has_backup = !bool::from(self.backup_spki_pin.ct_eq(&zero));

        let matches_primary = has_primary
            && (bool::from(spki_hash.as_ref().ct_eq(&self.primary_spki_pin))
                || bool::from(cert_hash.as_ref().ct_eq(&self.primary_spki_pin)));
        let matches_backup = has_backup
            && (bool::from(spki_hash.as_ref().ct_eq(&self.backup_spki_pin))
                || bool::from(cert_hash.as_ref().ct_eq(&self.backup_spki_pin)));

        if matches_primary || matches_backup {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(obfstr!("SPKI pin mismatch").to_string()))
        }
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

fn extract_spki_der(cert_der: &[u8]) -> Option<&[u8]> {
    if cert_der.len() < 30 || cert_der[0] != 0x30 {
        return None;
    }
    let mut idx = 1;
    let _cert_len = parse_der_length(cert_der, &mut idx)?;
    if idx >= cert_der.len() || cert_der[idx] != 0x30 {
        return None;
    }
    idx += 1;
    let _tbs_len = parse_der_length(cert_der, &mut idx)?;
    if idx < cert_der.len() && cert_der[idx] == 0xA0 {
        idx += 1;
        let vlen = parse_der_length(cert_der, &mut idx)?;
        idx += vlen;
    }
    skip_der_tlv(cert_der, &mut idx, 0x02)?;
    skip_der_tlv(cert_der, &mut idx, 0x30)?;
    skip_der_tlv(cert_der, &mut idx, 0x30)?;
    skip_der_tlv(cert_der, &mut idx, 0x30)?;
    skip_der_tlv(cert_der, &mut idx, 0x30)?;
    let spki_start = idx;
    if idx >= cert_der.len() || cert_der[idx] != 0x30 {
        return None;
    }
    idx += 1;
    let spki_content_len = parse_der_length(cert_der, &mut idx)?;
    let spki_end = idx + spki_content_len;
    if spki_end <= cert_der.len() {
        Some(&cert_der[spki_start..spki_end])
    } else {
        None
    }
}

fn parse_der_length(der: &[u8], idx: &mut usize) -> Option<usize> {
    if *idx >= der.len() {
        return None;
    }
    let b = der[*idx];
    *idx += 1;
    if b < 0x80 {
        Some(b as usize)
    } else {
        let num_bytes = (b & 0x7F) as usize;
        if *idx + num_bytes > der.len() || num_bytes > 4 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..num_bytes {
            len = (len << 8) | (der[*idx] as usize);
            *idx += 1;
        }
        Some(len)
    }
}

fn skip_der_tlv(der: &[u8], idx: &mut usize, expected_tag: u8) -> Option<()> {
    if *idx >= der.len() || der[*idx] != expected_tag {
        return None;
    }
    *idx += 1;
    let len = parse_der_length(der, idx)?;
    *idx += len;
    if *idx <= der.len() {
        Some(())
    } else {
        None
    }
}

fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0usize;
    while pos < raw.len() {
        let Some(rel_crlf) = raw[pos..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = std::str::from_utf8(&raw[pos..pos + rel_crlf])
            .map_err(|_| "Chunk header UTF8 error".to_string())?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|_| "Chunk size parse error".to_string())?;
        pos += rel_crlf + 2;
        if chunk_len == 0 {
            break;
        }
        if pos + chunk_len > raw.len() {
            return Err("Truncated HTTP chunk".to_string());
        }
        out.extend_from_slice(&raw[pos..pos + chunk_len]);
        pos += chunk_len;
        if pos + 2 <= raw.len() && &raw[pos..pos + 2] == b"\r\n" {
            pos += 2;
        }
    }
    Ok(out)
}

fn connect_tcp_any(domain: &str, port: u16) -> Result<TcpStream, String> {
    let host_port = format!("{domain}:{port}");
    let addrs = host_port
        .to_socket_addrs()
        .map_err(|_| obfstr!("DNS resolution failed").to_string())?;
    let mut last_err = String::from("No socket address");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(8)) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(format!("TCP connect error: {last_err}"))
}

/// Sends an encrypted HTTP/1.1 POST request over pinned TLS to `https://<domain><path>`.
pub fn post_encrypted_json(
    domain: &str,
    path: &str,
    json_body: &str,
    primary_pin: [u8; 32],
    backup_pin: [u8; 32],
    require_pin: bool,
) -> Result<String, String> {
    if require_pin && primary_pin == [0u8; 32] && backup_pin == [0u8; 32] {
        return Err(obfstr!("SPKI pin missing in pinned release build").to_string());
    }

    let tcp_stream = connect_tcp_any(domain, 443)?;
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(12)))
        .map_err(|e| e.to_string())?;
    tcp_stream
        .set_write_timeout(Some(Duration::from_secs(12)))
        .map_err(|e| e.to_string())?;

    let verifier = Arc::new(SpkiPinningVerifier {
        primary_spki_pin: primary_pin,
        backup_spki_pin: backup_pin,
        expected_domain: domain.to_string(),
    });

    let client_config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();

    let server_name = ServerName::try_from(domain.to_string())
        .map_err(|_| obfstr!("Invalid TLS server name").to_string())?;

    let mut conn = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|_| obfstr!("TLS handshake setup error").to_string())?;

    let mut stream_owner = tcp_stream;
    let mut sock = Stream::new(&mut conn, &mut stream_owner);

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: 3105SecCore/3.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        domain,
        json_body.len(),
        json_body
    );

    sock.write_all(req.as_bytes())
        .map_err(|_| obfstr!("TLS write failed").to_string())?;
    sock.flush()
        .map_err(|_| obfstr!("TLS flush failed").to_string())?;

    let mut response_bytes = Vec::new();
    let _ = sock.read_to_end(&mut response_bytes);
    if response_bytes.is_empty() {
        return Err(obfstr!("Empty TLS response").to_string());
    }

    let Some(hdr_end) = response_bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(obfstr!("Malformed HTTP response").to_string());
    };
    let hdr_str = String::from_utf8_lossy(&response_bytes[..hdr_end]);
    let body_slice = &response_bytes[hdr_end + 4..];
    let lower_hdr = hdr_str.to_ascii_lowercase();

    let status_code = hdr_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let decoded_body = if lower_hdr.contains(obfstr!("transfer-encoding: chunked")) {
        decode_chunked_body(body_slice)?
    } else {
        body_slice.to_vec()
    };

    let body_text = String::from_utf8_lossy(&decoded_body).to_string();
    if status_code >= 400 || status_code == 0 {
        return Err(format!("HTTP {status_code}: {body_text}"));
    }
    Ok(body_text)
}
