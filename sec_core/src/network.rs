//! Pure-Rust TLS Networking with SPKI Certificate Pinning
//! Completely bypasses iOS CFNetwork / NSURLSession and system proxy configurations

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use obfstr::obfstr;
use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, SignatureScheme, Stream};

/// Certificate Pinning Verifier: Pins Subject Public Key Info (SPKI) SHA-256 Hash
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
        // 1. Verify hostname matches
        let name_str = match server_name {
            ServerName::DnsName(dns) => dns.as_ref(),
            _ => return Err(RustlsError::General(obfstr!("Non-DNS name rejected").to_string())),
        };

        if name_str != self.expected_domain {
            return Err(RustlsError::General(obfstr!("Hostname mismatch").to_string()));
        }

        // 2. Extract SPKI from X.509 DER Certificate
        let cert_der = end_entity.as_ref();
        let spki_bytes = extract_spki_der(cert_der)
            .ok_or_else(|| RustlsError::General(obfstr!("SPKI extraction failed").to_string()))?;

        // 3. Compute SHA-256 of SPKI
        let spki_hash = digest(&SHA256, spki_bytes);

        // 4. Compare against Primary and Backup pins
        if spki_hash.as_ref() == self.primary_spki_pin || spki_hash.as_ref() == self.backup_spki_pin {
            Ok(ServerCertVerified::assertion())
        } else {
            // Also allow leaf certificate full hash match if pin was configured as leaf cert pin
            let cert_hash = digest(&SHA256, cert_der);
            if cert_hash.as_ref() == self.primary_spki_pin || cert_hash.as_ref() == self.backup_spki_pin {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(RustlsError::General(
                    obfstr!("Certificate Pinning Violation: SPKI hash mismatch").to_string(),
                ))
            }
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

/// Helper to parse X.509 ASN.1 DER to locate the `SubjectPublicKeyInfo` sequence
fn extract_spki_der(cert_der: &[u8]) -> Option<&[u8]> {
    // Basic ASN.1 DER parse:
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    // tbsCertificate ::= SEQUENCE { version [0], serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo }
    if cert_der.len() < 30 || cert_der[0] != 0x30 {
        return None;
    }

    let mut idx = 1;
    let _cert_len = parse_der_length(cert_der, &mut idx)?;

    // Enter tbsCertificate
    if idx >= cert_der.len() || cert_der[idx] != 0x30 {
        return None;
    }
    idx += 1;
    let _tbs_len = parse_der_length(cert_der, &mut idx)?;

    // Optional [0] EXPLICIT version
    if idx < cert_der.len() && cert_der[idx] == 0xA0 {
        idx += 1;
        let vlen = parse_der_length(cert_der, &mut idx)?;
        idx += vlen;
    }

    // Skip serialNumber (INTEGER 0x02)
    skip_der_tlv(cert_der, &mut idx, 0x02)?;

    // Skip signature (SEQUENCE 0x30)
    skip_der_tlv(cert_der, &mut idx, 0x30)?;

    // Skip issuer (SEQUENCE 0x30)
    skip_der_tlv(cert_der, &mut idx, 0x30)?;

    // Skip validity (SEQUENCE 0x30)
    skip_der_tlv(cert_der, &mut idx, 0x30)?;

    // Skip subject (SEQUENCE 0x30)
    skip_der_tlv(cert_der, &mut idx, 0x30)?;

    // Now at SubjectPublicKeyInfo (SEQUENCE 0x30)
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

/// Send an encrypted HTTP POST request to `https://<domain><path>` directly over pinned TLS
pub fn post_encrypted_json(
    domain: &str,
    path: &str,
    json_body: &str,
    primary_pin: [u8; 32],
    backup_pin: [u8; 32],
) -> Result<String, String> {
    // 1. Establish raw TCP connection
    let addr = format!("{}:443", domain);
    let tcp_stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .or_else(|_| {
                use std::net::ToSocketAddrs;
                addr.to_socket_addrs().map(|mut it| it.next().unwrap())
            })
            .map_err(|e| format!("DNS/TCP connect error: {:?}", e))?,
        Duration::from_secs(8),
    )
    .map_err(|e| format!("TCP connection timeout: {:?}", e))?;

    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(12)))
        .map_err(|e| e.to_string())?;
    tcp_stream
        .set_write_timeout(Some(Duration::from_secs(12)))
        .map_err(|e| e.to_string())?;

    // 2. Setup TLS with Custom SPKI Pinning Verifier
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
        .map_err(|e| format!("Invalid DNS name: {:?}", e))?;

    let mut conn = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|e| format!("TLS connection error: {:?}", e))?;

    let mut sock = Stream::new(&mut conn, &mut (tcp_stream));

    // 3. Format HTTP/1.1 POST Request
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: 3105SecCore/2.0\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path,
        domain,
        json_body.len(),
        json_body
    );

    sock.write_all(request.as_bytes())
        .map_err(|e| format!("Socket write error: {:?}", e))?;
    sock.flush().map_err(|e| format!("Socket flush error: {:?}", e))?;

    // 4. Read HTTP Response
    let mut response_bytes = Vec::new();
    sock.read_to_end(&mut response_bytes)
        .map_err(|e| format!("Socket read error: {:?}", e))?;

    let response_str = String::from_utf8_lossy(&response_bytes);

    // Extract body after \r\n\r\n
    if let Some(pos) = response_str.find("\r\n\r\n") {
        Ok(response_str[pos + 4..].to_string())
    } else {
        Err(obfstr!("Malformed HTTP response").to_string())
    }
}
