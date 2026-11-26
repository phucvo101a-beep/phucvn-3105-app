//! Apple File Conduit (AFC) Protocol Client Implementation
//! Pure-Rust, chunked I/O (64KB - 256KB), supports iOS 15.0 - iOS 27.2.1

use super::pairing::PairingFile;
use super::tunnel::{LockdownClient, LockdownStream};
use std::collections::HashMap;
use std::io::{Read, Write};

pub const AFC_MAGIC: u64 = 0x4141504c36414643; // "CFA6LPAA" in little-endian

pub const AFC_OP_STATUS: u64 = 0x00000001;
pub const AFC_OP_DATA: u64 = 0x00000002;
pub const AFC_OP_READ_DIR: u64 = 0x00000003;
pub const AFC_OP_READ_FILE: u64 = 0x00000004;
pub const AFC_OP_WRITE_FILE: u64 = 0x00000005;
pub const AFC_OP_REMOVE_PATH: u64 = 0x00000008;
pub const AFC_OP_MAKE_DIR: u64 = 0x00000009;
pub const AFC_OP_GET_FILE_INFO: u64 = 0x0000000a;
pub const AFC_OP_FILE_OPEN: u64 = 0x0000000d;
pub const AFC_OP_FILE_CLOSE: u64 = 0x00000014;
pub const AFC_OP_RENAME_PATH: u64 = 0x00000018;

// File open modes
pub const AFC_FOPEN_RDONLY: u64 = 0x00000001;
pub const AFC_FOPEN_RW: u64 = 0x00000002;
pub const AFC_FOPEN_WRONLY: u64 = 0x00000003;
pub const AFC_FOPEN_WR: u64 = 0x00000004;
pub const AFC_FOPEN_APPEND: u64 = 0x00000005;
pub const AFC_FOPEN_RDAPPEND: u64 = 0x00000006;

pub const AFC_CHUNK_SIZE: usize = 128 * 1024; // 128 KB buffer

pub struct AfcClient {
    stream: LockdownStream,
    packet_seq: u64,
}

impl AfcClient {
    pub fn new(stream: LockdownStream) -> Self {
        stream.set_timeouts(15, 15);
        Self {
            stream,
            packet_seq: 0,
        }
    }

    /// Connects to device file system trying `com.apple.afc2` (jailbreak root) first,
    /// falling back to `com.apple.afc` (Media partition: Downloads, DCIM, Books)
    pub fn connect_device_afc(ip: &str, port: u16, pairing: &PairingFile) -> Result<(Self, String), String> {
        let mut lockdown = LockdownClient::connect(ip, port, pairing)?;

        // Try afc2 first
        if let Ok((sock, _p, _ssl)) = lockdown.start_service("com.apple.afc2") {
            return Ok((Self::new(sock), "afc2".to_string()));
        }

        // Fallback cleanly to afc
        let (sock, _p, _ssl) = lockdown.start_service("com.apple.afc")
            .map_err(|e| format!("Both afc2 and afc service failed: {}", e))?;
        Ok((Self::new(sock), "afc".to_string()))
    }

    /// Sends an AFC request and reads the response packet
    fn dispatch(&mut self, op: u64, header_args: &[u8], payload: &[u8]) -> Result<(u64, Vec<u8>), String> {
        self.packet_seq += 1;
        let entire_len = (40 + header_args.len() + payload.len()) as u64;
        let this_len = (40 + header_args.len()) as u64;

        let mut header = [0u8; 40];
        header[0..8].copy_from_slice(&AFC_MAGIC.to_le_bytes());
        header[8..16].copy_from_slice(&entire_len.to_le_bytes());
        header[16..24].copy_from_slice(&this_len.to_le_bytes());
        header[24..32].copy_from_slice(&self.packet_seq.to_le_bytes());
        header[32..40].copy_from_slice(&op.to_le_bytes());

        self.stream.write_all(&header).map_err(|e| format!("AFC header write failed: {}", e))?;
        if !header_args.is_empty() {
            self.stream.write_all(header_args).map_err(|e| e.to_string())?;
        }
        if !payload.is_empty() {
            self.stream.write_all(payload).map_err(|e| e.to_string())?;
        }
        self.stream.flush().map_err(|e| e.to_string())?;

        // Read response header
        let mut resp_header = [0u8; 40];
        self.stream.read_exact(&mut resp_header).map_err(|e| format!("AFC read header failed: {}", e))?;

        let magic = u64::from_le_bytes([
            resp_header[0], resp_header[1], resp_header[2], resp_header[3],
            resp_header[4], resp_header[5], resp_header[6], resp_header[7],
        ]);
        if magic != AFC_MAGIC {
            return Err("Invalid AFC response magic".to_string());
        }

        let resp_entire_len = u64::from_le_bytes([
            resp_header[8], resp_header[9], resp_header[10], resp_header[11],
            resp_header[12], resp_header[13], resp_header[14], resp_header[15],
        ]);
        let resp_op = u64::from_le_bytes([
            resp_header[32], resp_header[33], resp_header[34], resp_header[35],
            resp_header[36], resp_header[37], resp_header[38], resp_header[39],
        ]);

        let payload_len = if resp_entire_len >= 40 { (resp_entire_len - 40) as usize } else { 0 };
        let mut resp_payload = vec![0u8; payload_len];
        if payload_len > 0 {
            self.stream.read_exact(&mut resp_payload).map_err(|e| format!("AFC read payload failed: {}", e))?;
        }

        if resp_op == AFC_OP_STATUS && payload_len >= 8 {
            let status = u64::from_le_bytes([
                resp_payload[0], resp_payload[1], resp_payload[2], resp_payload[3],
                resp_payload[4], resp_payload[5], resp_payload[6], resp_payload[7],
            ]);
            if status != 0 {
                return Err(format!("AFC returned error status: 0x{:08x}", status));
            }
        }

        Ok((resp_op, resp_payload))
    }

    /// Lists directory entries
    pub fn list_dir(&mut self, path: &str) -> Result<Vec<String>, String> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0); // Null terminated

        let (_op, payload) = self.dispatch(AFC_OP_READ_DIR, &[], &path_bytes)?;

        // Payload is null-terminated strings
        let mut entries = Vec::new();
        let mut start = 0;
        for (i, &b) in payload.iter().enumerate() {
            if b == 0 {
                if i > start {
                    let s = String::from_utf8_lossy(&payload[start..i]).to_string();
                    if s != "." && s != ".." {
                        entries.push(s);
                    }
                }
                start = i + 1;
            }
        }
        entries.sort();
        Ok(entries)
    }

    /// Retrieves file metadata (st_size, st_ifmt, st_mtime)
    pub fn get_file_info(&mut self, path: &str) -> Result<HashMap<String, String>, String> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);

        let (_op, payload) = self.dispatch(AFC_OP_GET_FILE_INFO, &[], &path_bytes)?;

        let mut info = HashMap::new();
        let mut pairs = Vec::new();
        let mut start = 0;
        for (i, &b) in payload.iter().enumerate() {
            if b == 0 {
                if i > start {
                    pairs.push(String::from_utf8_lossy(&payload[start..i]).to_string());
                }
                start = i + 1;
            }
        }

        for chunk in pairs.chunks(2) {
            if chunk.len() == 2 {
                info.insert(chunk[0].clone(), chunk[1].clone());
            }
        }
        Ok(info)
    }

    /// Opens a file for read/write
    pub fn file_open(&mut self, path: &str, mode: u64) -> Result<u64, String> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);

        let (_op, payload) = self.dispatch(AFC_OP_FILE_OPEN, &mode.to_le_bytes(), &path_bytes)?;
        if payload.len() < 8 {
            return Err("AFC file_open did not return handle".to_string());
        }
        let handle = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
            payload[4], payload[5], payload[6], payload[7],
        ]);
        Ok(handle)
    }

    /// Closes an open file handle
    pub fn file_close(&mut self, handle: u64) -> Result<(), String> {
        self.dispatch(AFC_OP_FILE_CLOSE, &handle.to_le_bytes(), &[])?;
        Ok(())
    }

    /// Reads an entire file in chunks
    pub fn read_file_full(&mut self, path: &str) -> Result<Vec<u8>, String> {
        let info = self.get_file_info(path)?;
        let total_size: usize = info.get("st_size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let handle = self.file_open(path, AFC_FOPEN_RDONLY)?;
        let mut content = Vec::with_capacity(total_size);

        let mut remaining = total_size;
        while remaining > 0 {
            let chunk_req = remaining.min(AFC_CHUNK_SIZE) as u64;
            let mut args = [0u8; 16];
            args[0..8].copy_from_slice(&handle.to_le_bytes());
            args[8..16].copy_from_slice(&chunk_req.to_le_bytes());

            let (op, chunk_data) = self.dispatch(AFC_OP_READ_FILE, &args, &[])?;
            if op != AFC_OP_DATA || chunk_data.is_empty() {
                break;
            }
            remaining -= chunk_data.len();
            content.extend_from_slice(&chunk_data);
        }

        self.file_close(handle)?;
        Ok(content)
    }

    /// Writes an entire file in chunks
    pub fn write_file_full(&mut self, path: &str, data: &[u8]) -> Result<(), String> {
        let handle = self.file_open(path, AFC_FOPEN_WRONLY)?;

        for chunk in data.chunks(AFC_CHUNK_SIZE) {
            self.dispatch(AFC_OP_WRITE_FILE, &handle.to_le_bytes(), chunk)?;
        }

        self.file_close(handle)?;
        Ok(())
    }

    /// Creates a directory
    pub fn make_dir(&mut self, path: &str) -> Result<(), String> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);
        self.dispatch(AFC_OP_MAKE_DIR, &[], &path_bytes)?;
        Ok(())
    }

    /// Removes a file or directory
    pub fn remove_path(&mut self, path: &str) -> Result<(), String> {
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);
        self.dispatch(AFC_OP_REMOVE_PATH, &[], &path_bytes)?;
        Ok(())
    }

    /// Renames a path
    pub fn rename_path(&mut self, old_path: &str, new_path: &str) -> Result<(), String> {
        let mut payload = Vec::new();
        payload.extend_from_slice(old_path.as_bytes());
        payload.push(0);
        payload.extend_from_slice(new_path.as_bytes());
        payload.push(0);
        self.dispatch(AFC_OP_RENAME_PATH, &[], &payload)?;
        Ok(())
    }
}
