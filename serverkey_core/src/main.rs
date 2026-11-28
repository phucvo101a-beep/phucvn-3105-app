mod crypto;
mod engine;
mod storage;

use crate::crypto::{verify_hmac_hex, ServerKeyMaterial};
use crate::engine::{handle_ci_register_build, handle_v3_request, CiRegisterRequest, V3EnvelopeRequest};
use crate::storage::Storage;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct CliDispatch {
    action: String,
    payload: Value,
}

fn load_env_file(path: &Path, map: &mut HashMap<String, String>) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_string();
            let mut val = v.trim().to_string();
            if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
            {
                val = val[1..val.len() - 1].to_string();
            }
            map.insert(key, val);
        }
    }
}

fn load_runtime_config() -> Result<(ServerKeyMaterial, Storage), String> {
    let mut env_map = HashMap::new();
    if let Ok(env_path) = env::var("SERVERKEY_ENV_FILE") {
        load_env_file(Path::new(&env_path), &mut env_map);
    } else {
        for candidate in [
            "../.env",
            ".env",
            "serverkey/.env",
            "/etc/phucvn3105/.env",
        ] {
            if Path::new(candidate).exists() {
                load_env_file(Path::new(candidate), &mut env_map);
                break;
            }
        }
    }
    for (k, v) in env::vars() {
        env_map.insert(k, v);
    }

    let keys = ServerKeyMaterial::from_env_map(&env_map)?;
    let data_dir = env_map
        .get("SERVERKEY_DATA_DIR")
        .cloned()
        .unwrap_or_else(|| "data".to_string());
    Ok((keys, Storage::new(PathBuf::from(data_dir))))
}

fn dispatch_action(
    storage: &Storage,
    keys: &ServerKeyMaterial,
    action: &str,
    payload: Value,
) -> (u16, Value) {
    match action {
        "v3" => match serde_json::from_value::<V3EnvelopeRequest>(payload) {
            Ok(req) => match handle_v3_request(storage, keys, &req) {
                Ok(val) => (200, val),
                Err((code, err)) => (code, err),
            },
            Err(_) => (400, json!({"error": "Invalid V3 envelope JSON"})),
        },
        "ci_register_build" => match serde_json::from_value::<CiRegisterRequest>(payload) {
            Ok(req) => match handle_ci_register_build(storage, keys, &req) {
                Ok(val) => (200, val),
                Err((code, err)) => (code, err),
            },
            Err(_) => (400, json!({"error": "Invalid CI payload"})),
        },
        "health" => (200, json!({"ok": true, "engine": "serverkey_core_rust", "v": 3})),
        _ => (404, json!({"error": "Unknown action"})),
    }
}

fn run_exec_mode(storage: &Storage, keys: &ServerKeyMaterial) -> i32 {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        println!("{}", json!({"http_status": 400, "body": {"error": "Stdin read error"}}));
        return 1;
    }
    let Ok(cmd) = serde_json::from_str::<CliDispatch>(&input) else {
        println!("{}", json!({"http_status": 400, "body": {"error": "Malformed CLI JSON"}}));
        return 1;
    };
    let (status, body) = dispatch_action(storage, keys, &cmd.action, cmd.payload);
    println!("{}", json!({"http_status": status, "body": body}));
    0
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &Value) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    let json_bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        json_bytes.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&json_bytes);
}

fn handle_http_conn(mut stream: TcpStream, storage: &Storage, keys: &ServerKeyMaterial) {
    let mut reader = BufReader::new(stream.try_clone().unwrap_or_else(|_| panic!("clone")));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        write_http_response(&mut stream, 400, &json!({"error": "Bad request line"}));
        return;
    }
    let path = parts[1];

    let mut content_len: usize = 0;
    let mut ipc_sig = String::new();
    loop {
        let mut hline = String::new();
        if reader.read_line(&mut hline).is_err() || hline == "\r\n" || hline == "\n" || hline.is_empty() {
            break;
        }
        if let Some((k, v)) = hline.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0).min(1024 * 1024);
            } else if k.eq_ignore_ascii_case("x-core-ipc-sig") {
                ipc_sig = v.trim().to_string();
            }
        }
    }

    let mut body = vec![0u8; content_len];
    if content_len > 0 && reader.read_exact(&mut body).is_err() {
        write_http_response(&mut stream, 400, &json!({"error": "Incomplete body"}));
        return;
    }

    if !keys.internal_ipc_secret.is_empty()
        && !verify_hmac_hex(&keys.internal_ipc_secret, &body, &ipc_sig)
    {
        write_http_response(&mut stream, 403, &json!({"error": "IPC auth failed"}));
        return;
    }

    let action = match path {
        "/v3" => "v3",
        "/ci_register_build" => "ci_register_build",
        "/health" => "health",
        _ => {
            write_http_response(&mut stream, 404, &json!({"error": "Not found"}));
            return;
        }
    };

    let payload: Value = if body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                write_http_response(&mut stream, 400, &json!({"error": "Malformed JSON"}));
                return;
            }
        }
    };
    let (status, res_body) = dispatch_action(storage, keys, action, payload);
    write_http_response(&mut stream, status, &res_body);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (keys, storage) = match load_runtime_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("serverkey_core config error: {e}");
            std::process::exit(2);
        }
    };

    if args.get(1).map(|s| s.as_str()) == Some("--serve") {
        let bind_addr = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:8787");
        let listener = TcpListener::bind(bind_addr).expect("Failed to bind serverkey_core HTTP");
        for stream in listener.incoming().flatten() {
            handle_http_conn(stream, &storage, &keys);
        }
    } else {
        let code = run_exec_mode(&storage, &keys);
        std::process::exit(code);
    }
}
