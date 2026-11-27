//! CoreDevice FileService Client (`com.apple.coredevice.fileservice.controlcapacity` / `.control` + `.data`)
//! Drives RemoteXPC `dtfileserviced` commands (`CreateSession`, `RetrieveDirectoryList`, `RetrieveFile`,
//! `FileSystemOperation`) + `rwb!FILE` binary data transfers over the Trusted RSD Software Tunnel
//! (`DataContainerURL` Domain 1 and `systemAppGroupIdentifiers` Domain 2), enforces positive
//! `controlcapacity`, and reports `streaming_zip_conduit` availability without falling back to `afc.shim.remote`.

use super::apps::{app_group_container_path, container_path_from_url, normalize_data_container_url};
use super::house_arrest::HouseArrestDirItem;
use super::rsd::{
    invocation_identifier_string, RemoteXpcConn, RsdAsyncStream, RsdPortDialer, RsdTunnelSession,
    StreamingZipConduitClient, XpcValue,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const SERVICE_FILESERVICE_CONTROLCAPACITY: &str =
    "com.apple.coredevice.fileservice.controlcapacity";
pub const SERVICE_FILESERVICE_CONTROL: &str = "com.apple.coredevice.fileservice.control";
pub const SERVICE_FILESERVICE_DATA: &str = "com.apple.coredevice.fileservice.data";
#[allow(dead_code)]
pub const COREDEVICE_FEATURE_TRANSFER_FILES: &str = "com.apple.coredevice.feature.transferFiles";

/// Strictly positive default buffer/control capacity (4 MiB) sent during CoreDevice FileService setup.
pub const DEFAULT_CONTROL_CAPACITY: u64 = 4 * 1024 * 1024;
pub const MIN_POSITIVE_CONTROL_CAPACITY: u64 = 1;

const DATA_STREAM_MAGIC: &[u8; 8] = b"rwb!FILE";
const DATA_STREAM_PREAMBLE_LEN: usize = 0x24;
const MAX_READ_FILE_BYTES: usize = 256 * 1024 * 1024;
const DOMAIN_APP_DATA_CONTAINER: u64 = 1;
const DOMAIN_APP_GROUP_CONTAINER: u64 = 2;
const DARWIN_O_RDONLY: i64 = 0x0000;
const DARWIN_O_WRONLY_CREAT_TRUNC: i64 = 0x0601;
const APP_GROUPS_VIRTUAL_DIR: &str = "@AppGroups";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileServiceFailureReason {
    Unavailable,
    Unsupported,
    RequestMappingIncomplete,
}

impl FileServiceFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            FileServiceFailureReason::Unavailable => "unavailable",
            FileServiceFailureReason::Unsupported => "unsupported",
            FileServiceFailureReason::RequestMappingIncomplete => "request_mapping_incomplete",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreDeviceFileServiceError {
    pub reason: FileServiceFailureReason,
    pub detail: String,
}

impl CoreDeviceFileServiceError {
    pub fn new(reason: FileServiceFailureReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(FileServiceFailureReason::Unavailable, detail)
    }

    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(FileServiceFailureReason::Unsupported, detail)
    }

    pub fn request_mapping_incomplete(detail: impl Into<String>) -> Self {
        Self::new(FileServiceFailureReason::RequestMappingIncomplete, detail)
    }
}

impl std::fmt::Display for CoreDeviceFileServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[fileservice:{}] {}", self.reason.as_str(), self.detail)
    }
}

/// Validates and guarantees a positive (> 0) `controlcapacity` parameter so CoreDevice FileService
/// never rejects session initialization with zero or negative capacity.
pub fn normalize_control_capacity(requested: u64) -> u64 {
    if requested >= MIN_POSITIVE_CONTROL_CAPACITY {
        requested
    } else {
        DEFAULT_CONTROL_CAPACITY
    }
}

#[allow(dead_code)]
pub fn validate_positive_control_capacity(capacity: i64) -> Result<u64, CoreDeviceFileServiceError> {
    if capacity <= 0 {
        return Err(CoreDeviceFileServiceError::unsupported(format!(
            "controlcapacity phải là số nguyên dương > 0 (nhận {})",
            capacity
        )));
    }
    Ok(capacity as u64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileServiceTargetContext {
    pub bundle_id: String,
    pub data_container_url: Option<String>,
    pub system_app_group_identifiers: Vec<String>,
    pub app_group_containers: HashMap<String, String>,
}

impl FileServiceTargetContext {
    pub fn from_app_info(
        bundle_id: &str,
        data_container_url: Option<&str>,
        system_app_group_identifiers: &[String],
        app_group_containers: &HashMap<String, String>,
    ) -> Self {
        let normalized_url = data_container_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(normalize_data_container_url);
        let mut normalized_groups = app_group_containers.clone();
        let mut uniq_ids = Vec::new();
        for raw_gid in system_app_group_identifiers {
            let gid = raw_gid.trim();
            if gid.is_empty() {
                continue;
            }
            if !uniq_ids.iter().any(|g| g == gid) {
                uniq_ids.push(gid.to_string());
            }
            normalized_groups
                .entry(gid.to_string())
                .or_insert_with(|| app_group_container_path(gid));
        }
        Self {
            bundle_id: bundle_id.trim().to_string(),
            data_container_url: normalized_url,
            system_app_group_identifiers: uniq_ids,
            app_group_containers: normalized_groups,
        }
    }

    pub fn app_group_xpc_paths(&self) -> Vec<XpcValue> {
        self.system_app_group_identifiers
            .iter()
            .map(|gid| {
                let path = self
                    .app_group_containers
                    .get(gid)
                    .cloned()
                    .unwrap_or_else(|| app_group_container_path(gid));
                XpcValue::Dictionary(vec![
                    ("identifier".to_string(), XpcValue::String(gid.clone())),
                    ("path".to_string(), XpcValue::String(path.clone())),
                    (
                        "url".to_string(),
                        XpcValue::String(normalize_data_container_url(&path)),
                    ),
                ])
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
enum ResolvedTargetScope {
    VirtualAppGroupIndex,
    AppGroup {
        group_id: String,
        root_path: String,
        subpath: String,
    },
    AppDataContainer {
        bundle_id: String,
        data_container_url: String,
        root_path: String,
        subpath: String,
    },
}

fn resolve_target_scope(
    ctx: &FileServiceTargetContext,
    raw_path: &str,
) -> Result<ResolvedTargetScope, CoreDeviceFileServiceError> {
    let trimmed = raw_path.trim();
    let normalized = if trimmed.is_empty() { "/" } else { trimmed };

    // Handle direct Shared/AppGroup absolute path
    let shared_prefix = "/var/mobile/Containers/Shared/AppGroup/";
    let priv_shared_prefix = "/private/var/mobile/Containers/Shared/AppGroup/";
    if let Some(rest) = normalized
        .strip_prefix(shared_prefix)
        .or_else(|| normalized.strip_prefix(priv_shared_prefix))
    {
        let mut parts = rest.splitn(2, '/');
        let group_id = parts.next().unwrap_or("").trim();
        if !group_id.is_empty() {
            let sub = parts.next().unwrap_or("").trim_start_matches('/');
            let root = app_group_container_path(group_id);
            return Ok(ResolvedTargetScope::AppGroup {
                group_id: group_id.to_string(),
                root_path: root,
                subpath: if sub.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}", sub)
                },
            });
        }
    }

    // Handle virtual `@AppGroups` or `AppGroup` navigation inside browser
    let rel = normalized.trim_start_matches('/');
    if rel == APP_GROUPS_VIRTUAL_DIR || rel == "AppGroup" {
        return Ok(ResolvedTargetScope::VirtualAppGroupIndex);
    }
    if let Some(after_group_dir) = rel
        .strip_prefix(&format!("{}/", APP_GROUPS_VIRTUAL_DIR))
        .or_else(|| rel.strip_prefix("AppGroup/"))
    {
        let mut parts = after_group_dir.splitn(2, '/');
        let group_id = parts.next().unwrap_or("").trim();
        if !group_id.is_empty() {
            let sub = parts.next().unwrap_or("").trim_start_matches('/');
            let root = ctx
                .app_group_containers
                .get(group_id)
                .cloned()
                .unwrap_or_else(|| app_group_container_path(group_id));
            return Ok(ResolvedTargetScope::AppGroup {
                group_id: group_id.to_string(),
                root_path: root,
                subpath: if sub.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}", sub)
                },
            });
        }
    }

    let raw_container_url = ctx
        .data_container_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CoreDeviceFileServiceError::request_mapping_incomplete(format!(
                "Thiếu DataContainerURL cho '{}' để ánh xạ yêu cầu fileservice",
                ctx.bundle_id
            ))
        })?;
    let canonical_url = normalize_data_container_url(raw_container_url);
    let root_path = container_path_from_url(&canonical_url);
    if root_path.is_empty() {
        return Err(CoreDeviceFileServiceError::request_mapping_incomplete(
            format!(
                "DataContainerURL '{}' của '{}' không hợp lệ",
                raw_container_url, ctx.bundle_id
            ),
        ));
    }

    Ok(ResolvedTargetScope::AppDataContainer {
        bundle_id: ctx.bundle_id.clone(),
        data_container_url: canonical_url,
        root_path,
        subpath: if normalized.starts_with('/') {
            normalized.to_string()
        } else {
            format!("/{}", normalized)
        },
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileServiceCapabilityReport {
    pub state: String, // "ready" | "unavailable" | "unsupported"
    pub control_service: Option<String>,
    pub control_port: Option<u16>,
    pub data_service: Option<String>,
    pub data_port: Option<u16>,
    pub controlcapacity_value: u64,
    pub control_uses_remote_xpc: bool,
    pub data_uses_remote_xpc: bool,
    pub app_group_count: usize,
    pub note: String,
    #[serde(default)]
    pub trusted_tunnel_active: bool,
    #[serde(default)]
    pub trusted_services_count: usize,
    #[serde(default)]
    pub streaming_zip_conduit_service: Option<String>,
    #[serde(default)]
    pub streaming_zip_conduit_port: Option<u16>,
    #[serde(default)]
    pub coredevice_tunnel_status: Option<String>,
}

pub fn probe_capabilities(
    session: Option<&RsdTunnelSession>,
    ctx: Option<&FileServiceTargetContext>,
    control_capacity: u64,
) -> FileServiceCapabilityReport {
    let cap = normalize_control_capacity(control_capacity);
    let app_group_count = ctx
        .map(|c| c.system_app_group_identifiers.len())
        .unwrap_or(0);

    let Some(sess) = session else {
        return FileServiceCapabilityReport {
            state: "unavailable".to_string(),
            control_service: None,
            control_port: None,
            data_service: None,
            data_port: None,
            controlcapacity_value: cap,
            control_uses_remote_xpc: false,
            data_uses_remote_xpc: false,
            app_group_count,
            note: "Phiên RemotePairing/RSD chưa hoạt động".to_string(),
            trusted_tunnel_active: false,
            trusted_services_count: 0,
            streaming_zip_conduit_service: None,
            streaming_zip_conduit_port: None,
            coredevice_tunnel_status: None,
        };
    };

    let ctrl = sess.resolve_service_pair(&[
        SERVICE_FILESERVICE_CONTROLCAPACITY,
        SERVICE_FILESERVICE_CONTROL,
    ]);
    let data = sess.resolve_service_pair(&[SERVICE_FILESERVICE_DATA]);
    let conduit = StreamingZipConduitClient::probe(sess);
    let conduit_svc = conduit.as_ref().map(|(n, _, _)| n.clone());
    let conduit_port = conduit.as_ref().map(|(_, i, _)| i.port);
    let trusted_active = sess.coredevice_proxy_active;
    let trusted_count = sess.trusted_services.len();
    let tunnel_status = sess.coredevice_tunnel_status.clone();

    match (ctrl, data) {
        (Some((ctrl_name, ctrl_info)), Some((data_name, data_info))) => {
            let conduit_note = conduit_svc
                .as_deref()
                .map(|c| format!(", conduit={}", c))
                .unwrap_or_default();
            FileServiceCapabilityReport {
                state: "ready".to_string(),
                control_service: Some(ctrl_name),
                control_port: Some(ctrl_info.port),
                data_service: Some(data_name),
                data_port: Some(data_info.port),
                controlcapacity_value: cap,
                control_uses_remote_xpc: ctrl_info.uses_remote_xpc,
                data_uses_remote_xpc: data_info.uses_remote_xpc,
                app_group_count,
                note: format!(
                    "CoreDevice FileService sẵn sàng qua Trusted RSD Tunnel ({} services, controlcapacity={}{})",
                    trusted_count.max(sess.services.len()),
                    cap,
                    conduit_note
                ),
                trusted_tunnel_active: trusted_active,
                trusted_services_count: trusted_count,
                streaming_zip_conduit_service: conduit_svc,
                streaming_zip_conduit_port: conduit_port,
                coredevice_tunnel_status: tunnel_status,
            }
        }
        (ctrl_opt, data_opt) => {
            let base_note = tunnel_status.clone().unwrap_or_else(|| {
                "RSD không quảng bá đủ cặp com.apple.coredevice.fileservice.controlcapacity & .data"
                    .to_string()
            });
            FileServiceCapabilityReport {
                state: "unavailable".to_string(),
                control_service: ctrl_opt.as_ref().map(|(n, _)| n.clone()),
                control_port: ctrl_opt.as_ref().map(|(_, i)| i.port),
                data_service: data_opt.as_ref().map(|(n, _)| n.clone()),
                data_port: data_opt.as_ref().map(|(_, i)| i.port),
                controlcapacity_value: cap,
                control_uses_remote_xpc: ctrl_opt
                    .as_ref()
                    .map(|(_, i)| i.uses_remote_xpc)
                    .unwrap_or(false),
                data_uses_remote_xpc: data_opt
                    .as_ref()
                    .map(|(_, i)| i.uses_remote_xpc)
                    .unwrap_or(false),
                app_group_count,
                note: base_note,
                trusted_tunnel_active: trusted_active,
                trusted_services_count: trusted_count,
                streaming_zip_conduit_service: conduit_svc,
                streaming_zip_conduit_port: conduit_port,
                coredevice_tunnel_status: tunnel_status,
            }
        }
    }
}

#[allow(dead_code)]
pub struct CoreDeviceFileServiceClient {
    control: RemoteXpcConn<RsdAsyncStream>,
    data_dialer: RsdPortDialer,
    data_port: u16,
    sessions: HashMap<(u64, String), String>,
    pub control_capacity: u64,
    pub control_service_name: String,
    pub session_token: String,
}

fn classify_xpc_error(detail: &str) -> FileServiceFailureReason {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("unsupported")
        || lower.contains("unimplemented")
        || lower.contains("entitlement")
        || lower.contains("not allowed")
        || lower.contains("permission")
        || lower.contains("denied")
        || lower.contains("controlcapacity")
        || lower.contains("11014")
    {
        FileServiceFailureReason::Unsupported
    } else if lower.contains("mapping")
        || lower.contains("incomplete")
        || lower.contains("missing")
        || lower.contains("invalid xpc")
        || lower.contains("schema")
        || lower.contains("datacontainerurl")
    {
        FileServiceFailureReason::RequestMappingIncomplete
    } else {
        FileServiceFailureReason::Unavailable
    }
}

fn extract_reply_error(reply: &XpcValue) -> Option<String> {
    if let Some(enc) = reply.dict_get_ci(&["EncodedError", "encodedError"]) {
        if let Some(desc) = enc
            .dict_get_ci(&[
                "LocalizedDescription",
                "NSLocalizedDescription",
                "localizedDescription",
                "description",
                "message",
                "reason",
            ])
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(desc.to_string());
        }
        return Some("dtfileserviced trả về EncodedError".to_string());
    }
    if let Some(err) = reply.dict_get_ci(&["CoreDevice.error", "error", "Error", "NSError"]) {
        if let Some(s) = err.as_str().map(str::trim).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
        if let Some(desc) = err
            .dict_get_ci(&[
                "NSLocalizedDescription",
                "LocalizedDescription",
                "localizedDescription",
                "description",
                "message",
                "reason",
                "domain",
            ])
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(desc.to_string());
        }
        return Some("CoreDevice trả về lỗi XPC".to_string());
    }
    None
}

fn scope_to_domain_identifier_rel(scope: &ResolvedTargetScope) -> Result<(u64, String, String), CoreDeviceFileServiceError> {
    match scope {
        ResolvedTargetScope::AppDataContainer {
            bundle_id,
            subpath,
            ..
        } => {
            let trimmed = subpath.trim().trim_start_matches('/').trim_end_matches('/');
            let rel = if trimmed.is_empty() {
                ".".to_string()
            } else {
                trimmed.to_string()
            };
            Ok((DOMAIN_APP_DATA_CONTAINER, bundle_id.clone(), rel))
        }
        ResolvedTargetScope::AppGroup {
            group_id,
            subpath,
            ..
        } => {
            let trimmed = subpath.trim().trim_start_matches('/').trim_end_matches('/');
            let rel = if trimmed.is_empty() {
                ".".to_string()
            } else {
                trimmed.to_string()
            };
            Ok((DOMAIN_APP_GROUP_CONTAINER, group_id.clone(), rel))
        }
        ResolvedTargetScope::VirtualAppGroupIndex => Err(
            CoreDeviceFileServiceError::request_mapping_incomplete(
                "Virtual AppGroup index handled directly",
            ),
        ),
    }
}

fn xpc_u64(val: &XpcValue) -> Option<u64> {
    match val {
        XpcValue::UInt64(u) => Some(*u),
        XpcValue::Int64(i) if *i >= 0 => Some(*i as u64),
        XpcValue::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn xpc_i64(val: &XpcValue) -> Option<i64> {
    match val {
        XpcValue::Int64(i) => Some(*i),
        XpcValue::UInt64(u) => i64::try_from(*u).ok(),
        XpcValue::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn join_rel_child(parent: &str, name: &str) -> String {
    let clean_name = name.trim_start_matches('/');
    if parent == "." || parent.is_empty() {
        clean_name.to_string()
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), clean_name)
    }
}

impl CoreDeviceFileServiceClient {
    /// Connects to `com.apple.coredevice.fileservice.controlcapacity` (or `.control`) and binds
    /// `com.apple.coredevice.fileservice.data` over the Trusted RSD Software Tunnel.
    pub async fn connect_async(
        session: &RsdTunnelSession,
        requested_capacity: u64,
    ) -> Result<Self, CoreDeviceFileServiceError> {
        let control_capacity = normalize_control_capacity(requested_capacity);

        let (ctrl_name, ctrl_info, ctrl_trusted) = session
            .resolve_layered_service(&[
                SERVICE_FILESERVICE_CONTROLCAPACITY,
                SERVICE_FILESERVICE_CONTROL,
            ])
            .ok_or_else(|| {
                let extra = session
                    .coredevice_tunnel_status
                    .as_deref()
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                CoreDeviceFileServiceError::unavailable(format!(
                    "RSD không có com.apple.coredevice.fileservice.controlcapacity / .control{}",
                    extra
                ))
            })?;

        let (_, data_info, data_trusted) = session
            .resolve_layered_service(&[SERVICE_FILESERVICE_DATA])
            .ok_or_else(|| {
                CoreDeviceFileServiceError::unavailable(
                    "RSD không có com.apple.coredevice.fileservice.data",
                )
            })?;

        let ctrl_stream = session
            .transport
            .connect_service_port(ctrl_info.port, ctrl_trusted)
            .await
            .map_err(CoreDeviceFileServiceError::unavailable)?;
        let data_dialer = session.port_dialer(data_trusted).map_err(|e| {
            CoreDeviceFileServiceError::unavailable(format!("Không tạo được dialer .data: {}", e))
        })?;

        let control = RemoteXpcConn::connect_and_handshake(ctrl_stream)
            .await
            .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;

        Ok(Self {
            control,
            data_dialer,
            data_port: data_info.port,
            sessions: HashMap::new(),
            control_capacity,
            control_service_name: ctrl_name,
            session_token: invocation_identifier_string(),
        })
    }

    pub fn connect_blocking(
        session: &RsdTunnelSession,
        requested_capacity: u64,
    ) -> Result<Self, CoreDeviceFileServiceError> {
        let rt = super::rsd::runtime().map_err(CoreDeviceFileServiceError::unavailable)?;
        rt.block_on(Self::connect_async(session, requested_capacity))
    }

    async fn send_cmd(
        &mut self,
        entries: Vec<(String, XpcValue)>,
    ) -> Result<XpcValue, CoreDeviceFileServiceError> {
        let req = XpcValue::Dictionary(entries);
        self.control
            .send_object(req, true)
            .await
            .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;

        let (_ch, reply) = tokio::time::timeout(Duration::from_secs(10), self.control.recv_any())
            .await
            .map_err(|_| {
                CoreDeviceFileServiceError::unavailable(
                    "CoreDevice FileService timeout khi chờ phản hồi XPC",
                )
            })?
            .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;

        if let Some(err_msg) = extract_reply_error(&reply) {
            return Err(CoreDeviceFileServiceError::new(
                classify_xpc_error(&err_msg),
                err_msg,
            ));
        }

        Ok(reply)
    }

    async fn ensure_session_for_scope(
        &mut self,
        domain: u64,
        identifier: &str,
    ) -> Result<String, CoreDeviceFileServiceError> {
        let key = (domain, identifier.to_string());
        if let Some(existing) = self.sessions.get(&key) {
            return Ok(existing.clone());
        }

        let cmd_entries = vec![
            ("Cmd".to_string(), XpcValue::String("CreateSession".to_string())),
            ("Domain".to_string(), XpcValue::UInt64(domain)),
            (
                "Identifier".to_string(),
                XpcValue::String(identifier.to_string()),
            ),
            ("Session".to_string(), XpcValue::String(String::new())),
            ("User".to_string(), XpcValue::String("mobile".to_string())),
        ];
        let reply = self.send_cmd(cmd_entries).await?;
        let sid = reply
            .dict_get_ci(&["NewSessionID", "SessionID", "sessionID"])
            .and_then(|v| v.as_id_string())
            .ok_or_else(|| {
                CoreDeviceFileServiceError::request_mapping_incomplete(format!(
                    "dtfileserviced CreateSession thiếu NewSessionID (keys: [{}])",
                    reply.summarize_dict_keys()
                ))
            })?;
        self.session_token = sid.clone();
        self.sessions.insert(key, sid.clone());
        Ok(sid)
    }

    async fn fs_op(
        &mut self,
        session_id: &str,
        sub_cmd: &str,
        extra: Vec<(String, XpcValue)>,
    ) -> Result<XpcValue, CoreDeviceFileServiceError> {
        let mut entries = vec![
            (
                "Cmd".to_string(),
                XpcValue::String("FileSystemOperation".to_string()),
            ),
            ("SubCmd".to_string(), XpcValue::String(sub_cmd.to_string())),
            (
                "SessionID".to_string(),
                XpcValue::String(session_id.to_string()),
            ),
        ];
        entries.extend(extra);
        self.send_cmd(entries).await
    }

    async fn get_attributes(
        &mut self,
        session_id: &str,
        rel_path: &str,
    ) -> Result<(bool, i64), CoreDeviceFileServiceError> {
        let reply = self
            .fs_op(
                session_id,
                "GetAttributes",
                vec![("Path".to_string(), XpcValue::String(rel_path.to_string()))],
            )
            .await?;
        let attrs = reply.dict_get_ci(&["Attributes", "attributes"]).unwrap_or(&reply);
        let is_dir = attrs
            .dict_get_ci(&["NSFileType", "FileType", "Type", "type"])
            .and_then(|v| v.as_str())
            .map(|s| s.contains("Directory") || s.eq_ignore_ascii_case("dir"))
            .or_else(|| {
                attrs
                    .dict_get_ci(&["StMode", "Mode", "mode"])
                    .and_then(xpc_u64)
                    .map(|m| (m & 0o170_000) == 0o040_000)
            })
            .or_else(|| {
                attrs
                    .dict_get_ci(&["isDirectory", "IsDirectory", "is_dir"])
                    .and_then(|v| v.as_bool())
            })
            .unwrap_or(false);
        let size = attrs
            .dict_get_ci(&["NSFileSize", "FileSize", "Size", "StSize", "size"])
            .and_then(xpc_i64)
            .unwrap_or(if is_dir { -1 } else { 0 });
        Ok((is_dir, if is_dir { -1 } else { size }))
    }

    async fn ensure_parent_dirs(
        &mut self,
        session_id: &str,
        rel_path: &str,
    ) -> Result<(), CoreDeviceFileServiceError> {
        let clean = rel_path.trim_start_matches('/').trim_end_matches('/');
        let parts: Vec<&str> = clean.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
        if parts.len() <= 1 {
            return Ok(());
        }
        let mut acc = String::new();
        for seg in &parts[..parts.len() - 1] {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(seg);
            match self
                .fs_op(
                    session_id,
                    "CreateDirectory",
                    vec![
                        ("Path".to_string(), XpcValue::String(acc.clone())),
                        ("Mode".to_string(), XpcValue::Int64(0o755)),
                    ],
                )
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    let low = e.detail.to_ascii_lowercase();
                    if !(low.contains("exist") || low.contains("eexist")) {
                        // Best-effort parent creation; let OpenFile report real permission failure
                        eprintln!("fileservice: CreateDirectory '{}' note: {}", acc, e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn read_via_open_file(
        &mut self,
        session_id: &str,
        rel_path: &str,
    ) -> Result<Vec<u8>, CoreDeviceFileServiceError> {
        let open_reply = self
            .fs_op(
                session_id,
                "OpenFile",
                vec![
                    ("Path".to_string(), XpcValue::String(rel_path.to_string())),
                    ("Flags".to_string(), XpcValue::Int64(DARWIN_O_RDONLY)),
                    ("Mode".to_string(), XpcValue::Int64(0o644)),
                ],
            )
            .await?;
        let fd = open_reply
            .dict_get_ci(&["FileDescriptor", "FD", "Handle", "NewFileID"])
            .and_then(xpc_i64)
            .ok_or_else(|| {
                CoreDeviceFileServiceError::request_mapping_incomplete(
                    "OpenFile (read) thiếu FileDescriptor",
                )
            })?;

        let chunk_sz = self.control_capacity.clamp(4096, 512 * 1024);
        let mut out = Vec::new();
        let mut offset: u64 = 0;
        let read_res: Result<Vec<u8>, CoreDeviceFileServiceError> = async {
            loop {
                let rd = self
                    .fs_op(
                        session_id,
                        "ReadFile",
                        vec![
                            ("FileDescriptor".to_string(), XpcValue::Int64(fd)),
                            ("Size".to_string(), XpcValue::UInt64(chunk_sz)),
                            ("Offset".to_string(), XpcValue::UInt64(offset)),
                        ],
                    )
                    .await?;
                let Some(XpcValue::Data(bytes)) = rd.dict_get_ci(&["Data", "data", "Payload"]) else {
                    break;
                };
                if bytes.is_empty() {
                    break;
                }
                if out.len() + bytes.len() > MAX_READ_FILE_BYTES {
                    return Err(CoreDeviceFileServiceError::unsupported(
                        "Tệp vượt quá giới hạn đọc 256 MiB",
                    ));
                }
                out.extend_from_slice(bytes);
                offset += bytes.len() as u64;
                if (bytes.len() as u64) < chunk_sz {
                    break;
                }
            }
            Ok(out)
        }
        .await;

        let _ = self
            .fs_op(
                session_id,
                "CloseFile",
                vec![("FileDescriptor".to_string(), XpcValue::Int64(fd))],
            )
            .await;

        read_res
    }

    pub async fn list_async(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<Vec<HouseArrestDirItem>, CoreDeviceFileServiceError> {
        let scope = resolve_target_scope(ctx, path)?;
        if matches!(scope, ResolvedTargetScope::VirtualAppGroupIndex) {
            let mut items = Vec::with_capacity(ctx.system_app_group_identifiers.len());
            for gid in &ctx.system_app_group_identifiers {
                items.push(HouseArrestDirItem {
                    name: gid.clone(),
                    is_dir: true,
                    size: -1,
                });
            }
            return Ok(items);
        }

        let (domain, identifier, rel_path) = scope_to_domain_identifier_rel(&scope)?;
        let session_id = self.ensure_session_for_scope(domain, &identifier).await?;

        let reply = self
            .send_cmd(vec![
                (
                    "Cmd".to_string(),
                    XpcValue::String("RetrieveDirectoryList".to_string()),
                ),
                (
                    "MessageUUID".to_string(),
                    XpcValue::String(invocation_identifier_string()),
                ),
                ("Path".to_string(), XpcValue::String(rel_path.clone())),
                (
                    "SessionID".to_string(),
                    XpcValue::String(session_id.clone()),
                ),
            ])
            .await?;

        let Some(raw_items) = reply
            .dict_get_ci(&["FileList", "fileList", "CoreDevice.output", "entries"])
            .and_then(|v| v.as_array())
        else {
            return Err(CoreDeviceFileServiceError::request_mapping_incomplete(
                format!(
                    "dtfileserviced RetrieveDirectoryList thiếu FileList (keys: [{}])",
                    reply.summarize_dict_keys()
                ),
            ));
        };

        let mut parsed = Vec::with_capacity(raw_items.len());
        let mut attrs_supported = raw_items.len() <= 64;
        for entry in raw_items {
            if let Some(name_str) = entry.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                if name_str == "." || name_str == ".." {
                    continue;
                }
                let child_rel = join_rel_child(&rel_path, name_str);
                let (is_dir, size) = if attrs_supported {
                    match self.get_attributes(&session_id, &child_rel).await {
                        Ok(pair) => pair,
                        Err(_) => {
                            if parsed.is_empty() {
                                attrs_supported = false;
                            }
                            let known_dir = matches!(
                                name_str,
                                "Documents" | "Library" | "tmp" | "SystemData" | "StoreKit"
                            );
                            (known_dir, if known_dir { -1 } else { 0 })
                        }
                    }
                } else {
                    (false, 0)
                };
                parsed.push(HouseArrestDirItem {
                    name: name_str.to_string(),
                    is_dir,
                    size,
                });
                continue;
            }
            let Some(name) = entry
                .dict_get_ci(&["name", "filename", "relativePath", "path"])
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            else {
                continue;
            };
            let is_dir = entry
                .dict_get_ci(&["isDirectory", "is_dir", "directory", "type"])
                .map(|v| match v {
                    XpcValue::Bool(b) => *b,
                    XpcValue::String(s) => {
                        s.eq_ignore_ascii_case("directory") || s.eq_ignore_ascii_case("dir")
                    }
                    _ => false,
                })
                .unwrap_or(false);
            let size = entry
                .dict_get_ci(&["size", "fileSize", "allocatedSize"])
                .and_then(xpc_i64)
                .unwrap_or(if is_dir { -1 } else { 0 });
            parsed.push(HouseArrestDirItem {
                name: name.to_string(),
                is_dir,
                size: if is_dir { -1 } else { size },
            });
        }

        if path.trim() == "/"
            && !ctx.system_app_group_identifiers.is_empty()
            && !parsed.iter().any(|i| i.name == APP_GROUPS_VIRTUAL_DIR)
        {
            parsed.push(HouseArrestDirItem {
                name: APP_GROUPS_VIRTUAL_DIR.to_string(),
                is_dir: true,
                size: -1,
            });
        }

        Ok(parsed)
    }

    pub async fn fileservice_read_async(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<Vec<u8>, CoreDeviceFileServiceError> {
        let scope = resolve_target_scope(ctx, path)?;
        let (domain, identifier, rel_path) = scope_to_domain_identifier_rel(&scope)?;
        let session_id = self.ensure_session_for_scope(domain, &identifier).await?;

        let reply = match self
            .send_cmd(vec![
                (
                    "Cmd".to_string(),
                    XpcValue::String("RetrieveFile".to_string()),
                ),
                ("Path".to_string(), XpcValue::String(rel_path.clone())),
                (
                    "SessionID".to_string(),
                    XpcValue::String(session_id.clone()),
                ),
            ])
            .await
        {
            Ok(r) => r,
            Err(retrieve_err) => {
                if let Ok(bytes) = self.read_via_open_file(&session_id, &rel_path).await {
                    return Ok(bytes);
                }
                return Err(retrieve_err);
            }
        };

        if let Some(XpcValue::Data(inline)) = reply.dict_get_ci(&["Data", "data", "contents"]) {
            return Ok(inline.clone());
        }

        let response_id = reply
            .dict_get_ci(&["Response", "response"])
            .and_then(xpc_u64);
        let new_file_id = reply
            .dict_get_ci(&["NewFileID", "newFileID", "FileID"])
            .and_then(xpc_u64);

        let (Some(resp_id), Some(file_id)) = (response_id, new_file_id) else {
            return self.read_via_open_file(&session_id, &rel_path).await;
        };

        let mut data_stream = self
            .data_dialer
            .connect(self.data_port)
            .await
            .map_err(CoreDeviceFileServiceError::unavailable)?;

        let mut req_hdr = Vec::with_capacity(40);
        req_hdr.extend_from_slice(DATA_STREAM_MAGIC);
        req_hdr.extend_from_slice(&resp_id.to_be_bytes());
        req_hdr.extend_from_slice(&0u64.to_be_bytes());
        req_hdr.extend_from_slice(&file_id.to_be_bytes());
        req_hdr.extend_from_slice(&0u64.to_be_bytes());

        data_stream
            .write_all(&req_hdr)
            .await
            .map_err(|e| CoreDeviceFileServiceError::unavailable(format!("Ghi rwb!FILE: {}", e)))?;
        data_stream
            .flush()
            .await
            .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;

        let mut preamble = [0u8; DATA_STREAM_PREAMBLE_LEN];
        tokio::time::timeout(Duration::from_secs(12), data_stream.read_exact(&mut preamble))
            .await
            .map_err(|_| {
                CoreDeviceFileServiceError::unavailable("Timeout đọc preamble fileservice.data")
            })?
            .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;

        let mut len_buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(12), data_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                CoreDeviceFileServiceError::unavailable("Timeout đọc độ dài tệp fileservice.data")
            })?
            .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;

        let payload_len = u32::from_be_bytes(len_buf) as usize;
        if payload_len > MAX_READ_FILE_BYTES {
            return Err(CoreDeviceFileServiceError::unsupported(format!(
                "Kích thước tệp fileservice.data vượt ngưỡng ({} bytes)",
                payload_len
            )));
        }
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            tokio::time::timeout(Duration::from_secs(20), data_stream.read_exact(&mut payload))
                .await
                .map_err(|_| {
                    CoreDeviceFileServiceError::unavailable(
                        "Timeout đọc payload từ fileservice.data",
                    )
                })?
                .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;
        }
        Ok(payload)
    }

    pub async fn fileservice_write_async(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
        data: &[u8],
    ) -> Result<(), CoreDeviceFileServiceError> {
        let scope = resolve_target_scope(ctx, path)?;
        let (domain, identifier, rel_path) = scope_to_domain_identifier_rel(&scope)?;
        let session_id = self.ensure_session_for_scope(domain, &identifier).await?;

        self.ensure_parent_dirs(&session_id, &rel_path).await?;

        let open_reply = self
            .fs_op(
                &session_id,
                "OpenFile",
                vec![
                    ("Path".to_string(), XpcValue::String(rel_path.clone())),
                    (
                        "Flags".to_string(),
                        XpcValue::Int64(DARWIN_O_WRONLY_CREAT_TRUNC),
                    ),
                    ("Mode".to_string(), XpcValue::Int64(0o644)),
                ],
            )
            .await?;
        let fd = open_reply
            .dict_get_ci(&["FileDescriptor", "FD", "Handle", "NewFileID"])
            .and_then(xpc_i64)
            .ok_or_else(|| {
                CoreDeviceFileServiceError::request_mapping_incomplete(format!(
                    "OpenFile (write) thiếu FileDescriptor (keys: [{}])",
                    open_reply.summarize_dict_keys()
                ))
            })?;

        let chunk_sz = self.control_capacity.clamp(4096, 512 * 1024) as usize;
        let mut offset: u64 = 0;
        let write_res: Result<(), CoreDeviceFileServiceError> = async {
            for chunk in data.chunks(chunk_sz) {
                self.fs_op(
                    &session_id,
                    "WriteFile",
                    vec![
                        ("FileDescriptor".to_string(), XpcValue::Int64(fd)),
                        ("Data".to_string(), XpcValue::Data(chunk.to_vec())),
                        ("Offset".to_string(), XpcValue::UInt64(offset)),
                    ],
                )
                .await?;
                offset += chunk.len() as u64;
            }
            Ok(())
        }
        .await;

        let _ = self
            .fs_op(
                &session_id,
                "CloseFile",
                vec![("FileDescriptor".to_string(), XpcValue::Int64(fd))],
            )
            .await;

        write_res
    }

    pub async fn fileservice_mkdir_async(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<(), CoreDeviceFileServiceError> {
        let scope = resolve_target_scope(ctx, path)?;
        let (domain, identifier, rel_path) = scope_to_domain_identifier_rel(&scope)?;
        let session_id = self.ensure_session_for_scope(domain, &identifier).await?;

        self.ensure_parent_dirs(&session_id, &rel_path).await?;
        self.fs_op(
            &session_id,
            "CreateDirectory",
            vec![
                ("Path".to_string(), XpcValue::String(rel_path)),
                ("Mode".to_string(), XpcValue::Int64(0o755)),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn fileservice_remove_async(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<(), CoreDeviceFileServiceError> {
        let scope = resolve_target_scope(ctx, path)?;
        let (domain, identifier, rel_path) = scope_to_domain_identifier_rel(&scope)?;
        let session_id = self.ensure_session_for_scope(domain, &identifier).await?;

        match self
            .fs_op(
                &session_id,
                "RemoveFile",
                vec![("Path".to_string(), XpcValue::String(rel_path.clone()))],
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(file_err) => {
                if self
                    .fs_op(
                        &session_id,
                        "RemoveDirectory",
                        vec![("Path".to_string(), XpcValue::String(rel_path))],
                    )
                    .await
                    .is_ok()
                {
                    Ok(())
                } else {
                    Err(file_err)
                }
            }
        }
    }

    pub fn list_blocking(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<Vec<HouseArrestDirItem>, CoreDeviceFileServiceError> {
        let rt = super::rsd::runtime().map_err(CoreDeviceFileServiceError::unavailable)?;
        rt.block_on(self.list_async(ctx, path))
    }

    pub fn fileservice_read(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<Vec<u8>, CoreDeviceFileServiceError> {
        let rt = super::rsd::runtime().map_err(CoreDeviceFileServiceError::unavailable)?;
        rt.block_on(self.fileservice_read_async(ctx, path))
    }

    pub fn fileservice_write(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
        data: &[u8],
    ) -> Result<(), CoreDeviceFileServiceError> {
        let rt = super::rsd::runtime().map_err(CoreDeviceFileServiceError::unavailable)?;
        rt.block_on(self.fileservice_write_async(ctx, path, data))
    }

    pub fn fileservice_mkdir(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<(), CoreDeviceFileServiceError> {
        let rt = super::rsd::runtime().map_err(CoreDeviceFileServiceError::unavailable)?;
        rt.block_on(self.fileservice_mkdir_async(ctx, path))
    }

    pub fn fileservice_remove(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<(), CoreDeviceFileServiceError> {
        let rt = super::rsd::runtime().map_err(CoreDeviceFileServiceError::unavailable)?;
        rt.block_on(self.fileservice_remove_async(ctx, path))
    }
}
