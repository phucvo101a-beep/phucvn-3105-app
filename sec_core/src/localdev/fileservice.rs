//! CoreDevice FileService Client (`com.apple.coredevice.fileservice.controlcapacity` / `.control` + `.data`)
//! Drives concurrent RemoteXPC / binary data channels over RSD (`10.7.0.1:49152`), enforces a positive
//! `controlcapacity` handshake parameter, resolves `DataContainerURL` and `systemAppGroupIdentifiers`
//! (`/var/mobile/Containers/Shared/AppGroup/<group_id>`), and classifies unavailability / mapping failures
//! cleanly for `patch.airlift` fallback routing.

use super::apps::{app_group_container_path, container_path_from_url, normalize_data_container_url};
use super::house_arrest::HouseArrestDirItem;
use super::rsd::{
    device_identifier_string, invocation_identifier_string, RemoteXpcConn, RsdAsyncStream,
    RsdTunnelSession, XpcValue,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const SERVICE_FILESERVICE_CONTROLCAPACITY: &str =
    "com.apple.coredevice.fileservice.controlcapacity";
pub const SERVICE_FILESERVICE_CONTROL: &str = "com.apple.coredevice.fileservice.control";
pub const SERVICE_FILESERVICE_DATA: &str = "com.apple.coredevice.fileservice.data";
pub const COREDEVICE_FEATURE_TRANSFER_FILES: &str = "com.apple.coredevice.feature.transferFiles";

/// Strictly positive default buffer/control capacity (4 MiB) sent during CoreDevice FileService setup.
pub const DEFAULT_CONTROL_CAPACITY: u64 = 4 * 1024 * 1024;
pub const MIN_POSITIVE_CONTROL_CAPACITY: u64 = 1;

const DATA_STREAM_MAGIC: &[u8; 8] = b"rwb!FILE";
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
        };
    };

    let ctrl = sess.resolve_service_pair(&[
        SERVICE_FILESERVICE_CONTROLCAPACITY,
        SERVICE_FILESERVICE_CONTROL,
    ]);
    let data = sess.resolve_service_pair(&[SERVICE_FILESERVICE_DATA]);

    match (ctrl, data) {
        (Some((ctrl_name, ctrl_info)), Some((data_name, data_info))) => {
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
                    "CoreDevice FileService sẵn sàng (controlcapacity={})",
                    cap
                ),
            }
        }
        (ctrl_opt, data_opt) => FileServiceCapabilityReport {
            state: "unavailable".to_string(),
            control_service: ctrl_opt.as_ref().map(|(n, _)| n.clone()),
            control_port: ctrl_opt.as_ref().map(|(_, i)| i.port),
            data_service: data_opt.as_ref().map(|(n, _)| n.clone()),
            data_port: data_opt.as_ref().map(|(_, i)| i.port),
            controlcapacity_value: cap,
            control_uses_remote_xpc: ctrl_opt.as_ref().map(|(_, i)| i.uses_remote_xpc).unwrap_or(false),
            data_uses_remote_xpc: data_opt.as_ref().map(|(_, i)| i.uses_remote_xpc).unwrap_or(false),
            app_group_count,
            note: "RSD không quảng bá đủ cặp com.apple.coredevice.fileservice.controlcapacity & .data"
                .to_string(),
        },
    }
}

enum FileServiceDataChannel {
    Xpc(RemoteXpcConn<RsdAsyncStream>),
    RawStream(RsdAsyncStream),
}

#[allow(dead_code)]
pub struct CoreDeviceFileServiceClient {
    control: RemoteXpcConn<RsdAsyncStream>,
    data: FileServiceDataChannel,
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
    {
        FileServiceFailureReason::Unsupported
    } else if lower.contains("mapping")
        || lower.contains("incomplete")
        || lower.contains("missing coredevice")
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
    if let Some(err) = reply.dict_get_ci(&["CoreDevice.error", "error", "Error", "NSError"]) {
        if let Some(s) = err.as_str().map(str::trim).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
        if let Some(desc) = err
            .dict_get_ci(&[
                "NSLocalizedDescription",
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

fn build_control_envelope(
    feature_id: &str,
    control_capacity: u64,
    input: XpcValue,
    action: XpcValue,
) -> XpcValue {
    let cap = normalize_control_capacity(control_capacity);
    let dev_id = device_identifier_string();
    let inv_id = invocation_identifier_string();
    XpcValue::Dictionary(vec![
        ("CoreDevice.CoreDeviceDDIProtocolVersion".to_string(), XpcValue::Int64(0)),
        ("CoreDevice.action".to_string(), action),
        (
            "CoreDevice.coreDeviceVersion".to_string(),
            XpcValue::Dictionary(vec![
                (
                    "components".to_string(),
                    XpcValue::Array(vec![XpcValue::UInt64(629), XpcValue::UInt64(3)]),
                ),
                ("originalComponentsCount".to_string(), XpcValue::Int64(2)),
                ("stringValue".to_string(), XpcValue::String("629.3".to_string())),
            ]),
        ),
        ("CoreDevice.deviceIdentifier".to_string(), XpcValue::String(dev_id)),
        (
            "CoreDevice.featureIdentifier".to_string(),
            XpcValue::String(feature_id.to_string()),
        ),
        ("controlcapacity".to_string(), XpcValue::UInt64(cap)),
        ("ControlCapacity".to_string(), XpcValue::UInt64(cap)),
        ("capacity".to_string(), XpcValue::UInt64(cap)),
        ("CoreDevice.input".to_string(), input),
        ("CoreDevice.invocationIdentifier".to_string(), XpcValue::String(inv_id)),
    ])
}

impl CoreDeviceFileServiceClient {
    /// Connects concurrently to `com.apple.coredevice.fileservice.controlcapacity` (or `.control`)
    /// and `com.apple.coredevice.fileservice.data`, initializing a strictly positive `controlcapacity`.
    pub async fn connect_async(
        session: &RsdTunnelSession,
        requested_capacity: u64,
    ) -> Result<Self, CoreDeviceFileServiceError> {
        let control_capacity = normalize_control_capacity(requested_capacity);

        let (ctrl_name, ctrl_info) = session
            .resolve_service_pair(&[
                SERVICE_FILESERVICE_CONTROLCAPACITY,
                SERVICE_FILESERVICE_CONTROL,
            ])
            .ok_or_else(|| {
                CoreDeviceFileServiceError::unavailable(
                    "RSD không có com.apple.coredevice.fileservice.controlcapacity / .control",
                )
            })?;

        let (_, data_info) = session
            .resolve_service_pair(&[SERVICE_FILESERVICE_DATA])
            .ok_or_else(|| {
                CoreDeviceFileServiceError::unavailable(
                    "RSD không có com.apple.coredevice.fileservice.data",
                )
            })?;

        let (ctrl_res, data_res) = tokio::join!(
            session.connect_port_async(ctrl_info.port),
            session.connect_port_async(data_info.port)
        );

        let ctrl_stream = ctrl_res.map_err(CoreDeviceFileServiceError::unavailable)?;
        let data_stream = data_res.map_err(CoreDeviceFileServiceError::unavailable)?;

        let mut control = RemoteXpcConn::connect_and_handshake(ctrl_stream)
            .await
            .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;

        let data = if data_info.uses_remote_xpc {
            let xpc_data = RemoteXpcConn::connect_and_handshake(data_stream)
                .await
                .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;
            FileServiceDataChannel::Xpc(xpc_data)
        } else {
            FileServiceDataChannel::RawStream(data_stream)
        };

        // Initialize session with positive `controlcapacity` (> 0) to satisfy CoreDevice control guard
        let session_token = invocation_identifier_string();
        let init_input = XpcValue::Dictionary(vec![
            ("controlcapacity".to_string(), XpcValue::UInt64(control_capacity)),
            ("ControlCapacity".to_string(), XpcValue::UInt64(control_capacity)),
            ("capacity".to_string(), XpcValue::UInt64(control_capacity)),
            ("bufferCapacity".to_string(), XpcValue::UInt64(control_capacity)),
            ("sessionIdentifier".to_string(), XpcValue::String(session_token.clone())),
            ("dataChannelStreamMagic".to_string(), XpcValue::String("rwb!FILE".to_string())),
        ]);
        let init_action = XpcValue::Dictionary(vec![
            ("command".to_string(), XpcValue::String("configure".to_string())),
            ("controlcapacity".to_string(), XpcValue::UInt64(control_capacity)),
        ]);
        let init_req = build_control_envelope(
            COREDEVICE_FEATURE_TRANSFER_FILES,
            control_capacity,
            init_input,
            init_action,
        );

        control
            .send_object(init_req, true)
            .await
            .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;

        let init_reply = tokio::time::timeout(
            Duration::from_secs(4),
            control.recv_reply(),
        )
        .await
        .map_err(|_| {
            CoreDeviceFileServiceError::unavailable(
                "Hết thời gian phản hồi phiên CoreDevice FileService",
            )
        })?
        .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;

        if let Some(err_msg) = extract_reply_error(&init_reply) {
            return Err(CoreDeviceFileServiceError::new(
                classify_xpc_error(&err_msg),
                err_msg,
            ));
        }

        let negotiated_token = init_reply
            .dict_get_ci(&["CoreDevice.output", "output", "result"])
            .and_then(|o| {
                o.dict_get_ci(&["sessionIdentifier", "sessionToken", "requestIdentifier"])
            })
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or(session_token);

        Ok(Self {
            control,
            data,
            control_capacity,
            control_service_name: ctrl_name,
            session_token: negotiated_token,
        })
    }

    pub fn connect_blocking(
        session: &RsdTunnelSession,
        requested_capacity: u64,
    ) -> Result<Self, CoreDeviceFileServiceError> {
        let rt = super::rsd::runtime().map_err(CoreDeviceFileServiceError::unavailable)?;
        rt.block_on(Self::connect_async(session, requested_capacity))
    }

    fn build_target_input(
        &self,
        op: &str,
        ctx: &FileServiceTargetContext,
        scope: &ResolvedTargetScope,
    ) -> Result<(XpcValue, XpcValue), CoreDeviceFileServiceError> {
        let mut input_entries = vec![
            ("operation".to_string(), XpcValue::String(op.to_string())),
            (
                "controlcapacity".to_string(),
                XpcValue::UInt64(self.control_capacity),
            ),
            (
                "sessionIdentifier".to_string(),
                XpcValue::String(self.session_token.clone()),
            ),
            (
                "bundleIdentifier".to_string(),
                XpcValue::String(ctx.bundle_id.clone()),
            ),
        ];

        if let Some(ref durl) = ctx.data_container_url {
            input_entries.push(("DataContainerURL".to_string(), XpcValue::String(durl.clone())));
            input_entries.push(("dataContainerURL".to_string(), XpcValue::String(durl.clone())));
        }
        if !ctx.system_app_group_identifiers.is_empty() {
            input_entries.push((
                "systemAppGroupIdentifiers".to_string(),
                XpcValue::Array(
                    ctx.system_app_group_identifiers
                        .iter()
                        .map(|g| XpcValue::String(g.clone()))
                        .collect(),
                ),
            ));
            input_entries.push((
                "appGroupContainers".to_string(),
                XpcValue::Array(ctx.app_group_xpc_paths()),
            ));
        }

        let action = match scope {
            ResolvedTargetScope::AppDataContainer {
                bundle_id,
                data_container_url,
                root_path,
                subpath,
            } => {
                input_entries.push((
                    "domain".to_string(),
                    XpcValue::String("appDataContainer".to_string()),
                ));
                input_entries.push(("identifier".to_string(), XpcValue::String(bundle_id.clone())));
                input_entries.push(("rootPath".to_string(), XpcValue::String(root_path.clone())));
                input_entries.push(("subdirectory".to_string(), XpcValue::String(subpath.clone())));
                input_entries.push(("path".to_string(), XpcValue::String(subpath.clone())));
                XpcValue::Dictionary(vec![
                    ("command".to_string(), XpcValue::String(op.to_string())),
                    ("domain".to_string(), XpcValue::String("appDataContainer".to_string())),
                    ("DataContainerURL".to_string(), XpcValue::String(data_container_url.clone())),
                    ("subdirectory".to_string(), XpcValue::String(subpath.clone())),
                ])
            }
            ResolvedTargetScope::AppGroup {
                group_id,
                root_path,
                subpath,
            } => {
                input_entries.push((
                    "domain".to_string(),
                    XpcValue::String("appGroupDataContainer".to_string()),
                ));
                input_entries.push(("identifier".to_string(), XpcValue::String(group_id.clone())));
                input_entries.push(("rootPath".to_string(), XpcValue::String(root_path.clone())));
                input_entries.push(("subdirectory".to_string(), XpcValue::String(subpath.clone())));
                input_entries.push(("path".to_string(), XpcValue::String(subpath.clone())));
                XpcValue::Dictionary(vec![
                    ("command".to_string(), XpcValue::String(op.to_string())),
                    ("domain".to_string(), XpcValue::String("appGroupDataContainer".to_string())),
                    ("identifier".to_string(), XpcValue::String(group_id.clone())),
                    ("appGroupPath".to_string(), XpcValue::String(root_path.clone())),
                    ("subdirectory".to_string(), XpcValue::String(subpath.clone())),
                ])
            }
            ResolvedTargetScope::VirtualAppGroupIndex => {
                return Err(CoreDeviceFileServiceError::request_mapping_incomplete(
                    "Virtual AppGroup index handled directly",
                ));
            }
        };

        Ok((XpcValue::Dictionary(input_entries), action))
    }

    async fn invoke_control(
        &mut self,
        feature_id: &str,
        input: XpcValue,
        action: XpcValue,
    ) -> Result<XpcValue, CoreDeviceFileServiceError> {
        let req = build_control_envelope(feature_id, self.control_capacity, input, action);
        self.control
            .send_object(req, true)
            .await
            .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;

        let reply = tokio::time::timeout(Duration::from_secs(8), self.control.recv_reply())
            .await
            .map_err(|_| {
                CoreDeviceFileServiceError::unavailable(
                    "CoreDevice FileService timeout khi chờ phản hồi",
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

        let (input, action) = self.build_target_input("list", ctx, &scope)?;
        let reply = self
            .invoke_control(COREDEVICE_FEATURE_TRANSFER_FILES, input, action)
            .await?;

        let Some(output) = reply.dict_get_ci(&["CoreDevice.output", "output", "entries", "items"])
        else {
            return Err(CoreDeviceFileServiceError::request_mapping_incomplete(
                "CoreDevice fileservice list thiếu CoreDevice.output/entries",
            ));
        };

        let raw_items = if let Some(arr) = output.as_array() {
            arr
        } else if let Some(arr) = output
            .dict_get_ci(&["entries", "items", "files", "contents"])
            .and_then(|v| v.as_array())
        {
            arr
        } else {
            return Err(CoreDeviceFileServiceError::request_mapping_incomplete(
                "CoreDevice fileservice list nhận định dạng output không đầy đủ",
            ));
        };

        let mut parsed = Vec::with_capacity(raw_items.len());
        for entry in raw_items {
            if let Some(name_str) = entry.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                parsed.push(HouseArrestDirItem {
                    name: name_str.to_string(),
                    is_dir: false,
                    size: 0,
                });
                continue;
            }
            let Some(name) = entry
                .dict_get_ci(&["name", "filename", "relativePath", "path"])
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            let is_dir = entry
                .dict_get_ci(&["isDirectory", "is_dir", "directory", "type"])
                .map(|v| match v {
                    XpcValue::Bool(b) => *b,
                    XpcValue::String(s) => s.eq_ignore_ascii_case("directory") || s.eq_ignore_ascii_case("dir"),
                    _ => false,
                })
                .unwrap_or(false);
            let size = entry
                .dict_get_ci(&["size", "fileSize", "allocatedSize"])
                .and_then(|v| match v {
                    XpcValue::Int64(i) => Some(*i),
                    XpcValue::UInt64(u) => Some(*u as i64),
                    _ => None,
                })
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
        let (input, action) = self.build_target_input("fileservice_read", ctx, &scope)?;
        let reply = self
            .invoke_control(COREDEVICE_FEATURE_TRANSFER_FILES, input, action)
            .await?;

        let output = reply
            .dict_get_ci(&["CoreDevice.output", "output"])
            .ok_or_else(|| {
                CoreDeviceFileServiceError::request_mapping_incomplete(
                    "CoreDevice fileservice_read thiếu CoreDevice.output",
                )
            })?;

        // Inline data fast-path (small metadata files)
        if let Some(XpcValue::Data(inline_bytes)) = output.dict_get_ci(&["data", "contents", "bytes"])
        {
            return Ok(inline_bytes.clone());
        }

        let stream_size = output
            .dict_get_ci(&["size", "fileSize", "length"])
            .and_then(|v| match v {
                XpcValue::UInt64(u) => Some(*u as usize),
                XpcValue::Int64(i) if *i >= 0 => Some(*i as usize),
                _ => None,
            })
            .ok_or_else(|| {
                CoreDeviceFileServiceError::request_mapping_incomplete(
                    "CoreDevice fileservice_read thiếu byte stream mapping trên .data",
                )
            })?;

        match &mut self.data {
            FileServiceDataChannel::Xpc(data_xpc) => {
                let data_msg = tokio::time::timeout(Duration::from_secs(10), data_xpc.recv_reply())
                    .await
                    .map_err(|_| {
                        CoreDeviceFileServiceError::unavailable("Timeout đọc kênh fileservice.data")
                    })?
                    .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;
                if let Some(XpcValue::Data(bytes)) = data_msg.dict_get_ci(&["data", "payload", "bytes"])
                {
                    return Ok(bytes.clone());
                }
                Err(CoreDeviceFileServiceError::request_mapping_incomplete(
                    "Kênh XPC fileservice.data không trả về payload",
                ))
            }
            FileServiceDataChannel::RawStream(stream) => {
                let mut hdr = [0u8; 16];
                tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut hdr))
                    .await
                    .map_err(|_| {
                        CoreDeviceFileServiceError::unavailable("Timeout đọc header rwb!FILE")
                    })?
                    .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;
                if &hdr[..8] != DATA_STREAM_MAGIC {
                    return Err(CoreDeviceFileServiceError::request_mapping_incomplete(
                        "Header kênh fileservice.data không khớp rwb!FILE",
                    ));
                }
                let frame_len = u64::from_le_bytes([
                    hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
                ]) as usize;
                let expected = if frame_len > 0 { frame_len } else { stream_size };
                let mut payload = vec![0u8; expected];
                if expected > 0 {
                    tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut payload))
                        .await
                        .map_err(|_| {
                            CoreDeviceFileServiceError::unavailable("Timeout đọc payload từ fileservice.data")
                        })?
                        .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;
                }
                Ok(payload)
            }
        }
    }

    pub async fn fileservice_write_async(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
        data: &[u8],
    ) -> Result<(), CoreDeviceFileServiceError> {
        let scope = resolve_target_scope(ctx, path)?;
        let (mut input, action) = self.build_target_input("fileservice_write", ctx, &scope)?;
        if let XpcValue::Dictionary(ref mut entries) = input {
            entries.push(("fileSize".to_string(), XpcValue::UInt64(data.len() as u64)));
        }
        let reply = self
            .invoke_control(COREDEVICE_FEATURE_TRANSFER_FILES, input, action)
            .await?;

        let output = reply
            .dict_get_ci(&["CoreDevice.output", "output"])
            .ok_or_else(|| {
                CoreDeviceFileServiceError::request_mapping_incomplete(
                    "CoreDevice fileservice_write thiếu CoreDevice.output",
                )
            })?;

        let stream_token = output
            .dict_get_ci(&["transferIdentifier", "requestIdentifier", "streamID"])
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.session_token.clone());

        match &mut self.data {
            FileServiceDataChannel::Xpc(data_xpc) => {
                let payload_msg = XpcValue::Dictionary(vec![
                    ("sessionIdentifier".to_string(), XpcValue::String(stream_token)),
                    (
                        "controlcapacity".to_string(),
                        XpcValue::UInt64(self.control_capacity),
                    ),
                    ("data".to_string(), XpcValue::Data(data.to_vec())),
                ]);
                data_xpc
                    .send_object(payload_msg, true)
                    .await
                    .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;
                let ack = tokio::time::timeout(Duration::from_secs(10), data_xpc.recv_reply())
                    .await
                    .map_err(|_| {
                        CoreDeviceFileServiceError::unavailable("Timeout ACK fileservice.data")
                    })?
                    .map_err(|e| CoreDeviceFileServiceError::new(classify_xpc_error(&e), e))?;
                if let Some(err_msg) = extract_reply_error(&ack) {
                    return Err(CoreDeviceFileServiceError::new(
                        classify_xpc_error(&err_msg),
                        err_msg,
                    ));
                }
                Ok(())
            }
            FileServiceDataChannel::RawStream(stream) => {
                let mut hdr = Vec::with_capacity(16);
                hdr.extend_from_slice(DATA_STREAM_MAGIC);
                hdr.extend_from_slice(&(data.len() as u64).to_le_bytes());
                stream
                    .write_all(&hdr)
                    .await
                    .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;
                for chunk in data.chunks(self.control_capacity.min(131_072) as usize) {
                    stream
                        .write_all(chunk)
                        .await
                        .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;
                }
                stream
                    .flush()
                    .await
                    .map_err(|e| CoreDeviceFileServiceError::unavailable(e.to_string()))?;
                Ok(())
            }
        }
    }

    pub async fn fileservice_mkdir_async(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<(), CoreDeviceFileServiceError> {
        let scope = resolve_target_scope(ctx, path)?;
        let (input, action) = self.build_target_input("mkdir", ctx, &scope)?;
        let reply = self
            .invoke_control(COREDEVICE_FEATURE_TRANSFER_FILES, input, action)
            .await?;
        if reply.dict_get_ci(&["CoreDevice.output", "output"]).is_none() {
            return Err(CoreDeviceFileServiceError::request_mapping_incomplete(
                "CoreDevice mkdir thiếu CoreDevice.output",
            ));
        }
        Ok(())
    }

    pub async fn fileservice_remove_async(
        &mut self,
        ctx: &FileServiceTargetContext,
        path: &str,
    ) -> Result<(), CoreDeviceFileServiceError> {
        let scope = resolve_target_scope(ctx, path)?;
        let (input, action) = self.build_target_input("remove", ctx, &scope)?;
        let reply = self
            .invoke_control(COREDEVICE_FEATURE_TRANSFER_FILES, input, action)
            .await?;
        if reply.dict_get_ci(&["CoreDevice.output", "output"]).is_none() {
            return Err(CoreDeviceFileServiceError::request_mapping_incomplete(
                "CoreDevice remove thiếu CoreDevice.output",
            ));
        }
        Ok(())
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
