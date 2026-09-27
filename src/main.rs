use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use clap::Parser;
use md5::Md5;
use parking_lot::{Condvar, Mutex};
use rand::RngCore;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tiny_http::{Header, Method, Response, Server, StatusCode};
use url::Url;
use uuid::Uuid;

const AK: &str = "9f5c54c4ed0e50109b800f7e28fec205";
const RSA_PUBLIC_KEY_B64: &str = concat!(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkKeLy4ywWLSnBkwRyqYgF3HMIj05V5uuh5HjyEsZOWnu1NHu3jPQv3sr32wwQNYv5qa",
    "psNXmNgLUDHtgHZxqPQAYXltjSRc0qhcD286t62wOIHId8zXS3s1Jy4rgU4qjQWzI9rp/1sE0pMsmwTaJa4zuJ5iz8VwF8Av5oJ1k+HxY+/HLnj",
    "NlW1hmWLpuDYmkZYuAoTHa1VGeHQh9FEKI8ZcL3GTQphShUoC+Kg3P1hGUVTtCYapmzPS5lkAdwebuzwvTCfGiTErYZCnPBUSeV7BVlgjtLYIi2",
    "9KvF0a8FHsJMfe/UdHcyW/RihsIYOtDQcRRpFGXyPXbVrzFJse24QIDAQAB"
);

const CLOUD_GET_URL: &str = "https://ytpcloudws.cctv.cn/cloudps/wssapi/device/v2/get";
const CLOUD_REGISTER_URL: &str = "https://ytpcloudws.cctv.cn/cloudps/wssapi/device/v2/register";
const APP_START_URL: &str = "https://ytpaddr.cctv.cn/gsnw/api/app/start/v1/01";
const DRM_CONFIG_URL: &str = "https://ytpaddr.cctv.cn/gsnw/drm/config/obtain/v1";
const VERSION_CONFIG_URL: &str = "https://ytpaddr.cctv.cn/gsnw/version/config/obtain/v1";
const DICTIONARY_URL: &str = "https://ytpaddr.cctv.cn/gsnw/player/dictionary/obtain/v1";
const INDEX_URL: &str = "https://ytpaddr.cctv.cn/gsnw/api/index/v1/01";
const REPORT_SINGLE_URL: &str = "https://ytpdata.cctv.cn/das/app/data/message/single";
const COLLECT_REPORT_URL: &str = "https://collect.cctv.cn/cctvmobileinf/rest/cctv/receive/new/app";
const LIVE_V1_01_URL: &str = "https://ytpaddr.cctv.cn/gsnw/api/live/v1/01";
const LIVE_V1_02_URL: &str = "https://ytpaddr.cctv.cn/gsnw/api/live/v1/02";
const VDN_GETSTREAM_URL: &str =
    "https://ytpvdn.cctv.cn/cctvmobileinf/rest/cctv/videoliveUrl/getstream";

const DEFAULT_LIVE_USER_ID: &str = "BAEBFF2B-C516-4F34-ABC0-A824A6461CBD";
const DEFAULT_DEVICE_NAME: &str = "央视频电视投屏助手";
const VDN_APP_NAME: &str = "央视频电视投屏助手";
const REPORT_APP_KEY: &str = "1178c84d-4818-44ff-b415-02106e87e144";
const COLLECT_SDK_VERSION: &str = "1.0.0";
const DEFAULT_PAGE_NAME: &str = "com.cctv.tv.mvp.ui.activity.MainActivity";
const DEFAULT_ACCEPT_LANGUAGE: &str = "zh-CN,zh;q=0.8";
const SWITCH_TOKEN: &str = "iptvofficalgroup";
const AD_REDIRECT_URL: &str = "https://cdn.jsdelivr.net/gh/iptvorganization/first/group.ts";
const DEFAULT_REDIRECT_URL: &str = "https://t.me/iptvofficalgroup";
const RESULT_OK: i64 = 0;
const RESULT_NEEDS_REGISTER: i64 = 601;
const RESULT_GET_MISSING_OR_INVALID: i64 = 2;
const RESULT_REGISTERED_ELSEWHERE: i64 = 694;
const RESULT_REGISTER_RETRY_LATER: i64 = 695;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Rust CCTV live m3u8 proxy")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value_t = 8766)]
    port: u16,
    #[arg(long, default_value_t = 600.0)]
    cache_ttl: f64,
    #[arg(long, default_value_t = 120.0)]
    stale_while_refresh_ttl: f64,
    #[arg(long, default_value_t = 30.0)]
    refresh_error_cooldown: f64,
    #[arg(long, default_value_t = 0.0)]
    playlist_cache_ttl: f64,
    #[arg(long, default_value_t = 4)]
    background_refresh_queue_limit: usize,
    #[arg(long, default_value_t = 64)]
    http_workers: usize,
    #[arg(long, default_value_t = 20000)]
    http_queue_limit: usize,
    #[arg(long, default_value_t = 3)]
    identity_reset_error_threshold: u32,
    #[arg(long, default_value_t = 300.0)]
    identity_reset_cooldown: f64,
    #[arg(long, default_value_t = 2.0)]
    refresh_interval: f64,
    #[arg(long, default_value_t = 0)]
    control_step_jitter_min_ms: u64,
    #[arg(long, default_value_t = 0)]
    control_step_jitter_max_ms: u64,
    #[arg(long, default_value_t = 30.0)]
    heartbeat_interval: f64,
    #[arg(long, default_value_t = 60.0)]
    heartbeat_ttl_guard: f64,
    #[arg(long, default_value_t = 7200.0)]
    session_ttl: f64,
    #[arg(long, default_value_t = 15.0)]
    timeout: f64,
    #[arg(long, default_value = "")]
    meta_json: String,
    #[arg(long, default_value = "")]
    device_json: String,
    #[arg(long, default_value_t = false)]
    insecure_tls: bool,
}

impl Args {
    fn resolve_paths(&mut self) -> Result<()> {
        let dir = binary_dir()?;
        if self.meta_json.trim().is_empty() {
            self.meta_json = dir
                .join("proxy-cache-state-rs.json")
                .to_string_lossy()
                .into_owned();
        }
        if self.device_json.trim().is_empty() {
            self.device_json = dir
                .join("device-state-rs.json")
                .to_string_lossy()
                .into_owned();
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeviceProfile {
    android_id: String,
    mac: String,
    hardware: String,
    board: String,
    brand: String,
    device: String,
    manufacturer: String,
    model: String,
    product: String,
    tags: String,
    build_type: String,
    user: String,
    resolution: String,
    display: String,
    version_id: String,
    host: String,
    fingerprint: String,
    report_model: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeviceState {
    schema_version: u32,
    profile_source: String,
    profile: DeviceProfile,
    screen_param: String,
    cast_model: String,
    x_uid: String,
    cloud_guid: String,
    registered_at: f64,
    updated_at: f64,
}

#[derive(Clone, Debug)]
struct LoadedDeviceState {
    state: DeviceState,
    existed: bool,
}

#[derive(Clone, Debug)]
struct Identity {
    x_uid: String,
    x_fingerprint: String,
    fingerprint_timestamp_ms: i64,
    headers: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChannelEntry {
    channel: String,
    live_id: String,
    final_url: String,
    playback_headers: HashMap<String, String>,
    android_id: String,
    x_uid: String,
    rate: String,
    rate_name: String,
    raw_live_host: String,
    final_host: String,
    refreshed_at: f64,
    expires_at: f64,
    generation: u64,
    last_refresh_error: String,
    last_refresh_failed_at: f64,
    session_generation: u64,
}

#[derive(Clone, Debug)]
struct PlaylistCacheEntry {
    body: String,
    content_type: String,
    cached_at: f64,
    expires_at: f64,
    final_url: String,
    android_id: String,
    proxy_origin: String,
    proxy_prefix: String,
}

#[derive(Clone, Debug)]
struct PlaylistCacheProbe {
    state: String,
    age_ms: Option<i64>,
}

impl ChannelEntry {
    fn fresh(&self, now: f64) -> bool {
        !self.final_url.is_empty() && now < self.expires_at
    }

    fn stale_usable(&self, now: f64, ttl: f64) -> bool {
        !self.final_url.is_empty() && ttl > 0.0 && now < self.expires_at + ttl
    }
}

#[derive(Clone)]
struct AppSessionState {
    profile: DeviceProfile,
    identity: Identity,
    client: Client,
    session_key: String,
    cloud_guid: String,
    version: String,
    screen_param: String,
    cast_model: String,
    created_at: f64,
    generation: u64,
    last_heartbeat_at: f64,
    heartbeat_count: u64,
    last_heartbeat_result: String,
    last_heartbeat_error: String,
}

struct ResolverState {
    cache: HashMap<String, ChannelEntry>,
    playlist_cache: HashMap<String, PlaylistCacheEntry>,
    background_refreshing: HashMap<String, f64>,
    generation: u64,
    session_generation: u64,
    app_session: Option<AppSessionState>,
    last_control_request_at: f64,
    last_business_end_at: f64,
    refreshing_channel: String,
    last_error: String,
    last_error_at: f64,
    identity_reset_error_count: u32,
    identity_reset_count: u64,
    last_identity_reset_at: f64,
    last_identity_reset_reason: String,
    ad_display: bool,
}

struct RefreshQueueState {
    queued: VecDeque<String>,
    queued_channels: HashMap<String, f64>,
    running_channel: String,
    running_started_at: f64,
    enqueued_total: u64,
    dropped_total: u64,
    completed_total: u64,
    failed_total: u64,
    last_enqueued_at: f64,
    last_finished_at: f64,
    last_dropped_at: f64,
    last_drop_reason: String,
}

struct RefreshQueue {
    state: Mutex<RefreshQueueState>,
    condvar: Condvar,
}

struct HttpQueueState {
    queued: VecDeque<tiny_http::Request>,
    active_workers: usize,
    enqueued_total: u64,
    rejected_total: u64,
    completed_total: u64,
    panicked_total: u64,
    last_enqueued_at: f64,
    last_completed_at: f64,
    last_rejected_at: f64,
}

struct HttpQueue {
    state: Mutex<HttpQueueState>,
    condvar: Condvar,
}

struct PrefixReader<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> PrefixReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<R: Read> Read for PrefixReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let len = (self.prefix.len() - self.pos).min(buf.len());
            buf[..len].copy_from_slice(&self.prefix[self.pos..self.pos + len]);
            self.pos += len;
            return Ok(len);
        }
        self.inner.read(buf)
    }
}

enum RefreshEnqueueResult {
    Enqueued,
    AlreadyActive,
    Rejected(String),
}

#[derive(Clone)]
struct Resolver {
    args: Args,
    generic_client: Client,
    state: Arc<Mutex<ResolverState>>,
    control_lock: Arc<Mutex<()>>,
    playlist_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    refresh_queue: Arc<RefreshQueue>,
    http_queue: Arc<HttpQueue>,
}

struct ControlRequestSlot {
    state: Arc<Mutex<ResolverState>>,
}

impl Drop for ControlRequestSlot {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        state.last_control_request_at = now_f64();
    }
}

fn channels() -> &'static [(&'static str, &'static str)] {
    &[
        ("cctv5", "Live1719474204987287"),
        ("cctv5p", "Live1719473996025286"),
        ("cctv164k", "Live1704966749996185"),
        ("cctv4k", "Live1767871224782105"),
        ("cctv8k", "Live1688400593818102"),
    ]
}

fn channel_by_name(name: &str) -> Option<&'static str> {
    channels()
        .iter()
        .find(|(c, _)| *c == name)
        .map(|(_, id)| *id)
}

fn is_session_invalidating_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("app/start")
        || lower.contains("decrypt")
        || lower.contains("session_key")
        || lower.contains("missing encrypted session key")
        || is_session_core_http_400(&lower)
        || lower.contains("live/v1/01 http 400")
        || lower.contains("live/v1/01 http 401")
        || lower.contains("live/v1/01 http 403")
        || lower.contains("live/v1/02 http 400")
        || lower.contains("live/v1/02 http 401")
        || lower.contains("live/v1/02 http 403")
}

fn is_identity_recoverable_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    is_session_invalidating_error(message)
        || is_control_plane_http_400(&lower)
        || lower.contains("upstream m3u8 http 400")
        || lower.contains("upstream m3u8 http 401")
        || lower.contains("upstream m3u8 http 403")
        || lower.contains("upstream m3u8 http 404")
        || lower.contains("playlist response missing")
        || lower.contains("invalid playlist status")
        || lower.contains("connection reset")
        || lower.contains("connection refused")
        || lower.contains("operation timed out")
        || lower.contains("timed out")
        || lower.contains("network is unreachable")
        || lower.contains("nodename nor servname")
        || lower.contains("failed to lookup address")
}

fn has_http_400(lower: &str) -> bool {
    lower.contains("http 400") || lower.contains("status=400")
}

fn is_session_core_http_400(lower: &str) -> bool {
    has_http_400(lower)
        && ["app/start", "live/v1/01", "live/v1/02", "vdn", "heartbeat"]
            .iter()
            .any(|needle| lower.contains(needle))
}

fn is_control_plane_http_400(lower: &str) -> bool {
    has_http_400(lower)
        && [
            "app/start",
            "dictionary",
            "app event",
            "page event",
            "cloud_get",
            "cloud get",
            "cloud_register",
            "cloud register",
            "device info",
            "heartbeat",
            "index",
            "drm config",
            "version config",
            "live/v1/01",
            "live/v1/02",
            "vdn",
            "collect report",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn normalize_channel(raw: &str) -> String {
    let mut key = raw.trim().trim_matches('/').to_ascii_lowercase();
    if let Some(stripped) = key.strip_suffix(".m3u8") {
        key = stripped.to_string();
    }
    match key.as_str() {
        "cctv16" | "cctv16-4k" | "cctv16_4k" | "cctv16/4k" | "cctv16(4k)" => "cctv164k".to_string(),
        _ => key,
    }
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn current_time_ms() -> i64 {
    (now_f64() * 1000.0) as i64
}

fn sha1_upper(value: &str) -> String {
    let mut h = Sha1::new();
    h.update(value.as_bytes());
    hex::encode_upper(h.finalize())
}

fn sha256_hex(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    hex::encode(h.finalize())
}

fn md5_hex(value: &str) -> String {
    let mut h = Md5::new();
    h.update(value.as_bytes());
    hex::encode(h.finalize())
}

fn log_program_initializing() {
    eprintln!("程序初始化中");
}

fn log_program_fetching() {
    eprintln!("程序获取直播源中");
}

fn log_channel_ready(channel: &str) {
    eprintln!("程序已成功获取{channel}的直播源");
}

fn inspect_playlist_cache(
    cached: Option<&PlaylistCacheEntry>,
    entry: &ChannelEntry,
    proxy_origin: &str,
    proxy_prefix: Option<&str>,
    now: f64,
) -> PlaylistCacheProbe {
    let Some(cached) = cached else {
        return PlaylistCacheProbe {
            state: "miss:not_found".to_string(),
            age_ms: None,
        };
    };

    let age_ms = Some(((now - cached.cached_at).max(0.0) * 1000.0).round() as i64);
    let fresh = now < cached.expires_at;
    let same_final_url = cached.final_url == entry.final_url;
    let same_android_id = cached.android_id == entry.android_id;
    let same_origin = cached.proxy_origin == proxy_origin;
    let same_prefix = cached.proxy_prefix == proxy_prefix.unwrap_or("");

    if fresh && same_final_url && same_android_id && same_origin && same_prefix {
        return PlaylistCacheProbe {
            state: "hit".to_string(),
            age_ms,
        };
    }

    let mut reasons = Vec::new();
    if !fresh {
        reasons.push("expired");
    }
    if !same_final_url {
        reasons.push("final_url_changed");
    }
    if !same_android_id {
        reasons.push("android_id_changed");
    }
    if !same_origin {
        reasons.push("origin_changed");
    }
    if !same_prefix {
        reasons.push("prefix_changed");
    }
    if reasons.is_empty() {
        reasons.push("unknown");
    }

    PlaylistCacheProbe {
        state: format!("miss:{}", reasons.join("+")),
        age_ms,
    }
}

fn java_string_hashcode(value: &str) -> i32 {
    let mut h: i32 = 0;
    for ch in value.chars() {
        h = h.wrapping_mul(31).wrapping_add(ch as i32);
    }
    h
}

fn java_uuid_from_hashes(msb_hash: i32, lsb_hash: i32) -> String {
    let msb = msb_hash as i64 as u64 as u128;
    let lsb = lsb_hash as i64 as u64 as u128;
    format!("{:032x}", (msb << 64) | lsb)
}

fn native_day0_ms(now_s: i64) -> i64 {
    86_400_000 * ((now_s + 28_800) / 86_400) - 28_800_000
}

fn compute_fingerprint(x_uid: &str, now_ms: i64) -> (String, i64, i64) {
    let day0_ms = native_day0_ms(now_ms / 1000);
    let first = sha256_hex(&format!("{AK}{x_uid}{now_ms}{day0_ms}"));
    (sha256_hex(&first), now_ms, day0_ms)
}

fn random_hex_string(len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut rng = rand::thread_rng();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for _ in 0..len {
        out.push(HEX[(rng.next_u32() as usize) & 0x0f] as char);
    }
    out
}

fn random_mac_address() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] = (bytes[0] | 0x02) & 0xfe;
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Clone, Copy)]
struct DeviceProfileTemplate {
    source: &'static str,
    brand: &'static str,
    manufacturer: &'static str,
    model: &'static str,
    report_model: &'static str,
    hardware: &'static str,
    board: &'static str,
    version_id: &'static str,
    screen_param: &'static str,
    cast_model: &'static str,
}

fn sanitize_profile_id(value: &str) -> String {
    let mut out = String::new();
    let mut last_underscore = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn resolution_from_screen_param(screen_param: &str) -> String {
    let mut parts = screen_param.split('-');
    match (parts.next(), parts.next()) {
        (Some(width), Some(height)) if !width.is_empty() && !height.is_empty() => {
            format!("{width}*{height}")
        }
        _ => "3840*2160".to_string(),
    }
}

fn device_profile_pool() -> &'static [DeviceProfileTemplate] {
    &[
        DeviceProfileTemplate {
            source: "sony_8k_pool.XR-85Z9K",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-85Z9K",
            report_model: "XR85Z9K",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2022.XR_85Z9K",
            screen_param: "7680-4320-280",
            cast_model: "XR-85Z9K",
        },
        DeviceProfileTemplate {
            source: "sony_8k_pool.XR-75Z9K",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-75Z9K",
            report_model: "XR75Z9K",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2022.XR_75Z9K",
            screen_param: "7680-4320-260",
            cast_model: "XR-75Z9K",
        },
        DeviceProfileTemplate {
            source: "sony_8k_pool.XR-85Z9J",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-85Z9J",
            report_model: "XR85Z9J",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2021.XR_85Z9J",
            screen_param: "7680-4320-280",
            cast_model: "XR-85Z9J",
        },
        DeviceProfileTemplate {
            source: "sony_8k_pool.XR-75Z9J",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-75Z9J",
            report_model: "XR75Z9J",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2021.XR_75Z9J",
            screen_param: "7680-4320-260",
            cast_model: "XR-75Z9J",
        },
        DeviceProfileTemplate {
            source: "sony_8k_pool.KD-98ZG9",
            brand: "Sony",
            manufacturer: "Sony",
            model: "KD-98ZG9",
            report_model: "KD98ZG9",
            hardware: "mt5893",
            board: "mt5893",
            version_id: "SONYTV.2019.KD_98ZG9",
            screen_param: "7680-4320-320",
            cast_model: "KD-98ZG9",
        },
        DeviceProfileTemplate {
            source: "sony_8k_pool.KD-85ZG9",
            brand: "Sony",
            manufacturer: "Sony",
            model: "KD-85ZG9",
            report_model: "KD85ZG9",
            hardware: "mt5893",
            board: "mt5893",
            version_id: "SONYTV.2019.KD_85ZG9",
            screen_param: "7680-4320-280",
            cast_model: "KD-85ZG9",
        },
        DeviceProfileTemplate {
            source: "sony_8k_pool.KD-85ZH8",
            brand: "Sony",
            manufacturer: "Sony",
            model: "KD-85ZH8",
            report_model: "KD85ZH8",
            hardware: "mt5893",
            board: "mt5893",
            version_id: "SONYTV.2020.KD_85ZH8",
            screen_param: "7680-4320-280",
            cast_model: "KD-85ZH8",
        },
        DeviceProfileTemplate {
            source: "sony_8k_pool.KD-75ZH8",
            brand: "Sony",
            manufacturer: "Sony",
            model: "KD-75ZH8",
            report_model: "KD75ZH8",
            hardware: "mt5893",
            board: "mt5893",
            version_id: "SONYTV.2020.KD_75ZH8",
            screen_param: "7680-4320-260",
            cast_model: "KD-75ZH8",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA85QN900A",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA85QN900A",
            report_model: "QA85QN900A",
            hardware: "s5e9925",
            board: "neo8k",
            version_id: "SAMSUNGTV.2021.QN900A",
            screen_param: "7680-4320-280",
            cast_model: "QA85QN900A",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA75QN900A",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA75QN900A",
            report_model: "QA75QN900A",
            hardware: "s5e9925",
            board: "neo8k",
            version_id: "SAMSUNGTV.2021.QN900A",
            screen_param: "7680-4320-260",
            cast_model: "QA75QN900A",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA85QN900B",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA85QN900B",
            report_model: "QA85QN900B",
            hardware: "s5e9925",
            board: "neo8k",
            version_id: "SAMSUNGTV.2022.QN900B",
            screen_param: "7680-4320-280",
            cast_model: "QA85QN900B",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA75QN900B",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA75QN900B",
            report_model: "QA75QN900B",
            hardware: "s5e9925",
            board: "neo8k",
            version_id: "SAMSUNGTV.2022.QN900B",
            screen_param: "7680-4320-260",
            cast_model: "QA75QN900B",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA85QN900C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA85QN900C",
            report_model: "QA85QN900C",
            hardware: "s5e9935",
            board: "neo8k",
            version_id: "SAMSUNGTV.2023.QN900C",
            screen_param: "7680-4320-280",
            cast_model: "QA85QN900C",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA75QN900C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA75QN900C",
            report_model: "QA75QN900C",
            hardware: "s5e9935",
            board: "neo8k",
            version_id: "SAMSUNGTV.2023.QN900C",
            screen_param: "7680-4320-260",
            cast_model: "QA75QN900C",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA85QN900D",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA85QN900D",
            report_model: "QA85QN900D",
            hardware: "s5e9945",
            board: "neo8k",
            version_id: "SAMSUNGTV.2024.QN900D",
            screen_param: "7680-4320-280",
            cast_model: "QA85QN900D",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA98QN990C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA98QN990C",
            report_model: "QA98QN990C",
            hardware: "s5e9935",
            board: "neo8k",
            version_id: "SAMSUNGTV.2023.QN990C",
            screen_param: "7680-4320-320",
            cast_model: "QA98QN990C",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA85QN800C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA85QN800C",
            report_model: "QA85QN800C",
            hardware: "s5e9935",
            board: "neo8k",
            version_id: "SAMSUNGTV.2023.QN800C",
            screen_param: "7680-4320-280",
            cast_model: "QA85QN800C",
        },
        DeviceProfileTemplate {
            source: "samsung_8k_pool.QA75QN800D",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA75QN800D",
            report_model: "QA75QN800D",
            hardware: "s5e9945",
            board: "neo8k",
            version_id: "SAMSUNGTV.2024.QN800D",
            screen_param: "7680-4320-260",
            cast_model: "QA75QN800D",
        },
        DeviceProfileTemplate {
            source: "lg_8k_pool.OLED88Z1PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED88Z1PCA",
            report_model: "OLED88Z1PCA",
            hardware: "alpha9gen4",
            board: "lg8k",
            version_id: "LGTV.2021.OLED88Z1",
            screen_param: "7680-4320-320",
            cast_model: "OLED88Z1PCA",
        },
        DeviceProfileTemplate {
            source: "lg_8k_pool.OLED77Z1PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED77Z1PCA",
            report_model: "OLED77Z1PCA",
            hardware: "alpha9gen4",
            board: "lg8k",
            version_id: "LGTV.2021.OLED77Z1",
            screen_param: "7680-4320-260",
            cast_model: "OLED77Z1PCA",
        },
        DeviceProfileTemplate {
            source: "lg_8k_pool.OLED88Z2PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED88Z2PCA",
            report_model: "OLED88Z2PCA",
            hardware: "alpha9gen5",
            board: "lg8k",
            version_id: "LGTV.2022.OLED88Z2",
            screen_param: "7680-4320-320",
            cast_model: "OLED88Z2PCA",
        },
        DeviceProfileTemplate {
            source: "lg_8k_pool.OLED77Z2PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED77Z2PCA",
            report_model: "OLED77Z2PCA",
            hardware: "alpha9gen5",
            board: "lg8k",
            version_id: "LGTV.2022.OLED77Z2",
            screen_param: "7680-4320-260",
            cast_model: "OLED77Z2PCA",
        },
        DeviceProfileTemplate {
            source: "lg_8k_pool.OLED88Z3PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED88Z3PCA",
            report_model: "OLED88Z3PCA",
            hardware: "alpha9gen6",
            board: "lg8k",
            version_id: "LGTV.2023.OLED88Z3",
            screen_param: "7680-4320-320",
            cast_model: "OLED88Z3PCA",
        },
        DeviceProfileTemplate {
            source: "lg_8k_pool.OLED77Z3PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED77Z3PCA",
            report_model: "OLED77Z3PCA",
            hardware: "alpha9gen6",
            board: "lg8k",
            version_id: "LGTV.2023.OLED77Z3",
            screen_param: "7680-4320-260",
            cast_model: "OLED77Z3PCA",
        },
        DeviceProfileTemplate {
            source: "lg_8k_pool.OLED88Z4PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED88Z4PCA",
            report_model: "OLED88Z4PCA",
            hardware: "alpha9gen7",
            board: "lg8k",
            version_id: "LGTV.2024.OLED88Z4",
            screen_param: "7680-4320-320",
            cast_model: "OLED88Z4PCA",
        },
        DeviceProfileTemplate {
            source: "lg_8k_pool.86QNED99",
            brand: "LG",
            manufacturer: "LGE",
            model: "86QNED99",
            report_model: "86QNED99",
            hardware: "alpha9gen4",
            board: "lg8k",
            version_id: "LGTV.2021.86QNED99",
            screen_param: "7680-4320-300",
            cast_model: "86QNED99",
        },
        DeviceProfileTemplate {
            source: "sony_4k_pool.XR-85X95K",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-85X95K",
            report_model: "XR85X95K",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2022.XR_85X95K",
            screen_param: "3840-2160-300",
            cast_model: "XR-85X95K",
        },
        DeviceProfileTemplate {
            source: "sony_4k_pool.XR-75X95K",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-75X95K",
            report_model: "XR75X95K",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2022.XR_75X95K",
            screen_param: "3840-2160-280",
            cast_model: "XR-75X95K",
        },
        DeviceProfileTemplate {
            source: "sony_4k_pool.XR-65X90K",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-65X90K",
            report_model: "XR65X90K",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2022.XR_65X90K",
            screen_param: "3840-2160-260",
            cast_model: "XR-65X90K",
        },
        DeviceProfileTemplate {
            source: "sony_4k_pool.XR-55X90K",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-55X90K",
            report_model: "XR55X90K",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2022.XR_55X90K",
            screen_param: "3840-2160-240",
            cast_model: "XR-55X90K",
        },
        DeviceProfileTemplate {
            source: "sony_4k_pool.XR-65A95K",
            brand: "Sony",
            manufacturer: "Sony",
            model: "XR-65A95K",
            report_model: "XR65A95K",
            hardware: "mt5895",
            board: "mt5895",
            version_id: "SONYTV.2022.XR_65A95K",
            screen_param: "3840-2160-260",
            cast_model: "XR-65A95K",
        },
        DeviceProfileTemplate {
            source: "samsung_4k_pool.QA85QN90C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA85QN90C",
            report_model: "QA85QN90C",
            hardware: "s5e9935",
            board: "neo4k",
            version_id: "SAMSUNGTV.2023.QN90C",
            screen_param: "3840-2160-300",
            cast_model: "QA85QN90C",
        },
        DeviceProfileTemplate {
            source: "samsung_4k_pool.QA75QN90C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA75QN90C",
            report_model: "QA75QN90C",
            hardware: "s5e9935",
            board: "neo4k",
            version_id: "SAMSUNGTV.2023.QN90C",
            screen_param: "3840-2160-280",
            cast_model: "QA75QN90C",
        },
        DeviceProfileTemplate {
            source: "samsung_4k_pool.QA65QN90C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA65QN90C",
            report_model: "QA65QN90C",
            hardware: "s5e9935",
            board: "neo4k",
            version_id: "SAMSUNGTV.2023.QN90C",
            screen_param: "3840-2160-260",
            cast_model: "QA65QN90C",
        },
        DeviceProfileTemplate {
            source: "samsung_4k_pool.QA55QN90C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA55QN90C",
            report_model: "QA55QN90C",
            hardware: "s5e9935",
            board: "neo4k",
            version_id: "SAMSUNGTV.2023.QN90C",
            screen_param: "3840-2160-240",
            cast_model: "QA55QN90C",
        },
        DeviceProfileTemplate {
            source: "samsung_4k_pool.QA65S95C",
            brand: "Samsung",
            manufacturer: "Samsung",
            model: "QA65S95C",
            report_model: "QA65S95C",
            hardware: "s5e9935",
            board: "oled4k",
            version_id: "SAMSUNGTV.2023.S95C",
            screen_param: "3840-2160-260",
            cast_model: "QA65S95C",
        },
        DeviceProfileTemplate {
            source: "lg_4k_pool.OLED83C3PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED83C3PCA",
            report_model: "OLED83C3PCA",
            hardware: "alpha9gen6",
            board: "lg4k",
            version_id: "LGTV.2023.OLED83C3",
            screen_param: "3840-2160-300",
            cast_model: "OLED83C3PCA",
        },
        DeviceProfileTemplate {
            source: "lg_4k_pool.OLED77C3PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED77C3PCA",
            report_model: "OLED77C3PCA",
            hardware: "alpha9gen6",
            board: "lg4k",
            version_id: "LGTV.2023.OLED77C3",
            screen_param: "3840-2160-280",
            cast_model: "OLED77C3PCA",
        },
        DeviceProfileTemplate {
            source: "lg_4k_pool.OLED65C3PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED65C3PCA",
            report_model: "OLED65C3PCA",
            hardware: "alpha9gen6",
            board: "lg4k",
            version_id: "LGTV.2023.OLED65C3",
            screen_param: "3840-2160-260",
            cast_model: "OLED65C3PCA",
        },
        DeviceProfileTemplate {
            source: "lg_4k_pool.OLED55C3PCA",
            brand: "LG",
            manufacturer: "LGE",
            model: "OLED55C3PCA",
            report_model: "OLED55C3PCA",
            hardware: "alpha9gen6",
            board: "lg4k",
            version_id: "LGTV.2023.OLED55C3",
            screen_param: "3840-2160-240",
            cast_model: "OLED55C3PCA",
        },
        DeviceProfileTemplate {
            source: "lg_4k_pool.86QNED90",
            brand: "LG",
            manufacturer: "LGE",
            model: "86QNED90",
            report_model: "86QNED90",
            hardware: "alpha7gen5",
            board: "lg4k",
            version_id: "LGTV.2022.86QNED90",
            screen_param: "3840-2160-300",
            cast_model: "86QNED90",
        },
        DeviceProfileTemplate {
            source: "tcl_8k_pool.85X925PRO",
            brand: "TCL",
            manufacturer: "TCL",
            model: "85X925 PRO",
            report_model: "85X925PRO",
            hardware: "mt9615",
            board: "tcl8k",
            version_id: "TCLTV.2021.X925PRO",
            screen_param: "7680-4320-280",
            cast_model: "85X925 PRO",
        },
        DeviceProfileTemplate {
            source: "tcl_8k_pool.75X925PRO",
            brand: "TCL",
            manufacturer: "TCL",
            model: "75X925 PRO",
            report_model: "75X925PRO",
            hardware: "mt9615",
            board: "tcl8k",
            version_id: "TCLTV.2021.X925PRO",
            screen_param: "7680-4320-260",
            cast_model: "75X925 PRO",
        },
        DeviceProfileTemplate {
            source: "tcl_4k_pool.85C845",
            brand: "TCL",
            manufacturer: "TCL",
            model: "85C845",
            report_model: "85C845",
            hardware: "mt9615",
            board: "tcl4k",
            version_id: "TCLTV.2023.C845",
            screen_param: "3840-2160-300",
            cast_model: "85C845",
        },
        DeviceProfileTemplate {
            source: "tcl_4k_pool.75C845",
            brand: "TCL",
            manufacturer: "TCL",
            model: "75C845",
            report_model: "75C845",
            hardware: "mt9615",
            board: "tcl4k",
            version_id: "TCLTV.2023.C845",
            screen_param: "3840-2160-280",
            cast_model: "75C845",
        },
        DeviceProfileTemplate {
            source: "tcl_4k_pool.65C845",
            brand: "TCL",
            manufacturer: "TCL",
            model: "65C845",
            report_model: "65C845",
            hardware: "mt9615",
            board: "tcl4k",
            version_id: "TCLTV.2023.C845",
            screen_param: "3840-2160-260",
            cast_model: "65C845",
        },
        DeviceProfileTemplate {
            source: "tcl_4k_pool.75C745",
            brand: "TCL",
            manufacturer: "TCL",
            model: "75C745",
            report_model: "75C745",
            hardware: "mt9615",
            board: "tcl4k",
            version_id: "TCLTV.2023.C745",
            screen_param: "3840-2160-280",
            cast_model: "75C745",
        },
        DeviceProfileTemplate {
            source: "tcl_4k_pool.65C745",
            brand: "TCL",
            manufacturer: "TCL",
            model: "65C745",
            report_model: "65C745",
            hardware: "mt9615",
            board: "tcl4k",
            version_id: "TCLTV.2023.C745",
            screen_param: "3840-2160-260",
            cast_model: "65C745",
        },
        DeviceProfileTemplate {
            source: "changhong_4k_pool.U65G7",
            brand: "CHANGHONG",
            manufacturer: "CHANGHONG",
            model: "U65G7",
            report_model: "U65G7",
            hardware: "mt9632",
            board: "changhong4k",
            version_id: "CHANGHONGTV.2022.U65G7",
            screen_param: "3840-2160-260",
            cast_model: "U65G7",
        },
        DeviceProfileTemplate {
            source: "changhong_4k_pool.U55G7",
            brand: "CHANGHONG",
            manufacturer: "CHANGHONG",
            model: "U55G7",
            report_model: "U55G7",
            hardware: "mt9632",
            board: "changhong4k",
            version_id: "CHANGHONGTV.2022.U55G7",
            screen_param: "3840-2160-240",
            cast_model: "U55G7",
        },
        DeviceProfileTemplate {
            source: "changhong_4k_pool.L55QCN1",
            brand: "CHANGHONG",
            manufacturer: "CHANGHONG",
            model: "L55QCN1",
            report_model: "L55QCN1",
            hardware: "mt9632",
            board: "changhong4k",
            version_id: "CHANGHONGTV.2021.L55QCN1",
            screen_param: "3840-2160-240",
            cast_model: "L55QCN1",
        },
        DeviceProfileTemplate {
            source: "changhong_4k_pool.U43QCN1",
            brand: "CHANGHONG",
            manufacturer: "CHANGHONG",
            model: "U43QCN1",
            report_model: "U43QCN1",
            hardware: "mt9632",
            board: "changhong4k",
            version_id: "CHANGHONGTV.2021.U43QCN1",
            screen_param: "3840-2160-220",
            cast_model: "U43QCN1",
        },
        DeviceProfileTemplate {
            source: "changhong_4k_pool.UD65YC5500UA",
            brand: "CHANGHONG",
            manufacturer: "CHANGHONG",
            model: "UD65YC5500UA",
            report_model: "UD65YC5500UA",
            hardware: "mt9632",
            board: "changhong4k",
            version_id: "CHANGHONGTV.2020.UD65YC5500UA",
            screen_param: "3840-2160-260",
            cast_model: "UD65YC5500UA",
        },
    ]
}

fn random_device_template() -> &'static DeviceProfileTemplate {
    let pool = device_profile_pool();
    let idx = (rand::thread_rng().next_u32() as usize) % pool.len();
    &pool[idx]
}

fn device_profile_from_template(
    template: &DeviceProfileTemplate,
    android_id: String,
    mac: String,
) -> DeviceProfile {
    let brand_id = sanitize_profile_id(template.brand);
    let model_id = sanitize_profile_id(template.model);
    let device = format!("{brand_id}_{model_id}");
    let product = format!("{brand_id}_{model_id}");
    DeviceProfile {
        android_id,
        mac,
        hardware: template.hardware.to_string(),
        board: template.board.to_string(),
        brand: template.brand.to_string(),
        device: device.clone(),
        manufacturer: template.manufacturer.to_string(),
        model: template.model.to_string(),
        product: product.clone(),
        tags: "release-keys".to_string(),
        build_type: "user".to_string(),
        user: "build".to_string(),
        resolution: resolution_from_screen_param(template.screen_param),
        display: format!(
            "{}-user 13 {} 2024 release-keys",
            template.model, template.version_id
        ),
        version_id: template.version_id.to_string(),
        host: format!("{brand_id}-tv-build"),
        fingerprint: format!(
            "{}/{}/{}:13/{}/2024:user/release-keys",
            template.manufacturer, product, device, template.version_id
        ),
        report_model: template.report_model.to_string(),
    }
}

fn default_device_state() -> DeviceState {
    let template = random_device_template();
    let profile =
        device_profile_from_template(template, random_hex_string(16), random_mac_address());
    let x_uid = compute_x_uid(&profile);
    DeviceState {
        schema_version: 1,
        profile_source: template.source.to_string(),
        profile,
        screen_param: template.screen_param.to_string(),
        cast_model: template.cast_model.to_string(),
        x_uid,
        cloud_guid: String::new(),
        registered_at: 0.0,
        updated_at: now_f64(),
    }
}

fn binary_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".")))
}

fn load_device_state(path: &str) -> LoadedDeviceState {
    let Ok(text) = fs::read_to_string(path) else {
        return LoadedDeviceState {
            state: default_device_state(),
            existed: false,
        };
    };
    let Ok(mut state) = serde_json::from_str::<DeviceState>(&text) else {
        return LoadedDeviceState {
            state: default_device_state(),
            existed: false,
        };
    };
    if state.profile.android_id.len() != 16 || state.profile.mac.is_empty() {
        return LoadedDeviceState {
            state: default_device_state(),
            existed: false,
        };
    }
    state.x_uid = compute_x_uid(&state.profile);
    if state.screen_param.is_empty() {
        state.screen_param = "7680-4320-280".to_string();
    }
    if state.cast_model.is_empty() {
        state.cast_model = state.profile.model.clone();
    }
    LoadedDeviceState {
        state,
        existed: true,
    }
}

fn save_device_state(path: &str, state: &DeviceState) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(state)? + "\n")?;
    Ok(())
}

fn infer_os_version(profile: &DeviceProfile) -> String {
    if let Some((_, tail)) = profile.fingerprint.split_once(':') {
        if let Some((release, _)) = tail.split_once('/') {
            return release.to_string();
        }
    }
    String::new()
}

fn infer_sdk_int(profile: &DeviceProfile) -> String {
    match infer_os_version(profile).split('.').next().unwrap_or("") {
        "13" => "33",
        "12" => "31",
        "11" => "30",
        "10" => "29",
        "9" => "28",
        "8" => "26",
        "7" => "24",
        "6" => "23",
        _ => "",
    }
    .to_string()
}

fn compute_x_uid(profile: &DeviceProfile) -> String {
    let build_identity = format!(
        "1698{}{}{}{}{}{}{}{}{}{}{}{}",
        profile.hardware,
        profile.board,
        profile.brand,
        profile.device,
        profile.manufacturer,
        profile.model,
        profile.product,
        profile.tags,
        profile.build_type,
        profile.user,
        profile.resolution,
        profile.mac
    );
    let uuid_part = java_uuid_from_hashes(
        java_string_hashcode(&build_identity),
        java_string_hashcode(&profile.model),
    );
    sha1_upper(&format!("{}|{}", profile.android_id, uuid_part))
}

fn build_identity(profile: &DeviceProfile, app_channel: &str, version: &str) -> Identity {
    let x_uid = compute_x_uid(profile);
    let (x_fingerprint, ts, _day0) = compute_fingerprint(&x_uid, current_time_ms());
    let mut headers = HashMap::new();
    headers.insert("Accept".to_string(), "application/json".to_string());
    headers.insert(
        "Accept-Language".to_string(),
        DEFAULT_ACCEPT_LANGUAGE.to_string(),
    );
    headers.insert("Referer".to_string(), "api.cctv.cn".to_string());
    headers.insert("User-Agent".to_string(), "cctv_app_tv".to_string());
    headers.insert("UID".to_string(), profile.android_id.clone());
    headers.insert("appChannel".to_string(), app_channel.to_string());
    headers.insert("X-Uid".to_string(), x_uid.clone());
    headers.insert("X-Fingerprint".to_string(), x_fingerprint.clone());
    headers.insert("X-Version".to_string(), version.to_string());
    headers.insert(
        "Content-Type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    headers.insert("Connection".to_string(), "Keep-Alive".to_string());
    headers.insert("Accept-Encoding".to_string(), "gzip".to_string());
    headers.insert("Cache-Control".to_string(), "no-cache".to_string());
    Identity {
        x_uid,
        x_fingerprint,
        fingerprint_timestamp_ms: ts,
        headers,
    }
}

fn next_request_timestamp_ms() -> i64 {
    current_time_ms()
}

fn fresh_headers(
    template: &HashMap<String, String>,
    content_type: &str,
    accept: Option<&str>,
    force_ts: Option<i64>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(accept) = accept {
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_str(accept).unwrap(),
        );
    }
    headers.insert(
        "X-Timestamp",
        HeaderValue::from_str(
            &force_ts
                .unwrap_or_else(next_request_timestamp_ms)
                .to_string(),
        )
        .unwrap(),
    );
    headers.insert(
        "X-Nonce",
        HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
    );
    for key in [
        "Accept-Language",
        "Referer",
        "User-Agent",
        "UID",
        "appChannel",
        "X-Uid",
        "X-Fingerprint",
        "X-Version",
    ] {
        if let Some(value) = template.get(key) {
            headers.insert(
                HeaderName::from_bytes(key.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
    }
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap(),
    );
    for key in ["Connection", "Accept-Encoding", "Cache-Control"] {
        if let Some(value) = template.get(key) {
            headers.insert(
                HeaderName::from_bytes(key.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
    }
    headers
}

fn compact_json_bytes(value: &Value, escape_forward_slashes: bool) -> Vec<u8> {
    let mut text = serde_json::to_string(value).unwrap();
    if escape_forward_slashes {
        text = text.replace('/', "\\/");
    }
    text.into_bytes()
}

fn normalize_aes_key(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn aes_gcm_decrypt_b64(value: &str, key: &str) -> Result<String> {
    let raw = B64.decode(value)?;
    if raw.len() <= 12 {
        bail!("AES-GCM payload too short");
    }
    let k = normalize_aes_key(key);
    let cipher = Aes256Gcm::new_from_slice(&k).unwrap();
    let plain = cipher
        .decrypt(Nonce::from_slice(&raw[..12]), &raw[12..])
        .map_err(|_| anyhow!("AES-GCM decrypt failed"))?;
    Ok(String::from_utf8(plain)?)
}

fn aes_gcm_encrypt_b64(value: &str, key: &str) -> Result<String> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let k = normalize_aes_key(key);
    let cipher = Aes256Gcm::new_from_slice(&k).unwrap();
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), value.as_bytes())
        .map_err(|_| anyhow!("AES-GCM encrypt failed"))?;
    let mut out = nonce.to_vec();
    out.extend(encrypted);
    Ok(B64.encode(out))
}

fn rsa_encrypt_device_id(device_id: &str) -> Result<String> {
    let der = B64.decode(RSA_PUBLIC_KEY_B64)?;
    let public_key = RsaPublicKey::from_public_key_der(&der)?;
    let mut rng = rand::thread_rng();
    let mut encrypted = Vec::new();
    for chunk in device_id.as_bytes().chunks(190) {
        encrypted.extend(public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), chunk)?);
    }
    Ok(B64.encode(encrypted))
}

fn report_model_from_build(profile: &DeviceProfile) -> String {
    profile
        .model
        .replace(&profile.manufacturer, "")
        .replace(' ', "")
}

fn app_start_field<T: ToString>(value: T, limit: usize) -> String {
    value.to_string().chars().take(limit).collect()
}

fn build_report_common_value(
    profile: &DeviceProfile,
    x_uid: &str,
    app_channel: &str,
    version: &str,
    sdk_version: &str,
    data_time_ms: i64,
) -> Value {
    json!({
        "cctv_id": app_start_field(x_uid, 64),
        "device_id": app_start_field(&profile.android_id, 64),
        "idfa": "",
        "idfv": "",
        "user_id": "",
        "app_key": app_start_field(REPORT_APP_KEY, 64),
        "imei": "",
        "android_id": app_start_field(&profile.android_id, 64),
        "mac": app_start_field(&profile.mac, 64),
        "device_builder_type": app_start_field(&profile.build_type, 64),
        "device_hardware": app_start_field(&profile.hardware, 64),
        "device_board": app_start_field(&profile.board, 64),
        "device_brand": app_start_field(&profile.brand, 64),
        "device_params": app_start_field(&profile.device, 64),
        "device_display": app_start_field(&profile.display, 64),
        "device_version_id": app_start_field(&profile.version_id, 64),
        "device_host": app_start_field(&profile.host, 128),
        "device_product": app_start_field(&profile.product, 64),
        "device_tags": app_start_field(&profile.tags, 64),
        "device_user": app_start_field(&profile.user, 30),
        "device_fingerprint": app_start_field(&profile.fingerprint, 128),
        "device_manufacturer": app_start_field(&profile.manufacturer, 64),
        "device_model": app_start_field(if profile.report_model.is_empty() { report_model_from_build(profile) } else { profile.report_model.clone() }, 50),
        "device_resolution": app_start_field(&profile.resolution, 20),
        "system_type": "Android",
        "device_type": "TV",
        "app_language": "CHINESE",
        "app_version": app_start_field(version, 30),
        "sdk_version": app_start_field(sdk_version, 30),
        "os_version": app_start_field(infer_os_version(profile), 20),
        "app_channel": app_start_field(app_channel, 50),
        "data_time": app_start_field(data_time_ms, 13),
    })
}

fn build_app_start_body(
    profile: &DeviceProfile,
    x_uid: &str,
    app_channel: &str,
    version: &str,
    data_time_ms: i64,
) -> Value {
    json!({"key":"app_start_d1","value": build_report_common_value(profile, x_uid, app_channel, version, "", data_time_ms)})
}

fn build_collect_headers(profile: &DeviceProfile) -> HeaderMap {
    let mut h = HeaderMap::new();
    let release = infer_os_version(profile);
    h.insert(
        "Content-type",
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    h.insert("Charset", HeaderValue::from_static("UTF-8"));
    h.insert(
        reqwest::header::USER_AGENT,
        HeaderValue::from_str(&format!(
            "Dalvik/2.1.0 (Linux; U; Android {}; {} Build/{})",
            if release.is_empty() {
                "Android"
            } else {
                &release
            },
            profile.model,
            profile.version_id
        ))
        .unwrap(),
    );
    h.insert(
        reqwest::header::CONNECTION,
        HeaderValue::from_static("Keep-Alive"),
    );
    h.insert(
        reqwest::header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip"),
    );
    h
}

fn parse_result_code(value: &Value) -> Option<i64> {
    if let Some(obj) = value.as_object() {
        for key in ["result", "code", "errCode", "errcode", "ret"] {
            if let Some(raw) = obj.get(key) {
                if let Some(n) = raw.as_i64() {
                    return Some(n);
                }
                if let Some(s) = raw.as_str() {
                    if let Ok(n) = s.parse::<i64>() {
                        return Some(n);
                    }
                }
            }
        }
        for key in ["data", "error", "response"] {
            if let Some(found) = obj.get(key).and_then(parse_result_code) {
                return Some(found);
            }
        }
    }
    None
}

fn response_json(resp: reqwest::blocking::Response) -> Result<(u16, String, Value)> {
    let status = resp.status().as_u16();
    let body = resp.text()?;
    let json = serde_json::from_str::<Value>(&body).unwrap_or(Value::Null);
    Ok((status, body, json))
}

fn extract_guid(value: &Value) -> String {
    value
        .pointer("/data/guid")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn root_headers(version: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("X-Uid", HeaderValue::from_static("ROOT"));
    h.insert("X-Fingerprint", HeaderValue::from_static("ROOT"));
    h.insert(
        "X-Nonce",
        HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
    );
    h.insert(
        "X-Timestamp",
        HeaderValue::from_str(&next_request_timestamp_ms().to_string()).unwrap(),
    );
    h.insert("X-Version", HeaderValue::from_str(version).unwrap());
    h.insert("UID", HeaderValue::from_static("ROOT"));
    h.insert("Referer", HeaderValue::from_static("api.cctv.cn"));
    h.insert(
        reqwest::header::USER_AGENT,
        HeaderValue::from_static("cctv_app_tv"),
    );
    h.insert("appChannel", HeaderValue::from_static("ROOT"));
    h.insert(
        reqwest::header::CONNECTION,
        HeaderValue::from_static("Keep-Alive"),
    );
    h.insert(
        reqwest::header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip"),
    );
    h
}

fn build_vdn_appcommon(version: &str) -> String {
    serde_json::to_string(&json!({"adid":"","av":version,"an":VDN_APP_NAME,"ap":"cctv_app_tv"}))
        .unwrap()
}

fn url_host(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn live_playback_host_needs_signed_headers(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower.contains("liveali") || lower.contains("liveten")
}

fn default_cctv_playback_headers(uid: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("UID".to_string(), uid.to_string());
    headers.insert("APPID".to_string(), AK.to_string());
    headers.insert("Referer".to_string(), "api.cctv.cn".to_string());
    headers.insert("User-Agent".to_string(), "cctv_app_tv".to_string());
    headers
}

fn cctv_playback_headers_for_entry(entry: &ChannelEntry) -> HashMap<String, String> {
    let mut headers = default_cctv_playback_headers(&entry.android_id);
    for key in [
        "UID",
        "APPID",
        "APPRANDOMSTR",
        "Referer",
        "User-Agent",
        "APPSIGN",
    ] {
        if let Some(value) = entry.playback_headers.get(key).filter(|v| !v.is_empty()) {
            headers.insert(key.to_string(), value.clone());
        }
    }
    headers
}

fn entry_missing_signed_playback_headers(entry: &ChannelEntry) -> bool {
    let host = if entry.final_host.is_empty() {
        url_host(&entry.final_url)
    } else {
        entry.final_host.clone()
    };
    live_playback_host_needs_signed_headers(&host)
        && ["APPID", "APPSIGN", "APPRANDOMSTR"].iter().any(|key| {
            entry
                .playback_headers
                .get(*key)
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
        })
}

fn ts_path_matches_final_url(ts_path: &str, final_url: &str) -> bool {
    let Ok(parsed) = Url::parse(final_url) else {
        return false;
    };
    let prefix = parsed.path().strip_suffix(".m3u8").unwrap_or(parsed.path());
    !prefix.is_empty() && ts_path.starts_with(prefix)
}

fn generate_app_random_str() -> String {
    let mut rng = rand::thread_rng();
    format!(
        "{:08x}-0000-{:04x}-0000-00000000{:04x}",
        rng.next_u32(),
        (rng.next_u32() & 0xffff),
        (rng.next_u32() & 0xffff)
    )
}

fn compute_vdn_code(app_secret: &str, random_str: Option<String>) -> (String, String) {
    let r = random_str.unwrap_or_else(generate_app_random_str);
    (md5_hex(&format!("{AK}{app_secret}{r}")), r)
}

impl Resolver {
    fn new(args: Args) -> Result<Self> {
        let generic_client = ClientBuilder::new()
            .timeout(Duration::from_secs_f64(args.timeout))
            .cookie_provider(Arc::new(reqwest::cookie::Jar::default()))
            .danger_accept_invalid_certs(args.insecure_tls)
            .build()?;
        let state = ResolverState {
            cache: load_cache(&args.meta_json),
            playlist_cache: HashMap::new(),
            background_refreshing: HashMap::new(),
            generation: 0,
            session_generation: 0,
            app_session: None,
            last_control_request_at: 0.0,
            last_business_end_at: 0.0,
            refreshing_channel: String::new(),
            last_error: String::new(),
            last_error_at: 0.0,
            identity_reset_error_count: 0,
            identity_reset_count: 0,
            last_identity_reset_at: 0.0,
            last_identity_reset_reason: String::new(),
            ad_display: false,
        };
        let refresh_queue = RefreshQueue {
            state: Mutex::new(RefreshQueueState {
                queued: VecDeque::new(),
                queued_channels: HashMap::new(),
                running_channel: String::new(),
                running_started_at: 0.0,
                enqueued_total: 0,
                dropped_total: 0,
                completed_total: 0,
                failed_total: 0,
                last_enqueued_at: 0.0,
                last_finished_at: 0.0,
                last_dropped_at: 0.0,
                last_drop_reason: String::new(),
            }),
            condvar: Condvar::new(),
        };
        let http_queue = HttpQueue {
            state: Mutex::new(HttpQueueState {
                queued: VecDeque::new(),
                active_workers: 0,
                enqueued_total: 0,
                rejected_total: 0,
                completed_total: 0,
                panicked_total: 0,
                last_enqueued_at: 0.0,
                last_completed_at: 0.0,
                last_rejected_at: 0.0,
            }),
            condvar: Condvar::new(),
        };
        Ok(Self {
            args,
            generic_client,
            state: Arc::new(Mutex::new(state)),
            control_lock: Arc::new(Mutex::new(())),
            playlist_locks: Arc::new(Mutex::new(HashMap::new())),
            refresh_queue: Arc::new(refresh_queue),
            http_queue: Arc::new(http_queue),
        })
    }

    fn start_heartbeat(self: &Arc<Self>) {
        let resolver = Arc::clone(self);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs_f64(resolver.args.heartbeat_interval));
            let _ = resolver.send_heartbeat();
        });
    }

    fn start_refresh_worker(self: &Arc<Self>) {
        let resolver = Arc::clone(self);
        thread::spawn(move || {
            resolver.refresh_worker_loop();
        });
    }

    fn start_http_workers(self: &Arc<Self>) {
        let worker_count = self.args.http_workers.max(1);
        for worker_id in 0..worker_count {
            let resolver = Arc::clone(self);
            thread::spawn(move || {
                resolver.http_worker_loop(worker_id);
            });
        }
    }

    fn enqueue_http_request(&self, request: tiny_http::Request) {
        let now = now_f64();
        let mut queue = self.http_queue.state.lock();
        let limit = self.args.http_queue_limit;
        if limit == 0 || queue.queued.len() >= limit {
            queue.rejected_total += 1;
            queue.last_rejected_at = now;
            drop(queue);
            respond_text(
                request,
                503,
                "server busy\n".to_string(),
                "text/plain; charset=utf-8",
                vec![Header::from_bytes(&b"Retry-After"[..], &b"1"[..]).unwrap()],
            );
            return;
        }
        queue.queued.push_back(request);
        queue.enqueued_total += 1;
        queue.last_enqueued_at = now;
        drop(queue);
        self.http_queue.condvar.notify_one();
    }

    fn http_worker_loop(self: Arc<Self>, _worker_id: usize) {
        loop {
            let request = {
                let mut queue = self.http_queue.state.lock();
                loop {
                    if let Some(request) = queue.queued.pop_front() {
                        queue.active_workers += 1;
                        break request;
                    }
                    self.http_queue.condvar.wait(&mut queue);
                }
            };
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                handle_request(Arc::clone(&self), request);
            }));
            let mut queue = self.http_queue.state.lock();
            queue.active_workers = queue.active_workers.saturating_sub(1);
            queue.last_completed_at = now_f64();
            if result.is_ok() {
                queue.completed_total += 1;
            } else {
                queue.panicked_total += 1;
            }
        }
    }

    fn enqueue_background_refresh(&self, channel: &str) -> RefreshEnqueueResult {
        let now = now_f64();
        let mut queue = self.refresh_queue.state.lock();
        if queue.running_channel == channel || queue.queued_channels.contains_key(channel) {
            return RefreshEnqueueResult::AlreadyActive;
        }
        let limit = self.args.background_refresh_queue_limit;
        if limit == 0 || queue.queued.len() >= limit {
            queue.dropped_total += 1;
            queue.last_dropped_at = now;
            queue.last_drop_reason = if limit == 0 {
                format!("background refresh queue disabled; channel={channel}")
            } else {
                format!(
                    "background refresh queue full ({}/{}); channel={channel}",
                    queue.queued.len(),
                    limit
                )
            };
            return RefreshEnqueueResult::Rejected(queue.last_drop_reason.clone());
        }
        queue.queued.push_back(channel.to_string());
        queue.queued_channels.insert(channel.to_string(), now);
        queue.enqueued_total += 1;
        queue.last_enqueued_at = now;
        drop(queue);
        self.refresh_queue.condvar.notify_one();
        RefreshEnqueueResult::Enqueued
    }

    fn refresh_worker_loop(&self) {
        loop {
            let channel = {
                let mut queue = self.refresh_queue.state.lock();
                loop {
                    if let Some(channel) = queue.queued.pop_front() {
                        queue.queued_channels.remove(&channel);
                        queue.running_channel = channel.clone();
                        queue.running_started_at = now_f64();
                        break channel;
                    }
                    self.refresh_queue.condvar.wait(&mut queue);
                }
            };

            let ok = self.refresh_channel_background(channel.clone());
            let mut queue = self.refresh_queue.state.lock();
            queue.running_channel.clear();
            queue.running_started_at = 0.0;
            queue.last_finished_at = now_f64();
            if ok {
                queue.completed_total += 1;
            } else {
                queue.failed_total += 1;
            }
        }
    }

    fn record_recoverable_error(&self, reason: &str) -> bool {
        if !is_identity_recoverable_error(reason) {
            return false;
        }
        let threshold = self.args.identity_reset_error_threshold;
        if threshold == 0 {
            return false;
        }
        let should_reset = {
            let mut state = self.state.lock();
            if state.last_identity_reset_at > 0.0
                && now_f64() - state.last_identity_reset_at < self.args.identity_reset_cooldown
            {
                return false;
            }
            state.identity_reset_error_count = state.identity_reset_error_count.saturating_add(1);
            state.identity_reset_error_count >= threshold
        };
        if should_reset {
            self.reset_identity_and_cache(reason);
            true
        } else {
            let _ = self.write_meta();
            false
        }
    }

    fn clear_recoverable_error_count(&self) {
        let mut state = self.state.lock();
        state.identity_reset_error_count = 0;
    }

    fn reset_identity_and_cache(&self, reason: &str) {
        let device_remove_result = fs::remove_file(&self.args.device_json);
        let meta_remove_result = fs::remove_file(&self.args.meta_json);
        let mut state = self.state.lock();
        state.cache.clear();
        state.playlist_cache.clear();
        state.background_refreshing.clear();
        state.app_session = None;
        state.refreshing_channel.clear();
        state.identity_reset_error_count = 0;
        state.identity_reset_count += 1;
        state.last_identity_reset_at = now_f64();
        state.last_identity_reset_reason = reason.to_string();
        state.last_error = format!("identity reset after recoverable errors: {reason}");
        state.last_error_at = now_f64();
        drop(state);
        self.refresh_queue.condvar.notify_one();
        let _ = device_remove_result;
        let _ = meta_remove_result;
    }

    fn ensure_channel(&self, channel: &str) -> Result<ChannelEntry> {
        let now = now_f64();
        {
            let mut state = self.state.lock();
            if let Some(entry) = state.cache.get(channel) {
                if entry.fresh(now) && !entry_missing_signed_playback_headers(entry) {
                    return Ok(entry.clone());
                }
                if entry.stale_usable(now, self.args.stale_while_refresh_ttl)
                    && !entry_missing_signed_playback_headers(entry)
                {
                    let retry_at = entry.last_refresh_failed_at + self.args.refresh_error_cooldown;
                    let should_refresh = now >= retry_at
                        && state
                            .background_refreshing
                            .get(channel)
                            .map(|started| now - *started > 300.0)
                            .unwrap_or(true);
                    let clone = entry.clone();
                    if should_refresh {
                        state.background_refreshing.insert(channel.to_string(), now);
                        match self.enqueue_background_refresh(channel) {
                            RefreshEnqueueResult::Enqueued => {}
                            RefreshEnqueueResult::AlreadyActive => {}
                            RefreshEnqueueResult::Rejected(reason) => {
                                state.background_refreshing.remove(channel);
                                if let Some(entry) = state.cache.get_mut(channel) {
                                    entry.last_refresh_error = reason.clone();
                                    entry.last_refresh_failed_at = now;
                                }
                            }
                        }
                    }
                    return Ok(clone);
                }
            }
        }

        let _control = self.control_lock.lock();
        let now = now_f64();
        {
            let state = self.state.lock();
            if let Some(entry) = state.cache.get(channel) {
                if entry.fresh(now) && !entry_missing_signed_playback_headers(entry) {
                    return Ok(entry.clone());
                }
            }
        }

        match self.refresh_channel_controlled(channel) {
            Ok(entry) => {
                self.clear_recoverable_error_count();
                let _ = self.write_meta();
                Ok(entry)
            }
            Err(err) => {
                let mut state = self.state.lock();
                state.last_error = format!("{err:#}");
                state.last_error_at = now_f64();
                let last_error = state.last_error.clone();
                let last_error_at = state.last_error_at;
                let err_text = format!("{err:#}");
                if let Some(entry) = state.cache.get_mut(channel) {
                    if !entry.final_url.is_empty() {
                        entry.last_refresh_error = last_error;
                        entry.last_refresh_failed_at = last_error_at;
                        let clone = entry.clone();
                        drop(state);
                        let did_reset = self.record_recoverable_error(&err_text);
                        if !did_reset {
                            let _ = self.write_meta();
                        }
                        if did_reset {
                            return Err(err);
                        }
                        return Ok(clone);
                    }
                }
                drop(state);
                let did_reset = self.record_recoverable_error(&err_text);
                if !did_reset {
                    let _ = self.write_meta();
                }
                Err(err)
            }
        }
    }

    fn refresh_channel_background(&self, channel: String) -> bool {
        let result = (|| -> Result<()> {
            let _control = self.control_lock.lock();
            let now = now_f64();
            {
                let state = self.state.lock();
                if let Some(entry) = state.cache.get(&channel) {
                    if entry.fresh(now) && !entry_missing_signed_playback_headers(entry) {
                        return Ok(());
                    }
                }
            }
            self.refresh_channel_controlled(&channel)?;
            let _ = self.write_meta();
            Ok(())
        })();
        let ok = result.is_ok();
        if let Err(err) = result {
            let mut state = self.state.lock();
            state.last_error = format!("{err:#}");
            state.last_error_at = now_f64();
            let last_error = state.last_error.clone();
            let last_error_at = state.last_error_at;
            if let Some(entry) = state.cache.get_mut(&channel) {
                entry.last_refresh_error = last_error;
                entry.last_refresh_failed_at = last_error_at;
            }
            if is_session_invalidating_error(&format!("{err:#}")) {
                state.app_session = None;
            }
            drop(state);
            let did_reset = self.record_recoverable_error(&format!("{err:#}"));
            if !did_reset {
                let _ = self.write_meta();
            }
        }
        let mut state = self.state.lock();
        state.background_refreshing.remove(&channel);
        ok
    }

    fn refresh_channel_controlled(&self, channel: &str) -> Result<ChannelEntry> {
        let wait = {
            let state = self.state.lock();
            self.args.refresh_interval - (now_f64() - state.last_business_end_at)
        };
        if wait > 0.0 {
            thread::sleep(Duration::from_secs_f64(wait));
        }
        let generation = {
            let mut state = self.state.lock();
            state.refreshing_channel = channel.to_string();
            state.generation += 1;
            state.generation
        };
        log_program_fetching();
        let result = (|| {
            let app_session = self.get_app_session_controlled()?;
            let live_id =
                channel_by_name(channel).ok_or_else(|| anyhow!("unknown channel {channel}"))?;
            self.resolve_channel_once(&app_session, channel, live_id, generation)
        })();
        let mut state = self.state.lock();
        state.last_business_end_at = now_f64();
        state.refreshing_channel.clear();
        match result {
            Ok(entry) => {
                state.cache.insert(channel.to_string(), entry.clone());
                state.playlist_cache.remove(channel);
                state.identity_reset_error_count = 0;
                state.last_error.clear();
                log_channel_ready(channel);
                Ok(entry)
            }
            Err(err) => {
                if is_session_invalidating_error(&format!("{err:#}")) {
                    state.app_session = None;
                }
                Err(err)
            }
        }
    }

    fn get_app_session_controlled(&self) -> Result<AppSessionState> {
        {
            let mut state = self.state.lock();
            if let Some(sess) = &state.app_session {
                if self.app_session_fresh(sess) {
                    return Ok(sess.clone());
                }
                state.app_session = None;
            }
        }
        let gen = {
            let mut state = self.state.lock();
            state.session_generation += 1;
            state.session_generation
        };
        let sess = self.bootstrap_session(gen)?;
        let mut state = self.state.lock();
        state.app_session = Some(sess.clone());
        Ok(sess)
    }

    fn app_session_fresh(&self, sess: &AppSessionState) -> bool {
        self.args.session_ttl <= 0.0 || (now_f64() - sess.created_at) < self.args.session_ttl
    }

    fn app_session_ttl_remaining(&self, sess: &AppSessionState) -> Option<f64> {
        if self.args.session_ttl <= 0.0 {
            None
        } else {
            Some(self.args.session_ttl - (now_f64() - sess.created_at))
        }
    }

    fn control_step_jitter_duration(&self) -> Option<Duration> {
        let min = self.args.control_step_jitter_min_ms;
        let max = self.args.control_step_jitter_max_ms;
        if max == 0 {
            return None;
        }
        let upper = max.max(min);
        let span = upper - min;
        let extra = if span == 0 {
            0
        } else {
            (rand::thread_rng().next_u64() % (span + 1)) as u64
        };
        Some(Duration::from_millis(min + extra))
    }

    fn control_request_slot(&self, _label: &str) -> ControlRequestSlot {
        let min_interval = self.args.refresh_interval.max(0.0);
        loop {
            let wait = {
                let state = self.state.lock();
                if state.last_control_request_at <= 0.0 {
                    0.0
                } else {
                    min_interval - (now_f64() - state.last_control_request_at)
                }
            };
            if wait <= 0.0 {
                break;
            }
            thread::sleep(Duration::from_secs_f64(wait));
        }
        if let Some(duration) = self.control_step_jitter_duration() {
            thread::sleep(duration);
        }
        ControlRequestSlot {
            state: Arc::clone(&self.state),
        }
    }

    fn new_ytpaddr_client(&self) -> Result<Client> {
        Ok(ClientBuilder::new()
            .timeout(Duration::from_secs_f64(self.args.timeout))
            .cookie_store(true)
            .danger_accept_invalid_certs(self.args.insecure_tls)
            .build()?)
    }

    fn bootstrap_session(&self, generation: u64) -> Result<AppSessionState> {
        let mut loaded_device_state = load_device_state(&self.args.device_json);
        if !loaded_device_state.existed {
            loaded_device_state.state.updated_at = now_f64();
            let _ = save_device_state(&self.args.device_json, &loaded_device_state.state);
        }
        let mut device_state = loaded_device_state.state;
        let profile = device_state.profile.clone();
        let app_channel = "dangbei";
        let version = "1.4.1";
        let mut identity = build_identity(&profile, app_channel, version);
        device_state.x_uid = identity.x_uid.clone();
        let client = self.new_ytpaddr_client()?;
        let page_session_id = Uuid::new_v4().to_string();

        {
            let _slot = self.control_request_slot("collect_report_start");
            self.collect_report(&profile, &json!({
                "key":"app_start_d1",
                "value": build_report_common_value(&profile, &identity.x_uid, app_channel, version, COLLECT_SDK_VERSION, current_time_ms())
            }))?;
        }
        self.dictionary_obtain(version)?;
        let app_start =
            self.app_start_flow(&client, &profile, &mut identity, app_channel, version)?;
        let session_key = app_start.session_key;

        // Python sends this just after the app/start payload is written. Rust's reqwest API is response-oriented;
        // sending it immediately after the successful app/start keeps the same fields without adding another app/start.
        let _ = self.app_event_flow(&profile, &identity, app_channel, version);

        let (page_start_time_ms, page_end_time_ms) = {
            let _slot = self.control_request_slot("collect_report_page");
            let page_end_time_ms = current_time_ms();
            let page_start_time_ms = page_end_time_ms - 1000;
            let mut page_value = build_report_common_value(
                &profile,
                &identity.x_uid,
                app_channel,
                version,
                "",
                page_end_time_ms + 2,
            );
            if let Some(obj) = page_value.as_object_mut() {
                obj.insert(
                    "start_time".to_string(),
                    json!(page_start_time_ms.to_string()),
                );
                obj.insert("end_time".to_string(), json!(page_end_time_ms.to_string()));
                obj.insert(
                    "duration".to_string(),
                    json!((page_end_time_ms - page_start_time_ms).to_string()),
                );
                obj.insert("page_name".to_string(), json!(DEFAULT_PAGE_NAME));
                obj.insert("session_id".to_string(), json!(page_session_id));
                obj.insert("network_type".to_string(), json!("WIFI"));
            }
            let _ = self.collect_report(&profile, &json!({"key":"page_d1","value": page_value}));
            (page_start_time_ms, page_end_time_ms)
        };
        let _ = self.page_event_flow(
            &profile,
            &identity,
            app_channel,
            version,
            &page_session_id,
            page_start_time_ms,
            page_end_time_ms,
        );

        let cloud_guid = self
            .cloud_registration_flow(&identity, &identity.x_uid)
            .unwrap_or_default();
        let now = now_f64();
        device_state.x_uid = identity.x_uid.clone();
        device_state.updated_at = now;
        if !cloud_guid.is_empty() {
            device_state.cloud_guid = cloud_guid.clone();
            if device_state.registered_at <= 0.0 {
                device_state.registered_at = now;
            }
        }
        let _ = save_device_state(&self.args.device_json, &device_state);
        if !cloud_guid.is_empty() {
            let _ = self.device_info_report_flow(
                &profile,
                &identity,
                app_channel,
                version,
                &cloud_guid,
            );
        }
        let hb = self.heartbeat_flow(&profile, &identity, app_channel, version, &cloud_guid)?;
        self.index_flow(&client, &identity, app_channel)?;
        self.warmup_flow(&client, &identity, version)?;

        Ok(AppSessionState {
            profile,
            identity,
            client,
            session_key,
            cloud_guid,
            version: version.to_string(),
            screen_param: device_state.screen_param,
            cast_model: device_state.cast_model,
            created_at: now_f64(),
            generation,
            last_heartbeat_at: now_f64(),
            heartbeat_count: 1,
            last_heartbeat_result: hb,
            last_heartbeat_error: String::new(),
        })
    }

    fn collect_report(&self, profile: &DeviceProfile, body: &Value) -> Result<()> {
        let headers = build_collect_headers(profile);
        let info = serde_json::to_string(body)?;
        let resp = self
            .generic_client
            .post(COLLECT_REPORT_URL)
            .headers(headers)
            .form(&[("info", info)])
            .send()?;
        if !resp.status().is_success() {
            bail!("collect report HTTP {}", resp.status());
        }
        Ok(())
    }

    fn dictionary_obtain(&self, version: &str) -> Result<()> {
        let _slot = self.control_request_slot("dictionary_obtain");
        let resp = self
            .generic_client
            .post(DICTIONARY_URL)
            .headers(root_headers(version))
            .body(Vec::new())
            .send()?;
        if !resp.status().is_success() {
            bail!("dictionary HTTP {}", resp.status());
        }
        Ok(())
    }

    fn app_start_flow(
        &self,
        client: &Client,
        profile: &DeviceProfile,
        identity: &mut Identity,
        app_channel: &str,
        version: &str,
    ) -> Result<AppStartResult> {
        let mut last = String::new();
        for attempt in 1..=4 {
            if attempt > 1 {
                thread::sleep(Duration::from_secs((attempt - 1) as u64));
            }
            let _slot = self.control_request_slot("app_start");
            let token_time = current_time_ms();
            let (xfp, ts, _day0) = compute_fingerprint(&identity.x_uid, token_time);
            identity.x_fingerprint = xfp.clone();
            identity.fingerprint_timestamp_ms = ts;
            identity
                .headers
                .insert("X-Fingerprint".to_string(), xfp.clone());
            let body = build_app_start_body(
                profile,
                &identity.x_uid,
                app_channel,
                version,
                current_time_ms(),
            );
            let payload = compact_json_bytes(&body, true);
            let mut headers = fresh_headers(
                &identity.headers,
                "application/json",
                Some("application/json"),
                Some(ts),
            );
            headers.insert("UID", HeaderValue::from_static(""));
            let resp = client
                .post(APP_START_URL)
                .headers(headers)
                .body(payload)
                .send()?;
            let (status, text, value) = response_json(resp)?;
            if (200..300).contains(&status) {
                let encrypted = value
                    .get("data")
                    .and_then(|d| d.get("key").or(Some(d)))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !encrypted.is_empty() {
                    let session_key = aes_gcm_decrypt_b64(encrypted, &xfp[..32])?;
                    return Ok(AppStartResult { session_key });
                }
            }
            last = format!(
                "app/start HTTP {status}: {}",
                &text.chars().take(300).collect::<String>()
            );
        }
        bail!(last)
    }

    fn app_event_flow(
        &self,
        profile: &DeviceProfile,
        identity: &Identity,
        app_channel: &str,
        version: &str,
    ) -> Result<()> {
        let _slot = self.control_request_slot("app_event");
        let event_time = current_time_ms();
        let mut value = build_report_common_value(
            profile,
            &identity.x_uid,
            app_channel,
            version,
            "",
            event_time,
        );
        let obj = value.as_object_mut().unwrap();
        obj.insert("event_id".to_string(), json!("app_start"));
        obj.insert("event_name".to_string(), json!("应用启动"));
        obj.insert("event_time".to_string(), json!(event_time.to_string()));
        obj.insert("network_type".to_string(), json!("WIFI"));
        obj.insert("cur_version".to_string(), json!(version));
        obj.insert("channel".to_string(), json!(app_channel));
        obj.insert("pre_version".to_string(), json!(version));
        let body = json!({"key":"event","value":value});
        let mut headers = fresh_headers(
            &identity.headers,
            "application/json",
            Some("application/json"),
            None,
        );
        headers.insert("UID", HeaderValue::from_static(""));
        let resp = self
            .generic_client
            .post(REPORT_SINGLE_URL)
            .headers(headers)
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            bail!("app event HTTP {}", resp.status());
        }
        Ok(())
    }

    fn page_event_flow(
        &self,
        profile: &DeviceProfile,
        identity: &Identity,
        app_channel: &str,
        version: &str,
        session_id: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<()> {
        let _slot = self.control_request_slot("page_event");
        let mut value = build_report_common_value(
            profile,
            &identity.x_uid,
            app_channel,
            version,
            "",
            end_ms + 2,
        );
        let obj = value.as_object_mut().unwrap();
        obj.insert("start_time".to_string(), json!(start_ms.to_string()));
        obj.insert("end_time".to_string(), json!(end_ms.to_string()));
        obj.insert(
            "duration".to_string(),
            json!((end_ms - start_ms).max(0).to_string()),
        );
        obj.insert("page_name".to_string(), json!(DEFAULT_PAGE_NAME));
        obj.insert("session_id".to_string(), json!(session_id));
        obj.insert("network_type".to_string(), json!("WIFI"));
        let body = json!({"key":"page_d1","value":value});
        let resp = self
            .generic_client
            .post(REPORT_SINGLE_URL)
            .headers(fresh_headers(
                &identity.headers,
                "application/json",
                Some("application/json"),
                None,
            ))
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            bail!("page event HTTP {}", resp.status());
        }
        Ok(())
    }

    fn cloud_registration_flow(
        &self,
        identity: &Identity,
        cloud_device_id: &str,
    ) -> Result<String> {
        let body = json!({"device_name": DEFAULT_DEVICE_NAME, "device_id": rsa_encrypt_device_id(cloud_device_id)?});
        let _slot = self.control_request_slot("cloud_get");
        let resp = self
            .generic_client
            .post(CLOUD_GET_URL)
            .headers(fresh_headers(
                &identity.headers,
                "application/json",
                Some("application/json"),
                None,
            ))
            .json(&body)
            .send()?;
        let (_status, _text, value) = response_json(resp)?;
        let result = parse_result_code(&value);
        if result == Some(RESULT_OK) {
            return Ok(extract_guid(&value));
        }
        if result != Some(RESULT_NEEDS_REGISTER) && result != Some(RESULT_GET_MISSING_OR_INVALID) {
            return Ok(String::new());
        }
        let mut last_result = None;
        let mut guid = String::new();
        for _ in 0..2 {
            let _slot = self.control_request_slot("cloud_register");
            let resp = self
                .generic_client
                .post(CLOUD_REGISTER_URL)
                .headers(fresh_headers(
                    &identity.headers,
                    "application/json",
                    Some("application/json"),
                    None,
                ))
                .json(&body)
                .send()?;
            let (_status, _text, value) = response_json(resp)?;
            last_result = parse_result_code(&value);
            guid = extract_guid(&value);
            if !guid.is_empty() || last_result != Some(RESULT_REGISTER_RETRY_LATER) {
                break;
            }
        }
        if !guid.is_empty() {
            return Ok(guid);
        }
        if matches!(
            last_result,
            Some(RESULT_OK | RESULT_REGISTERED_ELSEWHERE | RESULT_GET_MISSING_OR_INVALID)
        ) {
            let _slot = self.control_request_slot("cloud_get_after_register");
            let resp = self
                .generic_client
                .post(CLOUD_GET_URL)
                .headers(fresh_headers(
                    &identity.headers,
                    "application/json",
                    Some("application/json"),
                    None,
                ))
                .json(&body)
                .send()?;
            let (_status, _text, value) = response_json(resp)?;
            return Ok(extract_guid(&value));
        }
        Ok(String::new())
    }

    fn device_info_report_flow(
        &self,
        profile: &DeviceProfile,
        identity: &Identity,
        app_channel: &str,
        version: &str,
        cloud_guid: &str,
    ) -> Result<()> {
        let _slot = self.control_request_slot("device_info_report");
        let mut value = build_report_common_value(
            profile,
            &identity.x_uid,
            app_channel,
            version,
            "",
            current_time_ms(),
        );
        let sdk_int = infer_sdk_int(profile);
        let mut system_info = infer_os_version(profile);
        if !sdk_int.is_empty() {
            system_info = if system_info.is_empty() {
                sdk_int
            } else {
                format!("{system_info}/{sdk_int}")
            };
        }
        let obj = value.as_object_mut().unwrap();
        obj.insert("version".to_string(), json!(version));
        obj.insert("network_status".to_string(), json!("WiFi"));
        obj.insert(
            "device_info".to_string(),
            json!(format!("{}-{}", profile.brand, profile.model)),
        );
        obj.insert(
            "manufacturer".to_string(),
            json!(profile.manufacturer.clone()),
        );
        obj.insert("cpu_info".to_string(), json!(""));
        obj.insert("chip_info".to_string(), json!(profile.hardware.clone()));
        obj.insert("ram_info".to_string(), json!(""));
        obj.insert("memory_info".to_string(), json!(""));
        obj.insert("system_info".to_string(), json!(system_info));
        obj.insert("guid".to_string(), json!(cloud_guid));
        let body = json!({"key":"app_device_info","value":value});
        let resp = self
            .generic_client
            .post(REPORT_SINGLE_URL)
            .headers(fresh_headers(
                &identity.headers,
                "application/json",
                Some("application/json"),
                None,
            ))
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            bail!("device info HTTP {}", resp.status());
        }
        Ok(())
    }

    fn heartbeat_flow(
        &self,
        profile: &DeviceProfile,
        identity: &Identity,
        app_channel: &str,
        version: &str,
        cloud_guid: &str,
    ) -> Result<String> {
        let _slot = self.control_request_slot("heartbeat");
        let mut value = build_report_common_value(
            profile,
            &identity.x_uid,
            app_channel,
            version,
            "",
            current_time_ms(),
        );
        let obj = value.as_object_mut().unwrap();
        obj.insert("network_type".to_string(), json!("WiFi"));
        obj.insert("guid".to_string(), json!(cloud_guid));
        obj.insert("other".to_string(), json!(""));
        let body = json!({"key":"app_heartbeat","value":value});
        let resp = self
            .generic_client
            .post(REPORT_SINGLE_URL)
            .headers(fresh_headers(
                &identity.headers,
                "application/json",
                Some("application/json"),
                None,
            ))
            .json(&body)
            .send()?;
        let (status, _text, value) = response_json(resp)?;
        if !(200..300).contains(&status) {
            bail!("heartbeat HTTP {status}");
        }
        Ok(parse_result_code(&value)
            .map(|v| v.to_string())
            .unwrap_or_default())
    }

    fn index_flow(&self, client: &Client, identity: &Identity, app_channel: &str) -> Result<()> {
        let body = json!({"channel": app_channel, "source": "application"});
        let _slot = self.control_request_slot("index");
        let resp = client
            .post(INDEX_URL)
            .headers(fresh_headers(
                &identity.headers,
                "application/json",
                Some("application/json"),
                None,
            ))
            .json(&body)
            .send()?;
        if !resp.status().is_success() {
            bail!("index HTTP {}", resp.status());
        }
        Ok(())
    }

    fn warmup_flow(&self, client: &Client, identity: &Identity, version: &str) -> Result<()> {
        let appcommon = build_vdn_appcommon(version);
        let _slot = self.control_request_slot("drm_config");
        let resp = client
            .post(DRM_CONFIG_URL)
            .headers(fresh_headers(
                &identity.headers,
                "application/x-www-form-urlencoded",
                None,
                None,
            ))
            .form(&[("appcommon", appcommon.clone())])
            .send()?;
        if !resp.status().is_success() {
            bail!("drm config HTTP {}", resp.status());
        }
        let url = format!(
            "{}?{}",
            VERSION_CONFIG_URL,
            serde_urlencoded::to_string(&[("appcommon", appcommon)])?
        );
        let _slot = self.control_request_slot("version_config");
        let mut headers = fresh_headers(&identity.headers, "", None, None);
        headers.remove(reqwest::header::CONTENT_TYPE);
        let resp = client.get(url).headers(headers).send()?;
        if !resp.status().is_success() {
            bail!("version config HTTP {}", resp.status());
        }
        Ok(())
    }

    fn resolve_channel_once(
        &self,
        sess: &AppSessionState,
        channel: &str,
        live_id: &str,
        generation: u64,
    ) -> Result<ChannelEntry> {
        let live01 = self.live_v1_01_flow(sess, live_id)?;
        let app_secret = self.live_v1_02_flow(sess)?;
        let vdn =
            self.vdn_getstream_flow(&sess.identity, &sess.version, &live01.live_url, &app_secret)?;
        let now = now_f64();
        let mut playback_headers = default_cctv_playback_headers(&sess.profile.android_id);
        playback_headers.insert("APPRANDOMSTR".to_string(), vdn.app_random_str.clone());
        playback_headers.insert("APPSIGN".to_string(), vdn.app_sign.clone());
        Ok(ChannelEntry {
            channel: channel.to_string(),
            live_id: live_id.to_string(),
            final_url: vdn.final_url.clone(),
            playback_headers,
            android_id: sess.profile.android_id.clone(),
            x_uid: sess.identity.x_uid.clone(),
            rate: live01.rate,
            rate_name: live01.rate_name,
            raw_live_host: url_host(&live01.live_url),
            final_host: url_host(&vdn.final_url),
            refreshed_at: now,
            expires_at: now + self.args.cache_ttl,
            generation,
            last_refresh_error: String::new(),
            last_refresh_failed_at: 0.0,
            session_generation: sess.generation,
        })
    }

    fn live_v1_01_flow(&self, sess: &AppSessionState, live_id: &str) -> Result<Live01Result> {
        let body = json!({
            "screenParam": sess.screen_param,
            "rate": "",
            "systemType": "ios",
            "model": sess.cast_model,
            "id": live_id,
            "userId": DEFAULT_LIVE_USER_ID,
            "clientSign": "cctvVideo",
            "deviceId": {"serial":"","imei":"","android_id":""}
        });
        let _slot = self.control_request_slot("live_v1_01");
        let resp = sess
            .client
            .post(LIVE_V1_01_URL)
            .headers(fresh_headers(
                &sess.identity.headers,
                "application/json",
                Some("application/json"),
                None,
            ))
            .json(&body)
            .send()?;
        let (status, text, value) = response_json(resp)?;
        if !(200..300).contains(&status) {
            bail!(
                "live/v1/01 HTTP {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }
        let videos = value
            .pointer("/data/videoList")
            .or_else(|| value.pointer("/data/videos"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("live/v1/01 missing videos"))?;
        let mut selected: Option<&Value> = None;
        let mut fallback: Option<&Value> = None;
        for item in videos {
            if item
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
            {
                continue;
            }
            if fallback.is_none() {
                fallback = Some(item);
            }
            if item.get("rate").and_then(Value::as_str) == Some("36p") {
                selected = Some(item);
                break;
            }
        }
        let video = selected
            .or(fallback)
            .ok_or_else(|| anyhow!("live/v1/01 no usable URL"))?;
        let raw_url = video.get("url").and_then(Value::as_str).unwrap_or("");
        let live_url = if raw_url.starts_with("http://") || raw_url.starts_with("https://") {
            raw_url.to_string()
        } else {
            aes_gcm_decrypt_b64(raw_url, &sess.session_key)?
        };
        Ok(Live01Result {
            live_url,
            rate: video
                .get("rate")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            rate_name: video
                .get("rateName")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }

    fn live_v1_02_flow(&self, sess: &AppSessionState) -> Result<String> {
        let _slot = self.control_request_slot("live_v1_02");
        let encrypted_guid = aes_gcm_encrypt_b64("", &sess.session_key)?;
        let body = json!({"guid": encrypted_guid});
        let resp = sess
            .client
            .post(LIVE_V1_02_URL)
            .headers(fresh_headers(
                &sess.identity.headers,
                "application/json",
                Some("application/json"),
                None,
            ))
            .json(&body)
            .send()?;
        let (status, text, value) = response_json(resp)?;
        if !(200..300).contains(&status) {
            bail!(
                "live/v1/02 HTTP {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }
        let encrypted = value
            .pointer("/data/appSecret")
            .or_else(|| value.pointer("/data/app_secret"))
            .or_else(|| value.get("data"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("live/v1/02 missing appSecret"))?;
        aes_gcm_decrypt_b64(encrypted, &sess.session_key)
    }

    fn vdn_getstream_flow(
        &self,
        identity: &Identity,
        version: &str,
        live_url: &str,
        app_secret: &str,
    ) -> Result<VdnGetStreamResult> {
        let _slot = self.control_request_slot("vdn_getstream");
        let (app_sign, random_str) = compute_vdn_code(app_secret, None);
        let mut headers = fresh_headers(
            &identity.headers,
            "application/x-www-form-urlencoded",
            None,
            None,
        );
        headers.insert("APPID", HeaderValue::from_static(AK));
        headers.insert("APPSIGN", HeaderValue::from_str(&app_sign).unwrap());
        headers.insert("APPRANDOMSTR", HeaderValue::from_str(&random_str).unwrap());
        let appcommon = build_vdn_appcommon(version);
        let resp = self
            .generic_client
            .post(VDN_GETSTREAM_URL)
            .headers(headers)
            .form(&[("appcommon", appcommon), ("url", live_url.to_string())])
            .send()?;
        let (status, text, value) = response_json(resp)?;
        if !(200..300).contains(&status) {
            bail!(
                "VDN HTTP {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }
        if value
            .get("succeed")
            .map(|v| v.to_string().trim_matches('"').to_string())
            == Some("1".to_string())
        {
            if let Some(url) = value.get("url").and_then(Value::as_str) {
                return Ok(VdnGetStreamResult {
                    final_url: url.to_string(),
                    app_sign,
                    app_random_str: random_str,
                });
            }
        }
        bail!(
            "VDN did not return final URL: {}",
            text.chars().take(400).collect::<String>()
        )
    }

    fn send_heartbeat(&self) -> Result<()> {
        let Some(_control) = self.control_lock.try_lock() else {
            return Ok(());
        };
        loop {
            let sess = {
                let mut state = self.state.lock();
                let Some(sess) = state.app_session.clone() else {
                    return Ok(());
                };
                if !self.app_session_fresh(&sess) {
                    if let Some(s) = state.app_session.as_mut() {
                        s.last_heartbeat_error =
                            "session soft TTL reached; heartbeat paused until next on-demand refresh"
                                .to_string();
                    }
                    drop(state);
                    let _ = self.write_meta();
                    return Ok(());
                }
                if let Some(remaining) = self.app_session_ttl_remaining(&sess) {
                    if remaining <= self.args.heartbeat_ttl_guard.max(0.0) {
                        if let Some(s) = state.app_session.as_mut() {
                            s.last_heartbeat_error = format!(
                                "session TTL guard active; heartbeat skipped with {:.3}s remaining",
                                remaining.max(0.0)
                            );
                        }
                        drop(state);
                        let _ = self.write_meta();
                        return Ok(());
                    }
                }
                let wait = self.args.refresh_interval - (now_f64() - state.last_business_end_at);
                if wait > 0.0 {
                    drop(state);
                    thread::sleep(Duration::from_secs_f64(wait));
                    continue;
                }
                sess
            };
            let result = self.heartbeat_flow(
                &sess.profile,
                &sess.identity,
                "dangbei",
                &sess.version,
                &sess.cloud_guid,
            );
            let mut state = self.state.lock();
            state.last_business_end_at = now_f64();
            match result {
                Ok(code) => {
                    if let Some(s) = state.app_session.as_mut() {
                        s.last_heartbeat_at = now_f64();
                        s.heartbeat_count += 1;
                        s.last_heartbeat_result = code;
                        s.last_heartbeat_error.clear();
                    }
                    drop(state);
                    let _ = self.write_meta();
                    return Ok(());
                }
                Err(err) => {
                    if let Some(s) = state.app_session.as_mut() {
                        s.last_heartbeat_error = format!("{err:#}");
                    }
                    state.last_error = format!("heartbeat failed: {err:#}");
                    state.last_error_at = now_f64();
                    drop(state);
                    let _ = self.write_meta();
                    return Err(err);
                }
            }
        }
    }

    fn proxy_playlist_ts_urls(
        &self,
        playlist: &str,
        proxy_origin: &str,
        proxy_prefix: Option<&str>,
    ) -> String {
        let origin = proxy_prefix.unwrap_or(proxy_origin).trim_end_matches('/');
        let proxy_query = if proxy_prefix.is_some() {
            "/proxy?ts="
        } else {
            "/proxy.ts?="
        };
        let mut out = String::new();
        for line in playlist.lines() {
            let stripped = line.trim();
            if stripped.is_empty() || stripped.starts_with('#') {
                out.push_str(line);
            } else if is_ts_url(stripped) {
                let encoded = URL_SAFE_NO_PAD.encode(stripped.as_bytes());
                out.push_str(&format!("{origin}{proxy_query}{encoded}"));
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
        out
    }

    fn playback_headers_for_ts_url(&self, real_url: &str) -> Result<HashMap<String, String>> {
        let parsed = Url::parse(real_url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("proxy ts URL missing host"))?;
        let ts_path = parsed.path().to_string();
        let mut same_host_headers = None;
        {
            let state = self.state.lock();
            for entry in state.cache.values() {
                if entry_missing_signed_playback_headers(entry) {
                    continue;
                }
                let entry_host = if entry.final_host.is_empty() {
                    url_host(&entry.final_url)
                } else {
                    entry.final_host.clone()
                };
                if !entry_host.eq_ignore_ascii_case(host) {
                    continue;
                }
                let headers = cctv_playback_headers_for_entry(entry);
                if ts_path_matches_final_url(&ts_path, &entry.final_url) {
                    return Ok(headers);
                }
                if same_host_headers.is_none() {
                    same_host_headers = Some(headers);
                }
            }
        }
        if let Some(headers) = same_host_headers {
            return Ok(headers);
        }
        if live_playback_host_needs_signed_headers(host) {
            bail!("missing cached signed playback headers for {host}");
        }
        let uid = current_cctv_android_id(self)?;
        Ok(default_cctv_playback_headers(&uid))
    }

    fn fetch_playlist(
        &self,
        entry: &ChannelEntry,
        proxy_origin: &str,
        proxy_prefix: Option<&str>,
    ) -> Result<(String, String, PlaylistCacheProbe)> {
        let now = now_f64();
        {
            let state = self.state.lock();
            let probe = inspect_playlist_cache(
                state.playlist_cache.get(&entry.channel),
                entry,
                proxy_origin,
                proxy_prefix,
                now,
            );
            if probe.state == "hit" {
                let cached = state.playlist_cache.get(&entry.channel).unwrap();
                return Ok((cached.body.clone(), cached.content_type.clone(), probe));
            }
        }

        let lock = {
            let mut locks = self.playlist_locks.lock();
            locks
                .entry(entry.channel.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock();

        let now = now_f64();
        let miss_probe = {
            let state = self.state.lock();
            let probe = inspect_playlist_cache(
                state.playlist_cache.get(&entry.channel),
                entry,
                proxy_origin,
                proxy_prefix,
                now,
            );
            if probe.state == "hit" {
                let cached = state.playlist_cache.get(&entry.channel).unwrap();
                return Ok((cached.body.clone(), cached.content_type.clone(), probe));
            }
            probe
        };

        let playback_headers = cctv_playback_headers_for_entry(entry);
        let (status, content_type, text) =
            match fetch_playlist_http1(&entry.final_url, &playback_headers) {
                Ok(result) => result,
                Err(err) => {
                    let err_text = format!("{err:#}");
                    self.record_recoverable_error(&err_text);
                    return Err(err);
                }
            };
        if !(200..300).contains(&status) {
            let err = anyhow!(
                "upstream m3u8 HTTP {}: {}",
                status,
                text.chars().take(300).collect::<String>()
            );
            self.record_recoverable_error(&format!("{err:#}"));
            return Err(err);
        }
        self.clear_recoverable_error_count();
        // Keep the upstream playlist content as-is except for making media
        // segment URLs absolute for players that resolve relative paths
        // against this proxy instead of the upstream m3u8 URL.
        let body = rewrite_playlist_urls(&text, &entry.final_url);
        let body = self.proxy_playlist_ts_urls(&body, proxy_origin, proxy_prefix);
        if self.args.playlist_cache_ttl > 0.0 {
            let now = now_f64();
            let cached = PlaylistCacheEntry {
                body: body.clone(),
                content_type: content_type.clone(),
                cached_at: now,
                expires_at: now + self.args.playlist_cache_ttl,
                final_url: entry.final_url.clone(),
                android_id: entry.android_id.clone(),
                proxy_origin: proxy_origin.to_string(),
                proxy_prefix: proxy_prefix.unwrap_or("").to_string(),
            };
            let mut state = self.state.lock();
            state.playlist_cache.insert(entry.channel.clone(), cached);
        }
        Ok((body, content_type, miss_probe))
    }

    fn status_json(&self) -> Value {
        let state = self.state.lock();
        let now = now_f64();
        let device_state = if Path::new(&self.args.device_json).exists() {
            let loaded = load_device_state(&self.args.device_json);
            json!({
                "exists": loaded.existed,
                "android_id": loaded.state.profile.android_id,
                "mac": loaded.state.profile.mac,
                "brand": loaded.state.profile.brand,
                "model": loaded.state.profile.model,
                "screen_param": loaded.state.screen_param,
                "x_uid": loaded.state.x_uid,
                "cloud_guid_present": !loaded.state.cloud_guid.is_empty(),
                "registered_at": loaded.state.registered_at,
                "updated_at": loaded.state.updated_at,
            })
        } else {
            json!({"exists": false})
        };
        let cache: serde_json::Map<String, Value> = state
            .cache
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    json!({
                        "live_id": v.live_id,
                        "fresh": v.fresh(now),
                        "age_seconds": ((now - v.refreshed_at) * 1000.0).round() / 1000.0,
                        "expires_in_seconds": ((v.expires_at - now) * 1000.0).round() / 1000.0,
                        "rate": v.rate,
                        "rate_name": v.rate_name,
                        "final_host": v.final_host,
                        "generation": v.generation,
                        "session_generation": v.session_generation,
                        "last_refresh_error": v.last_refresh_error,
                    }),
                )
            })
            .collect();
        let playlist_cache: serde_json::Map<String, Value> = state
            .playlist_cache
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    json!({
                        "fresh": now < v.expires_at,
                        "age_seconds": ((now - v.cached_at) * 1000.0).round() / 1000.0,
                        "expires_in_seconds": ((v.expires_at - now) * 1000.0).round() / 1000.0,
                        "bytes": v.body.len(),
                        "content_type": v.content_type,
                        "proxy_origin": v.proxy_origin,
                        "proxy_prefix": v.proxy_prefix,
                    }),
                )
            })
            .collect();
        let app_session = state.app_session.as_ref().map(|s| {
            let expires_in = if self.args.session_ttl > 0.0 { Some(self.args.session_ttl - (now - s.created_at)) } else { None };
            json!({
                "active": true,
                "generation": s.generation,
                "age_seconds": ((now - s.created_at) * 1000.0).round() / 1000.0,
                "fresh": self.app_session_fresh(s),
                "expires_in_seconds": expires_in,
                "android_id": s.profile.android_id,
                "mac": s.profile.mac,
                "brand": s.profile.brand,
                "model": s.profile.model,
                "screen_param": s.screen_param,
                "cast_model": s.cast_model,
                "x_uid": s.identity.x_uid,
                "cloud_guid_present": !s.cloud_guid.is_empty(),
                "fingerprint_timestamp_ms": s.identity.fingerprint_timestamp_ms,
                "heartbeat_count": s.heartbeat_count,
                "last_heartbeat_age_seconds": ((now - s.last_heartbeat_at) * 1000.0).round() / 1000.0,
                "last_heartbeat_result": s.last_heartbeat_result,
                "last_heartbeat_error": s.last_heartbeat_error,
            })
        }).unwrap_or_else(|| json!({"active": false, "generation": state.session_generation}));
        let refresh_queue = {
            let queue = self.refresh_queue.state.lock();
            json!({
                "limit": self.args.background_refresh_queue_limit,
                "queued_depth": queue.queued.len(),
                "queued_channels": queue.queued.iter().cloned().collect::<Vec<_>>(),
                "running_channel": queue.running_channel,
                "running_age_seconds": if queue.running_started_at > 0.0 {
                    Some(((now - queue.running_started_at) * 1000.0).round() / 1000.0)
                } else {
                    None
                },
                "enqueued_total": queue.enqueued_total,
                "dropped_total": queue.dropped_total,
                "completed_total": queue.completed_total,
                "failed_total": queue.failed_total,
                "last_enqueued_age_seconds": if queue.last_enqueued_at > 0.0 {
                    Some(((now - queue.last_enqueued_at) * 1000.0).round() / 1000.0)
                } else {
                    None
                },
                "last_finished_age_seconds": if queue.last_finished_at > 0.0 {
                    Some(((now - queue.last_finished_at) * 1000.0).round() / 1000.0)
                } else {
                    None
                },
                "last_dropped_age_seconds": if queue.last_dropped_at > 0.0 {
                    Some(((now - queue.last_dropped_at) * 1000.0).round() / 1000.0)
                } else {
                    None
                },
                "last_drop_reason": queue.last_drop_reason,
            })
        };
        let http_queue = {
            let queue = self.http_queue.state.lock();
            json!({
                "workers": self.args.http_workers.max(1),
                "limit": self.args.http_queue_limit,
                "queued_depth": queue.queued.len(),
                "active_workers": queue.active_workers,
                "enqueued_total": queue.enqueued_total,
                "rejected_total": queue.rejected_total,
                "completed_total": queue.completed_total,
                "panicked_total": queue.panicked_total,
                "last_enqueued_age_seconds": if queue.last_enqueued_at > 0.0 {
                    Some(((now - queue.last_enqueued_at) * 1000.0).round() / 1000.0)
                } else {
                    None
                },
                "last_completed_age_seconds": if queue.last_completed_at > 0.0 {
                    Some(((now - queue.last_completed_at) * 1000.0).round() / 1000.0)
                } else {
                    None
                },
                "last_rejected_age_seconds": if queue.last_rejected_at > 0.0 {
                    Some(((now - queue.last_rejected_at) * 1000.0).round() / 1000.0)
                } else {
                    None
                },
            })
        };
        json!({
            "channels": channels().iter().map(|(c,_)| *c).collect::<Vec<_>>(),
            "cache_ttl_seconds": self.args.cache_ttl,
            "stale_while_refresh_ttl_seconds": self.args.stale_while_refresh_ttl,
            "refresh_error_cooldown_seconds": self.args.refresh_error_cooldown,
            "playlist_cache_ttl_seconds": self.args.playlist_cache_ttl,
            "background_refresh_queue_limit": self.args.background_refresh_queue_limit,
            "http_workers": self.args.http_workers.max(1),
            "http_queue_limit": self.args.http_queue_limit,
            "identity_reset_error_threshold": self.args.identity_reset_error_threshold,
            "identity_reset_cooldown_seconds": self.args.identity_reset_cooldown,
            "refresh_interval_seconds": self.args.refresh_interval,
            "control_step_jitter_min_ms": self.args.control_step_jitter_min_ms,
            "control_step_jitter_max_ms": self.args.control_step_jitter_max_ms,
            "heartbeat_interval_seconds": self.args.heartbeat_interval,
            "heartbeat_ttl_guard_seconds": self.args.heartbeat_ttl_guard,
            "session_ttl_seconds": self.args.session_ttl,
            "meta_json": self.args.meta_json,
            "device_json": self.args.device_json,
            "device_state": device_state,
            "refreshing_channel": state.refreshing_channel,
            "background_refreshing": state.background_refreshing.keys().cloned().collect::<Vec<_>>(),
            "background_refresh_queue": refresh_queue,
            "http_queue": http_queue,
            "generation": state.generation,
            "app_session": app_session,
            "last_business_end_at": state.last_business_end_at,
            "last_error": state.last_error,
            "identity_reset_error_count": state.identity_reset_error_count,
            "identity_reset_count": state.identity_reset_count,
            "last_identity_reset_at": state.last_identity_reset_at,
            "last_identity_reset_reason": state.last_identity_reset_reason,
            "ad_display": state.ad_display,
            "device_profile_pool_size": device_profile_pool().len(),
            "cache": cache,
            "playlist_cache": playlist_cache,
        })
    }

    fn write_meta(&self) -> Result<()> {
        let mut payload = self.status_json();
        let cache_detail = {
            let state = self.state.lock();
            serde_json::to_value(&state.cache)?
        };
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("cache_detail".to_string(), cache_detail);
            obj.insert("session_detail_note".to_string(), json!("Session secrets are intentionally not persisted for reuse; Rust process keeps live session in memory only."));
            obj.insert("device_state_note".to_string(), json!("Randomized TV device identity is persisted in device-state-rs.json after cloud registration succeeds; a new identity reset creates a new profile and MAC."));
        }
        if let Some(parent) = std::path::Path::new(&self.args.meta_json).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &self.args.meta_json,
            serde_json::to_string_pretty(&payload)? + "\n",
        )?;
        Ok(())
    }
}

#[derive(Debug)]
struct AppStartResult {
    session_key: String,
}

#[derive(Debug)]
struct Live01Result {
    live_url: String,
    rate: String,
    rate_name: String,
}

#[derive(Debug)]
struct VdnGetStreamResult {
    final_url: String,
    app_sign: String,
    app_random_str: String,
}

fn is_ts_url(value: &str) -> bool {
    Url::parse(value)
        .map(|url| url.path().to_ascii_lowercase().ends_with(".ts"))
        .unwrap_or(false)
}

fn rewrite_playlist_urls(text: &str, base_url: &str) -> String {
    let base = Url::parse(base_url).ok();
    let mut out = String::new();
    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            out.push_str(line);
        } else if let Some(base) = &base {
            out.push_str(
                base.join(stripped)
                    .map(|u| u.to_string())
                    .unwrap_or_else(|_| stripped.to_string())
                    .as_str(),
            );
        } else {
            out.push_str(stripped);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_identity_removes_state_files_and_clears_memory() {
        let dir =
            std::env::temp_dir().join(format!("cctv-live-proxy-rs-reset-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let device_json = dir.join("device-state-rs.json");
        let meta_json = dir.join("proxy-cache-state-rs.json");
        fs::write(&device_json, "{}\n").unwrap();
        fs::write(&meta_json, "{}\n").unwrap();

        let mut args = Args::parse_from(["test"]);
        args.meta_json = meta_json.to_string_lossy().into_owned();
        args.device_json = device_json.to_string_lossy().into_owned();
        args.http_workers = 1;
        args.background_refresh_queue_limit = 1;
        let resolver = Resolver::new(args).unwrap();
        {
            let mut state = resolver.state.lock();
            state.cache.insert(
                "cctv4k".to_string(),
                ChannelEntry {
                    channel: "cctv4k".to_string(),
                    live_id: "Live1767871224782105".to_string(),
                    final_url: "http://127.0.0.1:1/live/test.m3u8".to_string(),
                    playback_headers: HashMap::new(),
                    android_id: "0123456789abcdef".to_string(),
                    x_uid: "XUID".to_string(),
                    rate: "36p".to_string(),
                    rate_name: "8K高清".to_string(),
                    raw_live_host: "live-tpgq.cctv.cn".to_string(),
                    final_host: "127.0.0.1".to_string(),
                    refreshed_at: now_f64(),
                    expires_at: now_f64() + 600.0,
                    generation: 1,
                    last_refresh_error: String::new(),
                    last_refresh_failed_at: 0.0,
                    session_generation: 1,
                },
            );
            state.identity_reset_error_count = 2;
        }

        assert!(resolver.record_recoverable_error("connection refused"));
        assert!(!device_json.exists());
        assert!(!meta_json.exists());
        let state = resolver.state.lock();
        assert!(state.cache.is_empty());
        assert!(state.playlist_cache.is_empty());
        assert!(state.app_session.is_none());
        assert_eq!(state.identity_reset_count, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_400_is_identity_recoverable_and_session_invalidating() {
        let err = r#"live/v1/01 HTTP 400: {"data":{},"message":"","result":"400"}"#;
        assert!(is_session_invalidating_error(err));
        assert!(is_identity_recoverable_error(err));

        let err = r#"live/v1/02 HTTP 400: {"data":{},"message":"","result":"400"}"#;
        assert!(is_session_invalidating_error(err));
        assert!(is_identity_recoverable_error(err));
    }

    #[test]
    fn app_start_and_control_plane_400_are_identity_recoverable() {
        for err in [
            r#"app/start HTTP 400: {"data":{},"message":"","result":"400"}"#,
            r#"app/start status=400 body={"data":{},"message":"","result":"400"}"#,
        ] {
            assert!(is_session_invalidating_error(err));
            assert!(is_identity_recoverable_error(err));
        }

        for err in [
            "dictionary HTTP 400",
            "index HTTP 400",
            "drm config HTTP 400",
            "version config HTTP 400",
            "VDN HTTP 400",
            "heartbeat HTTP 400",
            "device info HTTP 400",
            "page event HTTP 400",
            "app event HTTP 400",
            "collect report HTTP 400",
            "upstream m3u8 HTTP 400",
        ] {
            assert!(is_identity_recoverable_error(err), "{err}");
        }
    }

    #[test]
    fn default_device_state_uses_profile_pool_and_random_mac() {
        assert!(device_profile_pool().len() >= 30);
        assert!(device_profile_pool()
            .iter()
            .any(|profile| profile.screen_param.starts_with("3840-2160-")));
        assert!(device_profile_pool()
            .iter()
            .any(|profile| profile.screen_param.starts_with("7680-4320-")));
        for profile in device_profile_pool() {
            assert!(matches!(
                profile.brand,
                "Sony" | "Samsung" | "LG" | "TCL" | "CHANGHONG"
            ));
        }
        let state = default_device_state();
        assert!(device_profile_pool()
            .iter()
            .any(|profile| profile.source == state.profile_source));
        assert_eq!(state.profile.android_id.len(), 16);
        assert!(matches!(
            state.profile.resolution.as_str(),
            "3840*2160" | "7680*4320"
        ));

        let parts = state.profile.mac.split(':').collect::<Vec<_>>();
        assert_eq!(parts.len(), 6);
        let first_octet = u8::from_str_radix(parts[0], 16).unwrap();
        assert_eq!(first_octet & 0x01, 0);
        assert_eq!(first_octet & 0x02, 0x02);
        assert!(!state.screen_param.is_empty());
        assert!(!state.cast_model.is_empty());
    }

    #[test]
    fn playlist_ts_lines_are_rewritten_to_local_proxy() {
        let args = Args::parse_from(["test"]);
        let resolver = Resolver::new(args).unwrap();
        let real_ts = "http://liveten-tpgq.cctv.cn/live/demo_123.ts?txSecret=abc&txTime=123";
        let playlist = format!("#EXTM3U\n#EXTINF:2.0,\n{real_ts}\n#EXT-X-ENDLIST\n");

        let rewritten = resolver.proxy_playlist_ts_urls(&playlist, "http://127.0.0.1:8766", None);

        let proxy_line = rewritten
            .lines()
            .find(|line| line.contains("/proxy.ts?="))
            .unwrap();
        let token = proxy_line.split("?=").nth(1).unwrap();
        assert_eq!(decode_proxy_ts_url(token).unwrap(), real_ts);
    }

    #[test]
    fn playlist_ts_lines_use_prefix_proxy_when_requested() {
        let args = Args::parse_from(["test"]);
        let resolver = Resolver::new(args).unwrap();
        let real_ts = "http://liveten-tpgq.cctv.cn/live/demo_123.ts?txSecret=abc&txTime=123";
        let playlist = format!("#EXTM3U\n#EXTINF:2.0,\n{real_ts}\n#EXT-X-ENDLIST\n");

        let rewritten = resolver.proxy_playlist_ts_urls(
            &playlist,
            "http://127.0.0.1:8766",
            Some("https://cdn.example.com"),
        );

        let proxy_line = rewritten
            .lines()
            .find(|line| line.contains("https://cdn.example.com/proxy?ts="))
            .unwrap();
        let token = proxy_ts_token(proxy_line).unwrap();
        assert_eq!(decode_proxy_ts_url(&token).unwrap(), real_ts);
    }

    #[test]
    fn liveten_cache_entry_requires_signed_playback_headers() {
        let mut entry = ChannelEntry {
            channel: "cctv4k".to_string(),
            live_id: "Live1767871224782105".to_string(),
            final_url: "http://liveten-tpgq.cctv.cn/live/demo.m3u8?wsSecret=x&wsTime=y".to_string(),
            playback_headers: HashMap::new(),
            android_id: "0123456789abcdef".to_string(),
            x_uid: "XUID".to_string(),
            rate: "36p".to_string(),
            rate_name: "8K高清".to_string(),
            raw_live_host: "live-tpgq.cctv.cn".to_string(),
            final_host: "liveten-tpgq.cctv.cn".to_string(),
            refreshed_at: now_f64(),
            expires_at: now_f64() + 600.0,
            generation: 1,
            last_refresh_error: String::new(),
            last_refresh_failed_at: 0.0,
            session_generation: 1,
        };
        assert!(entry_missing_signed_playback_headers(&entry));

        entry.playback_headers = default_cctv_playback_headers(&entry.android_id);
        entry
            .playback_headers
            .insert("APPRANDOMSTR".to_string(), "random".to_string());
        entry
            .playback_headers
            .insert("APPSIGN".to_string(), "sign".to_string());
        assert!(!entry_missing_signed_playback_headers(&entry));
    }
}

fn append_cctv_playback_header_lines(out: &mut String, headers: &HashMap<String, String>) {
    for key in [
        "UID",
        "APPID",
        "APPRANDOMSTR",
        "Referer",
        "User-Agent",
        "APPSIGN",
    ] {
        if let Some(value) = headers.get(key).filter(|v| !v.trim().is_empty()) {
            out.push_str(key);
            out.push_str(": ");
            out.push_str(&header_value_clean(value));
            out.push_str("\r\n");
        }
    }
}

fn fetch_playlist_http1(
    final_url: &str,
    playback_headers: &HashMap<String, String>,
) -> Result<(u16, String, String)> {
    let url = Url::parse(final_url)?;
    if url.scheme() != "http" {
        bail!(
            "manual playlist fetch currently expects http URL, got {}",
            url.scheme()
        );
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("final URL missing host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    if target.is_empty() {
        target.push('/');
    }
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut request = format!("GET {target} HTTP/1.1\r\nHost: {host_header}\r\n");
    append_cctv_playback_header_lines(&mut request, playback_headers);
    request.push_str("Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("playlist response missing header/body separator"))?;
    let header_text = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body = raw[split + 4..].to_vec();
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid playlist status line: {status_line}"))?;
    let mut content_type = "application/vnd.apple.mpegurl".to_string();
    let mut chunked = false;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let key_l = key.trim().to_ascii_lowercase();
            let value = value.trim();
            if key_l == "content-type" {
                content_type = value.to_string();
            } else if key_l == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    if chunked {
        body = decode_chunked_body(&body)?;
    }
    Ok((
        status,
        content_type,
        String::from_utf8_lossy(&body).to_string(),
    ))
}

fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    loop {
        let line_end = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("chunked body missing chunk size line"))?
            + pos;
        let size_line = String::from_utf8_lossy(&raw[pos..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size: {size_hex}"))?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size > raw.len() {
            bail!("chunked body truncated");
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos += size;
        if raw.get(pos..pos + 2) == Some(b"\r\n") {
            pos += 2;
        }
    }
    Ok(out)
}

fn load_cache(path: &str) -> HashMap<String, ChannelEntry> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return HashMap::new();
    };
    let Some(detail) = value.get("cache_detail") else {
        return HashMap::new();
    };
    serde_json::from_value(detail.clone()).unwrap_or_default()
}

fn respond_text(
    request: tiny_http::Request,
    status: u16,
    body: String,
    content_type: &str,
    extra: Vec<Header>,
) {
    let mut response = Response::from_string(body).with_status_code(StatusCode(status));
    response.add_header(Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap());
    for h in extra {
        response.add_header(h);
    }
    let _ = request.respond(response);
}

fn respond_redirect(request: tiny_http::Request, location: &str) {
    respond_text(
        request,
        302,
        String::new(),
        "text/plain; charset=utf-8",
        vec![
            Header::from_bytes(&b"Location"[..], location.as_bytes()).unwrap(),
            Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap(),
        ],
    );
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(value.to_string());
        }
    }
    None
}

fn request_header(request: &tiny_http::Request, name: &str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|header| header.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str().trim().to_string())
        .filter(|value| !value.is_empty())
}

fn first_header_value(value: &str) -> String {
    value.split(',').next().unwrap_or(value).trim().to_string()
}

fn request_origin(request: &tiny_http::Request, fallback_port: u16) -> String {
    let scheme = request_header(request, "X-Forwarded-Proto")
        .map(|value| first_header_value(&value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "http".to_string());
    let host = request_header(request, "X-Forwarded-Host")
        .or_else(|| request_header(request, "Host"))
        .map(|value| first_header_value(&value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("127.0.0.1:{fallback_port}"));
    format!(
        "{}://{}",
        scheme.trim_end_matches("://"),
        host.trim_end_matches('/')
    )
}

fn query_param_decoded(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key == name {
            return Some(value.into_owned());
        }
    }
    None
}

fn proxy_prefix_from_url(url: &str) -> Result<Option<String>> {
    let Some(raw) = query_param_decoded(url, "prefix") else {
        return Ok(None);
    };
    let prefix = raw.trim().trim_end_matches('/').to_string();
    if prefix.is_empty() {
        return Ok(None);
    }
    let parsed = Url::parse(&prefix).context("invalid prefix URL")?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        bail!("prefix scheme must be http or https");
    }
    if parsed.host_str().is_none() {
        bail!("prefix URL missing host");
    }
    Ok(Some(prefix))
}

fn build_4kfifa_playlist(origin: &str, proxy_prefix: Option<&str>) -> String {
    let origin = origin.trim_end_matches('/');
    let suffix = proxy_prefix
        .map(|prefix| format!("?prefix={}", prefix.trim_end_matches('/')))
        .unwrap_or_default();
    format!(
        "#EXTM3U x-tvg-url=\"http://epg.51zmt.top:8000/e.xml\"\n\
#EXTINF:-1 tvg-name=\"注意事项\" tvg-logo=\"https://cdn.jsdelivr.net/gh/iptvorganization/first/notice.jpg\" group-title=\"注意事项\",注意事项\n\
https://cdn.jsdelivr.net/gh/iptvorganization/first/group.ts\n\
#EXTINF:-1 tvg-name=\"cctv5\" tvg-logo=\"https://cdn.jsdelivr.net/gh/sparkssssssssss/epg/logo/cctv5.png\" group-title=\"高码率CCTV5\",cctv5\n\
{origin}/cctv5.m3u8{suffix}\n\
#EXTINF:-1 tvg-name=\"cctv5+\" tvg-logo=\"https://cdn.jsdelivr.net/gh/sparkssssssssss/epg/logo/cctv5+.png\" group-title=\"高码率CCTV5+\",cctv5+\n\
{origin}/cctv5p.m3u8{suffix}\n\
#EXTINF:-1 tvg-name=\"cctv16-4k\" tvg-logo=\"https://cdn.jsdelivr.net/gh/sparkssssssssss/epg/logo/cctv16.png\" group-title=\"4KUHD-FIFA\",cctv16-4k\n\
{origin}/cctv16.m3u8{suffix}\n\
#EXTINF:-1 tvg-name=\"cctv4k\" tvg-logo=\"https://cdn.jsdelivr.net/gh/sparkssssssssss/epg/logo/cctv4k.png\" group-title=\"4KUHD-FIFA\",cctv4k\n\
{origin}/cctv4k.m3u8{suffix}\n\
#EXTINF:-1 tvg-name=\"cctv8k\" tvg-logo=\"https://cdn.jsdelivr.net/gh/sparkssssssssss/epg/logo/cctv8k.png\" group-title=\"8K频道\",cctv8k\n\
{origin}/cctv8k.m3u8{suffix}\n"
    )
}

fn proxy_ts_token(url: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    if let Some(token) = query.strip_prefix('=') {
        return Some(token.to_string()).filter(|value| !value.is_empty());
    }
    if let Some(token) = query_param(url, "ts") {
        return Some(token).filter(|value| !value.is_empty());
    }
    if let Some(token) = query_param(url, "url") {
        return Some(token).filter(|value| !value.is_empty());
    }
    if !query.is_empty() && !query.contains('=') {
        return Some(query.to_string());
    }
    None
}

fn decode_proxy_ts_url(token: &str) -> Result<String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .context("invalid proxy ts token")?;
    let value = String::from_utf8(bytes).context("proxy ts token is not UTF-8")?;
    let parsed = Url::parse(&value).context("proxy ts token is not a URL")?;
    if parsed.scheme() != "http" {
        bail!(
            "proxy ts currently requires http URL, got {}",
            parsed.scheme()
        );
    }
    if !parsed.path().to_ascii_lowercase().ends_with(".ts") {
        bail!("proxy ts URL is not a .ts segment");
    }
    Ok(value)
}

fn header_value_clean(value: &str) -> String {
    value.replace(['\r', '\n'], "")
}

fn current_cctv_android_id(resolver: &Resolver) -> Result<String> {
    if Path::new(&resolver.args.device_json).exists() {
        let loaded = load_device_state(&resolver.args.device_json);
        if !loaded.state.profile.android_id.is_empty() {
            return Ok(loaded.state.profile.android_id);
        }
    }
    {
        let state = resolver.state.lock();
        if let Some(session) = &state.app_session {
            if !session.profile.android_id.is_empty() {
                return Ok(session.profile.android_id.clone());
            }
        }
        if let Some(entry) = state
            .cache
            .values()
            .find(|entry| !entry.android_id.is_empty())
        {
            return Ok(entry.android_id.clone());
        }
    }
    Err(anyhow!("missing cctv android_id"))
}

fn status_authorized(request: &tiny_http::Request, url: &str) -> bool {
    if query_param(url, "token").as_deref() == Some(SWITCH_TOKEN) {
        return true;
    }
    request.headers().iter().any(|header| {
        let value = header.value.as_str().trim();
        (header.field.equiv("X-Status-Token") && value == SWITCH_TOKEN)
            || (header.field.equiv("Authorization") && value == format!("Bearer {SWITCH_TOKEN}"))
    })
}

fn switch_authorized(request: &tiny_http::Request, url: &str) -> bool {
    if query_param(url, "token").as_deref() == Some(SWITCH_TOKEN) {
        return true;
    }
    request.headers().iter().any(|header| {
        let value = header.value.as_str().trim();
        (header.field.equiv("X-Switch-Token") && value == SWITCH_TOKEN)
            || (header.field.equiv("Authorization") && value == format!("Bearer {SWITCH_TOKEN}"))
    })
}

fn build_proxy_ts_response_http1(
    real_url: &str,
    playback_headers: &HashMap<String, String>,
    range: Option<String>,
    timeout: f64,
) -> Result<Response<Box<dyn Read + Send>>> {
    let url = Url::parse(real_url)?;
    if url.scheme() != "http" {
        bail!("proxy ts currently requires http URL, got {}", url.scheme());
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("proxy ts URL missing host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    if target.is_empty() {
        target.push('/');
    }

    let timeout = Duration::from_secs_f64(timeout.max(1.0));
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut upstream_request = format!("GET {target} HTTP/1.1\r\nHost: {host_header}\r\n");
    append_cctv_playback_header_lines(&mut upstream_request, playback_headers);
    upstream_request.push_str("Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n");
    if let Some(range) = range {
        upstream_request.push_str(&format!("Range: {}\r\n", header_value_clean(&range)));
    }
    upstream_request.push_str("\r\n");
    stream.write_all(upstream_request.as_bytes())?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    let split = loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            bail!("upstream ts response ended before headers");
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if raw.len() > 128 * 1024 {
            bail!("upstream ts response headers too large");
        }
    };

    let header_text = String::from_utf8_lossy(&raw[..split]).to_string();
    let body_prefix = raw[split + 4..].to_vec();
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid upstream ts status line: {status_line}"))?;

    let mut forwarded_headers = Vec::new();
    let mut has_content_type = false;
    let mut content_length = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let key_l = key.to_ascii_lowercase();
        if key_l == "content-length" {
            content_length = value.parse::<usize>().ok();
            continue;
        }
        if matches!(
            key_l.as_str(),
            "content-type" | "content-range" | "accept-ranges"
        ) {
            if key_l == "content-type" {
                has_content_type = true;
            }
            forwarded_headers.push(
                Header::from_bytes(key.as_bytes(), value.as_bytes())
                    .map_err(|_| anyhow!("invalid upstream ts header {key}"))?,
            );
        }
    }
    if !has_content_type {
        forwarded_headers
            .push(Header::from_bytes(&b"Content-Type"[..], &b"video/MP2T"[..]).unwrap());
    }
    forwarded_headers.push(
        Header::from_bytes(&b"Cache-Control"[..], &b"no-cache, no-store, max-age=0"[..]).unwrap(),
    );
    forwarded_headers
        .push(Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap());

    let reader: Box<dyn Read + Send> = Box::new(PrefixReader::new(body_prefix, stream));
    Ok(Response::new(
        StatusCode(status),
        forwarded_headers,
        reader,
        content_length,
        None,
    ))
}

fn respond_proxy_ts(resolver: Arc<Resolver>, request: tiny_http::Request, url: &str) {
    let Some(token) = proxy_ts_token(url) else {
        respond_text(
            request,
            400,
            "missing proxy ts token\n".to_string(),
            "text/plain; charset=utf-8",
            vec![],
        );
        return;
    };
    let real_url = match decode_proxy_ts_url(&token) {
        Ok(value) => value,
        Err(err) => {
            respond_text(
                request,
                400,
                format!("{err:#}\n"),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        }
    };
    let playback_headers = match resolver.playback_headers_for_ts_url(&real_url) {
        Ok(headers) => headers,
        Err(err) => {
            respond_text(
                request,
                500,
                format!("{err:#}\n"),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        }
    };
    let range = request_header(&request, "Range");
    match build_proxy_ts_response_http1(&real_url, &playback_headers, range, resolver.args.timeout)
    {
        Ok(response) => {
            let _ = request.respond(response);
        }
        Err(err) => {
            let _ = err;
            respond_redirect(request, AD_REDIRECT_URL);
        }
    }
}

fn handle_request(resolver: Arc<Resolver>, request: tiny_http::Request) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or(&url);
    if path == "/" {
        respond_redirect(request, DEFAULT_REDIRECT_URL);
        return;
    }
    if path == "/status" {
        if !status_authorized(&request, &url) {
            respond_text(
                request,
                401,
                "unauthorized\n".to_string(),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        }
        respond_text(
            request,
            200,
            serde_json::to_string_pretty(&resolver.status_json()).unwrap(),
            "application/json; charset=utf-8",
            vec![],
        );
        return;
    }
    if path == "/switch" {
        if method != Method::Get && method != Method::Head {
            respond_text(
                request,
                405,
                "method not allowed\n".to_string(),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        }
        if !switch_authorized(&request, &url) {
            respond_text(
                request,
                401,
                "unauthorized\n".to_string(),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        }
        let Some(ad) = query_param(&url, "ad") else {
            respond_text(
                request,
                400,
                "missing ad\n".to_string(),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        };
        let ad_display = match ad.as_str() {
            "display" => true,
            "nodisplay" => false,
            _ => {
                respond_text(
                    request,
                    400,
                    "invalid ad\n".to_string(),
                    "text/plain; charset=utf-8",
                    vec![],
                );
                return;
            }
        };
        {
            let mut state = resolver.state.lock();
            state.ad_display = ad_display;
        }
        let _ = resolver.write_meta();
        let body = if ad_display {
            format!("switch success\nad=display\nredirect={AD_REDIRECT_URL}\n")
        } else {
            "switch success\nad=nodisplay\n".to_string()
        };
        respond_text(request, 200, body, "text/plain; charset=utf-8", vec![]);
        return;
    }
    if path == "/4kfifa.m3u" {
        if method != Method::Get && method != Method::Head {
            respond_text(
                request,
                405,
                "method not allowed\n".to_string(),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        }
        let proxy_prefix = match proxy_prefix_from_url(&url) {
            Ok(value) => value,
            Err(err) => {
                respond_text(
                    request,
                    400,
                    format!("{err:#}\n"),
                    "text/plain; charset=utf-8",
                    vec![],
                );
                return;
            }
        };
        let body = if method == Method::Head {
            String::new()
        } else {
            let origin = request_origin(&request, resolver.args.port);
            build_4kfifa_playlist(&origin, proxy_prefix.as_deref())
        };
        respond_text(
            request,
            200,
            body,
            "application/vnd.apple.mpegurl; charset=utf-8",
            vec![
                Header::from_bytes(&b"Cache-Control"[..], &b"no-cache, no-store, max-age=0"[..])
                    .unwrap(),
                Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap(),
            ],
        );
        return;
    }
    if path == "/proxy.ts" || path == "/proxy" {
        if method != Method::Get {
            respond_text(
                request,
                405,
                "method not allowed\n".to_string(),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        }
        if resolver.state.lock().ad_display {
            respond_redirect(request, AD_REDIRECT_URL);
            return;
        }
        respond_proxy_ts(Arc::clone(&resolver), request, &url);
        return;
    }
    if method != Method::Get && method != Method::Head {
        respond_text(
            request,
            405,
            "method not allowed\n".to_string(),
            "text/plain; charset=utf-8",
            vec![],
        );
        return;
    }
    let channel = normalize_channel(path);
    if channel_by_name(&channel).is_none() {
        respond_redirect(request, DEFAULT_REDIRECT_URL);
        return;
    }
    let proxy_prefix = match proxy_prefix_from_url(&url) {
        Ok(value) => value,
        Err(err) => {
            respond_text(
                request,
                400,
                format!("{err:#}\n"),
                "text/plain; charset=utf-8",
                vec![],
            );
            return;
        }
    };
    if resolver.state.lock().ad_display {
        respond_redirect(request, AD_REDIRECT_URL);
        return;
    }
    match resolver.ensure_channel(&channel).and_then(|entry| {
        if method == Method::Head {
            Ok((
                String::new(),
                "application/vnd.apple.mpegurl".to_string(),
                Some(PlaylistCacheProbe {
                    state: "bypass:head".to_string(),
                    age_ms: None,
                }),
                entry,
            ))
        } else {
            let proxy_origin = request_origin(&request, resolver.args.port);
            let (body, content_type, playlist_probe) =
                resolver.fetch_playlist(&entry, &proxy_origin, proxy_prefix.as_deref())?;
            Ok((body, content_type, Some(playlist_probe), entry))
        }
    }) {
        Ok((body, content_type, playlist_probe, entry)) => {
            let mut headers = vec![
                Header::from_bytes(&b"Cache-Control"[..], &b"no-cache, no-store, max-age=0"[..])
                    .unwrap(),
                Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap(),
                Header::from_bytes(&b"X-CCTV-Channel"[..], entry.channel.as_bytes()).unwrap(),
                Header::from_bytes(&b"X-CCTV-Rate"[..], entry.rate.as_bytes()).unwrap(),
            ];
            let expires = ((entry.expires_at - now_f64()).max(0.0) as i64).to_string();
            headers.push(
                Header::from_bytes(&b"X-CCTV-Cache-Expires-In"[..], expires.as_bytes()).unwrap(),
            );
            let cache_state = if entry.fresh(now_f64()) {
                "fresh"
            } else {
                "stale-while-refresh"
            };
            headers.push(
                Header::from_bytes(&b"X-CCTV-Cache-State"[..], cache_state.as_bytes()).unwrap(),
            );
            if let Some(probe) = playlist_probe {
                headers.push(
                    Header::from_bytes(&b"X-CCTV-Playlist-Cache"[..], probe.state.as_bytes())
                        .unwrap(),
                );
                if let Some(age_ms) = probe.age_ms {
                    headers.push(
                        Header::from_bytes(
                            &b"X-CCTV-Playlist-Cache-Age-Ms"[..],
                            age_ms.to_string().as_bytes(),
                        )
                        .unwrap(),
                    );
                }
            }
            respond_text(request, 200, body, &content_type, headers);
        }
        Err(err) => {
            respond_text(
                request,
                502,
                format!("{err:#}\n"),
                "text/plain; charset=utf-8",
                vec![],
            );
        }
    }
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    args.resolve_paths()?;
    let bind = format!("{}:{}", args.host, args.port);
    let resolver = Arc::new(Resolver::new(args)?);
    resolver.start_heartbeat();
    resolver.start_refresh_worker();
    resolver.start_http_workers();
    let server = Server::http(&bind).map_err(|e| anyhow!("{e}"))?;
    log_program_initializing();
    for request in server.incoming_requests() {
        resolver.enqueue_http_request(request);
    }
    Ok(())
}
