use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{
        header::{
            ACCEPT_ENCODING, CONNECTION, CONTENT_LENGTH, HOST, LOCATION, PROXY_AUTHENTICATE,
            PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
        },
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    },
    response::{IntoResponse, Redirect, Response},
    routing::{any, get},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, HashSet},
    env, fs,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{fs as async_fs, sync::mpsc};

// 映射 config.toml 的数据结构
#[derive(Deserialize, Clone)]
struct AppConfig {
    secret_key: String,
    clear_secret_key: String,
    fake_website: String,
    json_path: String,
    listen_address: String,
    expiration_hours: u64,
}

// 专门给 sing-box 看的纯净规则集结构体
#[derive(Serialize, Deserialize, Clone, Default)]
struct SingBoxRule {
    source_ip_cidr: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct SingBoxConfig {
    version: u32,
    rules: Vec<SingBoxRule>,
}

// 专门给 Rust 后端内部持久化、防重启丢失用的状态结构体
#[derive(Serialize, Deserialize, Clone, Default)]
struct RustRegistryState {
    expires: HashMap<String, u64>,
}

// 小根堆节点，按到期时间升序排列
#[derive(Eq, PartialEq)]
struct ExpireNode {
    cidr: String,
    expire_at: u64,
}
impl Ord for ExpireNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other.expire_at.cmp(&self.expire_at)
    }
}
impl PartialOrd for ExpireNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// 异步通信通道指令类型
enum RegistryCmd {
    Register(String, u64),
    ClearAll,
}

// 全局状态无锁共享上下文
struct AppContext {
    config: AppConfig,
    tx: mpsc::Sender<RegistryCmd>,
    http_client: reqwest::Client,
}

const MAX_PROXY_REQUEST_BODY_BYTES: usize = 1024 * 1024;

#[tokio::main]
async fn main() {
    // 1. 解析命令行参数以支持自定义配置文件路径 (-c / --config)
    let args: Vec<String> = env::args().collect();
    let mut config_path_str = "config.toml".to_string(); // 默认寻找当前目录

    let mut i = 1;
    while i < args.len() {
        if (args[i] == "-c" || args[i] == "--config") && i + 1 < args.len() {
            config_path_str = args[i + 1].clone();
            break;
        }
        i += 1;
    }

    println!("📖 [配置加载] 正在尝试从路径读取配置: {}", config_path_str);

    let config_str = fs::read_to_string(&config_path_str).unwrap_or_else(|_| {
        panic!(
            "❌ 错误：无法在 [{}] 找到有效的配置文件，请检查路径是否正确",
            config_path_str
        )
    });

    let config: AppConfig =
        toml::from_str(&config_str).expect("❌ 错误：解析配置文件失败，请检查 TOML 语法格式");

    let listen_addr = config.listen_address.clone();
    let json_path = config.json_path.clone();

    // 计算 config 文件的同级目录路径，用来存放 .db 状态文件
    let config_path_buf = PathBuf::from(&config_path_str);
    let mut db_path_buf = if let Some(parent) = config_path_buf.parent() {
        parent.to_path_buf()
    } else {
        PathBuf::from(".")
    };
    db_path_buf.push("ip_whitelist.json.db"); // 固定在 config 同级目录下生成该状态文件
    let db_path_str = db_path_buf.to_string_lossy().into_owned();

    // 2. 初始化全异步无锁 MPSC 通道
    let (tx, rx) = mpsc::channel::<RegistryCmd>(256);

    // 3. 🚀 启动后台单线程注册中心任务（把计算好的 db_path_str 传给它）
    tokio::spawn(registry_center_loop(json_path, db_path_str, rx));

    // 4. 初始化全局唯一的复用高并发 HTTP 客户端
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .pool_max_idle_per_host(20)
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let shared_context = Arc::new(AppContext {
        config,
        tx,
        http_client,
    });

    // 5. 组装异步 Web 路由
    let app = Router::new()
        .route("/ip/:secret/:user", get(report_ip_handler))
        .route("/system/:clear_secret/:target", get(clear_ip_handler))
        .fallback(any(proxy_to_fake_handler))
        .layer(DefaultBodyLimit::max(MAX_PROXY_REQUEST_BODY_BYTES))
        .with_state(shared_context);

    println!(
        "🏆 [完美分家+DB路径对齐版] 服务启动成功！监听: {}",
        listen_addr
    );
    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// 获取当前系统独有的 UNIX 时间戳(秒)
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// 🛡️ 注册中心常驻任务
async fn registry_center_loop(
    json_path: String,
    db_path: String,
    mut rx: mpsc::Receiver<RegistryCmd>,
) {
    let mut sb_config = load_singbox_config(&json_path);
    let mut rust_state = load_rust_state(&db_path);
    let mut ip_set = sb_config
        .rules
        .first()
        .map(|rule| {
            rule.source_ip_cidr
                .iter()
                .cloned()
                .collect::<HashSet<String>>()
        })
        .unwrap_or_default();

    // 初始化小根堆，将历史状态中的到期倒计时无缝恢复回内存中
    let mut heap = BinaryHeap::new();
    for (cidr, &expire_at) in rust_state.expires.iter() {
        heap.push(ExpireNode {
            cidr: cidr.clone(),
            expire_at,
        });
    }
    println!("📦 [注册中心] 状态文件加载路径: {}", db_path);
    println!(
        "📦 [注册中心] 白名单当前存活历史 IP 数: {}",
        sb_config
            .rules
            .first()
            .map(|r| r.source_ip_cidr.len())
            .unwrap_or(0)
    );

    let mut is_dirty = false;
    let mut ticker = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            Some(cmd) = rx.recv() => {
                match cmd {
                    RegistryCmd::Register(cidr, duration_secs) => {
                        let expire_at = current_timestamp() + duration_secs;

                        // 1. 压入 Rust 私有数据库状态
                        rust_state.expires.insert(cidr.clone(), expire_at);

                        // 2. 压入绝对纯净、供 sing-box 正常读取的结构体
                        if sb_config.rules.is_empty() { sb_config.rules.push(SingBoxRule::default()); }
                        // 🌟 核心修复 1：通过 [0] 索引访问 Vec 数组内的规则对象
                        if ip_set.insert(cidr.clone()) {
                            sb_config.rules[0].source_ip_cidr.push(cidr.clone());
                        }

                        heap.push(ExpireNode { cidr, expire_at });
                        if should_rebuild_heap(heap.len(), rust_state.expires.len()) {
                            heap = rebuild_expire_heap(&rust_state);
                        }
                        is_dirty = true;
                    }
                    RegistryCmd::ClearAll => {
                        rust_state.expires.clear();
                        ip_set.clear();
                        // 🌟 核心修复 2：通过 [0] 索引访问 Vec 数组内对象并清空
                        if !sb_config.rules.is_empty() { sb_config.rules[0].source_ip_cidr.clear(); }
                        heap.clear();

                        is_dirty = !persist_configs(&json_path, &db_path, &sb_config, &rust_state).await;
                    }
                }
            }
            _ = ticker.tick() => {
                let now = current_timestamp();
                let mut has_expired = false;

                while let Some(node) = heap.peek() {
                    if now >= node.expire_at {
                        if let Some(expired_node) = heap.pop() {
                            if let Some(&real_expire) = rust_state.expires.get(&expired_node.cidr) {
                                if now >= real_expire {
                                    // 1. 从 Rust 私有状态释放
                                    rust_state.expires.remove(&expired_node.cidr);

                                    // 2. 从纯净的 sing-box 白名单中安全剔除
                                    // 🌟 核心修复 3：通过 [0] 索引安全调用数组的 retain 过滤
                                    if !sb_config.rules.is_empty() {
                                        ip_set.remove(&expired_node.cidr);
                                        sb_config.rules[0].source_ip_cidr.retain(|x| x != &expired_node.cidr);
                                    }
                                    has_expired = true;
                                    println!("⏱️ [自动销毁] IP {} 授权已满，注册中心成功将其从白名单中安全剥离。", expired_node.cidr);
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }

                if has_expired || is_dirty {
                    is_dirty = !persist_configs(&json_path, &db_path, &sb_config, &rust_state).await;
                }
            }
        }
    }
}

fn should_rebuild_heap(heap_len: usize, live_len: usize) -> bool {
    heap_len > live_len.saturating_mul(4).saturating_add(1024)
}

fn rebuild_expire_heap(rust_state: &RustRegistryState) -> BinaryHeap<ExpireNode> {
    rust_state
        .expires
        .iter()
        .map(|(cidr, &expire_at)| ExpireNode {
            cidr: cidr.clone(),
            expire_at,
        })
        .collect()
}

// 辅助文件读取：sing-box 白名单文件
fn load_singbox_config(path: &str) -> SingBoxConfig {
    match fs::read_to_string(path) {
        Ok(content) => {
            serde_json::from_str::<SingBoxConfig>(&content).unwrap_or_else(|_| SingBoxConfig {
                version: 1,
                rules: vec![SingBoxRule::default()],
            })
        }
        Err(_) => SingBoxConfig {
            version: 1,
            rules: vec![SingBoxRule::default()],
        },
    }
}

// 辅助文件读取：Rust 持久化时间戳状态
fn load_rust_state(path: &str) -> RustRegistryState {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str::<RustRegistryState>(&content).unwrap_or_else(|_| {
            RustRegistryState {
                expires: HashMap::new(),
            }
        }),
        Err(_) => RustRegistryState {
            expires: HashMap::new(),
        },
    }
}

// 辅助数据双写落盘
async fn persist_configs(
    json_path: &str,
    db_path: &str,
    sb_config: &SingBoxConfig,
    rust_state: &RustRegistryState,
) -> bool {
    match save_configs(json_path, db_path, sb_config, rust_state).await {
        Ok(()) => true,
        Err(err) => {
            eprintln!("⚠️ [注册中心] 保存白名单或状态文件失败: {}", err);
            false
        }
    }
}

async fn save_configs(
    json_path: &str,
    db_path: &str,
    sb_config: &SingBoxConfig,
    rust_state: &RustRegistryState,
) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(json_path).parent() {
        async_fs::create_dir_all(parent).await?;
    }
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        async_fs::create_dir_all(parent).await?;
    }

    write_json_atomic(json_path, sb_config).await?;
    write_json_atomic(db_path, rust_state).await?;

    Ok(())
}

async fn write_json_atomic<T: Serialize>(path: &str, value: &T) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    let path = std::path::Path::new(path);
    let temp_name = path
        .file_name()
        .map(|name| format!("{}.tmp.{}", name.to_string_lossy(), std::process::id()))
        .unwrap_or_else(|| format!("ip_whitelist.tmp.{}", std::process::id()));
    let temp_path = path.with_file_name(temp_name);

    async_fs::write(&temp_path, json).await?;
    async_fs::rename(temp_path, path).await
}

// 1️⃣ 接口：客户端上报注册 IP
async fn report_ip_handler(
    State(ctx): State<Arc<AppContext>>,
    Path((secret, _user)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if secret != ctx.config.secret_key {
        return proxy_to_fake(&ctx, Method::GET, uri, headers, None).await;
    }

    let client_ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1")
        .to_string();

    let Ok(client_ip_addr) = client_ip.parse::<IpAddr>() else {
        eprintln!("⚠️ [IP上报] 收到无效 cf-connecting-ip: {}", client_ip);
        return StatusCode::BAD_REQUEST.into_response();
    };
    let client_ip = client_ip_addr.to_string();

    let cidr = match client_ip_addr {
        IpAddr::V4(ip) => format!("{}/32", ip),
        IpAddr::V6(ip) => format!("{}/128", ip),
    };

    if ctx
        .tx
        .send(RegistryCmd::Register(
            cidr,
            ctx.config.expiration_hours * 3600,
        ))
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    if client_wants_html(&headers) {
        return Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .header("cache-control", "no-store")
            .body(axum::body::Body::from(report_ip_html(&client_ip)))
            .unwrap();
    }

    Response::builder()
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .body(axum::body::Body::from(format!("{}\n", client_ip)))
        .unwrap()
}

fn client_wants_html(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

fn report_ip_html(client_ip: &str) -> String {
    let client_ip = escape_html(client_ip);

    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>IP Address</title>
  <style>
    html{height:100%}
    body{min-height:100%;margin:0;display:grid;place-items:center;font-family:Arial,Helvetica,sans-serif;background:#f7f8fa;color:#1f2933}
    main{width:min(92vw,760px);padding:32px 20px;text-align:center}
    .label{font-size:18px;font-weight:600;color:#5f6b7a;margin-bottom:14px}
    .ip{font-size:44px;line-height:1.18;font-weight:700;word-break:break-all;overflow-wrap:anywhere}
    @media (max-width:640px){main{width:100%;box-sizing:border-box;padding:28px 18px}.label{font-size:16px}.ip{font-size:30px;line-height:1.25}}
  </style>
</head>
<body>
  <main>
    <div class="label">Your IP</div>
    <div class="ip">__CLIENT_IP__</div>
  </main>
</body>
</html>"#
        .replace("__CLIENT_IP__", &client_ip)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// 2️⃣ 接口：一键清理白名单
async fn clear_ip_handler(
    State(ctx): State<Arc<AppContext>>,
    Path((clear_secret, target)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if clear_secret != ctx.config.clear_secret_key {
        return proxy_to_fake(&ctx, Method::GET, uri, headers, None).await;
    }

    if target.to_lowercase() == "all" && ctx.tx.send(RegistryCmd::ClearAll).await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    Redirect::temporary(&clear_redirect_target(&ctx, &headers)).into_response()
}

// 3️⃣ 接口：全局未匹配路由
async fn proxy_to_fake_handler(
    State(ctx): State<Arc<AppContext>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response {
    proxy_to_fake(&ctx, method, uri, headers, Some(body)).await
}

// 🌐 反向代理底层实现
async fn proxy_to_fake(
    ctx: &AppContext,
    method: Method,
    uri: Uri,
    mut headers: HeaderMap,
    body: Option<bytes::Bytes>,
) -> Response {
    if proxy_target_is_current_host(ctx, &headers) {
        return local_fake_response(&uri);
    }

    let base_fake_url = ctx.config.fake_website.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("");
    let target_url = format!("{}{}", base_fake_url, path_and_query);
    let fake_origin = fake_origin(&ctx.config.fake_website);
    let public_origin = public_origin_from_headers(&headers);

    sanitize_proxy_request_headers(&mut headers);

    let mut req_builder = ctx
        .http_client
        .request(method, &target_url)
        .headers(headers);
    if let Some(b) = body {
        if !b.is_empty() {
            req_builder = req_builder.body(b);
        }
    }

    match req_builder.send().await {
        Ok(res) => {
            let mut resp_builder = Response::builder().status(res.status().as_u16());
            let headers = res.headers().clone();

            for (key, value) in headers.iter() {
                if !should_skip_proxy_response_header(key) {
                    let value = if key == LOCATION {
                        rewrite_location_header(
                            value,
                            fake_origin.as_deref(),
                            public_origin.as_deref(),
                        )
                        .unwrap_or_else(|| value.clone())
                    } else {
                        value.clone()
                    };

                    resp_builder = resp_builder.header(key.as_str(), value);
                }
            }
            resp_builder
                .body(axum::body::Body::from_stream(res.bytes_stream()))
                .unwrap()
        }
        Err(err) => {
            eprintln!("⚠️ [伪装反代] 请求伪装站失败: {}", err);
            local_fake_response(&uri)
        }
    }
}

fn sanitize_proxy_request_headers(headers: &mut HeaderMap) {
    for name in [
        HOST.as_str(),
        CONNECTION.as_str(),
        CONTENT_LENGTH.as_str(),
        PROXY_AUTHENTICATE.as_str(),
        PROXY_AUTHORIZATION.as_str(),
        TE.as_str(),
        TRAILER.as_str(),
        TRANSFER_ENCODING.as_str(),
        UPGRADE.as_str(),
        "keep-alive",
        "cf-connecting-ip",
        "cf-ipcountry",
        "cf-ray",
        "cf-visitor",
        "cf-worker",
        "cf-ew-via",
        "cdn-loop",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    ] {
        headers.remove(name);
    }

    headers.insert(ACCEPT_ENCODING, "identity".parse().unwrap());
}

fn should_skip_proxy_response_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "server"
            | "cf-ray"
    )
}

fn clear_redirect_target(ctx: &AppContext, headers: &HeaderMap) -> String {
    if fake_website_is_local(&ctx.config.fake_website) || proxy_target_is_current_host(ctx, headers)
    {
        "/".to_string()
    } else {
        format!("{}/", ctx.config.fake_website.trim_end_matches('/'))
    }
}

fn fake_website_is_local(fake_website: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(fake_website) else {
        return false;
    };

    let Some(host) = url.host_str().map(normalize_host) else {
        return false;
    };

    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn proxy_target_is_current_host(ctx: &AppContext, headers: &HeaderMap) -> bool {
    let Some(current_host) = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(HOST))
        .and_then(|value| value.to_str().ok())
        .map(normalize_host)
    else {
        return false;
    };

    let Ok(fake_url) = reqwest::Url::parse(&ctx.config.fake_website) else {
        return false;
    };

    fake_url
        .host_str()
        .map(normalize_host)
        .is_some_and(|fake_host| fake_host == current_host)
}

fn fake_origin(fake_website: &str) -> Option<String> {
    let url = reqwest::Url::parse(fake_website).ok()?;
    origin_from_url(&url)
}

fn origin_from_url(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    let host = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    let port = url
        .port()
        .map(|port| format!(":{}", port))
        .unwrap_or_default();

    Some(format!("{}://{}{}", url.scheme(), host, port))
}

fn public_origin_from_headers(headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(HOST))
        .and_then(|value| value.to_str().ok())?;

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|scheme| *scheme == "http" || *scheme == "https")
        .unwrap_or("https");

    Some(format!("{}://{}", scheme, host))
}

fn rewrite_location_header(
    value: &HeaderValue,
    fake_origin: Option<&str>,
    public_origin: Option<&str>,
) -> Option<HeaderValue> {
    let fake_origin = fake_origin?;
    let public_origin = public_origin?;
    let location = value.to_str().ok()?;
    let path = location.strip_prefix(fake_origin)?;

    HeaderValue::from_str(&format!("{}{}", public_origin, path)).ok()
}

fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');

    if let Some(stripped) = host.strip_prefix('[') {
        if let Some((ipv6_host, _)) = stripped.split_once(']') {
            return ipv6_host.to_ascii_lowercase();
        }
    }
    if host.matches(':').count() > 1 {
        return host.to_ascii_lowercase();
    }

    host.split_once(':')
        .map(|(host_only, _)| host_only)
        .unwrap_or(host)
        .to_ascii_lowercase()
}

fn local_fake_response(uri: &Uri) -> Response {
    if uri.path() == "/" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(axum::body::Body::from(
                r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Welcome</title>
  <style>
    body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#f7f7f8;color:#222}
    main{min-height:100vh;display:grid;place-items:center}
    section{max-width:560px;padding:40px 24px;text-align:center}
    h1{font-size:32px;font-weight:600;margin:0 0 12px}
    p{font-size:16px;line-height:1.6;margin:0;color:#666}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Welcome</h1>
      <p>The site is running.</p>
    </section>
  </main>
</body>
</html>"#,
            ))
            .unwrap();
    }

    StatusCode::NOT_FOUND.into_response()
}
