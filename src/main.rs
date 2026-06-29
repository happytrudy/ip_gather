use axum::{
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::{any, get},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BinaryHeap, HashMap},
    cmp::Ordering,
    env,
    fs,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

// 映射 config.toml 的结构体
#[derive(Deserialize, Clone)]
struct AppConfig {
    secret_key: String,
    clear_secret_key: String,
    fake_website: String,
    json_path: String,
    listen_address: String,
    expiration_hours: u64,
}

// 扩展 sing-box 结构，带上过期的注册对照表
#[derive(Serialize, Deserialize, Clone, Default)]
struct SingBoxRule {
    source_ip_cidr: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct SingBoxConfig {
    version: u32,
    rules: Vec<SingBoxRule>,
    #[serde(default)]
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

enum RegistryCmd {
    Register(String, u64), 
    ClearAll,              
}

struct AppContext {
    config: AppConfig,
    tx: mpsc::Sender<RegistryCmd>,
    http_client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    // 🌟 核心改进：解析命令行参数以支持自定义配置文件路径
    let args: Vec<String> = env::args().collect();
    let mut config_path = "config.toml".to_string(); // 默认路径

    let mut i = 1;
    while i < args.len() {
        if (args[i] == "-c" || args[i] == "--config") && i + 1 < args.len() {
            config_path = args[i + 1].clone();
            break;
        }
        i += 1;
    }

    println!("📖 [配置加载] 正在尝试从路径读取配置: {}", config_path);

    // 读取并解析 TOML 配置文件
    let config_str = fs::read_to_string(&config_path)
        .unwrap_or_else(|_| panic!("❌ 错误：无法在 [{}] 找到有效的配置文件，请检查路径是否正确", config_path));
        
    let config: AppConfig = toml::from_str(&config_str)
        .expect("❌ 错误：解析配置文件失败，请检查 TOML 语法格式是否正确");

    let listen_addr = config.listen_address.clone();
    let json_path = config.json_path.clone();
    
    // 初始化异步通道
    let (tx, rx) = mpsc::channel::<RegistryCmd>(256);
    
    // 启动后台单线程注册中心任务
    tokio::spawn(registry_center_loop(json_path, rx));

    // 初始化全局唯一的复用 HTTP 客户端
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
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

    let app = Router::new()
        .route("/ip/:secret/:user", get(report_ip_handler))
        .route("/system/:clear_secret/:target", get(clear_ip_handler))
        .fallback(any(proxy_to_fake_handler)) 
        .with_state(shared_context); 

    println!("🏆 [毫无遗憾·支持传参版] 服务启动成功！监听: {}", listen_addr);
    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// 注册中心常驻任务
async fn registry_center_loop(json_path: String, mut rx: mpsc::Receiver<RegistryCmd>) {
    let mut db = load_config(&json_path);
    let mut heap = BinaryHeap::new();
    for (cidr, &expire_at) in db.expires.iter() {
        heap.push(ExpireNode { cidr: cidr.clone(), expire_at });
    }

    let mut is_dirty = false;
    let mut ticker = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            Some(cmd) = rx.recv() => {
                match cmd {
                    RegistryCmd::Register(cidr, duration_secs) => {
                        let expire_at = current_timestamp() + duration_secs;
                        db.expires.insert(cidr.clone(), expire_at);
                        
                        if db.rules.is_empty() { db.rules.push(SingBoxRule::default()); }
                        let ip_list = &mut db.rules[0].source_ip_cidr;
                        if !ip_list.contains(&cidr) {
                            ip_list.push(cidr.clone());
                        }
                        
                        heap.push(ExpireNode { cidr, expire_at });
                        is_dirty = true;
                    }
                    RegistryCmd::ClearAll => {
                        db.expires.clear();
                        if !db.rules.is_empty() { db.rules[0].source_ip_cidr.clear(); }
                        heap.clear();
                        save_config(&json_path, &db);
                        is_dirty = false;
                    }
                }
            }
            _ = ticker.tick() => {
                let now = current_timestamp();
                let mut has_expired = false;

                while let Some(node) = heap.peek() {
                    if now >= node.expire_at {
                        if let Some(expired_node) = heap.pop() {
                            if let Some(&real_expire) = db.expires.get(&expired_node.cidr) {
                                if now >= real_expire {
                                    db.expires.remove(&expired_node.cidr);
                                    if !db.rules.is_empty() {
                                        db.rules[0].source_ip_cidr.retain(|x| x != &expired_node.cidr);
                                    }
                                    has_expired = true;
                                    println!("⏱️ [自动销毁] IP {} 授权过期，注册中心安全移除。", expired_node.cidr);
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }

                if has_expired || is_dirty {
                    save_config(&json_path, &db);
                    is_dirty = false;
                }
            }
        }
    }
}

fn load_config(path: &str) -> SingBoxConfig {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str::<SingBoxConfig>(&content).unwrap_or_else(|_| SingBoxConfig {
            version: 1, rules: vec![SingBoxRule::default()], expires: HashMap::new()
        }),
        Err(_) => SingBoxConfig { version: 1, rules: vec![SingBoxRule::default()], expires: HashMap::new() }
    }
}
fn save_config(path: &str, config: &SingBoxConfig) {
    if let Some(parent) = std::path::Path::new(path).parent() { let _ = fs::create_dir_all(parent); }
    let json_str = serde_json::to_string_pretty(config).unwrap();
    let _ = fs::write(path, json_str);
}

// 1️⃣ 接口：客户端上报 IP
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

    let cidr = if client_ip.contains(':') { format!("{}/128", client_ip) } else { format!("{}/32", client_ip) };

    let _ = ctx.tx.send(RegistryCmd::Register(cidr, ctx.config.expiration_hours * 3600)).await;

    Response::builder()
        .header("content-type", "text/plain; charset=utf-8")
        .body(axum::body::Body::from(format!("{}\n", client_ip)))
        .unwrap()
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

    if target.to_lowercase() == "all" {
        let _ = ctx.tx.send(RegistryCmd::ClearAll).await;
    }

    Redirect::temporary(&format!("{}/", ctx.config.fake_website)).into_response()
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
    body: Option<bytes::Bytes>
) -> Response {
    let base_fake_url = ctx.config.fake_website.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("");
    let target_url = format!("{}{}", base_fake_url, path_and_query);

    headers.remove("host"); 
    
    let mut req_builder = ctx.http_client.request(method, &target_url).headers(headers);
    if let Some(b) = body { if !b.is_empty() { req_builder = req_builder.body(b); } }

    match req_builder.send().await {
        Ok(res) => {
            let mut resp_builder = Response::builder().status(res.status().as_u16());
            for (key, value) in res.headers().iter() {
                if key != "server" && key != "cf-ray" { 
                    resp_builder = resp_builder.header(key.as_str(), value.clone()); 
                }
            }
            let bytes = res.bytes().await.unwrap_or_default();
            resp_builder.body(axum::body::Body::from(bytes)).unwrap()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(), 
    }
}
