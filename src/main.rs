mod tui;

use clap::Parser;
use futures_util::stream::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::UPGRADE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use once_cell::sync::Lazy;
use regex::Regex;
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::sleep;
use tracing::{error, info, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

// Compile regex once at startup
static PORT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https?://(?:localhost|127\.0\.0\.1|[\w\-\.]+):(\d+)").unwrap()
});

#[derive(Parser, Debug)]
#[command(name = "dev-proxy")]
#[command(about = "Multi-server on-demand development proxy (like puma-dev)", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to symlink directory
    #[arg(short, long, global = true)]
    dir: Option<String>,

    /// Port to listen on (for run command)
    #[arg(short, long, default_value = "3000", global = true)]
    port: u16,

    /// Domain suffix (for run command)
    #[arg(short = 's', long, default_value = "test", global = true)]
    domain_suffix: String,

    /// Enable TUI mode with split-panel interface
    #[arg(long, global = true)]
    ui: bool,
}

#[derive(Parser, Debug)]
enum Command {
    /// Add a new dev server
    Add {
        /// Name of the server (becomes <name>.test)
        name: String,
        /// Path to the project directory
        path: String,
    },
    /// Remove a dev server
    Remove {
        /// Name of the server to remove
        name: String,
    },
    /// List all configured dev servers
    List,
}

#[derive(Debug, Clone)]
struct ServerConfig {
    name: String,
    domain: String,
    directory: String,
    command: String,
    args: Vec<String>,
    idle_timeout: u64,
    startup_wait: u64,
}

impl ServerConfig {
    fn new(name: String, directory: String, domain_suffix: &str) -> std::io::Result<Self> {
        let domain = format!("{}.{}", name, domain_suffix);

        // Auto-detect package manager
        let (command, args) = detect_package_manager(&directory)?;

        Ok(Self {
            name,
            domain,
            directory,
            command,
            args,
            idle_timeout: 900,  // 15 minutes
            startup_wait: 15,   // 15 seconds for detection
        })
    }
}

fn detect_package_manager(directory: &str) -> std::io::Result<(String, Vec<String>)> {
    let path = std::path::Path::new(directory);

    // Check for lock files to determine package manager
    if path.join("pnpm-lock.yaml").exists() {
        Ok(("pnpm".to_string(), vec!["dev".to_string()]))
    } else if path.join("yarn.lock").exists() {
        Ok(("yarn".to_string(), vec!["dev".to_string()]))
    } else if path.join("package.json").exists() {
        Ok(("npm".to_string(), vec!["run".to_string(), "dev".to_string()]))
    } else {
        // Default to npm
        Ok(("npm".to_string(), vec!["run".to_string(), "dev".to_string()]))
    }
}

fn scan_symlinks_directory(dir_path: &str, domain_suffix: &str, verbose: bool) -> std::io::Result<Vec<ServerConfig>> {
    let path = std::path::Path::new(dir_path);

    if !path.exists() {
        // Create the directory if it doesn't exist
        std::fs::create_dir_all(dir_path)?;
        if verbose {
            info!("Created directory: {}", dir_path);
        }
        return Ok(Vec::new());
    }

    let mut servers = Vec::new();

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();

        // Check if it's a symlink
        if entry_path.is_symlink() {
            let name = entry.file_name().to_string_lossy().to_string();

            // Resolve the symlink to get the actual directory
            match std::fs::read_link(&entry_path) {
                Ok(target_path) => {
                    let directory = target_path.to_string_lossy().to_string();

                    match ServerConfig::new(name.clone(), directory, domain_suffix) {
                        Ok(config) => {
                            if verbose {
                                info!("   📌 {} → {}", config.domain, config.directory);
                            }
                            servers.push(config);
                        }
                        Err(e) => {
                            if verbose {
                                warn!("   ⚠️  Skipping {}: {}", name, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if verbose {
                        warn!("   ⚠️  Failed to read symlink {}: {}", name, e);
                    }
                }
            }
        }
    }

    Ok(servers)
}

fn get_default_symlinks_dir() -> String {
    if let Ok(home) = std::env::var("HOME") {
        format!("{}/.dev-proxy", home)
    } else {
        ".dev-proxy".to_string()
    }
}

fn cmd_add(symlinks_dir: &str, name: &str, path: &str, domain_suffix: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create symlinks directory if it doesn't exist
    std::fs::create_dir_all(symlinks_dir)?;

    let link_path = std::path::Path::new(symlinks_dir).join(name);

    // Validate the target path
    let path_obj = std::path::Path::new(path);

    if !path_obj.exists() {
        return Err(format!("Path does not exist: {}", path).into());
    }

    if !path_obj.is_dir() {
        return Err(format!("Path is not a directory: {}", path).into());
    }

    let target_path = path_obj.canonicalize()?;

    if link_path.exists() {
        return Err(format!("Server '{}' already exists. Remove it first with: dev-proxy remove {}", name, name).into());
    }

    // Create the symlink
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_path, &link_path)?;

    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&target_path, &link_path)?;

    println!("✅ Added {} → {}", name, target_path.display());
    println!("   Access at http://{}.{}", name, domain_suffix);

    Ok(())
}

fn cmd_remove(symlinks_dir: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let link_path = std::path::Path::new(symlinks_dir).join(name);

    if !link_path.exists() {
        return Err(format!("Server '{}' not found", name).into());
    }

    if !link_path.is_symlink() {
        return Err(format!("'{}' is not a symlink, refusing to remove", name).into());
    }

    // Read the symlink target before removing (for display)
    let target = std::fs::read_link(&link_path)?;

    std::fs::remove_file(&link_path)?;

    println!("✅ Removed {} (was pointing to {})", name, target.display());

    Ok(())
}

fn cmd_list(symlinks_dir: &str, domain_suffix: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::Path::new(symlinks_dir);

    if !path.exists() {
        println!("No servers configured yet.");
        println!("Add one with: dev-proxy add <name> <path>");
        return Ok(());
    }

    let mut servers = Vec::new();

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();

        if entry_path.is_symlink() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(target) = std::fs::read_link(&entry_path) {
                servers.push((name, target));
            }
        }
    }

    if servers.is_empty() {
        println!("No servers configured yet.");
        println!("Add one with: dev-proxy add <name> <path>");
        return Ok(());
    }

    println!("Configured servers:");
    println!();
    for (name, target) in servers {
        println!("  {} → http://{}.{}", name, name, domain_suffix);
        println!("    {}", target.display());
        println!();
    }

    Ok(())
}

struct DevServer {
    config: ServerConfig,
    process: Option<tokio::process::Child>,
    last_activity: Instant,
    is_starting: bool,
    detected_port: Option<u16>,
    connection_semaphore: Arc<Semaphore>,
    log_tx: Option<mpsc::UnboundedSender<(String, String)>>,
}

impl DevServer {
    fn new(config: ServerConfig) -> Self {
        Self {
            config,
            process: None,
            last_activity: Instant::now(),
            is_starting: false,
            detected_port: None,
            connection_semaphore: Arc::new(Semaphore::new(20)), // Max 20 concurrent connections per server
            log_tx: None,
        }
    }

    fn set_log_sender(&mut self, tx: mpsc::UnboundedSender<(String, String)>) {
        self.log_tx = Some(tx);
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.process.is_some() || self.is_starting {
            return Ok(());
        }

        self.is_starting = true;
        info!("🚀 [{}] Starting dev server (auto-detecting port)...", self.config.name);

        // Send status to TUI
        if let Some(tx) = &self.log_tx {
            let _ = tx.send((self.config.name.clone(), "🚀 Starting dev server...".to_string()));
        }

        let mut cmd = TokioCommand::new(&self.config.command);
        cmd.args(&self.config.args)
            .current_dir(&self.config.directory)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        // Spawn tasks to read stdout and stderr and detect port
        let detected_port = Arc::new(Mutex::new(None::<u16>));
        let log_tx = self.log_tx.clone();

        if let Some(stdout) = child.stdout.take() {
            let detected_port = detected_port.clone();
            let name = self.config.name.clone();
            let log_tx = log_tx.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    // Send to TUI if enabled
                    if let Some(tx) = &log_tx {
                        let _ = tx.send((name.clone(), line.clone()));
                    } else {
                        println!("[{}] {}", name, line);
                    }

                    if let Some(caps) = PORT_REGEX.captures(&line) {
                        if let Some(port_str) = caps.get(1) {
                            if let Ok(port) = port_str.as_str().parse::<u16>() {
                                let mut detected = detected_port.lock().await;
                                if detected.is_none() {
                                    *detected = Some(port);
                                    info!("🔍 [{}] Detected port: {}", name, port);
                                    // Also send to TUI
                                    if let Some(tx) = &log_tx {
                                        let _ = tx.send((name.clone(), format!("🔍 Detected port: {}", port)));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let detected_port = detected_port.clone();
            let name = self.config.name.clone();
            let log_tx = log_tx.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    // Send to TUI if enabled
                    if let Some(tx) = &log_tx {
                        let _ = tx.send((name.clone(), line.clone()));
                    } else {
                        eprintln!("[{}] {}", name, line);
                    }

                    if let Some(caps) = PORT_REGEX.captures(&line) {
                        if let Some(port_str) = caps.get(1) {
                            if let Ok(port) = port_str.as_str().parse::<u16>() {
                                let mut detected = detected_port.lock().await;
                                if detected.is_none() {
                                    *detected = Some(port);
                                    info!("🔍 [{}] Detected port: {}", name, port);
                                    // Also send to TUI
                                    if let Some(tx) = &log_tx {
                                        let _ = tx.send((name.clone(), format!("🔍 Detected port: {}", port)));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        self.process = Some(child);

        // Wait for server to be ready and port to be detected
        let start_time = Instant::now();
        let timeout = Duration::from_secs(self.config.startup_wait);

        loop {
            sleep(Duration::from_millis(100)).await;
            let port = detected_port.lock().await;
            if port.is_some() {
                self.detected_port = *port;
                break;
            }
            if start_time.elapsed() > timeout {
                warn!("⚠️  [{}] Could not detect port, waited {}s", self.config.name, self.config.startup_wait);
                break;
            }
        }

        if let Some(port) = self.detected_port {
            // Brief wait for server to accept connections
            sleep(Duration::from_millis(500)).await;
            self.is_starting = false;
            info!("✅ [{}] Dev server ready on port {}", self.config.name, port);

            // Send status to TUI
            if let Some(tx) = &self.log_tx {
                let _ = tx.send((self.config.name.clone(), format!("✅ Dev server ready on port {}", port)));
            }
        } else {
            // Port detection failed - kill the child process to prevent resource leak
            if let Some(mut child) = self.process.take() {
                warn!("Killing dev server process due to port detection failure");
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
            self.is_starting = false;
            error!("❌ [{}] Failed to detect port", self.config.name);
            return Err("Failed to detect port".into());
        }

        Ok(())
    }

    fn get_target_port(&self) -> Option<u16> {
        self.detected_port
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            info!("💤 [{}] Stopping dev server due to inactivity...",
                  self.config.name);

            // Send status to TUI
            if let Some(tx) = &self.log_tx {
                let _ = tx.send((self.config.name.clone(), "💤 Stopping due to inactivity...".to_string()));
            }

            let _ = child.start_kill();
        }
        self.detected_port = None;
    }

    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn should_stop(&self) -> bool {
        self.process.is_some()
            && self.last_activity.elapsed() > Duration::from_secs(self.config.idle_timeout)
    }
}

type ServerMap = Arc<Mutex<HashMap<String, DevServer>>>;

fn empty_body() -> BoxBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

async fn proxy_request<C>(
    req: Request<Incoming>,
    server_map: ServerMap,
    client: Arc<Client<C, Full<Bytes>>>,
) -> Result<Response<BoxBody>, std::convert::Infallible>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    let is_ws = is_websocket_upgrade(&req);

    // Extract domain from Host header
    let domain = match req.headers().get("host") {
        Some(host_header) => {
            match host_header.to_str() {
                Ok(host) => {
                    // Remove port if present (e.g., "localhost:3000" -> "localhost")
                    host.split(':').next().unwrap_or(host).to_string()
                }
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(full_body("Invalid Host header"))
                        .unwrap());
                }
            }
        }
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full_body("Missing Host header"))
                .unwrap());
        }
    };

    // Update activity and check if we need to start
    {
        let mut servers = server_map.lock().await;
        let server = match servers.get_mut(&domain) {
            Some(s) => s,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body(format!("No server configured for domain: {}", domain)))
                    .unwrap());
            }
        };

        server.update_activity();

        // Start server if needed
        if server.process.is_none() && !server.is_starting {
            if let Err(e) = server.start().await {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full_body(format!("Failed to start server: {}", e)))
                    .unwrap());
            }
        }
    }

    // Wait if starting (with timeout to prevent hanging)
    let wait_start = Instant::now();
    let max_wait = Duration::from_secs(30);

    loop {
        let is_starting = {
            let servers = server_map.lock().await;
            servers.get(&domain)
                .map(|s| s.is_starting)
                .unwrap_or(false)
        };

        if !is_starting {
            break;
        }

        if wait_start.elapsed() > max_wait {
            warn!("Timeout waiting for server to start");
            return Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(full_body("Server startup timeout"))
                .unwrap());
        }

        sleep(Duration::from_millis(100)).await;
    }

    // Get target port and semaphore
    let (target_port, semaphore) = {
        let servers = server_map.lock().await;
        match servers.get(&domain) {
            Some(server) => match server.get_target_port() {
                Some(port) => (port, server.connection_semaphore.clone()),
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full_body("Dev server port not detected"))
                        .unwrap());
                }
            },
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body(format!("No server configured for domain: {}", domain)))
                    .unwrap());
            }
        }
    };

    // Acquire a permit to limit concurrent connections to this backend
    let _permit = semaphore.acquire().await.unwrap();

    // Handle WebSocket upgrade
    if is_ws {
        info!("🔌 [{}] WebSocket upgrade request", domain);

        // Build the backend request URI
        let uri_string = format!(
            "http://localhost:{}{}",
            target_port,
            req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
        );

        let uri: hyper::Uri = match uri_string.parse() {
            Ok(u) => u,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full_body(format!("Invalid URI: {}", e)))
                    .unwrap());
            }
        };

        // Build WebSocket upgrade request for backend
        let mut backend_req = hyper::Request::builder()
            .method(req.method())
            .uri(uri);

        // Forward all headers
        for (name, value) in req.headers().iter() {
            if name != "host" {
                backend_req = backend_req.header(name, value);
            }
        }

        backend_req = backend_req.header("host", format!("localhost:{}", target_port));

        let backend_req = match backend_req.body(Full::new(Bytes::new())) {
            Ok(r) => r,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full_body(format!("Failed to build WebSocket request: {}", e)))
                    .unwrap());
            }
        };

        // Send upgrade request to backend
        let mut backend_response = match client.request(backend_req).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Failed to send WebSocket upgrade to backend: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full_body("Failed to connect to backend"))
                    .unwrap());
            }
        };

        // Check if backend accepted the upgrade
        if backend_response.status() != StatusCode::SWITCHING_PROTOCOLS {
            warn!("Backend rejected WebSocket upgrade: {}", backend_response.status());
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("Backend rejected WebSocket upgrade"))
                .unwrap());
        }

        // Forward response headers from backend
        let mut resp_builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);

        for (name, value) in backend_response.headers().iter() {
            resp_builder = resp_builder.header(name, value);
        }

        // Spawn task to tunnel the upgraded connections
        tokio::spawn(async move {
            // Upgrade both connections
            let client_upgrade_fut = hyper::upgrade::on(req);
            let backend_upgrade_fut = hyper::upgrade::on(&mut backend_response);

            match tokio::try_join!(client_upgrade_fut, backend_upgrade_fut) {
                Ok((client_upgraded, backend_upgraded)) => {
                    info!("🔌 WebSocket tunnel established");
                    let mut client = TokioIo::new(client_upgraded);
                    let mut backend = TokioIo::new(backend_upgraded);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
                    info!("🔌 WebSocket tunnel closed");
                }
                Err(e) => {
                    warn!("Failed to upgrade connections: {}", e);
                }
            }
        });

        return Ok(resp_builder.body(empty_body()).unwrap());
    }

    // Regular HTTP request handling
    let (parts, body) = req.into_parts();

    // Build the proxied request URI
    let uri_string = format!(
        "http://localhost:{}{}",
        target_port,
        parts.uri.path_and_query().map(|x| x.as_str()).unwrap_or("/")
    );

    let uri: hyper::Uri = match uri_string.parse() {
        Ok(u) => u,
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full_body(format!("Invalid URI: {}", e)))
                .unwrap());
        }
    };

    // Collect the incoming body
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full_body("Failed to read request body"))
                .unwrap());
        }
    };

    // Create new request with the collected body
    let mut proxy_req = hyper::Request::builder()
        .method(parts.method)
        .uri(uri.clone());

    // Forward headers (except Host, which should be for the target)
    for (name, value) in parts.headers.iter() {
        if name != "host" {
            proxy_req = proxy_req.header(name, value);
        }
    }

    // Set the new Host header for the target
    proxy_req = proxy_req.header("host", format!("localhost:{}", target_port));

    let proxy_req = match proxy_req.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full_body(format!("Failed to build proxy request: {}", e)))
                .unwrap());
        }
    };

    // Send the request (server should be ready due to verification above)
    match client.request(proxy_req).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();

            // Build response with forwarded headers and stream the body
            let mut resp_builder = Response::builder().status(parts.status);

            for (name, value) in parts.headers.iter() {
                resp_builder = resp_builder.header(name, value);
            }

            // Stream the body without buffering
            Ok(resp_builder.body(body.boxed()).unwrap())
        }
        Err(e) => {
            warn!("Failed to proxy request: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("Dev server not ready"))
                .unwrap())
        }
    }
}

async fn idle_checker(server_map: ServerMap) {
    loop {
        sleep(Duration::from_secs(30)).await;

        let mut servers = server_map.lock().await;
        for server in servers.values_mut() {
            if server.should_stop() {
                server.stop();
            }
        }
    }
}

async fn handle_signals(mut signals: Signals, server_map: ServerMap) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGTERM | SIGINT | SIGQUIT => {
                info!("Received shutdown signal, stopping all servers...");
                let mut servers = server_map.lock().await;
                for server in servers.values_mut() {
                    server.stop();
                }
                std::process::exit(0);
            }
            _ => {}
        }
    }
}

async fn start_proxy_server(
    proxy_port: u16,
    server_map: ServerMap,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    let listener = TcpListener::bind(addr).await?;

    info!("📡 Proxy listening on {}", addr);

    // Create a shared HTTP client for all requests with strict connection limits
    let client = Arc::new(
        Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(5)
            .pool_idle_timeout(Duration::from_secs(30))
            .build_http()
    );

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            let io = TokioIo::new(stream);
            let server_map = server_map.clone();
            let client = client.clone();

            tokio::task::spawn(async move {
                let service = service_fn(move |req| {
                    let server_map = server_map.clone();
                    let client = client.clone();
                    async move { proxy_request(req, server_map, client).await }
                });

                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    warn!("Error serving connection: {:?}", err);
                }
            });
        }
    });

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Get symlinks directory (default: ~/.dev-proxy)
    let symlinks_dir = args.dir.unwrap_or_else(get_default_symlinks_dir);

    // Handle subcommands
    match args.command {
        Some(Command::Add { name, path }) => {
            return cmd_add(&symlinks_dir, &name, &path, &args.domain_suffix);
        }
        Some(Command::Remove { name }) => {
            return cmd_remove(&symlinks_dir, &name);
        }
        Some(Command::List) => {
            return cmd_list(&symlinks_dir, &args.domain_suffix);
        }
        None => {
            // No subcommand - run the proxy server
        }
    }

    // From here on, we're running the proxy server
    // Only enable logging if not in TUI mode (TUI captures logs differently)
    if !args.ui {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("dev_proxy=info"))
            )
            .init();
    }

    if !args.ui {
        info!("🔍 Scanning {} for dev servers...", symlinks_dir);
    }

    // Scan for symlinks
    let server_configs = scan_symlinks_directory(&symlinks_dir, &args.domain_suffix, !args.ui)?;

    if server_configs.is_empty() {
        if args.ui {
            eprintln!("No servers found in {}", symlinks_dir);
            eprintln!("Add a server with: dev-proxy add <name> <path>");
            eprintln!("Example: dev-proxy add myapp ~/code/myapp");
        } else {
            error!("No servers found in {}", symlinks_dir);
            error!("Add a server with: dev-proxy add <name> <path>");
            error!("Example: dev-proxy add myapp ~/code/myapp");
        }
        std::process::exit(1);
    }

    if !args.ui {
        info!("🎯 DevProxy starting with {} servers on port {}", server_configs.len(), args.port);
    }

    // Initialize log collector if TUI mode is enabled
    let log_rx = if args.ui {
        let (tx, rx) = mpsc::unbounded_channel();
        Some((tx, rx))
    } else {
        None
    };

    // Initialize server map
    let server_map: ServerMap = Arc::new(Mutex::new(HashMap::new()));

    {
        let mut servers = server_map.lock().await;
        for server_config in server_configs.clone() {
            let mut dev_server = DevServer::new(server_config.clone());

            // Set log sender if TUI mode is enabled
            if let Some((ref tx, _)) = log_rx {
                dev_server.set_log_sender(tx.clone());
            }

            servers.insert(
                server_config.domain.clone(),
                dev_server,
            );
        }
    }

    // Start single proxy server
    start_proxy_server(args.port, server_map.clone()).await?;

    // Start idle checker
    let checker_map = server_map.clone();
    tokio::spawn(async move {
        idle_checker(checker_map).await;
    });

    // Setup signal handlers
    let signals = Signals::new([SIGTERM, SIGINT, SIGQUIT])?;
    let handle = signals.handle();
    let signal_map = server_map.clone();

    tokio::spawn(async move {
        handle_signals(signals, signal_map).await;
    });

    if !args.ui {
        info!("✨ DevProxy ready! Press Ctrl+C to stop.");
    }

    // Run TUI if enabled, otherwise just wait for Ctrl+C
    if let Some((_tx, log_rx)) = log_rx {
        // Build server info list for TUI
        let server_info: Vec<tui::ServerInfo> = server_configs
            .iter()
            .map(|config| tui::ServerInfo {
                name: config.name.clone(),
                domain: config.domain.clone(),
            })
            .collect();

        let tui_app = tui::TuiApp::new(server_info);

        // Run TUI in a blocking thread (not on async runtime)
        let tui_handle = tokio::task::spawn_blocking(move || {
            tui::run_tui_blocking(tui_app, log_rx)
        });

        // Wait for TUI to exit
        if let Err(e) = tui_handle.await {
            error!("TUI task error: {}", e);
        }

        // Shutdown signal handlers
        handle.close();

        // Stop all servers
        let mut servers = server_map.lock().await;
        for server in servers.values_mut() {
            server.stop();
        }
    } else {
        // Non-TUI mode - keep the main task alive
        tokio::signal::ctrl_c().await?;
        handle.close();
    }

    Ok(())
}
