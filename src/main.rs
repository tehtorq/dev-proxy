mod tui;

use chrono::{DateTime, Local};
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tokio::time::sleep;
use tracing::{error, info, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

// Compile regex once at startup
static PORT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https?://(?:localhost|127\.0\.0\.1|[\w\-\.]+):(\d+)").unwrap()
});

const STARTUP_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "dev-proxy")]
#[command(about = "Multi-server on-demand development proxy (like puma-dev)", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to symlink directory
    #[arg(short, long, global = true)]
    dir: Option<String>,

    /// Port to listen on
    #[arg(short, long, default_value = "3000", global = true)]
    port: u16,

    /// Domain suffix
    #[arg(short = 's', long, default_value = "test", global = true)]
    domain_suffix: String,

    /// Disable TUI mode (use plain logging instead)
    #[arg(long, global = true)]
    no_ui: bool,

    /// Idle timeout in seconds (0 = disabled)
    #[arg(long, default_value = "900", global = true)]
    idle_timeout: u64,
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

// ============================================================================
// Server Configuration
// ============================================================================

#[derive(Debug, Clone)]
struct ServerConfig {
    name: String,
    domain: String,
    directory: String,
    command: String,
    args: Vec<String>,
}

impl ServerConfig {
    fn new(name: String, directory: String, domain_suffix: &str) -> std::io::Result<Self> {
        let domain = format!("{}.{}", name, domain_suffix);
        let (command, args) = detect_package_manager(&directory)?;

        Ok(Self {
            name,
            domain,
            directory,
            command,
            args,
        })
    }
}

fn detect_package_manager(directory: &str) -> std::io::Result<(String, Vec<String>)> {
    let path = std::path::Path::new(directory);

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

// ============================================================================
// Process Management Helpers
// ============================================================================

/// Kill a process and its entire process group
#[cfg(unix)]
async fn kill_process_group(child: &mut tokio::process::Child, graceful: bool) {
    if let Some(pid) = child.id() {
        if graceful {
            // Try SIGTERM first for graceful shutdown
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
            // Give it 2 seconds to shut down gracefully
            tokio::select! {
                _ = child.wait() => return,
                _ = sleep(Duration::from_secs(2)) => {}
            }
        }
        // Force kill with SIGKILL
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[cfg(not(unix))]
async fn kill_process_group(child: &mut tokio::process::Child, _graceful: bool) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Check if a port is available (not in use)
async fn is_port_available(port: u16) -> bool {
    tokio::net::TcpListener::bind(("127.0.0.1", port)).await.is_ok()
}

/// Wait for a server to be ready by attempting TCP connection
/// Tries both IPv4 (127.0.0.1) and IPv6 (::1) since Node.js/Vite may bind to either
async fn wait_for_server_ready(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        // Try IPv4 first
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        // Try IPv6
        if tokio::net::TcpStream::connect(("::1", port)).await.is_ok() {
            return true;
        }
        sleep(Duration::from_millis(100)).await;
    }
    false
}

// ============================================================================
// Server Statistics
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    pub request_count: u64,
    pub started_at: Option<DateTime<Local>>,
    pub last_request: Option<DateTime<Local>>,
    pub total_starts: u64,
    pub failed_starts: u64,
}

// ============================================================================
// Dev Server
// ============================================================================

struct DevServer {
    config: ServerConfig,
    process: Option<tokio::process::Child>,
    last_activity: Instant,
    is_starting: bool,
    is_stopping: bool,
    detected_port: Option<u16>,
    connection_semaphore: Arc<Semaphore>,
    log_tx: Option<mpsc::UnboundedSender<(String, String)>>,
    status_store: Option<Arc<tui::LogStore>>,
    startup_notify: watch::Sender<bool>,
    startup_watch: watch::Receiver<bool>,
    stats: ServerStats,
    last_failure: Option<String>,
    // Cooldown: don't auto-restart if recently stopped by idle timeout
    idle_stopped_at: Option<Instant>,
}

// How long to wait after idle shutdown before allowing auto-restart
// This prevents HMR reconnection attempts from immediately restarting the server
const IDLE_COOLDOWN_SECS: u64 = 30;

impl DevServer {
    fn new(config: ServerConfig) -> Self {
        let (startup_notify, startup_watch) = watch::channel(false);
        Self {
            config,
            process: None,
            last_activity: Instant::now(),
            is_starting: false,
            is_stopping: false,
            detected_port: None,
            connection_semaphore: Arc::new(Semaphore::new(20)),
            log_tx: None,
            status_store: None,
            startup_notify,
            startup_watch,
            stats: ServerStats::default(),
            last_failure: None,
            idle_stopped_at: None,
        }
    }

    /// Check if server is in cooldown period after idle shutdown
    fn is_in_idle_cooldown(&self) -> bool {
        if let Some(stopped_at) = self.idle_stopped_at {
            stopped_at.elapsed() < Duration::from_secs(IDLE_COOLDOWN_SECS)
        } else {
            false
        }
    }

    fn set_log_sender(&mut self, tx: mpsc::UnboundedSender<(String, String)>) {
        self.log_tx = Some(tx);
    }

    fn set_status_store(&mut self, store: Arc<tui::LogStore>) {
        self.status_store = Some(store);
    }

    fn send_log(&self, message: String) {
        if let Some(tx) = &self.log_tx {
            let _ = tx.send((self.config.name.clone(), message));
        }
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.process.is_some() || self.is_starting || self.is_stopping {
            return Ok(());
        }

        self.is_starting = true;
        self.last_failure = None;
        self.idle_stopped_at = None; // Clear cooldown when starting
        let _ = self.startup_notify.send(false);

        info!("Starting dev server [{}] (auto-detecting port)...", self.config.name);
        self.send_log("Starting dev server...".to_string());

        let mut cmd = TokioCommand::new(&self.config.command);
        cmd.args(&self.config.args)
            .current_dir(&self.config.directory)
            .kill_on_drop(false)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // On Unix, create a new process group
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.is_starting = false;
                self.last_failure = Some(format!("Failed to spawn process: {}", e));
                self.stats.failed_starts += 1;
                self.send_log(format!("Failed to start: {}", e));
                return Err(format!("Failed to spawn process: {}", e).into());
            }
        };

        // Port detection
        let detected_port = Arc::new(Mutex::new(None::<u16>));
        let log_tx = self.log_tx.clone();
        let last_lines = Arc::new(Mutex::new(Vec::<String>::new()));

        // Spawn stdout reader
        if let Some(stdout) = child.stdout.take() {
            let detected_port = detected_port.clone();
            let name = self.config.name.clone();
            let log_tx = log_tx.clone();
            let last_lines = last_lines.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(tx) = &log_tx {
                        let _ = tx.send((name.clone(), line.clone()));
                    } else {
                        println!("[{}] {}", name, line);
                    }

                    // Keep last 20 lines for error reporting
                    {
                        let mut ll = last_lines.lock().await;
                        ll.push(line.clone());
                        if ll.len() > 20 {
                            ll.remove(0);
                        }
                    }

                    if let Some(caps) = PORT_REGEX.captures(&line) {
                        if let Some(port_str) = caps.get(1) {
                            if let Ok(port) = port_str.as_str().parse::<u16>() {
                                let mut detected = detected_port.lock().await;
                                if detected.is_none() {
                                    *detected = Some(port);
                                    info!("Detected port {} for [{}]", port, name);
                                    if let Some(tx) = &log_tx {
                                        let _ = tx.send((name.clone(), format!("Detected port: {}", port)));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        // Spawn stderr reader
        if let Some(stderr) = child.stderr.take() {
            let detected_port = detected_port.clone();
            let name = self.config.name.clone();
            let log_tx = log_tx.clone();
            let last_lines = last_lines.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(tx) = &log_tx {
                        let _ = tx.send((name.clone(), line.clone()));
                    } else {
                        eprintln!("[{}] {}", name, line);
                    }

                    // Keep last 20 lines for error reporting
                    {
                        let mut ll = last_lines.lock().await;
                        ll.push(line.clone());
                        if ll.len() > 20 {
                            ll.remove(0);
                        }
                    }

                    if let Some(caps) = PORT_REGEX.captures(&line) {
                        if let Some(port_str) = caps.get(1) {
                            if let Ok(port) = port_str.as_str().parse::<u16>() {
                                let mut detected = detected_port.lock().await;
                                if detected.is_none() {
                                    *detected = Some(port);
                                    info!("Detected port {} for [{}]", port, name);
                                    if let Some(tx) = &log_tx {
                                        let _ = tx.send((name.clone(), format!("Detected port: {}", port)));
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        self.process = Some(child);

        // Wait for port detection with timeout
        let start_time = Instant::now();
        let timeout = Duration::from_secs(STARTUP_TIMEOUT_SECS);

        loop {
            sleep(Duration::from_millis(100)).await;
            let port = detected_port.lock().await;
            if port.is_some() {
                self.detected_port = *port;
                break;
            }
            if start_time.elapsed() > timeout {
                warn!("Could not detect port for [{}], waited {}s", self.config.name, STARTUP_TIMEOUT_SECS);
                break;
            }
        }

        if let Some(port) = self.detected_port {
            // Wait for server to actually bind to the port
            // Vite/Next.js can print the URL before they're ready (especially during dep optimization)
            if is_port_available(port).await {
                self.send_log(format!("Port {} detected, waiting for server to bind...", port));
            }

            // Health check - wait for server to accept connections
            // 15s is generous but needed for slow starts (Vite dep optimization, Next.js compilation)
            let health_timeout = Duration::from_secs(15);
            if wait_for_server_ready(port, health_timeout).await {
                self.is_starting = false;
                self.stats.total_starts += 1;
                self.stats.started_at = Some(Local::now());
                let _ = self.startup_notify.send(true);

                info!("Dev server [{}] ready on port {}", self.config.name, port);
                self.send_log(format!("Server ready on port {}", port));

                if let Some(store) = &self.status_store {
                    store.set_server_running(self.config.name.clone());
                    store.set_server_port(self.config.name.clone(), port);
                }
            } else {
                // Health check failed
                let failure_msg = format!("Port {} detected but server not responding", port);
                self.last_failure = Some(failure_msg.clone());
                self.send_log(format!("Health check failed: {}", failure_msg));

                // Show last output lines for debugging
                let ll = last_lines.lock().await;
                if !ll.is_empty() {
                    self.send_log("Last output lines:".to_string());
                    for line in ll.iter().rev().take(5).rev() {
                        self.send_log(format!("  {}", line));
                    }
                }

                // Kill the process
                if let Some(mut child) = self.process.take() {
                    kill_process_group(&mut child, false).await;
                }
                self.is_starting = false;
                self.detected_port = None;
                self.stats.failed_starts += 1;

                if let Some(store) = &self.status_store {
                    store.set_server_stopped(self.config.name.clone());
                }

                return Err(failure_msg.into());
            }
        } else {
            // Port detection failed
            let ll = last_lines.lock().await;
            let failure_msg = if ll.is_empty() {
                "Port detection timeout - no output from server".to_string()
            } else {
                "Port detection timeout - check server output".to_string()
            };

            self.last_failure = Some(failure_msg.clone());
            self.send_log(format!("Failed to detect port: {}", failure_msg));

            // Show last output lines for debugging
            if !ll.is_empty() {
                self.send_log("Last output lines:".to_string());
                for line in ll.iter().rev().take(10).rev() {
                    self.send_log(format!("  {}", line));
                }
            }

            // Kill the process
            if let Some(mut child) = self.process.take() {
                kill_process_group(&mut child, false).await;
            }
            self.is_starting = false;
            self.stats.failed_starts += 1;

            if let Some(store) = &self.status_store {
                store.set_server_stopped(self.config.name.clone());
            }

            return Err(failure_msg.into());
        }

        Ok(())
    }

    fn get_target_port(&self) -> Option<u16> {
        self.detected_port
    }

    fn get_startup_watch(&self) -> watch::Receiver<bool> {
        self.startup_watch.clone()
    }

    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
        self.stats.request_count += 1;
        self.stats.last_request = Some(Local::now());
    }

    fn should_stop(&self, idle_timeout: u64) -> bool {
        idle_timeout > 0
            && self.process.is_some()
            && self.last_activity.elapsed() > Duration::from_secs(idle_timeout)
    }
}

type ServerMap = Arc<Mutex<HashMap<String, DevServer>>>;

// ============================================================================
// HTTP Helpers
// ============================================================================

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

// ============================================================================
// Request Handling
// ============================================================================

async fn proxy_request<C>(
    req: Request<Incoming>,
    server_map: ServerMap,
    client: Arc<Client<C, Full<Bytes>>>,
    request_counter: Arc<AtomicU64>,
) -> Result<Response<BoxBody>, std::convert::Infallible>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    let is_ws = is_websocket_upgrade(&req);
    request_counter.fetch_add(1, Ordering::Relaxed);

    // Extract domain from Host header
    let domain = match req.headers().get("host") {
        Some(host_header) => {
            match host_header.to_str() {
                Ok(host) => host.split(':').next().unwrap_or(host).to_string(),
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

    // Check if server exists and get its state
    let (needs_start, startup_watch) = {
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

        if server.is_stopping {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(full_body("Server is shutting down, please wait..."))
                .unwrap());
        }

        // Check if server is in cooldown after idle shutdown
        if server.is_in_idle_cooldown() {
            let remaining = IDLE_COOLDOWN_SECS.saturating_sub(
                server.idle_stopped_at.map(|t| t.elapsed().as_secs()).unwrap_or(0)
            );
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(full_body(format!(
                    "Server stopped due to inactivity. Cooldown: {}s remaining. Refresh to restart.",
                    remaining
                )))
                .unwrap());
        }

        server.update_activity();
        let needs_start = server.process.is_none() && !server.is_starting;
        let startup_watch = server.get_startup_watch();

        if needs_start {
            // Clear cooldown since user is explicitly requesting (after cooldown expired)
            server.idle_stopped_at = None;
            if let Err(e) = server.start().await {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full_body(format!("Failed to start server: {}", e)))
                    .unwrap());
            }
        }

        (needs_start, startup_watch)
    };

    // Wait for server to be ready using watch channel
    if !needs_start {
        let mut watch = startup_watch;
        let timeout = Duration::from_secs(30);
        let start = Instant::now();

        while !*watch.borrow() && start.elapsed() < timeout {
            let servers = server_map.lock().await;
            let is_starting = servers.get(&domain)
                .map(|s| s.is_starting)
                .unwrap_or(false);
            drop(servers);

            if !is_starting {
                break;
            }

            tokio::select! {
                _ = watch.changed() => {},
                _ = sleep(Duration::from_millis(100)) => {},
            }
        }
    }

    // Get target port and semaphore
    let (target_port, semaphore) = {
        let servers = server_map.lock().await;
        match servers.get(&domain) {
            Some(server) => match server.get_target_port() {
                Some(port) => (port, server.connection_semaphore.clone()),
                None => {
                    let failure_msg = server.last_failure.clone()
                        .unwrap_or_else(|| "Port not detected".to_string());
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full_body(format!("Dev server not ready: {}", failure_msg)))
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

    // Acquire connection permit
    let _permit = semaphore.acquire().await.unwrap();

    // Handle WebSocket upgrade
    if is_ws {
        info!("WebSocket upgrade request for [{}]", domain);

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

        let mut backend_req = hyper::Request::builder()
            .method(req.method())
            .uri(uri);

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

        if backend_response.status() != StatusCode::SWITCHING_PROTOCOLS {
            warn!("Backend rejected WebSocket upgrade: {}", backend_response.status());
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("Backend rejected WebSocket upgrade"))
                .unwrap());
        }

        let mut resp_builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);

        for (name, value) in backend_response.headers().iter() {
            resp_builder = resp_builder.header(name, value);
        }

        tokio::spawn(async move {
            let client_upgrade_fut = hyper::upgrade::on(req);
            let backend_upgrade_fut = hyper::upgrade::on(&mut backend_response);

            match tokio::try_join!(client_upgrade_fut, backend_upgrade_fut) {
                Ok((client_upgraded, backend_upgraded)) => {
                    let mut client = TokioIo::new(client_upgraded);
                    let mut backend = TokioIo::new(backend_upgraded);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
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

    let mut proxy_req = hyper::Request::builder()
        .method(parts.method)
        .uri(uri.clone());

    for (name, value) in parts.headers.iter() {
        if name != "host" {
            proxy_req = proxy_req.header(name, value);
        }
    }

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

    match client.request(proxy_req).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let mut resp_builder = Response::builder().status(parts.status);

            for (name, value) in parts.headers.iter() {
                resp_builder = resp_builder.header(name, value);
            }

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

// ============================================================================
// Server Commands (from TUI)
// ============================================================================

async fn handle_server_command(command: tui::ServerCommand, server_map: ServerMap) {
    match command {
        tui::ServerCommand::Kill(name) => {
            info!("Manual stop requested for [{}]", name);

            let child_to_kill = {
                let mut servers = server_map.lock().await;
                let server = servers.values_mut().find(|s| s.config.name == name);
                if let Some(server) = server {
                    server.is_stopping = true;
                    server.detected_port = None;
                    server.is_starting = false;

                    if let Some(tx) = &server.log_tx {
                        let _ = tx.send((name.clone(), "Stopping server...".to_string()));
                    }

                    if let Some(store) = &server.status_store {
                        store.set_server_stopped(name.clone());
                    }

                    server.process.take()
                } else {
                    return;
                }
            };

            if let Some(mut child) = child_to_kill {
                kill_process_group(&mut child, true).await;
                sleep(Duration::from_secs(3)).await;
            }

            {
                let mut servers = server_map.lock().await;
                if let Some(server) = servers.values_mut().find(|s| s.config.name == name) {
                    server.is_stopping = false;
                    if let Some(tx) = &server.log_tx {
                        let _ = tx.send((name.clone(), "Shutdown complete (will auto-restart on next request)".to_string()));
                    }
                }
            }
        }
        tui::ServerCommand::Restart(name) => {
            info!("Restart requested for [{}]", name);

            let domain_to_restart = {
                let servers = server_map.lock().await;
                servers.iter()
                    .find(|(_, s)| s.config.name == name)
                    .map(|(domain, _)| domain.clone())
            };

            if let Some(domain) = domain_to_restart {
                let mut child_to_kill = None;
                {
                    let mut servers = server_map.lock().await;
                    if let Some(server) = servers.get_mut(&domain) {
                        server.is_stopping = true;
                        server.detected_port = None;
                        server.is_starting = false;

                        if let Some(tx) = &server.log_tx {
                            let _ = tx.send((name.clone(), "Restarting...".to_string()));
                        }

                        if let Some(store) = &server.status_store {
                            store.set_server_stopped(name.clone());
                        }

                        child_to_kill = server.process.take();
                    }
                }

                if let Some(mut child) = child_to_kill {
                    kill_process_group(&mut child, true).await;
                    sleep(Duration::from_secs(3)).await;
                }

                {
                    let mut servers = server_map.lock().await;
                    if let Some(server) = servers.get_mut(&domain) {
                        server.is_stopping = false;
                        let _ = server.start().await;
                    }
                }
            }
        }
    }
}

// ============================================================================
// Background Tasks
// ============================================================================

async fn idle_checker(server_map: ServerMap, idle_timeout: u64) {
    if idle_timeout == 0 {
        return;
    }

    loop {
        sleep(Duration::from_secs(30)).await;

        let servers_to_stop: Vec<(String, Option<tokio::process::Child>, Option<mpsc::UnboundedSender<(String, String)>>)> = {
            let mut servers = server_map.lock().await;
            let mut to_stop = Vec::new();
            for (domain, server) in servers.iter_mut() {
                if server.should_stop(idle_timeout) {
                    server.is_stopping = true;
                    server.detected_port = None;
                    server.is_starting = false;

                    if let Some(tx) = &server.log_tx {
                        let _ = tx.send((server.config.name.clone(), "Stopping due to inactivity...".to_string()));
                    }

                    if let Some(store) = &server.status_store {
                        store.set_server_stopped(server.config.name.clone());
                    }

                    let child = server.process.take();
                    let log_tx = server.log_tx.clone();
                    to_stop.push((domain.clone(), child, log_tx));
                }
            }
            to_stop
        };

        for (domain, child_opt, log_tx) in servers_to_stop {
            if let Some(mut child) = child_opt {
                kill_process_group(&mut child, true).await;
                sleep(Duration::from_secs(3)).await;
            }

            {
                let mut servers = server_map.lock().await;
                if let Some(server) = servers.get_mut(&domain) {
                    server.is_stopping = false;
                    server.idle_stopped_at = Some(Instant::now()); // Start cooldown period

                    if let Some(tx) = &log_tx {
                        let _ = tx.send((server.config.name.clone(),
                            format!("Shutdown complete (cooldown {}s before auto-restart)", IDLE_COOLDOWN_SECS)));
                    }
                }
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
                    if let Some(mut child) = server.process.take() {
                        kill_process_group(&mut child, true).await;
                    }
                }
                std::process::exit(0);
            }
            _ => {}
        }
    }
}

// ============================================================================
// Symlink Management
// ============================================================================

fn scan_symlinks_directory(dir_path: &str, domain_suffix: &str, verbose: bool) -> std::io::Result<Vec<ServerConfig>> {
    let path = std::path::Path::new(dir_path);

    if !path.exists() {
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

        if entry_path.is_symlink() {
            let name = entry.file_name().to_string_lossy().to_string();

            match std::fs::read_link(&entry_path) {
                Ok(target_path) => {
                    let directory = target_path.to_string_lossy().to_string();

                    match ServerConfig::new(name.clone(), directory, domain_suffix) {
                        Ok(config) => {
                            if verbose {
                                info!("Found server: {} -> {}", config.domain, config.directory);
                            }
                            servers.push(config);
                        }
                        Err(e) => {
                            if verbose {
                                warn!("Skipping {}: {}", name, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if verbose {
                        warn!("Failed to read symlink {}: {}", name, e);
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
    std::fs::create_dir_all(symlinks_dir)?;

    let link_path = std::path::Path::new(symlinks_dir).join(name);
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

    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_path, &link_path)?;

    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&target_path, &link_path)?;

    println!("Added {} -> {}", name, target_path.display());
    println!("Access at http://{}.{}", name, domain_suffix);

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

    let target = std::fs::read_link(&link_path)?;
    std::fs::remove_file(&link_path)?;

    println!("Removed {} (was pointing to {})", name, target.display());

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
        println!("  {} -> http://{}.{}", name, name, domain_suffix);
        println!("    {}", target.display());
        println!();
    }

    Ok(())
}

// ============================================================================
// Proxy Server
// ============================================================================

async fn start_proxy_server(
    proxy_port: u16,
    server_map: ServerMap,
    request_counter: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    let listener = TcpListener::bind(addr).await?;

    info!("Proxy listening on {}", addr);

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
            let request_counter = request_counter.clone();

            tokio::task::spawn(async move {
                let service = service_fn(move |req| {
                    let server_map = server_map.clone();
                    let client = client.clone();
                    let request_counter = request_counter.clone();
                    async move { proxy_request(req, server_map, client, request_counter).await }
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

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

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
        None => {}
    }

    // Initialize logging
    if args.no_ui {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("dev_proxy=info"))
            )
            .init();
    }

    let idle_timeout = args.idle_timeout;

    if args.no_ui {
        info!("Scanning {} for dev servers...", symlinks_dir);
    }

    let server_configs = scan_symlinks_directory(&symlinks_dir, &args.domain_suffix, args.no_ui)?;

    if server_configs.is_empty() {
        if args.no_ui {
            error!("No servers found in {}", symlinks_dir);
            error!("Add a server with: dev-proxy add <name> <path>");
        } else {
            eprintln!("No servers found in {}", symlinks_dir);
            eprintln!("Add a server with: dev-proxy add <name> <path>");
        }
        std::process::exit(1);
    }

    if args.no_ui {
        info!("Starting with {} servers on port {} (idle timeout: {}s)",
            server_configs.len(), args.port, idle_timeout);
    }

    // Initialize log collector for TUI
    let log_rx = if !args.no_ui {
        let (tx, rx) = mpsc::unbounded_channel();
        Some((tx, rx))
    } else {
        None
    };

    // Initialize server map
    let server_map: ServerMap = Arc::new(Mutex::new(HashMap::new()));
    let request_counter = Arc::new(AtomicU64::new(0));

    {
        let mut servers = server_map.lock().await;
        for server_config in server_configs.clone() {
            let mut dev_server = DevServer::new(server_config.clone());

            if let Some((ref tx, _)) = log_rx {
                dev_server.set_log_sender(tx.clone());
            }

            servers.insert(server_config.domain.clone(), dev_server);
        }
    }

    // Start proxy server
    if let Err(e) = start_proxy_server(args.port, server_map.clone(), request_counter.clone()).await {
        if args.no_ui {
            error!("Failed to start proxy server: {}", e);
            if e.to_string().contains("Address already in use") {
                error!("Port {} is already in use", args.port);
                error!("Is dev-proxy already running? Check with: ps aux | grep dev-proxy");
                error!("Or use a different port: dev-proxy --port <PORT>");
            }
        } else {
            eprintln!("Failed to start proxy server: {}", e);
            if e.to_string().contains("Address already in use") {
                eprintln!("Port {} is already in use", args.port);
                eprintln!("Is dev-proxy already running? Check with: ps aux | grep dev-proxy");
            }
        }
        std::process::exit(1);
    }

    // Start idle checker
    let checker_map = server_map.clone();
    tokio::spawn(async move {
        idle_checker(checker_map, idle_timeout).await;
    });

    // Setup signal handlers
    let signals = Signals::new([SIGTERM, SIGINT, SIGQUIT])?;
    let handle = signals.handle();
    let signal_map = server_map.clone();

    tokio::spawn(async move {
        handle_signals(signals, signal_map).await;
    });

    if args.no_ui {
        info!("DevProxy ready! Press Ctrl+C to stop.");
    }

    // Run TUI or wait for Ctrl+C
    if let Some((_tx, log_rx)) = log_rx {
        let log_store = Arc::new(tui::LogStore::new());

        {
            let mut servers = server_map.lock().await;
            for server in servers.values_mut() {
                server.set_status_store(log_store.clone());
            }
        }

        let server_info: Vec<tui::ServerInfo> = server_configs
            .iter()
            .map(|config| tui::ServerInfo {
                name: config.name.clone(),
                domain: config.domain.clone(),
            })
            .collect();

        let mut tui_app = tui::TuiApp::new(server_info, idle_timeout);

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        tui_app.set_command_sender(cmd_tx);

        let cmd_server_map = server_map.clone();
        tokio::spawn(async move {
            while let Some(command) = cmd_rx.recv().await {
                handle_server_command(command, cmd_server_map.clone()).await;
            }
        });

        let (tui_tx, tui_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = tui::run_tui_blocking(tui_app, log_store, log_rx);
            let _ = tui_tx.send(result);
        });

        let tui_result = tokio::task::spawn_blocking(move || tui_rx.recv()).await;

        match tui_result {
            Ok(Ok(Ok(_))) => {
                info!("TUI exited cleanly");
            }
            Ok(Ok(Err(e))) => {
                error!("TUI error: {}", e);
            }
            Ok(Err(_)) => {
                error!("TUI thread panicked");
            }
            Err(e) => {
                error!("Failed to join TUI thread: {}", e);
            }
        }

        handle.close();

        // Stop all servers
        let mut servers = server_map.lock().await;
        for server in servers.values_mut() {
            if let Some(mut child) = server.process.take() {
                kill_process_group(&mut child, true).await;
            }
        }
    } else {
        tokio::signal::ctrl_c().await?;
        handle.close();
    }

    Ok(())
}
