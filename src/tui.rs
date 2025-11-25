use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap},
    Frame, Terminal,
};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

const MAX_LINES: usize = 1000;

/// Strip ANSI escape sequences from a string
fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for ch in chars.by_ref() {
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Detect log level from line content
fn detect_log_level(line: &str) -> LogLevel {
    let lower = line.to_lowercase();
    if lower.contains("error") || lower.contains("err!") || lower.contains("panic") || lower.contains("fatal") {
        LogLevel::Error
    } else if lower.contains("warn") || lower.contains("warning") {
        LogLevel::Warn
    } else if lower.contains("info") {
        LogLevel::Info
    } else if lower.contains("debug") || lower.contains("trace") {
        LogLevel::Debug
    } else {
        LogLevel::Normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Normal,
}

impl LogLevel {
    fn color(&self) -> Color {
        match self {
            LogLevel::Error => Color::Red,
            LogLevel::Warn => Color::Yellow,
            LogLevel::Info => Color::Cyan,
            LogLevel::Debug => Color::DarkGray,
            LogLevel::Normal => Color::White,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServerCommand {
    Kill(String),
    Restart(String),
}

pub struct LogStore {
    servers: Arc<Mutex<HashMap<String, Vec<String>>>>,
    all_logs_cache: Arc<Mutex<Vec<String>>>,
    active_servers: Arc<Mutex<HashSet<String>>>,
    running_servers: Arc<Mutex<HashSet<String>>>,
    server_ports: Arc<Mutex<HashMap<String, u16>>>,
    version: Arc<AtomicU64>,
}

impl LogStore {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(Mutex::new(HashMap::new())),
            all_logs_cache: Arc::new(Mutex::new(Vec::new())),
            active_servers: Arc::new(Mutex::new(HashSet::new())),
            running_servers: Arc::new(Mutex::new(HashSet::new())),
            server_ports: Arc::new(Mutex::new(HashMap::new())),
            version: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_server_running(&self, server_name: String) {
        let mut running = self.running_servers.lock().unwrap();
        running.insert(server_name);
    }

    pub fn set_server_stopped(&self, server_name: String) {
        let mut running = self.running_servers.lock().unwrap();
        running.remove(&server_name);
        drop(running);
        let mut ports = self.server_ports.lock().unwrap();
        ports.remove(&server_name);
    }

    pub fn set_server_port(&self, server_name: String, port: u16) {
        let mut ports = self.server_ports.lock().unwrap();
        ports.insert(server_name, port);
        drop(ports);
        self.version.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_server_ports_snapshot(&self) -> HashMap<String, u16> {
        self.server_ports.lock().unwrap().clone()
    }

    pub fn add_line(&self, server_name: String, line: String) {
        let mut servers = self.servers.lock().unwrap();
        let logs = servers.entry(server_name.clone()).or_insert_with(Vec::new);
        logs.push(line.clone());
        if logs.len() > MAX_LINES {
            logs.remove(0);
        }
        drop(servers);

        let mut active = self.active_servers.lock().unwrap();
        active.insert(server_name.clone());
        drop(active);

        let formatted = format!("[{}] {}", server_name, line);
        let mut cache = self.all_logs_cache.lock().unwrap();
        cache.push(formatted);
        if cache.len() > MAX_LINES * 10 {
            cache.remove(0);
        }
        drop(cache);

        self.version.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    pub fn get_lines(&self, server_name: Option<&str>) -> Vec<String> {
        match server_name {
            Some(name) => {
                let servers = self.servers.lock().unwrap();
                servers.get(name).cloned().unwrap_or_default()
            }
            None => {
                let cache = self.all_logs_cache.lock().unwrap();
                cache.clone()
            }
        }
    }

    pub fn get_running_servers_snapshot(&self) -> HashSet<String> {
        self.running_servers.lock().unwrap().clone()
    }

    pub fn clear_logs(&self, server_name: &str) {
        let mut servers = self.servers.lock().unwrap();
        if let Some(logs) = servers.get_mut(server_name) {
            logs.clear();
        }
        drop(servers);

        let prefix = format!("[{}] ", server_name);
        let mut cache = self.all_logs_cache.lock().unwrap();
        cache.retain(|line| !line.starts_with(&prefix));
        drop(cache);

        self.version.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct ServerInfo {
    pub name: String,
    pub domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    ServerList,
    LogsView,
    Help,
    Search,
}

pub struct TuiApp {
    servers: Vec<ServerInfo>,
    selected_index: usize,
    scroll_offset: u16,
    visible_height: u16,
    cached_logs: Vec<String>,
    filtered_logs: Vec<(usize, String)>, // (original_index, line)
    running_servers: HashSet<String>,
    server_ports: HashMap<String, u16>,
    log_store: Arc<LogStore>,
    last_version: u64,
    last_draw_time: Instant,
    command_tx: Option<mpsc::UnboundedSender<ServerCommand>>,
    view_mode: ViewMode,
    // Text selection state
    cursor_line: usize,
    selection_start: Option<usize>,
    selection_end: Option<usize>,
    // Status message
    status_message: Option<String>,
    status_message_time: Option<Instant>,
    // Search state
    search_query: String,
    search_active: bool,
    // Configuration
    idle_timeout: u64,
    // Statistics
    started_at: Instant,
}

impl TuiApp {
    pub fn new(servers: Vec<ServerInfo>, idle_timeout: u64) -> Self {
        Self {
            servers,
            selected_index: 0,
            scroll_offset: 0,
            visible_height: 20,
            cached_logs: Vec::new(),
            filtered_logs: Vec::new(),
            running_servers: HashSet::new(),
            server_ports: HashMap::new(),
            log_store: Arc::new(LogStore::new()),
            last_version: 0,
            last_draw_time: Instant::now(),
            command_tx: None,
            view_mode: ViewMode::ServerList,
            cursor_line: 0,
            selection_start: None,
            selection_end: None,
            status_message: None,
            status_message_time: None,
            search_query: String::new(),
            search_active: false,
            idle_timeout,
            started_at: Instant::now(),
        }
    }

    pub fn set_status_message(&mut self, message: String) {
        self.status_message = Some(message);
        self.status_message_time = Some(Instant::now());
    }

    pub fn clear_expired_status(&mut self) {
        if let Some(time) = self.status_message_time {
            if time.elapsed() > std::time::Duration::from_secs(3) {
                self.status_message = None;
                self.status_message_time = None;
            }
        }
    }

    pub fn set_command_sender(&mut self, tx: mpsc::UnboundedSender<ServerCommand>) {
        self.command_tx = Some(tx);
    }

    pub fn has_log_changes(&self) -> bool {
        self.log_store.get_version() != self.last_version
    }

    fn apply_search_filter(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_logs = self.cached_logs.iter()
                .enumerate()
                .map(|(i, s)| (i, s.clone()))
                .collect();
        } else {
            let query_lower = self.search_query.to_lowercase();
            self.filtered_logs = self.cached_logs.iter()
                .enumerate()
                .filter(|(_, line)| line.to_lowercase().contains(&query_lower))
                .map(|(i, s)| (i, s.clone()))
                .collect();
        }
    }

    pub fn refresh_current_logs(&mut self) {
        let was_at_bottom = {
            let total_lines = self.get_display_logs().len() as u16;
            let max_scroll = total_lines.saturating_sub(self.visible_height);
            self.scroll_offset >= max_scroll
        };

        let selected = self.get_selected_server();
        self.cached_logs = self.log_store.get_lines(selected);
        self.running_servers = self.log_store.get_running_servers_snapshot();
        self.server_ports = self.log_store.get_server_ports_snapshot();

        self.apply_search_filter();

        let display_len = self.get_display_logs().len();
        if self.cursor_line >= display_len && display_len > 0 {
            self.cursor_line = display_len - 1;
        } else if display_len == 0 {
            self.cursor_line = 0;
        }

        if was_at_bottom {
            self.scroll_to_bottom();
        }

        self.last_version = self.log_store.get_version();
    }

    fn get_display_logs(&self) -> &Vec<(usize, String)> {
        &self.filtered_logs
    }

    pub fn next(&mut self) {
        if self.selected_index < self.servers.len() {
            self.selected_index += 1;
        }
        self.refresh_current_logs();
        self.cursor_line = 0;
        self.selection_start = None;
        self.selection_end = None;
        self.scroll_to_bottom();
    }

    pub fn previous(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
        self.refresh_current_logs();
        self.cursor_line = 0;
        self.selection_start = None;
        self.selection_end = None;
        self.scroll_to_bottom();
    }

    pub fn scroll_to_bottom(&mut self) {
        let total_lines = self.get_display_logs().len() as u16;
        self.scroll_offset = total_lines.saturating_sub(self.visible_height);
    }

    pub fn scroll_down(&mut self) {
        let total_lines = self.get_display_logs().len() as u16;
        let max_scroll = total_lines.saturating_sub(self.visible_height);
        if self.scroll_offset < max_scroll {
            self.scroll_offset = self.scroll_offset.saturating_add(1);
        }
    }

    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    pub fn get_selected_server(&self) -> Option<&str> {
        if self.selected_index == 0 {
            None
        } else {
            self.servers.get(self.selected_index - 1).map(|s| s.name.as_str())
        }
    }

    pub fn get_selected_server_info(&self) -> Option<&ServerInfo> {
        if self.selected_index == 0 {
            None
        } else {
            self.servers.get(self.selected_index - 1)
        }
    }

    pub fn enter_logs_view(&mut self) {
        self.view_mode = ViewMode::LogsView;
        self.cursor_line = self.scroll_offset as usize;
        self.selection_start = None;
        self.selection_end = None;
        let display_len = self.get_display_logs().len();
        if self.cursor_line >= display_len && display_len > 0 {
            self.cursor_line = display_len - 1;
        }
    }

    pub fn exit_logs_view(&mut self) {
        self.view_mode = ViewMode::ServerList;
        self.selection_start = None;
        self.selection_end = None;
    }

    pub fn move_cursor_up(&mut self) {
        if self.cursor_line > 0 {
            self.cursor_line -= 1;
            if self.cursor_line < self.scroll_offset as usize {
                self.scroll_offset = self.cursor_line as u16;
            }
        }
    }

    pub fn move_cursor_down(&mut self) {
        let max_line = self.get_display_logs().len().saturating_sub(1);
        if self.cursor_line < max_line {
            self.cursor_line += 1;
            let bottom_visible = self.scroll_offset as usize + self.visible_height as usize;
            if self.cursor_line >= bottom_visible {
                self.scroll_offset = (self.cursor_line as u16).saturating_sub(self.visible_height - 1);
            }
        }
    }

    pub fn toggle_selection(&mut self) {
        match self.selection_start {
            None => {
                self.selection_start = Some(self.cursor_line);
                self.selection_end = Some(self.cursor_line);
            }
            Some(start) => {
                let end = self.cursor_line;
                let (from, to) = if start <= end { (start, end) } else { (end, start) };

                let display_logs = self.get_display_logs();
                let selected_lines: Vec<String> = display_logs
                    .iter()
                    .skip(from)
                    .take(to - from + 1)
                    .map(|(_, line)| strip_ansi_codes(line))
                    .collect();

                let selected_text = selected_lines.join("\n");

                match arboard::Clipboard::new() {
                    Ok(mut clipboard) => {
                        if clipboard.set_text(&selected_text).is_ok() {
                            self.set_status_message(format!("Copied {} lines to clipboard", to - from + 1));
                        } else {
                            self.set_status_message("Failed to copy to clipboard".to_string());
                        }
                    }
                    Err(_) => {
                        self.set_status_message("Failed to access clipboard".to_string());
                    }
                }

                self.selection_start = None;
                self.selection_end = None;
            }
        }
    }

    pub fn update_selection(&mut self) {
        if self.selection_start.is_some() {
            self.selection_end = Some(self.cursor_line);
        }
    }

    pub fn toggle_help(&mut self) {
        if self.view_mode == ViewMode::Help {
            self.view_mode = ViewMode::ServerList;
        } else {
            self.view_mode = ViewMode::Help;
        }
    }

    pub fn start_search(&mut self) {
        self.view_mode = ViewMode::Search;
        self.search_query.clear();
        self.search_active = true;
    }

    pub fn cancel_search(&mut self) {
        self.view_mode = ViewMode::ServerList;
        self.search_query.clear();
        self.search_active = false;
        self.apply_search_filter();
    }

    pub fn confirm_search(&mut self) {
        self.view_mode = ViewMode::ServerList;
        self.search_active = !self.search_query.is_empty();
        self.apply_search_filter();
        self.scroll_offset = 0;
        self.cursor_line = 0;
    }

    pub fn clear_search(&mut self) {
        self.search_query.clear();
        self.search_active = false;
        self.apply_search_filter();
    }

    pub fn add_search_char(&mut self, c: char) {
        self.search_query.push(c);
        self.apply_search_filter();
    }

    pub fn remove_search_char(&mut self) {
        self.search_query.pop();
        self.apply_search_filter();
    }

    fn format_uptime(&self) -> String {
        let secs = self.started_at.elapsed().as_secs();
        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        }
    }
}

pub fn run_tui_blocking(
    mut app: TuiApp,
    log_store: Arc<LogStore>,
    mut log_rx: mpsc::UnboundedReceiver<(String, String)>,
) -> io::Result<()> {
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    crossterm::terminal::enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    app.log_store = log_store.clone();

    let store_clone = log_store.clone();
    std::thread::spawn(move || {
        use std::time::{Duration, Instant};

        let mut batch: Vec<(String, String)> = Vec::with_capacity(100);
        let mut last_flush = Instant::now();
        const BATCH_INTERVAL: Duration = Duration::from_millis(50);

        loop {
            match log_rx.try_recv() {
                Ok((server_name, message)) => {
                    batch.push((server_name, message));

                    if batch.len() >= 50 || last_flush.elapsed() >= BATCH_INTERVAL {
                        for (name, msg) in batch.drain(..) {
                            store_clone.add_line(name, msg);
                        }
                        last_flush = Instant::now();
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(_) => {
                    if !batch.is_empty() {
                        for (name, msg) in batch.drain(..) {
                            store_clone.add_line(name, msg);
                        }
                        last_flush = Instant::now();
                    }
                    match log_rx.blocking_recv() {
                        Some((server_name, message)) => {
                            batch.push((server_name, message));
                        }
                        None => break,
                    }
                }
            }
        }
    });

    let result = run_app(&mut terminal, &mut app);

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
) -> io::Result<()> {
    app.refresh_current_logs();
    terminal.draw(|f| ui(f, app))?;
    app.last_draw_time = Instant::now();

    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let _event_thread = std::thread::spawn(move || {
        loop {
            match crossterm::event::read() {
                Ok(evt) => {
                    if event_tx.send(evt).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        match event_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                // Handle search mode input first
                if app.view_mode == ViewMode::Search {
                    match key.code {
                        KeyCode::Esc => {
                            app.cancel_search();
                        }
                        KeyCode::Enter => {
                            app.confirm_search();
                        }
                        KeyCode::Backspace => {
                            app.remove_search_char();
                        }
                        KeyCode::Char(c) => {
                            app.add_search_char(c);
                        }
                        _ => {}
                    }
                    terminal.draw(|f| ui(f, app))?;
                    app.last_draw_time = Instant::now();
                    continue;
                }

                // Handle help mode - any key closes it
                if app.view_mode == ViewMode::Help {
                    app.toggle_help();
                    terminal.draw(|f| ui(f, app))?;
                    app.last_draw_time = Instant::now();
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if app.view_mode == ViewMode::LogsView {
                            app.exit_logs_view();
                            terminal.draw(|f| ui(f, app))?;
                            app.last_draw_time = Instant::now();
                        } else if app.search_active {
                            app.clear_search();
                            terminal.draw(|f| ui(f, app))?;
                            app.last_draw_time = Instant::now();
                        } else {
                            return Ok(());
                        }
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Char('?') => {
                        app.toggle_help();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char('/') => {
                        app.start_search();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Right if app.view_mode == ViewMode::ServerList => {
                        app.enter_logs_view();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Left if app.view_mode == ViewMode::LogsView => {
                        app.exit_logs_view();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Down if app.view_mode == ViewMode::ServerList => {
                        app.next();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Up if app.view_mode == ViewMode::ServerList => {
                        app.previous();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Down if app.view_mode == ViewMode::LogsView => {
                        app.move_cursor_down();
                        app.update_selection();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Up if app.view_mode == ViewMode::LogsView => {
                        app.move_cursor_up();
                        app.update_selection();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char(' ') if app.view_mode == ViewMode::LogsView => {
                        app.toggle_selection();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Enter => {
                        if let Some(server) = app.get_selected_server_info() {
                            let url = format!("http://{}", server.domain);
                            #[cfg(target_os = "macos")]
                            let _ = std::process::Command::new("open").arg(&url).spawn();
                            #[cfg(target_os = "linux")]
                            let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
                            #[cfg(target_os = "windows")]
                            let _ = std::process::Command::new("cmd").args(&["/C", "start", &url]).spawn();
                        }
                    }
                    KeyCode::Char('z') | KeyCode::Char('Z') => {
                        for _ in 0..5 {
                            app.scroll_down();
                        }
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        for _ in 0..5 {
                            app.scroll_up();
                        }
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char('t') | KeyCode::Char('T') => {
                        app.scroll_offset = 0;
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char('b') | KeyCode::Char('B') => {
                        app.scroll_to_bottom();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char('k') => {
                        if let Some(server) = app.get_selected_server_info() {
                            if let Some(ref tx) = app.command_tx {
                                let _ = tx.send(ServerCommand::Kill(server.name.clone()));
                            }
                        } else {
                            app.set_status_message("Select a specific server to kill".to_string());
                            terminal.draw(|f| ui(f, app))?;
                            app.last_draw_time = Instant::now();
                        }
                    }
                    KeyCode::Char('r') => {
                        if let Some(server) = app.get_selected_server_info() {
                            if let Some(ref tx) = app.command_tx {
                                let _ = tx.send(ServerCommand::Restart(server.name.clone()));
                            }
                        } else {
                            app.set_status_message("Select a specific server to restart".to_string());
                            terminal.draw(|f| ui(f, app))?;
                            app.last_draw_time = Instant::now();
                        }
                    }
                    KeyCode::Char('f') => {
                        if let Some(server_name) = app.get_selected_server() {
                            app.log_store.clear_logs(server_name);
                            app.refresh_current_logs();
                            app.scroll_to_bottom();
                            terminal.draw(|f| ui(f, app))?;
                            app.last_draw_time = Instant::now();
                        }
                    }
                    KeyCode::Char('c') => {
                        let logs_text: String = app.get_display_logs()
                            .iter()
                            .map(|(_, line)| strip_ansi_codes(line))
                            .collect::<Vec<String>>()
                            .join("\n");
                        match arboard::Clipboard::new() {
                            Ok(mut clipboard) => {
                                if clipboard.set_text(&logs_text).is_ok() {
                                    app.set_status_message("Copied all logs to clipboard".to_string());
                                } else {
                                    app.set_status_message("Failed to copy to clipboard".to_string());
                                }
                            }
                            Err(_) => {
                                app.set_status_message("Failed to access clipboard".to_string());
                            }
                        }
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Home => {
                        app.selected_index = 0;
                        app.refresh_current_logs();
                        app.scroll_to_bottom();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::End => {
                        app.selected_index = app.servers.len();
                        app.refresh_current_logs();
                        app.scroll_to_bottom();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    _ => {}
                }
            }
            Ok(Event::Mouse(mouse)) => {
                match mouse.kind {
                    MouseEventKind::ScrollDown => {
                        app.scroll_down();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    MouseEventKind::ScrollUp => {
                        app.scroll_up();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    _ => {}
                }
            }
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let needs_redraw = app.has_log_changes() || app.status_message.is_some();

                if needs_redraw {
                    const MIN_DRAW_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
                    let time_since_last_draw = app.last_draw_time.elapsed();

                    if time_since_last_draw >= MIN_DRAW_INTERVAL {
                        app.refresh_current_logs();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Ok(());
            }
        }
    }
}

fn ui(f: &mut Frame, app: &mut TuiApp) {
    app.clear_expired_status();

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_chunks[0]);

    render_server_list(f, app, chunks[0]);
    render_logs(f, app, chunks[1]);
    render_status_bar(f, app, main_chunks[1]);

    // Render overlays
    if app.view_mode == ViewMode::Help {
        render_help_overlay(f, app);
    } else if app.view_mode == ViewMode::Search {
        render_search_overlay(f, app);
    }
}

fn render_status_bar(f: &mut Frame, app: &TuiApp, area: Rect) {
    let uptime = app.format_uptime();
    let running_count = app.running_servers.len();
    let total_count = app.servers.len();

    let status_text = if let Some(ref msg) = app.status_message {
        msg.clone()
    } else if app.search_active {
        format!(
            "Filter: \"{}\" ({} matches) | {} | {}/{} running | ?=Help",
            app.search_query,
            app.get_display_logs().len(),
            uptime,
            running_count,
            total_count
        )
    } else {
        format!(
            "Uptime: {} | {}/{} servers running | Idle timeout: {}s | ?=Help",
            uptime, running_count, total_count, app.idle_timeout
        )
    };

    let color = if app.status_message.is_some() {
        Color::Green
    } else if app.search_active {
        Color::Yellow
    } else {
        Color::DarkGray
    };

    let paragraph = Paragraph::new(Line::from(Span::styled(status_text, Style::default().fg(color))));
    f.render_widget(paragraph, area);
}

fn render_server_list(f: &mut Frame, app: &TuiApp, area: Rect) {
    let mut items = vec![ListItem::new(Line::from(vec![
        Span::styled("* ", Style::default().fg(Color::Blue)),
        Span::raw("All"),
    ]))];

    for server in &app.servers {
        let is_running = app.running_servers.contains(&server.name);
        let status_icon = if is_running { "*" } else { "o" };
        let status_color = if is_running { Color::Green } else { Color::DarkGray };

        let port_display = if let Some(port) = app.server_ports.get(&server.name) {
            format!(" [{}]", port)
        } else {
            String::new()
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("{} ", status_icon), Style::default().fg(status_color)),
            Span::raw(&server.domain),
            Span::styled(port_display, Style::default().fg(Color::DarkGray)),
        ])));
    }

    let title = if app.view_mode == ViewMode::ServerList {
        " Servers [ACTIVE] "
    } else {
        " Servers "
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(if app.view_mode == ViewMode::ServerList {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Cyan)
                }),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(app.selected_index));

    f.render_stateful_widget(list, area, &mut state);
}

fn render_logs(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let selected_server = app.get_selected_server();

    let title = match app.view_mode {
        ViewMode::LogsView => {
            if let Some(server) = selected_server {
                format!(" Logs: {} [NAVIGATE] ", server)
            } else {
                " Logs: All [NAVIGATE] ".to_string()
            }
        }
        _ => {
            if let Some(server) = selected_server {
                format!(" Logs: {} ", server)
            } else {
                " Logs: All ".to_string()
            }
        }
    };

    let visible_height = area.height.saturating_sub(2);
    app.visible_height = visible_height;
    let scroll = app.scroll_offset as usize;

    let selection_range = if let (Some(start), Some(end)) = (app.selection_start, app.selection_end) {
        let (from, to) = if start <= end { (start, end) } else { (end, start) };
        Some((from, to))
    } else {
        None
    };

    let display_logs = app.get_display_logs();
    let mut log_lines: Vec<Line> = display_logs
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible_height as usize)
        .map(|(display_idx, (_, line))| {
            let is_cursor = app.view_mode == ViewMode::LogsView && display_idx == app.cursor_line;
            let is_selected = selection_range.map_or(false, |(from, to)| display_idx >= from && display_idx <= to);

            // Determine base color from log level
            let log_level = detect_log_level(line);
            let base_color = log_level.color();

            let mut style = Style::default().fg(base_color);

            if is_selected {
                style = style.bg(Color::DarkGray).fg(Color::White);
            }

            if is_cursor {
                if is_selected {
                    style = style.bg(Color::Blue).add_modifier(Modifier::BOLD);
                } else {
                    style = style.bg(Color::DarkGray).add_modifier(Modifier::BOLD);
                }
            }

            // Highlight search matches
            if app.search_active && !app.search_query.is_empty() {
                let query_lower = app.search_query.to_lowercase();
                let line_lower = line.to_lowercase();
                if let Some(pos) = line_lower.find(&query_lower) {
                    let before = &line[..pos];
                    let matched = &line[pos..pos + app.search_query.len()];
                    let after = &line[pos + app.search_query.len()..];

                    return Line::from(vec![
                        Span::styled(before.to_string(), style),
                        Span::styled(matched.to_string(), style.bg(Color::Yellow).fg(Color::Black)),
                        Span::styled(after.to_string(), style),
                    ]);
                }
            }

            Line::from(Span::styled(line.as_str(), style))
        })
        .collect();

    while log_lines.len() < visible_height as usize {
        log_lines.push(Line::from(""));
    }

    let paragraph = Paragraph::new(log_lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(if app.view_mode == ViewMode::LogsView {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Cyan)
                }),
        );

    f.render_widget(paragraph, area);

    let total_lines = display_logs.len();
    if total_lines > visible_height as usize {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("^"))
            .end_symbol(Some("v"));

        let mut scrollbar_state = ScrollbarState::new(total_lines.saturating_sub(visible_height as usize))
            .position(app.scroll_offset as usize);

        f.render_stateful_widget(
            scrollbar,
            area.inner(ratatui::layout::Margin { vertical: 1, horizontal: 0 }),
            &mut scrollbar_state,
        );
    }
}

fn render_help_overlay(f: &mut Frame, _app: &TuiApp) {
    let area = centered_rect(60, 80, f.area());

    f.render_widget(Clear, area);

    let help_text = vec![
        Line::from(Span::styled("dev-proxy Help", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled("Navigation", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from("  Up/Down     Select server"),
        Line::from("  Right       Enter logs view (navigate mode)"),
        Line::from("  Left        Exit logs view"),
        Line::from("  Home/End    Jump to first/last server"),
        Line::from(""),
        Line::from(Span::styled("Scrolling", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from("  A/Z         Scroll up/down (5 lines)"),
        Line::from("  T/B         Jump to top/bottom"),
        Line::from("  Mouse       Scroll wheel"),
        Line::from(""),
        Line::from(Span::styled("Server Control", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from("  Enter       Open server in browser"),
        Line::from("  k           Kill selected server"),
        Line::from("  r           Restart selected server"),
        Line::from(""),
        Line::from(Span::styled("Logs", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from("  /           Search/filter logs"),
        Line::from("  c           Copy all logs to clipboard"),
        Line::from("  f           Flush/clear logs"),
        Line::from("  Space       Select text (in navigate mode)"),
        Line::from(""),
        Line::from(Span::styled("Other", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from("  ?           Toggle this help"),
        Line::from("  q/Esc       Quit (or exit view)"),
        Line::from(""),
        Line::from(Span::styled("Press any key to close", Style::default().fg(Color::DarkGray))),
    ];

    let paragraph = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

fn render_search_overlay(f: &mut Frame, app: &TuiApp) {
    let area = centered_rect(50, 10, f.area());

    f.render_widget(Clear, area);

    let search_text = format!("/{}", app.search_query);

    let paragraph = Paragraph::new(Line::from(vec![
        Span::raw(&search_text),
        Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
    ]))
    .block(
        Block::default()
            .title(" Search (Enter to confirm, Esc to cancel) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );

    f.render_widget(paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
