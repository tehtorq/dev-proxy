use ratatui::{
    backend::TermionBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use termion::event::Key;
use termion::input::TermRead;
use termion::raw::IntoRawMode;
use tokio::sync::mpsc;

const MAX_LINES: usize = 200;

// Pre-formatted, ready-to-render log lines for each server
pub struct LogStore {
    servers: Arc<Mutex<HashMap<String, Vec<String>>>>,
    all_logs_cache: Arc<Mutex<Vec<String>>>,
    active_servers: Arc<Mutex<HashSet<String>>>,
    version: Arc<AtomicU64>,
}

impl LogStore {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(Mutex::new(HashMap::new())),
            all_logs_cache: Arc::new(Mutex::new(Vec::new())),
            active_servers: Arc::new(Mutex::new(HashSet::new())),
            version: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn add_line(&self, server_name: String, line: String) {
        let mut servers = self.servers.lock().unwrap();
        let logs = servers.entry(server_name.clone()).or_insert_with(Vec::new);
        logs.push(line.clone());
        if logs.len() > MAX_LINES {
            logs.remove(0);
        }
        drop(servers);

        // Track active servers
        let mut active = self.active_servers.lock().unwrap();
        active.insert(server_name.clone());
        drop(active);

        // Update the "All" cache with the new formatted line
        let formatted = format!("[{}] {}", server_name, line);
        let mut cache = self.all_logs_cache.lock().unwrap();
        cache.push(formatted);
        if cache.len() > MAX_LINES * 10 {  // Allow more lines in "All" view
            cache.remove(0);
        }
        drop(cache);

        // Increment version to signal change
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
                // "All" - return cached formatted logs (zero allocations!)
                let cache = self.all_logs_cache.lock().unwrap();
                cache.clone()
            }
        }
    }

    pub fn get_active_servers_snapshot(&self) -> HashSet<String> {
        self.active_servers.lock().unwrap().clone()
    }
}

pub struct ServerInfo {
    pub name: String,
    pub domain: String,
}

pub struct TuiApp {
    servers: Vec<ServerInfo>,
    selected_index: usize,
    scroll_offset: u16,
    cached_logs: Vec<String>,
    cached_active_servers: HashSet<String>,
    log_store: Arc<LogStore>,
    last_version: u64,
    last_draw_time: Instant,
}

impl TuiApp {
    pub fn new(servers: Vec<ServerInfo>) -> Self {
        Self {
            servers,
            selected_index: 0,
            scroll_offset: 0,
            cached_logs: Vec::new(),
            cached_active_servers: HashSet::new(),
            log_store: Arc::new(LogStore::new()), // Placeholder, will be set later
            last_version: 0,
            last_draw_time: Instant::now(),
        }
    }

    pub fn has_log_changes(&self) -> bool {
        self.log_store.get_version() != self.last_version
    }

    pub fn refresh_current_logs(&mut self) {
        let selected = self.get_selected_server();
        self.cached_logs = self.log_store.get_lines(selected);
        self.cached_active_servers = self.log_store.get_active_servers_snapshot();
        self.last_version = self.log_store.get_version();
    }

    pub fn next(&mut self) {
        if self.selected_index < self.servers.len() {
            self.selected_index += 1;
        }
        self.scroll_offset = 0;
        self.refresh_current_logs();
    }

    pub fn previous(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
        self.scroll_offset = 0;
        self.refresh_current_logs();
    }

    pub fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
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
}

pub fn run_tui_blocking(
    mut app: TuiApp,
    mut log_rx: mpsc::UnboundedReceiver<(String, String)>,
) -> io::Result<()> {
    // Setup terminal with termion (more reliable than crossterm on macOS)
    let stdout = io::stdout();
    let backend = TermionBackend::new(stdout.into_raw_mode()?);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    write!(terminal.backend_mut(), "{}", termion::screen::ToAlternateScreen)?;

    let log_store = Arc::new(LogStore::new());

    // Give app access to log_store
    app.log_store = log_store.clone();

    // Spawn background task to collect logs with batching to prevent CPU starvation
    let store_clone = log_store.clone();
    std::thread::spawn(move || {
        use std::time::{Duration, Instant};

        let mut batch: Vec<(String, String)> = Vec::with_capacity(100);
        let mut last_flush = Instant::now();
        const BATCH_INTERVAL: Duration = Duration::from_millis(50);

        loop {
            // Try to receive without blocking first
            match log_rx.try_recv() {
                Ok((server_name, message)) => {
                    batch.push((server_name, message));

                    // Flush if batch is full or enough time has passed
                    if batch.len() >= 50 || last_flush.elapsed() >= BATCH_INTERVAL {
                        for (name, msg) in batch.drain(..) {
                            store_clone.add_line(name, msg);
                        }
                        last_flush = Instant::now();
                        // Yield CPU to TUI thread
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(_) => {
                    // No messages available, flush any pending batch
                    if !batch.is_empty() {
                        for (name, msg) in batch.drain(..) {
                            store_clone.add_line(name, msg);
                        }
                        last_flush = Instant::now();
                    }
                    // Block waiting for next message
                    match log_rx.blocking_recv() {
                        Some((server_name, message)) => {
                            batch.push((server_name, message));
                        }
                        None => break, // Channel closed
                    }
                }
            }
        }
    });

    let result = run_app(&mut terminal, &mut app);

    // Exit alternate screen
    write!(terminal.backend_mut(), "{}", termion::screen::ToMainScreen)?;
    // Raw mode cleanup happens automatically when RawTerminal drops

    result
}

fn run_app<W: Write>(
    terminal: &mut Terminal<TermionBackend<W>>,
    app: &mut TuiApp,
) -> io::Result<()> {
    // Initial refresh and draw
    app.refresh_current_logs();
    terminal.draw(|f| ui(f, app))?;
    app.last_draw_time = Instant::now();

    // Spawn dedicated thread to read keyboard events using termion
    // Termion reads from stdin directly, avoiding stdin inheritance issues with child processes
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let _event_thread = std::thread::spawn(move || {
        use std::io::stdin;
        let stdin = stdin();
        for key_result in stdin.keys() {
            if let Ok(key) = key_result {
                if event_tx.send(key).is_err() {
                    break; // Channel closed, exit thread
                }
            }
        }
    });

    loop {
        // Wait for keyboard event with timeout (for log refresh)
        match event_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(key) => {
                match key {
                    Key::Char('q') | Key::Esc | Key::Ctrl('c') => {
                        return Ok(());
                    }
                    Key::Down => {
                        app.next();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    Key::Up => {
                        app.previous();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    Key::Char('\n') => {
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
                    Key::PageDown => {
                        for _ in 0..10 {
                            app.scroll_down();
                        }
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    Key::PageUp => {
                        for _ in 0..10 {
                            app.scroll_up();
                        }
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    Key::Home => {
                        app.selected_index = 0;
                        app.scroll_offset = 0;
                        app.refresh_current_logs();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    Key::End => {
                        app.selected_index = app.servers.len();
                        app.scroll_offset = 0;
                        app.refresh_current_logs();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    _ => {}
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Timeout - check for log updates and redraw if needed
                if app.has_log_changes() {
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

fn ui(f: &mut Frame, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(f.area());

    render_server_list(f, app, chunks[0]);
    render_logs(f, app, chunks[1]);
}

fn render_server_list(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let mut items = vec![ListItem::new(Line::from(vec![
        Span::styled("◉ ", Style::default().fg(Color::Blue)),
        Span::raw("All"),
    ]))];

    for server in &app.servers {
        // Use cached status - NO mutex lock during render!
        let has_logs = app.cached_active_servers.contains(&server.name);
        let status_icon = if has_logs { "●" } else { "○" };
        let status_color = if has_logs {
            Color::Green
        } else {
            Color::DarkGray
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("{} ", status_icon), Style::default().fg(status_color)),
            Span::raw(&server.domain),
        ])));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Servers (↑/↓/Enter=Open/q) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("► ");

    let mut state = ListState::default();
    state.select(Some(app.selected_index));

    f.render_stateful_widget(list, area, &mut state);
}

fn render_logs(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let selected_server = app.get_selected_server();

    let title = if let Some(server) = selected_server {
        format!(" Logs: {} (PgUp/PgDn) ", server)
    } else {
        " Logs: All (PgUp/PgDn) ".to_string()
    };

    // Use cached logs - NO fetching during render!
    let visible_height = area.height.saturating_sub(2) as usize;
    let scroll = app.scroll_offset as usize;

    let log_lines: Vec<Line> = app.cached_logs
        .iter()
        .skip(scroll)
        .take(visible_height)
        .map(|line| Line::from(Span::raw(line.as_str())))
        .collect();

    let paragraph = Paragraph::new(log_lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    f.render_widget(paragraph, area);
}
