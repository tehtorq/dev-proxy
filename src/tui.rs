use crossterm::event::{Event, KeyCode, KeyEventKind, MouseEventKind};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

const MAX_LINES: usize = 200;

#[derive(Debug, Clone)]
pub enum ServerCommand {
    Kill(String),    // Server name
    Restart(String), // Server name
}

// Pre-formatted, ready-to-render log lines for each server
pub struct LogStore {
    servers: Arc<Mutex<HashMap<String, Vec<String>>>>,
    all_logs_cache: Arc<Mutex<Vec<String>>>,
    active_servers: Arc<Mutex<HashSet<String>>>,
    running_servers: Arc<Mutex<HashSet<String>>>,  // Track actual process state
    version: Arc<AtomicU64>,
}

impl LogStore {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(Mutex::new(HashMap::new())),
            all_logs_cache: Arc::new(Mutex::new(Vec::new())),
            active_servers: Arc::new(Mutex::new(HashSet::new())),
            running_servers: Arc::new(Mutex::new(HashSet::new())),
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

    pub fn get_running_servers_snapshot(&self) -> HashSet<String> {
        self.running_servers.lock().unwrap().clone()
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
    visible_height: u16,  // Track terminal height for scroll bounds
    cached_logs: Vec<String>,
    cached_active_servers: HashSet<String>,
    running_servers: HashSet<String>,  // Track which servers are actually running
    log_store: Arc<LogStore>,
    last_version: u64,
    last_draw_time: Instant,
    command_tx: Option<mpsc::UnboundedSender<ServerCommand>>,
}

impl TuiApp {
    pub fn new(servers: Vec<ServerInfo>) -> Self {
        Self {
            servers,
            selected_index: 0,
            scroll_offset: 0,
            visible_height: 20,  // Default, will be updated during render
            cached_logs: Vec::new(),
            cached_active_servers: HashSet::new(),
            running_servers: HashSet::new(),
            log_store: Arc::new(LogStore::new()), // Placeholder, will be set later
            last_version: 0,
            last_draw_time: Instant::now(),
            command_tx: None,
        }
    }

    pub fn set_command_sender(&mut self, tx: mpsc::UnboundedSender<ServerCommand>) {
        self.command_tx = Some(tx);
    }

    pub fn has_log_changes(&self) -> bool {
        self.log_store.get_version() != self.last_version
    }

    pub fn refresh_current_logs(&mut self) {
        let selected = self.get_selected_server();
        self.cached_logs = self.log_store.get_lines(selected);
        self.cached_active_servers = self.log_store.get_active_servers_snapshot();

        // Get running status directly from LogStore (no log parsing!)
        self.running_servers = self.log_store.get_running_servers_snapshot();

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
        // Don't scroll past the last visible line
        let total_lines = self.cached_logs.len() as u16;
        let max_scroll = total_lines.saturating_sub(self.visible_height);

        if self.scroll_offset < max_scroll {
            self.scroll_offset = self.scroll_offset.saturating_add(1);
        }
    }

    pub fn scroll_up(&mut self) {
        // Don't scroll past the first line (already handled by saturating_sub)
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
    log_store: Arc<LogStore>,
    mut log_rx: mpsc::UnboundedReceiver<(String, String)>,
) -> io::Result<()> {
    // Setup terminal
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

    // Restore terminal
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
    // Initial refresh and draw
    app.refresh_current_logs();
    terminal.draw(|f| ui(f, app))?;
    app.last_draw_time = Instant::now();

    // Spawn dedicated thread to read keyboard events using crossterm
    // With child processes having .stdin(Stdio::null()), they won't steal our keypresses
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let _event_thread = std::thread::spawn(move || {
        loop {
            match crossterm::event::read() {
                Ok(evt) => {
                    if event_tx.send(evt).is_err() {
                        break; // Channel closed, exit thread
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        // Wait for keyboard event with timeout (for log refresh)
        match event_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        return Ok(());
                    }
                    KeyCode::Char('c') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Down => {
                        app.next();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Up => {
                        app.previous();
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
                        for _ in 0..10 {
                            app.scroll_down();
                        }
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        for _ in 0..10 {
                            app.scroll_up();
                        }
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char('k') => {
                        if let Some(server) = app.get_selected_server_info() {
                            if let Some(ref tx) = app.command_tx {
                                let _ = tx.send(ServerCommand::Kill(server.name.clone()));
                            }
                        }
                    }
                    KeyCode::Char('r') => {
                        if let Some(server) = app.get_selected_server_info() {
                            if let Some(ref tx) = app.command_tx {
                                let _ = tx.send(ServerCommand::Restart(server.name.clone()));
                            }
                        }
                    }
                    KeyCode::Home => {
                        app.selected_index = 0;
                        app.scroll_offset = 0;
                        app.refresh_current_logs();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::End => {
                        app.selected_index = app.servers.len();
                        app.scroll_offset = 0;
                        app.refresh_current_logs();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    _ => {}
                }
            }
            Ok(Event::Mouse(mouse)) => {
                // Handle mouse wheel scrolling
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
            Ok(_) => {
                // Ignore other events (resize, etc.)
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

fn ui(f: &mut Frame, app: &mut TuiApp) {
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
        let is_running = app.running_servers.contains(&server.name);
        let status_icon = if is_running { "●" } else { "○" };
        let status_color = if is_running {
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
                .title(" Servers (↑↓=Nav Enter=Open k=Kill r=Restart q=Quit) ")
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

fn render_logs(f: &mut Frame, app: &mut TuiApp, area: ratatui::layout::Rect) {
    let selected_server = app.get_selected_server();

    let title = if let Some(server) = selected_server {
        format!(" Logs: {} (A/Z=Scroll Shift+Select=Copy) ", server)
    } else {
        " Logs: All (A/Z=Scroll Shift+Select=Copy) ".to_string()
    };

    // Use cached logs - NO fetching during render!
    let visible_height = area.height.saturating_sub(2);
    app.visible_height = visible_height;  // Update for scroll bounds
    let scroll = app.scroll_offset as usize;

    let log_lines: Vec<Line> = app.cached_logs
        .iter()
        .skip(scroll)
        .take(visible_height as usize)
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
