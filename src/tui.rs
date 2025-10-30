use crossterm::event::{Event, KeyCode, KeyEventKind, MouseEventKind};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
    Frame, Terminal,
};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

const MAX_LINES: usize = 1000;  // Keep more history per server

/// Strip ANSI escape sequences (color codes, etc.) from a string
fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Start of ANSI escape sequence
            if chars.next() == Some('[') {
                // Skip until we find a letter (the command character)
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

    pub fn clear_logs(&self, server_name: &str) {
        // Clear logs for specific server
        let mut servers = self.servers.lock().unwrap();
        if let Some(logs) = servers.get_mut(server_name) {
            logs.clear();
        }
        drop(servers);

        // Also clear from "All" cache - just rebuild it
        let servers = self.servers.lock().unwrap();
        let mut all = Vec::new();
        for (name, lines) in servers.iter() {
            for line in lines {
                all.push(format!("[{}] {}", name, line));
            }
        }
        drop(servers);

        let mut cache = self.all_logs_cache.lock().unwrap();
        *cache = all;
        drop(cache);

        // Increment version to trigger UI update
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
    view_mode: ViewMode,
    // Text selection state (for logs view)
    cursor_line: usize,     // Current line position in logs view
    selection_start: Option<usize>,  // Start line of selection (None = no selection)
    selection_end: Option<usize>,    // End line of selection
    // Status message (temporary, disappears after a few seconds)
    status_message: Option<String>,
    status_message_time: Option<Instant>,
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
            view_mode: ViewMode::ServerList,
            cursor_line: 0,
            selection_start: None,
            selection_end: None,
            status_message: None,
            status_message_time: None,
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

    pub fn refresh_current_logs(&mut self) {
        // Check if we're at the bottom before refreshing
        let was_at_bottom = {
            let total_lines = self.cached_logs.len() as u16;
            let max_scroll = total_lines.saturating_sub(self.visible_height);
            self.scroll_offset >= max_scroll
        };

        let selected = self.get_selected_server();
        self.cached_logs = self.log_store.get_lines(selected);
        self.cached_active_servers = self.log_store.get_active_servers_snapshot();

        // Get running status directly from LogStore (no log parsing!)
        self.running_servers = self.log_store.get_running_servers_snapshot();

        // Ensure cursor is within bounds of new log count
        if self.cursor_line >= self.cached_logs.len() && !self.cached_logs.is_empty() {
            self.cursor_line = self.cached_logs.len() - 1;
        } else if self.cached_logs.is_empty() {
            self.cursor_line = 0;
        }

        // Auto-scroll: if we were at the bottom, stay at the bottom as logs are added
        if was_at_bottom {
            self.scroll_to_bottom();
        }

        self.last_version = self.log_store.get_version();
    }

    pub fn next(&mut self) {
        if self.selected_index < self.servers.len() {
            self.selected_index += 1;
        }
        self.refresh_current_logs();
        // Reset cursor and selection when switching servers
        self.cursor_line = 0;
        self.selection_start = None;
        self.selection_end = None;
        // Scroll to bottom to see most recent logs
        self.scroll_to_bottom();
    }

    pub fn previous(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
        self.refresh_current_logs();
        // Reset cursor and selection when switching servers
        self.cursor_line = 0;
        self.selection_start = None;
        self.selection_end = None;
        // Scroll to bottom to see most recent logs
        self.scroll_to_bottom();
    }

    pub fn scroll_to_bottom(&mut self) {
        let total_lines = self.cached_logs.len() as u16;
        self.scroll_offset = total_lines.saturating_sub(self.visible_height);
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

    pub fn enter_logs_view(&mut self) {
        self.view_mode = ViewMode::LogsView;
        // Set cursor to first visible line on screen (scroll_offset)
        // This ensures the cursor is immediately visible
        self.cursor_line = self.scroll_offset as usize;
        self.selection_start = None;
        self.selection_end = None;
        // Ensure cursor is within bounds
        if self.cursor_line >= self.cached_logs.len() && !self.cached_logs.is_empty() {
            self.cursor_line = self.cached_logs.len() - 1;
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
            // Auto-scroll to keep cursor visible
            if self.cursor_line < self.scroll_offset as usize {
                self.scroll_offset = self.cursor_line as u16;
            }
        }
    }

    pub fn move_cursor_down(&mut self) {
        if self.cursor_line < self.cached_logs.len().saturating_sub(1) {
            self.cursor_line += 1;
            // Auto-scroll to keep cursor visible
            let bottom_visible = self.scroll_offset as usize + self.visible_height as usize;
            if self.cursor_line >= bottom_visible {
                self.scroll_offset = (self.cursor_line as u16).saturating_sub(self.visible_height - 1);
            }
        }
    }

    pub fn toggle_selection(&mut self) {
        match self.selection_start {
            None => {
                // Start new selection
                self.selection_start = Some(self.cursor_line);
                self.selection_end = Some(self.cursor_line);
            }
            Some(start) => {
                // End selection and copy to clipboard
                let end = self.cursor_line;
                let (from, to) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };

                // Get selected text and strip ANSI color codes
                let selected_lines: Vec<String> = self.cached_logs
                    .iter()
                    .skip(from)
                    .take(to - from + 1)
                    .map(|line| strip_ansi_codes(line))
                    .collect();

                let selected_text = selected_lines.join("\n");

                // Copy to clipboard
                match arboard::Clipboard::new() {
                    Ok(mut clipboard) => {
                        if clipboard.set_text(&selected_text).is_ok() {
                            // Show temporary status message
                            self.set_status_message(format!("📋 Copied {} lines to clipboard!", to - from + 1));
                        } else {
                            self.set_status_message("❌ Failed to copy to clipboard".to_string());
                        }
                    }
                    Err(_) => {
                        self.set_status_message("❌ Failed to access clipboard".to_string());
                    }
                }

                // Clear selection
                self.selection_start = None;
                self.selection_end = None;
            }
        }
    }

    pub fn update_selection(&mut self) {
        // Update selection end as cursor moves (if selection is active)
        if self.selection_start.is_some() {
            self.selection_end = Some(self.cursor_line);
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
                    KeyCode::Right if app.view_mode == ViewMode::ServerList => {
                        // Enter logs view
                        app.enter_logs_view();
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Left if app.view_mode == ViewMode::LogsView => {
                        // Exit logs view, return to server list
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
                        // Toggle selection
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
                        // Jump to top of logs
                        app.scroll_offset = 0;
                        terminal.draw(|f| ui(f, app))?;
                        app.last_draw_time = Instant::now();
                    }
                    KeyCode::Char('b') | KeyCode::Char('B') => {
                        // Jump to bottom of logs
                        app.scroll_to_bottom();
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
                        // Copy logs to clipboard (strip ANSI codes)
                        let logs_text: String = app.cached_logs
                            .iter()
                            .map(|line| strip_ansi_codes(line))
                            .collect::<Vec<String>>()
                            .join("\n");
                        match arboard::Clipboard::new() {
                            Ok(mut clipboard) => {
                                if clipboard.set_text(&logs_text).is_ok() {
                                    app.set_status_message("📋 Copied all logs to clipboard!".to_string());
                                } else {
                                    app.set_status_message("❌ Failed to copy to clipboard".to_string());
                                }
                            }
                            Err(_) => {
                                app.set_status_message("❌ Failed to access clipboard".to_string());
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
    // Clear expired status messages
    app.clear_expired_status();

    // Create main layout with status bar at bottom
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),      // Main content area
            Constraint::Length(1),   // Status bar
        ])
        .split(f.area());

    // Split main area horizontally for server list and logs
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_chunks[0]);

    render_server_list(f, app, chunks[0]);
    render_logs(f, app, chunks[1]);
    render_status_bar(f, app, main_chunks[1]);
}

fn render_status_bar(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let status_line = if let Some(ref msg) = app.status_message {
        Line::from(Span::styled(msg.as_str(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)))
    } else {
        Line::from("")
    };

    let paragraph = Paragraph::new(status_line);
    f.render_widget(paragraph, area);
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
                .title(" Servers (↑↓=Nav →=Logs Enter=Open k=Kill r=Restart q=Quit) ")
                .borders(Borders::ALL)
                .border_style(if app.view_mode == ViewMode::ServerList {
                    Style::default().fg(Color::Yellow)  // Highlight when focused
                } else {
                    Style::default().fg(Color::Cyan)
                }),
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

    let title = if app.view_mode == ViewMode::LogsView {
        if let Some(server) = selected_server {
            format!(" Logs: {} (←=Back ↑↓=Navigate Space=Select) ", server)
        } else {
            " Logs: All (←=Back ↑↓=Navigate Space=Select) ".to_string()
        }
    } else {
        if let Some(server) = selected_server {
            format!(" Logs: {} (→=Focus c=Copy f=Flush A/Z=Scroll T/B=Top/Bottom) ", server)
        } else {
            " Logs: All (→=Focus c=Copy A/Z=Scroll T/B=Top/Bottom) ".to_string()
        }
    };

    // Use cached logs - NO fetching during render!
    let visible_height = area.height.saturating_sub(2);
    app.visible_height = visible_height;  // Update for scroll bounds
    let scroll = app.scroll_offset as usize;

    // Calculate selection range if active
    let selection_range = if let (Some(start), Some(end)) = (app.selection_start, app.selection_end) {
        let (from, to) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        Some((from, to))
    } else {
        None
    };

    // Build visible log lines with proper styling
    let mut log_lines: Vec<Line> = app.cached_logs
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible_height as usize)
        .map(|(original_idx, line)| {
            let actual_idx = original_idx;
            let is_cursor = app.view_mode == ViewMode::LogsView && actual_idx == app.cursor_line;
            let is_selected = selection_range.map_or(false, |(from, to)| actual_idx >= from && actual_idx <= to);

            let mut style = Style::default();

            if is_selected {
                // Highlighted selection background
                style = style.bg(Color::DarkGray).fg(Color::White);
            }

            if is_cursor {
                // Cursor line - add bold and different background
                if is_selected {
                    style = style.bg(Color::Blue).add_modifier(Modifier::BOLD);
                } else {
                    style = style.bg(Color::DarkGray).add_modifier(Modifier::BOLD);
                }
            }

            Line::from(Span::styled(line.as_str(), style))
        })
        .collect();

    // Fill remaining space with empty lines to prevent visual corruption
    while log_lines.len() < visible_height as usize {
        log_lines.push(Line::from(""));
    }

    let paragraph = Paragraph::new(log_lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(if app.view_mode == ViewMode::LogsView {
                    Style::default().fg(Color::Yellow)  // Highlight when focused
                } else {
                    Style::default().fg(Color::Cyan)
                }),
        );

    f.render_widget(paragraph, area);

    // Only show scrollbar if content doesn't fit on screen
    let total_lines = app.cached_logs.len();
    if total_lines > visible_height as usize {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        let mut scrollbar_state = ScrollbarState::new(total_lines.saturating_sub(visible_height as usize))
            .position(app.scroll_offset as usize);

        f.render_stateful_widget(
            scrollbar,
            area.inner(ratatui::layout::Margin { vertical: 1, horizontal: 0 }),
            &mut scrollbar_state,
        );
    }
}
