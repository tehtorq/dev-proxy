use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const MAX_LINES: usize = 200;

// Pre-formatted, ready-to-render log lines for each server
pub struct LogStore {
    servers: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl LogStore {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_line(&self, server_name: String, line: String) {
        let mut servers = self.servers.lock().unwrap();
        let logs = servers.entry(server_name).or_insert_with(Vec::new);
        logs.push(line);
        if logs.len() > MAX_LINES {
            logs.remove(0);
        }
    }

    pub fn get_lines(&self, server_name: Option<&str>) -> Vec<String> {
        let servers = self.servers.lock().unwrap();
        match server_name {
            Some(name) => {
                servers.get(name).cloned().unwrap_or_default()
            }
            None => {
                // "All" - concatenate all servers' logs
                let mut all = Vec::new();
                for (name, lines) in servers.iter() {
                    for line in lines {
                        all.push(format!("[{}] {}", name, line));
                    }
                }
                all
            }
        }
    }

    pub fn has_logs(&self, server_name: &str) -> bool {
        self.servers.lock().unwrap().contains_key(server_name)
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
    log_store: Arc<LogStore>,
}

impl TuiApp {
    pub fn new(servers: Vec<ServerInfo>) -> Self {
        Self {
            servers,
            selected_index: 0,
            scroll_offset: 0,
            cached_logs: Vec::new(),
            log_store: Arc::new(LogStore::new()), // Placeholder, will be set later
        }
    }

    pub fn refresh_current_logs(&mut self) {
        let selected = self.get_selected_server();
        self.cached_logs = self.log_store.get_lines(selected);
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
    // Setup terminal
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    crossterm::terminal::enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let log_store = Arc::new(LogStore::new());

    // Give app access to log_store
    app.log_store = log_store.clone();

    // Spawn background task to collect logs
    let store_clone = log_store.clone();
    std::thread::spawn(move || {
        while let Some((server_name, message)) = log_rx.blocking_recv() {
            store_clone.add_line(server_name, message);
        }
    });

    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
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

    loop {
        // Wait for event with timeout for periodic log refresh
        if event::poll(std::time::Duration::from_millis(250))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(());
                        }
                        KeyCode::Down => {
                            app.next();
                            terminal.draw(|f| ui(f, app))?;
                        }
                        KeyCode::Up => {
                            app.previous();
                            terminal.draw(|f| ui(f, app))?;
                        }
                        KeyCode::Enter => {
                            if let Some(server) = app.get_selected_server_info() {
                                let url = format!("http://{}", server.domain);
                                // Open in browser
                                #[cfg(target_os = "macos")]
                                let _ = std::process::Command::new("open").arg(&url).spawn();
                                #[cfg(target_os = "linux")]
                                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
                                #[cfg(target_os = "windows")]
                                let _ = std::process::Command::new("cmd").args(&["/C", "start", &url]).spawn();
                            }
                        }
                        KeyCode::PageDown => {
                            for _ in 0..10 {
                                app.scroll_down();
                            }
                            terminal.draw(|f| ui(f, app))?;
                        }
                        KeyCode::PageUp => {
                            for _ in 0..10 {
                                app.scroll_up();
                            }
                            terminal.draw(|f| ui(f, app))?;
                        }
                        KeyCode::Home => {
                            app.selected_index = 0;
                            app.scroll_offset = 0;
                            app.refresh_current_logs();
                            terminal.draw(|f| ui(f, app))?;
                        }
                        KeyCode::End => {
                            app.selected_index = app.servers.len();
                            app.scroll_offset = 0;
                            app.refresh_current_logs();
                            terminal.draw(|f| ui(f, app))?;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        } else {
            // Timeout - refresh for new logs
            app.refresh_current_logs();
            terminal.draw(|f| ui(f, app))?;
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
        let has_logs = app.log_store.servers.lock().unwrap().contains_key(&server.name);
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
