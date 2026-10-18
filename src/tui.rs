//! Minimal terminal UI: server/mode header, live counters, recent log lines.
//! `q` (or Esc / Ctrl-C) shuts the proxy down gracefully.

use crate::config::Config;
use crate::runtime::ActiveServer;
use crate::servers::ServerList;
use crate::stats::{human_bytes, Snapshot, STATS};
use anyhow::Result;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind, KeyModifiers,
};
use ratatui::layout::{Constraint, Direction, Layout, Position};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing_subscriber::fmt::MakeWriter;

/// Ring buffer of formatted log lines, fed by a tracing writer.
pub struct LogBuffer {
    lines: Mutex<VecDeque<String>>,
    capacity: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            lines: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        })
    }

    fn push(&self, line: String) {
        let mut lines = self.lines.lock().expect("log buffer poisoned");
        if lines.len() == self.capacity {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    pub fn tail(&self, n: usize) -> Vec<String> {
        let lines = self.lines.lock().expect("log buffer poisoned");
        lines.iter().rev().take(n).rev().cloned().collect()
    }

    pub fn writer(self: &Arc<Self>) -> LogWriter {
        LogWriter {
            buffer: self.clone(),
            partial: String::new(),
        }
    }
}

/// `std::io::Write` that splits incoming text into lines for the buffer.
pub struct LogWriter {
    buffer: Arc<LogBuffer>,
    partial: String,
}

impl io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.partial.push_str(&String::from_utf8_lossy(buf));
        while let Some(idx) = self.partial.find('\n') {
            let line = self.partial[..idx].trim_end().to_string();
            self.partial.drain(..=idx);
            if !line.is_empty() {
                self.buffer.push(line);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `tracing_subscriber` writer factory backed by a [`LogBuffer`].
#[derive(Clone)]
pub struct LogSink(pub Arc<LogBuffer>);

impl<'a> MakeWriter<'a> for LogSink {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.0.writer()
    }
}

/// What the keyboard currently drives.
enum Mode {
    Normal,
    /// Typing or pasting a `vless://` link.
    Adding(String),
    /// `d` pressed on a server; `y`/Enter removes it.
    ConfirmDelete(usize),
}

/// Outcome of one handshake measurement.
type PingResult = Result<Duration, String>;

struct App {
    mode: Mode,
    config: Arc<Config>,
    servers: ServerList,
    active: ActiveServer,
    active_index: usize,
    selected: usize,
    logs: Arc<LogBuffer>,
    started: Instant,
    last: Snapshot,
    last_at: Instant,
    up_rate: f64,
    down_rate: f64,
    status: String,
    /// Latency per server: `None` = not measured yet / in flight.
    latency: Vec<Option<PingResult>>,
    ping_rx: mpsc::UnboundedReceiver<(usize, u64, PingResult)>,
    ping_tx: mpsc::UnboundedSender<(usize, u64, PingResult)>,
    /// Generation of the current ping round; stale results are dropped.
    ping_round: u64,
    pings_in_flight: usize,
}

impl App {
    /// Measure every server concurrently; results arrive through `ping_rx`.
    fn ping_all(&mut self) {
        if self.servers.is_empty() {
            return;
        }
        self.ping_round += 1;
        let round = self.ping_round;
        self.latency = vec![None; self.servers.len()];
        self.pings_in_flight = self.servers.len();
        let limit = Duration::from_secs(self.config.runtime.connect_timeout_secs.clamp(1, 10));
        for (i, entry) in self.servers.entries.iter().enumerate() {
            let server = entry.server.clone();
            let tx = self.ping_tx.clone();
            tokio::spawn(async move {
                let result = crate::runtime::measure_handshake(&server, limit)
                    .await
                    .map_err(|e| e.to_string());
                let _ = tx.send((i, round, result));
            });
        }
        self.status = format!("pinging {} servers…", self.servers.len());
    }

    fn collect_pings(&mut self) {
        while let Ok((i, round, result)) = self.ping_rx.try_recv() {
            if round != self.ping_round || i >= self.latency.len() {
                continue;
            }
            self.latency[i] = Some(result);
            self.pings_in_flight = self.pings_in_flight.saturating_sub(1);
            if self.pings_in_flight == 0 {
                self.status = match self.best_index() {
                    Some(best) => format!(
                        "fastest: {} ({}); b switches to it",
                        self.servers.entries[best].name,
                        latency_text(&self.latency[best])
                    ),
                    None => "ping finished: no server answered".to_string(),
                };
            }
        }
    }

    /// Index of the lowest measured latency.
    fn best_index(&self) -> Option<usize> {
        self.latency
            .iter()
            .enumerate()
            .filter_map(|(i, l)| match l {
                Some(Ok(d)) => Some((i, *d)),
                _ => None,
            })
            .min_by_key(|(_, d)| *d)
            .map(|(i, _)| i)
    }

    fn switch_to_best(&mut self) {
        match self.best_index() {
            Some(best) => {
                self.selected = best;
                self.switch_to_selected();
            }
            None if self.pings_in_flight > 0 => {
                self.status = "still pinging…".to_string();
            }
            None => self.status = "no latency data: press p to ping".to_string(),
        }
    }
    fn tick(&mut self) {
        let now = Instant::now();
        let snap = STATS.snapshot();
        let dt = now.duration_since(self.last_at).as_secs_f64();
        if dt >= 0.5 {
            self.up_rate = (snap.up.saturating_sub(self.last.up)) as f64 / dt;
            self.down_rate = (snap.down.saturating_sub(self.last.down)) as f64 / dt;
            self.last = snap;
            self.last_at = now;
        }
    }

    fn select(&mut self, delta: i32) {
        let n = self.servers.len() as i32;
        if n == 0 {
            return;
        }
        self.selected = ((self.selected as i32 + delta).rem_euclid(n)) as usize;
    }

    fn remove_at(&mut self, i: usize) {
        if i == self.active_index {
            self.status = "cannot remove the active server, switch first".to_string();
            return;
        }
        match self.servers.remove(i) {
            Ok(entry) => {
                if i < self.latency.len() {
                    self.latency.remove(i);
                }
                if i < self.active_index {
                    self.active_index -= 1;
                }
                self.selected = i.min(self.servers.len().saturating_sub(1));
                self.status = format!("removed {}", entry.name);
            }
            Err(e) => self.status = format!("cannot remove: {e}"),
        }
    }

    fn add_link(&mut self, link: &str) {
        let link = link.trim();
        if link.is_empty() {
            self.status = "nothing to add".to_string();
            return;
        }
        match self.servers.add_link(link, self.config.inbound.port) {
            Ok(entry) => {
                self.status = format!("added {}", entry.name);
                self.selected = self.servers.len() - 1;
                self.latency.push(None);
            }
            Err(e) => self.status = format!("cannot add: {e}"),
        }
    }

    /// Returns true when the key asks to quit.
    fn handle_key(&mut self, key: event::KeyEvent) -> bool {
        let ctrl_c =
            key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        match &mut self.mode {
            Mode::Adding(input) => {
                if ctrl_c {
                    return true;
                }
                match key.code {
                    KeyCode::Esc => {
                        self.mode = Mode::Normal;
                        self.status = "add cancelled".to_string();
                    }
                    KeyCode::Enter => {
                        let link = std::mem::take(input);
                        self.mode = Mode::Normal;
                        self.add_link(&link);
                    }
                    KeyCode::Backspace => {
                        input.pop();
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        input.push(c);
                    }
                    _ => {}
                }
                false
            }
            Mode::ConfirmDelete(i) => {
                let i = *i;
                self.mode = Mode::Normal;
                if ctrl_c {
                    return true;
                }
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => self.remove_at(i),
                    _ => self.status = "remove cancelled".to_string(),
                }
                false
            }
            Mode::Normal => {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => self.select(-1),
                    KeyCode::Down | KeyCode::Char('j') => self.select(1),
                    KeyCode::Enter => self.switch_to_selected(),
                    KeyCode::Char('p') => self.ping_all(),
                    KeyCode::Char('b') => self.switch_to_best(),
                    KeyCode::Char('a') => {
                        self.mode = Mode::Adding(String::new());
                        self.status =
                            "paste a vless:// link, Enter to add, Esc to cancel".to_string();
                    }
                    KeyCode::Char('d') | KeyCode::Delete => {
                        if let Some(entry) = self.servers.entries.get(self.selected) {
                            if self.selected == self.active_index {
                                self.status =
                                    "cannot remove the active server, switch first".to_string();
                            } else if self.servers.len() == 1 {
                                self.status = "cannot remove the last server".to_string();
                            } else {
                                self.mode = Mode::ConfirmDelete(self.selected);
                                self.status = format!("remove {}? y/n", entry.name);
                            }
                        }
                    }
                    _ => {}
                }
                matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c
            }
        }
    }

    fn paste(&mut self, text: &str) {
        if let Mode::Adding(input) = &mut self.mode {
            input.push_str(text.trim());
        }
    }

    fn switch_to_selected(&mut self) {
        let Some(entry) = self.servers.entries.get(self.selected) else {
            return;
        };
        if self.selected == self.active_index {
            self.status = format!("{} is already active", entry.name);
            return;
        }
        match self.active.swap(entry.server.clone(), &self.config) {
            Ok(()) => {
                self.active_index = self.selected;
                self.status = format!("switched to {} (new connections only)", entry.name);
                if let Err(e) = self.servers.persist_first(self.selected) {
                    self.status = format!("switched to {}; not saved: {e}", entry.name);
                }
            }
            Err(e) => self.status = format!("cannot switch: {e}"),
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let adding = matches!(self.mode, Mode::Adding(_));
        let list_height = if self.servers.len() > 1 || adding {
            (self.servers.len() as u16 + 2).min(8)
        } else {
            0
        };
        let input_height = if adding { 3 } else { 0 };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(list_height),
                Constraint::Length(input_height),
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .split(frame.area());

        let server = &self.active.get();
        let name = server
            .remark
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("{s}  ({})", server.endpoint()))
            .unwrap_or_else(|| server.endpoint());
        let engine = match self.config.needs_xray_sidecar() {
            Ok(true) => "xray-core sidecar",
            Ok(false) => "native",
            Err(_) => "?",
        };
        let flow = server.flow.as_deref().unwrap_or("-");
        let mux = match self.config.mux.sessions_per_connection() {
            Some(n) if server.flow.is_none() => format!("mux {n}"),
            Some(_) => "mux off (vision)".to_string(),
            None => "mux off".to_string(),
        };
        let tun = if self.config.tun.enabled { "ON" } else { "off" };
        let uptime = self.started.elapsed().as_secs();
        let header = vec![
            Line::from(vec![
                Span::styled("server   ", Style::default().fg(Color::DarkGray)),
                Span::styled(name, Style::default().add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("security ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!(
                    "{}  flow {}  sni {}  engine {}  {}",
                    server.security,
                    flow,
                    server.tls_server_name(),
                    engine,
                    mux
                )),
            ]),
            Line::from(vec![
                Span::styled("inbound  ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!(
                    "{} {}   TUN {}   uptime {:02}:{:02}:{:02}",
                    self.config.inbound.protocol,
                    self.config.inbound_addr(),
                    tun,
                    uptime / 3600,
                    uptime % 3600 / 60,
                    uptime % 60
                )),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(header).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" vproxy {} ", env!("CARGO_PKG_VERSION"))),
            ),
            chunks[0],
        );

        if list_height > 0 {
            let items: Vec<ListItem> = self
                .servers
                .entries
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    let marker = if i == self.active_index { "● " } else { "  " };
                    let latency = latency_text(self.latency.get(i).unwrap_or(&None));
                    let line = format!(
                        "{marker}{:<28} {:<16} {:<16} {:>8}",
                        e.name,
                        e.server.endpoint(),
                        e.kind(),
                        latency
                    );
                    let style = if i == self.active_index {
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    ListItem::new(Line::from(Span::styled(line, style)))
                })
                .collect();
            let mut state = ListState::default().with_selected(Some(self.selected));
            let list =
                List::new(items)
                    .block(Block::default().borders(Borders::ALL).title(
                        " servers (↑↓ select, Enter switch, p ping, b best, a add, d remove) ",
                    ))
                    .highlight_style(Style::default().bg(Color::DarkGray))
                    .highlight_symbol("▶ ");
            frame.render_stateful_widget(list, chunks[1], &mut state);
        }

        if let Mode::Adding(input) = &self.mode {
            let area = chunks[2];
            let width = area.width.saturating_sub(2) as usize;
            // Keep the end of a long link visible while typing.
            let skip = input
                .chars()
                .count()
                .saturating_sub(width.saturating_sub(1));
            let shown: String = input.chars().skip(skip).collect();
            frame.render_widget(
                Paragraph::new(shown.as_str()).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" add server: paste vless:// link, Enter to add, Esc to cancel "),
                ),
                area,
            );
            frame.set_cursor_position(Position::new(
                area.x + 1 + shown.chars().count() as u16,
                area.y + 1,
            ));
        }

        let s = STATS.snapshot();
        let stats = Line::from(vec![
            Span::raw(format!("conns {} active / {} total   ", s.active, s.total)),
            Span::styled("↑ ", Style::default().fg(Color::Green)),
            Span::raw(format!(
                "{} ({}/s)   ",
                human_bytes(s.up),
                human_bytes(self.up_rate as u64)
            )),
            Span::styled("↓ ", Style::default().fg(Color::Cyan)),
            Span::raw(format!(
                "{} ({}/s)   ",
                human_bytes(s.down),
                human_bytes(self.down_rate as u64)
            )),
            Span::styled(
                format!("errors {}", s.errors),
                if s.errors > 0 {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
        ]);
        frame.render_widget(
            Paragraph::new(stats).block(Block::default().borders(Borders::ALL).title(" traffic ")),
            chunks[3],
        );

        let height = chunks[4].height.saturating_sub(2) as usize;
        let lines: Vec<Line> = self
            .logs
            .tail(height)
            .into_iter()
            .map(|l| {
                let style = if l.contains("ERROR") {
                    Style::default().fg(Color::Red)
                } else if l.contains(" WARN") {
                    Style::default().fg(Color::Yellow)
                } else if l.contains("DEBUG") {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(l, style))
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" log ")),
            chunks[4],
        );

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" quit  "),
                Span::styled(" ↑↓ ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" server  "),
                Span::styled(" Enter ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" switch  "),
                Span::styled(" a ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" add  "),
                Span::styled(" d ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" remove  "),
                Span::styled(" p ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" ping  "),
                Span::styled(" b ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" best   "),
                Span::styled(&self.status, Style::default().fg(Color::Yellow)),
            ])),
            chunks[5],
        );
    }
}

/// `123 ms`, `fail`, `…` or blank.
fn latency_text(l: &Option<PingResult>) -> String {
    match l {
        None => "…".to_string(),
        Some(Ok(d)) => format!("{} ms", d.as_millis()),
        Some(Err(_)) => "fail".to_string(),
    }
}

/// Run the UI until the user quits or the server task ends.
pub async fn run(
    config: Arc<Config>,
    servers: ServerList,
    active: ActiveServer,
    logs: Arc<LogBuffer>,
    mut server: JoinHandle<Result<()>>,
) -> Result<()> {
    let mut terminal = ratatui::init();
    let _ = crossterm::execute!(io::stdout(), EnableBracketedPaste);
    let (ping_tx, ping_rx) = mpsc::unbounded_channel();
    let active_index = servers
        .entries
        .iter()
        .position(|e| {
            e.server.endpoint() == config.server.endpoint() && e.server.uuid == config.server.uuid
        })
        .unwrap_or(0);
    let mut app = App {
        mode: Mode::Normal,
        config,
        servers,
        active,
        active_index,
        selected: active_index,
        logs,
        started: Instant::now(),
        last: STATS.snapshot(),
        last_at: Instant::now(),
        up_rate: 0.0,
        down_rate: 0.0,
        status: String::new(),
        latency: Vec::new(),
        ping_rx,
        ping_tx,
        ping_round: 0,
        pings_in_flight: 0,
    };
    if app.servers.len() > 1 {
        app.ping_all();
    }

    let mut quitting = false;
    let outcome = loop {
        app.tick();
        app.collect_pings();
        if let Err(e) = terminal.draw(|f| app.draw(f)) {
            break Err(anyhow::Error::from(e));
        }

        // Drain pending key events without blocking the async loop.
        while event::poll(Duration::ZERO).unwrap_or(false) {
            let quit = match event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => app.handle_key(key),
                Ok(Event::Paste(text)) => {
                    app.paste(&text);
                    false
                }
                _ => false,
            };
            {
                if quit && !quitting {
                    quitting = true;
                    app.status = "shutting down…".to_string();
                    // serve() owns the graceful shutdown path via SIGINT.
                    // SAFETY: raising a signal in our own process.
                    unsafe { libc::raise(libc::SIGINT) };
                }
            }
        }

        if server.is_finished() {
            break match (&mut server).await {
                Ok(result) => result,
                Err(e) => Err(anyhow::anyhow!("server task failed: {e}")),
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let _ = crossterm::execute!(io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    outcome
}
