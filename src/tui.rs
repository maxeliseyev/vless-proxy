//! Minimal terminal UI: server/mode header, live counters, recent log lines.
//! `q` (or Esc / Ctrl-C) shuts the proxy down gracefully.

use crate::config::Config;
use crate::runtime::ActiveServer;
use crate::servers::ServerList;
use crate::stats::{human_bytes, Snapshot, STATS};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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

struct App {
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
}

impl App {
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
        let list_height = if self.servers.len() > 1 {
            (self.servers.len() as u16 + 2).min(8)
        } else {
            0
        };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(list_height),
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
                    "{}  flow {}  sni {}  engine {}",
                    server.security,
                    flow,
                    server.tls_server_name(),
                    engine
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
                    let line = format!(
                        "{marker}{:<28} {:<16} {}",
                        e.name,
                        e.server.endpoint(),
                        e.kind()
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
            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" servers (↑↓ select, Enter switch) "),
                )
                .highlight_style(Style::default().bg(Color::DarkGray))
                .highlight_symbol("▶ ");
            frame.render_stateful_widget(list, chunks[1], &mut state);
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
            chunks[2],
        );

        let height = chunks[3].height.saturating_sub(2) as usize;
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
            chunks[3],
        );

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" quit  "),
                Span::styled(" ↑↓ ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" server  "),
                Span::styled(" Enter ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" switch   "),
                Span::styled(&self.status, Style::default().fg(Color::Yellow)),
            ])),
            chunks[4],
        );
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
    let active_index = servers
        .entries
        .iter()
        .position(|e| {
            e.server.endpoint() == config.server.endpoint() && e.server.uuid == config.server.uuid
        })
        .unwrap_or(0);
    let mut app = App {
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
    };

    let mut quitting = false;
    let outcome = loop {
        app.tick();
        if let Err(e) = terminal.draw(|f| app.draw(f)) {
            break Err(anyhow::Error::from(e));
        }

        // Drain pending key events without blocking the async loop.
        while event::poll(Duration::ZERO).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => app.select(-1),
                    KeyCode::Down | KeyCode::Char('j') => app.select(1),
                    KeyCode::Enter => app.switch_to_selected(),
                    _ => {}
                }
                let quit = matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL));
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

    ratatui::restore();
    outcome
}
