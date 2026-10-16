//! Minimal terminal UI: server/mode header, live counters, recent log lines.
//! `q` (or Esc / Ctrl-C) shuts the proxy down gracefully.

use crate::config::Config;
use crate::stats::{human_bytes, Snapshot, STATS};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
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

    fn draw(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .split(frame.area());

        let server = &self.config.server;
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
            Paragraph::new(header).block(Block::default().borders(Borders::ALL).title(" vproxy ")),
            chunks[0],
        );

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
            chunks[1],
        );

        let height = chunks[2].height.saturating_sub(2) as usize;
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
            chunks[2],
        );

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Gray)),
                Span::raw(" quit   "),
                Span::styled(&self.status, Style::default().fg(Color::Yellow)),
            ])),
            chunks[3],
        );
    }
}

/// Run the UI until the user quits or the server task ends.
pub async fn run(
    config: Arc<Config>,
    logs: Arc<LogBuffer>,
    mut server: JoinHandle<Result<()>>,
) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App {
        config,
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
