//! `vproxy-server --tui`: a live dashboard reading the admin socket's
//! newline-delimited JSON snapshots. Run it on the server, e.g.
//! `docker compose exec vproxy-server vproxy-server --tui`.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Frame;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use vproxy_server::Snapshot;

use crate::{bytes, duration};

pub async fn run(path: &Path) -> Result<()> {
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connect {} (is the server running?)", path.display()))?;
    let mut lines = BufReader::new(stream).lines();

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut lines).await;
    ratatui::restore();
    result
}

async fn event_loop<R: tokio::io::AsyncBufRead + Unpin>(
    terminal: &mut ratatui::DefaultTerminal,
    lines: &mut tokio::io::Lines<R>,
) -> Result<()> {
    let mut snap: Option<Snapshot> = None;
    let mut prev: Option<(u64, u64, Instant)> = None; // up, down, when
    let mut rate = (0f64, 0f64);
    loop {
        // Keyboard, non-blocking.
        while event::poll(Duration::ZERO)? {
            if let Event::Key(k) = event::read()? {
                let quit = matches!(k.code, KeyCode::Char('q') | KeyCode::Esc)
                    || (k.code == KeyCode::Char('c')
                        && k.modifiers.contains(KeyModifiers::CONTROL));
                if quit {
                    return Ok(());
                }
            }
        }

        terminal.draw(|f| draw(f, snap.as_ref(), rate))?;

        // Next snapshot, or time out to keep the keyboard responsive.
        match tokio::time::timeout(Duration::from_millis(150), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Ok(s) = serde_json::from_str::<Snapshot>(&line) {
                    let now = Instant::now();
                    if let Some((up, down, when)) = prev {
                        let dt = now.duration_since(when).as_secs_f64().max(0.001);
                        rate = (
                            s.bytes_up.saturating_sub(up) as f64 / dt,
                            s.bytes_down.saturating_sub(down) as f64 / dt,
                        );
                    }
                    prev = Some((s.bytes_up, s.bytes_down, now));
                    snap = Some(s);
                }
            }
            Ok(Ok(None)) => return Ok(()), // server closed the socket
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {} // timeout: loop and service the keyboard
        }
    }
}

fn draw(f: &mut Frame, snap: Option<&Snapshot>, rate: (f64, f64)) {
    let Some(s) = snap else {
        f.render_widget(
            Paragraph::new("waiting for the server…").block(titled()),
            f.area(),
        );
        return;
    };
    let chunks = Layout::vertical([Constraint::Length(9), Constraint::Min(0)]).split(f.area());

    let summary = Text::from(vec![
        Line::from(format!("uptime        {}", duration(s.uptime_secs))),
        Line::from(format!(
            "connections   {} open · {} total",
            s.conns_open, s.conns_total
        )),
        Line::from(format!(
            "streams       {} open · {} total",
            s.streams_open, s.streams_total
        )),
        Line::from(format!(
            "udp sessions  {} open · {} total",
            s.udp_open, s.udp_total
        )),
        Line::from(format!(
            "traffic       up {} ({}/s) · down {} ({}/s)",
            bytes(s.bytes_up),
            bytes(rate.0 as u64),
            bytes(s.bytes_down),
            bytes(rate.1 as u64),
        )),
        Line::from(format!("site          {} HTTP/3 requests", s.site_requests)),
        Line::from("quit: q"),
    ]);
    f.render_widget(Paragraph::new(summary).block(titled()), chunks[0]);

    let rows = s.accounts.iter().map(|a| {
        Row::new(vec![
            a.tag.clone(),
            a.open.to_string(),
            a.total.to_string(),
            duration(a.idle_secs),
        ])
    });
    let widths = [
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["account", "open", "total", "idle"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(" accounts "));
    f.render_widget(table, chunks[1]);
}

fn titled() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(" vproxy-server ")
}
