//! Route a sidecar's stdout/stderr through `tracing` instead of letting it
//! write to the terminal: in `--tui` mode a child writing straight to the
//! tty scribbles over the frame, and in every mode one log format and one
//! log file are easier to read than two interleaved ones.
//!
//! sing-box only adapts the system's traffic to our SOCKS inbound, so its
//! per-connection errors always mirror something vproxy logs itself (a
//! refused SOCKS request, or our own dial to the server). Those go to
//! DEBUG; what stays visible is start/stop and system-level trouble (TUN
//! interface, routes, DNS, permissions), and the last lines are kept so a
//! crash can say why.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Child;
use tracing::Level;

const KEEP_LAST: usize = 5;

/// Handle on a forwarded sidecar: remembers its last few lines.
#[derive(Clone, Default)]
pub struct SidecarLog {
    last: Arc<Mutex<VecDeque<String>>>,
}

impl SidecarLog {
    /// The most recent lines (oldest first), for an exit message.
    pub fn last_lines(&self) -> Vec<String> {
        self.last
            .lock()
            .expect("sidecar log poisoned")
            .iter()
            .cloned()
            .collect()
    }

    /// `status` plus the sidecar's final words, for a `bail!`.
    pub fn exit_reason(&self, status: std::process::ExitStatus) -> String {
        let last = self.last_lines();
        match last.last() {
            Some(line) => format!("{status}: {line}"),
            None => status.to_string(),
        }
    }

    fn remember(&self, line: &str) {
        let mut last = self.last.lock().expect("sidecar log poisoned");
        if last.len() == KEEP_LAST {
            last.pop_front();
        }
        last.push_back(line.to_string());
    }
}

/// Take the child's piped stdout and stderr and re-emit every line as a
/// tracing event prefixed with `[name]`, at the level the line itself
/// carries. Pipes the child never got (not `Stdio::piped()`) are skipped.
pub fn forward_logs(child: &mut Child, name: &'static str) -> SidecarLog {
    let log = SidecarLog::default();
    if let Some(out) = child.stdout.take() {
        tokio::spawn(pump(out, name, log.clone()));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(pump(err, name, log.clone()));
    }
    log
}

async fn pump<R: AsyncRead + Unpin>(reader: R, name: &'static str, log: SidecarLog) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (level, message) = classify(line);
        let message = strip_request_id(message);
        let level = demote(name, level, message);
        log.remember(message);
        match level {
            Level::ERROR => tracing::error!("[{name}] {message}"),
            Level::WARN => tracing::warn!("[{name}] {message}"),
            Level::INFO => tracing::info!("[{name}] {message}"),
            _ => tracing::debug!("[{name}] {message}"),
        }
    }
}

/// Level from the line's own tag and the text after it. sing-box writes
/// `ERROR [id 10ms] msg` (or with a leading `+0300 2026-10-21 16:43:56`),
/// xray writes `2026/10/21 16:43:56 [Warning] msg`; anything else is INFO
/// as is.
fn classify(line: &str) -> (Level, &str) {
    const TAGS: &[(&str, Level)] = &[
        ("PANIC", Level::ERROR),
        ("FATAL", Level::ERROR),
        ("ERROR", Level::ERROR),
        ("[Error]", Level::ERROR),
        ("WARN", Level::WARN),
        ("[Warning]", Level::WARN),
        ("INFO", Level::INFO),
        ("[Info]", Level::INFO),
        ("DEBUG", Level::DEBUG),
        ("[Debug]", Level::DEBUG),
        ("TRACE", Level::TRACE),
    ];
    // Timestamps come first; the tag is within the first few tokens.
    for (i, token) in line.split_whitespace().take(5).enumerate() {
        for (tag, level) in TAGS {
            if token == *tag || (i == 0 && token.starts_with(tag)) {
                let after = line.find(token).map(|p| p + token.len()).unwrap_or(0);
                return (*level, line[after..].trim_start());
            }
        }
    }
    (Level::INFO, line)
}

/// `[988949701 10ms] connection: …` → `connection: …`. The id only
/// correlates sing-box's own lines with each other.
fn strip_request_id(message: &str) -> &str {
    let Some(rest) = message.strip_prefix('[') else {
        return message;
    };
    match rest.split_once(']') {
        Some((id, tail)) if id.starts_with(|c: char| c.is_ascii_digit()) => tail.trim_start(),
        _ => message,
    }
}

/// sing-box's per-connection failures duplicate vproxy's own log: a SOCKS
/// request vproxy rejected (it logged why), or a direct dial that is our own
/// connection to the server. Keep them for `-v` only.
fn demote(name: &str, level: Level, message: &str) -> Level {
    if name == "sing-box" && level <= Level::WARN && message.starts_with("connection:") {
        return Level::DEBUG;
    }
    level
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sing_box_lines() {
        let (l, m) = classify("+0300 2026-10-21 16:43:56 ERROR [988949701 10ms] connection: open connection to 1.2.3.4:443 using outbound/direct[direct]: dial tcp 1.2.3.4:443: connect: connection refused");
        assert_eq!(l, Level::ERROR);
        assert!(m.starts_with("[988949701 10ms] connection: open"));
        let (l, m) = classify("WARN [1 2ms] inbound/tun: something");
        assert_eq!(l, Level::WARN);
        assert_eq!(m, "[1 2ms] inbound/tun: something");
        let (l, _) = classify("INFO[0000] sing-box started (0.02s)");
        assert_eq!(l, Level::INFO);
    }

    #[test]
    fn xray_lines() {
        let (l, m) = classify(
            "2026/10/21 16:43:56 [Warning] [12] proxy/vless/outbound: failed to read response",
        );
        assert_eq!(l, Level::WARN);
        assert_eq!(m, "[12] proxy/vless/outbound: failed to read response");
        let (l, m) = classify("Xray 25.1.1 (Xray, Penetrates Everything.) Custom (go1.23)");
        assert_eq!(l, Level::INFO);
        assert!(m.starts_with("Xray 25.1.1"));
    }

    #[test]
    fn level_word_inside_the_message_is_not_a_tag() {
        let (l, m) = classify("INFO connection to ERROR.example.com failed");
        assert_eq!(l, Level::INFO);
        assert_eq!(m, "connection to ERROR.example.com failed");
    }

    #[test]
    fn request_id_is_stripped_but_other_brackets_stay() {
        assert_eq!(
            strip_request_id("[988949701 10ms] connection: open connection"),
            "connection: open connection"
        );
        assert_eq!(strip_request_id("[12] proxy/vless: x"), "proxy/vless: x");
        assert_eq!(
            strip_request_id("[tun-in] interface up"),
            "[tun-in] interface up"
        );
        assert_eq!(strip_request_id("no bracket"), "no bracket");
    }

    #[test]
    fn sing_box_connection_errors_are_debug_only() {
        let m = "connection: open connection to 1.2.3.4:443 using outbound/socks[proxy]: socks5: request rejected, code=1";
        assert_eq!(demote("sing-box", Level::ERROR, m), Level::DEBUG);
        assert_eq!(demote("sing-box", Level::WARN, m), Level::DEBUG);
        // Anything else from sing-box, and everything from xray, keeps its level.
        assert_eq!(
            demote(
                "sing-box",
                Level::ERROR,
                "start service: initialize inbound/tun[tun-in]: operation not permitted"
            ),
            Level::ERROR
        );
        assert_eq!(demote("xray", Level::ERROR, m), Level::ERROR);
    }

    #[tokio::test]
    async fn real_child_output_reaches_the_exit_reason() {
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("echo 'INFO[0000] started'; echo 'ERROR [7 1ms] connection: x' >&2; echo 'FATAL start service: boom' >&2; exit 1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let log = forward_logs(&mut child, "sing-box");
        let status = child.wait().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!status.success());
        let reason = log.exit_reason(status);
        assert!(reason.ends_with("start service: boom"), "{reason}");
        assert!(log.last_lines().contains(&"connection: x".to_string()));
    }

    #[test]
    fn exit_reason_quotes_the_last_line() {
        let log = SidecarLog::default();
        for i in 0..8 {
            log.remember(&format!("line {i}"));
        }
        assert_eq!(log.last_lines().len(), KEEP_LAST);
        assert_eq!(log.last_lines().last().unwrap(), "line 7");
    }
}
