//! Route a sidecar's stdout/stderr through `tracing` instead of letting it
//! write to the terminal: in `--tui` mode a child writing straight to the
//! tty scribbles over the frame, and in every mode one log format and one
//! log file are easier to read than two interleaved ones.

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Child;
use tracing::Level;

/// Take the child's piped stdout and stderr and re-emit every line as a
/// tracing event prefixed with `[name]`, at the level the line itself
/// carries. Pipes the child never got (not `Stdio::piped()`) are skipped.
pub fn forward_logs(child: &mut Child, name: &'static str) {
    if let Some(out) = child.stdout.take() {
        tokio::spawn(pump(out, name));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(pump(err, name));
    }
}

async fn pump<R: AsyncRead + Unpin>(reader: R, name: &'static str) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (level, message) = classify(line);
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
}
