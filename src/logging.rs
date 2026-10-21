//! Size-capped log file with rotation: `vproxy.log`, `vproxy.log.1`, …
//! Used by the TUI, which otherwise keeps logs only in memory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Default cap for one file (5 MiB) and how many rotated copies to keep.
pub const DEFAULT_MAX_BYTES: u64 = 5 * 1024 * 1024;
pub const DEFAULT_KEEP: usize = 3;

/// Appends to `path`; once it would exceed `max_bytes` the file is renamed
/// to `path.1` (shifting older copies up to `path.<keep>`) and a new one starts.
pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: File,
    written: u64,
}

impl RotatingFile {
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64, keep: usize) -> io::Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            max_bytes: max_bytes.max(1),
            keep,
            file,
            written,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Separate runs in the file: the TUI's timestamps are relative to start.
    pub fn write_session_header(&mut self) -> io::Result<()> {
        writeln!(
            self,
            "--- vproxy {} started {} UTC ---",
            env!("CARGO_PKG_VERSION"),
            utc_now()
        )
    }

    fn rotated(&self, n: usize) -> PathBuf {
        let mut os = self.path.clone().into_os_string();
        os.push(format!(".{n}"));
        PathBuf::from(os)
    }

    /// Shift `.1` → `.2` … and the current file to `.1`; without `keep`
    /// copies the current file is simply truncated.
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        if self.keep == 0 {
            self.file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&self.path)?;
        } else {
            let _ = fs::remove_file(self.rotated(self.keep));
            for n in (1..self.keep).rev() {
                let _ = fs::rename(self.rotated(n), self.rotated(n + 1));
            }
            fs::rename(&self.path, self.rotated(1))?;
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
        }
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // tracing hands over one whole event per call, so rotating between
        // calls never splits a line.
        if self.written > 0 && self.written + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// `2026-10-21 13:33:05` without pulling in a date crate.
fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

fn format_utc(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil-from-days (Howard Hinnant), valid for the Unix era.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc(1_709_164_800), "2024-02-29 00:00:00");
        assert_eq!(format_utc(1_761_046_385), "2025-10-21 11:33:05");
    }

    #[test]
    fn rotates_when_the_cap_is_reached() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.log");
        let mut f = RotatingFile::open(&path, 10, 2).unwrap();
        f.write_all(b"aaaaaa\n").unwrap(); // 7
        f.write_all(b"bbbbbb\n").unwrap(); // would be 14 > 10 → rotate
        f.write_all(b"cccccc\n").unwrap(); // rotate again
        assert_eq!(fs::read_to_string(&path).unwrap(), "cccccc\n");
        assert_eq!(fs::read_to_string(f.rotated(1)).unwrap(), "bbbbbb\n");
        assert_eq!(fs::read_to_string(f.rotated(2)).unwrap(), "aaaaaa\n");
        f.write_all(b"dddddd\n").unwrap();
        assert_eq!(fs::read_to_string(f.rotated(2)).unwrap(), "bbbbbb\n");
        assert!(!f.rotated(3).exists());
    }

    #[test]
    fn oversized_single_write_still_lands() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.log");
        let mut f = RotatingFile::open(&path, 4, 1).unwrap();
        f.write_all(b"0123456789\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "0123456789\n");
        f.write_all(b"x\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "x\n");
    }

    #[test]
    fn keep_zero_truncates_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.log");
        let mut f = RotatingFile::open(&path, 8, 0).unwrap();
        f.write_all(b"aaaaaa\n").unwrap();
        f.write_all(b"bb\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "bb\n");
        assert!(!f.rotated(1).exists());
    }
}
