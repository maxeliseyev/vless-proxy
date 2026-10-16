//! The list of servers vproxy can switch between at runtime: every
//! `vless://` link of the links file (or the single server of a TOML/JSON
//! config), plus persistence of the chosen one as the file's first link.

use crate::config::{Config, ServerConfig};
use crate::url::VlessUrl;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ServerEntry {
    pub name: String,
    /// Original `vless://` link when the entry came from a links file.
    pub link: Option<String>,
    pub server: ServerConfig,
}

impl ServerEntry {
    pub fn from_server(server: ServerConfig) -> Self {
        let name = server
            .remark
            .clone()
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| server.endpoint());
        Self {
            name,
            link: None,
            server,
        }
    }

    pub fn from_link(link: &str, inbound_port: u16) -> Result<Self> {
        let url = VlessUrl::parse(link)?;
        let config = Config::from_vless_url(&url, inbound_port);
        config.server.validate_transport_settings()?;
        let mut entry = Self::from_server(config.server);
        entry.link = Some(link.trim().to_string());
        Ok(entry)
    }

    /// Short transport description for lists: `reality+vision`, `tls/ws`, ...
    pub fn kind(&self) -> String {
        let mut s = self.server.security.clone();
        if self.server.transport_kind().ok() == Some(crate::config::Transport::Ws) {
            s.push_str("/ws");
        }
        if self.server.flow.is_some() {
            s.push_str("+vision");
        }
        s
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerList {
    pub entries: Vec<ServerEntry>,
    /// Links file the entries came from, for persisting the active choice.
    pub file: Option<PathBuf>,
}

impl ServerList {
    pub fn single(server: ServerConfig) -> Self {
        Self {
            entries: vec![ServerEntry::from_server(server)],
            file: None,
        }
    }

    /// Parse every link of a links file. Invalid lines are reported but do
    /// not prevent the valid ones from loading; at least one must be valid.
    pub fn from_file(path: &Path, inbound_port: u16) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read {}", path.display()))?;
        let mut entries = Vec::new();
        let mut errors = Vec::new();
        for (n, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match ServerEntry::from_link(line, inbound_port) {
                Ok(entry) => entries.push(entry),
                Err(e) => errors.push(format!("line {}: {e}", n + 1)),
            }
        }
        if entries.is_empty() {
            bail!(
                "No valid vless:// link in {}{}",
                path.display(),
                if errors.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", errors.join("; "))
                }
            );
        }
        for e in errors {
            tracing::warn!("{}: skipped {e}", path.display());
        }
        Ok(Self {
            entries,
            file: Some(path.to_path_buf()),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Rewrite the links file with entry `index` first (comment lines stay on
    /// top), so the next start uses it. No-op without a file.
    pub fn persist_first(&self, index: usize) -> Result<()> {
        let Some(path) = &self.file else {
            return Ok(());
        };
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("server index {index} out of range"))?;
        let Some(chosen) = &entry.link else {
            return Ok(());
        };
        let content = std::fs::read_to_string(path)?;
        let mut comments = Vec::new();
        let mut links = Vec::new();
        for line in content.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if t.starts_with('#') {
                comments.push(line.to_string());
            } else if t != chosen {
                links.push(t.to_string());
            }
        }
        let mut out = String::new();
        for c in comments {
            out.push_str(&c);
            out.push('\n');
        }
        out.push_str(chosen);
        out.push('\n');
        for l in links {
            out.push_str(&l);
            out.push('\n');
        }
        std::fs::write(path, out).with_context(|| format!("Cannot write {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "vless://00000000-0000-0000-0000-000000000001@a.example:443?security=tls#alpha";
    const B: &str = "vless://00000000-0000-0000-0000-000000000002@b.example:443?type=ws&security=tls&path=%2Fx#beta";
    const C: &str = "vless://00000000-0000-0000-0000-000000000003@1.2.3.4:443?security=reality&pbk=Mkpry4Un0Ka6RkyokWUIKYWVCuugce3hdEU7dLn6yD4&sid=63141c&sni=intel.com&flow=xtls-rprx-vision";

    #[test]
    fn loads_every_link_and_persists_the_chosen_one_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.txt");
        std::fs::write(
            &path,
            format!("# my servers\n{A}\nnot a link\n\n{B}\n{C}\n"),
        )
        .unwrap();

        let list = ServerList::from_file(&path, 1080).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list.entries[0].name, "alpha");
        assert_eq!(list.entries[1].kind(), "tls/ws");
        assert_eq!(list.entries[2].name, "1.2.3.4:443");
        assert_eq!(list.entries[2].kind(), "reality+vision");

        list.persist_first(2).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        // unknown lines are kept (never destroy the user's file), comments stay on top
        assert_eq!(content, format!("# my servers\n{C}\n{A}\nnot a link\n{B}\n"));

        let reloaded = ServerList::from_file(&path, 1080).unwrap();
        assert_eq!(reloaded.entries[0].name, "1.2.3.4:443");
    }

    #[test]
    fn rejects_file_without_valid_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.txt");
        std::fs::write(&path, "# nothing here\nvless://broken\n").unwrap();
        assert!(ServerList::from_file(&path, 1080).is_err());
    }
}
