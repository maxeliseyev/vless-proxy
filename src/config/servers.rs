//! The list of servers vproxy can switch between at runtime: every
//! `vless://` link of the links file (or the single server of a TOML/JSON
//! config), plus persistence of the chosen one as the file's first link.

use crate::config::import::amnezia;
use crate::config::subscription::{self, Meta, Subscription};
use crate::config::url::VlessUrl;
use crate::config::{Config, ServerConfig};
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

    /// From a `vless://` or Amnezia `vpn://` link.
    pub fn from_link(link: &str, inbound_port: u16) -> Result<Self> {
        let config = config_from_link(link, inbound_port)?;
        let mut entry = Self::from_server(config.server);
        entry.link = Some(link.trim().to_string());
        Ok(entry)
    }

    /// Short transport description for lists: `reality+vision`, `tls/ws`, ...
    pub fn kind(&self) -> String {
        let mut s = self.server.security.clone();
        match self.server.transport_kind().ok() {
            Some(crate::config::Transport::Ws) => s.push_str("/ws"),
            Some(crate::config::Transport::Xhttp) => s.push_str("/xhttp"),
            _ => {}
        }
        if self.server.flow.is_some() {
            s.push_str("+vision");
        }
        s
    }
}

/// A `vless://` link or an Amnezia `vpn://` link as a full config listening
/// on `inbound_port`.
pub fn config_from_link(link: &str, inbound_port: u16) -> Result<Config> {
    let link = link.trim();
    if amnezia::is_link(link) {
        return amnezia::from_link(link, inbound_port);
    }
    if !link.starts_with("vless://") {
        bail!("expected a vless:// or vpn:// link");
    }
    let url = VlessUrl::parse(link)?;
    let config = Config::from_vless_url(&url, inbound_port);
    config.server.validate_transport_settings()?;
    Ok(config)
}

#[derive(Debug, Clone, Default)]
pub struct ServerList {
    pub entries: Vec<ServerEntry>,
    /// Links file the entries came from, for persisting the active choice.
    pub file: Option<PathBuf>,
    /// Set when the links file is managed by a subscription.
    pub subscription: Option<Meta>,
}

impl ServerList {
    pub fn single(server: ServerConfig) -> Self {
        Self {
            entries: vec![ServerEntry::from_server(server)],
            file: None,
            subscription: None,
        }
    }

    /// Parse every link of a links file. Invalid lines are reported but do
    /// not prevent the valid ones from loading; at least one must be valid.
    pub fn from_file(path: &Path, inbound_port: u16) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read {}", path.display()))?;
        let subscription = Meta::from_lines(content.lines());
        let active = active_link(&content);
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
        // `# active:` names the server to start with; it goes first in memory.
        if let Some(active) = active {
            if let Some(pos) = entries
                .iter()
                .position(|e| e.link.as_deref() == Some(&active))
            {
                let entry = entries.remove(pos);
                entries.insert(0, entry);
            }
        }
        Ok(Self {
            entries,
            file: Some(path.to_path_buf()),
            subscription,
        })
    }

    /// Replace the subscription section of the links file with `sub`,
    /// keeping manual links and the active choice, and reload the entries.
    pub fn apply_subscription(&mut self, sub: &Subscription, inbound_port: u16) -> Result<()> {
        let path = self
            .file
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no links file to update"))?;
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let manual = if self.subscription.is_some() {
            subscription::split_sections(&content).1
        } else {
            // A plain links file becoming subscription-managed: its links are manual.
            subscription::split_sections(&content)
                .0
                .into_iter()
                .filter(|l| !sub.links.contains(l))
                .collect()
        };
        let active =
            active_link(&content).or_else(|| self.entries.first().and_then(|e| e.link.clone()));
        std::fs::write(
            &path,
            subscription::render_file(sub, active.as_deref(), &manual),
        )
        .with_context(|| format!("Cannot write {}", path.display()))?;
        *self = Self::from_file(&path, inbound_port)?;
        Ok(())
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
        if self.subscription.is_some() {
            // Managed file: record the choice in the header, keep the order.
            let content = std::fs::read_to_string(path)?;
            let mut out = String::new();
            let mut written = false;
            for line in content.lines() {
                if line.trim().starts_with(subscription::HEADER_ACTIVE) {
                    if !written {
                        out.push_str(&format!("{} {chosen}\n", subscription::HEADER_ACTIVE));
                        written = true;
                    }
                    continue;
                }
                if !written && !line.trim().starts_with('#') {
                    out.push_str(&format!("{} {chosen}\n", subscription::HEADER_ACTIVE));
                    written = true;
                }
                out.push_str(line);
                out.push('\n');
            }
            if !written {
                out.push_str(&format!("{} {chosen}\n", subscription::HEADER_ACTIVE));
            }
            return std::fs::write(path, out)
                .with_context(|| format!("Cannot write {}", path.display()));
        }
        rewrite_links_file(path, Some(chosen), None)
    }

    /// Add a server from a `vless://` link and append it to the links file.
    /// A link already in the list is rejected.
    pub fn add_link(&mut self, link: &str, inbound_port: u16) -> Result<&ServerEntry> {
        let entry = ServerEntry::from_link(link, inbound_port)?;
        let link = entry.link.as_deref().unwrap_or_default();
        if self.entries.iter().any(|e| e.link.as_deref() == Some(link)) {
            bail!("{} is already in the list", entry.name);
        }
        if let Some(path) = &self.file {
            let mut content = std::fs::read_to_string(path).unwrap_or_default();
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            // In a subscription-managed file hand-added links live after the
            // manual marker, so a refresh keeps them.
            if self.subscription.is_some()
                && !content
                    .lines()
                    .any(|l| l.trim() == subscription::MANUAL_MARKER)
            {
                content.push_str(subscription::MANUAL_MARKER);
                content.push('\n');
            }
            content.push_str(link);
            content.push('\n');
            std::fs::write(path, content)
                .with_context(|| format!("Cannot write {}", path.display()))?;
        }
        self.entries.push(entry);
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Remove entry `index` from the list and from the links file. The last
    /// server cannot be removed.
    pub fn remove(&mut self, index: usize) -> Result<ServerEntry> {
        if index >= self.entries.len() {
            bail!("server index {index} out of range");
        }
        if self.entries.len() == 1 {
            bail!("cannot remove the last server");
        }
        if let (Some(path), Some(link)) = (&self.file, &self.entries[index].link) {
            rewrite_links_file(path, None, Some(link))?;
        }
        Ok(self.entries.remove(index))
    }
}

/// The `# active:` link of a links file, if any.
pub fn active_link(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|l| l.trim().strip_prefix(subscription::HEADER_ACTIVE))
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

/// Rewrite a links file: comments stay on top, `first` (if present in the
/// file) moves to the top of the links, `drop` is removed, every other line
/// is kept verbatim so a hand-edited file is never damaged.
fn rewrite_links_file(path: &Path, first: Option<&str>, drop: Option<&str>) -> Result<()> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    let mut comments = Vec::new();
    let mut links = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || Some(t) == drop {
            continue;
        }
        if t.starts_with('#') {
            comments.push(line.to_string());
        } else if Some(t) != first {
            links.push(t.to_string());
        }
    }
    let mut out = String::new();
    for c in comments {
        out.push_str(&c);
        out.push('\n');
    }
    if let Some(first) = first {
        out.push_str(first);
        out.push('\n');
    }
    for l in links {
        out.push_str(&l);
        out.push('\n');
    }
    std::fs::write(path, out).with_context(|| format!("Cannot write {}", path.display()))
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
        assert_eq!(
            content,
            format!("# my servers\n{C}\n{A}\nnot a link\n{B}\n")
        );

        let reloaded = ServerList::from_file(&path, 1080).unwrap();
        assert_eq!(reloaded.entries[0].name, "1.2.3.4:443");
    }

    #[test]
    fn adds_and_removes_links_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.txt");
        std::fs::write(&path, format!("# my servers\n{A}")).unwrap();

        let mut list = ServerList::from_file(&path, 1080).unwrap();
        assert_eq!(list.add_link(B, 1080).unwrap().name, "beta");
        assert_eq!(
            list.add_link(&format!("  {C}\n"), 1080).unwrap().kind(),
            "reality+vision"
        );
        assert!(list
            .add_link(B, 1080)
            .unwrap_err()
            .to_string()
            .contains("already"));
        assert!(list.add_link("vless://broken", 1080).is_err());
        assert_eq!(list.len(), 3);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("# my servers\n{A}\n{B}\n{C}\n")
        );

        let removed = list.remove(1).unwrap();
        assert_eq!(removed.name, "beta");
        assert_eq!(list.len(), 2);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("# my servers\n{A}\n{C}\n")
        );
        list.remove(0).unwrap();
        assert!(list.remove(0).unwrap_err().to_string().contains("last"));
        assert_eq!(
            ServerList::from_file(&path, 1080).unwrap().entries[0].name,
            "1.2.3.4:443"
        );
    }

    #[test]
    fn subscription_managed_file() {
        use crate::config::subscription::{Meta, Subscription};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.txt");
        std::fs::write(&path, format!("{A}\n{B}\n")).unwrap();
        let mut list = ServerList::from_file(&path, 1080).unwrap();
        assert!(list.subscription.is_none());

        let sub = Subscription {
            meta: Meta {
                url: "https://p.example/sub".into(),
                title: Some("P".into()),
                updated: Some(1),
                interval_hours: 6,
                userinfo: None,
            },
            links: vec![B.to_string(), C.to_string()],
            skipped: 0,
        };
        // A was in the plain file and not in the subscription: it becomes manual.
        list.apply_subscription(&sub, 1080).unwrap();
        assert_eq!(list.subscription.as_ref().unwrap().interval_hours, 6);
        let names: Vec<&str> = list.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", "1.2.3.4:443"]); // active A first
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&format!("# active: {A}\n{B}\n{C}\n# manual\n{A}\n")));

        // choosing a server records it in the header, order untouched
        list.persist_first(1).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(&format!("# active: {B}\n{B}\n{C}\n# manual\n{A}\n")),
            "{text}"
        );
        assert_eq!(
            ServerList::from_file(&path, 1080).unwrap().entries[0].name,
            "beta"
        );

        // a hand-added link lands in the manual section and survives a refresh
        let d = "vless://00000000-0000-0000-0000-000000000004@d.example:443?security=tls#delta";
        list.add_link(d, 1080).unwrap();
        list.apply_subscription(&sub, 1080).unwrap();
        let (subs, manual) =
            crate::config::subscription::split_sections(&std::fs::read_to_string(&path).unwrap());
        assert_eq!(subs, vec![B.to_string(), C.to_string()]);
        assert_eq!(manual, vec![A.to_string(), d.to_string()]);
        assert_eq!(list.len(), 4);
    }

    #[test]
    fn in_memory_list_without_a_file() {
        let mut list = ServerList::single(ServerEntry::from_link(A, 1080).unwrap().server);
        list.add_link(B, 1080).unwrap();
        assert_eq!(list.len(), 2);
        list.remove(0).unwrap();
        assert_eq!(list.entries[0].name, "beta");
    }

    #[test]
    fn rejects_file_without_valid_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.txt");
        std::fs::write(&path, "# nothing here\nvless://broken\n").unwrap();
        assert!(ServerList::from_file(&path, 1080).is_err());
    }
}
