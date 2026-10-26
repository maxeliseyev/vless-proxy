//! Finding and installing the `sing-box` binary that TUN mode needs.
//!
//! Lookup order: an explicit `tun.sing_box_path` / `--sing-box`, then
//! `~/.config/vproxy/bin/sing-box` (where `vproxy install-sing-box` puts it),
//! `PATH`, the usual Homebrew and system prefixes, and the copy inside a Happ
//! installation. Under `sudo` the invoking user's home is searched too.
//!
//! Installation offers the platform's package manager when there is one
//! (Homebrew on macOS, the official sing-box repository script on deb/rpm/Arch
//! Linux) and otherwise downloads the official GitHub release into
//! `~/.config/vproxy/bin`.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const RELEASES_API: &str = "https://api.github.com/repos/SagerNet/sing-box/releases/latest";
const INSTALL_SCRIPT: &str = "https://sing-box.app/install.sh";
const HOMEBREW_SCRIPT: &str = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh";

/// Home directory of the real user, also when running under `sudo`.
pub fn real_home() -> Option<PathBuf> {
    if let Some(user) = std::env::var_os("SUDO_USER") {
        let user = user.to_string_lossy();
        if user != "root" {
            let candidate = if cfg!(target_os = "macos") {
                PathBuf::from("/Users").join(&*user)
            } else {
                PathBuf::from("/home").join(&*user)
            };
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }
    std::env::var_os("HOME").map(PathBuf::from)
}

/// `~/.config/vproxy/bin` of the real user.
pub fn bin_dir() -> Option<PathBuf> {
    real_home().map(|h| h.join(".config").join("vproxy").join("bin"))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.is_file()
            && std::fs::metadata(path)
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Where sing-box is, if anywhere. `configured` is `tun.sing_box_path`; a
/// value other than the bare default `sing-box` is taken literally.
pub fn locate(configured: &str) -> Option<PathBuf> {
    let configured = configured.trim();
    if !configured.is_empty() && configured != "sing-box" {
        let p = PathBuf::from(configured);
        if p.components().count() > 1 {
            return is_executable(&p).then_some(p);
        }
    }
    let name = if configured.is_empty() {
        "sing-box"
    } else {
        configured
    };
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = bin_dir() {
        candidates.push(dir.join(name));
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join(".config")
                .join("vproxy")
                .join("bin")
                .join(name),
        );
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            candidates.push(dir.join(name));
        }
    }
    for dir in [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/snap/bin",
        "/Applications/Happ.app/Contents/MacOS/core",
    ] {
        candidates.push(PathBuf::from(dir).join(name));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(name));
        }
    }
    candidates.into_iter().find(|p| is_executable(p))
}

/// Text for the "not found" error.
pub fn not_found_hint() -> String {
    let dir = bin_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "~/.config/vproxy/bin".to_string());
    format!(
        "sing-box was not found (TUN mode runs it as a sidecar). Run `vproxy install-sing-box` \
         to install it, or put the binary into {dir} or PATH, or set tun.sing_box_path / --sing-box"
    )
}

fn have(cmd: &str) -> Option<PathBuf> {
    let extra = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"];
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain(extra.iter().map(PathBuf::from))
        .map(|d| d.join(cmd))
        .find(|p| is_executable(p))
}

/// Ask a yes/no question on the terminal; `assume_yes` or no TTY takes the default.
pub fn ask(question: &str, default_yes: bool, assume_yes: bool) -> Result<bool> {
    if assume_yes || !std::io::stdin().is_terminal() {
        return Ok(default_yes);
    }
    let mut err = std::io::stderr();
    write!(
        err,
        "{question} [{}] ",
        if default_yes { "Y/n" } else { "y/N" }
    )?;
    err.flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let a = line.trim().to_ascii_lowercase();
    Ok(match a.as_str() {
        "" => default_yes,
        "y" | "yes" | "д" | "да" => true,
        _ => false,
    })
}

fn run_interactive(program: &str, args: &[&str]) -> Result<()> {
    eprintln!("$ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("cannot run {program}"))?;
    if !status.success() {
        bail!("{program} exited with {status}");
    }
    Ok(())
}

/// Install sing-box, preferring the platform package manager. Returns the
/// path it is now found at.
pub async fn install(assume_yes: bool) -> Result<PathBuf> {
    if let Some(found) = locate("sing-box") {
        let version = version_of(&found).unwrap_or_default();
        eprintln!(
            "sing-box is already installed: {} {version}",
            found.display()
        );
        if !ask("Reinstall / update anyway?", false, assume_yes)? {
            return Ok(found);
        }
    }

    if cfg!(target_os = "macos") {
        if let Some(brew) = have("brew") {
            if ask(
                "Install sing-box with Homebrew (brew install sing-box)?",
                true,
                assume_yes,
            )? {
                run_interactive(&brew.to_string_lossy(), &["install", "sing-box"])?;
                return locate("sing-box").context("brew finished but sing-box is still not found");
            }
        } else {
            eprintln!("Homebrew is not installed.");
            if ask(
                "Install Homebrew first (official script, asks for your password), then sing-box with it?",
                false,
                assume_yes,
            )? {
                run_interactive(
                    "/bin/bash",
                    &["-c", &format!("$(curl -fsSL {HOMEBREW_SCRIPT})")],
                )?;
                let brew = have("brew").context("Homebrew installer finished but brew is not in PATH; open a new terminal and rerun")?;
                run_interactive(&brew.to_string_lossy(), &["install", "sing-box"])?;
                return locate("sing-box").context("brew finished but sing-box is still not found");
            }
        }
    } else if cfg!(target_os = "linux") {
        let manager = ["apt-get", "dnf", "pacman", "opkg"]
            .into_iter()
            .find(|m| have(m).is_some());
        if let Some(manager) = manager {
            eprintln!(
                "Detected {manager}. sing-box's official install script adds its repository \
                 and installs the package (needs sudo). Flatpak does not carry sing-box."
            );
            if ask(
                &format!("Run `curl -fsSL {INSTALL_SCRIPT} | sh` now?"),
                true,
                assume_yes,
            )? {
                let sudo = if is_root() { "" } else { "sudo " };
                run_interactive(
                    "sh",
                    &["-c", &format!("curl -fsSL {INSTALL_SCRIPT} | {sudo}sh")],
                )?;
                return locate("sing-box")
                    .context("the install script finished but sing-box is still not found");
            }
        }
    }

    download_release(assume_yes).await
}

/// Running as root, a helper binary that a non-root user can replace is a
/// way for that user to become root. vproxy still runs it (Homebrew binaries
/// on macOS are user-owned by design) but says so once.
pub fn warn_if_unsafe_for_root(binary: &Path, what: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !is_root() {
            return;
        }
        let Ok(meta) = std::fs::metadata(binary) else {
            return;
        };
        let world_or_group_writable = meta.mode() & 0o022 != 0;
        if meta.uid() != 0 || world_or_group_writable {
            tracing::warn!(
                "{what} {} is owned by uid {} (mode {:o}) and runs as root: anyone who can change \
                 that file can run code as root. Prefer a root-owned copy, e.g. /usr/local/bin.",
                binary.display(),
                meta.uid(),
                meta.mode() & 0o7777
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (binary, what);
    }
}

fn is_root() -> bool {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() == 0 }
}

fn version_of(path: &Path) -> Option<String> {
    let out = Command::new(path).arg("version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .next()
        .map(|l| l.trim().trim_start_matches("sing-box version ").to_string())
}

/// Download the latest official release for this OS/CPU into `~/.config/vproxy/bin`.
pub async fn download_release(assume_yes: bool) -> Result<PathBuf> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => bail!("no sing-box release for {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("no sing-box release for {other}"),
    };
    let dir = bin_dir().context("cannot determine the home directory")?;
    if !ask(
        &format!(
            "Download the latest sing-box release ({os}/{arch}) from GitHub into {}?",
            dir.display()
        ),
        true,
        assume_yes,
    )? {
        bail!("sing-box not installed");
    }

    let client = reqwest::Client::builder()
        .user_agent(format!("vproxy/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let release_text = client
        .get(RELEASES_API)
        .send()
        .await
        .context("GitHub releases API")?
        .error_for_status()?
        .text()
        .await?;
    let release: serde_json::Value =
        serde_json::from_str(&release_text).context("GitHub releases API returned no JSON")?;
    let tag = release["tag_name"]
        .as_str()
        .context("release has no tag")?
        .to_string();
    let version = tag.trim_start_matches('v');
    let want = format!("sing-box-{version}-{os}-{arch}.tar.gz");
    let url = release["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"] == want.as_str())
        .and_then(|a| a["browser_download_url"].as_str())
        .with_context(|| format!("release {tag} has no asset {want}"))?
        .to_string();
    eprintln!("Downloading {url}");
    let bytes = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);
    let mut binary: Option<Vec<u8>> = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.file_name().is_some_and(|n| n == "sing-box") {
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut data)?;
            binary = Some(data);
            break;
        }
    }
    let binary = binary.context("archive has no sing-box binary")?;

    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let target = dir.join("sing-box");
    let tmp = dir.join(".sing-box.download");
    std::fs::write(&tmp, &binary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, &target)?;
    // Under sudo, give the files back to the real user.
    if let (Some(user), true) = (std::env::var_os("SUDO_USER"), is_root()) {
        let _ = Command::new("chown")
            .arg("-R")
            .arg(&user)
            .arg(dir.parent().unwrap_or(&dir))
            .status();
    }
    let version = version_of(&target).unwrap_or_else(|| tag.clone());
    eprintln!("Installed sing-box {version} to {}", target.display());
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_paths_are_taken_literally() {
        assert!(locate("/definitely/not/here/sing-box").is_none());
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("sing-box");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(locate(bin.to_str().unwrap()), Some(bin));
    }

    #[test]
    fn hint_mentions_the_installer() {
        assert!(not_found_hint().contains("vproxy install-sing-box"));
    }
}
