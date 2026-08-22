// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Starkka15

//! On-disk state: the stored Ubisoft session/token, in `auth.toml` under the
//! platform data dir (mirrors Maxima's `auth.toml`). Never contains the user's
//! password — only the returned session ticket + refresh (rememberMe) ticket.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The credential/session material UbiServices hands back on login. The `ticket`
/// is the `ubi_v1` session ticket used as `Authorization: ubi_v1 t=<ticket>` on
/// subsequent REST + Demux calls; `remember_me_ticket` refreshes it without a
/// password re-prompt.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Auth {
    pub ticket: String,
    pub session_id: String,
    #[serde(default)]
    pub session_key: String,
    pub profile_id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub name_on_platform: String,
    /// RFC3339 expiry of `ticket`, as returned by UbiServices.
    #[serde(default)]
    pub expiration: String,
    #[serde(default)]
    pub remember_me_ticket: String,
}

impl Auth {
    /// True only if we have a parseable `expiration` that is in the past. An
    /// EMPTY or unparseable expiration means "unknown" — the WebAuth SDK capture
    /// doesn't record one — and must NOT be treated as expired: doing so made
    /// every online call proactively burn a rememberMe refresh, wearing the
    /// rememberMe ticket out until it rate-limited/died ("tickets don't last").
    /// Unknown → assume usable and let the reactive 401 path (connect_demux)
    /// refresh only when the ticket is actually rejected.
    pub fn is_expired(&self) -> bool {
        if self.expiration.trim().is_empty() {
            return false;
        }
        match chrono::DateTime::parse_from_rfc3339(&self.expiration) {
            Ok(exp) => exp <= chrono::Utc::now(),
            Err(_) => false,
        }
    }
}

/// `~/.local/share/optima/` (or the platform equivalent), created on demand.
pub fn data_dir() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .context("no platform data dir")?
        .join("optima");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}


/// Write a secret to `path` so it is never briefly world-readable.
///
/// `write` + `set_permissions` leaves a window where the file exists at the
/// default umask, and a half-written file is visible if the process dies. This
/// creates a private temp file in the same directory, fills it, then renames
/// over the target, which is atomic within a filesystem.
fn write_private(path: &Path, body: &str) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("secret"),
        std::process::id()
    ));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600); // private from the moment it exists
    }
    let _ = std::fs::remove_file(&tmp); // stale temp from a previous crash
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(body.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all().ok();
    drop(f);

    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read a secret, refusing anything that is not a plain file we own.
///
/// A symlink here would make us read (and later overwrite through) a path
/// someone else chose; a file owned by another user is equally untrustworthy.
fn read_private(path: &Path) -> Result<String> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("{} is a symlink; refusing to read a secret through it", path.display());
    }
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::getuid() } {
            bail!("{} is owned by uid {}, not you", path.display(), meta.uid());
        }
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

fn auth_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("auth.toml"))
}

pub fn save_auth(auth: &Auth) -> Result<()> {
    let path = auth_path()?;
    let body = toml::to_string_pretty(auth).context("serializing auth")?;
    write_private(&path, &body)
}

pub fn load_auth() -> Result<Option<Auth>> {
    let path = auth_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let body = read_private(&path)?;
    let auth: Auth = toml::from_str(&body).context("parsing auth.toml")?;
    Ok(Some(auth))
}

/// Everything a launch needs, cached per product so an owned game can be started
/// **offline** (no Ubisoft round-trip). The SP Uplay R1 DRM never validates the
/// ticket online — it only reads the values we write into `Uplay.ini` — so a
/// cached ticket is sufficient forever for offline single-player. We still
/// refresh this on any launch that DOES reach the network.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LaunchCache {
    pub user_id: String,
    pub username: String,
    #[serde(default)]
    pub email: String,
    pub ticket: String,
    pub app_id: u32,
    pub language: String,
    /// Backslash-form exe path relative to the install dir (e.g. `AC4BFSP.exe`).
    pub exe_rel: String,
    /// Human-readable game name (for log lines).
    pub name: String,
    /// The game's own install-path registry location, verbatim from the product
    /// config's `working_directory.register` (e.g.
    /// `HKEY_LOCAL_MACHINE\SOFTWARE\Ubisoft\Beyond Good & Evil\Install path`). Old
    /// settings apps / games read this to confirm the game is "properly installed"
    /// and to find their data. Set at launch so they don't bail. Empty if unknown.
    #[serde(default)]
    pub install_reg: String,
}

/// The account identity the Uplay R1 emu presents to games. Browser/ticket login
/// never yields these (email/password aren't in the ticket), so the user supplies
/// them once — via `optima-cli profile set` on desktop, or the Optima extension's
/// account form on the Ally. Written into each game's `Uplay.toml` at launch.
/// None of it is validated online for offline SP; it's the local player identity.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Profile {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

fn profile_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("profile.toml"))
}

pub fn save_profile(p: &Profile) -> Result<()> {
    let path = profile_path()?;
    let body = toml::to_string_pretty(p).context("serializing profile")?;
    write_private(&path, &body)
}

pub fn load_profile() -> Result<Profile> {
    let path = profile_path()?;
    if !path.exists() {
        return Ok(Profile::default());
    }
    let body = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(toml::from_str(&body).context("parsing profile.toml")?)
}

fn launch_cache_path(product_id: u32) -> Result<PathBuf> {
    let dir = data_dir()?.join("launch_cache");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir.join(format!("{product_id}.toml")))
}

pub fn save_launch_cache(product_id: u32, c: &LaunchCache) -> Result<()> {
    let path = launch_cache_path(product_id)?;
    let body = toml::to_string_pretty(c).context("serializing launch cache")?;
    write_private(&path, &body)
}

pub fn load_launch_cache(product_id: u32) -> Result<Option<LaunchCache>> {
    let path = launch_cache_path(product_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let body = read_private(&path)?;
    let c: LaunchCache = toml::from_str(&body).context("parsing launch cache")?;
    Ok(Some(c))
}

#[cfg(test)]
mod tests {
    use super::{read_private, write_private};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("optima-cfg-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn writes_private_and_reads_back() {
        let d = tmpdir("rw");
        let f = d.join("auth.toml");
        write_private(&f, "ticket = \"abc\"\n").unwrap();
        assert_eq!(read_private(&f).unwrap(), "ticket = \"abc\"\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "secret should never be group/world readable");
        }
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn overwrites_atomically_and_leaves_no_temp() {
        let d = tmpdir("atomic");
        let f = d.join("auth.toml");
        write_private(&f, "one").unwrap();
        write_private(&f, "two").unwrap();
        assert_eq!(read_private(&f).unwrap(), "two");
        let strays: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(strays.is_empty(), "left temp files behind: {strays:?}");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn refuses_to_read_a_secret_through_a_symlink() {
        let d = tmpdir("link");
        let real = d.join("elsewhere.toml");
        std::fs::write(&real, "ticket = \"stolen\"").unwrap();
        let link = d.join("auth.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_private(&link).is_err());
        std::fs::remove_dir_all(&d).ok();
    }
}
