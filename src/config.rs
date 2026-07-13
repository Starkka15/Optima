//! On-disk state: the stored Ubisoft session/token, in `auth.toml` under the
//! platform data dir (mirrors Maxima's `auth.toml`). Never contains the user's
//! password — only the returned session ticket + refresh (rememberMe) ticket.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

fn auth_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("auth.toml"))
}

pub fn save_auth(auth: &Auth) -> Result<()> {
    let path = auth_path()?;
    let body = toml::to_string_pretty(auth).context("serializing auth")?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    // Best-effort tighten perms — this holds a session ticket.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_auth() -> Result<Option<Auth>> {
    let path = auth_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
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
    std::fs::write(&path, toml::to_string_pretty(p).context("serializing profile")?)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
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
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_launch_cache(product_id: u32) -> Result<Option<LaunchCache>> {
    let path = launch_cache_path(product_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let c: LaunchCache = toml::from_str(&body).context("parsing launch cache")?;
    Ok(Some(c))
}
