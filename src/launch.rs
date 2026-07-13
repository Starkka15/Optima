//! Game launch (P3): satisfy Uplay R1 DRM without the full Ubisoft Connect
//! launcher, then run the game under Proton.
//!
//! We ship our own reimplemented `uplay_r1_loader64.dll` / `uplay_r1_loader.dll`
//! (built from the vendored Mini_Uplay source in `drm/uplay_r1/`) into the game
//! folder. On boot the game loads OUR DLL (Windows/Wine resolves the folder-local
//! DLL first), which returns success for the ownership handshake and hands the
//! game the account's REAL data — id, name, and `uplay_pc_ticket` — that
//! `optima-cli` fetched from the ownership service. Ownership itself is gated
//! upstream (we only launch games the account owns), so this is ownership-backed,
//! not a spoof.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

/// Our reimplemented R1 loaders, compiled at build time by mingw and embedded so
/// `optima-cli` is self-contained (no external files to ship).
const LOADER64: &[u8] = include_bytes!("../drm/uplay_r1/uplay_r1_loader64.dll");
const LOADER32: &[u8] = include_bytes!("../drm/uplay_r1/uplay_r1_loader.dll");

/// Everything the reimplemented loader needs to present a logged-in, owning user.
pub struct LaunchAccount {
    pub user_id: String,   // Ubisoft account UUID (profile id)
    pub username: String,  // display name
    pub email: String,
    pub ticket: String,    // real uplay_pc_ticket (or a placeholder if unavailable)
    pub password: String,  // player-supplied (profile); not validated offline
    pub app_id: u32,       // used only for the on-disk save path layout
    pub language: String,  // e.g. "en-US"
}

/// Write `Uplay.ini` next to the game exe — the config the loader reads at
/// startup (`GetPrivateProfileStringA("Uplay", ...)`).
pub fn write_uplay_ini(game_dir: &Path, acct: &LaunchAccount) -> Result<()> {
    // IsAppOwned=1 → UPLAY_USER_IsOwned returns true (the DRM gate).
    // UplayConnection=0 → not offline; pairs with IsConnected=1.
    let ini = format!(
        "[Uplay]\r\n\
         IsAppOwned=1\r\n\
         UplayConnection=0\r\n\
         AppId={app_id}\r\n\
         Username={username}\r\n\
         Email={email}\r\n\
         Password={password}\r\n\
         Language={language}\r\n\
         CdKey=\r\n\
         UserId={user_id}\r\n\
         TickedId={ticket}\r\n\
         SavePath=Default\r\n",
        app_id = acct.app_id,
        username = acct.username,
        email = acct.email,
        password = acct.password,
        language = acct.language,
        user_id = acct.user_id,
        ticket = acct.ticket,
    );
    let path = game_dir.join("Uplay.ini");
    std::fs::write(&path, ini).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Escape a value for a TOML basic (double-quoted) string.
fn toml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Write `Uplay.toml` — the config our complete emu (Re0xCat uplay_r1_loader)
/// reads from the game's working dir at load time. `OfflineMode=true` keeps the
/// game on local saves; `InstallHooks=false` because there is no original DLL to
/// hook (we ARE the loader). Ownership + identity come from the real account we
/// resolved. `Saves="<default>"` → `<game_dir>/Saves`.
pub fn write_uplay_toml(game_dir: &Path, acct: &LaunchAccount, name: &str) -> Result<()> {
    let toml = format!(
        "[Uplay]\n\
         Name = \"{name}\"\n\
         Saves = \"<default>\"\n\
         CdKeys = [\"\"]\n\
         Language = \"{language}\"\n\
         OfflineMode = true\n\
         InstallHooks = false\n\
         \n\
         [Uplay.Log]\n\
         Write = false\n\
         Path = \"Uplay.log\"\n\
         \n\
         [Uplay.Profile]\n\
         AccountId = \"{account_id}\"\n\
         Email = \"{email}\"\n\
         Username = \"{username}\"\n\
         Password = \"{password}\"\n\
         Ticket = \"{ticket}\"\n",
        name = toml_escape(name),
        language = toml_escape(&acct.language),
        account_id = toml_escape(&acct.user_id),
        email = toml_escape(&acct.email),
        username = toml_escape(&acct.username),
        password = toml_escape(&acct.password),
        ticket = toml_escape(&acct.ticket),
    );
    let path = game_dir.join("Uplay.toml");
    std::fs::write(&path, toml).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Drop our reimplemented loaders into the game folder, backing up any real ones
/// the game shipped (so the move is reversible).
pub fn deploy_loaders(game_dir: &Path) -> Result<()> {
    for (name, bytes) in [
        ("uplay_r1_loader64.dll", LOADER64),
        ("uplay_r1_loader.dll", LOADER32),
        // Old Orbit-era titles import this name; our 64-bit DLL satisfies it too.
        ("ubiorbitapi_r1_loader64.dll", LOADER64),
    ] {
        let dst = game_dir.join(name);
        // Back up a real, non-Optima DLL exactly once.
        if dst.exists() {
            let bak = game_dir.join(format!("{name}.orig"));
            if !bak.exists() && !is_our_loader(&dst) {
                std::fs::rename(&dst, &bak)
                    .with_context(|| format!("backing up {}", dst.display()))?;
            }
        }
        std::fs::write(&dst, bytes).with_context(|| format!("writing {}", dst.display()))?;
    }
    Ok(())
}

/// Heuristic: is this DLL already one of ours? (Avoids re-backing-up on re-runs.)
/// Our loaders export `UPLAY_USER_IsOwned`; more simply, we tag by exact size
/// match against the embedded bytes.
fn is_our_loader(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => m.len() as usize == LOADER64.len() || m.len() as usize == LOADER32.len(),
        Err(_) => false,
    }
}

/// Locate maxima's bundled umu + Proton (already installed on this system and on
/// the Ally), falling back to a system `umu-run` / `PROTONPATH`.
fn resolve_runtime() -> Result<(PathBuf, Option<PathBuf>)> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("no home dir"))?;
    let umu = home.join(".local/share/maxima/wine/umu/umu-run");
    let umu = if umu.exists() {
        umu
    } else if let Ok(p) = which("umu-run") {
        p
    } else {
        bail!("umu-run not found (looked for maxima's bundle and $PATH). Install umu-launcher.");
    };
    // OPTIMA_PROTON pins a specific Proton (path, or a name resolved against the
    // usual Steam/umu install dirs). Old AnvilNext titles (AC3/AC4) want a stable
    // Proton — GE-Proton11-1 (wine-staging 11.0 "experimental") crashes services.exe
    // during prefix init here. Default stays on Maxima's bundle for parity.
    let proton = match std::env::var_os("OPTIMA_PROTON") {
        Some(v) => {
            let raw = PathBuf::from(&v);
            if raw.is_absolute() && raw.exists() {
                Some(raw)
            } else {
                let name = v.to_string_lossy();
                let candidates = [
                    home.join(".local/share/Steam/compatibilitytools.d").join(&*name),
                    home.join(".steam/root/compatibilitytools.d").join(&*name),
                    home.join(".local/share/umu").join(&*name),
                    home.join(".steam/steam/steamapps/common").join(&*name),
                ];
                candidates.into_iter().find(|p| p.exists()).or_else(|| {
                    eprintln!("[launch] OPTIMA_PROTON={name} not found; falling back to bundled proton");
                    None
                })
            }
        }
        None => None,
    };
    let proton = proton.or_else(|| {
        let p = home.join(".local/share/maxima/wine/proton");
        if p.exists() { Some(p) } else { None }
    });
    if let Some(p) = &proton {
        println!("[launch] using Proton: {}", p.display());
    }
    Ok((umu, proton))
}

fn which(bin: &str) -> Result<PathBuf> {
    let out = std::process::Command::new("which").arg(bin).output()?;
    if !out.status.success() {
        bail!("{bin} not on PATH");
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(PathBuf::from(p))
}

/// Convert a Linux path to the Wine drive-Z view (`/foo/bar` → `Z:\foo\bar`).
fn wine_path(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    format!("Z:{s}")
}

/// Ubisoft games resolve their working directory from
/// `HKLM\SOFTWARE\Ubisoft\Launcher\Installs\<id>\InstallDir` (and check the base
/// `Launcher\InstallDir`). In a fresh prefix those are absent, so the game can't
/// find its data and exits immediately. Set them once per prefix (marker-guarded
/// so we don't pay a full Proton spin-up on every launch).
fn ensure_registry(
    umu: &Path,
    proton: &Option<PathBuf>,
    prefix: &Path,
    product_id: u32,
    game_dir: &Path,
) -> Result<()> {
    let marker = prefix.join(format!(".optima-reg-{product_id}"));
    if marker.exists() {
        return Ok(());
    }
    let win = format!("{}\\", wine_path(game_dir));
    let keys = [
        (
            format!("HKLM\\SOFTWARE\\Ubisoft\\Launcher\\Installs\\{product_id}"),
            "InstallDir",
            win.clone(),
        ),
        (
            "HKLM\\SOFTWARE\\Ubisoft\\Launcher".to_string(),
            "InstallDir",
            win.clone(),
        ),
    ];
    for (key, val, data) in keys {
        let mut cmd = std::process::Command::new("python3");
        cmd.arg(umu)
            .arg("reg")
            .arg("add")
            .arg(&key)
            .arg("/v")
            .arg(val)
            .arg("/t")
            .arg("REG_SZ")
            .arg("/d")
            .arg(&data)
            .arg("/f")
            .env("WINEPREFIX", prefix)
            .env("GAMEID", "0")
            .env("STORE", "none");
        if let Some(p) = proton {
            cmd.env("PROTONPATH", p);
        }
        let _ = cmd.status();
    }
    std::fs::write(&marker, "").ok();
    Ok(())
}

/// Import any `.reg` files the game ships (its installer normally would) into the
/// prefix, so games that read pre-seeded registry settings — e.g. Beyond Good &
/// Evil's `support/settings.reg` — find them and don't bail with "settings not
/// correctly set". Looks in the game root and a `support/` subdir. Marker-guarded
/// per product. Best-effort: failures here never block the launch.
fn import_reg_seeds(
    umu: &Path,
    proton: &Option<PathBuf>,
    prefix: &Path,
    product_id: u32,
    game_dir: &Path,
) {
    let marker = prefix.join(format!(".optima-regseed-{product_id}"));
    if marker.exists() {
        return;
    }
    let mut regs: Vec<PathBuf> = Vec::new();
    for dir in [game_dir.to_path_buf(), game_dir.join("support")] {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()).map(|x| x.eq_ignore_ascii_case("reg"))
                    == Some(true)
                {
                    regs.push(p);
                }
            }
        }
    }
    for reg in &regs {
        let win = wine_path(reg);
        println!("[launch] importing registry seed {}", reg.display());
        let mut cmd = std::process::Command::new("python3");
        cmd.arg(umu)
            .arg("regedit")
            .arg("/S")
            .arg(&win)
            .env("WINEPREFIX", prefix)
            .env("GAMEID", "0")
            .env("STORE", "none");
        if let Some(p) = proton {
            cmd.env("PROTONPATH", p);
        }
        let _ = cmd.status();
    }
    std::fs::write(&marker, "").ok();
}

/// Run the game exe under Proton via umu, CWD set to the game folder.
pub fn run_game(
    game_dir: &Path,
    exe: &Path,
    prefix: &Path,
    product_id: u32,
    args: &[String],
) -> Result<()> {
    let (umu, proton) = resolve_runtime()?;
    std::fs::create_dir_all(prefix).ok();

    let mut cmd = std::process::Command::new("python3");
    cmd.arg(&umu)
        .arg(exe)
        .args(args)
        .current_dir(game_dir)
        .env("WINEPREFIX", prefix)
        .env("GAMEID", "0")
        .env("STORE", "none");
    if let Some(p) = &proton {
        cmd.env("PROTONPATH", p);
    }
    // Many Ubisoft/GameWorks titles (AC4's GFSDK HBAO+/Godrays/PCSS, etc.) call
    // NvAPI and null-deref when it fails to init under Proton — the same crash
    // that hit Mirror's Edge Catalyst here. Disable NvAPI cleanly so those
    // features are skipped instead of crashing. OPTIMA_ENABLE_NVAPI=1 to opt out.
    // Harmless on AMD (the Ally). DXVK-NVAPI off too for good measure.
    if std::env::var_os("OPTIMA_ENABLE_NVAPI").is_none() {
        cmd.env("PROTON_DISABLE_NVAPI", "1").env("DXVK_ENABLE_NVAPI", "0");
    }
    // Legacy Ubisoft AnvilNext titles (AC3/AC4/etc.) mismanage high CPU core
    // counts and crash on startup right after the first frame. Cap the CPU
    // topology the game sees (Proton's WINE_CPU_TOPOLOGY) — 4 is the documented
    // working value. OPTIMA_CPU_LIMIT=N overrides; OPTIMA_CPU_LIMIT=0 disables.
    let cpu_limit: usize = std::env::var("OPTIMA_CPU_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    if cpu_limit > 0 {
        let list: Vec<String> = (0..cpu_limit).map(|i| i.to_string()).collect();
        cmd.env("WINE_CPU_TOPOLOGY", format!("{}:{}", cpu_limit, list.join(",")));
    }
    // DXVK can put a game's D3D9 device on the software `llvmpipe`/lavapipe ICD
    // even when a real GPU is present (D3D11 gets the GPU, D3D9 gets llvmpipe) —
    // AC4 creates a D3D9 device and null-deref's on the software one. Pin DXVK to
    // the real GPU by name so llvmpipe is never selected. OPTIMA_DXVK_FILTER
    // overrides the substring; auto-detected NVIDIA/AMD otherwise.
    // OPTIMA_DXVK_FILTER="none" (or empty) disables the pin entirely.
    let filter = match std::env::var("OPTIMA_DXVK_FILTER") {
        Ok(v) if v.eq_ignore_ascii_case("none") || v.is_empty() => None,
        Ok(v) => Some(v),
        Err(_) => {
            // Only pin on NVIDIA desktops (the observed llvmpipe-for-D3D9 case).
            // The Ally's single AMD GPU has no such ambiguity, so leave it alone.
            if Path::new("/proc/driver/nvidia").exists() || Path::new("/dev/nvidia0").exists() {
                Some("NVIDIA".to_string())
            } else {
                None
            }
        }
    };
    if let Some(f) = filter {
        cmd.env("DXVK_FILTER_DEVICE_NAME", f);
    }
    if std::env::var_os("OPTIMA_LOG").is_some() {
        cmd.env("PROTON_LOG", "1")
            .env("PROTON_LOG_DIR", prefix)
            // Show the Vulkan loader's ICD discovery + DXVK's device pick, so we
            // can see exactly why a given arch does/doesn't get the real GPU.
            .env("VK_LOADER_DEBUG", "error,warn,info")
            .env("DXVK_LOG_LEVEL", "info");
    }

    // OPTIMA_NO_RUN: set up everything and print the command instead of launching
    // (used to verify the DRM setup without spawning the game's window).
    if std::env::var_os("OPTIMA_NO_RUN").is_some() {
        println!(
            "[launch] would run: cd {} && WINEPREFIX={} GAMEID=0 STORE=none{} python3 {} {} {}",
            game_dir.display(),
            prefix.display(),
            proton
                .as_ref()
                .map(|p| format!(" PROTONPATH={}", p.display()))
                .unwrap_or_default(),
            umu.display(),
            exe.display(),
            args.join(" "),
        );
        return Ok(());
    }

    // Point the Ubisoft install registry at the game folder first.
    ensure_registry(&umu, &proton, prefix, product_id, game_dir)?;
    // Old Ubisoft installers import shipped .reg seeds (e.g. BG&E's
    // support/settings.reg holds the SettingsApplication.INI keys the game
    // demands — without them it errors "Application settings not correctly
    // set"). Emulate that: import any shipped .reg into the prefix once.
    import_reg_seeds(&umu, &proton, prefix, product_id, game_dir);

    println!(
        "[launch] starting {} {} under Proton...",
        exe.display(),
        args.join(" ")
    );
    let status = cmd.status().context("spawning umu-run")?;
    if !status.success() {
        bail!("game exited with status {status}");
    }
    Ok(())
}
