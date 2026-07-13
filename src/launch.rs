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

/// Our reimplemented Orbit R2 loader (32-bit), built from Re0xCat's open
/// `ubiorbitapi_r2_loader` (the C++ `OrbitClient` ABI). Older titles like
/// Assassin's Creed III import `ubiorbitapi_r2_loader.dll` (the C++ Orbit client)
/// *and* `upc_r1_loader.dll` (flat UPLAY_* C API) instead of `uplay_r1_loader.dll`.
/// Without our own `ubiorbitapi_r2_loader.dll` the game bails with "Unable to find
/// Ubisoft Game Launcher". `upc_r1_loader.dll` exports the same 11 UPLAY_* symbols
/// our uplay R1 loader already provides, so we satisfy it by deploying a copy of
/// LOADER32 under that name.
const ORBIT_R2_32: &[u8] = include_bytes!("../drm/orbit_r2/ubiorbitapi_r2_loader.dll");

/// Our self-signed code-signing cert (public, DER). Some titles (Watch_Dogs)
/// anti-tamper-verify the Authenticode signature of the folder-local
/// `uplay_r1_loader64.dll`; our shims are signed with this cert (subject mimics
/// Ubisoft's) and it's imported into the prefix's trusted Root store at launch so
/// `WinVerifyTrust` chains OK. Only ever trusted inside the game's throwaway
/// prefix — it grants no real-world trust.
const SIGNING_CERT: &[u8] = include_bytes!("../drm/signing/optima-signing.cer");

/// EAX shim (`drm/eax/eax.dll`, 32-bit). Old titles (Beyond Good & Evil's settings
/// app, Splinter Cell) demand Creative EAX; it doesn't exist under Proton, so they
/// fail with "EAX not properly installed". Our shim forwards EAXDirectSoundCreate8
/// to plain DirectSound (Wine implements that) so the check passes. Deployed
/// next to any exe that references EAX (`deploy_eax`).
const EAX_STUB_32: &[u8] = include_bytes!("../drm/eax/eax.dll");

/// Does this exe require Creative EAX? Both statically-linked (imports EAX.DLL) and
/// dynamic (LoadLibrary "eax.dll" + GetProcAddress) users carry the literal
/// `EAXDirectSound...` symbol name in the binary, so a byte scan catches both.
pub fn needs_eax(exe: &Path) -> bool {
    match std::fs::read(exe) {
        Ok(bytes) => find_bytes(&bytes, b"EAXDirectSound").is_some(),
        Err(_) => false,
    }
}

/// Drop our EAX shim next to the exe if the exe needs EAX and no working `eax.dll`
/// is already ours. Backs up any real (Creative) eax.dll once — under Proton it
/// can't work anyway, but the move stays reversible.
pub fn deploy_eax(dir: &Path, exe: &Path) -> Result<()> {
    if !needs_eax(exe) {
        return Ok(());
    }
    let dst = dir.join("eax.dll");
    if dst.exists() {
        let bak = dir.join("eax.dll.orig");
        if !bak.exists() && std::fs::metadata(&dst).map(|m| m.len() as usize).ok() != Some(EAX_STUB_32.len()) {
            std::fs::rename(&dst, &bak).with_context(|| format!("backing up {}", dst.display()))?;
        }
    }
    std::fs::write(&dst, EAX_STUB_32).with_context(|| format!("writing {}", dst.display()))?;
    println!("[launch] deployed EAX shim → {}", dst.display());
    Ok(())
}

/// Which Ubisoft DRM generation a game's exe links against — decides which loader
/// DLLs and config files we deploy. Detected by scanning the exe's imports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Drm {
    /// Imports `uplay_r1_loader.dll` (flat UPLAY_* C API). AC4, most R1 SP titles.
    UplayR1,
    /// Imports `ubiorbitapi_r2_loader.dll` (C++ OrbitClient) + `upc_r1_loader.dll`.
    /// AC3 and other early-Orbit AnvilNext titles.
    OrbitR2,
}

/// Detect the DRM generation by scanning the game exe for the loader DLL name it
/// imports. Both names appear as plain ASCII in the PE import directory, so a byte
/// scan is enough and needs no PE parser. Orbit R2 is checked first because those
/// titles import *both* names.
pub fn detect_drm(exe: &Path) -> Drm {
    match std::fs::read(exe) {
        Ok(bytes) => {
            if find_bytes(&bytes, b"ubiorbitapi_r2_loader").is_some() {
                Drm::OrbitR2
            } else {
                Drm::UplayR1
            }
        }
        // Unreadable exe: assume the common case; run_game will surface a clearer
        // error if the path is actually wrong.
        Err(_) => Drm::UplayR1,
    }
}

/// Case-insensitive substring search over raw bytes (DLL import names are ASCII).
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let lower = |b: u8| b.to_ascii_lowercase();
    (0..=hay.len() - needle.len())
        .find(|&i| hay[i..i + needle.len()].iter().zip(needle).all(|(a, b)| lower(*a) == lower(*b)))
}

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
/// resolved. Saves go to a RELATIVE `Saves` dir we create up front — the `<default>`
/// token gets misread as a Windows path under Wine (`<`/`>` are illegal path chars)
/// and the loader hands the game a null save-store path, which WD1/AnvilNext then
/// null-derefs during local-save init right after the offline-mode check. Same bug
/// the Orbit R2 writer already dodges with a real relative dir.
pub fn write_uplay_toml(game_dir: &Path, acct: &LaunchAccount, name: &str) -> Result<()> {
    std::fs::create_dir_all(game_dir.join("Saves")).ok();
    // Most single-player titles want offline (AC4's cloud-save thread null-derefs
    // without a real backend). A few AnvilNext/Disrupt titles are the opposite —
    // Watch_Dogs null-derefs inside Disrupt right after IsInOfflineMode returns
    // true, i.e. its offline-gated init path expects online-session state our stub
    // never established. OPTIMA_ONLINE=1 reports online so those follow the
    // connected code path instead. Ownership is unaffected either way.
    let offline = !matches!(
        std::env::var("OPTIMA_ONLINE").ok().as_deref(),
        Some("1") | Some("true")
    );
    let toml = format!(
        "[Uplay]\n\
         Name = \"{name}\"\n\
         Saves = \"Saves\"\n\
         CdKeys = [\"\"]\n\
         Language = \"{language}\"\n\
         OfflineMode = {offline}\n\
         InstallHooks = false\n\
         \n\
         [Uplay.Log]\n\
         Write = {log}\n\
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
        log = std::env::var_os("OPTIMA_LOG").is_some(),
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

/// Write `Orbit.toml` — the config our Orbit R2 emu (`ubiorbitapi_r2_loader.dll`)
/// reads from the game's working dir at load time (`env::current_dir()/Orbit.toml`).
/// The struct is `[Orbit] Name/ProductId/Saves/CdKeys`, `[Orbit.Log] Write/Path`,
/// `[Orbit.Profile] AccountId/Username/Password`. `Saves` is a folder for local
/// saves; we point it at `<game_dir>/Saves` and create it so any early savegame
/// enumeration doesn't fail. Ownership + identity are the real account values.
pub fn write_orbit_toml(game_dir: &Path, acct: &LaunchAccount, name: &str) -> Result<()> {
    // Keep the saves dir path RELATIVE: the emu runs inside Wine and resolves it
    // against the game's working dir. An absolute Linux path ("/home/...") would be
    // misread as a Windows path under Wine and fail. "Saves" → <game_dir>/Saves in
    // both the Linux and Wine views.
    std::fs::create_dir_all(game_dir.join("Saves")).ok();
    let toml = format!(
        "[Orbit]\n\
         Name = \"{name}\"\n\
         ProductId = {product_id}\n\
         Saves = \"Saves\"\n\
         CdKeys = [\"\"]\n\
         \n\
         [Orbit.Log]\n\
         Write = {log}\n\
         Path = \"Orbit.log\"\n\
         \n\
         [Orbit.Profile]\n\
         AccountId = \"{account_id}\"\n\
         Username = \"{username}\"\n\
         Password = \"{password}\"\n",
        name = toml_escape(name),
        product_id = acct.app_id,
        log = std::env::var_os("OPTIMA_LOG").is_some(),
        account_id = toml_escape(&acct.user_id),
        username = toml_escape(&acct.username),
        password = toml_escape(&acct.password),
    );
    let path = game_dir.join("Orbit.toml");
    std::fs::write(&path, toml).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Drop our reimplemented loaders into the game folder, backing up any real ones
/// the game shipped (so the move is reversible). `drm` selects which loaders the
/// title actually imports: R1 titles only need the flat UPLAY_* loader; Orbit R2
/// titles (AC3) additionally need our C++ `ubiorbitapi_r2_loader.dll` and a
/// `upc_r1_loader.dll` (same UPLAY_* API — satisfied by a copy of our R1 loader).
pub fn deploy_loaders(game_dir: &Path, drm: Drm) -> Result<()> {
    let mut loaders: Vec<(&str, &[u8])> = vec![
        ("uplay_r1_loader64.dll", LOADER64),
        ("uplay_r1_loader.dll", LOADER32),
        // Old Orbit-era titles import this name; our 64-bit DLL satisfies it too.
        ("ubiorbitapi_r1_loader64.dll", LOADER64),
    ];
    if drm == Drm::OrbitR2 {
        // The C++ OrbitClient DLL (the "Ubisoft Game Launcher" the game looks for)
        // and the flat-C UPC loader (same 11 UPLAY_* exports as our R1 loader).
        loaders.push(("ubiorbitapi_r2_loader.dll", ORBIT_R2_32));
        loaders.push(("upc_r1_loader.dll", LOADER32));
    }
    for (name, bytes) in loaders {
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
        Ok(m) => {
            let n = m.len() as usize;
            n == LOADER64.len() || n == LOADER32.len() || n == ORBIT_R2_32.len()
        }
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

/// The working directory a game should run from. Ubisoft titles expect the install
/// ROOT (their config's `working_directory` points at the install dir). Unreal
/// titles (Splinter Cell Chaos Theory) keep their exe in a `System/` subdir and
/// resolve data relative to it, so those run from `System/`.
pub fn working_dir(install_root: &Path, exe: &Path) -> PathBuf {
    if let Some(parent) = exe.parent() {
        if parent
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("System"))
            .unwrap_or(false)
        {
            return parent.to_path_buf();
        }
    }
    install_root.to_path_buf()
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
    install_reg: Option<&str>,
) -> Result<()> {
    let win = format!("{}\\", wine_path(game_dir));

    // The Ubisoft Launcher install keys never change → set once per prefix.
    let launcher_marker = prefix.join(format!(".optima-reg3-{product_id}"));
    if !launcher_marker.exists() {
        reg_add_both(umu, proton, prefix,
            &format!("HKLM\\SOFTWARE\\Ubisoft\\Launcher\\Installs\\{product_id}"), "InstallDir", &win);
        reg_add_both(umu, proton, prefix,
            "HKLM\\SOFTWARE\\Ubisoft\\Launcher", "InstallDir", &win);
        std::fs::write(&launcher_marker, "").ok();
    }

    // The game's OWN install-path key from the product config (e.g. BG&E's
    // `HKLM\SOFTWARE\Ubisoft\Beyond Good & Evil\Install path`). Old settings apps /
    // games read it to confirm the game is installed and to find their data;
    // without it BG&E's SettingsApplication bails "not properly installed". This is
    // guarded by its OWN marker, written only once we ACTUALLY have the key — the
    // config fetch that yields it can flake/be offline, so we must keep retrying
    // across launches until it's set rather than marking it done prematurely.
    let gamekey_marker = prefix.join(format!(".optima-gamekey-{product_id}"));
    if !gamekey_marker.exists() {
        if let Some((key, value)) = install_reg.and_then(parse_register) {
            println!("[launch] setting game install key: {key}\\{value}");
            reg_add_both(umu, proton, prefix, &key, &value, &win);
            std::fs::write(&gamekey_marker, "").ok();
        }
    }
    Ok(())
}

/// `reg add` a value to BOTH the native and the Wow6432Node (32-bit view) path, so
/// it's visible regardless of the reading process's bitness. These classic titles
/// are 32-bit and their HKLM\SOFTWARE reads redirect to Wow6432Node.
fn reg_add_both(umu: &Path, proton: &Option<PathBuf>, prefix: &Path, key: &str, value: &str, data: &str) {
    let mut targets = vec![key.to_string()];
    if let Some(w) = wow64_variant(key) {
        targets.push(w);
    }
    for k in targets {
        let mut cmd = std::process::Command::new("python3");
        cmd.arg(umu)
            .arg("reg")
            .arg("add")
            .arg(&k)
            .arg("/v")
            .arg(value)
            .arg("/t")
            .arg("REG_SZ")
            .arg("/d")
            .arg(data)
            .arg("/f")
            .env("WINEPREFIX", prefix)
            .env("GAMEID", "0")
            .env("STORE", "none");
        if let Some(p) = proton {
            cmd.env("PROTONPATH", p);
        }
        let _ = cmd.status();
    }
}

/// Produce the WOW64 (32-bit view) variant of an HKLM\SOFTWARE key by inserting
/// `Wow6432Node` after `SOFTWARE`, so a value written from 64-bit `reg` is visible
/// to 32-bit apps (whose SOFTWARE reads are redirected there). Returns None if the
/// key isn't an HKLM\SOFTWARE key or already targets Wow6432Node.
fn wow64_variant(key: &str) -> Option<String> {
    let upper = key.to_uppercase();
    if upper.contains("WOW6432NODE") {
        return None;
    }
    let prefix = "HKLM\\SOFTWARE\\";
    if upper.starts_with("HKLM\\SOFTWARE\\") {
        let rest = &key[prefix.len()..];
        Some(format!("HKLM\\SOFTWARE\\Wow6432Node\\{rest}"))
    } else {
        None
    }
}

/// Import our code-signing cert into the prefix's trusted Root store, so games
/// that Authenticode-verify the folder-local loader DLL (e.g. Watch_Dogs) accept
/// our signed shims. Marker-guarded (one Proton spin-up per prefix). Best-effort.
fn ensure_cert_trust(umu: &Path, proton: &Option<PathBuf>, prefix: &Path) {
    let marker = prefix.join(".optima-cert");
    if marker.exists() {
        return;
    }
    let cer = prefix.join("optima-signing.cer");
    if std::fs::write(&cer, SIGNING_CERT).is_err() {
        return;
    }
    let win = wine_path(&cer);
    println!("[launch] trusting Optima signing cert in prefix Root store");
    // certutil.exe is a Wine builtin; run it through umu like `reg`.
    for store in ["Root", "TrustedPublisher"] {
        let mut cmd = std::process::Command::new("python3");
        cmd.arg(umu)
            .arg("certutil")
            .arg("-addstore")
            .arg("-f")
            .arg(store)
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

/// Split a Ubisoft config `register` string into (key, value_name). The last
/// backslash-separated segment is the value name; the rest is the key. Normalizes
/// the full hive names to the short forms `reg add` expects.
fn parse_register(reg: &str) -> Option<(String, String)> {
    let reg = reg
        .replace("HKEY_LOCAL_MACHINE", "HKLM")
        .replace("HKEY_CURRENT_USER", "HKCU")
        .replace("HKEY_CLASSES_ROOT", "HKCR");
    let idx = reg.rfind('\\')?;
    let key = reg[..idx].trim().to_string();
    let value = reg[idx + 1..].trim().to_string();
    if key.is_empty() || value.is_empty() {
        None
    } else {
        Some((key, value))
    }
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
    install_reg: Option<&str>,
) -> Result<()> {
    let (umu, proton) = resolve_runtime()?;
    std::fs::create_dir_all(prefix).ok();

    // Working directory: the install ROOT by default (what Ubisoft titles expect —
    // e.g. Watch_Dogs' exe is in bin/ but it resolves data_win64/ etc. relative to
    // the root, per its config working_directory=…\InstallDir). Unreal-engine
    // titles (Splinter Cell Chaos Theory) are the exception: their exe lives in a
    // System/ subdir and they resolve data relative to it, so those run from there.
    let cwd = working_dir(game_dir, exe);

    let mut cmd = std::process::Command::new("python3");
    cmd.arg(&umu)
        .arg(exe)
        .args(args)
        .current_dir(&cwd)
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
            cwd.display(),
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
    // Trust our signing cert so anti-tamper signature checks on the shim pass.
    ensure_cert_trust(&umu, &proton, prefix);
    ensure_registry(&umu, &proton, prefix, product_id, game_dir, install_reg)?;
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
