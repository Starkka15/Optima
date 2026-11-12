// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Starkka15

//! Official Ubisoft Connect launch mode.
//!
//! Instead of putting our DRM shims next to the game, this runs Ubisoft's own
//! client in a dedicated Proton prefix and starts the game through its
//! `uplay://launch/<id>/0` handler, so Ubisoft decides ownership, refunds and DRM.
//! Optima still downloads and installs the files; Connect only runs them.
//!
//! The approach (one shared client prefix, the CDN installer run with `/S`, the
//! `mscoree,mshtml=` overrides, seeding a paused official download) follows the
//! research in xXJSONDeruloXx/ubi-cli-mvp (MIT). This is a re-implementation, not
//! copied code.
//!
//! The prefix is separate from the shim prefix on purpose: no Optima certificate
//! is trusted in it and no shim is ever placed for a Connect launch.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use crate::config;
use crate::launch;

const INSTALLER_URL: &str = "https://static3.cdn.ubi.com/orbit/launcher_installer/UbisoftConnectInstaller.exe";
const LAUNCHER_DIR: &str = "drive_c/Program Files (x86)/Ubisoft/Ubisoft Game Launcher";
/// Connect's AppData, where it keeps its own remembered login.
const APPDATA_DIR: &str = "drive_c/users/steamuser/AppData/Local/Ubisoft Game Launcher";

/// The dedicated Connect prefix (`~/.local/share/optima/connect-prefix`).
pub fn prefix() -> Result<PathBuf> {
    Ok(config::data_dir()?.join("connect-prefix"))
}

fn launcher_dir(prefix: &Path) -> PathBuf {
    prefix.join(LAUNCHER_DIR)
}

fn connect_exe(prefix: &Path) -> Option<PathBuf> {
    let p = launcher_dir(prefix).join("UbisoftConnect.exe");
    p.is_file().then_some(p)
}

/// Connect writes these once someone has signed in inside it. Offline evidence
/// only: it cannot tell whether Ubisoft has since expired the login.
pub fn has_login(prefix: &Path) -> bool {
    let d = prefix.join(APPDATA_DIR);
    // Connect 175 writes the remembered login into secure storage (and
    // user.vdat, whose name has changed before, so it isn't relied on).
    std::fs::metadata(d.join("ConnectSecureStorage.dat")).map(|m| m.len() > 0).unwrap_or(false)
}

/// A `umu-run` command in the Connect prefix with the client's DLL overrides.
fn wine(prefix: &Path) -> Result<Command> {
    let (umu, proton) = launch::resolve_runtime()?;
    let mut cmd = Command::new("python3");
    cmd.arg(umu)
        .env("WINEPREFIX", prefix)
        .env("GAMEID", "0")
        .env("STORE", "none")
        // Connect fails ownership-signature requests without these.
        .env("WINEDLLOVERRIDES", "mscoree,mshtml=")
        .env("WINEDEBUG", "-all");
    launch::scrub_ubi_env(&mut cmd);
    // OPTIMA_CONNECT_PROTON picks a Proton for Connect alone (path or a name
    // umu understands, e.g. GE-Proton); otherwise the same one games use.
    match std::env::var_os("OPTIMA_CONNECT_PROTON") {
        Some(p) => {
            cmd.env("PROTONPATH", p);
        }
        None => {
            if let Some(p) = proton {
                cmd.env("PROTONPATH", p);
            }
        }
    }
    Ok(cmd)
}

/// Connect settings written before the first start, as the Lutris installer
/// does: no overlay (it hooks games and misbehaves under Wine) and quit on
/// close instead of hiding in a tray that Game Mode doesn't have.
const SETTINGS_YAML: &str = "overlay:\n  enabled: false\n  forceunhookgame: false\n  fps_enabled: false\n  warning_enabled: false\nuser:\n  closebehavior: CloseBehavior_Close\n";

fn write_settings(prefix: &Path) -> Result<()> {
    let dir = prefix.join(APPDATA_DIR);
    let path = dir.join("settings.yaml");
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dir)?;
    std::fs::write(&path, SETTINGS_YAML)?;
    Ok(())
}

/// Fonts and the D3D compiler Connect's UI wants (the Lutris recipe), once
/// per prefix. Best effort: a failure is reported, not fatal.
fn ensure_winetricks(prefix: &Path) {
    let marker = prefix.join(".optima-winetricks");
    if marker.exists() {
        return;
    }
    println!("[connect] installing fonts + d3dcompiler_43 with winetricks (first setup only)...");
    let ok = wine(prefix)
        .and_then(|mut c| {
            Ok(c.args(["winetricks", "-q", "corefonts", "d3dcompiler_43"])
                .stdout(std::process::Stdio::null())
                .status()?)
        })
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        let _ = std::fs::write(&marker, "");
    } else {
        eprintln!("[connect] winetricks failed; continuing (Connect may show missing fonts)");
    }
}

/// True if a PE file carries an Authenticode certificate table (data directory
/// 4). A structural check only; the HTTPS download from Ubisoft's CDN is what
/// we actually trust.
fn has_signature(pe: &[u8]) -> bool {
    let rd32 = |o: usize| pe.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let rd16 = |o: usize| pe.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let Some(e_lfanew) = rd32(0x3c).map(|v| v as usize) else { return false };
    if pe.get(0..2) != Some(b"MZ") || pe.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return false;
    }
    let opt = e_lfanew + 24;
    let dirs = match rd16(opt) {
        Some(0x10b) => opt + 96,  // PE32
        Some(0x20b) => opt + 112, // PE32+
        _ => return false,
    };
    let sec = dirs + 4 * 8;
    matches!((rd32(sec), rd32(sec + 4)), (Some(off), Some(len)) if off != 0 && len > 0)
}

/// Stream a URL into memory, failing if the connection stalls for 30 s
/// (a dead connection otherwise hangs forever with no error).
async fn download(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder().connect_timeout(Duration::from_secs(20)).build()?;
    let mut resp = tokio::time::timeout(Duration::from_secs(30), client.get(url).send())
        .await
        .context("no response within 30 s")??
        .error_for_status()?;
    let total = resp.content_length().unwrap_or(0);
    let mut out = Vec::with_capacity(total as usize);
    let mut next_report = 0u64;
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(30), resp.chunk())
        .await
        .context("download stalled for 30 s")??
    {
        out.extend_from_slice(&chunk);
        if total > 0 && out.len() as u64 >= next_report {
            println!("[connect] installer {}/{} MB", out.len() >> 20, total >> 20);
            next_report += total / 10;
        }
    }
    if total > 0 && out.len() as u64 != total {
        bail!("got {} of {total} bytes", out.len());
    }
    Ok(out)
}

/// Download Ubisoft's installer and install Connect into the prefix, silently.
pub async fn setup() -> Result<()> {
    let prefix = prefix()?;
    if let Some(exe) = connect_exe(&prefix) {
        println!("[connect] already installed: {}", exe.display());
        return Ok(());
    }
    std::fs::create_dir_all(&prefix)?;
    let cache = config::data_dir()?.join("cache");
    std::fs::create_dir_all(&cache)?;
    let installer = cache.join("UbisoftConnectInstaller.exe");

    // Reuse a cached copy from an earlier attempt (the installer is ~260 MB).
    let cached = std::fs::read(&installer).ok().filter(|b| has_signature(b));
    let bytes = match cached {
        Some(b) => {
            println!("[connect] using the cached installer");
            b
        }
        None => {
            let mut last = None;
            let mut got = None;
            for attempt in 1..=3 {
                println!("[connect] downloading the official installer from Ubisoft (attempt {attempt})...");
                match download(INSTALLER_URL).await {
                    Ok(b) => {
                        got = Some(b);
                        break;
                    }
                    Err(e) => {
                        eprintln!("[connect] download failed: {e:#}");
                        last = Some(e);
                    }
                }
            }
            let b = got.ok_or_else(|| last.unwrap_or_else(|| anyhow!("download failed")))?;
            if !has_signature(&b) {
                bail!("the downloaded installer is not a signed Windows executable; refusing to run it");
            }
            b
        }
    };
    let sha1 = {
        use sha1::{Digest, Sha1};
        Sha1::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    std::fs::write(&installer, &bytes)?;
    ensure_winetricks(&prefix);
    write_settings(&prefix)?;
    println!("[connect] installer: {} bytes, sha1 {sha1}", bytes.len());

    println!("[connect] installing Ubisoft Connect into {} (silent; first run sets up the prefix)...", prefix.display());
    let mut child = wine(&prefix)?
        .arg(&installer)
        .arg("/S")
        .current_dir(&cache)
        .spawn()
        .context("running the Connect installer")?;
    // The installer may start Connect when it finishes, and umu-run then waits
    // on that window forever. Treat "client present and installer gone" as done.
    let deadline = Instant::now() + Duration::from_secs(30 * 60);
    let mut done_since: Option<Instant> = None;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() && connect_exe(&prefix).is_none() {
                bail!("the Connect installer exited with {status}");
            }
            break;
        }
        if connect_exe(&prefix).is_some() && !process_running("UbisoftConnectInstaller.exe") {
            if done_since.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(15) {
                break;
            }
        } else {
            done_since = None;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!("the Connect installer did not finish within 30 minutes");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let exe = connect_exe(&prefix).ok_or_else(|| anyhow!("the installer finished but UbisoftConnect.exe is missing"))?;
    stop(&prefix);
    let _ = child.kill();
    let _ = child.wait();
    println!("[connect] installed: {}", exe.display());
    println!("[connect] next: `optima-cli connect open` and sign in once inside Ubisoft Connect.");
    Ok(())
}

/// Start the Connect window (for the one-time sign-in, or to look around) and
/// wait until it is closed.
pub fn open() -> Result<()> {
    let prefix = prefix()?;
    let exe = connect_exe(&prefix).ok_or_else(|| anyhow!("Connect is not installed; run `optima-cli connect setup`"))?;
    println!("[connect] opening Ubisoft Connect; close it when you're done.");
    let mut child = wine(&prefix)?.arg(&exe).current_dir(launcher_dir(&prefix)).spawn()?;
    // UbisoftConnect.exe hands off to upc.exe and returns, so wait on upc.exe.
    let started = wait_for(|| process_running("upc.exe"), Duration::from_secs(120));
    if started {
        while process_running("upc.exe") {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    if has_login(&prefix) {
        println!("[connect] Connect has a remembered login.");
    } else {
        println!("[connect] no remembered login yet; sign in (and tick remember me) next time.");
    }
    Ok(())
}

/// Connect's processes. It can linger after a game (Heroic sees the same and
/// uses `pkill -f Ubisoft -9`), which would keep Steam showing "Playing".
const CONNECT_IMAGES: &[&str] = &["upc.exe", "UbisoftConnect.exe", "UplayWebCore.exe", "UplayService.exe", "UbisoftGameLauncher.exe", "UbisoftGameLauncher64.exe", "UplayCrashReporter.exe"];

/// Make Connect quit: politely through Wine first, then kill what is left.
pub fn stop(prefix: &Path) {
    if !CONNECT_IMAGES.iter().any(|i| process_running(i)) {
        return;
    }
    // A polite close first (WM_CLOSE; settings.yaml makes close mean quit).
    // Connect rewrites its saved login while running, and a hard kill at the
    // wrong moment has signed it out.
    let all_gone = || !CONNECT_IMAGES.iter().any(|i| process_running(i));
    for force in [false, true] {
        if let Ok(mut c) = wine(prefix) {
            c.args(["taskkill", "/IM", "upc.exe"]);
            if force {
                c.arg("/F");
            }
            let _ = c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
        }
        if wait_for(all_gone, Duration::from_secs(if force { 8 } else { 20 })) {
            return;
        }
    }
    for image in CONNECT_IMAGES {
        for pid in pids_of(image) {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
    }
}

/// Every Windows process under any Wine shows up in /proc with its exe in the
/// command line. Matching on the image name is enough to follow the game.
fn process_running(image: &str) -> bool {
    !pids_of(image).is_empty()
}

fn pids_of(image: &str) -> Vec<u32> {
    let want = image.to_ascii_lowercase();
    let me = std::process::id();
    let Ok(rd) = std::fs::read_dir("/proc") else { return vec![] };
    rd.flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok())?;
            if pid == me {
                return None;
            }
            let raw = std::fs::read(e.path().join("cmdline")).ok()?;
            // argv[0] only: our own command lines name the exe as an argument.
            let argv0 = raw.split(|&b| b == 0).next().unwrap_or_default();
            let argv0 = String::from_utf8_lossy(argv0).to_ascii_lowercase().replace('\\', "/");
            (argv0.rsplit('/').next() == Some(want.as_str())).then_some(pid)
        })
        .collect()
}

fn wait_for(mut f: impl FnMut() -> bool, timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// Connect's `InstallDir` form: Windows drive path with forward slashes and a
/// trailing slash (`Z:/home/deck/Games/optima/109/`).
fn connect_path(dir: &Path) -> String {
    // Rebuild from components so `a//b/` (GameVault passes a trailing slash)
    // comes out as `a/b`.
    let clean: PathBuf = dir.components().collect();
    let s = clean.to_string_lossy().trim_end_matches('/').to_string();
    format!("Z:{s}/")
}

/// Turn a Connect `InstallDir` back into a host path.
fn host_path(prefix: &Path, win: &str) -> Option<PathBuf> {
    let w = win.replace('\\', "/");
    let w = w.trim_end_matches('/');
    let (drive, rest) = w.split_once(':')?;
    let rest = rest.trim_start_matches('/');
    match drive.to_ascii_lowercase().as_str() {
        "z" => Some(PathBuf::from("/").join(rest)),
        "c" => Some(prefix.join("drive_c").join(rest)),
        _ => None,
    }
}

/// Unescape a quoted value from a Wine `.reg` file.
fn reg_unescape(v: &str) -> String {
    let mut out = String::new();
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Read every `Launcher\Installs\<id>\InstallDir` straight from the prefix's
/// `system.reg`, so checking registrations costs no Proton spin-up.
pub fn registrations(prefix: &Path) -> Vec<(u32, String)> {
    let Ok(text) = std::fs::read_to_string(prefix.join("system.reg")) else { return vec![] };
    parse_registrations(&text)
}

fn parse_registrations(text: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut current: Option<u32> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('[') {
            let key = rest.split(']').next().unwrap_or("").to_ascii_lowercase();
            // Wine keeps the 32-bit view under Wow6432Node; accept either view.
            current = key
                .strip_prefix("software\\\\wow6432node\\\\ubisoft\\\\launcher\\\\installs\\\\")
                .or_else(|| key.strip_prefix("software\\\\ubisoft\\\\launcher\\\\installs\\\\"))
                .and_then(|id| id.parse().ok());
        } else if let (Some(id), Some(v)) = (current, line.strip_prefix("\"InstallDir\"=\"")) {
            let v = v.strip_suffix('"').unwrap_or(v);
            if !out.iter().any(|(i, _)| *i == id) {
                out.push((id, reg_unescape(v)));
            }
        }
    }
    out
}

/// Point Connect at an Optima install of `product_id`. Connect must not be
/// running (it rewrites the registry on exit).
pub fn register(prefix: &Path, product_id: u32, dir: &Path) -> Result<()> {
    if process_running("upc.exe") {
        bail!("Ubisoft Connect is running; close it before registering a game");
    }
    let data = connect_path(dir);
    let mut values: Vec<RegValue> = vec![
        RegValue::sz(&format!("HKLM\\SOFTWARE\\Ubisoft\\Launcher\\Installs\\{product_id}\\InstallDir"), &data),
    ];
    // The keys the game's own installer would set, from the manifest Optima
    // saved: Connect resolves some exe paths through them (Splinter Cell's
    // working_directory is `…\Chaos Theory\InstallDir` + `system`).
    match read_manifest(dir) {
        Ok(m) => values.extend(install_registry(&m, dir)),
        Err(e) => eprintln!("[connect] no install-registry entries ({e:#})"),
    }
    let reg = render_reg(&values);
    let file = prefix.join(format!("optima-register-{product_id}.reg"));
    std::fs::write(&file, reg)?;
    let status = wine(prefix)?
        .arg("regedit")
        .arg("/S")
        .arg(&file)
        .stdout(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        bail!("importing the registry for {product_id} failed ({status})");
    }
    println!("[connect] registered product {product_id} at {data} ({} registry values)", values.len());
    // Old installers also imported .reg files the game ships (BG&E's
    // support/settings.reg holds the settings it refuses to start without).
    // Once per product: these are defaults, and re-importing after an update
    // would undo what the player chose in the settings app.
    let seeded = prefix.join(format!(".optima-regseed-{product_id}"));
    if !seeded.exists() {
        for seed in shipped_reg_files(dir) {
            println!("[connect] importing {}", seed.display());
            let _ = wine(prefix)?.arg("regedit").arg("/S").arg(&seed).stdout(std::process::Stdio::null()).status();
        }
        let _ = std::fs::write(&seeded, "");
    }
    Ok(())
}

/// `.reg` files in the game root or its `support` folder (any case).
fn shipped_reg_files(dir: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![dir.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(dir) {
        dirs.extend(
            rd.flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .filter(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case("support"))
                .map(|e| e.path()),
        );
    }
    let mut out: Vec<PathBuf> = dirs
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flat_map(|rd| rd.flatten().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().map(|x| x.eq_ignore_ascii_case("reg")).unwrap_or(false))
        .collect();
    out.sort();
    out
}

/// One registry value to import. `key` is the full path including the value
/// name, as the manifest gives it.
#[derive(Debug, PartialEq)]
struct RegValue {
    key: String,
    data: RegData,
}

#[derive(Debug, PartialEq)]
enum RegData {
    Sz(String),
    Dword(u32),
}

impl RegValue {
    fn sz(key: &str, v: &str) -> Self {
        RegValue { key: key.to_string(), data: RegData::Sz(v.to_string()) }
    }
}

/// Parse the `uplay_install.manifest` Optima wrote next to the game.
fn read_manifest(dir: &Path) -> Result<crate::proto::download::Manifest> {
    use prost::Message;
    use std::io::Read;
    let raw = std::fs::read(dir.join("uplay_install.manifest")).context("reading uplay_install.manifest")?;
    if raw.len() <= 356 {
        bail!("uplay_install.manifest is too short");
    }
    let mut inflated = Vec::new();
    flate2::read::ZlibDecoder::new(&raw[356..]).read_to_end(&mut inflated)?;
    Ok(crate::proto::download::Manifest::decode(&inflated[..])?)
}

/// The manifest's `installRegistry` entries as values to write: the English
/// variant where there is a choice (matching the state Optima writes), and
/// `$INSTALL_DIR` replaced by the game folder as a Windows path.
fn install_registry(m: &crate::proto::download::Manifest, dir: &Path) -> Vec<RegValue> {
    let clean: PathBuf = dir.components().collect();
    let win_dir = format!("Z:{}", clean.to_string_lossy().replace('/', "\\"));
    let pick = |langs: Vec<Option<&str>>| -> Option<usize> {
        let at = |want: &str| langs.iter().position(|l| l.map(|l| l.eq_ignore_ascii_case(want)).unwrap_or(false));
        at("en-US").or_else(|| at("")).or_else(|| langs.iter().position(|l| l.is_none())).or(if langs.is_empty() { None } else { Some(0) })
    };
    let mut out = Vec::new();
    for r in &m.install_registry {
        let data = if r.r#type == crate::proto::download::install_registry::ValueType::Number as i32 {
            let langs = r.registry_number_entry.iter().map(|e| e.language.as_deref()).collect();
            pick(langs).map(|i| RegData::Dword(r.registry_number_entry[i].value))
        } else {
            let langs = r.registry_string_entry.iter().map(|e| e.language.as_deref()).collect();
            pick(langs).map(|i| {
                let v = &r.registry_string_entry[i].value;
                RegData::Sz(v.replace("$INSTALL_DIR", &win_dir).replace("$(INSTALL_DIR)", &win_dir))
            })
        };
        if let Some(data) = data {
            out.push(RegValue { key: r.key.clone(), data });
        }
    }
    out
}

/// A REGEDIT4 file. HKLM\SOFTWARE values go to both registry views, since
/// old 32-bit games read the Wow6432Node copy.
fn render_reg(values: &[RegValue]) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::from("REGEDIT4\r\n");
    for v in values {
        let full = v
            .key
            .replacen("HKLM\\", "HKEY_LOCAL_MACHINE\\", 1)
            .replacen("HKCU\\", "HKEY_CURRENT_USER\\", 1);
        let Some((key, name)) = full.rsplit_once('\\') else { continue };
        let mut keys = vec![key.to_string()];
        let upper = key.to_ascii_uppercase();
        if upper.starts_with("HKEY_LOCAL_MACHINE\\SOFTWARE\\") && !upper.contains("WOW6432NODE") {
            keys.push(format!("HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\{}", &key["HKEY_LOCAL_MACHINE\\SOFTWARE\\".len()..]));
        }
        let value = match &v.data {
            RegData::Sz(s) => format!("\"{}\"", esc(s)),
            RegData::Dword(n) => format!("dword:{n:08x}"),
        };
        for k in keys {
            out.push_str(&format!("\r\n[{k}]\r\n\"{}\"={value}\r\n", esc(name)));
        }
    }
    out
}

pub fn status() -> Result<()> {
    let prefix = prefix()?;
    println!("prefix:     {}", prefix.display());
    match connect_exe(&prefix) {
        Some(e) => println!("installed:  yes ({})", e.display()),
        None => {
            println!("installed:  no  (run `optima-cli connect setup`)");
            return Ok(());
        }
    }
    println!(
        "signed in:  {}",
        if has_login(&prefix) { "yes (remembered login on disk)" } else { "no  (run `optima-cli connect open` and sign in)" }
    );
    println!("running:    {}", if process_running("upc.exe") { "yes" } else { "no" });
    let regs = registrations(&prefix);
    if regs.is_empty() {
        println!("games:      none registered");
    }
    for (id, dir) in regs {
        let host = host_path(&prefix, &dir);
        let state = host
            .as_ref()
            .map(|h| {
                if h.join("uplay_install.state").exists() {
                    "installed (Connect state present)"
                } else if h.join("uplay_download").join(id.to_string()).exists() {
                    "download staged"
                } else if h.exists() {
                    "registered (no Connect state yet)"
                } else {
                    "folder missing"
                }
            })
            .unwrap_or("unknown path");
        println!("game {id:>6}: {dir}  [{state}]");
    }
    Ok(())
}

/// Make sure Connect knows this install: the Installs key plus the manifest's
/// install registry and shipped .reg files, on first use and again whenever
/// the install changes. A registration Connect made for a folder of its own
/// is left alone.
pub fn ensure_registered(prefix: &Path, product_id: u32, dir: &Path) -> Result<()> {
    let want = connect_path(dir);
    let normalize = |s: &str| {
        let s = s.replace('\\', "/");
        let mut out = String::new();
        for c in s.chars() {
            if !(c == '/' && out.ends_with('/')) {
                out.push(c);
            }
        }
        out.to_ascii_lowercase()
    };
    let marker = prefix.join(format!(".optima-reg-{product_id}"));
    let stamp = std::fs::metadata(dir.join("uplay_install.manifest"))
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (m.len(), t)))
        .map(|(len, t)| format!("{want}|{len}|{:?}", t))
        .unwrap_or_else(|| want.clone());
    match registrations(&prefix).into_iter().find(|(id, _)| *id == product_id) {
        Some((_, have)) if normalize(&have) != normalize(&want) => {
            println!("[connect] Connect has product {product_id} at {have}; launching that")
        }
        _ if std::fs::read_to_string(&marker).ok().as_deref() == Some(stamp.as_str()) => {}
        _ => {
            if process_running("upc.exe") {
                stop(&prefix);
                wait_for(|| !process_running("upc.exe"), Duration::from_secs(20));
            }
            register(&prefix, product_id, dir)?;
            let _ = std::fs::write(&marker, &stamp);
        }
    }
    Ok(())
}

/// Run one of the game's own tools (its settings app) directly in the Connect
/// prefix, so what it writes is what the game reads when Connect starts it.
/// Connect itself isn't needed for these.
pub fn run_tool(product_id: u32, dir: &Path, exe: &Path) -> Result<()> {
    let prefix = prefix()?;
    if connect_exe(&prefix).is_none() {
        bail!("Ubisoft Connect is not installed; launch a game once (or `optima-cli connect setup`) first");
    }
    ensure_registered(&prefix, product_id, dir)?;
    let cwd = exe.parent().unwrap_or(dir);
    println!("[settings] launching {} in the Connect prefix...", exe.display());
    let status = wine(&prefix)?.arg(exe).current_dir(cwd).status().context("starting the settings app")?;
    if !status.success() {
        bail!("the settings app exited with {status}");
    }
    Ok(())
}

/// Launch through Connect and stay alive until the game exits, so whatever
/// started Optima (Steam via GameVault) sees the game's real lifetime.
pub fn launch_game(product_id: u32, dir: &Path, exe: &Path) -> Result<()> {
    let prefix = prefix()?;
    let client = connect_exe(&prefix).ok_or_else(|| {
        anyhow!("Ubisoft Connect is not installed; run `optima-cli connect setup`, then `connect open` to sign in")
    })?;
    if !has_login(&prefix) {
        // Connect shows its own sign-in first and then carries on to the game.
        println!("[connect] Connect isn't signed in yet; sign in when it asks (tick remember me)");
    }
    let image = exe
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .ok_or_else(|| anyhow!("no exe name"))?;

    ensure_registered(&prefix, product_id, dir)?;

    if std::env::var_os("OPTIMA_NO_RUN").is_some() {
        println!("[connect] would run: {} uplay://launch/{product_id}/0 (waiting for {image})", client.display());
        return Ok(());
    }

    let uri = format!("uplay://launch/{product_id}/0");
    println!("[connect] starting {image} through Ubisoft Connect ({uri})...");
    let mut child: Child = wine(&prefix)?
        .arg(&client)
        .arg(&uri)
        .current_dir(launcher_dir(&prefix))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("starting Ubisoft Connect")?;

    // Connect may verify files, show an EULA or a sign-in first, so allow time.
    let timeout = std::env::var("OPTIMA_CONNECT_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1800u64);
    let started = wait_for(|| process_running(&image), Duration::from_secs(timeout));
    if !started {
        let _ = child.kill();
        let _ = child.wait();
        bail!(
            "{image} did not start within {timeout}s; Connect was left open so you can see why \
             (it may want a sign-in, an update, or to verify/download the game)"
        );
    }
    println!("[connect] {image} is running");
    // Follow the game; a short gap covers launchers that restart themselves.
    let mut gone_since: Option<Instant> = None;
    loop {
        std::thread::sleep(Duration::from_secs(2));
        if process_running(&image) {
            gone_since = None;
        } else if gone_since.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(8) {
            break;
        }
    }
    println!("[connect] game exited; closing Ubisoft Connect");
    stop(&prefix);
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

/// Fallback when Connect will not accept a registered folder: start its own
/// download (`connect install`), pause it, quit Connect, then fill its staging
/// folder from the Optima install with hard links (no extra space, no
/// re-download). Opening Connect afterwards lets it verify and finish.
pub fn seed(product_id: u32, source: &Path) -> Result<()> {
    let prefix = prefix()?;
    if process_running("upc.exe") {
        bail!("Ubisoft Connect is running; pause the download and quit Connect first");
    }
    let (_, win) = registrations(&prefix)
        .into_iter()
        .find(|(id, _)| *id == product_id)
        .ok_or_else(|| anyhow!("Connect has no registration for {product_id}; start its download with `optima-cli connect install {product_id}` first"))?;
    let target = host_path(&prefix, &win).ok_or_else(|| anyhow!("can't map Connect's path {win}"))?;
    let staging = target.join("uplay_download").join(product_id.to_string());
    if !staging.is_dir() || !target.join("uplay_install.state").exists() {
        bail!(
            "Connect's download for {product_id} hasn't started at {}; let it begin, pause it, quit Connect, then retry",
            target.display()
        );
    }
    let source = source.canonicalize()?;
    let (mut linked, mut copied, mut same) = (0u64, 0u64, 0u64);
    for entry in walk(&source)? {
        let rel = entry.strip_prefix(&source)?;
        // Never seed Optima's own bookkeeping or anything Connect owns.
        let first = rel.components().next().map(|c| c.as_os_str().to_string_lossy().to_string()).unwrap_or_default();
        if first.starts_with(".optima") || first.starts_with("uplay_") {
            continue;
        }
        let dst = staging.join(rel);
        if std::fs::symlink_metadata(&dst).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            bail!("refusing symlink in Connect staging: {}", dst.display());
        }
        if let (Ok(a), Ok(b)) = (std::fs::metadata(&entry), std::fs::metadata(&dst)) {
            if a.len() == b.len() && files_equal(&entry, &dst)? {
                same += 1;
                continue;
            }
        }
        if let Some(p) = dst.parent() {
            std::fs::create_dir_all(p)?;
        }
        let tmp = dst.with_extension("optima-seed");
        let _ = std::fs::remove_file(&tmp);
        if std::fs::hard_link(&entry, &tmp).is_ok() {
            linked += 1;
        } else {
            std::fs::copy(&entry, &tmp)?;
            copied += 1;
        }
        std::fs::rename(&tmp, &dst)?;
    }
    println!(
        "[connect] seeded {}: {linked} linked, {copied} copied, {same} already matched",
        staging.display()
    );
    println!("[connect] now `optima-cli connect open` and resume the download; Connect verifies and finishes it.");
    Ok(())
}

fn walk(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
            let e = e?;
            let t = e.file_type()?;
            if t.is_dir() {
                stack.push(e.path());
            } else if t.is_file() {
                out.push(e.path());
            }
        }
    }
    Ok(out)
}

fn files_equal(a: &Path, b: &Path) -> Result<bool> {
    use std::io::Read;
    let (mut fa, mut fb) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let na = fa.read(&mut ba)?;
        let mut nb = 0;
        while nb < na {
            let n = fb.read(&mut bb[nb..na])?;
            if n == 0 {
                return Ok(false);
            }
            nb += n;
        }
        if na == 0 {
            return Ok(fb.read(&mut bb[..1])? == 0);
        }
        if ba[..na] != bb[..na] {
            return Ok(false);
        }
    }
}

/// Open Connect's own install dialog for a product (`uplay://install/<id>`),
/// the first step of the seed fallback.
pub fn install_dialog(product_id: u32) -> Result<()> {
    let prefix = prefix()?;
    let exe = connect_exe(&prefix).ok_or_else(|| anyhow!("Connect is not installed; run `optima-cli connect setup`"))?;
    println!("[connect] opening Connect's install dialog for {product_id}. Start the download, let it begin,");
    println!("          pause it, quit Connect, then run `optima-cli connect seed {product_id}`.");
    let mut child = wine(&prefix)?
        .arg(&exe)
        .arg(format!("uplay://install/{product_id}"))
        .current_dir(launcher_dir(&prefix))
        .spawn()?;
    if wait_for(|| process_running("upc.exe"), Duration::from_secs(120)) {
        while process_running("upc.exe") {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_round_trip() {
        let p = Path::new("/home/deck/Games/optima/109");
        assert_eq!(connect_path(p), "Z:/home/deck/Games/optima/109/");
        assert_eq!(connect_path(Path::new("/home/deck/Games/optima//109/")), "Z:/home/deck/Games/optima/109/");
        assert_eq!(host_path(Path::new("/pfx"), "Z:/home/deck/Games/optima/109/").unwrap(), p);
        assert_eq!(
            host_path(Path::new("/pfx"), "C:/Program Files (x86)/Ubisoft/games/X/").unwrap(),
            Path::new("/pfx/drive_c/Program Files (x86)/Ubisoft/games/X")
        );
    }

    #[test]
    fn manifest_registry_becomes_reg_values() {
        use crate::proto::download::{install_registry::ValueType, InstallRegistry, Manifest, RegistryNumberEntry, RegistryStringEntry};
        let s = |v: &str, l: &str| RegistryStringEntry { value: v.into(), language: Some(l.into()) };
        let m = Manifest {
            install_registry: vec![
                InstallRegistry {
                    key: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Ubisoft\\SC\\InstallDir".into(),
                    r#type: ValueType::String as i32,
                    registry_string_entry: vec![s("$INSTALL_DIR", "")],
                    registry_number_entry: vec![],
                },
                InstallRegistry {
                    key: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Ubisoft\\SC\\Language".into(),
                    r#type: ValueType::String as i32,
                    registry_string_entry: vec![s("frenchuk", "fr-FR"), s("englishuk", "en-US")],
                    registry_number_entry: vec![],
                },
                InstallRegistry {
                    key: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Ubisoft\\BGE\\InstallLanguage".into(),
                    r#type: ValueType::Number as i32,
                    registry_string_entry: vec![],
                    registry_number_entry: vec![
                        RegistryNumberEntry { value: 0, language: Some("fr-FR".into()) },
                        RegistryNumberEntry { value: 1, language: Some("en-US".into()) },
                    ],
                },
            ],
            ..Default::default()
        };
        let v = install_registry(&m, Path::new("/home/deck/Games/optima//95/"));
        assert_eq!(v[0].data, RegData::Sz("Z:\\home\\deck\\Games\\optima\\95".into()));
        assert_eq!(v[1].data, RegData::Sz("englishuk".into()));
        assert_eq!(v[2].data, RegData::Dword(1));
        let reg = render_reg(&v);
        assert!(reg.starts_with("REGEDIT4\r\n"));
        assert!(reg.contains("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Ubisoft\\SC]\r\n\"InstallDir\"=\"Z:\\\\home\\\\deck\\\\Games\\\\optima\\\\95\"\r\n"));
        assert!(reg.contains("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Ubisoft\\SC]"));
        assert!(reg.contains("\"InstallLanguage\"=dword:00000001"));
    }

    #[test]
    fn reads_registrations_from_system_reg() {
        let reg = "WINE REGISTRY Version 2\n\
            [Software\\\\Wow6432Node\\\\Ubisoft\\\\Launcher\\\\Installs\\\\109] 1700000000\n\
            #time=1\n\
            \"InstallDir\"=\"Z:/home/deck/Games/optima/109/\"\n\
            \n\
            [Software\\\\Wow6432Node\\\\Ubisoft\\\\Launcher] 1700000000\n\
            \"InstallDir\"=\"C:\\\\Program Files (x86)\\\\Ubisoft\\\\Ubisoft Game Launcher\\\\\"\n";
        assert_eq!(parse_registrations(reg), vec![(109, "Z:/home/deck/Games/optima/109/".to_string())]);
    }

    #[test]
    fn spots_a_certificate_table() {
        // Minimal PE32+ header with a nonzero security directory.
        let mut pe = vec![0u8; 0x200];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let opt = 0x80 + 24;
        pe[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        let sec = opt + 112 + 32;
        assert!(!has_signature(&pe));
        pe[sec..sec + 4].copy_from_slice(&0x100u32.to_le_bytes());
        pe[sec + 4..sec + 8].copy_from_slice(&0x40u32.to_le_bytes());
        assert!(has_signature(&pe));
    }
}
