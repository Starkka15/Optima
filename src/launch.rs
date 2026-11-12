// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Starkka15

//! What Optima still puts in a game folder, now that the official Ubisoft
//! Connect client launches every game (see `connect.rs`):
//!
//! - the EAX shim, an audio fix for old titles that demand Creative EAX
//!   (Beyond Good & Evil, Splinter Cell), placed for one run and taken out after;
//! - a one-time cleanup of what older Optima builds left behind: their own
//!   Uplay/Orbit loader DLLs and the ticket-bearing Uplay.ini/Uplay.toml/
//!   Orbit.toml, with the game's own DLLs put back from `.orig`.
//!
//! Plus the Proton runtime lookup shared with `connect.rs`.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

/// The public half of the certificate older Optima builds signed their shim
/// DLLs with. Every one of those DLLs carries its DER, and no Ubisoft or
/// Creative DLL does, so it identifies them for cleanup. Nothing is trusted
/// or imported with it any more.
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

/// Drop our EAX shim next to the exe if the exe needs EAX. A real (Creative)
/// eax.dll cannot work under Proton anyway; it is set aside and put back after
/// the game exits.
pub fn deploy_eax(dep: &mut Deployment, dir: &Path, exe: &Path) -> Result<()> {
    if !needs_eax(exe) {
        return Ok(());
    }
    let dst = dir.join("eax.dll");
    dep.place(&dst, EAX_STUB_32, is_signed_by_us)?;
    println!("[launch] deployed EAX shim → {}", dst.display());
    Ok(())
}

const DEPLOY_RECORD: &str = ".optima-deploy.json";

fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// A DLL Optima shipped (the EAX shim, or an old Uplay/Orbit shim).
fn is_signed_by_us(bytes: &[u8]) -> bool {
    contains(bytes, SIGNING_CERT)
}

/// The emu configs older builds wrote; they carry the account ticket.
fn is_our_config(name: &str, bytes: &[u8]) -> bool {
    match name.to_ascii_lowercase().as_str() {
        "uplay.ini" => contains(bytes, b"TickedId="),
        "uplay.toml" => contains(bytes, b"[Uplay.Profile]"),
        "orbit.toml" => contains(bytes, b"[Orbit.Profile]"),
        _ => false,
    }
}

/// DLL names the old shims were deployed under.
const OLD_SHIM_NAMES: &[&str] = &[
    "uplay_r1_loader.dll",
    "uplay_r1_loader64.dll",
    "ubiorbitapi_r1_loader64.dll",
    "ubiorbitapi_r2_loader.dll",
    "upc_r1_loader.dll",
    "upc_r1_loader64.dll",
    "eax.dll",
];

/// Undo what older Optima builds left in a game folder (top level and two
/// levels down, where exes live: `bin/`, `System/`). The game's own DLLs come
/// back from `.orig`; our DLLs and configs go. Anything not provably ours is
/// left alone. Returns how many files changed.
pub fn clean_legacy_shims(install_dir: &Path) -> usize {
    let mut dirs = vec![install_dir.to_path_buf()];
    let mut i = 0;
    while i < dirs.len() {
        let depth = dirs[i].strip_prefix(install_dir).map(|r| r.components().count()).unwrap_or(9);
        if depth < 2 {
            if let Ok(rd) = std::fs::read_dir(&dirs[i]) {
                let subs: Vec<PathBuf> = rd
                    .flatten()
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .map(|e| e.path())
                    .collect();
                dirs.extend(subs);
            }
        }
        i += 1;
    }
    let mut changed = 0;
    for dir in &dirs {
        for name in OLD_SHIM_NAMES {
            let path = dir.join(name);
            let orig = dir.join(format!("{name}.orig"));
            let ours = std::fs::read(&path).map(|b| is_signed_by_us(&b));
            match (ours, orig.exists()) {
                // Our shim over the game's DLL: put the game's back.
                (Ok(true), true) | (Err(_), true) => {
                    let _ = std::fs::remove_file(&path);
                    if std::fs::rename(&orig, &path).is_ok() {
                        changed += 1;
                    }
                }
                // Our shim where the game had none.
                (Ok(true), false) => {
                    if std::fs::remove_file(&path).is_ok() {
                        changed += 1;
                    }
                }
                _ => {}
            }
        }
        for name in ["Uplay.ini", "Uplay.toml", "Orbit.toml"] {
            let path = dir.join(name);
            if let Ok(b) = std::fs::read(&path) {
                if is_our_config(name, &b) && std::fs::remove_file(&path).is_ok() {
                    changed += 1;
                }
            }
        }
    }
    if changed > 0 {
        println!("[launch] removed {changed} file(s) an older Optima left in {}", install_dir.display());
    }
    changed
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Deployed {
    path: PathBuf,
    sha1: String,
    backup: Option<PathBuf>,
}

/// Files Optima put into a game folder for one launch, so they can all be taken
/// out again and whatever they replaced comes back. The list is kept on disk as
/// it grows, so a run that crashed or was killed gets cleaned up at the start
/// of the next one.
#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct Deployment {
    #[serde(skip)]
    record: PathBuf,
    entries: Vec<Deployed>,
}

impl Deployment {
    pub fn begin(install_dir: &Path) -> Self {
        let record = install_dir.join(DEPLOY_RECORD);
        if let Ok(text) = std::fs::read_to_string(&record) {
            match serde_json::from_str::<Deployment>(&text) {
                Ok(mut old) => {
                    println!("[launch] undoing the files a previous run left in place");
                    old.record = record.clone();
                    old.restore();
                }
                Err(_) => {
                    let _ = std::fs::remove_file(&record);
                }
            }
        }
        Self { record, entries: Vec::new() }
    }

    /// Write `bytes` to `path`. A file already there that `ours` does not
    /// recognise belongs to the game: it moves to `<name>.orig` (replacing a
    /// stale backup, since the file on disk is the newer one) and comes back
    /// in `restore`.
    pub fn place(&mut self, path: &Path, bytes: &[u8], ours: fn(&[u8]) -> bool) -> Result<()> {
        let mut bak = path.as_os_str().to_owned();
        bak.push(".orig");
        let bak = PathBuf::from(bak);
        if let Ok(existing) = std::fs::read(path) {
            if !ours(&existing) {
                if bak.exists() {
                    std::fs::remove_file(&bak).with_context(|| format!("replacing {}", bak.display()))?;
                }
                std::fs::rename(path, &bak).with_context(|| format!("backing up {}", path.display()))?;
            }
        }
        std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
        self.entries.retain(|e| e.path != path);
        self.entries.push(Deployed {
            path: path.to_path_buf(),
            sha1: sha1_hex(bytes),
            backup: bak.exists().then_some(bak),
        });
        self.save()
    }

    fn save(&self) -> Result<()> {
        let tmp = self.record.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.record).with_context(|| format!("saving {}", self.record.display()))
    }

    /// Take out what `place` put in and put back what it set aside. A file that
    /// changed since (a game update replaced the DLL, say) is left alone.
    pub fn restore(self) {
        for e in self.entries.iter().rev() {
            match std::fs::read(&e.path) {
                Ok(cur) if sha1_hex(&cur) == e.sha1 => {
                    if let Err(err) = std::fs::remove_file(&e.path) {
                        eprintln!("[launch] could not remove {}: {err}", e.path.display());
                        continue;
                    }
                }
                Ok(_) => {
                    eprintln!("[launch] {} changed since launch; leaving it in place", e.path.display());
                    continue;
                }
                Err(_) => {}
            }
            if let Some(b) = &e.backup {
                if b.exists() && !e.path.exists() {
                    if let Err(err) = std::fs::rename(b, &e.path) {
                        eprintln!("[launch] could not restore {}: {err}", e.path.display());
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&self.record);
    }
}

/// Case-insensitive substring search over raw bytes.
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let lower = |b: u8| b.to_ascii_lowercase();
    (0..=hay.len() - needle.len())
        .find(|&i| hay[i..i + needle.len()].iter().zip(needle).all(|(a, b)| lower(*a) == lower(*b)))
}

/// Locate maxima's bundled umu + Proton (already installed on this system and on
/// the Ally), falling back to a system `umu-run` / `PROTONPATH`.
pub(crate) fn resolve_runtime() -> Result<(PathBuf, Option<PathBuf>)> {
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
    // usual Steam/umu install dirs). Default stays on Maxima's bundle.
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

/// Names of inherited environment variables that must not reach a child.
///
/// Anything `UBI_*` in our environment is meaningful to Ubisoft code: the real
/// Connect client and the games both read them, so leaking ours into a Wine or
/// Proton child lets the game see state it should not, and can make a title
/// behave differently depending on how Optima happened to be started.
fn ubi_vars_to_strip<I: IntoIterator<Item = String>>(names: I) -> Vec<String> {
    names
        .into_iter()
        .filter(|n| n.to_ascii_uppercase().starts_with("UBI"))
        .collect()
}

/// Remove every inherited `UBI_*` variable from a child's environment.
pub(crate) fn scrub_ubi_env(cmd: &mut std::process::Command) {
    for name in ubi_vars_to_strip(std::env::vars().map(|(k, _)| k)) {
        cmd.env_remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::{clean_legacy_shims, is_signed_by_us, ubi_vars_to_strip, Deployment, EAX_STUB_32, SIGNING_CERT};

    #[test]
    fn strips_ubi_vars_case_insensitively() {
        let env = vec![
            "UBI_TOKEN".to_string(),
            "ubi_session".to_string(),
            "UbiServicesUrl".to_string(),
            "UBISOFT_HOME".to_string(),
            "PATH".to_string(),
            "WINEPREFIX".to_string(),
            "GAMEID".to_string(),
            "SUBIDENTITY".to_string(), // contains "ubi" but does not start with it
        ];
        let mut got = ubi_vars_to_strip(env);
        got.sort();
        assert_eq!(
            got,
            vec![
                "UBISOFT_HOME".to_string(),
                "UBI_TOKEN".to_string(),
                "UbiServicesUrl".to_string(),
                "ubi_session".to_string(),
            ]
        );
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("optima-launch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Something that looks like an old shim: any bytes carrying our cert.
    fn old_shim() -> Vec<u8> {
        let mut v = b"MZ old optima shim ".to_vec();
        v.extend_from_slice(SIGNING_CERT);
        v
    }

    #[test]
    fn the_eax_shim_is_recognised_and_real_dlls_are_not() {
        assert!(is_signed_by_us(EAX_STUB_32));
        assert!(!is_signed_by_us(b"MZ a real creative eax.dll"));
    }

    #[test]
    fn eax_comes_out_and_the_games_copy_comes_back() {
        let dir = scratch("eax");
        let dll = dir.join("eax.dll");
        std::fs::write(&dll, b"REAL CREATIVE EAX").unwrap();
        let mut dep = Deployment::begin(&dir);
        dep.place(&dll, EAX_STUB_32, is_signed_by_us).unwrap();
        assert_eq!(std::fs::read(&dll).unwrap(), EAX_STUB_32);
        dep.restore();
        assert_eq!(std::fs::read(&dll).unwrap(), b"REAL CREATIVE EAX");
        assert!(!dir.join("eax.dll.orig").exists());
        assert!(!dir.join(".optima-deploy.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_killed_run_is_cleaned_up_by_the_next_one() {
        let dir = scratch("killed");
        let dll = dir.join("eax.dll");
        std::fs::write(&dll, b"REAL").unwrap();
        let mut dep = Deployment::begin(&dir);
        dep.place(&dll, EAX_STUB_32, is_signed_by_us).unwrap();
        std::mem::forget(dep); // the process died here
        let _next = Deployment::begin(&dir);
        assert_eq!(std::fs::read(&dll).unwrap(), b"REAL");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_replaced_during_the_run_is_left_alone() {
        let dir = scratch("updated");
        let dll = dir.join("eax.dll");
        std::fs::write(&dll, b"OLD REAL").unwrap();
        let mut dep = Deployment::begin(&dir);
        dep.place(&dll, EAX_STUB_32, is_signed_by_us).unwrap();
        std::fs::write(&dll, b"PATCHED BY THE GAME").unwrap();
        dep.restore();
        assert_eq!(std::fs::read(&dll).unwrap(), b"PATCHED BY THE GAME");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leftovers_from_old_builds_are_cleaned_and_game_files_kept() {
        let dir = scratch("legacy");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        // Shim over a real DLL, a shim where the game had none, and configs.
        std::fs::write(dir.join("uplay_r1_loader.dll"), old_shim()).unwrap();
        std::fs::write(dir.join("uplay_r1_loader.dll.orig"), b"REAL R1").unwrap();
        std::fs::write(dir.join("uplay_r1_loader64.dll"), old_shim()).unwrap();
        std::fs::write(dir.join("Uplay.ini"), b"[Uplay]\r\nTickedId=SECRET\r\n").unwrap();
        std::fs::write(bin.join("Uplay.toml"), b"[Uplay.Profile]\nTicket = \"x\"\n").unwrap();
        std::fs::write(bin.join("uplay_r1_loader64.dll.orig"), b"REAL 64").unwrap();
        std::fs::write(bin.join("uplay_r1_loader64.dll"), old_shim()).unwrap();
        // Game files that must survive: a real loader and a game's own ini.
        std::fs::write(bin.join("upc_r1_loader.dll"), b"REAL UPC").unwrap();
        std::fs::write(bin.join("Orbit.toml"), b"[Something]\n").unwrap();

        assert_eq!(clean_legacy_shims(&dir), 5);
        assert_eq!(std::fs::read(dir.join("uplay_r1_loader.dll")).unwrap(), b"REAL R1");
        assert!(!dir.join("uplay_r1_loader64.dll").exists());
        assert!(!dir.join("Uplay.ini").exists());
        assert!(!bin.join("Uplay.toml").exists());
        assert_eq!(std::fs::read(bin.join("uplay_r1_loader64.dll")).unwrap(), b"REAL 64");
        assert_eq!(std::fs::read(bin.join("upc_r1_loader.dll")).unwrap(), b"REAL UPC");
        assert!(bin.join("Orbit.toml").exists());
        assert_eq!(clean_legacy_shims(&dir), 0, "a second pass finds nothing");
        std::fs::remove_dir_all(&dir).ok();
    }
}
