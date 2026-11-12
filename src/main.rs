// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Starkka15

//! Optima — an ownership-backed Ubisoft Connect client (maxima-cli style).
//!
//! P0 (this build): UbiServices authentication. `login` stores a session ticket;
//! `whoami` live-verifies it against the profile endpoint; `refresh` renews it
//! from the rememberMe ticket. Later phases: Demux `ownership_service` (list
//! owned games), CDN install, and the Uplay R1/R2 DRM handshake under Proton.

mod auth;
mod browser_login;
mod config;
mod connect;
mod steam_login;
mod demux;
mod install;
mod launch;
mod proto;

use anyhow::{Context, Result};
use auth::LoginOutcome;
use clap::{Parser, Subcommand};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "optima-cli", version, about = "Ownership-backed Ubisoft Connect client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Log into your Ubisoft account and store the session.
    Login {
        /// Account email (prompted if omitted).
        #[arg(long)]
        email: Option<String>,
        /// Account password (prompted, hidden, if omitted). Prefer the prompt —
        /// a flag lands in your shell history.
        #[arg(long)]
        password: Option<String>,
        /// BOOTSTRAP: store a ubi_v1 ticket captured from a real browser
        /// session (devtools → any request to public-ubiservices.ubi.com →
        /// Authorization header → the part after `ubi_v1 t=`). Bypasses the
        /// DataDome-walled password endpoint. For machines without Steam; use
        /// --steam where Steam runs. Optionally pair with --session-id.
        #[arg(long)]
        ticket: Option<String>,
        /// Ubi-SessionId that goes with a pasted --ticket (devtools: the
        /// `Ubi-SessionId` request header). Needed for authorized REST calls.
        #[arg(long)]
        session_id: Option<String>,
        /// Sign in on Ubisoft's real login page inside Steam's browser (Game
        /// Mode friendly; needs Steam running with its browser debugger on,
        /// which Decky Loader enables).
        #[arg(long)]
        steam: bool,
    },
    /// List the games your Ubisoft account owns (via the Demux ownership service).
    ListGames {
        /// Emit a JSON array (product_id, name, installable) for the GameVault
        /// extension to parse, instead of the human-readable listing.
        #[arg(long)]
        json: bool,
    },
    /// Download/install an owned game by its product id (see `list-games`).
    Install {
        /// Product id of the game to install.
        product_id: u32,
        /// Install directory (default: ~/Games/optima/<product_id>).
        #[arg(long)]
        path: Option<String>,
        /// Hash-check every file already on disk instead of trusting the
        /// resume state (repairs a damaged install).
        #[arg(long)]
        verify: bool,
        /// Only write Ubisoft Connect's install records (uplay_install.*) into
        /// an existing install, without checking or downloading files.
        #[arg(long)]
        records_only: bool,
    },
    /// Launch an installed, owned game through Ubisoft Connect (installed into
    /// its own prefix on first use; sign in once when it asks).
    Launch {
        /// Product id of the game to launch (see `list-games`).
        product_id: u32,
        /// Install directory (default: ~/Games/optima/<product_id>).
        #[arg(long)]
        path: Option<String>,
        /// Executable to run, relative to the install dir. If omitted, the first
        /// executable from the product configuration is used.
        #[arg(long)]
        exe: Option<String>,
    },
    /// Official Ubisoft Connect mode: install the client in its own prefix,
    /// sign in once, and launch games through it.
    Connect {
        #[command(subcommand)]
        cmd: ConnectCmd,
    },
    /// Launch a game's bundled settings/config application (e.g. Beyond Good &
    /// Evil's SettingsApplication.exe) in the same Proton prefix, so you can change
    /// resolution/graphics. Many old titles boot at a tiny default (BG&E = 640x480)
    /// with no in-game video options — this is the only way to fix it.
    Settings {
        /// Product id of the game (see `list-games`).
        product_id: u32,
        /// Install directory (default: ~/Games/optima/<product_id>).
        #[arg(long)]
        path: Option<String>,
        /// Settings executable, relative to the install dir. If omitted, it's
        /// auto-detected (the config's `internal_name: Settings` exe, else a disk
        /// scan for *settings*/*config*.exe).
        #[arg(long)]
        exe: Option<String>,
    },
    /// Dump the raw product `configuration` YAML for an owned product id
    /// (diagnostic: reveals real title, launch exe, uplay app id, DRM info).
    Config {
        /// Product id (see `list-games --all`).
        product_id: u32,
    },
    /// Show the stored session and live-verify it against UbiServices.
    Whoami,
    /// Renew the stored session from its rememberMe ticket (no password).
    Refresh,
}

#[derive(Subcommand)]
enum ConnectCmd {
    /// Download Ubisoft's installer and install Connect into its own prefix.
    Setup,
    /// Open the Connect window (sign in once here; tick "remember me").
    Open,
    /// Install Connect if needed, open it for sign-in, and close it once the
    /// login is saved (for front ends; does nothing if already signed in).
    Signin,
    /// Show whether Connect is installed and signed in, and its registered games.
    Status,
    /// Point Connect at an Optima install (done automatically on first launch).
    Register {
        product_id: u32,
        /// Install directory (default: ~/Games/optima/<product_id>).
        #[arg(long)]
        path: Option<String>,
    },
    /// Fallback step 1: open Connect's own install dialog for a product.
    Install { product_id: u32 },
    /// Fallback step 2: fill Connect's paused download from the Optima install.
    Seed {
        product_id: u32,
        /// Optima install directory (default: ~/Games/optima/<product_id>).
        #[arg(long)]
        path: Option<String>,
    },
}

fn default_install_dir(product_id: u32, path: Option<String>) -> std::path::PathBuf {
    match path {
        Some(p) => std::path::PathBuf::from(p),
        None => dirs::home_dir()
            .unwrap_or_default()
            .join("Games/optima")
            .join(product_id.to_string()),
    }
}

async fn do_connect(cmd: ConnectCmd) -> Result<()> {
    match cmd {
        ConnectCmd::Setup => connect::setup().await,
        ConnectCmd::Open => connect::open(),
        ConnectCmd::Signin => connect::signin().await,
        ConnectCmd::Status => connect::status(),
        ConnectCmd::Register { product_id, path } => {
            let dir = default_install_dir(product_id, path);
            if !dir.is_dir() {
                anyhow::bail!("{} does not exist", dir.display());
            }
            connect::register(&connect::prefix()?, product_id, &dir)
        }
        ConnectCmd::Install { product_id } => connect::install_dialog(product_id),
        ConnectCmd::Seed { product_id, path } => connect::seed(product_id, &default_install_dir(product_id, path)),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().cmd {
        Cmd::Login { email, password, ticket, session_id, steam } => {
            if steam {
                do_steam_login().await
            } else {
                do_login(email, password, ticket, session_id).await
            }
        }
        Cmd::ListGames { json } => do_list_games(json).await,
        Cmd::Install { product_id, path, verify, records_only } => do_install(product_id, path, verify, records_only).await,
        Cmd::Launch { product_id, path, exe } => do_launch(product_id, path, exe).await,
        Cmd::Connect { cmd } => do_connect(cmd).await,
        Cmd::Settings { product_id, path, exe } => do_settings(product_id, path, exe).await,
        Cmd::Config { product_id } => do_config(product_id).await,
        Cmd::Whoami => do_whoami().await,
        Cmd::Refresh => do_refresh().await,
    }
}

/// `login --steam`: Ubisoft's real login page in Steam's browser.
async fn do_steam_login() -> Result<()> {
    let auth = steam_login::run().await?;
    config::save_auth(&auth)?;
    if auth.name_on_platform.is_empty() {
        println!("Signed in. Run `optima-cli list-games`.");
    } else {
        println!("Signed in as {}. Run `optima-cli list-games`.", auth.name_on_platform);
    }
    Ok(())
}

/// Load the stored ticket, exchange it for a Demux-app ticket (past DataDome),
/// and open an authenticated Demux connection.
/// Load the stored session, silently renewing it with the `rememberMe` ticket if
/// it looks expired. This is the whole point of "log in once": after the first
/// login, a long-idle machine (or the Ally waking days later) refreshes its
/// ticket without a password, browser, or desktop-mode trip.
async fn load_auth_refreshing() -> Result<config::Auth> {
    let Some(mut auth) = config::load_auth()? else {
        anyhow::bail!("Not logged in. Run `optima-cli login`.");
    };
    if auth.ticket.is_empty() {
        anyhow::bail!("no ticket stored; run `optima-cli login`");
    }
    if auth.is_expired() && !auth.remember_me_ticket.is_empty() {
        match auth::refresh(&auth).await {
            Ok(fresh) => {
                config::save_auth(&fresh)?;
                println!("[auth] session expired — auto-refreshed via rememberMe (no re-login).");
                auth = fresh;
            }
            Err(e) => eprintln!("[auth] auto-refresh failed ({e}); trying the stored ticket anyway."),
        }
    }
    Ok(auth)
}

async fn connect_demux() -> Result<(demux::Demux, String)> {
    let mut auth = load_auth_refreshing().await?;
    // The browser ticket is for the web app; Demux wants a launcher-app ticket.
    // If the exchange is rejected (ticket dead despite the expiry heuristic), do a
    // reactive refresh via rememberMe and retry once — still no re-login.
    let demux_ticket = match auth::exchange_for_app(&auth.ticket, auth::DEMUX_APP_ID).await {
        Ok(t) => t,
        Err(e) if !auth.remember_me_ticket.is_empty() => {
            let fresh = auth::refresh(&auth)
                .await
                .with_context(|| format!("ticket exchange failed ({e}); rememberMe refresh also failed"))?;
            config::save_auth(&fresh)?;
            println!("[auth] ticket rejected — auto-refreshed via rememberMe.");
            auth = fresh;
            auth::exchange_for_app(&auth.ticket, auth::DEMUX_APP_ID)
                .await
                .context("exchanging refreshed ticket for a Demux-app ticket")?
        }
        Err(e) => return Err(e).context("exchanging web ticket for a Demux-app ticket"),
    };
    let demux = demux::Demux::connect(&demux_ticket).await?;
    Ok((demux, demux_ticket))
}

/// Rebuild ONLY the demux socket, reusing the app ticket we already exchanged.
/// The Shipyard ticket-exchange (`exchange_for_app`) is per-profile rate limited
/// (429 "Too many calls per profile"), so a mid-install reconnect must NOT call
/// it again — the demux ticket is still valid; only the TCP session dropped.
async fn reconnect_demux(demux_ticket: &str) -> Result<demux::Demux> {
    demux::Demux::connect(demux_ticket).await
}

async fn do_list_games(json: bool) -> Result<()> {
    let (mut demux, _ticket) = connect_demux().await?;
    let games = demux.owned_games().await?;

    // product_type 0 = base Game, 1 = AddOn/DLC, etc. Owned base games are what
    // a library view cares about; the rest is catalog metadata.
    // OPTIMA_ALL=1 shows every catalog entry (DLC, oddly-typed, non-owned) — used
    // to locate games whose base entry is typed unusually.
    let show_all = std::env::var_os("OPTIMA_ALL").is_some();
    let mut owned: Vec<_> = games
        .iter()
        .filter(|g| show_all || (g.owned.unwrap_or(false) && g.product_type.unwrap_or(0) == 0))
        .collect();
    owned.sort_by_key(|g| g.product_id);

    // Resolve installability: a game is installable if it has a manifest in the
    // listing OR one resolves via GetLatestManifests (one batched call for all
    // the ones missing it). Steam-linked / delisted copies resolve to nothing.
    let missing: Vec<u32> = owned
        .iter()
        .filter(|g| g.latest_manifest.as_deref().unwrap_or("").is_empty())
        .map(|g| g.product_id)
        .collect();
    let resolved = demux.get_latest_manifests(&missing).await.unwrap_or_default();

    let installable = |g: &proto::ownership::OwnedGame| -> bool {
        !g.latest_manifest.as_deref().unwrap_or("").is_empty()
            || resolved.contains_key(&g.product_id)
    };

    // OPTIMA_HIDE_UNAVAILABLE=1 drops games with no Ubisoft build (the extension
    // uses this so Steam-linked copies don't clutter the library).
    let hide = std::env::var_os("OPTIMA_HIDE_UNAVAILABLE").is_some();
    let shown: Vec<_> = owned
        .iter()
        .filter(|g| show_all || !hide || installable(g))
        .collect();

    if json {
        // Structured output for the GameVault extension backend. Only games with
        // a real Ubisoft build are useful to a library, so JSON always hides the
        // Steam-linked/delisted ones regardless of OPTIMA_HIDE_UNAVAILABLE.
        let arr: Vec<serde_json::Value> = shown
            .iter()
            .filter(|g| show_all || installable(g))
            .map(|g| {
                let name = g
                    .configuration
                    .as_deref()
                    .and_then(game_name)
                    .unwrap_or_else(|| g.product_id.to_string());
                serde_json::json!({
                    "product_id": g.product_id,
                    "name": name,
                    "installable": installable(g),
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&arr)?);
        return Ok(());
    }

    println!(
        "{} owned games ({} installable, {} total catalog entries):",
        shown.len(),
        owned.iter().filter(|g| installable(g)).count(),
        games.len()
    );
    for g in &shown {
        let name = g
            .configuration
            .as_deref()
            .and_then(game_name)
            .unwrap_or_else(|| "<unknown>".to_string());
        let tag = if installable(g) {
            String::new()
        } else {
            "  [no Ubisoft build — Steam-linked/delisted]".to_string()
        };
        let flags = if show_all {
            format!("  [owned={} type={}]", g.owned.unwrap_or(false), g.product_type.unwrap_or(0))
        } else {
            String::new()
        };
        println!("  {:<45}  (product_id={}){}{}", name, g.product_id, flags, tag);
    }
    Ok(())
}

async fn do_install(product_id: u32, path: Option<String>, verify: bool, records_only: bool) -> Result<()> {
    let (mut demux, mut ticket) = connect_demux().await?;
    let games = demux.owned_games().await?;
    let game = games
        .iter()
        .find(|g| g.product_id == product_id && g.owned.unwrap_or(false))
        .ok_or_else(|| anyhow::anyhow!("product {product_id} is not in your owned games"))?;
    let name = game
        .configuration
        .as_deref()
        .and_then(game_name)
        .unwrap_or_else(|| product_id.to_string());
    let stored_manifest = game.latest_manifest.clone().filter(|m| !m.is_empty());
    // Newer titles omit `latest_manifest` in the listing — fetch it on demand.
    let manifest_id = match stored_manifest {
        Some(m) => m,
        None => demux
            .get_latest_manifest(product_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!(
                "no Ubisoft CDN build for product {product_id} — this copy is Steam-linked \
                 (or delisted); download it through Steam, not Optima"
            ))?,
    };
    let dir = match path {
        Some(p) => std::path::PathBuf::from(p),
        None => dirs::home_dir()
            .unwrap_or_default()
            .join("Games/optima")
            .join(product_id.to_string()),
    };
    // Outer safety net: a demux drop can land anywhere (owned_games, ownership
    // token, manifest sign) — not just the per-file sign loop. Retry the whole
    // install on connection failure; resume skips already-downloaded files, so
    // each attempt makes forward progress.
    let mut attempt = 0;
    loop {
        match install::install_game(&mut demux, &ticket, product_id, &manifest_id, &name, &dir, verify && attempt == 0, records_only).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                // Out of space, not owned, unsupported codec: another run
                // would fail the same way.
                if e.downcast_ref::<install::Fatal>().is_some() {
                    return Err(e);
                }
                attempt += 1;
                if attempt > 30 {
                    return Err(e.context("install failed after 30 whole-run retries"));
                }
                eprintln!("[install] run failed ({e:#}); reconnecting demux and resuming (attempt {attempt})...");
                // Backoff grows with attempts (capped) so a persistent failure
                // doesn't hammer the CDN / trip a 429.
                let backoff = std::cmp::min(3 * attempt as u64, 30);
                tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                // Reuse the already-exchanged ticket: rebuild only the socket.
                // Re-exchange (rate-limited) ONLY if the ticket is genuinely dead.
                match reconnect_demux(&ticket).await {
                    Ok(d) => demux = d,
                    Err(re) => {
                        eprintln!("[install] socket reconnect failed ({re}); re-exchanging ticket...");
                        match connect_demux().await {
                            Ok((d, t)) => {
                                demux = d;
                                ticket = t;
                            }
                            Err(ce) => {
                                eprintln!("[install] re-exchange failed ({ce}); retrying...");
                                continue;
                            }
                        }
                    }
                };
            }
        }
    }
}

/// Pull a human-readable game name out of a Ubisoft product `configuration`
/// blob (YAML). `root.name` is a localization key resolved through
/// `localizations.default[key]`; fall back to `sort_string`, then the raw key.
fn game_name(config: &str) -> Option<String> {
    let v: serde_yaml::Value = serde_yaml::from_str(config).ok()?;
    let root = v.get("root")?;
    let key = root.get("name").and_then(|n| n.as_str());
    if let Some(key) = key {
        if let Some(name) = v
            .get("localizations")
            .and_then(|l| l.get("default"))
            .and_then(|d| d.get(key))
            .and_then(|n| n.as_str())
        {
            return Some(name.trim().to_string());
        }
    }
    root.get("sort_string")
        .and_then(|s| s.as_str())
        .map(|s| s.trim().to_string())
        .or_else(|| key.map(String::from))
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s).context("reading stdin")?;
    Ok(s.trim().to_string())
}

async fn do_login(
    email: Option<String>,
    password: Option<String>,
    ticket: Option<String>,
    session_id: Option<String>,
) -> Result<()> {
    // Bootstrap path: a ticket captured from a real browser session. Skips the
    // DataDome-walled password endpoint entirely. Store it and let the Demux
    // ownership calls (which are NOT behind DataDome) use it.
    if let Some(ticket) = ticket {
        // Upgrade the bare ticket into a real session so it carries an expiry
        // and a rememberMe ticket; otherwise `refresh` can never work.
        let auth = auth::upgrade_captured_ticket(&ticket, &session_id.unwrap_or_default()).await;
        config::save_auth(&auth)?;
        println!("Stored browser-captured ticket. Try `optima-cli whoami` (REST /me may still be DataDome-walled) and the upcoming `list-games` (Demux, not walled).");
        return Ok(());
    }

    // Default: open the real system browser and capture the ticket (the
    // maxima/GOG approach). The DataDome-walled email/password REST path only
    // runs if the user explicitly passes credentials.
    if email.is_none() && password.is_none() {
        return browser_login::run().await;
    }

    let email = match email {
        Some(e) => e,
        None => prompt("Ubisoft email: ")?,
    };
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Ubisoft password: ").context("reading password")?,
    };

    let outcome = auth::login(&email, &password).await?;
    let auth = match outcome {
        LoginOutcome::Session(a) => a,
        LoginOutcome::TwoFactorRequired { ticket } => {
            let code = prompt("2FA code: ")?;
            match auth::login_2fa(&ticket, &code).await? {
                LoginOutcome::Session(a) => a,
                LoginOutcome::TwoFactorRequired { .. } => {
                    anyhow::bail!("2FA code rejected; try again")
                }
            }
        }
    };

    config::save_auth(&auth)?;
    println!(
        "Logged in as {} (profileId {})",
        if auth.name_on_platform.is_empty() { "<unknown>" } else { &auth.name_on_platform },
        auth.profile_id
    );
    Ok(())
}

/// Recursively collect every `relative:` value that names a `.exe`, in document
/// order — the game's launch executables live under
/// `start_game.{online,offline}.executables[].relative` (nesting varies by
/// title, so we walk the whole tree).
fn collect_executables(v: &serde_yaml::Value, out: &mut Vec<String>) {
    match v {
        serde_yaml::Value::Mapping(m) => {
            for (k, val) in m {
                if k.as_str() == Some("relative") {
                    if let Some(s) = val.as_str() {
                        if s.to_lowercase().ends_with(".exe") && !out.contains(&s.to_string()) {
                            out.push(s.to_string());
                        }
                    }
                }
                collect_executables(val, out);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                collect_executables(item, out);
            }
        }
        _ => {}
    }
}

/// Pick the launch exe from a product configuration: prefer a single-player exe
/// (…SP.exe) over multiplayer, else the first.
fn first_executable(config: &str) -> Option<String> {
    let v: serde_yaml::Value = serde_yaml::from_str(config).ok()?;
    let mut exes = Vec::new();
    collect_executables(&v, &mut exes);
    exes.iter()
        .find(|e| {
            let u = e.to_uppercase();
            u.contains("SP") && !u.contains("MP")
        })
        .cloned()
        .or_else(|| exes.first().cloned())
}

async fn do_launch(product_id: u32, path: Option<String>, exe: Option<String>) -> Result<()> {
    // The install dir is fully local — resolve it before touching the network so
    // an offline launch never depends on Ubisoft.
    let dir = default_install_dir(product_id, path);
    if !dir.exists() {
        anyhow::bail!("install dir {} does not exist — run `optima-cli install {product_id}` first", dir.display());
    }

    // Ask Ubisoft whether the account owns the game and which exe it runs.
    // Ownership itself is Connect's call when it starts the game; this is only
    // a quick refusal for a definite "not owned", and the exe name lets Optima
    // follow the game. Offline, the cached answer from the last launch is used.
    let cache = match resolve_launch_online(product_id, exe.clone()).await {
        Ok(c) => {
            let _ = config::save_launch_cache(product_id, &c);
            Some(c)
        }
        Err(e) if e.downcast_ref::<NotOwned>().is_some() => return Err(e),
        Err(e) => {
            println!("[launch] couldn't reach Ubisoft ({e}); using the cached game details");
            config::load_launch_cache(product_id).ok().flatten()
        }
    };
    let name = cache.as_ref().map(|c| c.name.clone()).unwrap_or_else(|| product_id.to_string());

    // An explicit --exe always wins over the cached path.
    let exe_rel = exe.or_else(|| cache.as_ref().map(|c| c.exe_rel.clone())).unwrap_or_default();
    let mut exe_path = dir.join(exe_rel.replace('\\', std::path::MAIN_SEPARATOR_STR));
    if exe_rel.trim().is_empty() || !exe_path.exists() {
        let base = std::path::Path::new(&exe_rel)
            .file_name()
            .map(|f| f.to_owned())
            .unwrap_or_default();
        // The config's `executables.relative` sometimes omits the subdir the
        // files land in (Splinter Cell Chaos Theory: System/splintercell3.exe),
        // and some configs list no relative exe at all (Watch_Dogs resolves it
        // from a registry key), so search by name, else pick the main exe.
        let found = if base.is_empty() {
            find_main_exe(&dir)
        } else {
            find_exe_in(&dir, &base)
        };
        match found {
            Some(found) => exe_path = found,
            None => anyhow::bail!(
                "could not find the game executable under {} (install incomplete?). \
                 Pass one with --exe <relative\\path.exe>.",
                dir.display()
            ),
        }
    }
    println!("[launch] {name}: {}", exe_path.display());

    // Ubisoft Connect runs the game. Optima only takes out what older builds
    // left in the folder and adds the EAX audio shim for the titles that need
    // it (BG&E, Splinter Cell), which comes out again when the game exits.
    connect::setup().await?;
    let mut dep = launch::Deployment::begin(&dir);
    launch::clean_legacy_shims(&dir);
    let exe_dir = exe_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| dir.clone());
    if let Err(e) = launch::deploy_eax(&mut dep, &exe_dir, &exe_path) {
        dep.restore();
        return Err(e);
    }
    let result = connect::launch_game(product_id, &dir, &exe_path);
    finish_deployment(dep);
    result
}

/// Undo a launch's file changes, unless they were asked to stay for
/// inspection (`OPTIMA_NO_RUN` dry runs, or `OPTIMA_KEEP_DEPLOY`). Anything kept
/// is undone at the start of the next launch.
fn finish_deployment(dep: launch::Deployment) {
    if std::env::var_os("OPTIMA_NO_RUN").is_some() || std::env::var_os("OPTIMA_KEEP_DEPLOY").is_some() {
        println!("[launch] leaving the deployed files in place until the next launch");
    } else {
        dep.restore();
    }
}

async fn do_settings(product_id: u32, path: Option<String>, exe: Option<String>) -> Result<()> {
    let dir = default_install_dir(product_id, path);
    if !dir.exists() {
        anyhow::bail!(
            "install dir {} does not exist — run `optima-cli install {product_id}` first",
            dir.display()
        );
    }

    // The product config names the settings exe (best effort: it needs the
    // network, and a disk scan works without it).
    let cfg = resolve_product_config(product_id).await.ok();

    // Resolve the settings exe: explicit --exe wins; else the config's
    // `internal_name: Settings` exe; else a disk scan.
    let settings_path = if let Some(rel) = exe {
        let p = dir.join(rel.replace('\\', std::path::MAIN_SEPARATOR_STR));
        if p.exists() {
            Some(p)
        } else {
            find_exe_in(&dir, p.file_name().unwrap_or_default())
        }
    } else {
        let from_config = cfg.as_deref().and_then(find_settings_exe).and_then(|rel| {
            let base = std::path::Path::new(&rel).file_name()?.to_owned();
            find_exe_in(&dir, &base)
        });
        from_config.or_else(|| find_settings_exe_on_disk(&dir))
    };

    let settings_path = settings_path.ok_or_else(|| {
        anyhow::anyhow!(
            "no settings/config application found for product {product_id}. \
             Pass one explicitly with --exe <relative\\path.exe> (look for a \
             *Settings*.exe or *Config*.exe in {}).",
            dir.display()
        )
    })?;

    // The settings app itself needs the EAX shim (that's exactly what BG&E's
    // SettingsApplication.exe demands). Deploy it next to the settings exe.
    let settings_dir = settings_path.parent().unwrap_or(&dir);
    let mut dep = launch::Deployment::begin(&dir);
    launch::clean_legacy_shims(&dir);
    if let Err(e) = launch::deploy_eax(&mut dep, settings_dir, &settings_path) {
        dep.restore();
        return Err(e);
    }
    // Same prefix Connect runs the game in, so what the app writes is what the
    // game reads.
    let result = connect::run_tool(product_id, &dir, &settings_path);
    finish_deployment(dep);
    result
}

/// Fetch just the product `configuration` YAML for a product id (no launch cache).
async fn resolve_product_config(product_id: u32) -> Result<String> {
    let (mut demux, _ticket) = connect_demux().await?;
    let games = demux.owned_games().await?;
    let game = games
        .iter()
        .find(|g| g.product_id == product_id)
        .ok_or_else(|| anyhow::anyhow!("product {product_id} not found"))?;
    game.configuration
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no configuration for product {product_id}"))
}

/// Find the settings/config executable named in a product configuration — the
/// entry whose sibling `internal_name`/description marks it as the Settings app.
fn find_settings_exe(config: &str) -> Option<String> {
    let v: serde_yaml::Value = serde_yaml::from_str(config).ok()?;
    let mut found = None;
    walk_for_settings(&v, &mut found);
    found
}

fn walk_for_settings(v: &serde_yaml::Value, found: &mut Option<String>) {
    if found.is_some() {
        return;
    }
    match v {
        serde_yaml::Value::Mapping(m) => {
            // Does THIS mapping name an exe and mark itself as the settings app?
            let rel = m
                .iter()
                .find(|(k, _)| k.as_str() == Some("relative"))
                .and_then(|(_, val)| val.as_str());
            if let Some(rel) = rel {
                if rel.to_lowercase().ends_with(".exe") {
                    let is_settings = m.iter().any(|(k, val)| {
                        let kn = k.as_str().unwrap_or("").to_lowercase();
                        let vs = val.as_str().unwrap_or("").to_lowercase();
                        (kn.contains("internal_name")
                            || kn.contains("description")
                            || kn == "name")
                            && (vs.contains("setting") || vs.contains("config"))
                    });
                    if is_settings {
                        *found = Some(rel.to_string());
                        return;
                    }
                }
            }
            for (_, val) in m {
                walk_for_settings(val, found);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                walk_for_settings(item, found);
            }
        }
        _ => {}
    }
}

/// Fallback: scan the install dir for an exe that looks like a settings/config app
/// (name contains "settings" or "config"), excluding installer/redistributable
/// junk. Prefers the shallowest match.
fn find_settings_exe_on_disk(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut matches: Vec<std::path::PathBuf> = Vec::new();
    while let Some(d) = stack.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !name.ends_with(".exe") {
                continue;
            }
            let looks_settings = name.contains("setting") || name.contains("config");
            let is_junk = ["vcredist", "vc_redist", "dxsetup", "directx", "redist", "unins"]
                .iter()
                .any(|j| name.contains(j))
                || p.to_string_lossy().to_lowercase().contains("support/installs");
            if looks_settings && !is_junk {
                matches.push(p);
            }
        }
    }
    matches.into_iter().min_by_key(|p| p.components().count())
}

/// Ubisoft's live answer that this account does not own the product. Unlike a
/// network failure, it must not fall back to the offline launch cache.
#[derive(Debug)]
struct NotOwned(u32);

impl std::fmt::Display for NotOwned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "product {} is not in your owned games", self.0)
    }
}

impl std::error::Error for NotOwned {}

async fn resolve_launch_online(product_id: u32, exe: Option<String>) -> Result<config::LaunchCache> {
    let (mut demux, _ticket) = connect_demux().await?;
    let games = demux.owned_games().await?;
    let game = games
        .iter()
        .find(|g| g.product_id == product_id && g.owned.unwrap_or(false))
        .ok_or_else(|| anyhow::Error::new(NotOwned(product_id)))?;
    let name = game
        .configuration
        .as_deref()
        .and_then(game_name)
        .unwrap_or_else(|| product_id.to_string());
    let config = game.configuration.clone().unwrap_or_default();
    // Some titles (e.g. Watch_Dogs) list NO `relative:` exe in the config; an
    // empty exe_rel makes do_launch scan the install dir instead.
    let exe_rel = match exe {
        Some(e) => e,
        None => first_executable(&config).unwrap_or_default(),
    };
    Ok(config::LaunchCache { exe_rel, name })
}


/// Recursively search `root` for a file named `base` (the exe basename). Used when
/// the product config's `executables.relative` path doesn't match the actual
/// on-disk layout (e.g. the exe sits in a System/ subdir). Returns the first match.
fn find_exe_in(root: &std::path::Path, base: &std::ffi::OsStr) -> Option<std::path::PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut matches: Vec<std::path::PathBuf> = Vec::new();
    while let Some(d) = stack.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(_) => continue, // unreadable dir: skip, keep searching
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name() == Some(base) {
                matches.push(p);
            }
        }
    }
    // Prefer the shallowest match — the main-game exe (e.g. System/foo.exe) over a
    // deeper multiplayer copy (e.g. Versus/System/foo.exe).
    matches
        .into_iter()
        .min_by_key(|p| p.components().count())
}

/// Pick the main game exe by scanning the install dir, for titles whose config
/// lists no relative exe (they resolve it from a registry key — e.g. Watch_Dogs →
/// bin/Watch_Dogs.exe). Skips installers/redistributables and support dirs, then
/// takes the largest remaining exe (the game binary is invariably the biggest).
fn find_main_exe(root: &std::path::Path) -> Option<std::path::PathBuf> {
    const JUNK: &[&str] = &[
        "vcredist", "vc_redist", "dxsetup", "d3d", "directx", "redist", "unins",
        "setup", "netfx", "dotnet", "clwireg", "uplayinstaller", "firewall",
        "gdfinstall", "install", "crashreport", "activation", "cleanup", "helper",
    ];
    let mut stack = vec![root.to_path_buf()];
    let mut best: Option<(u64, std::path::PathBuf)> = None;
    while let Some(d) = stack.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
            if !name.ends_with(".exe") {
                continue;
            }
            let path_l = p.to_string_lossy().to_lowercase();
            // Skip redistributables/installers and anything under a support/ tree.
            if path_l.contains("/support/") || JUNK.iter().any(|j| name.contains(j)) {
                continue;
            }
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            if best.as_ref().map(|(s, _)| size > *s).unwrap_or(true) {
                best = Some((size, p));
            }
        }
    }
    best.map(|(_, p)| p)
}

async fn do_config(product_id: u32) -> Result<()> {
    let (mut demux, _ticket) = connect_demux().await?;
    let games = demux.owned_games().await?;
    let game = games
        .iter()
        .find(|g| g.product_id == product_id)
        .ok_or_else(|| anyhow::anyhow!("product {product_id} not in your catalog"))?;
    match game.configuration.as_deref() {
        Some(c) if !c.is_empty() => {
            println!("{c}");
        }
        _ => println!("(product {product_id} has no inline configuration blob)"),
    }
    Ok(())
}

async fn do_whoami() -> Result<()> {
    let Some(auth) = config::load_auth()? else {
        println!("Not logged in. Run `optima-cli login`.");
        return Ok(());
    };
    println!("Stored session:");
    println!("  name:       {}", auth.name_on_platform);
    println!("  profileId:  {}", auth.profile_id);
    // An empty expiry used to print as "(valid)", which is how a long-dead
    // ticket looked healthy right up until every call 401'd.
    if auth.expiration.is_empty() {
        println!("  expiration: unknown — this session was stored without one");
    } else {
        println!(
            "  expiration: {} ({})",
            auth.expiration,
            if auth.is_expired() { "EXPIRED" } else { "valid" }
        );
    }
    if auth.remember_me_ticket.is_empty() {
        println!("  refresh:    unavailable (no rememberMe ticket stored)");
    } else {
        println!("  refresh:    available");
    }

    // Live check — the real proof the ticket authorizes API calls.
    let (status, body) = auth::fetch_me(&auth).await?;
    if status.is_success() {
        println!("  live check: OK ({status})");
    } else {
        println!("  live check: FAILED ({status})");
        println!("  response:   {}", body.chars().take(300).collect::<String>());
        if auth.is_expired() {
            println!("  hint: session expired — run `optima-cli refresh`.");
        }
    }
    Ok(())
}

async fn do_refresh() -> Result<()> {
    let Some(auth) = config::load_auth()? else {
        println!("Not logged in. Run `optima-cli login`.");
        return Ok(());
    };
    let fresh = auth::refresh(&auth).await?;
    config::save_auth(&fresh)?;
    println!("Session refreshed (new expiration {}).", fresh.expiration);
    Ok(())
}
