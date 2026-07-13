//! Optima — an ownership-backed Ubisoft Connect client (maxima-cli style).
//!
//! P0 (this build): UbiServices authentication. `login` stores a session ticket;
//! `whoami` live-verifies it against the profile endpoint; `refresh` renews it
//! from the rememberMe ticket. Later phases: Demux `ownership_service` (list
//! owned games), CDN install, and the Uplay R1/R2 DRM handshake under Proton.

mod auth;
mod browser_login;
mod config;
mod demux;
mod install;
mod launch;
mod proto;
mod webauth_capture;

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
        /// DataDome-walled password endpoint. Temporary until the embedded
        /// webview login lands. Optionally pair with --session-id / --profile-id.
        #[arg(long)]
        ticket: Option<String>,
        /// Ubi-SessionId that goes with a pasted --ticket (devtools: the
        /// `Ubi-SessionId` request header). Needed for authorized REST calls.
        #[arg(long)]
        session_id: Option<String>,
        /// SteamOS/no-devtools mode: host a local page with Ubisoft's WebAuth
        /// SDK and capture the ticket automatically (no copy/paste).
        #[arg(long)]
        local: bool,
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
    },
    /// Launch an installed, owned game under Proton with our Uplay R1 DRM shim.
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
    /// Set or show the Uplay player profile (email / username / password) the emu
    /// presents to games. Browser/ticket login can't capture these, so you set
    /// them here (the Optima extension exposes the same fields as a form). Run
    /// with no flags to print the current profile.
    Profile {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    /// Show the stored session and live-verify it against UbiServices.
    Whoami,
    /// Renew the stored session from its rememberMe ticket (no password).
    Refresh,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().cmd {
        Cmd::Login { email, password, ticket, session_id, local } => {
            if local {
                webauth_capture::run().await
            } else {
                do_login(email, password, ticket, session_id).await
            }
        }
        Cmd::ListGames { json } => do_list_games(json).await,
        Cmd::Install { product_id, path } => do_install(product_id, path).await,
        Cmd::Launch { product_id, path, exe } => do_launch(product_id, path, exe).await,
        Cmd::Settings { product_id, path, exe } => do_settings(product_id, path, exe).await,
        Cmd::Config { product_id } => do_config(product_id).await,
        Cmd::Profile { email, username, password } => do_profile(email, username, password),
        Cmd::Whoami => do_whoami().await,
        Cmd::Refresh => do_refresh().await,
    }
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

async fn do_install(product_id: u32, path: Option<String>) -> Result<()> {
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
        match install::install_game(&mut demux, &ticket, product_id, &manifest_id, &name, &dir).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                attempt += 1;
                if attempt > 30 {
                    return Err(e.context("install failed after 30 whole-run retries"));
                }
                eprintln!("[install] run failed ({e}); reconnecting demux and resuming (attempt {attempt})...");
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
        let auth = config::Auth {
            ticket,
            session_id: session_id.unwrap_or_default(),
            ..Default::default()
        };
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
    let dir = match &path {
        Some(p) => std::path::PathBuf::from(p),
        None => dirs::home_dir()
            .unwrap_or_default()
            .join("Games/optima")
            .join(product_id.to_string()),
    };
    if !dir.exists() {
        anyhow::bail!("install dir {} does not exist — run `optima-cli install {product_id}` first", dir.display());
    }

    // Ownership was proven the first time you launched online (we cached the real
    // account + ticket then). Since the SP Uplay R1 DRM only reads the values we
    // write into Uplay.ini — it never re-checks ownership over the network — a
    // cached account lets you play fully offline, forever. So: try to refresh
    // from Ubisoft (best effort), but fall back to the cache when the network is
    // down or `OPTIMA_OFFLINE=1` is set. No aggressive per-launch online gate.
    let forced_offline = std::env::var_os("OPTIMA_OFFLINE").is_some();
    let mut cache: Option<config::LaunchCache> = None;
    if forced_offline {
        println!("[launch] OPTIMA_OFFLINE set — using cached account, skipping Ubisoft.");
    } else {
        match resolve_launch_online(product_id, exe.clone()).await {
            Ok(c) => {
                let _ = config::save_launch_cache(product_id, &c);
                cache = Some(c);
            }
            Err(e) => {
                println!("[launch] couldn't reach Ubisoft ({e}); falling back to cached account for offline play.");
            }
        }
    }
    let cache = match cache {
        Some(c) => c,
        None => config::load_launch_cache(product_id)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no cached account for product {product_id} yet — launch it once while online \
                 so Optima can cache your ownership ticket, then offline launches will work"
            )
        })?,
    };

    // An explicit --exe always wins over the cached path.
    let exe_rel = exe.unwrap_or_else(|| cache.exe_rel.clone());
    let mut exe_path = dir.join(exe_rel.replace('\\', std::path::MAIN_SEPARATOR_STR));
    if !exe_path.exists() {
        // The product config's `executables.relative` sometimes omits the subdir
        // the files actually land in (e.g. Splinter Cell Chaos Theory's exe is at
        // System/splintercell3.exe but the config just says "splintercell3.exe").
        // Fall back to searching the install dir for the exe basename.
        let base = std::path::Path::new(&exe_rel)
            .file_name()
            .map(|f| f.to_owned())
            .unwrap_or_default();
        match find_exe_in(&dir, &base) {
            Some(found) => {
                println!("[launch] exe not at {}; found it at {}", exe_path.display(), found.display());
                exe_path = found;
            }
            None => anyhow::bail!(
                "executable {} not found (install incomplete?)",
                exe_path.display()
            ),
        }
    }
    // Unreal-style games (Chaos Theory) live in a System/ subdir and resolve their
    // data via paths relative to the exe's own directory, so the game must run with
    // its CWD = the exe folder and load its folder-local DLLs from there. For
    // root-level exes (AC3/AC4) this is just the install root — no change.
    let run_dir = exe_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| dir.clone());

    // The player identity the emu presents. Precedence: env override →
    // stored profile (from `optima-cli profile set` / the extension form) →
    // what we recovered from the account/cache. Username defaults to the real
    // Ubisoft display name; email is synthesized only as a last resort so it's
    // never blank; password is optional (unused offline).
    let profile = config::load_profile().unwrap_or_default();
    let username = first_nonempty([
        std::env::var("OPTIMA_USERNAME").ok(),
        Some(profile.username.clone()),
        Some(cache.username.clone()),
    ])
    .unwrap_or_else(|| "Optima".to_string());
    let email = first_nonempty([
        std::env::var("OPTIMA_EMAIL").ok(),
        Some(profile.email.clone()),
        Some(cache.email.clone()),
    ])
    .unwrap_or_default();
    let email = if email.trim().is_empty() { resolve_email(&username) } else { email };
    let password = first_nonempty([
        std::env::var("OPTIMA_PASSWORD").ok(),
        Some(profile.password.clone()),
    ])
    .unwrap_or_default();

    let acct = launch::LaunchAccount {
        user_id: cache.user_id.clone(),
        username,
        email,
        password,
        ticket: cache.ticket.clone(),
        app_id: cache.app_id,
        language: cache.language.clone(),
    };

    // Which Ubisoft DRM does this exe link against? AC4 & most SP titles import
    // uplay_r1_loader.dll (flat UPLAY_*). AC3 & other early-Orbit AnvilNext titles
    // import ubiorbitapi_r2_loader.dll (C++ OrbitClient) + upc_r1_loader.dll — a
    // different emu. Detect from the exe so we deploy the matching loaders.
    let drm = launch::detect_drm(&exe_path);
    println!(
        "[launch] preparing {}: DRM={:?}, writing config + deploying loaders...",
        cache.name, drm
    );
    // Our complete emu reads Uplay.toml; keep the legacy Uplay.ini too (harmless,
    // ignored by the new loader) so a fallback minimal loader would still work.
    // upc_r1_loader.dll (Orbit R2 titles) is our R1 loader and reads Uplay.toml too.
    // Everything goes next to the exe (run_dir) so the game loads its folder-local
    // DLLs and reads the config from its own working dir.
    launch::write_uplay_toml(&run_dir, &acct, &cache.name)?;
    launch::write_uplay_ini(&run_dir, &acct)?;
    // Orbit R2 titles additionally need Orbit.toml for ubiorbitapi_r2_loader.dll.
    if drm == launch::Drm::OrbitR2 {
        launch::write_orbit_toml(&run_dir, &acct, &cache.name)?;
    }
    launch::deploy_loaders(&run_dir, drm)?;
    // Old titles that demand Creative EAX (BG&E, Splinter Cell) — drop our shim.
    launch::deploy_eax(&run_dir, &exe_path)?;

    let prefix = config::data_dir()?.join("prefix");
    // `-offline` is a title-SPECIFIC Uplay SP variant (AC4 accepts it) — but many
    // games (e.g. Beyond Good & Evil) treat an unknown arg as a file to open and
    // die with "unable to open file (-offline)". So run with NO extra args by
    // default. For titles whose offline SP exe genuinely needs it, set
    // OPTIMA_OFFLINE_ARG=1; or pass arbitrary args via OPTIMA_ARGS="a b c".
    let args: Vec<String> = if let Some(a) = std::env::var_os("OPTIMA_ARGS") {
        a.to_string_lossy().split_whitespace().map(String::from).collect()
    } else if std::env::var_os("OPTIMA_OFFLINE_ARG").is_some() {
        vec!["-offline".to_string()]
    } else {
        vec![]
    };
    let install_reg = (!cache.install_reg.is_empty()).then(|| cache.install_reg.clone());
    launch::run_game(&dir, &exe_path, &prefix, product_id, &args, install_reg.as_deref())
}

/// Launch a game's settings/config application in the same Proton prefix so the
/// player can change resolution/graphics (many old titles boot tiny with no
/// in-game video menu). No account/DRM setup needed — the settings app just reads
/// and writes the game's registry/ini in the prefix, which the game then reads.
async fn do_settings(product_id: u32, path: Option<String>, exe: Option<String>) -> Result<()> {
    let dir = match &path {
        Some(p) => std::path::PathBuf::from(p),
        None => dirs::home_dir()
            .unwrap_or_default()
            .join("Games/optima")
            .join(product_id.to_string()),
    };
    if !dir.exists() {
        anyhow::bail!(
            "install dir {} does not exist — run `optima-cli install {product_id}` first",
            dir.display()
        );
    }

    // Fetch the product config once (best-effort, offline-tolerant) — it names both
    // the settings exe and the game's install-path registry key. If the fetch
    // flakes (it hits the network), fall back to the install key cached by a prior
    // launch so the settings app still gets its "properly installed" registry key.
    let cfg = resolve_product_config(product_id).await.ok();
    let install_reg = cfg
        .as_deref()
        .and_then(install_register)
        .or_else(|| {
            config::load_launch_cache(product_id)
                .ok()
                .flatten()
                .map(|c| c.install_reg)
                .filter(|s| !s.is_empty())
        });

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
    launch::deploy_eax(settings_dir, &settings_path)?;

    let prefix = config::data_dir()?.join("prefix");
    println!("[settings] launching {} ...", settings_path.display());
    // Reuse the game runner: it points the Ubisoft install registry (incl. the
    // game's own install-path key, so the app doesn't bail "not properly
    // installed") at the game, sets CWD to the exe's dir, and runs under the same
    // prefix — so the settings app's writes land where the game reads them.
    launch::run_game(&dir, &settings_path, &prefix, product_id, &[], install_reg.as_deref())
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

/// Resolve the real account + ticket + launch exe from Ubisoft. Used to build
/// (and refresh) the offline launch cache. Any failure here is non-fatal — the
/// caller falls back to a previously cached account.
async fn resolve_launch_online(
    product_id: u32,
    exe: Option<String>,
) -> Result<config::LaunchCache> {
    let (mut demux, _ticket) = connect_demux().await?;
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
    let config = game.configuration.clone().unwrap_or_default();
    let uplay_id = game.uplay_id.unwrap_or(0);

    let exe_rel = match exe {
        Some(e) => e,
        None => first_executable(&config)
            .ok_or_else(|| anyhow::anyhow!("could not find a launch exe in the product config; pass --exe"))?,
    };

    // Real account data for the DRM shim. A paste-only login may not have stored
    // the profile id / name — fetch them from /v3/profiles/me (not DataDome-walled
    // with a valid ticket) and persist for next time.
    let mut auth = config::load_auth()?.ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    if auth.profile_id.is_empty() || auth.name_on_platform.is_empty() {
        if let Ok((st, body)) = auth::fetch_me(&auth).await {
            if st.is_success() {
                if let Ok(j) = serde_json::from_str::<serde_json::Value>(&body) {
                    if auth.profile_id.is_empty() {
                        if let Some(p) = j.get("profileId").and_then(|x| x.as_str()) {
                            auth.profile_id = p.to_string();
                        }
                    }
                    if auth.name_on_platform.is_empty() {
                        if let Some(n) = j.get("nameOnPlatform").and_then(|x| x.as_str()) {
                            auth.name_on_platform = n.to_string();
                        }
                    }
                    let _ = config::save_auth(&auth);
                }
            }
        }
    }
    let user_id = auth.profile_id.clone();
    let username = if auth.name_on_platform.is_empty() {
        "Optima".to_string()
    } else {
        auth.name_on_platform.clone()
    };
    let ticket = if uplay_id != 0 {
        match demux.get_uplay_pc_ticket(uplay_id).await {
            Ok(Some(t)) => {
                println!("[launch] got real uplay_pc_ticket ({} chars) for uplay_id {uplay_id}", t.len());
                t
            }
            Ok(None) => {
                println!("[launch] no uplay ticket returned; using a placeholder (SP DRM doesn't validate it)");
                "OPTIMA".to_string()
            }
            Err(e) => {
                println!("[launch] ticket fetch failed ({e}); using placeholder");
                "OPTIMA".to_string()
            }
        }
    } else {
        println!("[launch] game has no uplay_id; using placeholder ticket");
        "OPTIMA".to_string()
    };

    let email = resolve_email(&username);
    Ok(config::LaunchCache {
        user_id,
        username,
        email,
        ticket,
        app_id: uplay_id.max(product_id),
        language: "en-US".to_string(),
        exe_rel,
        name,
        install_reg: install_register(&config).unwrap_or_default(),
    })
}

/// Extract the game's own install-path registry location from the product config
/// (`working_directory.register`) — old titles read it to confirm the game is
/// installed and to find their data. Returns the raw registry string.
fn install_register(config: &str) -> Option<String> {
    let v: serde_yaml::Value = serde_yaml::from_str(config).ok()?;
    let mut found = None;
    walk_for_register(&v, &mut found);
    found
}

fn walk_for_register(v: &serde_yaml::Value, found: &mut Option<String>) {
    if found.is_some() {
        return;
    }
    match v {
        serde_yaml::Value::Mapping(m) => {
            for (k, val) in m {
                if k.as_str() == Some("register") {
                    if let Some(s) = val.as_str() {
                        if s.to_uppercase().contains("HKEY") {
                            *found = Some(s.to_string());
                            return;
                        }
                    }
                }
                walk_for_register(val, found);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                walk_for_register(item, found);
            }
        }
        _ => {}
    }
}


/// The Ubisoft account email isn't in the `/me` response and the ticket is an
/// encrypted JWE, so we can't recover it after login. Games don't validate it in
/// offline SP (Re0xCat's own sample ships a placeholder), but it must not be
/// blank. Prefer an explicit `OPTIMA_EMAIL`; otherwise synthesize a stable,
/// valid-format address from the account name.
/// First option that is present and not blank (after trimming).
fn first_nonempty<const N: usize>(opts: [Option<String>; N]) -> Option<String> {
    opts.into_iter().flatten().find(|s| !s.trim().is_empty())
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

fn resolve_email(username: &str) -> String {
    if let Ok(e) = std::env::var("OPTIMA_EMAIL") {
        if !e.trim().is_empty() {
            return e;
        }
    }
    let handle: String = username.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let handle = if handle.is_empty() { "player".to_string() } else { handle.to_lowercase() };
    format!("{handle}@ubisoft.local")
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

fn do_profile(email: Option<String>, username: Option<String>, password: Option<String>) -> Result<()> {
    let mut p = config::load_profile().unwrap_or_default();
    let mut changed = false;
    if let Some(e) = email {
        p.email = e;
        changed = true;
    }
    if let Some(u) = username {
        p.username = u;
        changed = true;
    }
    if let Some(pw) = password {
        p.password = pw;
        changed = true;
    }
    if changed {
        config::save_profile(&p)?;
        println!("Profile saved.");
    }
    println!("Uplay player profile (fed to each game's Uplay.toml):");
    println!(
        "  email:    {}",
        if p.email.is_empty() { "(unset — synthesized at launch)".to_string() } else { p.email.clone() }
    );
    println!(
        "  username: {}",
        if p.username.is_empty() { "(unset — uses Ubisoft display name)".to_string() } else { p.username.clone() }
    );
    println!("  password: {}", if p.password.is_empty() { "(unset)" } else { "********" });
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
    println!("  expiration: {} ({})", auth.expiration, if auth.is_expired() { "EXPIRED" } else { "valid" });

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
