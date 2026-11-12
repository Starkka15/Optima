// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Starkka15

//! Sign in on Ubisoft's real login page, inside Steam's own browser.
//!
//! `steam://openurl/` opens `connect.ubisoft.com/login` in Steam's browser (the
//! overlay browser in Game Mode, with the on-screen keyboard; a real Ubisoft
//! page with a real certificate). Steam's browser exposes the Chrome DevTools
//! protocol on 127.0.0.1:8080 whenever Decky Loader is installed (Decky needs it
//! to load plugins). After the user signs in, the page's `localStorage` holds
//! `PRODloginData` (ticket, sessionId, rememberMeTicket, expiration, profileId,
//! nameOnPlatform), which we read through that protocol: the same data Lutris
//! reads from its own WebKit window. Then the tab is closed.
//!
//! After sign-in Ubisoft sends the tab to its `nextUrl` (`/ready`), which now
//! fails to load; the tab is then moved to `logged-in.html` (a page on the same
//! site that does load) so the storage can be read.
//!
//! Only the tab this login opened is read, and only `PRODloginData`.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::config::Auth;

const CLUB_APP_ID: &str = "82b650c0-6cb3-40c0-9f41-25a53b62b206";
const CLUB_GENOME_ID: &str = "42d07c95-9914-4450-8b38-267c4e462b21";
const LOGIN_PREFIX: &str = "https://connect.ubisoft.com/login?";

fn login_url() -> String {
    format!(
        "{LOGIN_PREFIX}appId={CLUB_APP_ID}&genomeId={CLUB_GENOME_ID}&lang=en-US\
         &nextUrl=https:%2F%2Fconnect.ubisoft.com%2Fready"
    )
}

fn logged_in_url() -> String {
    format!("https://connect.ubisoft.com/logged-in.html?appId={CLUB_APP_ID}&lang=en-US&genomeId={CLUB_GENOME_ID}")
}

fn cdp_port() -> u16 {
    std::env::var("OPTIMA_CDP_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8080)
}

#[derive(Deserialize)]
struct Target {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    url: String,
}

async fn targets(port: u16) -> Result<Vec<Target>> {
    let url = format!("http://127.0.0.1:{port}/json");
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("Steam's browser debugger is not reachable at {url}"))?;
    Ok(resp.json().await?)
}

async fn close_target(port: u16, id: &str) {
    let url = format!("http://127.0.0.1:{port}/json/close/{id}");
    if let Ok(c) = reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        let _ = c.get(&url).send().await;
    }
}

/// Closing the tab leaves Steam's UI on an empty browser screen. Steam's UI is
/// one web app (the `SharedJSContext` page), so step its history back once, as
/// pressing B would, but only while it is still on that browser screen.
async fn leave_browser_screen(port: u16) {
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let Ok(all) = targets(port).await else { return };
        let Some(ui) = all.into_iter().find(|t| t.kind == "page" && t.url.contains("/routes/externalweb")) else {
            return;
        };
        if cdp_call(port, &ui.id, "Runtime.evaluate", serde_json::json!({"expression": "history.back()"})).is_ok() {
            return;
        }
    }
}

/// One DevTools request over a fresh websocket to a page target (stdlib only;
/// the debugger is plain ws on loopback and the messages are small).
fn cdp_call(port: u16, target: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let key = {
        use base64::Engine;
        let nonce: [u8; 16] = std::array::from_fn(|i| (Instant::now().elapsed().subsec_nanos() as u8).wrapping_add(i as u8 * 37));
        base64::engine::general_purpose::STANDARD.encode(nonce)
    };
    write!(
        s,
        "GET /devtools/page/{target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte)?;
        head.push(byte[0]);
        if head.len() > 8192 {
            bail!("bad websocket handshake");
        }
    }
    if !head.starts_with(b"HTTP/1.1 101") {
        bail!("websocket refused: {}", String::from_utf8_lossy(&head[..head.len().min(80)]));
    }

    let msg = serde_json::json!({"id": 1, "method": method, "params": params}).to_string();
    let data = msg.as_bytes();
    let mut frame = vec![0x81u8];
    match data.len() {
        n if n < 126 => frame.push(0x80 | n as u8),
        n if n <= 0xFFFF => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    let mask = [0x5au8, 0x13, 0xc7, 0x2e];
    frame.extend_from_slice(&mask);
    frame.extend(data.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    s.write_all(&frame)?;

    loop {
        let mut h = [0u8; 2];
        s.read_exact(&mut h)?;
        let mut len = (h[1] & 0x7F) as u64;
        if len == 126 {
            let mut b = [0u8; 2];
            s.read_exact(&mut b)?;
            len = u16::from_be_bytes(b) as u64;
        } else if len == 127 {
            let mut b = [0u8; 8];
            s.read_exact(&mut b)?;
            len = u64::from_be_bytes(b);
        }
        if len > 16 << 20 {
            bail!("oversized websocket frame");
        }
        let mut payload = vec![0u8; len as usize];
        s.read_exact(&mut payload)?;
        if h[0] & 0x0F != 1 {
            continue; // not a text frame
        }
        let v: serde_json::Value = serde_json::from_slice(&payload)?;
        if v.get("id").and_then(|i| i.as_u64()) == Some(1) {
            if let Some(e) = v.get("error") {
                bail!("{method} failed: {e}");
            }
            return Ok(v.get("result").cloned().unwrap_or_default());
        }
    }
}

/// `PRODloginData` from the tab, if the user has signed in.
fn read_login_data(port: u16, target: &str) -> Result<Option<serde_json::Value>> {
    let r = cdp_call(
        port,
        target,
        "Runtime.evaluate",
        serde_json::json!({"expression": "localStorage.getItem('PRODloginData')", "returnByValue": true}),
    )?;
    let Some(text) = r.pointer("/result/value").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let data: serde_json::Value = serde_json::from_str(text).context("PRODloginData is not JSON")?;
    let field = |k: &str| data.get(k).and_then(|v| v.as_str()).unwrap_or("");
    if field("ticket").is_empty() || field("sessionId").is_empty() {
        return Ok(None);
    }
    // A stored login from an earlier visit can be stale; wait for a live one.
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(field("expiration")) {
        if exp < chrono::Utc::now() {
            return Ok(None);
        }
    }
    Ok(Some(data))
}

fn auth_from_login_data(d: &serde_json::Value) -> Auth {
    let f = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    Auth {
        ticket: f("ticket"),
        session_id: f("sessionId"),
        profile_id: f("profileId"),
        user_id: f("userId"),
        name_on_platform: f("nameOnPlatform"),
        expiration: f("expiration"),
        remember_me_ticket: f("rememberMeTicket"),
        ..Default::default()
    }
}

/// Open the login page in Steam, wait for the sign-in, and return the session.
pub async fn run() -> Result<Auth> {
    let port = cdp_port();
    targets(port).await.context(
        "Steam's browser debugger is off. It is on whenever Decky Loader is installed; \
         otherwise create ~/.steam/steam/.cef-enable-remote-debugging and restart Steam",
    )?;
    let before: Vec<String> = targets(port).await?.into_iter().map(|t| t.id).collect();

    let url = login_url();
    println!("[login] opening Ubisoft's login page in Steam...");
    std::process::Command::new("steam")
        .arg(format!("steam://openurl/{url}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("running `steam` to open the login page")?;

    // Find the tab we just opened.
    let deadline = Instant::now() + Duration::from_secs(60);
    let tab = loop {
        if let Some(t) = targets(port).await?.into_iter().find(|t| {
            t.kind == "page" && t.url.starts_with(LOGIN_PREFIX) && !before.contains(&t.id)
        }) {
            break t.id;
        }
        // Steam may reuse its one external-web tab instead of making a new one.
        if let Some(t) = targets(port).await?.into_iter().find(|t| t.kind == "page" && t.url.starts_with(LOGIN_PREFIX)) {
            break t.id;
        }
        if Instant::now() > deadline {
            bail!("Steam did not open the login page within 60 s");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    println!("[login] sign in on the Ubisoft page (2FA included); waiting...");

    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    let data = loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if Instant::now() > deadline {
            close_target(port, &tab).await;
            bail!("no sign-in within 15 minutes");
        }
        let Some(t) = targets(port).await?.into_iter().find(|t| t.id == tab) else {
            bail!("the login page was closed before signing in");
        };
        if t.url.starts_with("https://connect.ubisoft.com/") && !t.url.starts_with("https://connect.ubisoft.com/ready") {
            match read_login_data(port, &tab) {
                Ok(Some(d)) => break d,
                Ok(None) => {}
                Err(e) => eprintln!("[login] reading the page: {e:#}"),
            }
        } else if t.url.starts_with("http://error") || t.url.starts_with("https://connect.ubisoft.com/ready") {
            // Signed in; Ubisoft's nextUrl doesn't load. Move to a page that does.
            let _ = cdp_call(port, &tab, "Page.navigate", serde_json::json!({"url": logged_in_url()}));
        }
    };
    close_target(port, &tab).await;
    leave_browser_screen(port).await;

    // Exchange for Optima's own app session (also checks the ticket is live);
    // fall back to the page's session as-is, which already has rememberMe.
    let page = auth_from_login_data(&data);
    let mut auth = crate::auth::upgrade_captured_ticket(&page.ticket, &page.session_id).await;
    if auth.remember_me_ticket.is_empty() {
        auth.remember_me_ticket = page.remember_me_ticket.clone();
    }
    for (dst, src) in [
        (&mut auth.profile_id, &page.profile_id),
        (&mut auth.user_id, &page.user_id),
        (&mut auth.name_on_platform, &page.name_on_platform),
        (&mut auth.expiration, &page.expiration),
    ] {
        if dst.is_empty() {
            *dst = src.clone();
        }
    }
    if auth.ticket.is_empty() {
        return Err(anyhow!("the sign-in produced no ticket"));
    }
    Ok(auth)
}
