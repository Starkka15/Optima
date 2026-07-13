//! Browser login, the maxima/GOG way: open the user's REAL system browser (it
//! renders fine and clears DataDome + 2FA on its own — unlike an embedded
//! webview), then capture the `ubi_v1` ticket. Two capture paths run together,
//! exactly like maxima's `begin_oauth_login_flow`:
//!   1. a loopback HTTP listener, in case the flow redirects to 127.0.0.1 with
//!      the ticket in the query (hands-free), and
//!   2. stdin, so the user can paste the ticket (or the whole Authorization
//!      header, or a URL containing it) from their browser's devtools.

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Auth;

/// Ubisoft account sign-in — a plain page that renders in any real browser.
const LOGIN_PAGE: &str = "https://account.ubisoft.com/";
/// Loopback port for the optional hands-free redirect capture (maxima uses
/// 31033 for EA; keep clear of it).
const PORT: u16 = 31034;

pub async fn run() -> Result<()> {
    // Open the system default browser (honor $BROWSER like maxima does, so the
    // GameVault wrapper can point it at a flatpak Firefox on the Ally).
    if let Ok(browser) = std::env::var("BROWSER") {
        let _ = std::process::Command::new(browser).arg(LOGIN_PAGE).spawn();
    } else if let Err(e) = open::that(LOGIN_PAGE) {
        eprintln!("Couldn't open a browser automatically ({e}). Open this URL manually:\n  {LOGIN_PAGE}");
    }

    let listener = TcpListener::bind(("127.0.0.1", PORT)).await.ok();

    println!("============================================================");
    println!("A browser window opened to the Ubisoft sign-in.");
    println!();
    println!("  1. Log in (complete 2FA if prompted).");
    println!("  2. Press F12 -> Network tab.");
    println!("  3. Click any request to 'public-ubiservices.ubi.com'.");
    println!("  4. Under Request Headers, find 'Authorization: ubi_v1 t=...'.");
    println!("  5. Copy the value after 'ubi_v1 t=' and paste it below, Enter.");
    println!("     (Pasting the whole Authorization header or a URL also works.)");
    println!("============================================================");

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut line = String::new();

    loop {
        tokio::select! {
            // Hands-free path: a redirect to our loopback carrying the ticket.
            accept = accept_opt(&listener) => {
                if let Some(mut socket) = accept {
                    if let Some(ticket) = read_ticket_from_request(&mut socket).await {
                        return finish(&ticket);
                    }
                }
            }
            // Paste path: whatever the user copied from devtools.
            r = stdin.read_line(&mut line) => {
                r.context("reading stdin")?;
                let input = line.trim().to_string();
                if input.is_empty() {
                    // EOF / empty — keep waiting on the listener.
                    if line.is_empty() { std::future::pending::<()>().await; }
                    line.clear();
                    continue;
                }
                match extract_ticket(&input) {
                    Some(ticket) => return finish(&ticket),
                    None => {
                        println!("Couldn't find a ticket there. Paste just the token — the part after 'ubi_v1 t='.");
                        line.clear();
                    }
                }
            }
        }
    }
}

/// Await the listener only when it exists; otherwise never resolve (so the
/// select! falls through to stdin).
async fn accept_opt(listener: &Option<TcpListener>) -> Option<TcpStream> {
    match listener {
        Some(l) => l.accept().await.ok().map(|(s, _)| s),
        None => std::future::pending().await,
    }
}

/// Pull a ticket out of an HTTP request line like `GET /auth?token=XYZ HTTP/1.1`.
async fn read_ticket_from_request(socket: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = socket.read(&mut buf).await.ok()?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next()?;
    // Reply so the browser tab doesn't hang.
    use tokio::io::AsyncWriteExt;
    let _ = socket
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h2>Optima: ticket received. You can close this tab.</h2>")
        .await;
    extract_ticket(first)
}

/// Extract a ubi_v1 ticket from free-form input: the raw token, a full
/// `Authorization` header, or a URL/query carrying `ticket=`/`token=`/`t=`.
fn extract_ticket(input: &str) -> Option<String> {
    let s = input.trim();

    // `... ubi_v1 t=<token> ...`
    if let Some(idx) = s.to_lowercase().find("ubi_v1 t=") {
        let rest = &s[idx + "ubi_v1 t=".len()..];
        let tok = rest.split([' ', ',', ';', '&', '"', '\'']).next().unwrap_or("").trim();
        if !tok.is_empty() {
            return Some(tok.to_string());
        }
    }

    // URL / query param forms.
    if let Some((_, qs)) = s.split_once('?') {
        for pair in qs.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let k = k.trim().to_lowercase();
                if (k == "ticket" || k == "token" || k == "t") && !v.trim().is_empty() {
                    return Some(v.trim().to_string());
                }
            }
        }
    }

    // Bare token: long, single-token, no whitespace — treat as the ticket.
    if s.len() > 30 && !s.contains(char::is_whitespace) && !s.starts_with("http") {
        return Some(s.to_string());
    }

    None
}

fn finish(ticket: &str) -> Result<()> {
    let auth = Auth {
        ticket: ticket.to_string(),
        ..Default::default()
    };
    crate::config::save_auth(&auth)?;
    println!("Ticket captured and saved. Run `optima-cli list-games` (Demux — not DataDome-walled).");
    Ok(())
}
