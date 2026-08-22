// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Starkka15

//! UbiServices authentication (P0).
//!
//! Login is a `POST` to the public UbiServices session endpoint with HTTP Basic
//! (email:password) and the Ubisoft Connect PC `Ubi-AppId`. The response carries
//! a `ubi_v1` session ticket used to authorize every later REST + Demux call.
//! If the account has 2FA, the first response instead returns a
//! `twoFactorAuthenticationTicket`; we re-POST that ticket plus the `Ubi-2FACode`
//! header to complete the session.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::Deserialize;

use crate::config::Auth;

/// UbiServices session endpoint.
const SESSIONS_URL: &str = "https://public-ubiservices.ubi.com/v3/profiles/sessions";
/// The Ubisoft Connect PC launcher application id (NOT the Nadeo/Trackmania one,
/// which is rate-limited). Games/services expect this app id from the desktop
/// client.
const UBI_APP_ID: &str = "685a3038-2b04-47ee-9c5a-6403381a46aa";
const USER_AGENT: &str = "Optima/0.1 (+https://github.com/Starkka15/Optima)";

/// Raw UbiServices session response (camelCase on the wire).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    two_factor_authentication_ticket: Option<String>,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    session_key: String,
    #[serde(default)]
    profile_id: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    name_on_platform: String,
    #[serde(default)]
    expiration: String,
    #[serde(default)]
    remember_me_ticket: String,
}

/// What a login attempt yields: either a complete session, or a 2FA challenge
/// carrying the ticket we must echo back with the user's code.
pub enum LoginOutcome {
    Session(Auth),
    TwoFactorRequired { ticket: String },
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_secs(20))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .context("building http client")
}

fn to_auth(r: SessionResponse) -> Auth {
    Auth {
        ticket: r.ticket,
        session_id: r.session_id,
        session_key: r.session_key,
        profile_id: r.profile_id,
        user_id: r.user_id,
        name_on_platform: r.name_on_platform,
        expiration: r.expiration,
        remember_me_ticket: r.remember_me_ticket,
    }
}

/// Step 1: email + password. Returns a full session, or a 2FA challenge.
pub async fn login(email: &str, password: &str) -> Result<LoginOutcome> {
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{email}:{password}"));
    let send = |challenge: Option<String>| {
        let basic = basic.clone();
        async move {
            let mut req = client()?
                .post(SESSIONS_URL)
                .header("Content-Type", "application/json")
                .header("Ubi-AppId", UBI_APP_ID)
                .header("Ubi-RequestedPlatformType", "uplay")
                .header("Authorization", format!("Basic {basic}"));
            if let Some(c) = challenge {
                req = req.header("Ubi-Challenge", c);
            }
            req.json(&serde_json::json!({ "rememberMe": true }))
                .send()
                .await
                .context("sending login request")
        }
    };

    let resp = send(None).await?;
    // UbiServices can answer a login with a challenge that must be echoed back
    // on a second, otherwise identical request. Without this the login just
    // looks like it failed. Replayed once only — a challenge that repeats is a
    // real refusal, not a handshake.
    if let Some(challenge) = resp
        .headers()
        .get("Ubi-Challenge")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        eprintln!("[auth] server issued a challenge; replaying the login with it");
        return parse_session(send(Some(challenge)).await?).await;
    }

    parse_session(resp).await
}

/// Step 2 (only if `login` returned `TwoFactorRequired`): echo the 2FA ticket as
/// the bearer and supply the user's authenticator/SMS code via `Ubi-2FACode`.
pub async fn login_2fa(two_factor_ticket: &str, code: &str) -> Result<LoginOutcome> {
    // Ubisoft's own clients send the challenge ticket under `ubi_2fa_v1`, not
    // `ubi_v1`. Which one this endpoint accepts is not documented, so try the
    // observed scheme first and fall back rather than betting on either.
    for scheme in ["ubi_2fa_v1", "ubi_v1"] {
        let resp = client()?
            .post(SESSIONS_URL)
            .header("Content-Type", "application/json")
            .header("Ubi-AppId", UBI_APP_ID)
            .header("Ubi-RequestedPlatformType", "uplay")
            .header("Authorization", format!("{scheme} t={two_factor_ticket}"))
            .header("Ubi-2FACode", code)
            .json(&serde_json::json!({ "rememberMe": true }))
            .send()
            .await
            .context("sending 2FA request")?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED && scheme == "ubi_2fa_v1" {
            eprintln!("[auth] ubi_2fa_v1 rejected; retrying with ubi_v1");
            continue;
        }
        return parse_session(resp).await;
    }
    unreachable!("the loop returns or continues exactly once")
}

/// The app id whose ticket the Demux `uplay_pc` auth accepts (same one
/// ubisoft-demux-node uses). A browser ticket is issued for the *web* app, so we
/// re-request a session for this app id using the existing ticket as bearer.
pub const DEMUX_APP_ID: &str = "f68a4bb5-608a-4ff2-8123-be8ef797e0a6";

/// Exchange a valid `ubi_v1` ticket for a **complete** session scoped to
/// `app_id`.
///
/// The browser/WebAuth capture paths only ever see a bare ticket: no session id,
/// no expiry, and no rememberMe ticket, so `refresh` could not work and the
/// stored session looked valid long after it had expired. Re-requesting a
/// session with the captured ticket as bearer returns the full object, which is
/// what those paths should store.
pub async fn exchange_session(ticket: &str, app_id: &str) -> Result<Auth> {
    let resp = client()?
        .post(SESSIONS_URL)
        .header("Content-Type", "application/json")
        .header("Ubi-AppId", app_id)
        .header("Ubi-RequestedPlatformType", "uplay")
        .header("Authorization", format!("ubi_v1 t={ticket}"))
        .json(&serde_json::json!({ "rememberMe": true }))
        .send()
        .await
        .context("sending ticket-exchange request")?;
    let status = resp.status();
    let body = resp.text().await.context("reading exchange body")?;
    if !status.is_success() {
        bail!("ticket exchange returned {status}: {body}");
    }
    let parsed: SessionResponse =
        serde_json::from_str(&body).with_context(|| format!("parsing exchange json: {body}"))?;
    if parsed.ticket.is_empty() {
        bail!("ticket exchange returned no ticket: {body}");
    }
    Ok(to_auth(parsed))
}

/// Upgrade a bare captured ticket into a full session for our own app id.
/// Falls back to the bare ticket if Ubisoft refuses the exchange, so a capture
/// that used to work still works.
pub async fn upgrade_captured_ticket(ticket: &str, session_id: &str) -> Auth {
    match exchange_session(ticket, UBI_APP_ID).await {
        Ok(mut full) => {
            if full.session_id.is_empty() {
                full.session_id = session_id.to_string();
            }
            if full.remember_me_ticket.is_empty() {
                eprintln!(
                    "[auth] note: Ubisoft returned no rememberMe ticket; \
                     `refresh` will not work for this session"
                );
            }
            full
        }
        Err(e) => {
            eprintln!("[auth] could not upgrade the captured ticket ({e}); storing it as-is");
            Auth {
                ticket: ticket.to_string(),
                session_id: session_id.to_string(),
                ..Default::default()
            }
        }
    }
}

/// Exchange a valid `ubi_v1` ticket for one scoped to `app_id`. Because this is
/// authorized by an existing ticket (not a password), DataDome generally lets it
/// through where a fresh login would be blocked.
pub async fn exchange_for_app(ticket: &str, app_id: &str) -> Result<String> {
    let resp = client()?
        .post(SESSIONS_URL)
        .header("Content-Type", "application/json")
        .header("Ubi-AppId", app_id)
        .header("Ubi-RequestedPlatformType", "uplay")
        .header("Authorization", format!("ubi_v1 t={ticket}"))
        .json(&serde_json::json!({ "rememberMe": true }))
        .send()
        .await
        .context("sending ticket-exchange request")?;
    let status = resp.status();
    let body = resp.text().await.context("reading exchange body")?;
    if !status.is_success() {
        bail!("ticket exchange returned {status}: {body}");
    }
    let parsed: SessionResponse =
        serde_json::from_str(&body).with_context(|| format!("parsing exchange json: {body}"))?;
    if parsed.ticket.is_empty() {
        bail!("ticket exchange returned no ticket: {body}");
    }
    Ok(parsed.ticket)
}

/// Refresh an expired session without a password, using the stored rememberMe
/// ticket. UbiServices treats a POST authorized with the rememberMe ticket as a
/// silent re-login.
pub async fn refresh(auth: &Auth) -> Result<Auth> {
    if auth.remember_me_ticket.is_empty() {
        bail!("no rememberMe ticket stored; run `optima-cli login` again");
    }
    let resp = client()?
        .post(SESSIONS_URL)
        .header("Content-Type", "application/json")
        .header("Ubi-AppId", UBI_APP_ID)
        .header("Ubi-RequestedPlatformType", "uplay")
        .header("Authorization", format!("rm_v1 t={}", auth.remember_me_ticket))
        .json(&serde_json::json!({ "rememberMe": true }))
        .send()
        .await
        .context("sending refresh request")?;

    match parse_session(resp).await? {
        LoginOutcome::Session(a) => Ok(a),
        LoginOutcome::TwoFactorRequired { .. } => {
            bail!("refresh unexpectedly asked for 2FA; run `optima-cli login` again")
        }
    }
}

/// Live-verify the stored session by fetching the caller's own profile. Returns
/// the HTTP status + raw body so callers can both confirm validity and surface
/// UbiServices' response. This is the P0 end-to-end proof: a 200 means our
/// ticket + session headers authorize real API calls.
pub async fn fetch_me(auth: &Auth) -> Result<(reqwest::StatusCode, String)> {
    let resp = client()?
        .get("https://public-ubiservices.ubi.com/v3/profiles/me")
        .header("Ubi-AppId", UBI_APP_ID)
        .header("Ubi-RequestedPlatformType", "uplay")
        .header("Ubi-SessionId", &auth.session_id)
        .header("Authorization", format!("ubi_v1 t={}", auth.ticket))
        .send()
        .await
        .context("sending profile request")?;
    let status = resp.status();
    let body = resp.text().await.context("reading profile body")?;
    Ok((status, body))
}

async fn parse_session(resp: reqwest::Response) -> Result<LoginOutcome> {
    let status = resp.status();
    let body = resp.text().await.context("reading response body")?;

    if !status.is_success() {
        // Surface the server's own error text — UbiServices returns a JSON
        // `{ "message": ... , "errorCode": ... }` we want to see verbatim.
        return Err(anyhow!("UbiServices returned {status}: {body}"));
    }

    let parsed: SessionResponse =
        serde_json::from_str(&body).with_context(|| format!("parsing session json: {body}"))?;

    let tfa = parsed
        .two_factor_authentication_ticket
        .as_deref()
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    if let Some(tfa) = tfa {
        // A 2FA-gated account: no real ticket yet, just the challenge ticket.
        if parsed.ticket.is_empty() {
            return Ok(LoginOutcome::TwoFactorRequired { ticket: tfa });
        }
    }

    if parsed.ticket.is_empty() {
        bail!("login succeeded ({status}) but no ticket in response: {body}");
    }
    Ok(LoginOutcome::Session(to_auth(parsed)))
}
