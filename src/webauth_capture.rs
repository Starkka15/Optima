//! User-friendly unified login. One local page, one browser session, everything
//! captured in the right order:
//!   1. Our own form collects **email + password** — the two values Ubisoft's
//!      cross-origin login never exposes to us, and that the Uplay emu needs for
//!      each game's `Uplay.toml`. Stored to `profile.toml`.
//!   2. We embed Ubisoft's official **WebAuth SDK** (`connectSdkPublic.js`) and
//!      call `getTicket()`. The SDK's hidden `sdk.html` iframe (on
//!      connect.ubisoft.com) is the only thing that can read the SSO session and
//!      hand back a ticket. That iframe's storage is normally blocked as a
//!      third-party — so we serve THIS page from `localhost.ubisoft.com` (a real
//!      Ubisoft-published hostname that resolves to 127.0.0.1, like `lvh.me`).
//!      Then our page and the iframe are **same-site** (both `ubisoft.com`) and
//!      the iframe gets full storage access — exactly Ubisoft's own dev setup
//!      (`https://localhost.ubisoft.com:50000`). No devtools, works in gaming
//!      mode. First launch the user signs in via a popup (`logged-in.html`,
//!      the only whitelisted nextUrl); after that the stored SSO session +
//!      rememberMe refresh keep it silent.
//!   3. With the ticket we fetch `/v3/profiles/me` and fill in the **username**
//!      (`nameOnPlatform`) automatically — the user never types it.
//! OPTIMA_DEBUG logs each request.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::{self, Auth};

const PORT: u16 = 31034;
// We bind 127.0.0.1 but the browser must reach us as `localhost.ubisoft.com` so
// the page is same-site with the connect.ubisoft.com SDK iframe. Ubisoft
// publishes a public A record for it → 127.0.0.1 (no /etc/hosts edit needed).
const HOST: &str = "localhost.ubisoft.com";
// connect.ubisoft.com's WebAuth needs BOTH an appId and a genomeId (and lang).
// These are the public constants the live login page uses. The ticket the SDK
// mints is exchanged for the Demux app id downstream (auth::exchange_for_app),
// so the specific appId here only has to be one connect.ubisoft.com accepts.
const APP_ID: &str = "f35adcb5-1911-440c-b1c9-48fdc1701c68";
const GENOME_ID: &str = "5b36b900-65d8-47f3-93c8-86bdaa48ab50";
// The official WebAuth SDK (found referenced from connect.ubisoft.com/logged-in.html).
const SDK_URL: &str =
    "https://ubistatic2-a.ubisoft.com/uplay-connect/v3/prod/default/sdk/connectSdkPublic.js";

/// What a single loopback request turned out to be.
enum Action {
    /// Served a page (form or the /back bounce). Keep listening.
    Served,
    /// The form posted the player's email + password.
    Profile { email: String, password: String },
    /// Ubisoft redirected back with the ticket.
    Ticket(String),
}

/// A self-signed TLS acceptor for `localhost.ubisoft.com`. HTTPS is REQUIRED:
/// connect.ubisoft.com's WebAuth SDK validates the embedding domain, and in PROD
/// its `extractHostName` only parses `https://` origins — an http:// origin is
/// mis-read (→ hostname "http") and rejected as `invalidDomain`. Over https the
/// origin resolves to `localhost.ubisoft.com` → a `ubisoft.com` root domain →
/// valid + primary. Cert is generated once and cached so the browser exception
/// (self-signed) only has to be accepted a single time.
fn tls_acceptor() -> Result<TlsAcceptor> {
    // rustls needs a crypto provider; install ring (ignore if already installed).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = config::data_dir()?.join("tls");
    std::fs::create_dir_all(&dir).ok();
    let cert_path = dir.join("localhost-ubisoft.cert.der");
    let key_path = dir.join("localhost-ubisoft.key.der");

    let (cert_der, key_der): (Vec<u8>, Vec<u8>) =
        match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            (Ok(c), Ok(k)) if !c.is_empty() && !k.is_empty() => (c, k),
            _ => {
                let cert = rcgen::generate_simple_self_signed(vec![
                    "localhost.ubisoft.com".to_string(),
                    "localhost".to_string(),
                ])
                .context("generating self-signed cert")?;
                let c = cert.cert.der().to_vec();
                let k = cert.key_pair.serialize_der();
                let _ = std::fs::write(&cert_path, &c);
                let _ = std::fs::write(&key_path, &k);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
                }
                (c, k)
            }
        };

    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls server config")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub async fn run() -> Result<()> {
    let acceptor = tls_acceptor()?;
    let listener = TcpListener::bind(("127.0.0.1", PORT))
        .await
        .with_context(|| format!("binding 127.0.0.1:{PORT}"))?;
    // The popup's nextUrl MUST be a Ubisoft-whitelisted URL — logged-in.html is
    // the one the SDK is built around. It postMessages the session up to our
    // same-site sdk.html iframe, which then answers getTicket().
    let logged_in = format!(
        "https://connect.ubisoft.com/logged-in.html?appId={APP_ID}&lang=en-US&genomeId={GENOME_ID}"
    );
    let login_url = format!(
        "https://connect.ubisoft.com/login?appId={APP_ID}&genomeId={GENOME_ID}&lang=en-US&nextUrl={}",
        urlencode(&logged_in)
    );

    // Open OUR page first (the email/password form), not Ubisoft directly — and
    // via the localhost.ubisoft.com name so the SDK iframe is same-site with us.
    let start = format!("https://{HOST}:{PORT}/");
    if let Ok(browser) = std::env::var("BROWSER") {
        let _ = std::process::Command::new(browser).arg(&start).spawn();
    } else if let Err(e) = open::that(&start) {
        eprintln!("Open this in your browser: {start}  ({e})");
    }

    println!("A browser tab opened to the Optima sign-in form ({start}).");
    println!("If it didn't open, paste that URL into a browser (the localhost.ubisoft.com name matters).");
    println!("First time: the browser warns about a self-signed certificate — click Advanced → proceed. It's your own local server.");
    println!("Enter your Ubisoft email + password, then authorize with Ubisoft — Optima does the rest.");

    let mut ticket: Option<String> = None;
    loop {
        let (socket, _) = listener.accept().await?;
        let mut socket = match acceptor.accept(socket).await {
            Ok(s) => s,
            Err(e) => {
                if std::env::var_os("OPTIMA_DEBUG").is_some() {
                    eprintln!("[tls] handshake failed: {e}");
                }
                continue;
            }
        };
        match handle(&mut socket, &login_url).await? {
            Action::Served => {}
            Action::Profile { email, password } => {
                let mut p = config::load_profile().unwrap_or_default();
                p.email = email;
                p.password = password;
                config::save_profile(&p)?;
                if std::env::var_os("OPTIMA_DEBUG").is_some() {
                    eprintln!("[profile] stored email + password");
                }
            }
            Action::Ticket(t) => {
                ticket = Some(t);
                break;
            }
        }
    }

    let ticket = ticket.expect("loop only breaks with a ticket");
    println!("[login] ticket captured ({} chars) — resolving your profile…", ticket.len());
    let mut auth = Auth {
        ticket,
        ..Default::default()
    };

    // Recover the username (and profile id) from the ticket — no typing needed.
    match crate::auth::fetch_me(&auth).await {
        Ok((status, body)) if status.is_success() => {
            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(n) = j.get("nameOnPlatform").and_then(|x| x.as_str()) {
                    auth.name_on_platform = n.to_string();
                    let mut p = config::load_profile().unwrap_or_default();
                    p.username = n.to_string();
                    let _ = config::save_profile(&p);
                }
                if let Some(id) = j.get("profileId").and_then(|x| x.as_str()) {
                    auth.profile_id = id.to_string();
                }
            }
        }
        _ => {
            println!("(Signed in; couldn't auto-fetch your username yet — it'll resolve on first launch.)");
        }
    }

    config::save_auth(&auth)?;
    if auth.name_on_platform.is_empty() {
        println!("Signed in — ticket + credentials captured. Run `optima-cli list-games`.");
    } else {
        println!(
            "Signed in as {} — ticket + credentials captured. Run `optima-cli list-games`.",
            auth.name_on_platform
        );
    }
    Ok(())
}

async fn handle<S>(socket: &mut S, login_url: &str) -> Result<Action>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read the whole request. A single read over TLS can return just the
    // headers (or a partial body) — the POST /ticket body carries a ~1-2 KB
    // ticket that may land in a later record. Keep reading until we have the
    // full body per Content-Length, or the peer stops.
    let mut data: Vec<u8> = Vec::with_capacity(8192);
    let mut buf = [0u8; 8192];
    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(hdr_end) = find_subslice(&data, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..hdr_end]);
            let clen = content_length(&head);
            let body_have = data.len() - (hdr_end + 4);
            if body_have >= clen {
                break; // full request in hand
            }
        }
        if data.len() > 1_048_576 {
            break; // sanity guard
        }
    }
    if data.is_empty() {
        return Ok(Action::Served);
    }
    let req = String::from_utf8_lossy(&data);
    let line = req.lines().next().unwrap_or("");
    if std::env::var_os("OPTIMA_DEBUG").is_some() {
        eprintln!("[login] {line}");
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path_and_query = parts.next().unwrap_or("/");
    let path = path_and_query.split('?').next().unwrap_or("/");

    // POST /profile — the form submitting email + password.
    if method == "POST" && path == "/profile" {
        let body = req.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let (mut email, mut password) = (String::new(), String::new());
        for pair in body.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "email" => email = urldecode(v),
                    "password" => password = urldecode(v),
                    _ => {}
                }
            }
        }
        send(socket, "200 OK", "text/plain", "ok").await;
        return Ok(Action::Profile { email, password });
    }

    // POST /ticket — the SDK page delivering the captured ticket (primary path).
    if method == "POST" && path == "/ticket" {
        let body = req.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let mut ticket = String::new();
        for pair in body.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "ticket" {
                    ticket = urldecode(v);
                }
            }
        }
        if ticket.trim().len() >= 40 {
            send(socket, "200 OK", "text/plain", "ok").await;
            return Ok(Action::Ticket(ticket.trim().to_string()));
        }
        if std::env::var_os("OPTIMA_DEBUG").is_some() {
            eprintln!(
                "[login] /ticket POST but body had no usable ticket (len={})",
                ticket.trim().len()
            );
        }
        send(socket, "400 Bad Request", "text/plain", "no ticket").await;
        return Ok(Action::Served);
    }

    // GET /back — legacy redirect carrying the ticket (query or #fragment).
    if path == "/back" {
        if let Some(t) = extract_ticket(path_and_query) {
            send(
                socket,
                "200 OK",
                "text/html; charset=utf-8",
                "<h2>Signed in — return to Optima. You can close this tab.</h2>",
            )
            .await;
            return Ok(Action::Ticket(t));
        }
        // Ticket may be in the URL #fragment (server can't see it) → bounce it up.
        send(
            socket,
            "200 OK",
            "text/html; charset=utf-8",
            r#"<html><body><script>
            if (location.hash && location.hash.length > 1) {
              location.replace('/back?' + location.hash.substring(1));
            } else { document.write('<h2>Waiting for Ubisoft… complete sign-in in this tab.</h2>'); }
            </script></body></html>"#,
        )
        .await;
        return Ok(Action::Served);
    }

    // GET / (anything else) — serve the login page.
    let page = FORM_PAGE
        .replace("__APP_ID__", &json_string(APP_ID))
        .replace("__GENOME_ID__", &json_string(GENOME_ID))
        .replace("__SDK_URL__", SDK_URL)
        .replace("__LOGIN_URL__", &json_string(login_url));
    send(socket, "200 OK", "text/html; charset=utf-8", &page).await;
    Ok(Action::Served)
}

async fn send<S>(socket: &mut S, status: &str, content_type: &str, body: &str)
where
    S: AsyncWrite + Unpin,
{
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = socket.write_all(resp.as_bytes()).await;
    // Over TLS the response sits in the rustls write buffer until flushed; and a
    // clean shutdown sends close_notify so the browser sees the full body.
    let _ = socket.flush().await;
    let _ = socket.shutdown().await;
}

const FORM_PAGE: &str = r#"<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Optima — Sign in</title><style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#15151a;color:#ececf1;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:1rem}
.card{background:#20202a;padding:2rem;border-radius:14px;width:360px;box-shadow:0 10px 40px rgba(0,0,0,.5);border:1px solid #2e2e3a}
h1{font-size:1.25rem;margin:0 0 .4rem} p{color:#9a9aa8;font-size:.85rem;line-height:1.4;margin:0 0 1.2rem}
label{display:block;font-size:.78rem;letter-spacing:.02em;text-transform:uppercase;margin:.9rem 0 .3rem;color:#b9b9c6}
input{width:100%;padding:.6rem .7rem;border:1px solid #363644;border-radius:8px;background:#15151a;color:#ececf1;font-size:.95rem}
input:focus{outline:none;border-color:#e8622c}
button{width:100%;margin-top:1.2rem;padding:.7rem;border:0;border-radius:8px;background:#e8622c;color:#fff;
font-weight:600;font-size:.95rem;cursor:pointer}
button:hover{background:#f0723c} button:disabled{opacity:.5;cursor:default}
button.alt{background:#2e2e3a;color:#ececf1} button.alt:hover{background:#3a3a48}
.note{margin-top:1rem;font-size:.72rem;color:#6f6f80;text-align:center}
#log{margin-top:1rem;background:#0e0e12;border:1px solid #2a2a34;border-radius:8px;padding:.6rem .7rem;
font:12px/1.45 ui-monospace,Menlo,Consolas,monospace;color:#8fbf8f;white-space:pre-wrap;max-height:180px;overflow:auto}
details{margin-top:1rem} summary{cursor:pointer;font-size:.78rem;color:#8a8a98}
textarea{width:100%;height:64px;margin-top:.5rem;padding:.5rem;border:1px solid #363644;border-radius:8px;
background:#15151a;color:#ececf1;font:12px ui-monospace,monospace}
</style></head><body>
<div class=card>
<form id=stage1 onsubmit="go(event)">
<h1>Sign in to Ubisoft</h1>
<p>Optima stores your email &amp; password locally to present your account to games, then gets a session ticket from Ubisoft. Your username fills in automatically.</p>
<label for=email>Ubisoft email</label>
<input id=email name=email type=email autocomplete=username autofocus required>
<label for=password>Password</label>
<input id=password name=password type=password autocomplete=current-password required>
<button id=btn type=submit>Continue &rarr;</button>
<div class=note>Password is stored locally only — never sent anywhere but the game.</div>
</form>
<div id=stage2 style="display:none">
<h1>Authorizing…</h1>
<p>Getting your Ubisoft session ticket. If prompted, sign in — the window closes itself.</p>
<button id=signin class=alt style="display:none" onclick="popupLogin()">Sign in to Ubisoft</button>
<div id=log></div>
<details><summary>Having trouble? Paste a ticket manually</summary>
<textarea id=paste placeholder="ubi_v1 ticket…"></textarea>
<button class=alt onclick="usePaste()">Use pasted ticket</button>
</details>
</div>
</div>
<script src="__SDK_URL__"></script>
<script>
const APP_ID=__APP_ID__, GENOME_ID=__GENOME_ID__, LOGIN_URL=__LOGIN_URL__;
const NEXT='https://connect.ubisoft.com/logged-in.html?appId='+APP_ID+'&lang=en-US&genomeId='+GENOME_ID;
let sdkInst=null, delivered=false;
function log(m){var el=document.getElementById('log');if(el){el.textContent+=m+'\n';el.scrollTop=el.scrollHeight;}}
function initSdk(){
  if(!window.Connect||!window.Connect.init){log('Loading SDK…');return void setTimeout(initSdk,300);}
  log('page origin: '+location.origin);
  log('Initializing Ubisoft WebAuth SDK…');
  try{
    window.Connect.init({env:'PROD',appId:APP_ID,genomeId:GENOME_ID,lang:'en-US',
      nextUrl:NEXT,thirdPartyCookiesSupport:true,localLoginExpirationMinutes:10});
  }catch(e){log('init threw → '+e);}
  try{
    log('Connect keys: '+Object.keys(window.Connect).join(','));
    log('Connect.sdk: '+(window.Connect.sdk?('yes, '+(window.Connect.sdk.constructor&&window.Connect.sdk.constructor.name)):'MISSING'));
  }catch(e){log('inspect threw → '+e);}
  if(window.Connect.sdk&&window.Connect.sdk.subscribe){
    window.Connect.sdk.subscribe(function(sdk){if(!sdk)return;sdkInst=sdk;log('SDK ready.');attempt();});
  }else{log('⚠ Connect.sdk has no subscribe — SDK shape unexpected.');}
  // Watchdog: if the iframe never reports ready, surface the manual path.
  setTimeout(function(){
    if(!sdkInst&&!delivered){log('⚠ No "SDK ready" after 8s — iframe likely not booting. Try Sign in, or check for blocked cookies.');showLogin();}
  },8000);
}
function attempt(){
  if(delivered||!sdkInst)return;
  log('Requesting ticket…');
  try{
    sdkInst.getTicket().subscribe(function(res){
      log('getTicket → '+JSON.stringify(res));
      var t=res&&(res.ticket||(res.payload&&res.payload.ticket));
      if(t)deliver(t); else showLogin();
    },function(err){log('getTicket error → '+JSON.stringify(err));showLogin();});
  }catch(e){log('getTicket threw → '+e);showLogin();}
}
function showLogin(){var b=document.getElementById('signin');if(b)b.style.display='block';}
function popupLogin(){
  log('Opening Ubisoft sign-in…');
  var w=window.open(LOGIN_URL,'ubilogin','width=520,height=800');
  var iv=setInterval(function(){
    if(w&&w.closed){clearInterval(iv);log('Sign-in window closed — re-checking…');setTimeout(attempt,700);}
  },700);
}
window.addEventListener('message',function(e){
  var d=e.data;
  // Diagnostic: surface any message from a ubisoft origin so we can see the
  // iframe handshake (ready / status) even without devtools.
  if(/ubisoft/.test(e.origin||'')){
    var s; try{s=typeof d==='string'?d:JSON.stringify(d);}catch(_){s='[unserializable]';}
    if(s&&s.length<300) log('msg ‹'+e.origin+'›: '+s);
  }
  if(d&&(d.topic==='ubisoftConnect@LOGGED_IN'||(d.data&&d.data.txt==='ubisoftConnect@LOGGED_IN'))){
    log('Detected sign-in — fetching ticket…');setTimeout(attempt,500);
  }
});
async function deliver(ticket){
  if(delivered)return; delivered=true;
  log('Ticket captured ('+ticket.length+' chars). Saving…');
  var r;
  try{r=await fetch('/ticket',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({ticket:ticket}).toString()});}catch(e){log('save failed → '+e);delivered=false;return;}
  if(!r.ok){log('server rejected ticket (HTTP '+r.status+') — will retry');delivered=false;return;}
  document.getElementById('stage2').innerHTML='<h1>Signed in ✓</h1><p>Credentials + ticket captured. Return to Optima — you can close this tab.</p>';
}
async function go(e){
  e.preventDefault();
  var btn=document.getElementById('btn');btn.disabled=true;btn.textContent='Saving…';
  var email=document.getElementById('email').value.trim();
  var password=document.getElementById('password').value;
  try{await fetch('/profile',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({email:email,password:password}).toString()});}catch(_){}
  document.getElementById('stage1').style.display='none';
  document.getElementById('stage2').style.display='block';
  initSdk();
}
function usePaste(){
  var t=document.getElementById('paste').value.trim();
  if(t.length>=40)deliver(t); else log('Pasted value too short to be a ticket.');
}
</script></body></html>"#;

/// First index of `needle` in `hay`.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse the `Content-Length` header value from a request head (0 if absent).
fn content_length(head: &str) -> usize {
    for l in head.lines() {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Look for a ticket in the redirect's query/fragment params.
fn extract_ticket(path_and_query: &str) -> Option<String> {
    let qs = path_and_query.split_once('?').map(|(_, q)| q)?;
    for pair in qs.split(['&', ';']) {
        if let Some((k, v)) = pair.split_once('=') {
            let k = k.trim().to_lowercase();
            if matches!(k.as_str(), "ticket" | "token" | "t" | "code" | "id_token" | "access_token")
                && v.len() >= 40
            {
                return Some(urldecode(v));
            }
        }
    }
    None
}

/// Minimal JSON string literal (for injecting the login URL into the page).
fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
