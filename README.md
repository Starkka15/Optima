# Optima

**An ownership-backed Ubisoft Connect driver for Linux.** Optima logs into *your*
Ubisoft account, lists the games *you own*, downloads them from Ubisoft's *own*
CDN, and launches them through the **official Ubisoft Connect client** under
Proton. It's the Ubisoft analog of a Linux-friendly store client, built for the
interop / Steam Deck & handheld case.

It talks to Ubisoft's real services with your real credentials and your real
entitlements. Optima does the parts Connect can't do headless (game list,
downloads with progress, resume) and leaves sign-in, ownership, DRM and launch to
Ubisoft's own client.

## What this is — and what it is NOT

**Optima is not a piracy tool.** It is deliberately built so it can *only* touch
games you actually own:

- **It authenticates as you.** Every request carries a session ticket minted by
  Ubisoft from your own login. There is no credential sharing, no token farm.
- **Ownership is enforced by Ubisoft, not faked.** The game list comes from
  Ubisoft's ownership service (`dmx.upc.ubisoft.com`); a title only appears — and
  can only be downloaded — if Ubisoft says your account entitles it. There is no
  "unlock everything" mode.
- **Downloads come from Ubisoft's CDN**, using download tokens Ubisoft issues to
  your session. Optima hosts no game data and redistributes nothing.
- **It does not touch DRM.** Games are started by the official Ubisoft Connect
  client, which does its own ownership and DRM checks exactly as on Windows.
  Optima ships no DRM replacement (earlier versions did; see
  [Launching](#launching-through-ubisoft-connect)).

If you don't own a game, Optima can't list it, can't download it, and won't
launch it. That's the whole point.

## Why Optima pairs with the official Ubisoft Connect client

Optima used to launch games on its own, by swapping Ubisoft's loader DLLs in
each game folder for compatibility shims. It worked, but it was a hack. Optima
now hands every launch to **Ubisoft's own Connect client**, and that is more
secure and much less hacky:

| | Old shim launch | Optima + official Connect |
|---|---|---|
| **Sign-in** | Optima's ticket, fed to the shims | Ubisoft's own login inside Connect, including 2FA |
| **Ownership and DRM** | Answered locally by the shims ("you own this") | Checked by Ubisoft, exactly as on Windows |
| **Game files** | Ubisoft's DLLs replaced with third-party ones | Untouched (only the EAX audio fix below, removed when the game exits) |
| **Proton prefix** | Trusted a self-signed Optima certificate | A separate prefix with no Optima certificate in it |
| **Refunds, revoked or expired licenses** | Not seen by the shims | Enforced by Ubisoft |

Optima still does what Connect can't do from Game Mode: list your library,
download with progress and resume, and set the game up so Connect sees it as
installed. Sign-in, ownership, DRM and launch belong to Ubisoft's client.

## What leaves your machine

Only requests to **Ubisoft's own endpoints**:

- `public-ubiservices.ubi.com` — login / session tickets (UbiServices)
- `dmx.upc.ubisoft.com` — ownership + download services (the Demux protobuf API)
- `*.cdn.ubi.com` / `uplaypc-s-ubisoft.cdn.ubi.com` — game files
- `connect.ubisoft.com` — Ubisoft's login page, opened in Steam's browser
- `static3.cdn.ubi.com` — the official Ubisoft Connect installer

The Ubisoft Connect client itself, once installed, talks to Ubisoft as it does
on Windows.

There is **no Optima server**, no telemetry, no third party. Your session ticket
is stored locally in `~/.local/share/optima/` (mode `0600`)
and never sent anywhere except Ubisoft. Read the source — it's all here.

## How it works

| Stage | What happens |
|-------|--------------|
| **Auth** | `optima-cli login --steam` opens **Ubisoft's real login page** (`connect.ubisoft.com`) in Steam's own browser — the overlay browser in Game Mode, with the on-screen keyboard and 2FA. After you sign in, Optima reads the session Ubisoft's page stores (ticket, session id, rememberMe ticket) through Steam's browser debugger and closes the tab, as Lutris does with its own window. Renewed silently via the rememberMe ticket. |
| **Library** | The Demux ownership service returns your owned products (each with an embedded configuration blob: real title, launch exe, Uplay app id). |
| **Download** | An ownership token → a download-service session → signed CDN URLs. Manifests and slices are fetched, decompressed, verified and written to disk, with resume + reconnect for large titles. At the end Optima writes Connect's own install records (`uplay_install.manifest`, `uplay_install.state`) so the official client sees the game as installed. |
| **Launch** | The official Ubisoft Connect client (installed once into its own Proton prefix) starts the game through its `uplay://launch/<id>/0` handler. Optima registers the install with it first, including the registry keys the game's installer would set. |

The protobuf wire formats were reverse-engineered by the
[YoobieRE](https://github.com/YoobieRE) project (Optima's `proto/` schemas derive
from their work); Optima is an independent Rust reimplementation of the client.

## Launching through Ubisoft Connect

The first launch installs Ubisoft Connect from Ubisoft's CDN into
`~/.local/share/optima/connect-prefix` (with the fonts and D3D compiler it
needs, and its overlay off) and asks you to sign in to it once. After that,
`optima-cli launch` registers the game with Connect and has Connect start it;
Optima stays running until the game exits, then closes Connect. Connect's own
offline mode works as usual.

The one thing Optima still puts in a game folder is an **EAX** shim (`eax.dll`,
source in `drm/eax/`): classic titles (Beyond Good & Evil, Splinter Cell) demand
Creative EAX, which doesn't exist under Proton, so the shim forwards
`EAXDirectSoundCreate8` to plain DirectSound. It is an audio fix, not DRM, and
it is taken out again when the game exits. Rebuild it with:

```bash
cd drm/eax && i686-w64-mingw32-gcc -shared -O2 -o eax.dll eax_stub.c eax.def -static-libgcc
```

Earlier versions launched games without Connect by replacing Ubisoft's loader
DLLs with compatibility shims. Those are gone; on first launch Optima removes
anything they left in a game folder and puts the game's own DLLs back.
`drm/signing/optima-signing.cer` remains only so those old files can be
recognized.

The approach (official client in its own prefix, seeding a folder Connect will
accept) follows research by
[xXJSONDeruloXx/ubi-cli-mvp](https://github.com/xXJSONDeruloXx/ubi-cli-mvp); the
install-state layout comes from [UplayDB/Protobufs](https://github.com/UplayDB/Protobufs).

## Building

Requires Rust (stable) and `protoc` (Protocol Buffers compiler) for the build
script.

```bash
# Debian/Ubuntu: sudo apt install protobuf-compiler
cargo build --release
# -> target/release/optima-cli
```

For a portable binary that runs on SteamOS / older glibc, build static musl:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Usage

```bash
optima-cli login --steam              # sign in on Ubisoft's page in Steam (one time)
optima-cli list-games                 # your owned, installable games
optima-cli install <product_id>       # download from Ubisoft's CDN
optima-cli launch <product_id>        # start it through Ubisoft Connect
optima-cli settings <product_id>      # run a game's settings/config app (resolution, etc.)
optima-cli connect signin             # install Connect if needed, sign in, close it when done
optima-cli connect status             # Connect installed / signed in / registered games
optima-cli whoami                     # show + verify the stored session
```

`login`, session storage, and refresh all use your own Ubisoft account. Nothing
is shared or centralized.

> **`login --steam` needs Steam running with its browser debugger on.** Decky
> Loader turns it on, so it is always on for GameVault users. Elsewhere, create
> `~/.steam/steam/.cef-enable-remote-debugging` and restart Steam. Without Steam,
> `login --ticket` stores a ticket copied from a browser's developer tools.

> **Switching accounts:** signing out of Optima doesn't sign you out of Ubisoft
> in Steam's browser, so the next `login --steam` signs the same account straight
> back in. To change accounts, sign out on Ubisoft's page in Steam's browser
> first.

## Handheld / Steam Deck

Optima powers the **Ubisoft Connect ("Optima") extension** for
[GameVault](https://github.com/Starkka15/GameVault) (a Decky plugin fork), which
gives you a Game-Mode UI to log in, install, and launch — no desktop mode.

## Credits & prior art

- [YoobieRE](https://github.com/YoobieRE) — Ubisoft Demux / manifest / install
  protocol reversing (the basis for `proto/`)
- [xXJSONDeruloXx/ubi-cli-mvp](https://github.com/xXJSONDeruloXx/ubi-cli-mvp) —
  the official-Connect launch research and the hardening review
- [UplayDB/Protobufs](https://github.com/UplayDB/Protobufs) — Connect's
  `uplay_install.state` layout
- [Re0xCat/uplay-r1-loader](https://github.com/Re0xCat/uplay-r1-loader) and
  [Re0xCat/ubiorbitapi-r2-loader](https://github.com/Re0xCat/ubiorbitapi-r2-loader)
  — the compatibility shims earlier versions used
- [Open-Wine-Components/umu-launcher](https://github.com/Open-Wine-Components/umu-launcher)
  — the Proton runtime launcher

## Legal

Optima is an interoperability tool for accessing games you have lawfully
purchased, on a platform of your choice. You are responsible for complying with
the Ubisoft Terms of Service and the laws of your jurisdiction. It is not
affiliated with, endorsed by, or supported by Ubisoft. "Ubisoft", "Uplay", and
"Ubisoft Connect" are trademarks of Ubisoft Entertainment.

Licensed under the [GNU General Public License v3.0 or later](LICENSE). If you
fork Optima, any changes you distribute must also be released under the GPL —
please contribute fixes back.

## AI Disclosure

This project is developed with AI assistance. See **[AI.md](AI.md)** for how AI is used
here, the ethical obligations behind it, and how upstream credit and licensing are handled.
