# Optima

**An ownership-backed Ubisoft Connect client for Linux.** Optima logs into *your*
Ubisoft account, lists the games *you own*, downloads them from Ubisoft's *own*
CDN, and launches them under Proton — no Ubisoft Connect launcher required. It's
the Ubisoft analog of a Linux-friendly store client, built for the interop /
Steam Deck & handheld case.

It talks to Ubisoft's real services with your real credentials and your real
entitlements. Think of it as a headless, scriptable replacement for the Ubisoft
Connect PC app on a platform Ubisoft doesn't ship one for.

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
- **It does NOT crack DRM.** It does not defeat Denuvo or any modern anti-tamper;
  Denuvo-wrapped titles are explicitly out of scope. What it *does* provide is a
  minimal **Uplay R1 compatibility shim** so that older single-player titles
  which expect the Ubisoft Connect overlay to be present will boot offline once
  you already own and have downloaded them (see [DRM shim](#drm-shim) below).

If you don't own a game, Optima can't list it, can't download it, and won't
launch it. That's the whole point.

## What leaves your machine

Only requests to **Ubisoft's own endpoints**:

- `public-ubiservices.ubi.com` — login / session tickets (UbiServices)
- `dmx.upc.ubisoft.com` — ownership + download services (the Demux protobuf API)
- `*.cdn.ubi.com` / `uplaypc-s-ubisoft.cdn.ubi.com` — game files
- `connect.ubisoft.com` / `ubistatic*.ubisoft.com` — the WebAuth SDK used for the
  browser login

There is **no Optima server**, no telemetry, no third party. Your session ticket
and account profile are stored locally in `~/.local/share/optima/` (mode `0600`)
and never sent anywhere except Ubisoft. Read the source — it's all here.

## How it works

| Stage | What happens |
|-------|--------------|
| **Auth** | `optima-cli login --local` hosts a tiny local HTTPS page that embeds Ubisoft's official **WebAuth SDK** and captures a `ubi_v1` session ticket the same way the web login does. Works in any browser, no devtools. Renewed silently via the rememberMe ticket. |
| **Library** | The Demux ownership service returns your owned products (each with an embedded configuration blob: real title, launch exe, Uplay app id). |
| **Download** | An ownership token → a download-service session → signed CDN URLs. Manifests and slices are fetched, decompressed, and written to disk, with resume + reconnect for large titles. |
| **Launch** | Optima writes the Uplay config, deploys the R1 shim into the game folder, seeds the required registry keys, and runs the game exe under Proton (via `umu`). |

The protobuf wire formats were reverse-engineered by the
[YoobieRE](https://github.com/YoobieRE) project (Optima's `proto/` schemas derive
from their work); Optima is an independent Rust reimplementation of the client.

## DRM shims

Older Ubisoft single-player titles load a folder-local Ubisoft loader DLL and
expect it to answer a small set of ownership/overlay calls. Optima ships
compatibility shims that answer those calls for a game **you own and have already
downloaded**, so it boots without the Ubisoft Connect launcher running. They do
**not** bypass any cryptographic license check and do nothing for titles you
don't own. `optima-cli launch` auto-detects which shim a game needs from its exe
imports and deploys the matching one:

- **Uplay R1** (`uplay_r1_loader.dll`, flat `UPLAY_*` C API) — e.g. AC4 Black Flag.
  Built from **[Re0xCat/uplay-r1-loader](https://github.com/Re0xCat/uplay-r1-loader)**;
  prebuilt DLLs in `drm/uplay_r1/`. Games that import `upc_r1_loader.dll` (same API)
  get a copy of this one under that name.
- **Orbit R2** (`ubiorbitapi_r2_loader.dll`, the C++ `OrbitClient` class) — e.g.
  Assassin's Creed III. Vendored (with fixes) in `drm/orbit_r2/source/`, prebuilt
  DLL in `drm/orbit_r2/`. Based on
  [Re0xCat/ubiorbitapi-r2-loader](https://github.com/Re0xCat/ubiorbitapi-r2-loader),
  with a corrected `__thiscall` invocation (the listener callbacks were reaching
  the game with a null `this`) and asynchronous callback delivery from `Update()`.
- **EAX** (`eax.dll`) — classic titles (Beyond Good & Evil, Splinter Cell) demand
  Creative EAX, which doesn't exist under Proton. Our shim (source in `drm/eax/`)
  forwards `EAXDirectSoundCreate8` to plain DirectSound so the check passes.

All shims are embedded into `optima-cli` at compile time (via `include_bytes!`),
so a normal `cargo build` works without a Windows cross-toolchain. To rebuild and
verify them yourself:

```bash
# Uplay R1 (mingw):
git clone https://github.com/Re0xCat/uplay-r1-loader && cd uplay-r1-loader
cargo build --release --target i686-pc-windows-gnu     # -> loader.dll (32-bit)
cargo build --release --target x86_64-pc-windows-gnu   # -> loader.dll (64-bit)
# copy over drm/uplay_r1/uplay_r1_loader{,64}.dll

# Orbit R2 (MSVC target via cargo-xwin — the C++ ABI needs MSVC):
cargo install cargo-xwin
cd drm/orbit_r2/source
XWIN_ARCH="x86,x86_64" cargo xwin build --release --target i686-pc-windows-msvc
# copy target/i686-pc-windows-msvc/release/ubiorbitapi_r2_loader.dll to drm/orbit_r2/

# EAX (mingw):
cd drm/eax && i686-w64-mingw32-gcc -shared -O2 -o eax.dll eax_stub.c eax.def -static-libgcc
```

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
optima-cli login --local              # sign in (browser, one time)
optima-cli list-games                 # your owned, installable games
optima-cli install <product_id>       # download from Ubisoft's CDN
optima-cli launch <product_id>        # run under Proton
optima-cli settings <product_id>      # run a game's settings/config app (resolution, etc.)
optima-cli profile --email … --username … --password …   # local Uplay profile
optima-cli whoami                     # show + verify the stored session
```

`login`, session storage, and refresh all use your own Ubisoft account. Nothing
is shared or centralized.

## Handheld / Steam Deck

Optima powers the **Ubisoft Connect ("Optima") extension** for
[GameVault](https://github.com/Starkka15/GameVault) (a Decky plugin fork), which
gives you a Game-Mode UI to log in, install, and launch — no desktop mode.

## Credits & prior art

- [YoobieRE](https://github.com/YoobieRE) — Ubisoft Demux / manifest / install
  protocol reversing (the basis for `proto/`)
- [Re0xCat/uplay-r1-loader](https://github.com/Re0xCat/uplay-r1-loader) — the
  Uplay R1 compatibility shim
- [Re0xCat/ubiorbitapi-r2-loader](https://github.com/Re0xCat/ubiorbitapi-r2-loader)
  — the basis for the Orbit R2 shim (vendored + fixed in `drm/orbit_r2/source/`)
- [Open-Wine-Components/umu-launcher](https://github.com/Open-Wine-Components/umu-launcher)
  — the Proton runtime launcher

## Legal

Optima is an interoperability tool for accessing games you have lawfully
purchased, on a platform of your choice. You are responsible for complying with
the Ubisoft Terms of Service and the laws of your jurisdiction. It is not
affiliated with, endorsed by, or supported by Ubisoft. "Ubisoft", "Uplay", and
"Ubisoft Connect" are trademarks of Ubisoft Entertainment.

Licensed under the [MIT License](LICENSE).
