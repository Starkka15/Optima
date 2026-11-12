# Hardening / compatibility work

Prompted by an independent review of Optima in
[`xXJSONDeruloXx/ubi-cli-mvp`](https://github.com/xXJSONDeruloXx/ubi-cli-mvp)
(`docs/optima-comparison.md`, 2026-07-13). That project is MIT, Optima is
GPL-3.0, so borrowing from it is fine with attribution; it is TypeScript, so
everything here is a re-implementation of the technique, not copied code.

Each item below was checked against this tree before being listed.

## P0 — secret exposure

- [x] `drm/signing/optima-signing.key` is a real RSA private key, committed and
      public since 2026-07-13. Treat as burned: generate a new key/cert, stop
      tracking the private half, and purge it from history (public, so the old
      key stays compromised regardless).
      *Done 2026-08-22: new key/cert, all four DLLs re-signed, private half
      untracked, history purged and force-pushed. The old key is still
      reachable via the orphaned commit `e452457` until GitHub GCs it, but it
      only chains to the retired cert `A0:23:BA...`; shipped is `8F:3E:1B...`.*

## P1 — network-controlled paths

- [x] `install.rs:382` joins `file.name` straight from the manifest onto the
      install dir. A manifest containing `..\..\` or an absolute path writes
      outside the game tree. Reject absolute paths, `..` components, and
      symlinked parents; verify the result stays inside the install dir.
      *Done 2026-08-22: `safe_install_path()` rejects absolute paths, `..`,
      drive/UNC prefixes, NUL, non-plain components, and any ancestor that is a
      symlink, then re-checks containment. 3 unit tests — the first tests in
      the project. Writing the tests caught a real gap: `/etc/passwd` was being
      silently reinterpreted as relative instead of refused.*

## P2 — download integrity

- [x] Slices are never verified. `download_sha1` is used only to build the CDN
      key; nothing checks the bytes that come back. Verify the compressed blob
      against `download_sha1`, and the decompressed output against the content
      hash + expected size.
      *Done 2026-08-22: `verify_and_decompress()` checks compressed size vs
      `downloadSize`, compressed SHA-1 vs `downloadSha1`, decompressed size vs
      `Slice.size`, and decompressed SHA-1 vs `File.slices[i]`, then the whole
      file's byte count vs `File.size` before the rename. Hash mismatches are
      not retried — the CDN served something definite and wrong. Manifests
      lacking hashes still install (size checks only). 4 unit tests.
      NOT yet confirmed against a real CDN download — see below.*
- [x] Resume trusts a size match alone. Re-verify the content hash before
      skipping an existing file. (Deliberately left: re-hashing a 50 GB install
      on every resume is worse than the risk. Wants a `--verify` flag instead.)
      *Done 2026-11-11: `.optima-install.json` in the install dir binds resume
      to the manifest id and records size + mtime of every file Optima
      finished. A file whose stamp still matches is trusted without rehashing;
      anything else of the right size is hash-checked slice by slice against
      the manifest (once, then stamped) and re-downloaded if it fails. A
      different manifest id (a game update) drops the state, so every file is
      checked against the new manifest. `install --verify` ignores the state
      and hashes everything (first attempt of the retry loop only). Installs
      made before this have no state, so their first resume hashes them once.
      UNPROVEN on a real install.*
- [x] Slice `fileOffset` was ignored; slices were appended in manifest order.
      *Done 2026-11-11: writes seek to `fileOffset` when the manifest gives
      one. Before anything downloads, each file's slices must tile it exactly
      (sizes sum to `File.size`, in bounds, no overlap, all-or-none offsets),
      or the install stops with a manifest error.*
- [x] Signed-URL mirrors were flattened into one list, so a second mirror for
      one path shifted every later slice onto the wrong URL.
      *Done 2026-11-11: `sign()` keeps mirrors per path and checks the count;
      slice fetches rotate through a slice's mirrors on retry. NotOwned from
      download_service is reported as such. Signed URLs are logged without
      their query (the signature is a bearer credential).*
- [x] LZHAM and unknown compression methods were passed through as if raw.
      *Done 2026-11-11: method 0 is still stored as is; LZHAM and anything
      unknown stop the install with a clear message.*
- [x] No disk-space check. *Done 2026-11-11: statvfs preflight on the bytes
      still to download (+64 MB); `OPTIMA_SKIP_SPACE_CHECK=1` overrides.*
- [x] Every install error was retried 30 times by `do_install`, including ones
      a retry cannot fix. *Done 2026-11-11: `install::Fatal` (no space, not
      owned, unsupported codec, self-contradicting manifest, unsafe path)
      stops at once.*

## P3 — process environment hygiene

- [x] Wine/Proton children inherit the whole environment, including any `UBI_*`
      variables. Strip all case-insensitive `UBI_*` before spawning.
      *Done 2026-08-22: `scrub_ubi_env()` at all 5 umu/Proton spawn sites,
      matching `UBI*` case-insensitively. Unit test covers the case mix and
      confirms `SUBIDENTITY` (contains "ubi", does not start with it) survives.*

## P4 — session store

- [x] Mode 0600 is applied with `set_permissions` *after* the file exists, so
      there is a window where it is not. Create with the mode set, write to a
      temp file and rename, and check owner/type/`O_NOFOLLOW` on read.
      *Done 2026-08-22: `write_private()` creates a temp file with mode 0600
      already set, fills, fsyncs and renames over the target; `read_private()`
      refuses symlinks, non-regular files and files owned by another uid. All
      three writers (auth, profile, launch cache) and both secret readers go
      through them. 3 unit tests; verified live — `whoami` still reads the real
      session and `auth.toml` is 600.*

## P5 — auth (needs a live account to confirm)

- [x] MFA posts `Authorization: ubi_v1 t=<2fa ticket>` + `Ubi-2FACode`. The
      review says the observed scheme is `ubi_2fa_v1`. Ours may still work;
      confirm against the real endpoint before changing.
      *Done 2026-08-22: tries `ubi_2fa_v1` first and falls back to `ubi_v1` on
      401, so whichever the endpoint wants, login works. STILL UNPROVEN — needs
      an account with 2FA enabled to say which one is actually right.*
- [x] No `Ubi-Challenge` replay handling.
      *Done 2026-08-22: a `Ubi-Challenge` response header is echoed back on one
      replayed login. UNPROVEN — has not been seen in the wild here, so the
      header name comes from the review, not observation.*
- [x] Browser/WebAuth paths store a ticket with empty session id, expiry and
      remember-me ticket, so silent renewal cannot work on those paths.
      *Done 2026-08-22: all three capture paths (`--ticket`, `--local`,
      browser) now exchange the bare ticket for a full session via
      `upgrade_captured_ticket()`, which yields the expiry and rememberMe
      ticket, falling back to storing the bare ticket if Ubisoft refuses.
      `whoami` no longer prints "(valid)" for a session with no expiry — it
      says the expiry is unknown and whether refresh is even possible.
      **PROVEN 2026-08-23 on a session that expired overnight by itself:**
      whoami reported EXPIRED + live 401, `refresh` renewed it with no password
      and no browser, whoami then returned 200. Before this fix that case
      required a full `--local` re-login. Observed ticket lifetime ~3h.*

## P5b — launch side (2026-11-11)

- [x] Loader backups were one-shot and identified by file size, and nothing
      was ever put back: the game folder stayed modified after every run.
      *`launch::Deployment` places every shim DLL and config and records it in
      `.optima-deploy.json`; when the game exits the shims are removed and the
      game's own files come back from `.orig`. A run that crashed or was
      killed is undone at the start of the next launch. Our DLLs are
      recognised by the signing cert's DER inside them (this also works for
      older Optima builds), so a stale shim is never mistaken for the original.
      A file that changed during the run (a game patch) is left alone.
      `OPTIMA_NO_RUN` / `OPTIMA_KEEP_DEPLOY` keep the files for inspection.
      UNPROVEN on a real game: the round trip is unit-tested only.*
- [x] `Uplay.ini` / `Uplay.toml` / `Orbit.toml` carry the account ticket and
      stayed in the game folder permanently. *Now part of the deployment: they
      exist only while the game runs.*
- [x] A live "not owned" answer fell back to the offline cache and launched
      anyway. *`NotOwned` now stops the launch; only an unreachable Ubisoft
      falls back to the cache.*
- [x] Demux reported a hard-coded launcher build (13247), which goes stale and
      ends in ClientOutdatedPush. *`connect` asks the patch service
      (`getPatchInfoReq`, track `DPR`) for the current build and reports that,
      falling back to the constant on a fresh socket if there is no answer;
      `OPTIMA_DEMUX_VERSION` overrides. Live check 2026-11-11: the service
      answers anonymously with 13416. **PROVEN 2026-11-11 on the Ally:**
      `list-games` reported 13416, authenticated, and listed all 17 games.*
- [x] The WebAuth capture server accepted a POSTed ticket/email from any page,
      and its logs could show the ticket. *Per-run `state` nonce in our page
      plus an `Origin` check on every POST (and `state` on the legacy
      `/back`), so another site cannot push its own ticket in. The page's
      on-screen log no longer prints the `getTicket` response or message
      payloads, and `OPTIMA_DEBUG` prints the request path without its query.*

## Tabled — official Connect launch mode (2026-11-11)

- [ ] For newer games the shims can't run, ubi-cli-mvp installs the real
      Ubisoft Connect in the prefix, has it recognize the already-downloaded
      game folder, and launches via `uplay://`; Connect then does sign-in and
      DRM itself. Idea: an opt-in Optima launch mode next to the shims.
      Costs: Ubisoft's client in the prefix, first login/2FA inside Connect,
      Connect's first-run setup per game, and Connect may not accept a fresh
      folder right away. Tabled by the user; not started.
      **Goal set 2026-11-11:** if Connect mode works for *all* the user's games,
      replace the shims completely (drops shim DLLs, prefix cert trust,
      `IsAppOwned=1`, placeholder tickets; Ubisoft enforces ownership/refunds).
      Optima keeps download/install/progress. Prove it per game on the Ally
      first, including the older R1/Orbit titles and Connect's login on Deck.
      **Started 2026-11-11** (`src/connect.rs`):
      - `connect setup` downloads Ubisoft's installer over HTTPS, checks it is
        a signed PE, runs it `/S` into `~/.local/share/optima/connect-prefix`
        (separate from the shim prefix; no Optima cert in it).
      - `connect open` for the one-time sign-in; `connect status` reads
        login evidence and registrations from disk (no Proton spin-up).
      - `launch --connect` (or `OPTIMA_CONNECT=1`): undoes any old shim
        deployment, registers the Optima folder in Connect's
        `Launcher\Installs\<id>\InstallDir` if Connect has none, runs
        `uplay://launch/<id>/0`, follows the game exe via /proc, then closes
        Connect. Optima stays alive for the game's lifetime (Steam tracking).
      - Fallback if Connect won't accept a registered folder:
        `connect install <id>` (its own dialog; start, pause, quit) then
        `connect seed <id>` hard-links the Optima files into its staging, and
        `connect open` lets it verify and finish.
      UNPROVEN: first `connect setup` on the Ally ran past 10 min and the Ally
      then went to sleep mid-install; setup now treats "client present and
      installer gone" as done in case the installer starts Connect itself.
      Unknown: whether Connect accepts a registry-only registration, and
      whether it needs `uplay_install.state`/`.manifest` for that.
      GameVault not wired yet (wait until proven).
      **PROVEN 2026-11-11 on the Ally, Game Mode via GameVault:**
      - Connect setup works in under a minute once winetricks
        (corefonts, d3dcompiler_43) and settings.yaml are in place; the earlier
        hangs were the installer starting Connect under umu, and a stalled
        download with no timeout (both fixed).
      - Registry alone is NOT enough: Connect offered a full reinstall. It
        needs its own records in the game folder: `uplay_install.manifest`
        (Ubisoft's signed CDN manifest, byte for byte) and
        `uplay_install.state` (`DownloadInstallState` protobuf, layout from
        UplayDB/Protobufs, Connect 175). Optima now writes both at the end of
        every install; `install <id> --records-only` adds them to old installs.
      - AC IV (273, old install + records-only) and Brawlhalla (16382, fresh
        Optima install) both launched straight through Connect, no clicks.
      - Connect sign-in check uses ConnectSecureStorage.dat (it writes
        user.vdat, not user.dat).
      - Splinter Cell (95): Connect "couldn't find the game" until Optima
        also wrote the manifest's `installRegistry` entries (its config
        resolves the exe via `…\Chaos Theory\InstallDir` + `system`). Now
        written with every Connect registration ($INSTALL_DIR filled in,
        en-US variants), re-applied when the manifest changes. Works.
      - EAX shim kept in Connect mode (audio fix, not DRM), deployed and
        restored per launch as before.
      - Connect lost its saved login once during testing, probably from a
        hard kill; stop() now closes it politely first (20 s grace).
      - BG&E (232): "Application settings not valid" until its shipped
        support/settings.reg was imported into the Connect prefix. Registration
        now imports shipped .reg files once per product (so updates don't
        reset settings); `settings` runs in the Connect prefix in Connect mode.
        Works, EAX shim included.
      Next: confirm 54, 274 through Connect; offline launch; GameVault
      wiring (connect-mode default, first-launch sign-in); then remove the
      shims, the prefix cert and the shim launch path.

## Planned — real Ubisoft login page (2026-11-11)

- [ ] Replace the self-signed `localhost.ubisoft.com` WebAuth page with
      Ubisoft's real login page in a browser window Optima controls, reading
      the session afterwards (as Lutris does), so users never click through a
      certificate warning. After the Connect work.

## P6 — throughput (only after the above)

- [x] Downloader does 16 slices per file with files strictly sequential. The
      review's model is 1-8 files in flight with shared slice requests and a
      persistent slice cache.

## Their ideas already in Optima

Recorded so they are not "borrowed" twice: `GetLatestManifests` fallback, legacy
flat `slices/` layout, raw-deflate fallback, bounded per-file prefetch and
byte-based progress are all present — the review credits Optima for them and
ported them the other way.

## P7 — stop storing credentials at all (2026-08-22)

Prompted by "we shouldn't be storing passwords".

- [x] `profile.toml` held the account password in plaintext, and it was written
      into `Uplay.ini` **and** `Uplay.toml` next to every game exe.
      *The emu never checks it: the vendored Orbit emu ships
      `Password = "123456"` as its own default and just interns the string and
      hands the pointer to the game (`drm/orbit_r2/source/src/api.rs:31,381`).
      Optima now passes a fixed placeholder. `--password` on `profile` is
      accepted and ignored with a note, and the WebAuth page no longer has a
      password field at all.*
- [x] Existing stored passwords are removed on the first profile load, with a
      message. Verified on the real profile here.
- [x] The email is now optional and synthesised as `<username>@optima.local`
      unless the user sets a real one.
- [x] `session_key` is stored but never read outside `config.rs`. Drop it.
      *Done 2026-11-11: removed from `Auth` and the login response mapping;
      it disappears from `auth.toml` on the next save.*

What remains on disk is a ticket, a rememberMe ticket, an opaque profile id and
a display name — no reusable credentials.
