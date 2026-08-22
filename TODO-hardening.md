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
- [ ] Resume trusts a size match alone. Re-verify the content hash before
      skipping an existing file. (Deliberately left: re-hashing a 50 GB install
      on every resume is worse than the risk. Wants a `--verify` flag instead.)

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
      says the expiry is unknown and whether refresh is even possible.*

## P6 — throughput (only after the above)

- [ ] Downloader does 16 slices per file with files strictly sequential. The
      review's model is 1-8 files in flight with shared slice requests and a
      persistent slice cache.

## Their ideas already in Optima

Recorded so they are not "borrowed" twice: `GetLatestManifests` fallback, legacy
flat `slices/` layout, raw-deflate fallback, bounded per-file prefetch and
byte-based progress are all present — the review credits Optima for them and
ported them the other way.
