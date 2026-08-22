# Hardening / compatibility work

Prompted by an independent review of Optima in
[`xXJSONDeruloXx/ubi-cli-mvp`](https://github.com/xXJSONDeruloXx/ubi-cli-mvp)
(`docs/optima-comparison.md`, 2026-07-13). That project is MIT, Optima is
GPL-3.0, so borrowing from it is fine with attribution; it is TypeScript, so
everything here is a re-implementation of the technique, not copied code.

Each item below was checked against this tree before being listed.

## P0 — secret exposure

- [ ] `drm/signing/optima-signing.key` is a real RSA private key, committed and
      public since 2026-07-13. Treat as burned: generate a new key/cert, stop
      tracking the private half, and purge it from history (public, so the old
      key stays compromised regardless).
      *Verified: present in `git log --all`, readable on github.com.*

## P1 — network-controlled paths

- [ ] `install.rs:382` joins `file.name` straight from the manifest onto the
      install dir. A manifest containing `..\..\` or an absolute path writes
      outside the game tree. Reject absolute paths, `..` components, and
      symlinked parents; verify the result stays inside the install dir.
      *Verified: `let out_path = install_dir.join(&rel);`, no validation.*

## P2 — download integrity

- [ ] Slices are never verified. `download_sha1` is used only to build the CDN
      key; nothing checks the bytes that come back. Verify the compressed blob
      against `download_sha1`, and the decompressed output against the content
      hash + expected size.
      *Verified: `install.rs:400-440`. Note the per-file temp+rename already
      exists, so only the hashing is missing.*
- [ ] Resume trusts a size match alone. Re-verify the content hash before
      skipping an existing file.

## P3 — process environment hygiene

- [ ] Wine/Proton children inherit the whole environment, including any `UBI_*`
      variables. Strip all case-insensitive `UBI_*` before spawning.
      *Verified: no `env_remove`/`env_clear` anywhere in `launch.rs`.*

## P4 — session store

- [ ] Mode 0600 is applied with `set_permissions` *after* the file exists, so
      there is a window where it is not. Create with the mode set, write to a
      temp file and rename, and check owner/type/`O_NOFOLLOW` on read.
      *Verified: `config.rs:74,142,169`.*

## P5 — auth (needs a live account to confirm)

- [ ] MFA posts `Authorization: ubi_v1 t=<2fa ticket>` + `Ubi-2FACode`. The
      review says the observed scheme is `ubi_2fa_v1`. Ours may still work;
      confirm against the real endpoint before changing.
      *Verified in code at `auth.rs:99-106`; the claim itself is untested here.*
- [ ] No `Ubi-Challenge` replay handling.
- [ ] Browser/WebAuth paths store a ticket with empty session id, expiry and
      remember-me ticket, so silent renewal cannot work on those paths — the
      README claims it does. Either implement renewal or correct the README.

## P6 — throughput (only after the above)

- [ ] Downloader does 16 slices per file with files strictly sequential. The
      review's model is 1-8 files in flight with shared slice requests and a
      persistent slice cache.

## Their ideas already in Optima

Recorded so they are not "borrowed" twice: `GetLatestManifests` fallback, legacy
flat `slices/` layout, raw-deflate fallback, bounded per-file prefetch and
byte-based progress are all present — the review credits Optima for them and
ported them the other way.
