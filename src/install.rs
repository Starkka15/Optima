// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Starkka15

//! Game installer (P2): download an owned game's files from the Ubisoft CDN.
//!
//! Flow (mirrors YoobieRE's manifest-downloader):
//!   1. ownership_service `ownershipTokenReq{product_id}` → an ownership token.
//!   2. download_service `initializeReq{ownership_token}`, then `urlReq{paths}` →
//!      **signed CDN URLs** for those relative paths.
//!   3. sign + fetch `manifests/<id>.manifest`; strip 356-byte header, zlib
//!      inflate, decode as `download.Manifest` (chunks → files → slices).
//!   4. per file: slice path = `slices_v3/<hashChar>/<HASH>`; sign, download each
//!      slice, decompress (Zstd/Deflate), write in order. Slices are compressed,
//!      NOT encrypted.

use anyhow::{anyhow, bail, Context, Result};
use prost::Message;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// What the manifest promises about one slice, so the bytes can be checked
/// against it. `download_sha1` covers the *compressed* blob as served by the
/// CDN; `content_sha1` covers the decompressed result.
#[derive(Clone)]
struct SliceCheck {
    download_size: Option<u32>,
    download_sha1: Option<Vec<u8>>,
    size: u32,
    content_sha1: Option<Vec<u8>>,
}

fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex_upper(&hasher.finalize())
}

/// Check a slice as served, then as decompressed.
///
/// The CDN is not trusted to return what was asked for: a corrupted proxy, a
/// truncated response or a swapped object would otherwise be written into the
/// game with no complaint, and resume would then trust the result because the
/// size matched.
fn verify_and_decompress(
    comp: i32,
    raw: &[u8],
    check: &SliceCheck,
    file_name: &str,
    index: usize,
) -> Result<Vec<u8>> {
    if let Some(expected) = check.download_size {
        if raw.len() as u32 != expected {
            bail!(
                "{file_name} slice {index}: compressed size {} != manifest {expected}",
                raw.len()
            );
        }
    }
    if let Some(expected) = check.download_sha1.as_ref().filter(|h| !h.is_empty()) {
        let got = sha1_hex(raw);
        let want = hex_upper(expected);
        if got != want {
            bail!("{file_name} slice {index}: compressed sha1 {got} != manifest {want}");
        }
    }

    let out = decompress(comp, raw)?;

    if out.len() as u32 != check.size {
        bail!(
            "{file_name} slice {index}: decompressed size {} != manifest {}",
            out.len(),
            check.size
        );
    }
    if let Some(expected) = check.content_sha1.as_ref().filter(|h| !h.is_empty()) {
        let got = sha1_hex(&out);
        let want = hex_upper(expected);
        if got != want {
            bail!("{file_name} slice {index}: content sha1 {got} != manifest {want}");
        }
    }
    Ok(out)
}

/// Map a manifest-supplied file name onto a path inside `install_dir`.
///
/// `File.name` arrives over the network inside the manifest, so it is untrusted
/// input. Joining it directly lets a manifest containing `..\..\.bashrc`, an
/// absolute path, or a Windows drive prefix write anywhere the process can
/// reach. Only plain relative components are accepted, and no existing ancestor
/// inside the tree may be a symlink — otherwise a link planted by an earlier
/// entry would redirect a later write outside the install dir.
fn safe_install_path(install_dir: &Path, raw_name: &str) -> Result<PathBuf> {
    if raw_name.trim().is_empty() {
        bail!("manifest entry has an empty file name");
    }
    if raw_name.contains('\0') {
        bail!("manifest path contains a NUL byte: {raw_name:?}");
    }

    // Manifests use Windows separators; treat both so `a\b` cannot smuggle a
    // component past a `/`-only check.
    let unified = raw_name.replace('\\', "/");
    // An absolute name would be silently re-read as relative by the loop below.
    // A manifest should never contain one, so refuse rather than reinterpret.
    if unified.starts_with('/') {
        bail!("manifest path is absolute: {raw_name:?}");
    }
    let mut out = install_dir.to_path_buf();
    let mut depth = 0usize;

    for part in unified.split('/') {
        match part {
            "" | "." => continue,
            ".." => bail!("manifest path escapes the install dir: {raw_name:?}"),
            _ => {}
        }
        // `C:` or `\\server` style prefixes, and anything the OS would treat as
        // a root, must never become a component.
        if part.ends_with(':') {
            bail!("manifest path has a drive/volume prefix: {raw_name:?}");
        }
        let candidate = Path::new(part);
        if candidate.components().any(|c| !matches!(c, Component::Normal(_))) {
            bail!("manifest path has a non-plain component: {raw_name:?}");
        }

        out.push(part);
        depth += 1;

        // An ancestor that already exists as a symlink would move the write
        // outside the tree even though every component looked plain.
        if let Ok(meta) = std::fs::symlink_metadata(&out) {
            if meta.file_type().is_symlink() {
                bail!("manifest path crosses a symlink at {}", out.display());
            }
        }
    }

    if depth == 0 {
        bail!("manifest path resolves to the install dir itself: {raw_name:?}");
    }
    // Belt and braces: the loop cannot produce an escape, but assert it anyway.
    if !out.starts_with(install_dir) {
        bail!("manifest path escapes the install dir: {raw_name:?}");
    }
    Ok(out)
}

use crate::demux::Demux;
use crate::proto::{download, download_service, ownership};

const BASE32: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// Mirror of ubisoft-demux's `fileHashToPathChar`: the CDN shards slices into
/// buckets keyed by a char derived from the first byte of the (uppercase-hex)
/// slice hash, with its nibbles swapped.
fn hash_path_char(hash_upper: &str) -> char {
    let mut chars = hash_upper.chars();
    let first = chars.next().unwrap_or('0');
    let second = chars.next().unwrap_or('0');
    let swapped = format!("{second}{first}");
    let reversed = u8::from_str_radix(&swapped, 16).unwrap_or(0);
    let offset = (reversed / 16) as usize;
    let half = if reversed % 2 == 0 { 0 } else { 16 };
    BASE32[offset + half] as char
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// How this product's slices are laid out on the CDN. Newer AnvilNext titles
/// (AC4, Brawlhalla) sit under `slices_v3/<bucketchar>/<HASH>`; older ones
/// (AC Unity — `chunks_version=None`) serve them FLAT at `slices/<HASH>`. We
/// probe once per install and reuse the answer for every slice.
#[derive(Clone, Copy, Debug)]
enum SliceLayout {
    V3Bucket,
    Flat,
}

/// Build a slice CDN path (relative to the product's download root) for a hash.
fn slice_path(layout: SliceLayout, hash_upper: &str) -> String {
    match layout {
        SliceLayout::V3Bucket => format!("slices_v3/{}/{}", hash_path_char(hash_upper), hash_upper),
        SliceLayout::Flat => format!("slices/{hash_upper}"),
    }
}

async fn ownership_token(demux: &mut Demux, product_id: u32) -> Result<String> {
    let conn = demux.open_connection("ownership_service").await?;
    // A service connection must be initialized before it answers requests.
    let init = ownership::Upstream {
        request: Some(ownership::Req {
            request_id: 1,
            initialize_req: Some(ownership::InitializeReq {
                get_associations: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    let _ = demux.service_call(conn, init.encode_to_vec()).await?;

    let up = ownership::Upstream {
        request: Some(ownership::Req {
            request_id: 2,
            ownership_token_req: Some(ownership::OwnershipTokenReq {
                product_id: Some(product_id),
            }),
            ..Default::default()
        }),
    };
    let raw = demux.service_call(conn, up.encode_to_vec()).await?;
    let down = ownership::Downstream::decode(&raw[..]).context("decoding ownership token rsp")?;
    down.response
        .and_then(|r| r.ownership_token_rsp)
        .and_then(|t| t.token)
        .ok_or_else(|| anyhow!("no ownership token for product {product_id}"))
}

/// A held-open download_service connection with its own request-id counter.
struct DownloadService {
    conn: u32,
    req_id: u32,
}

impl DownloadService {
    async fn open(demux: &mut Demux, ownership_token: &str) -> Result<Self> {
        let conn = demux.open_connection("download_service").await?;
        let mut svc = Self { conn, req_id: 1 };
        let up = download_service::Upstream {
            request: Some(download_service::Req {
                request_id: svc.next_id(),
                initialize_req: Some(download_service::InitializeReq {
                    ownership_token: ownership_token.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let _ = demux.service_call(conn, up.encode_to_vec()).await?;
        Ok(svc)
    }

    fn next_id(&mut self) -> u32 {
        let id = self.req_id;
        self.req_id += 1;
        id
    }

    /// Sign relative CDN paths → for each path, its signed URL on every mirror
    /// the service offers (usually one). Kept per path: flattening them used to
    /// make a second mirror look like another slice and shift every slice after it.
    async fn sign(&mut self, demux: &mut Demux, product_id: u32, paths: Vec<String>) -> Result<Vec<Vec<String>>> {
        let wanted = paths.len();
        let up = download_service::Upstream {
            request: Some(download_service::Req {
                request_id: self.next_id(),
                url_req: Some(download_service::UrlReq {
                    url_requests: vec![download_service::url_req::Request {
                        product_id,
                        relative_file_path: paths,
                    }],
                }),
                ..Default::default()
            }),
        };
        let raw = demux.service_call(self.conn, up.encode_to_vec()).await?;
        let down = download_service::Downstream::decode(&raw[..]).context("decoding url rsp")?;
        let rsp = down
            .response
            .and_then(|r| r.url_rsp)
            .ok_or_else(|| anyhow!("download_service answered without a url response"))?;
        mirrors_from_response(rsp, product_id, wanted)
    }
}

/// One `urlReq` carries one product request, so the answer is one `UrlResponse`
/// whose `download_urls` line up with the requested paths, each holding that
/// path's mirrors.
fn mirrors_from_response(
    rsp: download_service::UrlRsp,
    product_id: u32,
    wanted: usize,
) -> Result<Vec<Vec<String>>> {
    let mut out = Vec::with_capacity(wanted);
    for resp in rsp.url_responses {
        if resp.result == download_service::url_rsp::Result::NotOwned as i32 {
            return Err(fatal(format!("download_service says product {product_id} is not owned by this account")));
        }
        for d in resp.download_urls {
            if d.urls.is_empty() {
                bail!("download_service returned a path with no URL");
            }
            out.push(d.urls);
        }
    }
    if out.len() != wanted {
        bail!("download_service signed {} of {wanted} paths", out.len());
    }
    Ok(out)
}

/// A signed URL without its query string: the signature is a bearer credential
/// for the object until it expires, so it never goes into a log.
fn redact_url(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

fn decompress(method: i32, data: &[u8]) -> Result<Vec<u8>> {
    if method == download::CompressionMethod::Zstd as i32 {
        zstd::decode_all(data).with_context(|| {
            let head: String = data.iter().take(16).map(|b| format!("{b:02x}")).collect();
            format!(
                "zstd decompress (method={method}, {} bytes, head={head}, text={:?})",
                data.len(),
                String::from_utf8_lossy(&data[..data.len().min(64)])
            )
        })
    } else if method == download::CompressionMethod::Deflate as i32 {
        // Ubisoft slices are zlib-wrapped deflate (same as the manifest blob),
        // but some older manifests store raw deflate. Pick by the zlib header
        // (0x78 …) and fall back to the other framing if the first fails.
        let raw = |data: &[u8]| -> std::io::Result<Vec<u8>> {
            let mut o = Vec::new();
            flate2::read::DeflateDecoder::new(data).read_to_end(&mut o)?;
            Ok(o)
        };
        let zlib = |data: &[u8]| -> std::io::Result<Vec<u8>> {
            let mut o = Vec::new();
            flate2::read::ZlibDecoder::new(data).read_to_end(&mut o)?;
            Ok(o)
        };
        let looks_zlib = data.len() >= 2 && data[0] == 0x78;
        let attempt = if looks_zlib {
            zlib(data).or_else(|_| raw(data))
        } else {
            raw(data).or_else(|_| zlib(data))
        };
        attempt.with_context(|| {
            let head: String = data.iter().take(16).map(|b| format!("{b:02x}")).collect();
            format!(
                "deflate decompress (method={method}, {} bytes, zlib_header={looks_zlib}, head={head})",
                data.len()
            )
        })
    } else if method == 0 {
        // No compression field: stored as is. The slice hashes still apply.
        Ok(data.to_vec())
    } else if method == download::CompressionMethod::Lzham as i32 {
        Err(fatal("slice uses LZHAM compression, which Optima does not support yet"))
    } else {
        // Passing an unknown codec through would write compressed bytes into the
        // game and, on a manifest without hashes, nothing would notice.
        Err(fatal(format!("slice uses unknown compression method {method}")))
    }
}

/// (Re)establish an ownership token + a fresh download_service on `demux`.
async fn open_dl(demux: &mut Demux, product_id: u32) -> Result<DownloadService> {
    let token = ownership_token(demux, product_id).await?;
    DownloadService::open(demux, &token).await
}

/// Sign a (possibly huge) list of relative CDN paths → signed URLs, in order.
/// Signs in batches so no single urlReq protobuf grows large enough to make the
/// server drop the socket, and rebuilds the whole demux session on any failure.
async fn sign_all(
    demux: &mut Demux,
    dl: &mut DownloadService,
    demux_ticket: &str,
    product_id: u32,
    paths: &[String],
) -> Result<Vec<Vec<String>>> {
    const BATCH: usize = 100;
    let mut all = Vec::with_capacity(paths.len());
    for chunk in paths.chunks(BATCH) {
        let batch = chunk.to_vec();
        let mut attempt = 0;
        loop {
            match dl.sign(demux, product_id, batch.clone()).await {
                Ok(u) => {
                    all.extend(u);
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    if attempt > 10 {
                        return Err(e.context("signing a slice batch failed after 10 reconnects"));
                    }
                    eprintln!("[install] demux dropped ({e}); reconnecting (attempt {attempt})...");
                    match Demux::connect(demux_ticket).await {
                        Ok(d) => {
                            *demux = d;
                            match open_dl(demux, product_id).await {
                                Ok(new_dl) => *dl = new_dl,
                                Err(oe) => {
                                    eprintln!("[install] reopen download_service failed ({oe}); retrying...");
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                }
                            }
                        }
                        Err(ce) => {
                            eprintln!("[install] reconnect failed ({ce}); retrying...");
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                    }
                }
            }
        }
    }
    Ok(all)
}

/// An install error that another whole-run retry cannot fix (no disk space, a
/// game this account does not own, a codec Optima lacks, a manifest that
/// contradicts itself). `do_install` stops on these instead of looping.
#[derive(Debug)]
pub struct Fatal(pub String);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fatal {}

fn fatal(msg: impl Into<String>) -> anyhow::Error {
    Fatal(msg.into()).into()
}

/// Where each slice lands in its file. Newer manifests say so per slice
/// (`fileOffset`); older ones imply back-to-back order. Either way the slices
/// must tile the file exactly — no gap, no overlap, nothing past the end — or
/// the manifest is wrong and nothing it says about this file can be written.
fn slice_offsets(file: &download::File) -> Result<Vec<u64>> {
    let n = file.slice_list.len();
    let given = file.slice_list.iter().filter(|s| s.file_offset.is_some()).count();
    if given != 0 && given != n {
        return Err(fatal(format!(
            "{}: only {given} of {n} slices carry a file offset",
            file.name
        )));
    }
    let mut offsets = Vec::with_capacity(n);
    let mut total = 0u64;
    for s in &file.slice_list {
        offsets.push(s.file_offset.unwrap_or(total));
        total += s.size as u64;
    }
    if total != file.size {
        return Err(fatal(format!(
            "{}: slices add up to {total} bytes but the file is {}",
            file.name, file.size
        )));
    }
    let mut spans: Vec<(u64, u64)> = Vec::with_capacity(n);
    for (o, s) in offsets.iter().zip(&file.slice_list) {
        let end = o
            .checked_add(s.size as u64)
            .filter(|e| *e <= file.size)
            .ok_or_else(|| fatal(format!("{}: a slice at offset {o} runs past the end", file.name)))?;
        spans.push((*o, end));
    }
    spans.sort_unstable();
    let mut covered = 0u64;
    for (start, end) in spans {
        if start < covered {
            return Err(fatal(format!("{}: slices overlap at offset {start}", file.name)));
        }
        covered = end;
    }
    // Sum == size, in bounds and no overlap together mean no gap either.
    Ok(offsets)
}

const STATE_FILE: &str = ".optima-install.json";

/// Size and mtime of a file Optima finished writing. A file whose stamp still
/// matches was not touched since, so resume can trust it without rehashing.
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
struct FileStamp {
    size: u64,
    secs: u64,
    nanos: u32,
}

impl FileStamp {
    fn of(meta: &std::fs::Metadata) -> Option<Self> {
        let d = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some(Self { size: meta.len(), secs: d.as_secs(), nanos: d.subsec_nanos() })
    }
}

/// Resume state, bound to one manifest. Size alone used to decide whether a
/// file was done, so a same-sized file from an older build, or one damaged
/// after the fact, was kept. A different manifest id throws the state away and
/// every existing file is hash-checked against the new manifest instead.
#[derive(serde::Serialize, serde::Deserialize, Default, Clone, PartialEq, Debug)]
struct InstallState {
    manifest_id: String,
    files: std::collections::BTreeMap<String, FileStamp>,
}

impl InstallState {
    fn load(dir: &Path, manifest_id: &str) -> Self {
        let fresh = Self { manifest_id: manifest_id.to_string(), files: Default::default() };
        let Ok(text) = std::fs::read_to_string(dir.join(STATE_FILE)) else {
            return fresh;
        };
        match serde_json::from_str::<Self>(&text) {
            Ok(s) if s.manifest_id == manifest_id => s,
            _ => fresh,
        }
    }

    fn save(&self, dir: &Path) -> Result<()> {
        let tmp = dir.join(format!("{STATE_FILE}.tmp"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, dir.join(STATE_FILE))
            .with_context(|| format!("saving {STATE_FILE}"))?;
        Ok(())
    }

    fn trusts(&self, name: &str, meta: &std::fs::Metadata) -> bool {
        matches!((self.files.get(name), FileStamp::of(meta)), (Some(a), Some(b)) if *a == b)
    }

    fn record(&mut self, name: &str, path: &Path) {
        if let Some(stamp) = std::fs::metadata(path).ok().as_ref().and_then(FileStamp::of) {
            self.files.insert(name.to_string(), stamp);
        }
    }
}

/// Hash an existing file slice by slice against the manifest's content hashes.
/// `Ok(false)` means it is wrong or short and has to be downloaded again.
fn verify_on_disk(path: &Path, checks: &[SliceCheck], offsets: &[u64]) -> std::io::Result<bool> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    for (check, offset) in checks.iter().zip(offsets) {
        let Some(want) = check.content_sha1.as_ref().filter(|h| !h.is_empty()) else {
            continue;
        };
        buf.resize(check.size as usize, 0);
        f.seek(SeekFrom::Start(*offset))?;
        if f.read_exact(&mut buf).is_err() || sha1_hex(&buf) != hex_upper(want) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn has_content_hashes(checks: &[SliceCheck]) -> bool {
    checks.iter().any(|c| c.content_sha1.as_ref().is_some_and(|h| !h.is_empty()))
}

/// Bytes an unprivileged user can still write on the filesystem holding `dir`.
fn free_bytes(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(st.f_bavail as u64 * st.f_frsize as u64)
}

/// Byte progress on stdout. `[<done>/<total> B]` is the token GameVault parses;
/// keep that exact shape.
struct Progress {
    done: u64,
    total: u64,
    last_emit: u64,
    step: u64,
}

impl Progress {
    fn new(total: u64) -> Self {
        // ~400 samples over the whole download, but at least every 4 MB.
        Self { done: 0, total, last_emit: 0, step: (total / 400).max(4 * 1024 * 1024) }
    }

    fn add(&mut self, n: u64, label: &str) {
        self.done += n;
        if self.done - self.last_emit >= self.step {
            self.last_emit = self.done;
            println!(
                "  [{}/{} B] {:.2}/{:.2} GB — {label}",
                self.done,
                self.total,
                self.done as f64 / 1e9,
                self.total as f64 / 1e9
            );
        }
    }
}

/// One file that has to be downloaded.
struct Planned<'a> {
    file: &'a download::File,
    out_path: PathBuf,
    offsets: Vec<u64>,
    checks: Vec<SliceCheck>,
    slice_paths: Vec<String>,
}

pub async fn install_game(
    demux: &mut Demux,
    demux_ticket: &str,
    product_id: u32,
    manifest_id: &str,
    name: &str,
    install_dir: &Path,
    verify: bool,
    records_only: bool,
) -> Result<()> {
    eprintln!("[install] requesting ownership token...");
    let mut dl = open_dl(demux, product_id).await?;
    eprintln!("[install] download_service ready; signing manifest url...");

    // Fetch + parse the manifest.
    let manifest_urls = sign_all(
        demux,
        &mut dl,
        demux_ticket,
        product_id,
        &[format!("manifests/{manifest_id}.manifest")],
    )
    .await?;
    let manifest_mirrors = manifest_urls
        .into_iter()
        .next()
        .filter(|m| !m.is_empty())
        .ok_or_else(|| anyhow!("no signed URL for the manifest"))?;
    let client = reqwest::Client::new();
    let mut mbytes = None;
    let mut last_err = None;
    for url in &manifest_mirrors {
        match client.get(url).send().await.and_then(|r| r.error_for_status()) {
            Ok(r) => match r.bytes().await {
                Ok(b) => {
                    mbytes = Some(b);
                    break;
                }
                Err(e) => last_err = Some(e),
            },
            Err(e) => last_err = Some(e),
        }
    }
    let mbytes = match mbytes {
        Some(b) => b,
        None => {
            return Err(anyhow!("fetching the manifest from {} mirror(s) failed: {last_err:?}", manifest_mirrors.len()))
        }
    };
    if mbytes.len() <= 356 {
        bail!("manifest is only {} bytes", mbytes.len());
    }
    let mut inflated = Vec::new();
    flate2::read::ZlibDecoder::new(&mbytes[356..])
        .read_to_end(&mut inflated)
        .context("inflating manifest")?;
    let manifest = download::Manifest::decode(&inflated[..]).context("decoding manifest")?;
    let comp = manifest.compression_method.unwrap_or(0);

    // An install finished before Optima wrote Connect's records: add just them.
    if records_only {
        if !install_dir.is_dir() {
            bail!("{} does not exist", install_dir.display());
        }
        write_connect_records(install_dir, product_id, manifest_id, name, &mbytes, &manifest)?;
        println!("Wrote Connect's install records for {name} in {}", install_dir.display());
        return Ok(());
    }

    let files: Vec<&download::File> = manifest.chunks.iter().flat_map(|c| c.files.iter()).collect();
    let total_bytes: u64 = files.iter().map(|f| f.size).sum();
    println!(
        "{name}: {} files, {:.2} GB → {}",
        files.len(),
        total_bytes as f64 / 1e9,
        install_dir.display()
    );

    tokio::fs::create_dir_all(install_dir).await?;

    // Diagnostic: find the correct slice bucket char by signing every candidate
    // for one real slice and seeing which the CDN actually serves.
    if std::env::var_os("OPTIMA_PROBE").is_some() {
        if let Some(f) = files.iter().find(|f| !f.slices.is_empty()) {
            let hu = hex_upper(&f.slices[0]);
            let hl = hu.to_lowercase();
            let c = hash_path_char(&hu);
            eprintln!(
                "[probe] slice {hu} char={c} | manifest chunks_version={:?} slicer={:?} comp={comp}",
                manifest.chunks_version, manifest.slicer_config
            );
            let mut paths = Vec::new();
            for pre in ["slices_v3", "slices_v2", "slices", "sliceList", "chunks"] {
                for (tag, h) in [("U", &hu), ("L", &hl)] {
                    paths.push((format!("{pre}/{c}/{h}"), format!("{pre}/bucket/{tag}")));
                    paths.push((format!("{pre}/{h}"), format!("{pre}/flat/{tag}")));
                }
            }
            let urls = dl.sign(demux, product_id, paths.iter().map(|(p, _)| p.clone()).collect()).await?;
            for ((_, label), mirrors) in paths.iter().zip(urls.iter()) {
                let st = client.get(&mirrors[0]).send().await.map(|r| r.status().as_u16()).unwrap_or(0);
                eprintln!("[probe] {label:16} -> {st}");
            }
            eprintln!("[probe] done");
            return Ok(());
        }
    }

    // Detect the slice CDN layout once (older titles like AC Unity are flat
    // `slices/<HASH>`, newer ones bucketed `slices_v3/<c>/<HASH>`) by signing the
    // first real slice under each and using whichever the CDN actually serves.
    let slice_layout = {
        let sample = files.iter().find_map(|f| {
            if f.slice_list.is_empty() {
                return None;
            }
            let h = match &f.slice_list[0].download_sha1 {
                Some(d) if !d.is_empty() => hex_upper(d),
                _ => hex_upper(f.slices.first().map(|v| v.as_slice()).unwrap_or_default()),
            };
            (!h.is_empty()).then_some(h)
        });
        match sample {
            None => SliceLayout::V3Bucket,
            Some(h) => {
                let candidates = [SliceLayout::V3Bucket, SliceLayout::Flat];
                let paths: Vec<String> = candidates.iter().map(|l| slice_path(*l, &h)).collect();
                let urls = dl.sign(demux, product_id, paths).await?;
                let mut chosen = SliceLayout::V3Bucket;
                'probe: for (layout, mirrors) in candidates.iter().zip(urls.iter()) {
                    for u in mirrors {
                        if client.get(u).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
                            chosen = *layout;
                            break 'probe;
                        }
                    }
                }
                eprintln!("[install] slice CDN layout: {chosen:?}");
                chosen
            }
        }
    };

    // Plan: validate every entry, settle what is already on disk, and list
    // what has to come down. Everything that can make the manifest unusable
    // fails here, before a single byte is downloaded.
    let mut state = InstallState::load(install_dir, manifest_id);
    let mut progress = Progress::new(total_bytes);
    let mut planned: Vec<Planned> = Vec::new();
    let mut skipped = 0usize;
    let mut checked = 0usize;
    let mut need_bytes = 0u64;
    for file in &files {
        // Manifests use Windows `\` separators and arrive over the network:
        // validated rather than joined straight on. See `safe_install_path`.
        let out_path = safe_install_path(install_dir, &file.name).map_err(|e| fatal(format!("{e:#}")))?;
        if file.is_dir {
            tokio::fs::create_dir_all(&out_path)
                .await
                .with_context(|| format!("create_dir_all {}", out_path.display()))?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create_dir_all {}", parent.display()))?;
        }
        if file.slice_list.is_empty() {
            if file.size != 0 {
                return Err(fatal(format!(
                    "{}: the manifest lists {} bytes but no slices",
                    file.name, file.size
                )));
            }
            tokio::fs::File::create(&out_path)
                .await
                .with_context(|| format!("touch empty file {}", out_path.display()))?;
            continue;
        }

        let offsets = slice_offsets(file)?;
        let checks: Vec<SliceCheck> = file
            .slice_list
            .iter()
            .enumerate()
            .map(|(i, sl)| SliceCheck {
                download_size: sl.download_size,
                download_sha1: sl.download_sha1.clone(),
                size: sl.size,
                content_sha1: file.slices.get(i).cloned(),
            })
            .collect();

        // Resume: a same-sized file is kept only if this manifest's state says
        // Optima wrote it and it has not changed since, or its bytes hash out.
        // `--verify` ignores the state and hashes everything. A manifest
        // without content hashes can only be checked by size.
        if let Ok(meta) = std::fs::metadata(&out_path) {
            if meta.len() == file.size {
                let good = if !verify && state.trusts(&file.name, &meta) {
                    true
                } else if has_content_hashes(&checks) {
                    checked += 1;
                    let (p, c, o) = (out_path.clone(), checks.clone(), offsets.clone());
                    tokio::task::spawn_blocking(move || verify_on_disk(&p, &c, &o))
                        .await?
                        .unwrap_or(false)
                } else {
                    true
                };
                if good {
                    state.record(&file.name, &out_path);
                    skipped += 1;
                    progress.add(file.size, &file.name);
                    continue;
                }
                eprintln!("[install] {} failed its hash check; downloading it again", file.name);
            }
        }
        state.files.remove(&file.name);

        let slice_paths: Vec<String> = file
            .slice_list
            .iter()
            .enumerate()
            .map(|(i, sl)| {
                let h = match &sl.download_sha1 {
                    Some(d) if !d.is_empty() => hex_upper(d),
                    _ => hex_upper(file.slices.get(i).map(|v| v.as_slice()).unwrap_or_default()),
                };
                slice_path(slice_layout, &h)
            })
            .collect();
        need_bytes += file.size;
        planned.push(Planned { file, out_path, offsets, checks, slice_paths });
    }
    if checked > 0 {
        eprintln!("[install] hash-checked {checked} existing file(s)");
    }
    // Retries after a dropped connection start from here; they should not have
    // to rehash what this pass already settled.
    state.save(install_dir)?;

    // Free-space preflight: fail now, not with ENOSPC three hours in.
    if need_bytes > 0 && std::env::var_os("OPTIMA_SKIP_SPACE_CHECK").is_none() {
        if let Some(free) = free_bytes(install_dir) {
            let margin = 64 * 1024 * 1024;
            if free < need_bytes + margin {
                return Err(fatal(format!(
                    "not enough free space in {}: {:.2} GB to download, {:.2} GB free \
                     (set OPTIMA_SKIP_SPACE_CHECK=1 to try anyway)",
                    install_dir.display(),
                    need_bytes as f64 / 1e9,
                    free as f64 / 1e9
                )));
            }
        }
    }

    let result = download_planned(
        demux,
        &mut dl,
        demux_ticket,
        product_id,
        comp,
        &client,
        install_dir,
        &planned,
        &mut state,
        &mut progress,
    )
    .await;
    // Whatever happened, keep what was finished so the next attempt skips it.
    let saved = state.save(install_dir);
    result?;
    saved?;

    // Final 100% sample.
    println!(
        "  [{total_bytes}/{total_bytes} B] {:.2}/{:.2} GB — done",
        total_bytes as f64 / 1e9,
        total_bytes as f64 / 1e9
    );
    if skipped > 0 {
        println!("  ({skipped} files already present, skipped)");
    }
    // Leave the folder the way Ubisoft Connect leaves its own installs, so the
    // official client recognises it as installed instead of offering a fresh
    // download. Harmless for the shim launch, which never reads these.
    if let Err(e) = write_connect_records(install_dir, product_id, manifest_id, name, &mbytes, &manifest) {
        eprintln!("[install] couldn't write Connect's install records: {e:#}");
    }
    println!("Installed {name} to {}", install_dir.display());
    Ok(())
}

/// Connect's install record for a fully downloaded manifest (every chunk).
fn connect_install_state(
    product_id: u32,
    manifest_id: &str,
    name: &str,
    manifest: &download::Manifest,
    now: u64,
) -> crate::proto::download_install_state::DownloadInstallState {
    use crate::proto::download_install_state as st;
    let languages: Vec<String> = manifest
        .languages
        .iter()
        .filter_map(|l| l.code.clone())
        .filter(|c| !c.is_empty())
        .collect();
    let selected = languages
        .iter()
        .find(|l| l.eq_ignore_ascii_case("en-US"))
        .or_else(|| languages.first())
        .cloned();
    st::DownloadInstallState {
        manifest_sha1: Some(manifest_id.to_uppercase()),
        version: manifest.version,
        selected_language: selected,
        licenses: manifest
            .licenses
            .iter()
            .map(|l| st::License { identifier: l.identifier.clone(), version: l.version })
            .collect(),
        chunks: manifest
            .chunks
            .iter()
            .map(|c| st::Chunk {
                chunk_id: c.id,
                is_required: c.r#type == download::chunk::ChunkType::Required as i32,
                // Optima downloads every chunk, optional languages included.
                is_downloaded: true,
                language: c.language.clone(),
                uplay_id: c.uplay_id,
                tags: c.tags.clone(),
                uplay_ids: c.uplay_ids.clone(),
            })
            .collect(),
        shortcut_name: Some(name.to_string()),
        installed_languages: languages.clone(),
        languages,
        patch_required: Some(false),
        game_name: Some(name.to_string()),
        game_version: manifest.game_version.clone(),
        uplay_id: Some(product_id),
        install_date: Some(now),
    }
}

/// Write `uplay_install.manifest` (Ubisoft's signed manifest, byte for byte)
/// and `uplay_install.state` next to the game, atomically.
fn write_connect_records(
    dir: &Path,
    product_id: u32,
    manifest_id: &str,
    name: &str,
    manifest_bytes: &[u8],
    manifest: &download::Manifest,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let state = connect_install_state(product_id, manifest_id, name, manifest, now).encode_to_vec();
    for (file, bytes) in [("uplay_install.manifest", manifest_bytes), ("uplay_install.state", &state[..])] {
        let tmp = dir.join(format!("{file}.optima-tmp"));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, dir.join(file))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn download_planned(
    demux: &mut Demux,
    dl: &mut DownloadService,
    demux_ticket: &str,
    product_id: u32,
    comp: i32,
    client: &reqwest::Client,
    install_dir: &Path,
    planned: &[Planned<'_>],
    state: &mut InstallState,
    progress: &mut Progress,
) -> Result<()> {
    use futures::StreamExt;
    use tokio::io::AsyncSeekExt;

    // In-flight slice requests for a file. Measured on a 103 MB/s line with a
    // 2.93 GB install (one 1274-slice file plus 186 small ones):
    //   16 -> 47.7s   32 -> 45.6s   64 -> 54.2s
    // 64 is worse than 16 and burns noticeably more sys time, so this is
    // connection churn rather than bandwidth. 32 is the measured best;
    // override per link with OPTIMA_SLICE_CONCURRENCY.
    let concurrency: usize = std::env::var("OPTIMA_SLICE_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n >= 1 && *n <= 256)
        .unwrap_or(32);
    let debug = std::env::var_os("OPTIMA_DEBUG").is_some();

    // Signed CDN urls carry an expiry token, so signing the whole install up
    // front would hand the last files links that have already died. Sign a
    // window of upcoming files instead: few enough round trips to stop the
    // per-file stall (one round trip per 100 paths), recent enough that the
    // urls are still valid when used.
    const SIGN_WINDOW_SLICES: usize = 400;
    let mut signed: std::collections::VecDeque<Vec<Vec<String>>> = Default::default();
    let mut next_to_sign = 0usize;
    let mut last_save = std::time::Instant::now();

    for (pi, p) in planned.iter().enumerate() {
        if pi >= next_to_sign {
            let mut paths = Vec::new();
            let mut counts = Vec::new();
            let mut j = pi;
            while j < planned.len() && paths.len() < SIGN_WINDOW_SLICES {
                paths.extend(planned[j].slice_paths.iter().cloned());
                counts.push(planned[j].slice_paths.len());
                j += 1;
            }
            let urls = sign_all(demux, dl, demux_ticket, product_id, &paths).await?;
            if urls.len() != paths.len() {
                bail!("signing returned {} urls for {} slices", urls.len(), paths.len());
            }
            let mut it = urls.into_iter();
            for n in counts {
                signed.push_back(it.by_ref().take(n).collect());
            }
            next_to_sign = j;
        }
        let mirrors = signed.pop_front().ok_or_else(|| anyhow!("signing window out of step"))?;
        let file = p.file;
        if debug {
            eprintln!(
                "[file {}] {} slices, {} mirror(s); url0={}",
                file.name,
                mirrors.len(),
                mirrors.first().map(|m| m.len()).unwrap_or(0),
                mirrors.first().and_then(|m| m.first()).map(|u| redact_url(u)).unwrap_or_default()
            );
        }

        // Write to a temp file, then rename on success — so an interrupted file
        // never leaves a wrong-sized artifact that resume would trust.
        let tmp_path = p.out_path.with_extension("optima-part");
        let mut out = tokio::fs::File::create(&tmp_path)
            .await
            .with_context(|| format!("create part file {}", tmp_path.display()))?;

        // Fetch slices CONCURRENTLY but keep order: `buffered(N)` runs N
        // requests in flight and yields results in input order. A failed
        // request moves on to the slice's next mirror.
        let fname = file.name.clone();
        let mut stream = futures::stream::iter(mirrors.into_iter().enumerate().map(|(idx, urls)| {
            let client = client.clone();
            let check = p.checks.get(idx).cloned();
            let fname = fname.clone();
            async move {
                let mut tries = 0usize;
                loop {
                    let url = &urls[tries % urls.len()];
                    let failure = match client.get(url).send().await.and_then(|r| r.error_for_status()) {
                        Ok(resp) => match resp.bytes().await {
                            Ok(b) => {
                                // A hash mismatch is not retried: the CDN served
                                // something definite and wrong, so repeating the
                                // request just repeats it.
                                return match check.as_ref() {
                                    Some(c) => verify_and_decompress(comp, &b, c, &fname, idx),
                                    None => decompress(comp, &b),
                                };
                            }
                            Err(e) => format!("reading slice body from {}: {e}", redact_url(url)),
                        },
                        Err(e) => format!("fetching slice from {}: {}", redact_url(url), e.without_url()),
                    };
                    tries += 1;
                    if tries > 5 {
                        return Err(anyhow!("{failure} (gave up after 5 tries)"));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }))
        .buffered(concurrency);

        let mut pos = 0u64;
        let mut idx = 0usize;
        while let Some(res) = stream.next().await {
            let bytes = res
                .with_context(|| format!("fetching a slice of {}", file.name))?;
            let at = p.offsets[idx];
            if at != pos {
                out.seek(std::io::SeekFrom::Start(at)).await?;
            }
            out.write_all(&bytes)
                .await
                .with_context(|| format!("writing to part file {}", tmp_path.display()))?;
            pos = at + bytes.len() as u64;
            idx += 1;
            progress.add(bytes.len() as u64, &file.name);
        }
        out.flush().await?;
        drop(out);
        // Every slice matched, so the total must match too; if it does not the
        // manifest disagrees with itself and the file must not be published.
        let written = tokio::fs::metadata(&tmp_path).await?.len();
        if written != file.size {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            bail!("{}: wrote {written} bytes but the manifest says {}", file.name, file.size);
        }
        tokio::fs::rename(&tmp_path, &p.out_path)
            .await
            .with_context(|| format!("rename {} -> {}", tmp_path.display(), p.out_path.display()))?;
        state.record(&file.name, &p.out_path);
        if last_save.elapsed() >= std::time::Duration::from_secs(10) {
            state.save(install_dir)?;
            last_save = std::time::Instant::now();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        decompress, mirrors_from_response, redact_url, safe_install_path, sha1_hex, slice_offsets,
        verify_and_decompress, verify_on_disk, Fatal, InstallState, SliceCheck,
    };
    use crate::proto::{download, download_service};
    use std::path::Path;

    #[test]
    fn connect_state_marks_every_chunk_installed() {
        use prost::Message;
        let manifest = download::Manifest {
            licenses: vec![download::License { identifier: "eula".into(), version: 3, ..Default::default() }],
            chunks: vec![
                download::Chunk { id: 1, r#type: 0, ..Default::default() },
                download::Chunk { id: 2, r#type: 1, language: Some("fr-FR".into()), ..Default::default() },
            ],
            languages: vec![
                download::Language { code: Some("fr-FR".into()), uplay_ids: vec![] },
                download::Language { code: Some("en-US".into()), uplay_ids: vec![] },
            ],
            version: Some(7),
            ..Default::default()
        };
        let st = super::connect_install_state(273, "abc123", "AC IV", &manifest, 1_700_000_000);
        assert_eq!(st.manifest_sha1.as_deref(), Some("ABC123"));
        assert_eq!(st.selected_language.as_deref(), Some("en-US"));
        assert_eq!(st.uplay_id, Some(273));
        assert_eq!(st.licenses[0].identifier, "eula");
        assert!(st.chunks.iter().all(|c| c.is_downloaded));
        assert!(st.chunks[0].is_required && !st.chunks[1].is_required);
        // Survives a round trip through the wire format.
        let back = crate::proto::download_install_state::DownloadInstallState::decode(&st.encode_to_vec()[..]).unwrap();
        assert_eq!(back, st);
    }

    /// Compression method 0 is not Deflate/Zstd, so `decompress` passes the
    /// bytes through — lets these tests exercise verification, not codecs.
    const PASSTHROUGH: i32 = 0;

    fn check_for(payload: &[u8]) -> SliceCheck {
        SliceCheck {
            download_size: Some(payload.len() as u32),
            download_sha1: Some(hex_to_bytes(&sha1_hex(payload))),
            size: payload.len() as u32,
            content_sha1: Some(hex_to_bytes(&sha1_hex(payload))),
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn accepts_a_slice_that_matches_the_manifest() {
        let payload = b"the quick brown fox".to_vec();
        let check = check_for(&payload);
        let out = verify_and_decompress(PASSTHROUGH, &payload, &check, "game.dat", 0).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn rejects_a_corrupted_slice() {
        let payload = b"the quick brown fox".to_vec();
        let check = check_for(&payload);
        let mut corrupt = payload.clone();
        corrupt[3] ^= 0xff; // same length, different bytes
        let err = verify_and_decompress(PASSTHROUGH, &corrupt, &check, "game.dat", 7)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sha1"), "unexpected error: {err}");
        assert!(err.contains("slice 7"), "error should name the slice: {err}");
    }

    #[test]
    fn rejects_a_truncated_slice() {
        let payload = b"the quick brown fox".to_vec();
        let check = check_for(&payload);
        let err = verify_and_decompress(PASSTHROUGH, &payload[..10], &check, "game.dat", 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("compressed size"), "unexpected error: {err}");
    }

    #[test]
    fn tolerates_a_manifest_without_hashes() {
        // Older manifests omit downloadSha1/slices; size still has to line up.
        let payload = b"legacy".to_vec();
        let check = SliceCheck {
            download_size: None,
            download_sha1: None,
            size: payload.len() as u32,
            content_sha1: None,
        };
        assert!(verify_and_decompress(PASSTHROUGH, &payload, &check, "old.dat", 0).is_ok());
    }

    #[test]
    fn accepts_plain_relative_paths() {
        let root = Path::new("/tmp/game");
        assert_eq!(
            safe_install_path(root, "data\\textures\\hero.dds").unwrap(),
            Path::new("/tmp/game/data/textures/hero.dds")
        );
        assert_eq!(
            safe_install_path(root, "game.exe").unwrap(),
            Path::new("/tmp/game/game.exe")
        );
        // "." components are noise, not an escape
        assert_eq!(
            safe_install_path(root, ".\\bin\\.\\x.dll").unwrap(),
            Path::new("/tmp/game/bin/x.dll")
        );
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        let root = Path::new("/tmp/game");
        for bad in [
            "..\\..\\.bashrc",
            "data/../../etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\System32\\evil.dll",
            "\\\\server\\share\\x",
            "",
            "   ",
            ".",
        ] {
            assert!(
                safe_install_path(root, bad).is_err(),
                "should have been rejected: {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_paths_crossing_a_symlink() {
        let tmp = std::env::temp_dir().join(format!("optima-test-{}", std::process::id()));
        let root = tmp.join("game");
        std::fs::create_dir_all(&root).unwrap();
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("mods")).unwrap();

        assert!(safe_install_path(&root, "mods\\payload.dll").is_err());
        std::fs::remove_dir_all(&tmp).ok();
    }

    fn file_with(size: u64, slices: &[(u32, Option<u64>)]) -> download::File {
        download::File {
            name: "game.forge".into(),
            size,
            slice_list: slices
                .iter()
                .map(|(s, o)| download::Slice { size: *s, file_offset: *o, ..Default::default() })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn offsets_default_to_back_to_back() {
        let f = file_with(30, &[(10, None), (15, None), (5, None)]);
        assert_eq!(slice_offsets(&f).unwrap(), vec![0, 10, 25]);
    }

    #[test]
    fn offsets_from_the_manifest_are_honored_out_of_order() {
        let f = file_with(30, &[(10, Some(20)), (20, Some(0))]);
        assert_eq!(slice_offsets(&f).unwrap(), vec![20, 0]);
    }

    #[test]
    fn offsets_that_do_not_tile_the_file_are_fatal() {
        for (size, slices) in [
            (30u64, vec![(10u32, Some(0u64)), (10, Some(5)), (10, Some(20))]), // overlap
            (30, vec![(10, Some(0)), (10, Some(25))]),                          // past end / short
            (20, vec![(10, Some(0)), (10, Some(15))]),                          // past end
            (30, vec![(10, Some(0)), (20, None)]),                              // mixed
            (25, vec![(10, None), (10, None)]),                                 // sum != size
            (20, vec![(10, Some(u64::MAX)), (10, Some(0))]),                    // overflow
        ] {
            let f = file_with(size, &slices);
            let err = slice_offsets(&f).expect_err(&format!("accepted {slices:?}"));
            assert!(err.downcast_ref::<Fatal>().is_some(), "not fatal: {err}");
        }
    }

    #[test]
    fn mirrors_stay_grouped_per_path() {
        use download_service::url_rsp::{DownloadUrls, UrlResponse};
        let rsp = download_service::UrlRsp {
            url_responses: vec![UrlResponse {
                result: download_service::url_rsp::Result::Success as i32,
                download_urls: vec![
                    DownloadUrls { urls: vec!["a1".into(), "a2".into()] },
                    DownloadUrls { urls: vec!["b1".into()] },
                ],
            }],
            ttl_seconds: 60,
        };
        let m = mirrors_from_response(rsp, 1, 2).unwrap();
        assert_eq!(m, vec![vec!["a1".to_string(), "a2".into()], vec!["b1".to_string()]]);
    }

    #[test]
    fn mirror_count_mismatch_and_not_owned_are_errors() {
        use download_service::url_rsp::{DownloadUrls, UrlResponse};
        let one = |result| download_service::UrlRsp {
            url_responses: vec![UrlResponse {
                result,
                download_urls: vec![DownloadUrls { urls: vec!["a".into()] }],
            }],
            ttl_seconds: 60,
        };
        assert!(mirrors_from_response(one(0), 1, 2).is_err());
        let err = mirrors_from_response(one(download_service::url_rsp::Result::NotOwned as i32), 1, 1)
            .unwrap_err();
        assert!(err.downcast_ref::<Fatal>().is_some());
    }

    #[test]
    fn signed_urls_are_redacted() {
        assert_eq!(redact_url("https://cdn/x/slice?sig=SECRET&exp=1"), "https://cdn/x/slice");
        assert_eq!(redact_url("https://cdn/x"), "https://cdn/x");
    }

    #[test]
    fn unsupported_codecs_are_fatal() {
        let lzham = download::CompressionMethod::Lzham as i32;
        assert!(decompress(lzham, b"x").unwrap_err().downcast_ref::<Fatal>().is_some());
        assert!(decompress(99, b"x").unwrap_err().downcast_ref::<Fatal>().is_some());
        assert_eq!(decompress(0, b"raw").unwrap(), b"raw");
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("optima-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn disk_verification_catches_a_changed_byte() {
        let dir = scratch("verify");
        let path = dir.join("f.bin");
        let (a, b) = (b"first slice".to_vec(), b"second".to_vec());
        let checks = vec![check_for(&a), check_for(&b)];
        let offsets = vec![0, a.len() as u64];
        std::fs::write(&path, [a.clone(), b.clone()].concat()).unwrap();
        assert!(verify_on_disk(&path, &checks, &offsets).unwrap());

        let mut bad = [a, b].concat();
        bad[13] ^= 1;
        std::fs::write(&path, &bad).unwrap();
        assert!(!verify_on_disk(&path, &checks, &offsets).unwrap());

        // Short file: the last slice cannot be read in full.
        std::fs::write(&path, &bad[..12]).unwrap();
        assert!(!verify_on_disk(&path, &checks, &offsets).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn state_is_bound_to_its_manifest_and_to_the_file_stamp() {
        let dir = scratch("state");
        let path = dir.join("f.bin");
        std::fs::write(&path, b"abc").unwrap();

        let mut st = InstallState::load(&dir, "M1");
        st.record("f.bin", &path);
        st.save(&dir).unwrap();

        let again = InstallState::load(&dir, "M1");
        assert!(again.trusts("f.bin", &std::fs::metadata(&path).unwrap()));
        // Another manifest starts over.
        assert!(InstallState::load(&dir, "M2").files.is_empty());

        // A rewrite (new mtime) is no longer trusted.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, b"xyz").unwrap();
        assert!(!again.trusts("f.bin", &std::fs::metadata(&path).unwrap()));
        std::fs::remove_dir_all(&dir).ok();
    }
}