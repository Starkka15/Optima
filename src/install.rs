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
use std::path::Path;
use tokio::io::AsyncWriteExt;

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

    /// Sign relative CDN paths → full signed URLs.
    async fn sign(&mut self, demux: &mut Demux, product_id: u32, paths: Vec<String>) -> Result<Vec<String>> {
        let up = download_service::Upstream {
            request: Some(download_service::Req {
                request_id: self.next_id(),
                url_req: Some(download_service::UrlReq {
                    url_requests: vec![download_service::url_req::Request {
                        product_id,
                        relative_file_path: paths,
                        ..Default::default()
                    }],
                }),
                ..Default::default()
            }),
        };
        let raw = demux.service_call(self.conn, up.encode_to_vec()).await?;
        let down = download_service::Downstream::decode(&raw[..]).context("decoding url rsp")?;
        let urls = down
            .response
            .and_then(|r| r.url_rsp)
            .map(|u| {
                u.url_responses
                    .into_iter()
                    .flat_map(|resp| resp.download_urls.into_iter().flat_map(|d| d.urls))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(urls)
    }
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
    } else {
        // No/unknown compression → passthrough (matches the reference tool).
        Ok(data.to_vec())
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
) -> Result<Vec<String>> {
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

pub async fn install_game(
    demux: &mut Demux,
    demux_ticket: &str,
    product_id: u32,
    manifest_id: &str,
    name: &str,
    install_dir: &Path,
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
    eprintln!("[install] signed {} manifest url(s)", manifest_urls.len());
    let manifest_url = manifest_urls
        .first()
        .ok_or_else(|| anyhow!("no signed URL for the manifest"))?;
    let mbytes = reqwest::get(manifest_url).await?.bytes().await?;
    if mbytes.len() <= 356 {
        bail!("manifest is only {} bytes", mbytes.len());
    }
    let mut inflated = Vec::new();
    flate2::read::ZlibDecoder::new(&mbytes[356..])
        .read_to_end(&mut inflated)
        .context("inflating manifest")?;
    let manifest = download::Manifest::decode(&inflated[..]).context("decoding manifest")?;
    let comp = manifest.compression_method.unwrap_or(0);

    let files: Vec<&download::File> = manifest.chunks.iter().flat_map(|c| c.files.iter()).collect();
    let total_bytes: u64 = files.iter().map(|f| f.size).sum();
    println!(
        "{name}: {} files, {:.2} GB → {}",
        files.len(),
        total_bytes as f64 / 1e9,
        install_dir.display()
    );

    tokio::fs::create_dir_all(install_dir).await?;
    let client = reqwest::Client::new();

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
            for ((_, label), u) in paths.iter().zip(urls.iter()) {
                let st = client.get(u).send().await.map(|r| r.status().as_u16()).unwrap_or(0);
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
                for (layout, u) in candidates.iter().zip(urls.iter()) {
                    if client.get(u).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
                        chosen = *layout;
                        break;
                    }
                }
                eprintln!("[install] slice CDN layout: {chosen:?}");
                chosen
            }
        }
    };

    let mut skipped = 0usize;
    for (i, file) in files.iter().enumerate() {
        // Manifests use Windows `\` separators — map to the host separator so
        // subdirectories are created instead of literal-backslash filenames.
        let rel = file.name.replace('\\', std::path::MAIN_SEPARATOR_STR);
        let out_path = install_dir.join(&rel);
        if let Some(parent) = out_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create_dir_all {}", parent.display()))?;
        }

        // Empty file / directory → just touch it.
        if file.slice_list.is_empty() {
            tokio::fs::File::create(&out_path)
                .await
                .with_context(|| format!("touch empty file {}", out_path.display()))?;
            continue;
        }

        // Resume: skip files already fully written (matching uncompressed size).
        if let Ok(meta) = tokio::fs::metadata(&out_path).await {
            if meta.len() == file.size {
                skipped += 1;
                continue;
            }
        }

        // The CDN key is each slice's `downloadSha1` (the hash of the *compressed*
        // blob), NOT `File.slices` (the uncompressed content hash). Fall back to
        // the content hash for older, uncompressed manifests.
        let slice_paths: Vec<String> = file
            .slice_list
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let h = match &s.download_sha1 {
                    Some(d) if !d.is_empty() => hex_upper(d),
                    _ => hex_upper(file.slices.get(i).map(|v| v.as_slice()).unwrap_or_default()),
                };
                slice_path(slice_layout, &h)
            })
            .collect();
        // Sign the file's slice paths (with reconnect + batching). AC-sized files
        // have thousands of slices; packing them all into one urlReq makes a
        // protobuf big enough that the server drops the socket — so sign in
        // batches, reconnecting the whole session on any failure.
        let urls = sign_all(demux, &mut dl, demux_ticket, product_id, &slice_paths).await?;
        if std::env::var_os("OPTIMA_DEBUG").is_some() {
            eprintln!(
                "[file {}] {} slices, {} urls; slice0 path={} url={}",
                file.name,
                slice_paths.len(),
                urls.len(),
                slice_paths.first().cloned().unwrap_or_default(),
                urls.first().map(|u| u.chars().take(120).collect::<String>()).unwrap_or_default()
            );
        }

        // Write to a temp file, then rename on success — so an interrupted file
        // never leaves a wrong-sized artifact that resume would trust.
        let tmp_path = out_path.with_extension("optima-part");
        let mut out = tokio::fs::File::create(&tmp_path)
            .await
            .with_context(|| format!("create part file {}", tmp_path.display()))?;

        // Fetch slices CONCURRENTLY but keep write order: `buffered(N)` runs N
        // requests in flight and yields results in input order, so we stream them
        // straight to disk. Single-connection sequential fetching was the
        // bottleneck on AC-sized files (thousands of ~1 MB slices).
        const CONCURRENCY: usize = 16;
        let mut stream = futures::stream::iter(urls.iter().cloned().map(|url| {
            let client = client.clone();
            async move {
                let mut tries = 0;
                loop {
                    match client.get(&url).send().await.and_then(|r| r.error_for_status()) {
                        Ok(resp) => match resp.bytes().await {
                            Ok(b) => return decompress(comp, &b),
                            Err(e) => {
                                tries += 1;
                                if tries > 5 {
                                    return Err(anyhow!("reading slice body failed after 5 tries: {e}"));
                                }
                            }
                        },
                        Err(e) => {
                            tries += 1;
                            if tries > 5 {
                                return Err(anyhow!("fetching slice failed after 5 tries: {e}"));
                            }
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }))
        .buffered(CONCURRENCY);

        use futures::StreamExt;
        while let Some(res) = stream.next().await {
            let bytes = res.with_context(|| format!("fetching a slice of {}", file.name))?;
            out.write_all(&bytes)
                .await
                .with_context(|| format!("writing to part file {}", tmp_path.display()))?;
        }
        out.flush().await?;
        drop(out);
        tokio::fs::rename(&tmp_path, &out_path)
            .await
            .with_context(|| format!("rename {} -> {}", tmp_path.display(), out_path.display()))?;

        // Print progress every few files so the UI bar actually moves on games
        // with large files (AC-sized .forge files are hundreds of MB each).
        if (i + 1) % 5 == 0 || i + 1 == files.len() {
            println!("  [{}/{}] {}", i + 1, files.len(), file.name);
        }
    }

    if skipped > 0 {
        println!("  ({skipped} files already present, skipped)");
    }
    println!("Installed {name} to {}", install_dir.display());
    Ok(())
}
