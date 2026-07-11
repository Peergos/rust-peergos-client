//! Live DirectS3 verification against an S3-backed Peergos server.
//!
//! Uploads a multi-chunk file and reads it back THROUGH a DirectS3Storage, with an
//! instrumented poster wrapping the "direct" (presigned-S3) transport so we can
//! prove that the large raw fragment blocks (~1 MiB each) are written to and read
//! from S3 directly, not proxied through the server.
//!
//!   cargo run -p peergos-fs --example direct_s3_live -- <base-url> <username> <password>

use async_trait::async_trait;
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, DirectS3Storage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_core::error::Result;
use peergos_fs::UserContext;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Wraps a poster and records the byte sizes of the direct (S3) PUTs and GETs it
/// performs, so we can tell large-block S3 traffic from small.
struct CountingPoster {
    inner: Arc<dyn HttpPoster>,
    put_sizes: Mutex<Vec<usize>>,
    get_sizes: Mutex<Vec<usize>>,
    posts: AtomicUsize,
}

impl CountingPoster {
    fn new(inner: Arc<dyn HttpPoster>) -> Arc<CountingPoster> {
        Arc::new(CountingPoster { inner, put_sizes: Mutex::new(Vec::new()), get_sizes: Mutex::new(Vec::new()), posts: AtomicUsize::new(0) })
    }
    fn large(v: &Mutex<Vec<usize>>) -> (usize, usize, usize) {
        let g = v.lock().unwrap();
        let large = g.iter().filter(|&&n| n >= 100 * 1024).count();
        let bytes: usize = g.iter().sum();
        (g.len(), large, bytes)
    }
    fn report(&self, phase: &str) {
        let (puts, put_large, put_bytes) = Self::large(&self.put_sizes);
        let (gets, get_large, get_bytes) = Self::large(&self.get_sizes);
        println!(
            "[{phase}] direct-S3: PUTs={puts} (>=100KiB: {put_large}, {} MiB) GETs={gets} (>=100KiB: {get_large}, {} MiB) presign-POSTs={}",
            put_bytes / (1024 * 1024),
            get_bytes / (1024 * 1024),
            self.posts.load(Ordering::Relaxed),
        );
    }
}

#[async_trait]
impl HttpPoster for CountingPoster {
    async fn post(&self, url: &str, payload: Vec<u8>, unzip: bool, timeout_ms: i32) -> Result<Vec<u8>> {
        self.posts.fetch_add(1, Ordering::Relaxed);
        self.inner.post(url, payload, unzip, timeout_ms).await
    }
    async fn put(&self, url: &str, body: Vec<u8>, headers: Vec<(String, String)>) -> Result<Vec<u8>> {
        let n = body.len();
        let r = self.inner.put(url, body, headers).await;
        if r.is_ok() {
            self.put_sizes.lock().unwrap().push(n);
        }
        r
    }
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let r = self.inner.get(url).await;
        if let Ok(bytes) = &r {
            self.get_sizes.lock().unwrap().push(bytes.len());
        }
        r
    }
}

/// Build a DirectS3-backed store, returning it plus the counting poster wrapping
/// the direct S3 transport.
async fn build_store(base: &str) -> Result<(Arc<dyn ContentAddressedStorage>, Arc<CountingPoster>)> {
    let server: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(base, false)?);
    // The direct transport talks to absolute presigned S3 URLs, so it must issue
    // real GETs/PUTs (is_public_server = true).
    let direct = CountingPoster::new(Arc::new(ReqwestPoster::new(base, true)?));
    let fallback: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(base, false)?), true));
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(DirectS3Storage::build(server, direct.clone(), fallback).await);
    Ok((store, direct))
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "https://test.peergos.net/".to_string());
    let username = args.next().expect("usage: direct_s3_live <base> <username> <password>");
    let password = args.next().expect("usage: direct_s3_live <base> <username> <password>");

    let server_only: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let props = DirectS3Storage::fetch_properties(server_only.as_ref()).await?;
    println!(
        "server blockstore: direct_writes={} public_reads={} authed_reads={} (uses S3: {})",
        props.direct_writes, props.public_reads, props.authed_reads, props.use_direct_block_store()
    );
    if !props.use_direct_block_store() {
        println!("!! server is not S3-backed; direct-S3 cannot be verified here");
        return Ok(());
    }

    // Upload a file from disk if a path is given, else a synthetic ~7 MiB file.
    let (data, name) = match args.next() {
        Some(path) => {
            let bytes = std::fs::read(&path)?;
            let base_name = std::path::Path::new(&path).file_name().and_then(|s| s.to_str()).unwrap_or("upload.bin").to_string();
            (bytes, base_name)
        }
        None => {
            let size = 7 * 1024 * 1024;
            ((0..size).map(|i| (i as u64).wrapping_mul(131).wrapping_add(7) as u8).collect(), format!("directs3-multichunk-{}.bin", now()))
        }
    };
    let size = data.len();
    let source_hash = peergos_crypto::hash::sha256(&data);

    // ---- Phase 1: upload, verifying large blocks are WRITTEN to S3 ----------
    let (store, direct_w) = build_store(&base).await?;
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);

    let ctx = UserContext::sign_in(&username, &password, None, poster.clone(), store.clone(), mutable.clone()).await?;
    println!("signed in as {username}");
    let home = ctx.get_home().await?;
    // Replace any existing copy so a re-run refreshes it (e.g. to add a thumbnail).
    let _ = home.remove_child(&name).await;
    let home = ctx.get_home().await?;
    let file = home.upload(&name, &data).await?;
    println!("uploaded {name:?} ({} MiB, size={})", size / (1024 * 1024), file.size());
    direct_w.report("write");
    let (_, put_large, _) = CountingPoster::large(&direct_w.put_sizes);
    assert!(put_large > 0, "expected large raw fragment blocks to be PUT directly to S3");

    // ---- Phase 2: cold read, verifying large blocks are READ from S3 --------
    // A brand-new context + store => cold cryptree cache, so the fragment blocks
    // are actually fetched (from S3) rather than served from memory.
    let (store2, direct_r) = build_store(&base).await?;
    let mutable2: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));
    let poster2: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let ctx2 = UserContext::sign_in(&username, &password, None, poster2, store2, mutable2).await?;
    let readback = ctx2
        .get_by_path(&format!("/{username}/{name}"))
        .await?
        .expect("file should exist")
        .read()
        .await?;
    direct_r.report("read");

    assert_eq!(readback.len(), size, "read-back length mismatch");
    assert_eq!(peergos_crypto::hash::sha256(&readback), source_hash, "read-back content hash mismatch");
    let (_, get_large, _) = CountingPoster::large(&direct_r.get_sizes);
    assert!(get_large > 0, "expected large raw fragment blocks to be GET directly from S3");

    println!(
        "\nOK: {} MiB multi-chunk file round-tripped; {} large fragment blocks written to S3, {} read from S3.",
        size / (1024 * 1024),
        put_large,
        get_large
    );
    println!("left {name:?} in /{username} for manual verification (not deleted)");
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
