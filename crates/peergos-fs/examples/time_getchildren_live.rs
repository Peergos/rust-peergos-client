//! Time `UserContext::get_children` for a directory with 10 children on a live
//! server, logging every HTTP request made during the call (with per-call timing).
//!
//!   cargo run -p peergos-fs --example time_getchildren_live -- <base> <username> <password> [dir]

use async_trait::async_trait;
use peergos_core::error::Result;
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, DirectS3Storage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Shared log across every poster: an on/off switch and the collected entries.
struct LogState {
    enabled: AtomicBool,
    entries: Mutex<Vec<String>>,
}

/// A poster that records each HTTP call it makes (method, url, sizes, elapsed)
/// into a shared [`LogState`] when logging is enabled.
struct LoggingPoster {
    inner: Arc<dyn HttpPoster>,
    state: Arc<LogState>,
    tag: &'static str,
}

impl LoggingPoster {
    fn record(&self, method: &str, url: &str, req_len: usize, resp: &Result<Vec<u8>>, dt_ms: f64) {
        if !self.state.enabled.load(Ordering::Relaxed) {
            return;
        }
        let short = shorten(url);
        let resp_str = match resp {
            Ok(b) => format!("resp={}B", b.len()),
            Err(e) => format!("ERR {e}"),
        };
        self.state
            .entries
            .lock()
            .unwrap()
            .push(format!("{dt_ms:8.1}ms  [{}] {method} {short}  req={req_len}B {resp_str}", self.tag));
    }
}

#[async_trait]
impl HttpPoster for LoggingPoster {
    async fn post(&self, url: &str, payload: Vec<u8>, unzip: bool, timeout_ms: i32) -> Result<Vec<u8>> {
        let n = payload.len();
        let t = Instant::now();
        let r = self.inner.post(url, payload, unzip, timeout_ms).await;
        self.record("POST", url, n, &r, t.elapsed().as_secs_f64() * 1000.0);
        r
    }
    async fn put(&self, url: &str, body: Vec<u8>, headers: Vec<(String, String)>) -> Result<Vec<u8>> {
        let n = body.len();
        let t = Instant::now();
        let r = self.inner.put(url, body, headers).await;
        self.record("PUT", url, n, &r, t.elapsed().as_secs_f64() * 1000.0);
        r
    }
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let t = Instant::now();
        let r = self.inner.get(url).await;
        self.record("GET", url, 0, &r, t.elapsed().as_secs_f64() * 1000.0);
        r
    }
}

fn shorten(url: &str) -> String {
    // Keep the last path segment(s) / query start so lines stay readable.
    let u = url.split("://").last().unwrap_or(url);
    if u.len() <= 80 {
        u.to_string()
    } else {
        format!("{}…{}", &u[..40], &u[u.len() - 36..])
    }
}

fn logged(base: &str, public: bool, state: &Arc<LogState>, tag: &'static str) -> Result<Arc<LoggingPoster>> {
    Ok(Arc::new(LoggingPoster { inner: Arc::new(ReqwestPoster::new(base, public)?), state: state.clone(), tag }))
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "https://test.peergos.net/".to_string());
    let username = args.next().expect("usage: <base> <username> <password> [dir]");
    let password = args.next().expect("usage: <base> <username> <password> [dir]");
    let dir_name = args.next().unwrap_or_else(|| "ls-bench".to_string());

    let state = Arc::new(LogState { enabled: AtomicBool::new(false), entries: Mutex::new(Vec::new()) });

    let poster: Arc<dyn HttpPoster> = logged(&base, false, &state, "core")?;
    // Pointer cache (7s TTL) over the HTTP pointers, so repeated lookups within a
    // single operation are served from RAM.
    let http_mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(logged(&base, false, &state, "mut")?));
    let mutable: Arc<dyn MutablePointers> = Arc::new(peergos_core::CachedMutablePointers::new(http_mutable));
    let http_store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(logged(&base, false, &state, "store")?, true));

    // Props-driven: only use direct-S3 when the server advertises it.
    let props = DirectS3Storage::fetch_properties(poster.as_ref()).await.unwrap_or_default();
    println!("server S3-backed: {}", props.use_direct_block_store());
    let raw_store: Arc<dyn ContentAddressedStorage> = if props.use_direct_block_store() {
        Arc::new(DirectS3Storage::with_properties(
            props,
            logged(&base, false, &state, "s3srv")?,
            logged(&base, true, &state, "s3get")?,
            http_store,
        ))
    } else {
        http_store
    };
    // Small in-RAM cbor block cache over the store.
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(peergos_core::CachedStorage::new(raw_store));

    let ctx = UserContext::sign_in(&username, &password, None, poster, store, mutable).await?;
    println!("signed in as {username}");

    // --- Ensure the directory has exactly 10 children (setup, not logged) ----
    let path = format!("/{username}/{dir_name}");
    let existing = ctx.get_children(&path).await.unwrap_or_default();
    if existing.len() != 10 {
        println!("setting up {path} with 10 files (had {})...", existing.len());
        let home = ctx.get_home().await?;
        let dir = home.get_or_mkdirs(&dir_name).await?;
        // Remove any stragglers then create exactly 10.
        for c in dir.children().await? {
            let _ = dir.remove_child(c.name()).await;
        }
        let dir = ctx.get_by_path(&path).await?.unwrap();
        for i in 0..10 {
            dir.upload(&format!("file{i:02}.txt"), format!("child number {i}\n").as_bytes()).await?;
        }
    }

    // --- Time get_children, logging every HTTP call it makes -----------------
    state.entries.lock().unwrap().clear();
    state.enabled.store(true, Ordering::Relaxed);
    let t = Instant::now();
    let children = ctx.get_children(&path).await?;
    let elapsed = t.elapsed();
    state.enabled.store(false, Ordering::Relaxed);

    let log = state.entries.lock().unwrap();
    println!("\n--- HTTP calls during get_children({path}) ---");
    for line in log.iter() {
        println!("{line}");
    }
    let http_total: f64 = 0.0; // (sum shown per line; wall time below is what matters)
    let _ = http_total;
    println!("\nget_children returned {} children in {:.1} ms across {} HTTP call(s)", children.len(), elapsed.as_secs_f64() * 1000.0, log.len());
    Ok(())
}
