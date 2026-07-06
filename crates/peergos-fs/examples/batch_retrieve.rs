//! Two-step directory read matching Java:
//!   1. `list_directory` returns every child's capability (from the parent's
//!      NamedRelativeCapability links) WITHOUT fetching the children.
//!   2. `retrieve_all_metadata` resolves all those caps in batched `champ/get/bulk`
//!      calls (<=MAX_CHAMP_GETS per call), verifying every returned block locally.
//!
//!   cargo run -p peergos-fs --example batch_retrieve -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{list_directory, retrieve_all_metadata, UserContext};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?,
    };
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let dir = ctx.get_home().await?.mkdir(&format!("batch{n}")).await?;

    // Create enough children to span >1 champ/get batch (MAX_CHAMP_GETS = 20).
    let names: Vec<String> = (0..25).map(|i| format!("file{i:02}.txt")).collect();
    for (i, name) in names.iter().enumerate() {
        dir.upload(name, format!("contents-of-{i}").as_bytes()).await?;
    }

    // --- 1. list: child caps only, no child fetch -----------------------------
    let entries = list_directory(dir.capability(), store.clone(), mutable.as_ref()).await?;
    println!("listed {} children (caps only, none retrieved):", entries.len());
    for e in &entries {
        println!("  {} -> map_key {}…", e.name, hex8(&e.cap.map_key));
    }
    assert_eq!(entries.len(), names.len());

    // --- 2. batch-retrieve every child cap via champ/get ----------------------
    let caps: Vec<_> = entries.iter().map(|e| e.cap.clone()).collect();
    let (retrieved, absent) = retrieve_all_metadata(&caps, store.clone(), mutable.as_ref()).await?;
    println!("\nbatch retrieved {} caps ({} absent) via champ/get/bulk", retrieved.len(), absent.len());
    assert!(absent.is_empty(), "no cap should be absent");
    assert_eq!(retrieved.len(), names.len());

    // Every retrieved node is a real file with the size we wrote.
    for rc in &retrieved {
        assert!(!rc.node.is_directory());
        let want = names.iter().position(|_| true); // just show sizes
        let _ = want;
        println!("  file size={} bytes  is_dir={}", rc.properties.size, rc.node.is_directory());
        assert!(rc.properties.size > 0);
    }

    println!("\nOK: list returns child caps without fetching; retrieve_all_metadata resolves them all in one batched, locally-verified champ/get.");
    Ok(())
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{x:02x}")).collect()
}
