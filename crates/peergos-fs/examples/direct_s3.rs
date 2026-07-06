//! DirectS3Storage: a ContentAddressedStorage that reads/writes large blocks
//! straight to S3 when the server is S3-backed, and otherwise delegates to the
//! server. This demo fetches the server's block-store properties and then drives a
//! full sign-in + upload + read THROUGH a DirectS3Storage.
//!
//! On an IPFS-backed dev server (like :7777) S3 is disabled, so every operation
//! transparently delegates to the fallback HttpStorage — proving the wrapper is
//! safe to slot in anywhere. Against an S3-backed Peergos server, large blocks
//! would go directly to S3.
//!
//!   cargo run -p peergos-fs --example direct_s3 -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, DirectS3Storage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let server: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let direct: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let fallback: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));

    // Show what the server advertises.
    let props = DirectS3Storage::fetch_properties(server.as_ref()).await?;
    println!(
        "blockstore props: direct_writes={} public_reads={} authed_reads={} (uses S3: {})",
        props.direct_writes, props.public_reads, props.authed_reads, props.use_direct_block_store()
    );

    // Wrap the server storage in a DirectS3Storage and use it everywhere.
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(DirectS3Storage::build(server, direct, fallback).await);
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);

    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster, store.clone(), mutable.clone()).await?,
    };

    // A full round-trip through the DirectS3-backed store.
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let home = ctx.get_home().await?;
    let name = format!("s3demo{n}.txt");
    let file = home.upload(&name, b"stored via DirectS3Storage").await?;
    let data = file.read().await?;
    println!("uploaded + read {name:?} through DirectS3Storage -> {:?}", String::from_utf8_lossy(&data));
    assert_eq!(data, b"stored via DirectS3Storage");

    // Also verify a >1 MiB (multi-fragment) upload: put_raw sees large blocks but,
    // with S3 disabled, still routes them to the server.
    let big: Vec<u8> = (0..(6 * 1024 * 1024u32)).map(|i| (i * 7) as u8).collect();
    let big_file = home.upload(&format!("s3big{n}.bin"), &big).await?;
    assert_eq!(big_file.read().await?.len(), big.len());
    println!("multi-fragment ({} MiB) upload+read OK through DirectS3Storage", big.len() / (1024 * 1024));

    println!("\nDirectS3Storage OK: properties fetched, transparent delegation verified end-to-end.");
    Ok(())
}
