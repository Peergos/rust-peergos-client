//! Multi-chunk truncate / append / writable-file rotation.
//!   cargo run -p peergos-fs --example multichunk_edit -- http://localhost:7777/
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{retrieve_secret_link_capability, read_file, UserContext};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MIB: usize = 1024 * 1024;
fn pattern(n: usize) -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));
    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c, Err(_) => UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?,
    };
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let dir = ctx.get_home().await?.mkdir(&format!("mc{n}")).await?;

    // truncate: 11 MiB (3 chunks) -> 6 MiB (2 chunks) -> 1 MiB (1 chunk)
    let big = pattern(11 * MIB);
    let f = dir.upload("t.bin", &big).await?;
    f.truncate((6 * MIB) as u64).await?;
    let a = dir.get_by_path("t.bin").await?.unwrap();
    assert_eq!(a.size(), (6 * MIB) as u64);
    assert!(a.read().await? == big[..6 * MIB], "truncate 3->2 chunks content");
    a.truncate(MIB as u64).await?;
    let b = dir.get_by_path("t.bin").await?.unwrap();
    assert!(b.size() == MIB as u64 && b.read().await? == big[..MIB], "truncate to 1 chunk");
    println!("truncate 11MiB -> 6MiB -> 1MiB: content matches at each step");

    // append: 4 MiB + 3 MiB = 7 MiB (crosses into a 2nd chunk)
    let base4 = pattern(4 * MIB);
    let g = dir.upload("a.bin", &base4).await?;
    let extra = vec![0xEE; 3 * MIB];
    g.append(&extra).await?;
    let ga = dir.get_by_path("a.bin").await?.unwrap();
    let mut want = base4.clone(); want.extend_from_slice(&extra);
    assert_eq!(ga.size(), (7 * MIB) as u64);
    assert!(ga.read().await? == want, "append across chunk boundary");
    println!("append 4MiB + 3MiB -> 7MiB (2 chunks): content matches");

    // writable link to a multi-chunk file (rotation into own writer)
    let m = pattern(8 * MIB);
    dir.upload("w.bin", &m).await?;
    let parent_writer = dir.capability().writer.clone();
    let link = ctx.create_secret_link(&format!("mc{n}/w.bin"), true, "", None, None).await?;
    let cap = retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    assert!(cap.is_writable() && cap.writer != parent_writer, "writable, own writer");
    let (_p, via) = read_file(&cap, store.clone(), mutable.as_ref()).await?;
    assert!(via == m, "multi-chunk content preserved through rotation");
    // still readable at its path
    assert!(ctx.get_by_path(&format!("mc{n}/w.bin")).await?.unwrap().read().await? == m);
    println!("writable link to 8MiB file: rotated to own writer, content preserved");

    println!("\nMulti-chunk edit OK: truncate, append, and writable-file rotation all handle >1 chunk.");
    Ok(())
}
