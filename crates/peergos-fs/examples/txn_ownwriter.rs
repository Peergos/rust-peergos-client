//! Transactional uploads across writer configurations, all with `entry_signer =
//! None` (the writer is resolved automatically, like Java's `parent.signingPair`):
//!  (a) into home (the entry-point writer),
//!  (b) into a PLAIN subdir (shares home's writer, no writer link of its own),
//!  (c) into an OWN-writer dir (as when write-shared) — the transaction record
//!      lives under home's `.transactions` (home writer) while the file chunks
//!      live in the dir's own writer subspace.
//!
//!   cargo run -p peergos-fs --example txn_ownwriter -- http://localhost:7777/

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::io::Cursor;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());
    let _ = peergos_fs::signup("w2", "w2pass", None, poster.as_ref(), store.as_ref()).await;
    let user = peergos_fs::login("w2", "w2pass", poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = user.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;

    let data: Vec<u8> = (0..1500u32).map(|i| i as u8).collect();

    let plain = peergos_fs::create_directory(&home, "plain", Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::create_directory(&home, "own", Some(signer.clone()), None, store.clone(), &mutable).await?;
    let own = peergos_fs::move_dir_to_own_writer(&home, "own", None, None, store.clone(), &mutable).await?;

    for (label, dir) in [("home", &home), ("plain-subdir", &plain), ("own-writer", &own)] {
        let d = data.clone();
        let path = format!("/w2/{label}/f.bin");
        let cap = peergos_fs::upload_file_with_transaction(
            &home, dir, &path, "f.bin", data.len() as u64, None, None, None,
            move || Ok(Cursor::new(d.clone())), store.clone(), &mutable).await?;
        let open = peergos_fs::list_open_transactions(&home, store.clone(), &mutable).await?;
        let (_p, back) = peergos_fs::read_file(&cap, store.clone(), &mutable).await?;
        println!("{label:>13}: writer==home? {}  open_txns={}  matches={}",
            dir.writer == home.writer, open.len(), back == data);
        assert!(open.is_empty() && back == data, "{label} failed");
    }
    println!("OK: transactional uploads work for home, plain subdirs, and own-writer dirs (entry_signer=None).");
    Ok(())
}
