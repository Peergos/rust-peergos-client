//! File upload transactions: normal upload, an interrupted upload (record +
//! partial chunks survive), then listing, resume, and cleanup.
//!
//!   cargo run -p peergos-fs --example transactions -- http://localhost:7777/

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());
    let (u, p) = ("w2", "w2pass");
    match peergos_fs::signup(u, p, None, poster.as_ref(), store.as_ref()).await {
        Ok(()) | Err(_) => {}
    }
    let user = peergos_fs::login(u, p, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = user.home().ok_or("no home")?.clone();

    let chunk = peergos_fs::CHUNK_MAX_SIZE as usize;
    let size = chunk + 2 * 1024 * 1024; // ~7 MiB → 2 chunks
    let data: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
    let owned = data.clone();
    let reader = move || Ok(Cursor::new(owned.clone()));

    // 1. A normal transactional upload completes and leaves no open transaction.
    println!("== Normal upload ==");
    let cap = peergos_fs::upload_file_with_transaction(
        &home, &home, "/w2/normal.bin", "normal.bin", size as u64, None, None, reader.clone(),
        store.clone(), &mutable).await?;
    let open = peergos_fs::list_open_transactions(&home, store.clone(), &mutable).await?;
    let (_p, back) = peergos_fs::read_file(&cap, store.clone(), &mutable).await?;
    println!("  uploaded {} bytes; open transactions: {}; read-back matches: {}", size, open.len(), back == data);
    assert!(open.is_empty() && back == data);

    // 2. An interrupted upload: pass 1 (hashing) sees the whole file, but pass 2
    //    fails after the first chunk — leaving a transaction record + partial chunks.
    println!("\n== Interrupted upload ==");
    let call = Arc::new(AtomicUsize::new(0));
    let d2 = data.clone();
    let fail_at = chunk; // fail right after the first chunk
    let open2 = {
        let call = call.clone();
        move || -> std::io::Result<Box<dyn Read>> {
            if call.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Box::new(Cursor::new(d2.clone())) as Box<dyn Read>)
            } else {
                Ok(Box::new(FailingReaderOwned { data: d2.clone(), pos: 0, fail_at }) as Box<dyn Read>)
            }
        }
    };
    let err = peergos_fs::upload_file_with_transaction(
        &home, &home, "/w2/big.bin", "big.bin", size as u64, None, None, open2,
        store.clone(), &mutable).await;
    println!("  upload result: {:?}", err.as_ref().map(|_| "ok").map_err(|e| e.to_string()));
    assert!(err.is_err(), "upload should have been interrupted");

    let open = peergos_fs::list_open_transactions(&home, store.clone(), &mutable).await?;
    println!("  open transactions after interruption: {}", open.len());
    for t in &open {
        println!("    {} -> path={:?} size={} chunks={}", &t.name[..16.min(t.name.len())], t.path, t.size, t.chunk_count());
    }
    assert_eq!(open.len(), 1);
    // The interrupted file is not yet visible in home.
    let visible = peergos_fs::list_directory(&home, store.clone(), &mutable).await?.iter().any(|e| e.name == "big.bin");
    println!("  big.bin visible in home yet: {visible}");

    // 3. Resume the interrupted upload with a good reader → completes.
    println!("\n== Resume ==");
    let txn = open.into_iter().next().unwrap();
    let full = { let d = data.clone(); move || Ok(Cursor::new(d.clone())) };
    let resumed = peergos_fs::resume_transaction(&home, &home, None, &txn, full, store.clone(), &mutable).await?;
    let after = peergos_fs::list_open_transactions(&home, store.clone(), &mutable).await?;
    let (_p, back) = peergos_fs::read_file(&resumed, store.clone(), &mutable).await?;
    println!("  resumed; open transactions: {}; read-back matches: {}", after.len(), back == data);
    assert!(after.is_empty() && back == data);

    // 4. Interrupt another upload, then CLEAR it (delete partial chunks + record).
    println!("\n== Clear a failed upload ==");
    let call = Arc::new(AtomicUsize::new(0));
    let d3 = data.clone();
    let open3 = {
        let call = call.clone();
        move || -> std::io::Result<Box<dyn Read>> {
            if call.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Box::new(Cursor::new(d3.clone())) as Box<dyn Read>)
            } else {
                Ok(Box::new(FailingReaderOwned { data: d3.clone(), pos: 0, fail_at: chunk }) as Box<dyn Read>)
            }
        }
    };
    let _ = peergos_fs::upload_file_with_transaction(
        &home, &home, "/w2/scratch.bin", "scratch.bin", size as u64, None, None, open3, store.clone(), &mutable).await;
    let open = peergos_fs::list_open_transactions(&home, store.clone(), &mutable).await?;
    assert_eq!(open.len(), 1, "expected a stuck transaction to clear");
    peergos_fs::clear_transaction(&home, &open[0], store.clone(), &mutable).await?;
    let after = peergos_fs::list_open_transactions(&home, store.clone(), &mutable).await?;
    println!("  cleared; open transactions now: {}", after.len());
    assert!(after.is_empty());

    println!("\nUpload transactions OK (normal / interrupt+list / resume / clear).");
    Ok(())
}

/// Owned variant of the failing reader (for boxed trait objects).
struct FailingReaderOwned {
    data: Vec<u8>,
    pos: usize,
    fail_at: usize,
}
impl Read for FailingReaderOwned {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.fail_at {
            return Err(std::io::Error::other("simulated upload interruption"));
        }
        let end = self.data.len().min(self.pos + buf.len()).min(self.fail_at);
        let n = end - self.pos;
        buf[..n].copy_from_slice(&self.data[self.pos..end]);
        self.pos += n;
        Ok(n)
    }
}
