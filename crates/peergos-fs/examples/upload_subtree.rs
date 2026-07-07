//! Efficient batched subtree upload: 1000 small (1 KiB) files into one directory
//! in a single buffered commit — should take on the order of ~10s, versus one
//! server round-trip per file.
//!
//!   cargo run --release -p peergos-fs --example upload_subtree -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{FileUpload, FolderUpload, UserContext};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let username = format!("sub{n}");
    let ctx = UserContext::sign_up(&username, "subpass99", None, poster.clone(), store.clone(), mutable.clone()).await?;
    println!("signed up {username}");

    // 1000 distinct 1 KiB files, all in one directory.
    const COUNT: usize = 1000;
    let make_files = || -> Vec<FileUpload> {
        (0..COUNT)
            .map(|i| FileUpload {
                name: format!("f{i:04}.bin"),
                data: {
                    let mut d = vec![(i % 251) as u8; 1024];
                    d[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                    d
                },
            })
            .collect()
    };

    let dir = ctx.get_home().await?.mkdir(&format!("bulk{n}")).await?;

    let started = Instant::now();
    dir.upload_subtree(vec![FolderUpload { rel_path: vec![], files: make_files() }]).await?;
    let elapsed = started.elapsed();
    println!("uploaded {COUNT} x 1 KiB files in {:.2}s", elapsed.as_secs_f64());
    assert!(elapsed.as_secs() < 30, "1000 small files took too long: {:.1}s", elapsed.as_secs_f64());

    // Correctness: all children present, sample contents intact.
    let refreshed = ctx.get_by_path(&format!("bulk{n}")).await?.expect("dir");
    let count = refreshed.direct_children_count().await?;
    println!("directory now has {count} children");
    assert_eq!(count, COUNT, "every uploaded file must be present");

    for i in [0usize, 1, 499, 999] {
        let f = ctx.get_by_path(&format!("bulk{n}/f{i:04}.bin")).await?.expect("file");
        let data = f.read().await?;
        assert_eq!(data.len(), 1024);
        assert_eq!(&data[0..4], &(i as u32).to_le_bytes(), "content of f{i:04} must match");
    }
    println!("sampled files read back correctly");

    // Dedup: re-uploading the identical tree skips every file (content unchanged),
    // so it is much faster and the directory is unchanged.
    let dir2 = ctx.get_by_path(&format!("bulk{n}")).await?.expect("dir");
    let started2 = Instant::now();
    dir2.upload_subtree(vec![FolderUpload { rel_path: vec![], files: make_files() }]).await?;
    let elapsed2 = started2.elapsed();
    let count2 = ctx.get_by_path(&format!("bulk{n}")).await?.expect("dir").direct_children_count().await?;
    println!("re-uploaded identical {COUNT} files in {:.2}s (dedup); children still {count2}", elapsed2.as_secs_f64());
    assert_eq!(count2, COUNT, "dedup must not add or drop children");
    assert!(elapsed2 < elapsed, "re-upload (all deduped) must be faster than the initial upload");

    println!("\nupload_subtree OK: {COUNT} files in one buffered commit ({:.2}s); re-upload deduped ({:.2}s).", elapsed.as_secs_f64(), elapsed2.as_secs_f64());
    Ok(())
}
