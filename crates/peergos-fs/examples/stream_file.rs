//! Stream a file up and down without buffering it in RAM: upload from a
//! file-backed reader, download into a file sink. Verifies the round-trip.
//!
//!   cargo run -p peergos-fs --example stream_file -- <base> <writable-dir-link> <path>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let link = args.get(2).cloned().expect("need a writable dir link");
    let path = args.get(3).cloned().expect("need a file path");

    let name = std::path::Path::new(&path).file_name().unwrap().to_string_lossy().to_string();
    let size = std::fs::metadata(&path)?.len();
    println!("Streaming up {name:?} ({size} bytes) from {path} ...");

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster);

    let mut dir_cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    let (_n, props) = peergos_fs::retrieve_file_metadata(&dir_cap, store.clone(), &mutable).await?;
    if props.is_link {
        let children = peergos_fs::list_directory(&dir_cap, store.clone(), &mutable).await?;
        dir_cap = children.into_iter().next().ok_or("link node has no target")?.cap;
    }

    // Upload streaming: the reader is opened per pass; the file is never fully
    // buffered in memory.
    let path_up = path.clone();
    let file_cap = peergos_fs::upload_file_streaming(
        &dir_cap,
        &name,
        size,
        None,
        None,
        None,
        move || File::open(&path_up),
        store.clone(),
        &mutable,
    )
    .await?;
    println!("Uploaded.");

    // Download streaming: write each decrypted chunk straight to a file.
    let out_path = format!("/tmp/streamed-{name}");
    let mut out = std::io::BufWriter::new(File::create(&out_path)?);
    let mut total = 0u64;
    let stored = peergos_fs::read_file_to(&file_cap, store, &mutable, |chunk| {
        out.write_all(chunk).map_err(|e| peergos_core::Error::Protocol(e.to_string()))?;
        total += chunk.len() as u64;
        Ok(())
    })
    .await?;
    out.flush()?;
    drop(out);

    println!("Downloaded {total} bytes to {out_path}");
    let on_disk = std::fs::metadata(&out_path)?.len();
    // Stream-compare the two files in 1 MiB windows (no full buffering).
    let identical = files_equal(&path, &out_path)?;
    println!("  declared size: {}  on disk: {on_disk}  identical: {identical}", stored.size);
    assert!(identical, "round-trip mismatch!");
    Ok(())
}

fn files_equal(a: &str, b: &str) -> std::io::Result<bool> {
    let (mut fa, mut fb) = (File::open(a)?, File::open(b)?);
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let na = read_full(&mut fa, &mut ba)?;
        let nb = read_full(&mut fb, &mut bb)?;
        if na != nb || ba[..na] != bb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }
}

fn read_full(f: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::io::Read;
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}
