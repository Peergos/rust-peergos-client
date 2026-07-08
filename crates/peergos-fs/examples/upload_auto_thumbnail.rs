//! Upload a file *without* an explicit thumbnail — tests the auto-generation
//! added to `upload_file`. Works for images and videos (if ffmpeg is installed).
//!
//!   cargo run --example upload_auto_thumbnail -- <base> <writable-dir-link> <file-path>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let link = args.get(2).cloned().expect("need a writable dir link");
    let path = args.get(3).cloned().expect("need a file path");
    let name = std::path::Path::new(&path).file_name().unwrap().to_string_lossy().to_string();
    let bytes = std::fs::read(&path)?;
    println!("Read {} ({} bytes)", name, bytes.len());

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster);

    let mut dir_cap =
        peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    let (_n, props) = peergos_fs::retrieve_file_metadata(&dir_cap, store.clone(), &mutable).await?;
    if props.is_link {
        let children = peergos_fs::list_directory(&dir_cap, store.clone(), &mutable).await?;
        dir_cap = children.into_iter().next().ok_or("link node has no target")?.cap;
    }

    // Pass `None` — auto-generation should kick in.
    println!("\nUploading {name:?} with auto-generated thumbnail ...");
    let file_cap = peergos_fs::upload_file(
        &dir_cap, &name, &bytes, None, None, None, store.clone(), &mutable,
    )
    .await?;

    // Inspect the stored thumbnail.
    let (_node, stored) =
        peergos_fs::retrieve_file_metadata(&file_cap, store.clone(), &mutable).await?;
    println!("  name: {}  size: {}  mime: {}", stored.name, stored.size, stored.mime_type);
    match &stored.thumbnail {
        Some((m, d)) => {
            let is_webp = d.len() >= 12 && &d[0..4] == b"RIFF" && &d[8..12] == b"WEBP";
            println!(
                "  thumbnail: mime={m}, {} bytes, webp-magic={is_webp}",
                d.len(),
            );
        }
        None => println!("  NO THUMBNAIL STORED!"),
    }
    Ok(())
}
