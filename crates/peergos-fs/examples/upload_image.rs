//! Upload an image (with a webp thumbnail) into a writable directory link, then
//! verify the stored thumbnail's format and dimensions.
//!
//!   cargo run -p peergos-fs --example upload_image -- <base> <writable-dir-link> [image-path]

use image::DynamicImage;
use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

const THUMBNAIL_SIZE: u32 = 400;
const THUMBNAIL_DOWNSCALE: u32 = 200;
const THUMBNAIL_MAX_BYTES: usize = 100 * 1024;

/// Center-cropped square webp thumbnail of `size`×`size` (mirrors the Peergos
/// JavaImageThumbnailer: scale the short edge to `size`, crop the long edge).
fn center_crop_webp(img: &DynamicImage, size: u32) -> Vec<u8> {
    let (w, h) = (img.width(), img.height());
    let tall = h > w;
    let canvas_w = if tall { size } else { w * size / h };
    let canvas_h = if tall { h * size / w } else { size };
    let resized = img.resize_exact(canvas_w, canvas_h, image::imageops::FilterType::Triangle);
    let x = if tall { 0 } else { (canvas_w - size) / 2 };
    let y = if tall { (canvas_h - size) / 2 } else { 0 };
    let rgba = resized.crop_imm(x, y, size, size).to_rgba8();
    webp::Encoder::from_rgba(rgba.as_raw(), size, size).encode(80.0).to_vec()
}

/// 400×400 webp, downscaled to 200×200 if it exceeds 100 KiB.
fn make_thumbnail(bytes: &[u8]) -> Option<(String, Vec<u8>)> {
    let img = image::load_from_memory(bytes).ok()?;
    let big = center_crop_webp(&img, THUMBNAIL_SIZE);
    let data = if big.len() > THUMBNAIL_MAX_BYTES {
        center_crop_webp(&img, THUMBNAIL_DOWNSCALE)
    } else {
        big
    };
    Some(("image/webp".to_string(), data))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let link = args.get(2).cloned().expect("need a writable dir link");
    let home = std::env::var("HOME").unwrap_or_default();
    let path = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| format!("{home}/Downloads/climbing-koonya.jpg"));

    let bytes = std::fs::read(&path)?;
    let name = std::path::Path::new(&path).file_name().unwrap().to_string_lossy().to_string();
    println!("Read {} ({} bytes)", name, bytes.len());

    let thumbnail = make_thumbnail(&bytes);
    match &thumbnail {
        Some((m, d)) => {
            let td = image::load_from_memory(d)?;
            println!("Generated thumbnail: {m}, {}x{}, {} bytes", td.width(), td.height(), d.len());
        }
        None => println!("Could not decode image for a thumbnail; uploading without one."),
    }

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster);

    // Follow the link node to the real writable directory.
    let mut dir_cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    let (_n, props) = peergos_fs::retrieve_file_metadata(&dir_cap, store.clone(), &mutable).await?;
    if props.is_link {
        let children = peergos_fs::list_directory(&dir_cap, store.clone(), &mutable).await?;
        dir_cap = children.into_iter().next().ok_or("link node has no target")?.cap;
    }

    println!("\nUploading {name:?} with thumbnail ...");
    let file_cap = peergos_fs::upload_file(
        &dir_cap,
        &name,
        &bytes,
        thumbnail,
        None,
        None,
        store.clone(),
        &mutable,
    )
    .await?;
    println!("Uploaded ({} bytes).", bytes.len());

    // Verify: re-fetch the file's metadata from the server and inspect the thumbnail.
    println!("\nVerifying stored file + thumbnail from the server ...");
    let (_node, stored) = peergos_fs::retrieve_file_metadata(&file_cap, store.clone(), &mutable).await?;
    println!("  name: {}  size: {}  mime: {}", stored.name, stored.size, stored.mime_type);
    match &stored.thumbnail {
        Some((m, d)) => {
            let ti = image::load_from_memory(d)?;
            let is_webp = d.len() >= 12 && &d[0..4] == b"RIFF" && &d[8..12] == b"WEBP";
            println!(
                "  thumbnail: mime={m}, {} bytes, decoded {}x{}, webp-magic={is_webp}",
                d.len(),
                ti.width(),
                ti.height()
            );
        }
        None => println!("  NO THUMBNAIL STORED!"),
    }
    match &stored.tree_hash {
        Some(b) => println!(
            "  tree hash: root={}, level1={} chunk-hashes",
            b.root_hash.hash.iter().take(6).map(|x| format!("{x:02x}")).collect::<String>(),
            b.level1.as_ref().map(|l| l.chunk_hashes.len() / 32).unwrap_or(0)
        ),
        None => println!("  NO TREE HASH STORED!"),
    }

    // Read the full image back and confirm it round-trips byte-for-byte.
    let (_p, roundtrip) = peergos_fs::read_file(&file_cap, store, &mutable).await?;
    println!("  full-image round-trip: {} bytes, identical={}", roundtrip.len(), roundtrip == bytes);
    Ok(())
}
