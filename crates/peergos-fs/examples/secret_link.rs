//! Resolve a Peergos secret link against a live server and print the decrypted
//! capability. Usage:
//!
//!   cargo run -p peergos-fs --example secret_link -- <base-url> <link> [user-password]
//!
//! e.g. cargo run -p peergos-fs --example secret_link -- \
//!        http://localhost:7777/ \
//!        'http://localhost:7777/secret/z59.../1126520708#uAjtTdWVWURJ'

use peergos_cbor::Cborable;
use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let link = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| {
            "http://localhost:7777/secret/z59vuwzfFDotcy4BSS7EPNyKWQcjwn7L2Hg3dLBrqyCyfSbvS5WJLj5/1126520708#uAjtTdWVWURJ".to_string()
        });
    let user_password = args.get(3).map(|s| s.as_str());

    // Local server needs POST (not GET) for the API, so is_public_server = false.
    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn peergos_core::ContentAddressedStorage> =
        Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster);

    println!("Resolving secret link against {base} ...");
    let cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), user_password).await?;

    println!("Decrypted capability:");
    println!("  owner:    {}", cap.owner);
    println!("  writer:   {}", cap.writer);
    println!("  map key:  {}", hex(&cap.map_key));
    println!("  base key: {} bytes", cap.r_base_key.key.len());
    println!("  bat:      {}", if cap.bat.is_some() { "present" } else { "none" });
    println!("  writable: {}", cap.is_writable());
    println!("  cap cbor: {} bytes", cap.serialize().len());

    println!("\nWalking to the target's metadata ...");
    let (node, props) =
        peergos_fs::retrieve_file_metadata(&cap, store.clone(), &mutable).await?;
    println!("Target:");
    println!("  name:        {}", props.name);
    println!("  is directory: {}", node.is_directory());
    println!("  size:        {} bytes", props.size);
    println!("  mime type:   {}", props.mime_type);
    println!("  hidden:      {}", props.is_hidden);
    println!("  streamed:    {}", props.stream_secret.is_some());

    if node.is_directory() {
        println!("\nListing directory ...");
        let entries = peergos_fs::list_directory(&cap, store.clone(), &mutable).await?;
        println!("  {} entries:", entries.len());
        for e in &entries {
            let kind = match e.is_dir {
                Some(true) => "dir ",
                Some(false) => "file",
                None => "?   ",
            };
            println!("  [{kind}] {}", e.name);
        }
        // Verify child caps are usable by reading a small text child.
        if let Some(child) = entries
            .iter()
            .find(|e| e.name.ends_with(".md") || e.name.ends_with(".txt"))
        {
            println!("\nReading child {:?} via its listed capability ...", child.name);
            let (props, data) = peergos_fs::read_file(&child.cap, store, &mutable).await?;
            println!("  {} bytes", props.size);
            if let Ok(text) = std::str::from_utf8(&data) {
                println!("  contents: {text:?}");
            }
        }
    } else {
        println!("\nReading file contents ...");
        let (props, data) = peergos_fs::read_file(&cap, store, &mutable).await?;
        println!("  {} bytes decrypted", data.len());
        // Always save to /tmp so binary files (e.g. zips) can be inspected.
        let out_path = format!("/tmp/{}", props.name);
        std::fs::write(&out_path, &data)?;
        println!("  wrote {} bytes to {out_path}", data.len());
        if let Ok(text) = std::str::from_utf8(&data) {
            let lines: Vec<&str> = text.lines().collect();
            println!("  {} lines", lines.len());
            if data.len() <= 512 {
                println!("  contents (utf-8): {text:?}");
            } else {
                let last = lines.iter().rev().find(|l| !l.trim().is_empty());
                println!("  last non-empty line: {:?}", last.unwrap_or(&""));
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
