//! List a directory on a live server and sanity-check any PDF files in it.
//!   cargo run -p peergos-fs --example read_dir_live -- <base> <username> <password> <dir-path>

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "https://test.peergos.net/".to_string());
    let username = args.next().expect("usage: <base> <username> <password> <dir-path>");
    let password = args.next().expect("usage: <base> <username> <password> <dir-path>");
    let dir_path = args.next().expect("usage: <base> <username> <password> <dir-path>");

    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let ctx = UserContext::sign_in(&username, &password, None, poster, store, mutable).await?;
    println!("signed in as {username}");

    let dir = ctx.get_by_path(&dir_path).await?.ok_or_else(|| format!("no directory at {dir_path}"))?;
    let children = dir.children().await?;
    println!("{dir_path} has {} entries:", children.len());
    for c in &children {
        let kind = if c.is_directory() { "dir " } else { "file" };
        println!("  [{kind}] {} ({} bytes)", c.name(), c.size());
    }

    for c in &children {
        if c.is_directory() {
            continue;
        }
        let data = c.read().await?;
        if data.starts_with(b"%PDF-") {
            let version = std::str::from_utf8(&data[5..8]).unwrap_or("?");
            let has_eof = data.windows(5).rev().take(1024).any(|w| w == b"%%EOF")
                || data.windows(5).any(|w| w == b"%%EOF");
            // Rough page count: occurrences of "/Type /Page" not followed by 's'.
            let pages = count_pages(&data);
            println!(
                "\nPDF {:?}: {} bytes, version {version}, valid trailer={has_eof}, ~{pages} page(s)",
                c.name(),
                data.len(),
            );
        } else if c.name().to_lowercase().ends_with(".pdf") {
            println!("\n{:?} is named .pdf but does not start with %PDF- (first bytes: {:02x?})", c.name(), &data[..data.len().min(8)]);
        }
    }
    Ok(())
}

/// Rough page count: `/Type /Page` (optionally with whitespace) but not `/Pages`.
fn count_pages(data: &[u8]) -> usize {
    let needle = b"/Type";
    let mut count = 0;
    let mut i = 0;
    while let Some(pos) = find(&data[i..], needle) {
        let start = i + pos + needle.len();
        // skip whitespace and a possible '/'
        let rest = &data[start..(start + 8).min(data.len())];
        let s: String = rest.iter().map(|&b| b as char).collect();
        let s = s.trim_start().trim_start_matches('/');
        if s.starts_with("Page") && !s.starts_with("Pages") {
            count += 1;
        }
        i = start;
    }
    count
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
