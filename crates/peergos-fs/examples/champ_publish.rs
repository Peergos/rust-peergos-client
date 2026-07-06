//! Test the CHAMP-form public directory through the Java server's /public/ gateway.
//!
//! We publish 40 files individually under one directory, so that directory's public
//! `DirectoryInode` exceeds the 32-child inline limit and is stored as an inner
//! champ. Then we ask the Java server to resolve one of them via
//! `GET :7777/public/w2/<dir>/<file>` (which runs `getPublicCapability`, walking the
//! inode tree). A 302 redirect means the Java server successfully parsed our
//! champ-form directory — end-to-end byte compatibility.
//!
//!   cargo run -p peergos-fs --example champ_publish -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster, store.clone(), mutable.clone()).await?,
    };
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // Create a directory with 40 files (> the 32-child inline threshold).
    const N: usize = 40;
    let dir_name = format!("champ{n}");
    let dir = ctx.get_home().await?.mkdir(&dir_name).await?;
    for i in 0..N {
        dir.upload(&format!("file{i}.html"), format!("<h1>file {i} ({n})</h1>").as_bytes()).await?;
    }
    println!("created /w2/{dir_name}/ with {N} files");

    // Publish all 40 files individually (one commit) — forces {dir_name}'s public
    // DirectoryInode into champ form.
    let paths: Vec<String> = (0..N).map(|i| format!("{dir_name}/file{i}.html")).collect();
    ctx.make_public_many(&paths).await?;
    println!("published {N} files (public DirectoryInode is now champ-form)");

    // Client-side: several of them resolve to their own caps through the champ.
    for i in [0usize, 20, 39] {
        let cap = ctx.get_public_capability(&format!("/w2/{dir_name}/file{i}.html")).await?;
        let (_p, data) = peergos_fs::read_file(&cap, store.clone(), mutable.as_ref()).await?;
        assert_eq!(data, format!("<h1>file {i} ({n})</h1>").into_bytes(), "file{i}");
    }
    println!("client-side get_public_capability resolves files 0/20/39 through the champ");

    // The Java server resolves a champ-mapped file via /public/ (302 redirect).
    let target = format!("http://localhost:7777/public/w2/{dir_name}/file20.html");
    let out = std::process::Command::new("curl")
        .args(["-s", "-D", "-", "-o", "/dev/null", &target])
        .output()?;
    let resp = String::from_utf8_lossy(&out.stdout);
    let status = resp.lines().next().unwrap_or("").to_string();
    let location = resp.lines().find(|l| l.to_ascii_lowercase().starts_with("location:")).unwrap_or("");
    println!("\nJava server GET /public/w2/{dir_name}/file20.html\n  status: {status}");
    if status.contains("302") && location.contains("secretLink") {
        println!("  ✓ the Java server resolved a file inside our CHAMP-form public directory (302 redirect)");
    } else {
        let trailer = resp.lines().find(|l| l.to_ascii_lowercase().starts_with("trailer:")).unwrap_or("");
        println!("  status/location unexpected: {location} {trailer}");
        return Err("gateway did not resolve the champ-form file".into());
    }

    println!("\nChamp-form public directory OK through the Java /public/ gateway.");
    Ok(())
}
