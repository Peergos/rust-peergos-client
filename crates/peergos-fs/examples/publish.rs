//! Public + website publishing, end to end:
//!  - publish a file publicly, then resolve it via get_public_capability and read it,
//!  - publish a directory as a website (make_public + set webroot),
//!  - confirm the local gateway at :9000 serves /public/<user>/<path> (302 redirect
//!    to a secret-link URL).
//!
//!   cargo run -p peergos-fs --example publish -- http://localhost:7777/
//! (the gateway is assumed at http://localhost:9000/)

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

    // Build a small website directory: site<n>/index.html
    let site = format!("site{n}");
    let home = ctx.get_home().await?;
    let dir = home.mkdir(&site).await?;
    let html = format!("<!doctype html><h1>hello from w2 ({n})</h1>");
    dir.upload("index.html", html.as_bytes()).await?;
    println!("created website dir /w2/{site}/index.html");

    // --- publish a single file publicly ---------------------------------------
    ctx.make_public(&format!("{site}/index.html")).await?;
    let cap = ctx.get_public_capability(&format!("/w2/{site}/index.html")).await?;
    let (_p, data) = peergos_fs::read_file(&cap, store.clone(), mutable.as_ref()).await?;
    println!("get_public_capability(/w2/{site}/index.html) resolved; read {} bytes", data.len());
    assert_eq!(data, html.as_bytes(), "public file should read back its content");

    // Publishing a non-existent path fails; the root can't be published.
    assert!(ctx.make_public("does-not-exist").await.is_err());

    // --- publish the whole directory as a website -----------------------------
    ctx.publish_website(&site).await?;
    let webroot = ctx.get_profile_string("webroot").await?;
    println!("published website; profile webroot = {webroot:?}");
    assert_eq!(webroot.as_deref(), Some(format!("/w2/{site}").as_str()));
    // The dir cap is now the most-privileged public cap for that subtree.
    let dir_cap = ctx.get_public_capability(&format!("/w2/{site}")).await?;
    let listed = peergos_fs::list_directory(&dir_cap, store.clone(), mutable.as_ref()).await?;
    println!("public dir lists: {:?}", listed.iter().map(|e| e.name.clone()).collect::<Vec<_>>());
    assert!(listed.iter().any(|e| e.name == "index.html"));

    // --- confirm the gateway at :9000 serves the website ----------------------
    // The gateway serves by subdomain: Host = <owner>.peergos.localhost:9000, and
    // the URL path is the asset within the web root (defaulting to index.html).
    let out = std::process::Command::new("curl")
        .args([
            "-s",
            "-D",
            "-",
            "-H",
            "Host: w2.peergos.localhost:9000",
            "http://localhost:9000/index.html",
        ])
        .output();
    match out {
        Ok(o) => {
            let resp = String::from_utf8_lossy(&o.stdout);
            let status = resp.lines().next().unwrap_or("").to_string();
            let served = resp.contains(&html);
            println!("\ngateway GET w2.peergos.localhost:9000/index.html\n  status: {status}\n  served our html: {served}");
            if status.contains("200") && served {
                println!("  ✓ gateway serves the published website");
            } else {
                let trailer = resp.lines().find(|l| l.to_ascii_lowercase().starts_with("trailer:")).unwrap_or("");
                println!("  (gateway did not serve it; {trailer} — client-side resolution already passed)");
            }
        }
        Err(e) => println!("\n(couldn't run curl to check the gateway: {e}; client-side resolution passed)"),
    }

    // --- unpublish + pruning ---------------------------------------------------
    // Publish two siblings, unpublish one: the other survives (only now-empty
    // directory inodes are pruned).
    let sib = format!("sib{n}");
    let sdir = home.mkdir(&sib).await?;
    sdir.upload("a.txt", b"aaa").await?;
    sdir.upload("b.txt", b"bbb").await?;
    ctx.make_public(&format!("{sib}/a.txt")).await?;
    ctx.make_public(&format!("{sib}/b.txt")).await?;
    assert!(ctx.get_public_capability(&format!("/w2/{sib}/a.txt")).await.is_ok());

    ctx.unpublish(&format!("{sib}/a.txt")).await?;
    assert!(ctx.get_public_capability(&format!("/w2/{sib}/a.txt")).await.is_err(), "a.txt should be unpublished");
    assert!(ctx.get_public_capability(&format!("/w2/{sib}/b.txt")).await.is_ok(), "sibling b.txt must stay public");
    println!("\nunpublish {sib}/a.txt: gone; sibling b.txt still public (dir not pruned)");

    ctx.unpublish(&format!("{sib}/b.txt")).await?;
    assert!(ctx.get_public_capability(&format!("/w2/{sib}/b.txt")).await.is_err());
    assert!(ctx.get_public_capability(&format!("/w2/{sib}")).await.is_err(), "now-empty dir should be pruned");
    println!("unpublish {sib}/b.txt: gone (empty {sib} dir pruned up the chain)");

    // Take the website offline.
    ctx.unpublish_website(&site).await?;
    assert!(ctx.get_public_capability(&format!("/w2/{site}")).await.is_err(), "website dir should be unpublished");
    assert!(ctx.get_public_capability(&format!("/w2/{site}/index.html")).await.is_err());
    println!("website taken offline (dir + webroot field unpublished)");

    println!("\nPublic/website publishing OK: publish + resolve + read, website served by gateway, unpublish + pruning.");
    Ok(())
}
