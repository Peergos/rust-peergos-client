//! Log in to a Peergos server and list the user's home directory.
//!
//!   cargo run -p peergos-fs --example login -- <base> <username> <password>
//!   cargo run -p peergos-fs --example login -- http://localhost:7777/ q qq

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let username = args.get(2).cloned().unwrap_or_else(|| "q".to_string());
    let password = args.get(3).cloned().unwrap_or_else(|| "qq".to_string());

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());

    println!("Logging in as {username:?} ...");
    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;

    println!("Logged in.");
    println!("  identity: {}", user.identity);
    println!("  writer:   {}", user.signer.public_key_hash);
    println!("  entry points ({}):", user.entries.len());
    for e in &user.entries {
        println!(
            "    {} → owner={} writable={}",
            e.owner_name,
            e.pointer.owner,
            e.pointer.is_writable()
        );
    }

    let home = user.home().ok_or("no home directory entry point found")?;
    println!("\nHome directory /{} contents:", user.username);
    let entries = peergos_fs::list_directory(home, store.clone(), &mutable).await?;
    if entries.is_empty() {
        println!("  (empty)");
    }
    for e in &entries {
        println!("  {} {}", if e.is_dir == Some(true) { "[dir ]" } else { "[file]" }, e.name);
    }
    Ok(())
}
