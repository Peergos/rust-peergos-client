//! Sign up a new user, then log in to verify the account works.
//!
//!   cargo run -p peergos-fs --example signup -- <base> <username> <password>
//!   cargo run -p peergos-fs --example signup -- http://localhost:7777/ w ww

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let username = args.get(2).cloned().unwrap_or_else(|| "w".to_string());
    let password = args.get(3).cloned().unwrap_or_else(|| "ww".to_string());
    let token = args.get(4).cloned(); // optional signup token

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());

    println!("Signing up {username:?} ...");
    peergos_fs::signup(&username, &password, token.as_deref(), poster.as_ref(), store.as_ref()).await?;
    println!("Signup accepted by the server.");

    println!("\nLogging in as {username:?} to verify ...");
    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    println!("  identity: {}", user.identity);
    println!("  entry points: {}", user.entries.len());

    let home = user.home().ok_or("no home directory entry point")?;
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
