//! Rust half of an interop run against a live server and the Java client. Each
//! step writes what it made (paths, sha256s, link strings) into a shared directory
//! for the Java half to check, or checks what the Java half wrote there.
//!
//!   cargo run -p peergos-fs --example interop -- <step> <shared-dir> [server]
//!
//! The Java half and the step order are in `interop/` at the repo root.

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::archive::{self, EntrySource, NewEntry, ZipReader};
use peergos_fs::{FileUpload, FolderUpload, MultiFactorAuthResponse, UserContext};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

struct Net {
    poster: Arc<dyn HttpPoster>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: Arc<dyn MutablePointers>,
}

fn net(base: &str) -> Res<Net> {
    Ok(Net {
        poster: Arc::new(ReqwestPoster::new(base, false)?),
        store: Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(base, false)?), true)),
        mutable: Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(base, false)?))),
    })
}

async fn sign_in(n: &Net, user: &str, pw: &str) -> Res<UserContext> {
    Ok(UserContext::sign_in(user, pw, None, n.poster.clone(), n.store.clone(), n.mutable.clone()).await?)
}

async fn sign_up_or_in(n: &Net, user: &str, pw: &str) -> Res<UserContext> {
    match UserContext::sign_up(user, pw, None, n.poster.clone(), n.store.clone(), n.mutable.clone()).await {
        Ok(c) => Ok(c),
        Err(_) => sign_in(n, user, pw).await,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha(b: &[u8]) -> String {
    hex(&peergos_crypto::hash::sha256(b))
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31) as u8).wrapping_add(seed)).collect()
}

fn check(ok: bool, what: &str) -> Res<()> {
    if ok {
        println!("  ok   {what}");
        Ok(())
    } else {
        Err(format!("FAIL {what}").into())
    }
}

async fn read_path(ctx: &UserContext, path: &str) -> Res<Vec<u8>> {
    Ok(ctx.get_by_path(path).await?.ok_or_else(|| format!("missing {path}"))?.read().await?)
}

/// Check every `path sha256` line of a file written by the Java half.
async fn check_expected(ctx: &UserContext, file: &Path) -> Res<()> {
    for line in std::fs::read_to_string(file)?.lines().filter(|l| !l.is_empty()) {
        let (path, want) = line.split_once(' ').ok_or("bad expected line")?;
        let got = sha(&read_path(ctx, path).await?);
        check(got == want, &format!("{path} reads as the Java client wrote it"))?;
    }
    Ok(())
}

async fn rust_setup(n: &Net, dir: &Path) -> Res<()> {
    let ctx = sign_up_or_in(n, "ri", "ripass").await?;
    let home = ctx.get_home().await?;
    let root = match home.child("interop").await? {
        Some(d) => d,
        None => home.mkdir("interop").await?,
    };
    let mut expected = Vec::new();
    let mut put = |path: &str, data: &[u8]| expected.push(format!("/ri/interop/{path} {}", sha(data)));

    let small = b"written by the rust client".to_vec();
    root.upload("small.txt", &small).await?;
    put("small.txt", &small);

    let big = pattern(11 * 1024 * 1024, 3);
    root.get_latest().await?.upload("big.bin", &big).await?;
    put("big.bin", &big);

    // a file at the 4 MiB BLAKE3 chunk size, as a newer client writes them
    let b3 = pattern(9 * 1024 * 1024 + 123, 5);
    let b3c = b3.clone();
    let r = root.get_latest().await?;
    peergos_fs::upload_file_streaming_at_chunk_size(
        r.capability(), "b3.bin", b3.len() as u64, peergos_fs::DEFAULT_CHUNK_SIZE, r.signer().cloned(),
        ctx.mirror_bat_id().as_ref(), move || Ok(std::io::Cursor::new(b3c.clone())), ctx.store(), ctx.mutable().as_ref(),
    )
    .await?;
    put("b3.bin", &b3);
    std::fs::write(dir.join("b3.blake3"), hex(&peergos_crypto::hash::blake3(&b3)))?;

    // a buffered subtree upload: bulk commits, split, with large blocks written ahead
    let mut files = Vec::new();
    for i in 0..40 {
        let d = pattern(90 * 1024, i as u8);
        put(&format!("bulk/s{i}.bin"), &d);
        files.push(FileUpload::from_bytes(format!("s{i}.bin"), d));
    }
    let large = pattern(6 * 1024 * 1024, 9);
    put("bulk/large.bin", &large);
    files.push(FileUpload::from_bytes("large.bin", large));
    let bulk = match root.get_latest().await?.child("bulk").await? {
        Some(d) => d,
        None => root.get_latest().await?.mkdir("bulk").await?,
    };
    bulk.upload_subtree(vec![FolderUpload { rel_path: vec![], files }]).await?;

    // a zip written by another tool, then edited here
    let fixture = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.zip"))?;
    root.get_latest().await?.upload("archive.zip", &fixture).await?;
    let zip_file = ctx.get_by_path("interop/archive.zip").await?.ok_or("no zip")?;
    let added = b"added by the rust client".to_vec();
    archive::append(&zip_file, vec![NewEntry::file("rust/added.txt", added.len() as u64, 0, EntrySource::Bytes(Arc::new(added)))?]).await?;
    archive::rename(&zip_file, "readme.txt", "README.txt").await?;
    archive::remove(&zip_file, &["empty".to_string()], true).await?;

    // a link over two items, one writable
    let props = ctx
        .create_secret_link_to(
            &["interop/small.txt".to_string(), "interop/bulk".to_string()],
            &["interop/bulk".to_string()],
            "",
            None,
            None,
        )
        .await?;
    std::fs::write(dir.join("rust-link.txt"), ctx.secret_link_string(&props)?)?;
    if root.get_latest().await?.child("shared").await?.is_none() {
        root.get_latest().await?.mkdir("shared").await?;
    }
    std::fs::write(dir.join("rust-expected.txt"), expected.join("\n"))?;
    println!("rust-setup done");
    Ok(())
}

async fn rust_share(n: &Net) -> Res<()> {
    let ctx = sign_in(n, "ri", "ripass").await?;
    ctx.share_write_access("interop/shared", "ji").await?;
    println!("rust-share done: /ri/interop/shared is writable by ji");
    Ok(())
}

async fn check_java(n: &Net, dir: &Path) -> Res<()> {
    let ctx = sign_in(n, "ri", "ripass").await?;
    let ji = sign_in(n, "ji", "jipass").await?;
    check_expected(&ji, &dir.join("java-expected.txt")).await?;

    // the Java user's zip, built with its ZipWriter
    let zip_file = ji.get_by_path("/ji/jinterop/java.zip").await?.ok_or("no java zip")?;
    let zip = ZipReader::open(&zip_file).await?;
    check(zip.read_path("docs/j.txt").await? == b"zipped by the java client", "Java-written zip entry reads back")?;

    // the Java user's multi-item link
    let link = std::fs::read_to_string(dir.join("java-link.txt"))?;
    let anon = UserContext::from_secret_link(link.trim(), None, n.poster.clone(), n.store.clone(), n.mutable.clone()).await?;
    let mounts = anon.link_mount_paths();
    check(mounts.len() == 2, &format!("Java link opens with both items: {mounts:?}"))?;
    let a = anon.get_by_path("/ji/jinterop/j-small.txt").await?.ok_or("link item 1")?;
    check(a.read().await? == b"written by the java client", "Java link's read-only item reads")?;
    let wdir = anon.get_by_path("/ji/jinterop/jlinkdir").await?.ok_or("link item 2")?;
    check(wdir.is_writable(), "Java link's writable item is writable")?;
    wdir.upload("via-java-link.txt", b"rust wrote through a java link").await?;
    check(
        read_path(&ji, "/ji/jinterop/jlinkdir/via-java-link.txt").await? == b"rust wrote through a java link",
        "Rust wrote through the Java link",
    )?;

    // what the Java user wrote into our write-shared folder
    check(read_path(&ctx, "interop/shared/from-java.txt").await? == b"java wrote into rust's shared folder", "Java wrote into Rust's write share")?;
    // write into the folder the Java user shared with us
    let jshared = ctx.get_by_path("/ji/jinterop/jshared").await?.ok_or("no jshared")?;
    check(jshared.is_writable(), "Java's write share is writable for Rust")?;
    jshared.upload("from-rust.txt", b"rust wrote into java's shared folder").await?;
    // what the Java client wrote through our link
    check(read_path(&ctx, "interop/bulk/via-rust-link.txt").await? == b"java wrote through a rust link", "Java wrote through the Rust link")?;
    println!("check-java done");
    Ok(())
}

async fn rust_mfa(n: &Net, dir: &Path) -> Res<()> {
    let ctx = sign_up_or_in(n, "rm", "rmpass").await?;
    let totp = ctx.enroll_totp().await?;
    let codes = ctx.generate_backup_codes().await?;
    std::fs::write(dir.join("backup-codes.txt"), codes.formatted().join("\n"))?;
    std::fs::write(dir.join("totp.txt"), totp.encode())?;
    // sign in again answering with the last backup code
    let last = codes.codes.last().unwrap().clone();
    let responder = move |req: &peergos_fs::MultiFactorAuthRequest| {
        let m = req.backup_codes_method().ok_or_else(|| peergos_core::Error::Protocol("no backup codes offered".into()))?;
        Ok(MultiFactorAuthResponse::new_backup_code(m.credential_id.clone(), &last))
    };
    let again = UserContext::sign_in("rm", "rmpass", Some(&responder), n.poster.clone(), n.store.clone(), n.mutable.clone()).await?;
    check(again.username() == Some("rm"), "Rust signs in with a backup code")?;
    let totp_responder = |req: &peergos_fs::MultiFactorAuthRequest| {
        let m = req.totp_method().ok_or_else(|| peergos_core::Error::Protocol("no totp offered".into()))?;
        Ok(MultiFactorAuthResponse::new_totp(m.credential_id.clone(), totp.current_code()))
    };
    UserContext::sign_in("rm", "rmpass", Some(&totp_responder), n.poster.clone(), n.store.clone(), n.mutable.clone()).await?;
    check(true, "Rust signs in with TOTP")?;
    println!("rust-mfa done");
    Ok(())
}

#[tokio::main]
async fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().collect();
    let step = args.get(1).ok_or("step")?.clone();
    let dir = PathBuf::from(args.get(2).ok_or("shared dir")?);
    let base = args.get(3).cloned().unwrap_or_else(|| "http://localhost:7777/".into());
    std::fs::create_dir_all(&dir)?;
    let n = net(&base)?;
    match step.as_str() {
        "rust-setup" => rust_setup(&n, &dir).await,
        "rust-share" => rust_share(&n).await,
        "check-java" => check_java(&n, &dir).await,
        "rust-mfa" => rust_mfa(&n, &dir).await,
        other => Err(format!("unknown step {other}").into()),
    }
}
