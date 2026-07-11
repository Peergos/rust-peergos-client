//! An interactive Peergos shell, mirroring the Java `peergos.server.cli` shell:
//! the same commands (ls/lls, get/put, mkdir, rm, cd/lcd, pwd/lpwd, space,
//! follow, get_follow_requests, process_follow_request, share_read, passwd) over a
//! remote working directory + a local working directory.
//!
//!   cargo run -p peergos-cli -- [--server URL] [--username NAME]

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, DirectS3Storage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{FileWrapper, MultiFactorAuthRequest, MultiFactorAuthResponse, UserContext};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::sync::Arc;

type BoxErr = Box<dyn std::error::Error>;

struct Shell {
    ctx: UserContext,
    username: String,
    server: String,
    /// Remote working directory, always absolute (`/username/...`).
    pwd: String,
    /// Local working directory.
    lpwd: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), BoxErr> {
    let mut server = arg_value("--server");
    let mut username = arg_value("--username");

    let server = match server.take() {
        Some(s) => s,
        None => prompt("Enter server address [https://peergos.net] > ")?,
    };
    let server = if server.trim().is_empty() { "https://peergos.net".to_string() } else { server.trim().to_string() };
    let server = if server.starts_with("http") { server } else { format!("https://{server}") };

    let username = match username.take() {
        Some(u) => u,
        None => prompt("Enter username > ")?,
    };
    let username = username.trim().to_string();
    let password = read_password("Enter password > ")?;

    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&server, false)?);
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&server, false)?)));
    let http_store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&server, false)?), true));

    // Whether we read/write large blocks directly to S3 is decided by the server's
    // advertised blockstore properties: wrap in DirectS3Storage only if the server
    // says it's S3-backed; otherwise talk to the server directly.
    let props = DirectS3Storage::fetch_properties(poster.as_ref()).await.unwrap_or_default();
    let store: Arc<dyn ContentAddressedStorage> = if props.use_direct_block_store() {
        let s3_server: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&server, false)?);
        let s3_direct: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&server, true)?);
        Arc::new(DirectS3Storage::with_properties(props, s3_server, s3_direct, http_store))
    } else {
        http_store
    };

    // A TOTP prompt for second-factor accounts. `sign_in` only invokes this if the
    // server actually requests a second factor, so it's harmless for non-MFA logins.
    let responder = |req: &MultiFactorAuthRequest| -> peergos_core::error::Result<MultiFactorAuthResponse> {
        let method = req.totp_method().ok_or_else(|| {
            peergos_core::error::Error::Protocol("this account needs a second factor the shell can't handle (only TOTP is supported)".into())
        })?;
        let code = prompt("Two-factor code (TOTP) > ")
            .map_err(|e| peergos_core::error::Error::Protocol(format!("failed to read TOTP code: {e}")))?;
        Ok(MultiFactorAuthResponse::new_totp(method.credential_id.clone(), code.trim().to_string()))
    };
    // Single-user interactive session: enable the client-side pointer + block caches.
    let ctx = UserContext::sign_in(&username, &password, Some(&responder), poster, store, mutable)
        .await?
        .with_session_caches();
    println!("Connected to {server} as {username}.\nType 'help' for commands, 'exit' to quit.");

    let mut shell = Shell {
        ctx,
        username: username.clone(),
        server,
        pwd: format!("/{username}"),
        lpwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    loop {
        let line = prompt(&format!("{}@{} > ", shell.username, shell.server))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
        let cmd = parts[0].as_str();
        let args = &parts[1..];
        if matches!(cmd, "exit" | "quit" | "bye") {
            println!("Bye.");
            break;
        }
        match shell.dispatch(cmd, args).await {
            Ok(out) => {
                if !out.is_empty() {
                    println!("{out}");
                }
            }
            Err(e) => eprintln!("error: {e}"),
        }
    }
    Ok(())
}

impl Shell {
    async fn dispatch(&mut self, cmd: &str, args: &[String]) -> Result<String, BoxErr> {
        match cmd {
            "help" | "?" => Ok(help_text()),
            "ls" => self.ls(args).await,
            "lls" => self.lls(args),
            "cd" => self.cd(args).await,
            "lcd" => self.lcd(args),
            "pwd" => Ok(format!("Remote working directory: {}", self.pwd)),
            "lpwd" => Ok(format!("Local working directory: {}", self.lpwd.display())),
            "mkdir" => self.mkdir(args).await,
            "rm" => self.rm(args).await,
            "get" => self.get(args).await,
            "put" => self.put(args).await,
            "space" => self.space().await,
            "follow" => self.follow(args).await,
            "get_follow_requests" => self.get_follow_requests().await,
            "process_follow_request" => self.process_follow_request(args).await,
            "share_read" => self.share_read(args).await,
            "passwd" => self.passwd().await,
            other => Err(format!("unknown command '{other}' (try 'help')").into()),
        }
    }

    // ---- remote/local listing + navigation ---------------------------------

    async fn ls(&self, args: &[String]) -> Result<String, BoxErr> {
        let path = self.resolve_remote(args.first().map(|s| s.as_str()).unwrap_or(""));
        let node = self.ctx.get_by_path(&path).await?.ok_or_else(|| format!("no such path: {path}"))?;
        if !node.is_directory() {
            return Ok(path);
        }
        let mut names: Vec<String> = node.children().await?.iter().map(|c| c.name().to_string()).collect();
        names.sort();
        Ok(names.join("\n"))
    }

    fn lls(&self, args: &[String]) -> Result<String, BoxErr> {
        let dir = self.resolve_local(args.first().map(|s| s.as_str()).unwrap_or("."));
        let mut names: Vec<String> = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .map(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                if e.path().is_dir() { format!("{n}/") } else { n }
            })
            .collect();
        names.sort();
        Ok(names.join("\n"))
    }

    async fn cd(&mut self, args: &[String]) -> Result<String, BoxErr> {
        let path = match args.first() {
            None => format!("/{}", self.username),
            Some(a) => self.resolve_remote(a),
        };
        let node = self.ctx.get_by_path(&path).await?.ok_or_else(|| format!("no such path: {path}"))?;
        if !node.is_directory() {
            return Err(format!("not a directory: {path}").into());
        }
        self.pwd = path.clone();
        Ok(format!("Current directory: {path}"))
    }

    fn lcd(&mut self, args: &[String]) -> Result<String, BoxErr> {
        let dir = self.resolve_local(args.first().map(|s| s.as_str()).unwrap_or("."));
        if !dir.is_dir() {
            return Err(format!("not a directory: {}", dir.display()).into());
        }
        self.lpwd = dir.canonicalize().unwrap_or(dir);
        Ok(format!("Current local directory: {}", self.lpwd.display()))
    }

    // ---- remote mutations ---------------------------------------------------

    async fn mkdir(&self, args: &[String]) -> Result<String, BoxErr> {
        let arg = args.first().ok_or("usage: mkdir <dir>")?;
        let path = self.resolve_remote(arg);
        let rel = self.home_relative(&path)?;
        self.ctx.get_home().await?.get_or_mkdirs(&rel).await?;
        Ok(format!("Created {path}"))
    }

    async fn rm(&self, args: &[String]) -> Result<String, BoxErr> {
        let arg = args.first().ok_or("usage: rm <remote-path>")?;
        let path = self.resolve_remote(arg);
        let node = self.ctx.get_by_path(&path).await?.ok_or_else(|| format!("no such path: {path}"))?;
        if node.is_directory() {
            let ans = prompt(&format!("Delete directory and all contents of {path}? (y/N) "))?;
            if ans.trim().to_lowercase() != "y" {
                return Ok("Aborting delete".to_string());
            }
        }
        let (parent, name) = split_remote(&path);
        let parent_dir = self.ctx.get_by_path(&parent).await?.ok_or_else(|| format!("no such parent: {parent}"))?;
        parent_dir.remove_child(&name).await?;
        Ok(format!("Deleted {path}"))
    }

    // ---- transfer -----------------------------------------------------------

    async fn get(&self, args: &[String]) -> Result<String, BoxErr> {
        let (flags, pos) = split_flags(args);
        let skip_existing = flags.contains(&"--skip-existing".to_string());
        let remote_arg = pos.first().ok_or("usage: get <remote-path> [local-path]")?;
        let remote = self.resolve_remote(remote_arg);
        let node = self.ctx.get_by_path(&remote).await?.ok_or_else(|| format!("no such path: {remote}"))?;
        let base_name = remote.rsplit('/').next().unwrap_or("download").to_string();
        let local_target = match pos.get(1) {
            Some(l) => self.resolve_local(l),
            None => self.lpwd.join(&base_name),
        };
        let n = self.download(&node, &local_target, skip_existing).await?;
        Ok(format!("Downloaded {n} file(s) to {}", local_target.display()))
    }

    async fn download(&self, node: &FileWrapper, local: &Path, skip_existing: bool) -> Result<usize, BoxErr> {
        if node.is_directory() {
            std::fs::create_dir_all(local)?;
            let mut count = 0;
            for child in node.children().await? {
                count += Box::pin(self.download(&child, &local.join(child.name()), skip_existing)).await?;
            }
            Ok(count)
        } else {
            if skip_existing && local.exists() {
                return Ok(0);
            }
            if let Some(parent) = local.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(local, node.read().await?)?;
            Ok(1)
        }
    }

    async fn put(&self, args: &[String]) -> Result<String, BoxErr> {
        let (flags, pos) = split_flags(args);
        let skip_existing = flags.contains(&"--skip-existing".to_string());
        let local_arg = pos.first().ok_or("usage: put [--skip-existing] <local-path> [remote-path]")?;
        let local = self.resolve_local(local_arg);
        if !local.exists() {
            return Err(format!("no such local path: {}", local.display()).into());
        }
        let base_name = local.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "upload".to_string());
        // Destination directory (remote): the given remote path, or pwd; the item
        // keeps its local name inside it.
        let dest_dir = match pos.get(1) {
            Some(r) => self.resolve_remote(r),
            None => self.pwd.clone(),
        };
        let n = self.upload(&local, &dest_dir, &base_name, skip_existing).await?;
        Ok(format!("Uploaded {n} file(s) to {dest_dir}/{base_name}"))
    }

    async fn upload(&self, local: &Path, remote_dir: &str, name: &str, skip_existing: bool) -> Result<usize, BoxErr> {
        if local.is_dir() {
            let sub = format!("{remote_dir}/{name}");
            let rel = self.home_relative(&sub)?;
            self.ctx.get_home().await?.get_or_mkdirs(&rel).await?;
            let mut count = 0;
            for entry in std::fs::read_dir(local)? {
                let entry = entry?;
                let child_name = entry.file_name().to_string_lossy().to_string();
                count += Box::pin(self.upload(&entry.path(), &sub, &child_name, skip_existing)).await?;
            }
            Ok(count)
        } else {
            let dir = self.ctx.get_by_path(remote_dir).await?;
            let dir = match dir {
                Some(d) => d,
                None => {
                    let rel = self.home_relative(remote_dir)?;
                    self.ctx.get_home().await?.get_or_mkdirs(&rel).await?
                }
            };
            if skip_existing && dir.child(name).await?.is_some() {
                return Ok(0);
            }
            let data = std::fs::read(local)?;
            dir.upload(name, &data).await?;
            Ok(1)
        }
    }

    // ---- account / social ---------------------------------------------------

    async fn space(&self) -> Result<String, BoxErr> {
        let used = self.ctx.get_usage().await?;
        Ok(format!("Total space used: {} MiB.", used / 1024 / 1024))
    }

    async fn follow(&self, args: &[String]) -> Result<String, BoxErr> {
        let target = args.first().ok_or("usage: follow <username>")?;
        let user = self.ctx.user().ok_or("not signed in")?;
        let sent = peergos_fs::send_follow_request(user, target, true, self.ctx.poster().as_ref(), self.ctx.store(), self.ctx.mutable().as_ref()).await?;
        Ok(if sent { format!("Sent follow request to '{target}'") } else { format!("Follow request to '{target}' was not accepted (already pending?)") })
    }

    async fn get_follow_requests(&self) -> Result<String, BoxErr> {
        let user = self.ctx.user().ok_or("not signed in")?;
        let reqs = peergos_fs::get_follow_requests(user, self.ctx.poster().as_ref()).await?;
        let names: Vec<String> = reqs.iter().filter_map(|r| r.sender().map(|s| s.to_string())).collect();
        if names.is_empty() {
            return Ok("No pending follow requests.".to_string());
        }
        Ok(format!("You have pending follow requests from:\n\t{}", names.join("\n\t")))
    }

    async fn process_follow_request(&self, args: &[String]) -> Result<String, BoxErr> {
        let target = args.first().ok_or("usage: process_follow_request <user> <accept|accept-and-reciprocate|reject>")?;
        let action = args.get(1).map(|s| s.as_str()).ok_or("please specify accept | accept-and-reciprocate | reject")?;
        let user = self.ctx.user().ok_or("not signed in")?;
        let reqs = peergos_fs::get_follow_requests(user, self.ctx.poster().as_ref()).await?;
        let req = reqs.into_iter().find(|r| r.sender() == Some(target.as_str()))
            .ok_or_else(|| format!("no pending follow request from '{target}'"))?;
        match action {
            "accept" => peergos_fs::accept_follow_request(user, &req, false, self.ctx.poster().as_ref(), self.ctx.store(), self.ctx.mutable().as_ref()).await?,
            "accept-and-reciprocate" => peergos_fs::accept_follow_request(user, &req, true, self.ctx.poster().as_ref(), self.ctx.store(), self.ctx.mutable().as_ref()).await?,
            "reject" => peergos_fs::reject_follow_request(user, &req, false, self.ctx.poster().as_ref(), self.ctx.store(), self.ctx.mutable().as_ref()).await?,
            other => return Err(format!("unknown action '{other}' (accept | accept-and-reciprocate | reject)").into()),
        }
        Ok(format!("Processed follow request from '{target}' with '{action}'."))
    }

    async fn share_read(&self, args: &[String]) -> Result<String, BoxErr> {
        let remote_arg = args.first().ok_or("usage: share_read <remote-path> <user>")?;
        let target = args.get(1).ok_or("usage: share_read <remote-path> <user>")?;
        let remote = self.resolve_remote(remote_arg);
        let node = self.ctx.get_by_path(&remote).await?.ok_or_else(|| format!("no such path: {remote}"))?;
        let user = self.ctx.user().ok_or("not signed in")?;
        let followers = peergos_fs::get_follower_names(user, self.ctx.store(), self.ctx.mutable().as_ref()).await?;
        if !followers.contains(target) {
            return Ok(format!("Not shared: '{target}' is not following you"));
        }
        let rel = self.home_relative(&remote)?;
        peergos_fs::share_read_access(user, &rel, node.capability(), target, self.ctx.store(), self.ctx.mutable().as_ref()).await?;
        Ok(format!("Shared read-access to '{remote}' with {target}"))
    }

    async fn passwd(&self) -> Result<String, BoxErr> {
        let old = read_password("Current password > ")?;
        let new1 = read_password("New password > ")?;
        let new2 = read_password("Re-enter new password > ")?;
        if new1 != new2 {
            return Err("passwords did not match".into());
        }
        self.ctx.change_password(&old, &new1, None).await?;
        Ok("Password changed. Please sign in again.".to_string())
    }

    // ---- path helpers -------------------------------------------------------

    fn resolve_remote(&self, arg: &str) -> String {
        let combined = if arg.is_empty() {
            self.pwd.clone()
        } else if arg.starts_with('/') {
            arg.to_string()
        } else {
            format!("{}/{}", self.pwd, arg)
        };
        normalize_remote(&combined)
    }

    fn resolve_local(&self, arg: &str) -> PathBuf {
        let p = Path::new(arg);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.lpwd.join(p)
        }
    }

    /// A remote absolute path (`/username/a/b`) as a home-relative path (`a/b`).
    fn home_relative(&self, path: &str) -> Result<String, BoxErr> {
        let prefix = format!("/{}", self.username);
        let rel = path.strip_prefix(&prefix).unwrap_or(path).trim_start_matches('/');
        if rel.is_empty() {
            return Err("path resolves to the home root".into());
        }
        Ok(rel.to_string())
    }
}

// ---- free helpers ----------------------------------------------------------

/// Collapse `.`/`..` segments in an absolute remote path.
fn normalize_remote(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// Split an absolute remote path into (parent, name).
fn split_remote(path: &str) -> (String, String) {
    let norm = normalize_remote(path);
    match norm.rsplit_once('/') {
        Some((parent, name)) => (if parent.is_empty() { "/".to_string() } else { parent.to_string() }, name.to_string()),
        None => ("/".to_string(), norm),
    }
}

/// Partition `args` into (flags starting with `--`, positional args).
fn split_flags(args: &[String]) -> (Vec<String>, Vec<String>) {
    args.iter().cloned().partition(|a| a.starts_with("--"))
}

fn arg_value(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn prompt(msg: &str) -> io::Result<String> {
    print!("{msg}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Read a line with terminal echo disabled (via `stty`, best-effort).
fn read_password(msg: &str) -> io::Result<String> {
    print!("{msg}");
    io::stdout().flush()?;
    let echo_off = ProcCommand::new("stty").arg("-echo").stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    let mut pw = String::new();
    io::stdin().read_line(&mut pw)?;
    if echo_off {
        let _ = ProcCommand::new("stty").arg("echo").stderr(std::process::Stdio::null()).status();
        println!();
    }
    Ok(pw.trim_end_matches(['\n', '\r']).to_string())
}

fn help_text() -> String {
    [
        "Commands:",
        "  ls [path]                              list a remote directory",
        "  lls [path]                             list a local directory",
        "  cd [path]                              change remote directory (no arg = home)",
        "  lcd <path>                             change local directory",
        "  pwd | lpwd                             print remote/local working directory",
        "  mkdir <dir>                            create a remote directory",
        "  get [--skip-existing] <remote> [local] download a file or folder",
        "  put [--skip-existing] <local> [remote] upload a file or folder",
        "  rm <remote>                            remove a remote file/folder",
        "  space                                  show used remote space",
        "  follow <user>                          send a follow request",
        "  get_follow_requests                    list pending follow requests",
        "  process_follow_request <user> <accept|accept-and-reciprocate|reject>",
        "  share_read <remote> <user>             grant read access to a follower",
        "  passwd                                 change your password",
        "  help | ?                               show this help",
        "  exit | quit | bye                      disconnect",
    ]
    .join("\n")
}
