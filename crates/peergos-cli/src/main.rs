//! An interactive Peergos shell, mirroring the Java `peergos.server.cli` shell:
//! the same commands (ls/lls, get/put, mkdir, rm, cd/lcd, pwd/lpwd, space,
//! follow, get_follow_requests, process_follow_request, share_read, share_write,
//! link, passwd) over a
//! remote working directory + a local working directory.
//!
//!   cargo run -p peergos-cli -- [--server URL] [--username NAME]
//!                               [--stay-logged-in] [--fresh] [--logout]
//!                               [--links LINK1,LINK2,...]
//!
//! `--stay-logged-in` saves the session (server + derived keys) to
//! `~/.peergos-shell/session.cbor` (mode 0600); later runs then resume it
//! automatically — no password, no KDF, no login round-trips. `--fresh` ignores a
//! saved session, `--logout` deletes it.
//!
//! `--links` opens the shell over a comma-separated set of secret links instead of
//! a login. Each link is mounted at its true absolute path (recovered by following
//! cryptree parent links), so nested links — e.g. a writable link to a subdirectory
//! plus a read-only link to its parent — appear in one coherent tree, the writable
//! child taking precedence where they overlap.

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, DirectS3Storage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{
    retrieve_secret_link_capability, AbsoluteCapability, FileWrapper, MultiFactorAuthRequest, MultiFactorAuthResponse, UserContext,
};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type BoxErr = Box<dyn std::error::Error>;

struct Shell {
    ctx: UserContext,
    username: String,
    server: String,
    /// Remote working directory, always absolute (`/username/...`, or `/` at the
    /// virtual root of a secret-link session).
    pwd: String,
    /// Local working directory.
    lpwd: PathBuf,
    /// True when the session was opened from secret links rather than a login:
    /// there is no home, and `/` is a virtual root listing the link targets.
    link_mode: bool,
}

#[tokio::main]
async fn main() -> Result<(), BoxErr> {
    let session_path = session_file_path();

    // `--logout` clears any saved session and exits.
    if has_flag("--logout") {
        if session_path.exists() {
            let _ = std::fs::remove_file(&session_path);
        }
        println!("Logged out (session cleared).");
        return Ok(());
    }

    let server_arg = arg_value("--server").map(|s| normalize_server(&s));
    let username_arg = arg_value("--username");
    let links_arg = arg_value("--links");
    let stay = has_flag("--stay-logged-in");
    let fresh = has_flag("--fresh");

    let mut shell: Option<Shell> = None;

    // 0. `--links a,b,c`: browse a set of secret links instead of logging in. Each
    //    link becomes an addressable root; nested links (e.g. a writable child plus
    //    a read-only parent) each keep their own access level.
    if let Some(links_csv) = links_arg {
        let server = match server_arg.clone() {
            Some(s) => s,
            None => normalize_server(&prompt("Enter server address [https://peergos.net] > ")?),
        };
        let (poster, store, mutable) = build_transport(&server).await?;
        let mut caps: Vec<AbsoluteCapability> = Vec::new();
        for raw in links_csv.split(',') {
            let link = raw.trim();
            if link.is_empty() {
                continue;
            }
            caps.push(resolve_link_interactive(link, store.as_ref()).await?);
        }
        if caps.is_empty() {
            return Err("no secret links provided to --links".into());
        }
        let ctx = UserContext::from_link_caps(caps, poster, store, mutable).await?.with_session_caches();
        let mounts = ctx.link_mount_paths();
        println!("Opened {} secret link(s) on {server}:", mounts.len());
        for m in &mounts {
            println!("  {m}");
        }
        shell = Some(make_link_shell(ctx, server));
    }

    // 1. Try to resume a saved session (unless --fresh), skipping password + KDF.
    if !fresh && shell.is_none() {
        if let Some((srv, user)) = load_session(&session_path) {
            let server_ok = server_arg.as_ref().map_or(true, |s| *s == srv);
            let user_ok = username_arg.as_ref().map_or(true, |u| *u == user.username);
            if server_ok && user_ok {
                let username = user.username.clone();
                let (poster, store, mutable) = build_transport(&srv).await?;
                let ctx = UserContext::from_session(user, poster, store, mutable).with_session_caches();
                if ctx.get_home().await.is_ok() {
                    println!("Resumed session as {username} on {srv}.");
                    shell = Some(make_shell(ctx, username, srv));
                } else {
                    eprintln!("Saved session is no longer valid; logging in again.");
                    let _ = std::fs::remove_file(&session_path);
                }
            }
        }
    }

    // 2. Otherwise, a full login (and save the session if --stay-logged-in).
    if shell.is_none() {
        let server = match server_arg {
            Some(s) => s,
            None => normalize_server(&prompt("Enter server address [https://peergos.net] > ")?),
        };
        let username = match username_arg {
            Some(u) => u,
            None => prompt("Enter username > ")?.trim().to_string(),
        };
        let password = read_password("Enter password > ")?;
        let (poster, store, mutable) = build_transport(&server).await?;

        // A TOTP prompt for second-factor accounts (only invoked if the server asks).
        let responder = |req: &MultiFactorAuthRequest| -> peergos_core::error::Result<MultiFactorAuthResponse> {
            let method = req.totp_method().ok_or_else(|| {
                peergos_core::error::Error::Protocol("this account needs a second factor the shell can't handle (only TOTP is supported)".into())
            })?;
            let code = prompt("Two-factor code (TOTP) > ")
                .map_err(|e| peergos_core::error::Error::Protocol(format!("failed to read TOTP code: {e}")))?;
            Ok(MultiFactorAuthResponse::new_totp(method.credential_id.clone(), code.trim().to_string()))
        };
        let ctx = UserContext::sign_in(&username, &password, Some(&responder), poster, store, mutable)
            .await?
            .with_session_caches();
        if stay {
            match save_session(&session_path, &server, ctx.user().expect("logged in")) {
                Ok(()) => println!("Session saved to {} — future runs will resume automatically.", session_path.display()),
                Err(e) => eprintln!("warning: could not save session: {e}"),
            }
        }
        println!("Connected to {server} as {username}.");
        shell = Some(make_shell(ctx, username, server));
    }

    let mut shell = shell.expect("connected");
    println!("Type 'help' for commands, 'exit' to quit.");

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
            "share_write" => self.share_write(args).await,
            "link" => self.link(args).await,
            "passwd" => self.passwd().await,
            other => Err(format!("unknown command '{other}' (try 'help')").into()),
        }
    }

    // ---- remote/local listing + navigation ---------------------------------

    async fn ls(&self, args: &[String]) -> Result<String, BoxErr> {
        let path = self.resolve_remote(args.first().map(|s| s.as_str()).unwrap_or(""));
        if let Some(node) = self.ctx.get_by_path(&path).await? {
            if !node.is_directory() {
                return Ok(path);
            }
            let mut names: Vec<String> = node.children().await?.iter().map(|c| c.name().to_string()).collect();
            names.sort();
            return Ok(names.join("\n"));
        }
        // In a secret-link session a path can be a virtual directory: an ancestor of
        // the mounted links that has no capability of its own. List its next segments.
        if self.link_mode {
            let kids = self.virtual_children(&path);
            if !kids.is_empty() {
                return Ok(kids.into_iter().map(|k| format!("{k}/")).collect::<Vec<_>>().join("\n"));
            }
        }
        Err(format!("no such path: {path}").into())
    }

    /// The immediate child segments of `path` implied by the mounted link paths —
    /// i.e. the contents of a virtual intermediate directory in a `--links` session.
    fn virtual_children(&self, path: &str) -> Vec<String> {
        let base = normalize_remote(path);
        let prefix = if base == "/" { "/".to_string() } else { format!("{base}/") };
        let mut kids = std::collections::BTreeSet::new();
        for m in self.ctx.link_mount_paths() {
            if let Some(rest) = normalize_remote(&m).strip_prefix(&prefix) {
                if let Some(seg) = rest.split('/').find(|s| !s.is_empty()) {
                    kids.insert(seg.to_string());
                }
            }
        }
        kids.into_iter().collect()
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
            None if self.link_mode => "/".to_string(),
            None => format!("/{}", self.username),
            Some(a) => self.resolve_remote(a),
        };
        if let Some(node) = self.ctx.get_by_path(&path).await? {
            if !node.is_directory() {
                return Err(format!("not a directory: {path}").into());
            }
            self.pwd = path.clone();
            return Ok(format!("Current directory: {path}"));
        }
        // A virtual directory (root or an intermediate ancestor of the mounted links).
        if self.link_mode && (path == "/" || !self.virtual_children(&path).is_empty()) {
            self.pwd = normalize_remote(&path);
            return Ok(format!("Current directory: {}", self.pwd));
        }
        Err(format!("no such path: {path}").into())
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

    async fn share_write(&self, args: &[String]) -> Result<String, BoxErr> {
        let remote_arg = args.first().ok_or("usage: share_write <remote-path> <user>")?;
        let target = args.get(1).ok_or("usage: share_write <remote-path> <user>")?;
        let remote = self.resolve_remote(remote_arg);
        // Write sharing works on a child of a parent directory: split the path.
        let rel = self.home_relative(&remote)?;
        let (parent_rel, child_name) = match rel.rsplit_once('/') {
            Some((p, n)) => (p.to_string(), n.to_string()),
            None => (String::new(), rel.clone()),
        };
        let parent_remote = if parent_rel.is_empty() {
            format!("/{}", self.username)
        } else {
            format!("/{}/{}", self.username, parent_rel)
        };
        let parent = self.ctx.get_by_path(&parent_remote).await?.ok_or_else(|| format!("no such path: {parent_remote}"))?;
        let user = self.ctx.user().ok_or("not signed in")?;
        let followers = peergos_fs::get_follower_names(user, self.ctx.store(), self.ctx.mutable().as_ref()).await?;
        if !followers.contains(target) {
            return Ok(format!("Not shared: '{target}' is not following you"));
        }
        peergos_fs::share_write_access(user, &parent_rel, parent.capability(), &child_name, target, self.ctx.store(), self.ctx.mutable().as_ref()).await?;
        Ok(format!("Shared write-access to '{remote}' with {target}"))
    }

    /// Mint a secret link to a file/dir. Read-only by default; `--write` makes it
    /// writable (rotating the target into its own writer). Optionally password-
    /// protect it, expire it after a duration, and/or cap the number of retrievals.
    ///   link <remote> [--write] [--password [pw]] [--expiry <30m|24h|7d>] [--max-uses <n>]
    async fn link(&self, args: &[String]) -> Result<String, BoxErr> {
        const USAGE: &str = "usage: link <remote-path> [--write] [--password [pw]] [--expiry <30m|24h|7d>] [--max-uses <n>]";
        let path_arg = args.first().filter(|a| !a.starts_with("--")).ok_or(USAGE)?;
        let remote = self.resolve_remote(path_arg);
        let rel = self.home_relative(&remote)?;

        let mut writable = false;
        let mut password = String::new();
        let mut expiry: Option<i64> = None;
        let mut max_uses: Option<i64> = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--write" | "--writable" => writable = true,
                "--password" => {
                    // Optional inline value; otherwise prompt (kept out of shell history).
                    match args.get(i + 1).filter(|v| !v.starts_with("--")) {
                        Some(v) => {
                            password = v.clone();
                            i += 1;
                        }
                        None => password = read_password("Link password > ")?,
                    }
                }
                "--expiry" => {
                    let v = args.get(i + 1).ok_or("--expiry needs a duration like 30m, 24h, 7d")?;
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
                    expiry = Some(now + parse_duration_secs(v)?);
                    i += 1;
                }
                "--max-uses" | "--max-retrievals" => {
                    let v = args.get(i + 1).ok_or("--max-uses needs a number")?;
                    max_uses = Some(v.parse().map_err(|_| format!("invalid --max-uses value: {v}"))?);
                    i += 1;
                }
                other => return Err(format!("unknown option '{other}'\n{USAGE}").into()),
            }
            i += 1;
        }

        if self.ctx.get_by_path(&rel).await?.is_none() {
            return Err(format!("no such path: {remote}").into());
        }
        let link = self.ctx.create_secret_link(&rel, writable, &password, expiry, max_uses).await?;

        let mut notes = vec![if writable { "writable" } else { "read-only" }.to_string()];
        if !password.is_empty() {
            notes.push("password-protected".to_string());
        }
        if expiry.is_some() {
            notes.push("expiring".to_string());
        }
        if let Some(n) = max_uses {
            notes.push(format!("max {n} use(s)"));
        }
        Ok(format!("Created secret link to '{remote}' ({}):\n{link}", notes.join(", ")))
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

fn has_flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn normalize_server(s: &str) -> String {
    let s = s.trim();
    let s = if s.is_empty() { "https://peergos.net" } else { s };
    if s.starts_with("http") { s.to_string() } else { format!("https://{s}") }
}

fn make_shell(ctx: UserContext, username: String, server: String) -> Shell {
    Shell {
        pwd: format!("/{username}"),
        lpwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        ctx,
        username,
        server,
        link_mode: false,
    }
}

/// A shell over a secret-link context: no home, `/` is a virtual root listing the
/// link targets, and each link target is an addressable root beneath it.
fn make_link_shell(ctx: UserContext, server: String) -> Shell {
    Shell {
        pwd: "/".to_string(),
        lpwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        ctx,
        username: "links".to_string(),
        server,
        link_mode: true,
    }
}

/// Resolve a secret link to its capability, prompting for a user password if the
/// link turns out to be password-protected.
async fn resolve_link_interactive(
    link: &str,
    store: &dyn ContentAddressedStorage,
) -> Result<AbsoluteCapability, BoxErr> {
    match retrieve_secret_link_capability(link, store, None).await {
        Ok(cap) => Ok(cap),
        Err(e) if e.to_string().to_lowercase().contains("password") => {
            let pw = read_password(&format!("Password for link {link} > "))?;
            Ok(retrieve_secret_link_capability(link, store, Some(&pw)).await?)
        }
        Err(e) => Err(e.into()),
    }
}

/// Build the poster + (props-driven direct-S3) store + mutable pointers for a server.
async fn build_transport(
    server: &str,
) -> Result<(Arc<dyn HttpPoster>, Arc<dyn ContentAddressedStorage>, Arc<dyn MutablePointers>), BoxErr> {
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(server, false)?);
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(server, false)?)));
    let http_store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(server, false)?), true));
    let props = DirectS3Storage::fetch_properties(poster.as_ref()).await.unwrap_or_default();
    let store: Arc<dyn ContentAddressedStorage> = if props.use_direct_block_store() {
        let s3_server: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(server, false)?);
        let s3_direct: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(server, true)?);
        Arc::new(DirectS3Storage::with_properties(props, s3_server, s3_direct, http_store))
    } else {
        http_store
    };
    Ok((poster, store, mutable))
}

// ---- persisted session ("stay logged in") ----------------------------------

fn session_file_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".peergos-shell").join("session.cbor")
}

/// Load a saved `(server, session)` from disk, if present and parseable.
fn load_session(path: &Path) -> Option<(String, peergos_fs::LoggedInUser)> {
    let bytes = std::fs::read(path).ok()?;
    let cbor = peergos_cbor::CborObject::from_bytes(&bytes).ok()?;
    let server = cbor.get("s")?.as_string()?.to_string();
    let user = peergos_fs::LoggedInUser::from_cbor(cbor.get("u")?).ok()?;
    Some((server, user))
}

/// Save the current session (contains secret keys) to a private (0600) file.
fn save_session(path: &Path, server: &str, user: &peergos_fs::LoggedInUser) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let cbor = peergos_cbor::CborObject::map()
        .put("s", peergos_cbor::CborObject::Str(server.to_string()))
        .put("u", user.to_cbor())
        .build();
    std::fs::write(path, cbor.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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

/// Parse a duration like `30s`, `15m`, `24h`, `7d` into seconds.
fn parse_duration_secs(s: &str) -> Result<i64, BoxErr> {
    let s = s.trim();
    let err = || format!("invalid duration '{s}' (use e.g. 30m, 24h, 7d)");
    let (num, unit) = s.split_at(s.len().checked_sub(1).ok_or_else(err)?);
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(err().into()),
    };
    let n: i64 = num.parse().map_err(|_| err())?;
    if n < 0 {
        return Err(err().into());
    }
    Ok(n * mult)
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
        "  share_write <remote> <user>            grant write access to a follower",
        "  link <remote> [--write] [--password [pw]] [--expiry <30m|24h|7d>] [--max-uses <n>]",
        "                                         mint a secret link to a file/dir",
        "  passwd                                 change your password",
        "  help | ?                               show this help",
        "  exit | quit | bye                      disconnect",
    ]
    .join("\n")
}
