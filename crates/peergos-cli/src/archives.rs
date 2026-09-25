//! Shell commands that reach inside zip archives, plus `cat`, `mv`, `make_public`
//! and `ls -l` (`peergos.server.cli.ArchiveNavigator` and friends).
//!
//! The archive boundary is the first component of a path that is a zip file rather
//! than a directory, so `/me/backups/data.zip/logs/first.log` needs no new syntax.

use crate::{normalize_remote, prompt, split_flags, split_remote, BoxErr, Shell};
use peergos_fs::archive::{self, EntrySource, FnSink, NewEntry, ZipEntry, ZipReader};
use peergos_fs::FileWrapper;
use std::io::Write;
use std::path::Path;

const ZIP_MIMETYPE: &str = "application/zip";

/// Where a remote path points.
pub(crate) enum Target {
    /// A file or directory in the drive, which may itself be an archive.
    Node(FileWrapper),
    /// A path inside an archive, `entry` being relative to its root.
    InArchive { archive: FileWrapper, entry: String },
}

pub(crate) fn is_archive(node: &FileWrapper) -> bool {
    !node.is_directory() && node.properties().mime_type == ZIP_MIMETYPE
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let units = ["KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    size /= 1024.0;
    while size >= 1024.0 && unit < units.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if size < 10.0 { format!("{size:.1} {}", units[unit]) } else { format!("{size:.0} {}", units[unit]) }
}

fn format_time(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

fn long_line(is_dir: bool, readable: bool, writable: bool, size: u64, millis: i64, name: &str) -> String {
    format!(
        "{}{}{}  {:>9}  {}  {}{}",
        if is_dir { "d" } else { "-" },
        if readable { "r" } else { "-" },
        if writable { "w" } else { "-" },
        if is_dir { "-".to_string() } else { format_size(size) },
        format_time(millis),
        name,
        if is_dir { "/" } else { "" }
    )
}

fn node_line(node: &FileWrapper) -> String {
    let p = node.properties();
    long_line(node.is_directory(), true, node.is_writable(), p.size, p.modified_epoch * 1000, node.name())
}

/// An entry is writable when its archive is, since writing to one rewrites the archive.
fn entry_line(entry: &ZipEntry, writable: bool) -> String {
    long_line(entry.is_directory, entry.is_supported(), writable, entry.size, entry.modified_millis, entry.name())
}

/// A local file's modification time as the local wall clock, which is what a zip
/// records (it has no timezone).
fn local_clock_millis(path: &Path) -> i64 {
    let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let utc: chrono::DateTime<chrono::Utc> = modified.map(Into::into).unwrap_or_else(chrono::Utc::now);
    utc.with_timezone(&chrono::Local).naive_local().and_utc().timestamp_millis()
}

/// Prints bytes as UTF-8 text, carrying a character split across two pieces over.
struct TextPrinter {
    carry: Vec<u8>,
}

impl TextPrinter {
    fn print(&mut self, bytes: &[u8]) {
        self.carry.extend_from_slice(bytes);
        let valid = match std::str::from_utf8(&self.carry) {
            Ok(_) => self.carry.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => self.carry.len(),
        };
        let text = String::from_utf8_lossy(&self.carry[..valid]).into_owned();
        print!("{text}");
        self.carry.drain(..valid);
    }

    fn finish(mut self) {
        if !self.carry.is_empty() {
            print!("{}", String::from_utf8_lossy(&std::mem::take(&mut self.carry)));
        }
        let _ = std::io::stdout().flush();
    }
}

impl Shell {
    /// What a remote path points at, looking inside the first archive on the way.
    pub(crate) async fn resolve_target(&self, path: &str) -> Result<Option<Target>, BoxErr> {
        if let Some(node) = self.ctx.get_by_path(path).await? {
            return Ok(Some(Target::Node(node)));
        }
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for k in (1..comps.len()).rev() {
            let ancestor = format!("/{}", comps[..k].join("/"));
            if let Some(node) = self.ctx.get_by_path(&ancestor).await? {
                if is_archive(&node) {
                    return Ok(Some(Target::InArchive { archive: node, entry: comps[k..].join("/") }));
                }
                return Ok(None);
            }
        }
        Ok(None)
    }

    pub(crate) async fn ls(&self, args: &[String]) -> Result<String, BoxErr> {
        let (flags, pos) = split_flags(args);
        let long = flags.iter().any(|f| f == "-l" || f == "--long");
        let path = self.resolve_remote(pos.first().map(|s| s.as_str()).unwrap_or(""));
        match self.resolve_target(&path).await? {
            Some(Target::Node(node)) if is_archive(&node) => self.ls_archive(&node, "", &path, long).await,
            Some(Target::Node(node)) if !node.is_directory() => Ok(if long { node_line(&node) } else { path }),
            Some(Target::Node(node)) => {
                let mut children = node.children().await?;
                children.sort_by(|a, b| a.name().cmp(b.name()));
                Ok(children
                    .iter()
                    .map(|c| if long { node_line(c) } else { c.name().to_string() })
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
            Some(Target::InArchive { archive, entry }) => self.ls_archive(&archive, &entry, &path, long).await,
            None => {
                // In a secret-link session a path can be a virtual directory: an ancestor
                // of the mounted links with no capability of its own.
                if self.link_mode {
                    let kids = self.virtual_children(&path);
                    if !kids.is_empty() {
                        return Ok(kids.into_iter().map(|k| format!("{k}/")).collect::<Vec<_>>().join("\n"));
                    }
                }
                Err(format!("no such path: {path}").into())
            }
        }
    }

    async fn ls_archive(&self, archive: &FileWrapper, entry: &str, path: &str, long: bool) -> Result<String, BoxErr> {
        let zip = ZipReader::open(archive).await?;
        let writable = archive.is_writable();
        if !entry.is_empty() {
            let e = zip.index().get(entry).ok_or_else(|| format!("no such path: {path}"))?;
            if !e.is_directory {
                return Ok(if long { entry_line(e, writable) } else { path.to_string() });
            }
        }
        let mut children = zip.list_directory(entry)?;
        children.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(children
            .iter()
            .map(|e| if long { entry_line(e, writable) } else { e.name().to_string() })
            .collect::<Vec<_>>()
            .join("\n"))
    }

    pub(crate) async fn cd(&mut self, args: &[String]) -> Result<String, BoxErr> {
        let path = match args.first() {
            None if self.link_mode => "/".to_string(),
            None => format!("/{}", self.username),
            Some(a) => self.resolve_remote(a),
        };
        let is_dir = match self.resolve_target(&path).await? {
            Some(Target::Node(node)) => node.is_directory() || is_archive(&node),
            Some(Target::InArchive { archive, entry }) => ZipReader::open(&archive).await?.index().is_directory(&entry),
            None => {
                // a virtual directory: the root or an ancestor of the mounted links
                if self.link_mode && (path == "/" || !self.virtual_children(&path).is_empty()) {
                    self.pwd = normalize_remote(&path);
                    return Ok(format!("Current directory: {}", self.pwd));
                }
                return Err(format!("no such path: {path}").into());
            }
        };
        if !is_dir {
            return Err(format!("not a directory: {path}").into());
        }
        self.pwd = path.clone();
        Ok(format!("Current directory: {path}"))
    }

    pub(crate) async fn cat(&self, args: &[String]) -> Result<String, BoxErr> {
        let path = self.resolve_remote(args.first().ok_or("usage: cat <remote-path>")?);
        let mut printer = TextPrinter { carry: Vec::new() };
        match self.resolve_target(&path).await? {
            Some(Target::Node(node)) if node.is_directory() => return Err(format!("'{path}' is a directory.").into()),
            Some(Target::Node(node)) => {
                let size = node.size();
                let mut at = 0;
                while at < size {
                    let piece = node.read_section(at, 1024 * 1024).await?;
                    if piece.is_empty() {
                        break;
                    }
                    at += piece.len() as u64;
                    printer.print(&piece);
                }
            }
            Some(Target::InArchive { archive, entry }) => {
                let zip = ZipReader::open(&archive).await?;
                let e = zip.index().get(&entry).ok_or_else(|| format!("no such path: {path}"))?.clone();
                if e.is_directory {
                    return Err(format!("'{path}' is a directory.").into());
                }
                zip.read_to(&e, &mut FnSink(|b: &[u8]| {
                    printer.print(b);
                    Ok(())
                }))
                .await?;
            }
            None => return Err(format!("no such path: {path}").into()),
        }
        printer.finish();
        Ok(String::new())
    }

    /// `get` of a path inside an archive: one entry, or a directory of them.
    pub(crate) async fn get_from_archive(
        &self,
        archive: &FileWrapper,
        entry: &str,
        local_arg: Option<&String>,
        skip_existing: bool,
    ) -> Result<String, BoxErr> {
        let zip = ZipReader::open(archive).await?;
        let root = zip.index().get(entry).ok_or_else(|| format!("no such entry in the archive: {entry}"))?.clone();
        let local = match local_arg {
            Some(l) => self.resolve_local(l),
            None => self.lpwd.join(root.name()),
        };
        let files: Vec<ZipEntry> = if root.is_directory {
            let prefix = format!("{}/", root.path);
            zip.index().entries().iter().filter(|e| e.path.starts_with(&prefix)).cloned().collect()
        } else {
            vec![root.clone()]
        };
        std::fs::create_dir_all(if root.is_directory { local.as_path() } else { local.parent().unwrap_or(Path::new(".")) })?;
        let mut count = 0;
        for e in files {
            let target = if root.is_directory { local.join(&e.path[root.path.len() + 1..]) } else { local.clone() };
            if e.is_directory {
                std::fs::create_dir_all(&target)?;
                continue;
            }
            if skip_existing && target.exists() {
                continue;
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = std::fs::File::create(&target)?;
            zip.read_to(&e, &mut FnSink(|b: &[u8]| out.write_all(b).map_err(|err| peergos_core::Error::Protocol(err.to_string()))))
                .await?;
            count += 1;
        }
        Ok(format!("Extracted {count} file(s) to {}", local.display()))
    }

    /// `put` into an archive: a local file or directory goes under `entry` when that
    /// is a directory in the archive (or its root), else to `entry` itself, all in one
    /// rewrite of the archive's tail.
    pub(crate) async fn put_in_archive(
        &self,
        archive: &FileWrapper,
        entry: &str,
        local: &Path,
        skip_existing: bool,
    ) -> Result<String, BoxErr> {
        let zip = ZipReader::open(archive).await?;
        let name = local.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let into_dir = entry.is_empty() || zip.index().is_directory(entry);
        let base = match (into_dir, entry.is_empty()) {
            (true, true) => name,
            (true, false) => format!("{entry}/{name}"),
            (false, _) if local.is_dir() => return Err(format!("{entry} is a file in the archive, not a directory").into()),
            (false, _) => entry.to_string(),
        };
        let mut entries = Vec::new();
        collect_local(local, &base, &mut entries)?;
        if skip_existing {
            entries.retain(|e| zip.index().get(&e.path).is_none());
        }
        if entries.is_empty() {
            return Ok("Nothing to add".to_string());
        }
        let n = entries.len();
        archive::append(archive, entries).await?;
        Ok(format!("Added {n} entr{} to {}", if n == 1 { "y" } else { "ies" }, archive.name()))
    }

    pub(crate) async fn rm_in_archive(&self, archive: &FileWrapper, entry: &str, path: &str) -> Result<String, BoxErr> {
        let zip = ZipReader::open(archive).await?;
        let e = zip.index().get(entry).ok_or_else(|| format!("no such path: {path}"))?;
        if e.is_directory {
            let ans = prompt(&format!("Delete {path} and everything in it from the archive? (y/N) "))?;
            if ans.trim().to_lowercase() != "y" {
                return Ok("Aborting delete".to_string());
            }
        }
        archive::remove(archive, &[entry.to_string()], true).await?;
        Ok(format!("Deleted {path}"))
    }

    /// `mv src dst`: a rename or move of a file or directory, including within an
    /// archive. A `dst` that is an existing directory receives `src` under its name.
    pub(crate) async fn mv(&self, args: &[String]) -> Result<String, BoxErr> {
        const USAGE: &str = "usage: mv <remote-path> <new-name-or-path>";
        let src = self.resolve_remote(args.first().ok_or(USAGE)?);
        let dst = self.resolve_remote(args.get(1).ok_or(USAGE)?);
        match self.resolve_target(&src).await?.ok_or_else(|| format!("no such path: {src}"))? {
            Target::InArchive { archive, entry } => {
                let prefix = format!("{}/", src[..src.len() - entry.len()].trim_end_matches('/'));
                let dst_entry = dst
                    .strip_prefix(&prefix)
                    .ok_or("an entry can only be moved within its own archive")?
                    .to_string();
                let zip = ZipReader::open(&archive).await?;
                let name = entry.rsplit('/').next().unwrap_or(&entry);
                let target = if zip.index().is_directory(&dst_entry) { format!("{dst_entry}/{name}") } else { dst_entry };
                archive::move_entry(&archive, &entry, &target).await?;
                Ok(format!("Moved {src} to {prefix}{target}"))
            }
            Target::Node(_) => {
                let (src_parent, name) = split_remote(&src);
                let parent = self.ctx.get_by_path(&src_parent).await?.ok_or_else(|| format!("no such path: {src_parent}"))?;
                if let Some(dir) = self.ctx.get_by_path(&dst).await? {
                    if dir.is_directory() {
                        parent.move_child(&name, &dir, true).await?;
                        return Ok(format!("Moved {src} into {dst}"));
                    }
                    return Err(format!("{dst} already exists").into());
                }
                let (dst_parent, new_name) = split_remote(&dst);
                if dst_parent != src_parent {
                    let dir = self.ctx.get_by_path(&dst_parent).await?.ok_or_else(|| format!("no such path: {dst_parent}"))?;
                    parent.move_child(&name, &dir, true).await?;
                    if new_name != name {
                        dir.get_latest().await?.rename_child(&name, &new_name).await?;
                    }
                } else {
                    parent.rename_child(&name, &new_name).await?;
                }
                Ok(format!("Moved {src} to {dst}"))
            }
        }
    }

    pub(crate) async fn make_public(&self, args: &[String]) -> Result<String, BoxErr> {
        let path = self.resolve_remote(args.first().ok_or("usage: make_public <remote-path>")?);
        let rel = self.home_relative(&path)?;
        self.ctx.make_public(&rel).await?;
        Ok(format!("{path} is now public"))
    }
}

/// Every file (and empty directory) under a local path, as archive entries under `base`.
fn collect_local(local: &Path, base: &str, out: &mut Vec<NewEntry>) -> Result<(), BoxErr> {
    let modified = local_clock_millis(local);
    if local.is_dir() {
        let mut children: Vec<_> = std::fs::read_dir(local)?.filter_map(|e| e.ok()).collect();
        if children.is_empty() {
            out.push(NewEntry::directory(base, modified)?);
        }
        children.sort_by_key(|e| e.file_name());
        for c in children {
            collect_local(&c.path(), &format!("{base}/{}", c.file_name().to_string_lossy()), out)?;
        }
    } else {
        let size = std::fs::metadata(local)?.len();
        out.push(NewEntry::file(base, size, modified, EntrySource::Local(local.to_path_buf()))?);
    }
    Ok(())
}
