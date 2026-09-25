//! Zip archives stored in Peergos, read and changed without reading or rewriting
//! the whole file (`peergos.shared.user.fs.archive`).
//!
//! A zip's index lives at its end, so listing an archive costs a read of its tail
//! and central directory, opening an entry costs a read of just that entry, and
//! adding, removing or renaming entries comes down to rewriting the tail. Records
//! for entries that aren't touched are carried over byte for byte, so whatever a
//! previous writer put in them survives.

use crate::filewrapper::FileWrapper;
use async_trait::async_trait;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use peergos_core::error::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

const LOCAL_HEADER_SIG: u32 = 0x04034b50;
const CENTRAL_HEADER_SIG: u32 = 0x02014b50;
const EOCD_SIG: u32 = 0x06054b50;
const ZIP64_EOCD_SIG: u32 = 0x06064b50;
const ZIP64_LOCATOR_SIG: u32 = 0x07064b50;

const EOCD_SIZE: usize = 22;
const ZIP64_EOCD_SIZE: usize = 56;
const ZIP64_LOCATOR_SIZE: usize = 20;
const LOCAL_HEADER_SIZE: usize = 30;
const CENTRAL_HEADER_SIZE: usize = 46;
const MAX_COMMENT_SIZE: usize = 0xFFFF;

pub const STORED: u16 = 0;
pub const DEFLATED: u16 = 8;

const FLAG_ENCRYPTED: u16 = 1;
const FLAG_STRONG_ENCRYPTION: u16 = 1 << 6;
const FLAG_UTF8_NAMES: u16 = 1 << 11;

const ZIP64_EXTRA_ID: u16 = 0x0001;
const UNICODE_NAME_EXTRA_ID: u16 = 0x7075;
const EXTENDED_TIMESTAMP_EXTRA_ID: u16 = 0x5455;

const U32_MAX: u64 = 0xFFFF_FFFF;
const U16_MAX: u64 = 0xFFFF;

/// An index of this many entries already costs over 100 MB of RAM, which is where
/// browsing stops being a sensible thing to offer.
pub const MAX_ENTRIES: usize = 500_000;
/// Central directories bigger than this are refused rather than read into memory.
const MAX_CENTRAL_DIRECTORY: u64 = 64 * 1024 * 1024;
/// How much of an entry is read or written per request.
const PIECE: usize = 1024 * 1024;
/// A tail up to this size is written in one request, so the change is atomic.
const TAIL_BUFFER: usize = 32 * 1024 * 1024;

/// Where streamed bytes go: an entry being read, a compressor, or the archive tail.
#[async_trait(?Send)]
pub trait ByteSink {
    async fn accept(&mut self, bytes: &[u8]) -> Result<()>;
}

/// A [`ByteSink`] over a closure.
pub struct FnSink<F>(pub F);

#[async_trait(?Send)]
impl<F: FnMut(&[u8]) -> Result<()>> ByteSink for FnSink<F> {
    async fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        (self.0)(bytes)
    }
}

struct CountingSink(u64);

#[async_trait(?Send)]
impl ByteSink for CountingSink {
    async fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        self.0 += bytes.len() as u64;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// little endian primitives
// ---------------------------------------------------------------------------

fn u16_at(d: &[u8], i: usize) -> u64 {
    u16::from_le_bytes([d[i], d[i + 1]]) as u64
}

fn u32_at(d: &[u8], i: usize) -> u64 {
    u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]) as u64
}

fn u64_at(d: &[u8], i: usize) -> Result<u64> {
    let v = u64::from_le_bytes(d[i..i + 8].try_into().unwrap());
    if v > i64::MAX as u64 {
        return Err(Error::Protocol(format!("Zip value too large: {v}")));
    }
    Ok(v)
}

fn put_u16(d: &mut [u8], i: usize, v: u64) {
    d[i..i + 2].copy_from_slice(&(v as u16).to_le_bytes());
}

fn put_u32(d: &mut [u8], i: usize, v: u64) {
    d[i..i + 4].copy_from_slice(&(v as u32).to_le_bytes());
}

fn put_u64(d: &mut [u8], i: usize, v: u64) {
    d[i..i + 8].copy_from_slice(&v.to_le_bytes());
}

/// The 128 high characters of code page 437, the ZIP default encoding for names.
const CP437_HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

fn decode_name(raw: &[u8], utf8: bool) -> Result<String> {
    if utf8 {
        return String::from_utf8(raw.to_vec()).map_err(|_| Error::Protocol("Invalid UTF-8 in zip entry name".into()));
    }
    let high: Vec<char> = CP437_HIGH.chars().collect();
    Ok(raw.iter().map(|&b| if b < 0x80 { b as char } else { high[(b - 0x80) as usize] }).collect())
}

/// An MS-DOS date and time pair as milliseconds since the epoch, in whatever
/// timezone the writer used, which is all the DOS format records.
fn dos_time_to_millis(dos_time: u64, dos_date: u64) -> i64 {
    if dos_date == 0 {
        return 0;
    }
    let year = 1980 + ((dos_date >> 9) & 0x7F) as i64;
    let month = ((dos_date >> 5) & 0x0F) as i64;
    let day = (dos_date & 0x1F) as i64;
    let hour = ((dos_time >> 11) & 0x1F) as i64;
    let minute = ((dos_time >> 5) & 0x3F) as i64;
    let second = ((dos_time & 0x1F) * 2) as i64;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return 0;
    }
    let days = days_from_civil(year, month, day);
    ((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The date of a day count since 1970-01-01, as (year, month, day).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/// The MS-DOS (time, date) pair for a moment.
fn millis_to_dos_time(millis: i64) -> (u64, u64) {
    let seconds = millis.div_euclid(1000);
    let days = seconds.div_euclid(86400);
    let second_of_day = seconds.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    if y < 1980 {
        return (0, 0x21); // the earliest the format can express: 1980-01-01
    }
    let date = (((y - 1980) << 9) | (m << 5) | d) as u64;
    let time = (((second_of_day / 3600) << 11) | (((second_of_day / 60) % 60) << 5) | ((second_of_day % 60) / 2)) as u64;
    (time, date)
}

// ---------------------------------------------------------------------------
// entries and the index
// ---------------------------------------------------------------------------

/// Strip what a zip name may carry that a path within the archive cannot: a
/// leading slash, a windows drive, and "." components. A ".." component would
/// escape the archive, so such a name is rejected.
pub fn normalise_path(raw: &str) -> Option<String> {
    let mut name = raw.replace('\\', "/");
    if name.len() > 1 && name.as_bytes()[1] == b':' {
        name = name[2..].to_string();
    }
    let mut parts = Vec::new();
    for c in name.split('/') {
        match c {
            "" | "." => continue,
            ".." => return None,
            c => parts.push(c),
        }
    }
    Some(parts.join("/"))
}

/// One entry in a zip archive, as its central directory record describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    /// Normalised: no leading or trailing slash, no "." or ".." components.
    pub path: String,
    pub is_directory: bool,
    pub size: u64,
    pub compressed_size: u64,
    pub compression_method: u16,
    pub crc32: u32,
    /// -1 for a directory no record describes, which the paths below it imply.
    pub local_header_offset: i64,
    /// Milliseconds since the epoch, in the writer's local time.
    pub modified_millis: i64,
    pub flags: u16,
}

impl ZipEntry {
    fn implicit_directory(path: String, modified_millis: i64) -> ZipEntry {
        ZipEntry {
            path,
            is_directory: true,
            size: 0,
            compressed_size: 0,
            compression_method: STORED,
            crc32: 0,
            local_header_offset: -1,
            modified_millis,
            flags: 0,
        }
    }

    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn parent_path(&self) -> &str {
        self.path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0
    }

    pub fn is_supported(&self) -> bool {
        !self.is_encrypted() && (self.compression_method == STORED || self.compression_method == DEFLATED)
    }

    /// Parse a central directory record at `d[offset..]`. `None` for an entry whose
    /// name escapes the archive root.
    fn from_central_directory(d: &[u8], offset: usize, delta: i64) -> Result<Option<ZipEntry>> {
        if u32_at(d, offset) as u32 != CENTRAL_HEADER_SIG {
            return Err(Error::Protocol("Invalid zip central directory record".into()));
        }
        let flags = u16_at(d, offset + 8) as u16;
        let method = u16_at(d, offset + 10) as u16;
        let dos_time = u16_at(d, offset + 12);
        let dos_date = u16_at(d, offset + 14);
        let crc = u32_at(d, offset + 16) as u32;
        let mut compressed_size = u32_at(d, offset + 20);
        let mut size = u32_at(d, offset + 24);
        let name_len = u16_at(d, offset + 28) as usize;
        let extra_len = u16_at(d, offset + 30) as usize;
        let external = u32_at(d, offset + 38);
        let mut local_header_offset = u32_at(d, offset + 42);

        let name_start = offset + CENTRAL_HEADER_SIZE;
        let extra_start = name_start + name_len;
        let utf8 = flags & FLAG_UTF8_NAMES != 0;
        let mut raw_name = decode_name(&d[name_start..extra_start], utf8)?;
        let mut millis = dos_time_to_millis(dos_time, dos_date);
        let mut i = extra_start;
        while i + 4 <= extra_start + extra_len {
            let id = u16_at(d, i) as u16;
            let len = u16_at(d, i + 2) as usize;
            let body = i + 4;
            if body + len > extra_start + extra_len {
                break;
            }
            if id == ZIP64_EXTRA_ID {
                let mut at = body;
                if size == U32_MAX && at + 8 <= body + len {
                    size = u64_at(d, at)?;
                    at += 8;
                }
                if compressed_size == U32_MAX && at + 8 <= body + len {
                    compressed_size = u64_at(d, at)?;
                    at += 8;
                }
                if local_header_offset == U32_MAX && at + 8 <= body + len {
                    local_header_offset = u64_at(d, at)?;
                }
            } else if id == UNICODE_NAME_EXTRA_ID && !utf8 && len > 5 && d[body] == 1 {
                if crc32fast::hash(&d[name_start..extra_start]) as u64 == u32_at(d, body + 1) {
                    raw_name = decode_name(&d[body + 5..body + len], true)?;
                }
            } else if id == EXTENDED_TIMESTAMP_EXTRA_ID && len >= 5 && d[body] & 1 != 0 {
                millis = i32::from_le_bytes(d[body + 1..body + 5].try_into().unwrap()) as i64 * 1000;
            }
            i = body + len;
        }
        // a directory is signalled by a trailing slash, or by the MS-DOS directory attribute
        let is_directory = raw_name.ends_with('/') || external & 0x10 != 0;
        let path = match normalise_path(&raw_name) {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(None),
        };
        Ok(Some(ZipEntry {
            path,
            is_directory,
            size: if is_directory { 0 } else { size },
            compressed_size: if is_directory { 0 } else { compressed_size },
            compression_method: method,
            crc32: crc,
            local_header_offset: local_header_offset as i64 + delta,
            modified_millis: millis,
            flags,
        }))
    }
}

/// The listing of an archive: every entry, and the directory tree their paths imply.
/// Archives often omit directory entries, so the tree comes from the paths.
#[derive(Debug, Clone)]
pub struct ZipIndex {
    entries: Vec<ZipEntry>,
    by_path: HashMap<String, ZipEntry>,
    children: HashMap<String, Vec<ZipEntry>>,
    /// Entries dropped because their name escaped the archive root.
    pub rejected: usize,
}

impl ZipIndex {
    fn build(parsed: Vec<ZipEntry>, rejected: usize) -> ZipIndex {
        let mut by_path: HashMap<String, ZipEntry> = HashMap::new();
        let mut order: Vec<String> = Vec::new();
        for entry in parsed {
            // a later duplicate wins, as unzip extracts, unless it would hide a directory
            match by_path.get(&entry.path) {
                Some(existing) if existing.is_directory => {}
                Some(_) => {
                    by_path.insert(entry.path.clone(), entry);
                }
                None => {
                    order.push(entry.path.clone());
                    by_path.insert(entry.path.clone(), entry);
                }
            }
        }
        for path in order {
            let entry = by_path[&path].clone();
            let mut parent = entry.parent_path().to_string();
            while !parent.is_empty() {
                if by_path.get(&parent).is_some_and(|e| e.is_directory) {
                    break;
                }
                by_path.insert(parent.clone(), ZipEntry::implicit_directory(parent.clone(), entry.modified_millis));
                parent = parent.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default();
            }
        }
        let mut children: HashMap<String, Vec<ZipEntry>> = HashMap::new();
        for e in by_path.values() {
            children.entry(e.parent_path().to_string()).or_default().push(e.clone());
        }
        for siblings in children.values_mut() {
            siblings.sort_by(|a, b| {
                b.is_directory.cmp(&a.is_directory).then_with(|| a.name().to_lowercase().cmp(&b.name().to_lowercase()))
            });
        }
        let mut entries: Vec<ZipEntry> = by_path.values().cloned().collect();
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        ZipIndex { entries, by_path, children, rejected }
    }

    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, path: &str) -> Option<&ZipEntry> {
        normalise_path(path).and_then(|p| self.by_path.get(&p))
    }

    pub fn is_directory(&self, path: &str) -> bool {
        self.get(path).is_some_and(|e| e.is_directory)
    }

    /// The contents of a directory within the archive, "" being its root.
    pub fn list_directory(&self, path: &str) -> Result<Vec<ZipEntry>> {
        let dir = normalise_path(path).ok_or_else(|| Error::Protocol(format!("Invalid path: {path}")))?;
        if !dir.is_empty() && !self.is_directory(&dir) {
            return Err(Error::Protocol(format!("Not a directory in this archive: {path}")));
        }
        Ok(self.children.get(&dir).cloned().unwrap_or_default())
    }

    /// The total decompressed size of the archive's files: what extracting it costs.
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }
}

// ---------------------------------------------------------------------------
// reading
// ---------------------------------------------------------------------------

/// Where the central directory is and how big. The position is derived from where
/// the end records are rather than the offset they record, so an archive with data
/// prepended still resolves; every stored offset is then shifted by `delta`.
#[derive(Debug, Clone)]
struct Directory {
    start: u64,
    size: u64,
    entries: u64,
    delta: i64,
}

/// Reads a zip archive stored in Peergos without ever reading the whole file.
#[derive(Clone)]
pub struct ZipReader {
    file: FileWrapper,
    file_size: u64,
    index: ZipIndex,
    cd: Directory,
}

async fn read_exact(file: &FileWrapper, offset: u64, len: usize) -> Result<Vec<u8>> {
    let bytes = file.read_section(offset, len as u64).await?;
    if bytes.len() != len {
        return Err(Error::Protocol("Unexpected end of zip file".into()));
    }
    Ok(bytes)
}

fn find_eocd(tail: &[u8]) -> Option<usize> {
    if tail.len() < EOCD_SIZE {
        return None;
    }
    let candidates = (0..=tail.len() - EOCD_SIZE).rev();
    for i in candidates.clone() {
        if u32_at(tail, i) as u32 == EOCD_SIG && i + EOCD_SIZE + u16_at(tail, i + 20) as usize == tail.len() {
            return Some(i);
        }
    }
    // some writers record a comment length that doesn't reach the end of the file
    candidates.into_iter().find(|&i| u32_at(tail, i) as u32 == EOCD_SIG)
}

impl ZipReader {
    /// Open an archive: a read of its tail, then of its central directory.
    pub async fn open(file: &FileWrapper) -> Result<ZipReader> {
        // every write to an archive changes it, so never trust a handle's size
        let file = &file.get_latest().await?;
        let file_size = file.size();
        if file_size < EOCD_SIZE as u64 {
            return Err(Error::Protocol("File is too small to be a zip archive".into()));
        }
        let tail_len = file_size.min((EOCD_SIZE + MAX_COMMENT_SIZE) as u64) as usize;
        let tail_start = file_size - tail_len as u64;
        let tail = read_exact(file, tail_start, tail_len).await?;
        let eocd = find_eocd(&tail)
            .ok_or_else(|| Error::Protocol("Not a zip archive: no end of central directory record".into()))?;
        let cd = Self::locate_central_directory(file, &tail, tail_start, eocd).await?;
        if cd.entries > MAX_ENTRIES as u64 {
            return Err(Error::Protocol(format!("Too many entries to browse this archive: {}", cd.entries)));
        }
        if cd.start + cd.size > file_size {
            return Err(Error::Protocol("Corrupt zip archive: invalid central directory".into()));
        }
        if cd.size > MAX_CENTRAL_DIRECTORY {
            return Err(Error::Protocol(format!("This archive's index is too big: {}", cd.size)));
        }
        let bytes = read_exact(file, cd.start, cd.size as usize).await?;
        let mut entries = Vec::new();
        let mut rejected = 0;
        for (offset, _) in records(&bytes) {
            match ZipEntry::from_central_directory(&bytes, offset, cd.delta)? {
                Some(e) => entries.push(e),
                None => rejected += 1,
            }
            if entries.len() > MAX_ENTRIES {
                return Err(Error::Protocol("Too many entries to browse this archive".into()));
            }
        }
        Ok(ZipReader { file: file.clone(), file_size, index: ZipIndex::build(entries, rejected), cd })
    }

    async fn locate_central_directory(file: &FileWrapper, tail: &[u8], tail_start: u64, eocd: usize) -> Result<Directory> {
        let entries = u16_at(tail, eocd + 10);
        let size = u32_at(tail, eocd + 12);
        let offset = u32_at(tail, eocd + 16);
        let needs_zip64 = size == U32_MAX || offset == U32_MAX;
        let locator = eocd.checked_sub(ZIP64_LOCATOR_SIZE);
        let locator = match locator {
            Some(l) if u32_at(tail, l) as u32 == ZIP64_LOCATOR_SIG => l,
            _ => {
                if needs_zip64 {
                    return Err(Error::Protocol("Corrupt zip archive: zip64 fields without a zip64 locator".into()));
                }
                let start = (tail_start + eocd as u64)
                    .checked_sub(size)
                    .ok_or_else(|| Error::Protocol("Corrupt zip archive: invalid central directory".into()))?;
                return Ok(Directory { start, size, entries, delta: start as i64 - offset as i64 });
            }
        };
        let parse = |d: &[u8], at: usize, position: u64| -> Result<Directory> {
            let entries = u64_at(d, at + 32)?;
            let size = u64_at(d, at + 40)?;
            let offset = u64_at(d, at + 48)?;
            let start = position
                .checked_sub(size)
                .ok_or_else(|| Error::Protocol("Corrupt zip archive: invalid central directory".into()))?;
            Ok(Directory { start, size, entries, delta: start as i64 - offset as i64 })
        };
        // the zip64 end record normally sits right before its locator, so is already read
        if let Some(in_tail) = locator.checked_sub(ZIP64_EOCD_SIZE) {
            if u32_at(tail, in_tail) as u32 == ZIP64_EOCD_SIG {
                return parse(tail, in_tail, tail_start + in_tail as u64);
            }
        }
        let recorded = u64_at(tail, locator + 8)?;
        let record = read_exact(file, recorded, ZIP64_EOCD_SIZE).await?;
        if u32_at(&record, 0) as u32 != ZIP64_EOCD_SIG {
            return Err(Error::Protocol("Corrupt zip archive: no zip64 end of central directory record".into()));
        }
        parse(&record, 0, recorded)
    }

    pub fn index(&self) -> &ZipIndex {
        &self.index
    }

    pub fn file(&self) -> &FileWrapper {
        &self.file
    }

    pub fn list_directory(&self, path: &str) -> Result<Vec<ZipEntry>> {
        self.index.list_directory(path)
    }

    /// Stream an entry's decompressed contents to `sink`, piece by piece, checking
    /// its size and CRC. An entry that inflates to more than its recorded size is
    /// refused rather than read forever.
    pub async fn read_to(&self, entry: &ZipEntry, sink: &mut dyn ByteSink) -> Result<()> {
        if entry.is_directory {
            return Err(Error::Protocol(format!("Cannot read a directory in an archive: {}", entry.path)));
        }
        if entry.is_encrypted() {
            return Err(Error::Protocol(format!("Encrypted zip entries are not supported: {}", entry.path)));
        }
        if !entry.is_supported() {
            return Err(Error::Protocol(format!(
                "Unsupported zip compression method {} in {}",
                entry.compression_method, entry.path
            )));
        }
        let header_at = entry.local_header_offset as u64;
        let header = read_exact(&self.file, header_at, LOCAL_HEADER_SIZE).await?;
        if u32_at(&header, 0) as u32 != LOCAL_HEADER_SIG {
            return Err(Error::Protocol(format!("Invalid local header for zip entry {}", entry.path)));
        }
        // the local header, not the central directory, describes the bytes that follow it
        let method = u16_at(&header, 8) as u16;
        let data_start = header_at + LOCAL_HEADER_SIZE as u64 + u16_at(&header, 26) + u16_at(&header, 28);
        if data_start + entry.compressed_size > self.file_size {
            return Err(Error::Protocol(format!("Truncated zip entry {}", entry.path)));
        }
        let mut out_sink = Checked { entry, crc: crc32fast::Hasher::new(), produced: 0, sink };
        let mut inflater = Decompress::new(false);
        let mut out = vec![0u8; 64 * 1024];
        let mut read: u64 = 0;
        while read < entry.compressed_size {
            let n = (entry.compressed_size - read).min(PIECE as u64);
            let input = read_exact(&self.file, data_start + read, n as usize).await?;
            read += n;
            if method == STORED {
                out_sink.accept(&input).await?;
                continue;
            }
            let mut consumed = 0;
            while consumed < input.len() {
                let (before_in, before_out) = (inflater.total_in(), inflater.total_out());
                let status = inflater
                    .decompress(&input[consumed..], &mut out, FlushDecompress::None)
                    .map_err(|e| Error::Protocol(format!("Corrupt zip entry {}: {e}", entry.path)))?;
                consumed += (inflater.total_in() - before_in) as usize;
                let made = (inflater.total_out() - before_out) as usize;
                out_sink.accept(&out[..made]).await?;
                if status == Status::StreamEnd || (made == 0 && inflater.total_in() == before_in) {
                    break;
                }
            }
        }
        if method != STORED {
            // drain whatever is still buffered in the inflater
            loop {
                let before_out = inflater.total_out();
                let status = inflater
                    .decompress(&[], &mut out, FlushDecompress::Finish)
                    .map_err(|e| Error::Protocol(format!("Corrupt zip entry {}: {e}", entry.path)))?;
                let made = (inflater.total_out() - before_out) as usize;
                out_sink.accept(&out[..made]).await?;
                if made == 0 || status == Status::StreamEnd {
                    break;
                }
            }
        }
        if out_sink.produced != entry.size {
            return Err(Error::Protocol(format!("Zip entry {} is shorter than its recorded size", entry.path)));
        }
        if out_sink.crc.finalize() != entry.crc32 {
            return Err(Error::Protocol(format!("Zip entry {} failed its CRC check", entry.path)));
        }
        Ok(())
    }

    /// An entry's whole decompressed contents.
    pub async fn read(&self, entry: &ZipEntry) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(entry.size.min(64 * 1024 * 1024) as usize);
        self.read_to(
            entry,
            &mut FnSink(|b: &[u8]| {
                out.extend_from_slice(b);
                Ok(())
            }),
        )
        .await?;
        Ok(out)
    }

    pub async fn read_path(&self, path: &str) -> Result<Vec<u8>> {
        let entry = self.index.get(path).ok_or_else(|| Error::Protocol(format!("No such entry in archive: {path}")))?;
        self.read(entry).await
    }
}

/// Passes an entry's bytes on while checking them against its recorded size, so an
/// entry that inflates past it is refused rather than read forever.
struct Checked<'a> {
    entry: &'a ZipEntry,
    crc: crc32fast::Hasher,
    produced: u64,
    sink: &'a mut dyn ByteSink,
}

#[async_trait(?Send)]
impl ByteSink for Checked<'_> {
    async fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        self.produced += bytes.len() as u64;
        if self.produced > self.entry.size {
            return Err(Error::Protocol(format!("Zip entry {} is larger than its recorded size", self.entry.path)));
        }
        self.crc.update(bytes);
        self.sink.accept(bytes).await
    }
}

/// The (offset, length) of each central directory record in `cd`.
fn records(cd: &[u8]) -> Vec<(usize, usize)> {
    let mut res = Vec::new();
    let mut pos = 0;
    while cd.len() - pos >= CENTRAL_HEADER_SIZE && u32_at(cd, pos) as u32 == CENTRAL_HEADER_SIG {
        let len = CENTRAL_HEADER_SIZE + u16_at(cd, pos + 28) as usize + u16_at(cd, pos + 30) as usize + u16_at(cd, pos + 32) as usize;
        if cd.len() - pos < len {
            break;
        }
        res.push((pos, len));
        pos += len;
    }
    res
}

// ---------------------------------------------------------------------------
// writing
// ---------------------------------------------------------------------------

/// Where a new entry's bytes come from. Each is read twice, once to find out how far
/// it compresses and once to write it, so none is ever held whole.
#[derive(Clone)]
pub enum EntrySource {
    Bytes(Arc<Vec<u8>>),
    /// A file on the local disk.
    Local(PathBuf),
    /// A file in the drive.
    File(FileWrapper),
    /// An entry of an archive, possibly the one being written: reading the version
    /// opened before the write is what renaming relies on.
    Archive(Arc<ZipReader>, ZipEntry),
}

impl EntrySource {
    async fn stream(&self, sink: &mut dyn ByteSink) -> Result<()> {
        match self {
            EntrySource::Bytes(b) => sink.accept(b).await,
            EntrySource::Local(path) => {
                use std::io::Read;
                let mut f = std::fs::File::open(path).map_err(|e| Error::Protocol(format!("open {}: {e}", path.display())))?;
                let mut buf = vec![0u8; PIECE];
                loop {
                    let n = f.read(&mut buf).map_err(|e| Error::Protocol(format!("read {}: {e}", path.display())))?;
                    if n == 0 {
                        return Ok(());
                    }
                    sink.accept(&buf[..n]).await?;
                }
            }
            EntrySource::File(file) => {
                let size = file.size();
                let mut at = 0;
                while at < size {
                    let piece = file.read_section(at, PIECE as u64).await?;
                    if piece.is_empty() {
                        break;
                    }
                    at += piece.len() as u64;
                    sink.accept(&piece).await?;
                }
                Ok(())
            }
            EntrySource::Archive(zip, entry) => zip.read_to(entry, sink).await,
        }
    }
}

/// A file to add to an archive, or a directory to record in it.
#[derive(Clone)]
pub struct NewEntry {
    pub path: String,
    pub size: u64,
    /// Milliseconds since the epoch, in the local time the archive should show.
    pub modified_millis: i64,
    pub source: EntrySource,
    pub is_directory: bool,
}

impl NewEntry {
    pub fn file(path: &str, size: u64, modified_millis: i64, source: EntrySource) -> Result<NewEntry> {
        Ok(NewEntry {
            path: normalise_path(path).ok_or_else(|| Error::Protocol(format!("Invalid path in an archive: {path}")))?,
            size,
            modified_millis,
            source,
            is_directory: false,
        })
    }

    /// A directory only needs a record of its own when nothing implies it, which
    /// means an empty one: every other directory is implied by the files under it.
    pub fn directory(path: &str, modified_millis: i64) -> Result<NewEntry> {
        Ok(NewEntry {
            path: normalise_path(path).ok_or_else(|| Error::Protocol(format!("Invalid path in an archive: {path}")))?,
            size: 0,
            modified_millis,
            source: EntrySource::Bytes(Arc::new(Vec::new())),
            is_directory: true,
        })
    }

    /// An entry taken from a file in the drive.
    pub fn from_file(path: &str, file: &FileWrapper) -> Result<NewEntry> {
        let props = file.properties();
        let millis = props.modified_epoch * 1000;
        if props.is_directory {
            return NewEntry::directory(path, millis);
        }
        NewEntry::file(path, props.size, millis, EntrySource::File(file.clone()))
    }

    /// An entry taken from an archive, this one or another. The bytes are inflated
    /// and compressed again, however this archive would compress them.
    pub fn from_archive(path: &str, source: &Arc<ZipReader>, entry: &ZipEntry) -> Result<NewEntry> {
        if entry.is_directory {
            return NewEntry::directory(path, entry.modified_millis);
        }
        NewEntry::file(path, entry.size, entry.modified_millis, EntrySource::Archive(source.clone(), entry.clone()))
    }

    /// A directory ends in a slash in an archive, which is the only thing that says so.
    fn name_bytes(&self) -> Vec<u8> {
        if self.is_directory { format!("{}/", self.path) } else { self.path.clone() }.into_bytes()
    }
}

struct Measured {
    entry: NewEntry,
    crc: u32,
    compressed_size: u64,
    method: u16,
}

/// Raw deflate in front of another sink, keeping the CRC and size of its input.
struct Deflater<'a> {
    compress: Compress,
    buf: Vec<u8>,
    crc: crc32fast::Hasher,
    total: u64,
    out: &'a mut dyn ByteSink,
}

impl<'a> Deflater<'a> {
    fn new(out: &'a mut dyn ByteSink) -> Deflater<'a> {
        Deflater { compress: Compress::new(Compression::default(), false), buf: vec![0u8; 256 * 1024], crc: crc32fast::Hasher::new(), total: 0, out }
    }

    /// Flush what the compressor still holds; returns the input's CRC and size.
    async fn finish(mut self) -> Result<(u32, u64)> {
        loop {
            let bo = self.compress.total_out();
            let status = self
                .compress
                .compress(&[], &mut self.buf, FlushCompress::Finish)
                .map_err(|e| Error::Protocol(format!("deflate: {e}")))?;
            let made = (self.compress.total_out() - bo) as usize;
            self.out.accept(&self.buf[..made]).await?;
            if status == Status::StreamEnd {
                return Ok((self.crc.finalize(), self.total));
            }
        }
    }
}

#[async_trait(?Send)]
impl ByteSink for Deflater<'_> {
    async fn accept(&mut self, input: &[u8]) -> Result<()> {
        self.crc.update(input);
        self.total += input.len() as u64;
        let mut consumed = 0;
        while consumed < input.len() {
            let (bi, bo) = (self.compress.total_in(), self.compress.total_out());
            self.compress
                .compress(&input[consumed..], &mut self.buf, FlushCompress::None)
                .map_err(|e| Error::Protocol(format!("deflate: {e}")))?;
            consumed += (self.compress.total_in() - bi) as usize;
            let made = (self.compress.total_out() - bo) as usize;
            self.out.accept(&self.buf[..made]).await?;
        }
        Ok(())
    }
}

/// Compress an entry once to learn how big it becomes and its CRC: its header
/// precedes its data and has to say both.
async fn measure(entry: NewEntry) -> Result<Measured> {
    if entry.is_directory {
        return Ok(Measured { entry, crc: 0, compressed_size: 0, method: STORED });
    }
    let mut counted = CountingSink(0);
    let mut deflater = Deflater::new(&mut counted);
    entry.source.stream(&mut deflater).await?;
    let (crc, size) = deflater.finish().await?;
    let compressed = counted.0;
    if size != entry.size {
        return Err(Error::Protocol(format!("{} is {size} bytes, not the {} expected", entry.path, entry.size)));
    }
    // deflate makes some things bigger, and the format lets us just store those
    Ok(if compressed < entry.size {
        Measured { entry, crc, compressed_size: compressed, method: DEFLATED }
    } else {
        let size = entry.size;
        Measured { entry, crc, compressed_size: size, method: STORED }
    })
}

fn local_header(m: &Measured) -> Vec<u8> {
    let name = m.entry.name_bytes();
    let zip64 = m.entry.size > U32_MAX || m.compressed_size > U32_MAX;
    let extra = if zip64 { 20 } else { 0 };
    let mut h = vec![0u8; LOCAL_HEADER_SIZE + name.len() + extra];
    let (time, date) = millis_to_dos_time(m.entry.modified_millis);
    put_u32(&mut h, 0, LOCAL_HEADER_SIG as u64);
    put_u16(&mut h, 4, if zip64 { 45 } else { 20 });
    put_u16(&mut h, 6, FLAG_UTF8_NAMES as u64);
    put_u16(&mut h, 8, m.method as u64);
    put_u16(&mut h, 10, time);
    put_u16(&mut h, 12, date);
    put_u32(&mut h, 14, m.crc as u64);
    put_u32(&mut h, 18, if zip64 { U32_MAX } else { m.compressed_size });
    put_u32(&mut h, 22, if zip64 { U32_MAX } else { m.entry.size });
    put_u16(&mut h, 26, name.len() as u64);
    put_u16(&mut h, 28, extra as u64);
    h[LOCAL_HEADER_SIZE..LOCAL_HEADER_SIZE + name.len()].copy_from_slice(&name);
    if zip64 {
        let at = LOCAL_HEADER_SIZE + name.len();
        put_u16(&mut h, at, ZIP64_EXTRA_ID as u64);
        put_u16(&mut h, at + 2, 16);
        put_u64(&mut h, at + 4, m.entry.size);
        put_u64(&mut h, at + 12, m.compressed_size);
    }
    h
}

fn central_record(m: &Measured, local_header_offset: u64) -> Vec<u8> {
    let name = m.entry.name_bytes();
    let big_sizes = m.entry.size > U32_MAX || m.compressed_size > U32_MAX;
    let big_offset = local_header_offset > U32_MAX;
    let extra = if big_sizes || big_offset { 4 + if big_sizes { 16 } else { 0 } + if big_offset { 8 } else { 0 } } else { 0 };
    let mut r = vec![0u8; CENTRAL_HEADER_SIZE + name.len() + extra];
    let (time, date) = millis_to_dos_time(m.entry.modified_millis);
    put_u32(&mut r, 0, CENTRAL_HEADER_SIG as u64);
    put_u16(&mut r, 4, 0x031E); // unix, version 3.0
    put_u16(&mut r, 6, if big_sizes || big_offset { 45 } else { 20 });
    put_u16(&mut r, 8, FLAG_UTF8_NAMES as u64);
    put_u16(&mut r, 10, m.method as u64);
    put_u16(&mut r, 12, time);
    put_u16(&mut r, 14, date);
    put_u32(&mut r, 16, m.crc as u64);
    put_u32(&mut r, 20, if big_sizes { U32_MAX } else { m.compressed_size });
    put_u32(&mut r, 24, if big_sizes { U32_MAX } else { m.entry.size });
    put_u16(&mut r, 28, name.len() as u64);
    put_u16(&mut r, 30, extra as u64);
    // 0755 and the ms-dos directory bit, or 0644 for a regular file
    put_u32(&mut r, 38, if m.entry.is_directory { 0x41ED_0010 } else { 0x81A4_0000 });
    put_u32(&mut r, 42, if big_offset { U32_MAX } else { local_header_offset });
    r[CENTRAL_HEADER_SIZE..CENTRAL_HEADER_SIZE + name.len()].copy_from_slice(&name);
    if extra > 0 {
        let at = CENTRAL_HEADER_SIZE + name.len();
        put_u16(&mut r, at, ZIP64_EXTRA_ID as u64);
        put_u16(&mut r, at + 2, (extra - 4) as u64);
        let mut v = at + 4;
        if big_sizes {
            put_u64(&mut r, v, m.entry.size);
            put_u64(&mut r, v + 8, m.compressed_size);
            v += 16;
        }
        if big_offset {
            put_u64(&mut r, v, local_header_offset);
        }
    }
    r
}

/// The end of central directory record, with the zip64 pair in front of it when the
/// archive has outgrown what the original fields can say.
fn end_records(entries: u64, dir_size: u64, dir_offset: u64, end_position: u64) -> Vec<u8> {
    let zip64 = entries > U16_MAX || dir_size > U32_MAX || dir_offset > U32_MAX;
    let mut res = vec![0u8; if zip64 { ZIP64_EOCD_SIZE + ZIP64_LOCATOR_SIZE } else { 0 } + EOCD_SIZE];
    let mut at = 0;
    if zip64 {
        put_u32(&mut res, 0, ZIP64_EOCD_SIG as u64);
        put_u64(&mut res, 4, (ZIP64_EOCD_SIZE - 12) as u64);
        put_u16(&mut res, 12, 0x031E);
        put_u16(&mut res, 14, 45);
        put_u64(&mut res, 24, entries);
        put_u64(&mut res, 32, entries);
        put_u64(&mut res, 40, dir_size);
        put_u64(&mut res, 48, dir_offset);
        at = ZIP64_EOCD_SIZE;
        put_u32(&mut res, at, ZIP64_LOCATOR_SIG as u64);
        put_u64(&mut res, at + 8, end_position);
        put_u32(&mut res, at + 16, 1);
        at += ZIP64_LOCATOR_SIZE;
    }
    put_u32(&mut res, at, EOCD_SIG as u64);
    put_u16(&mut res, at + 8, if zip64 { U16_MAX } else { entries });
    put_u16(&mut res, at + 10, if zip64 { U16_MAX } else { entries });
    put_u32(&mut res, at + 12, if zip64 { U32_MAX } else { dir_size });
    put_u32(&mut res, at + 16, if zip64 { U32_MAX } else { dir_offset });
    res
}

/// Writes a run of bytes into a file from `pos` on, in as few requests as memory
/// allows: a tail that fits in one buffer lands in one write, atomically.
struct TailWriter<'a> {
    file: &'a FileWrapper,
    pos: u64,
    buf: Vec<u8>,
}

#[async_trait(?Send)]
impl ByteSink for TailWriter<'_> {
    async fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() >= TAIL_BUFFER {
            self.flush().await?;
        }
        Ok(())
    }
}

impl TailWriter<'_> {
    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    async fn flush(&mut self) -> Result<()> {
        if !self.buf.is_empty() {
            self.file.write_section(self.pos, &self.buf).await?;
            self.pos += self.buf.len() as u64;
            self.buf.clear();
        }
        Ok(())
    }

    fn position(&self) -> u64 {
        self.pos + self.buf.len() as u64
    }
}

struct CentralDirectory {
    bytes: Vec<u8>,
    /// (offset, length, normalised path) of each record.
    records: Vec<(usize, usize, String)>,
}

async fn read_directory(zip: &ZipReader) -> Result<CentralDirectory> {
    let bytes = read_exact(&zip.file, zip.cd.start, zip.cd.size as usize).await?;
    let mut records = Vec::new();
    for (offset, len) in self::records(&bytes) {
        let flags = u16_at(&bytes, offset + 8) as u16;
        let name_len = u16_at(&bytes, offset + 28) as usize;
        let name = decode_name(&bytes[offset + CENTRAL_HEADER_SIZE..offset + CENTRAL_HEADER_SIZE + name_len], flags & FLAG_UTF8_NAMES != 0)?;
        records.push((offset, len, normalise_path(&name).unwrap_or_default()));
    }
    Ok(CentralDirectory { bytes, records })
}

/// Rewrite the archive from its central directory on: the new entries, then the
/// directory keeping `kept` records and adding theirs, then the end records.
async fn write_tail(
    archive: &FileWrapper,
    zip: &ZipReader,
    directory: &CentralDirectory,
    kept: &[(usize, usize, String)],
    added: Vec<Measured>,
) -> Result<()> {
    if !archive.is_writable() {
        return Err(Error::Protocol("Cannot change an archive you can only read".into()));
    }
    let delta = zip.cd.delta;
    let mut w = TailWriter { file: archive, pos: zip.cd.start, buf: Vec::new() };
    let mut new_records = Vec::with_capacity(added.len());
    for m in &added {
        let at = w.position();
        new_records.push(central_record(m, (at as i64 - delta) as u64));
        w.push(&local_header(m));
        if m.entry.is_directory {
            continue;
        }
        let data_start = w.position();
        if m.method == STORED {
            m.entry.source.stream(&mut w).await?;
        } else {
            let mut deflater = Deflater::new(&mut w);
            m.entry.source.stream(&mut deflater).await?;
            deflater.finish().await?;
        }
        if w.position() - data_start != m.compressed_size {
            return Err(Error::Protocol(format!("{} changed while it was being added", m.entry.path)));
        }
    }
    let dir_start = w.position();
    let mut new_dir = Vec::new();
    for (offset, len, _) in kept {
        new_dir.extend_from_slice(&directory.bytes[*offset..offset + len]);
    }
    for r in &new_records {
        new_dir.extend_from_slice(r);
    }
    let dir_len = new_dir.len() as u64;
    w.push(&new_dir);
    let end = dir_start + dir_len;
    let eocd = end_records((kept.len() + new_records.len()) as u64, dir_len, (dir_start as i64 - delta) as u64, end);
    w.push(&eocd);
    let end = end + eocd.len() as u64;
    w.flush().await?;
    archive.truncate(end).await
}

/// Add files to an archive, or replace ones already in it, in one rewrite of its tail.
pub async fn append(archive: &FileWrapper, entries: Vec<NewEntry>) -> Result<()> {
    let zip = ZipReader::open(archive).await?;
    let directory = read_directory(&zip).await?;
    let replaced: HashSet<String> = entries.iter().map(|e| e.path.clone()).collect();
    let mut measured = Vec::with_capacity(entries.len());
    for e in entries {
        measured.push(measure(e).await?);
    }
    let kept: Vec<_> = directory.records.iter().filter(|(_, _, p)| !replaced.contains(p)).cloned().collect();
    write_tail(archive, &zip, &directory, &kept, measured).await
}

/// The entries `paths` cover, so removing a directory removes what is under it.
fn expand(zip: &ZipReader, paths: &[String]) -> Vec<ZipEntry> {
    let mut res = Vec::new();
    for path in paths {
        let entry = match zip.index.get(path) {
            Some(e) => e.clone(),
            None => continue,
        };
        if entry.is_directory {
            let prefix = format!("{}/", entry.path);
            res.extend(zip.index.entries.iter().filter(|c| c.path.starts_with(&prefix) && !c.is_directory).cloned());
        }
        // a directory some writer recorded explicitly has a record of its own to drop
        res.push(entry);
    }
    res
}

/// Remove entries from an archive. Dropping a record is what makes the entry gone;
/// with `erase_data` the bytes it left behind are also overwritten, since a delete
/// that leaves them readable is not what anyone means by delete.
pub async fn remove(archive: &FileWrapper, paths: &[String], erase_data: bool) -> Result<()> {
    let zip = ZipReader::open(archive).await?;
    let directory = read_directory(&zip).await?;
    let removed = expand(&zip, paths);
    if removed.is_empty() {
        return Err(Error::Protocol(format!("No such entry in the archive: {paths:?}")));
    }
    let gone: HashSet<&str> = removed.iter().map(|e| e.path.as_str()).collect();
    let kept: Vec<_> = directory.records.iter().filter(|(_, _, p)| !gone.contains(p.as_str())).cloned().collect();
    // drop the records first: a crash after this leaves a valid archive that no longer
    // mentions the entry, rather than one whose directory points at erased bytes
    write_tail(archive, &zip, &directory, &kept, Vec::new()).await?;
    if erase_data {
        for e in removed.iter().filter(|e| !e.is_directory && e.local_header_offset >= 0) {
            erase(archive, &zip, e).await?;
        }
    }
    Ok(())
}

/// Overwrite an entry's local header and data with zeros.
async fn erase(archive: &FileWrapper, zip: &ZipReader, entry: &ZipEntry) -> Result<()> {
    let start = entry.local_header_offset as u64;
    let header = read_exact(&zip.file, start, LOCAL_HEADER_SIZE).await?;
    if u32_at(&header, 0) as u32 != LOCAL_HEADER_SIG {
        return Ok(());
    }
    let len = LOCAL_HEADER_SIZE as u64 + u16_at(&header, 26) + u16_at(&header, 28) + entry.compressed_size;
    let mut at = start;
    let end = start + len;
    while at < end {
        let n = (end - at).min(TAIL_BUFFER as u64);
        archive.write_section(at, &vec![0u8; n as usize]).await?;
        at += n;
    }
    Ok(())
}

/// Rename an entry, or a directory of them, keeping it where it is in the tree.
pub async fn rename(archive: &FileWrapper, path: &str, new_name: &str) -> Result<()> {
    if new_name.is_empty() || new_name.contains('/') || new_name == "." || new_name == ".." {
        return Err(Error::Protocol(format!("Invalid name: {new_name}")));
    }
    let zip = ZipReader::open(archive).await?;
    let entry = zip.index.get(path).ok_or_else(|| Error::Protocol(format!("No such entry in the archive: {path}")))?;
    let parent = entry.parent_path();
    let target = if parent.is_empty() { new_name.to_string() } else { format!("{parent}/{new_name}") };
    move_entry(archive, path, &target).await
}

/// Move an entry, or a directory of them, to another path within the same archive.
/// A name of the same length is patched where it stands, which is two small writes
/// whatever the entry weighs; otherwise the entry is written again under the new
/// name and the old one removed.
pub async fn move_entry(archive: &FileWrapper, path: &str, new_path: &str) -> Result<()> {
    let renamed = match normalise_path(new_path) {
        Some(p) if !p.is_empty() => p,
        _ => return Err(Error::Protocol(format!("Invalid path in an archive: {new_path}"))),
    };
    let zip = Arc::new(ZipReader::open(archive).await?);
    let entry = zip.index.get(path).ok_or_else(|| Error::Protocol(format!("No such entry in the archive: {path}")))?.clone();
    if zip.index.get(&renamed).is_some() {
        return Err(Error::Protocol(format!("Already in the archive: {renamed}")));
    }
    if entry.is_directory {
        let prefix = format!("{}/", entry.path);
        let children: Vec<ZipEntry> =
            zip.index.entries.iter().filter(|c| c.path.starts_with(&prefix) && !c.is_directory).cloned().collect();
        if children.is_empty() {
            return Err(Error::Protocol(format!("Nothing to rename in {}", entry.path)));
        }
        let mut moved = Vec::with_capacity(children.len());
        let mut old = Vec::with_capacity(children.len() + 1);
        for c in &children {
            moved.push(NewEntry::from_archive(&format!("{renamed}/{}", &c.path[prefix.len()..]), &zip, c)?);
            old.push(c.path.clone());
        }
        old.push(entry.path.clone());
        append(archive, moved).await?;
        return remove(archive, &old, true).await;
    }
    if entry.path.len() == renamed.len() && entry.local_header_offset >= 0 {
        return rename_in_place(archive, &zip, &entry, &renamed).await;
    }
    append(archive, vec![NewEntry::from_archive(&renamed, &zip, &entry)?]).await?;
    remove(archive, &[entry.path.clone()], true).await
}

async fn rename_in_place(archive: &FileWrapper, zip: &ZipReader, entry: &ZipEntry, renamed: &str) -> Result<()> {
    let name = renamed.as_bytes();
    let mut directory = read_directory(zip).await?;
    let (offset, _, _) = directory
        .records
        .iter()
        .find(|(_, _, p)| p == &entry.path)
        .cloned()
        .ok_or_else(|| Error::Protocol(format!("No such entry in the archive: {}", entry.path)))?;
    // the name lives in two places, and a reader is entitled to look at either
    directory.bytes[offset + CENTRAL_HEADER_SIZE..offset + CENTRAL_HEADER_SIZE + name.len()].copy_from_slice(name);
    archive.write_section(entry.local_header_offset as u64 + LOCAL_HEADER_SIZE as u64, name).await?;
    let records = directory.records.clone();
    write_tail(archive, zip, &directory, &records, Vec::new()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_normalised_and_escapes_rejected() {
        assert_eq!(normalise_path("/a/./b/").as_deref(), Some("a/b"));
        assert_eq!(normalise_path("C:\\dir\\f.txt").as_deref(), Some("dir/f.txt"));
        assert_eq!(normalise_path("a/../b"), None);
    }

    #[test]
    fn dos_times_round_trip() {
        let millis = days_from_civil(2026, 9, 25) * 86_400_000 + (13 * 3600 + 14 * 60 + 16) * 1000;
        let (t, d) = millis_to_dos_time(millis);
        assert_eq!(dos_time_to_millis(t, d), millis);
        assert_eq!(millis_to_dos_time(0), (0, 0x21), "before 1980 clamps to its start");
    }

    #[test]
    fn cp437_table_is_complete() {
        assert_eq!(CP437_HIGH.chars().count(), 128);
    }

    #[test]
    fn cp437_names_decode() {
        assert_eq!(decode_name(&[b'a', 0x81, 0xE1], false).unwrap(), "aüß");
    }
}
