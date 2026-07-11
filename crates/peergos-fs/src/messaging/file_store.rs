//! `FileBackedMessageStore` — a [`MessageStore`] backed by the chat's shared
//! append-only log file, ported from
//! `peergos.shared.messaging.FileBackedMessageStore`.
//!
//! The log lives at `<chatRoot>/shared/peergos-chat-messages.cborstream`: a
//! concatenation of serialized [`SignedMessage`]s. A companion
//! `peergos-chat-messages.index.bin` maps message index → byte offset at every
//! 5 MiB ([`crate::CHUNK_MAX_SIZE`]) chunk boundary, so a large log can be seeked
//! close to a target message without scanning it from the start. Each index entry
//! is two big-endian `i64`s (`msgIndex`, `byteOffset`); the file starts life as a
//! single zero entry `(0, 0)`.

use super::envelope::SignedMessage;
use super::store::MessageStore;
use crate::context::UserContext;
use crate::filewrapper::FileWrapper;
use crate::CHUNK_MAX_SIZE;
use async_trait::async_trait;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use std::collections::BTreeSet;

pub(crate) const SHARED_MSG_LOG: &str = "peergos-chat-messages.cborstream";
pub(crate) const SHARED_MSG_LOG_INDEX: &str = "peergos-chat-messages.index.bin";

pub struct FileBackedMessageStore {
    context: UserContext,
    /// Absolute path to the chat's `shared` directory (e.g.
    /// `/alice/.messaging/<uid>/shared`).
    shared_dir: String,
    /// Absolute path to the chat root (`shared`'s parent), for access revocation.
    chat_root: String,
}

impl FileBackedMessageStore {
    pub fn new(context: UserContext, shared_dir: String, chat_root: String) -> FileBackedMessageStore {
        FileBackedMessageStore { context, shared_dir, chat_root }
    }

    fn log_path(&self) -> String {
        format!("{}/{}", self.shared_dir, SHARED_MSG_LOG)
    }

    fn index_path(&self) -> String {
        format!("{}/{}", self.shared_dir, SHARED_MSG_LOG_INDEX)
    }

    async fn resolve_log(&self) -> Result<Option<FileWrapper>> {
        self.context.get_by_path(&self.log_path()).await
    }

    async fn resolve_index(&self) -> Result<Option<FileWrapper>> {
        self.context.get_by_path(&self.index_path()).await
    }

    /// The byte offset to seek to and the number of messages to skip from there to
    /// reach message `index` (`getChunkByteOffset`). Small logs (< one chunk) are
    /// scanned from the start; larger ones consult the index file.
    async fn chunk_byte_offset(&self, log_size: u64, index: i64) -> Result<(u64, usize)> {
        if index <= 0 {
            return Ok((0, 0));
        }
        if log_size < CHUNK_MAX_SIZE {
            return Ok((0, index as usize));
        }
        let idx_bytes = match self.resolve_index().await? {
            Some(f) => f.read().await?,
            None => return Ok((0, index as usize)),
        };
        let (offset, at_index) = scan_index(&idx_bytes, index);
        Ok((offset, (index - at_index) as usize))
    }

    /// Read up to `max` messages starting at message index `from`.
    async fn read_range(&self, from: i64, max: usize) -> Result<Vec<SignedMessage>> {
        let log = match self.resolve_log().await? {
            Some(f) => f,
            None => return Ok(Vec::new()),
        };
        let log_size = log.size();
        let (offset, skip) = self.chunk_byte_offset(log_size, from).await?;
        if offset >= log_size || max == 0 {
            return Ok(Vec::new());
        }
        let bytes = log.read_section(offset, log_size - offset).await?;
        parse_stream(&bytes, skip, max)
    }
}

#[async_trait(?Send)]
impl MessageStore for FileBackedMessageStore {
    async fn get_messages_from(&self, index: i64) -> Result<Vec<SignedMessage>> {
        self.read_range(index, usize::MAX).await
    }

    async fn get_messages(&self, from_index: i64, to_index: i64) -> Result<Vec<SignedMessage>> {
        if to_index <= from_index {
            return Ok(Vec::new());
        }
        self.read_range(from_index, (to_index - from_index) as usize).await
    }

    async fn add_messages(&self, msg_index: i64, msgs: Vec<SignedMessage>) -> Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        let mut sizes = Vec::with_capacity(msgs.len());
        let mut raw = Vec::new();
        for msg in &msgs {
            let bytes = msg.serialize();
            sizes.push(bytes.len());
            raw.extend_from_slice(&bytes);
        }
        let log = self
            .resolve_log()
            .await?
            .ok_or_else(|| Error::Protocol(format!("chat message log missing: {}", self.log_path())))?;
        let size_before = log.size();
        log.append(&raw).await?;

        // If this append crossed a chunk boundary, record an index entry pointing at
        // the message that crossed it (mirrors Java's single-entry-per-append).
        if let Some((entry_index, entry_offset)) = boundary_entry(size_before, &sizes, msg_index, raw.len() as u64) {
            let mut two_longs = Vec::with_capacity(16);
            two_longs.extend_from_slice(&entry_index.to_be_bytes());
            two_longs.extend_from_slice(&(entry_offset as i64).to_be_bytes());
            let idx = self
                .resolve_index()
                .await?
                .ok_or_else(|| Error::Protocol(format!("chat message index missing: {}", self.index_path())))?;
            idx.append(&two_longs).await?;
        }
        Ok(())
    }

    async fn revoke_access(&self, usernames: BTreeSet<String>) -> Result<()> {
        if usernames.is_empty() {
            return Ok(());
        }
        let user = self
            .context
            .user()
            .ok_or_else(|| Error::Protocol("cannot revoke access in a secret-link context".into()))?;
        let chat_root = self
            .context
            .get_by_path(&self.chat_root)
            .await?
            .ok_or_else(|| Error::Protocol(format!("chat root missing: {}", self.chat_root)))?;
        let revoked: Vec<String> = usernames.into_iter().collect();
        crate::unshare_read_access(
            user,
            &self.chat_root,
            chat_root.capability(),
            "shared",
            &revoked,
            self.context.store(),
            self.context.mutable().as_ref(),
        )
        .await
    }
}

/// Scan the index file for the entry with the largest `msgIndex <= index`,
/// returning its `(byteOffset, msgIndex)` (`findOffset`). Defaults to the base
/// `(0, 0)` entry.
fn scan_index(idx_bytes: &[u8], index: i64) -> (u64, i64) {
    let mut prev_index = 0i64;
    let mut prev_bytes = 0u64;
    for entry in idx_bytes.chunks_exact(16) {
        let msg_index = i64::from_be_bytes(entry[0..8].try_into().unwrap());
        let byte_offset = i64::from_be_bytes(entry[8..16].try_into().unwrap()) as u64;
        if msg_index > index {
            break;
        }
        prev_index = msg_index;
        prev_bytes = byte_offset;
    }
    (prev_bytes, prev_index)
}

/// Parse a concatenated stream of [`SignedMessage`]s, skipping the first `skip`
/// and returning at most `max`.
fn parse_stream(bytes: &[u8], skip: usize, max: usize) -> Result<Vec<SignedMessage>> {
    let mut out = Vec::new();
    let mut offset = 0;
    let mut skipped = 0;
    while offset < bytes.len() && out.len() < max {
        let (cbor, consumed) = CborObject::from_bytes_consumed(&bytes[offset..])?;
        if consumed == 0 {
            break;
        }
        offset += consumed;
        if skipped < skip {
            skipped += 1;
            continue;
        }
        out.push(SignedMessage::from_cbor(&cbor)?);
    }
    Ok(out)
}

/// If appending `appended_len` bytes crosses a [`CHUNK_MAX_SIZE`] boundary, the
/// index entry `(msgIndex, byteOffset)` to record — pointing just past the message
/// that crossed it (`addMessages`'s boundary logic).
fn boundary_entry(size_before: u64, sizes: &[usize], msg_index: i64, appended_len: u64) -> Option<(i64, u64)> {
    let crossed = |extra: u64| (size_before + extra) / CHUNK_MAX_SIZE > size_before / CHUNK_MAX_SIZE;
    if !crossed(appended_len) {
        return None;
    }
    let mut count = 0usize;
    let mut total = 0u64;
    while count < sizes.len() {
        total += sizes[count] as u64;
        count += 1;
        if crossed(total) {
            break;
        }
    }
    Some((msg_index + count as i64, size_before + total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::{ApplicationMessage, Id, Message, MessageEnvelope, TreeClock};

    fn signed(n: usize) -> SignedMessage {
        let env = MessageEnvelope::new(
            Id::creator(),
            TreeClock::init(&[Id::creator()]),
            0,
            Vec::new(),
            Message::Application(ApplicationMessage::text(format!("msg-{n}"))),
        );
        SignedMessage::new(vec![0u8; 64], env)
    }

    fn entry(bytes: &mut Vec<u8>, index: i64, offset: u64) {
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&(offset as i64).to_be_bytes());
    }

    #[test]
    fn parse_stream_skip_and_limit() {
        let mut raw = Vec::new();
        for i in 0..5 {
            raw.extend_from_slice(&signed(i).serialize());
        }
        // No skip, unbounded → all 5.
        assert_eq!(parse_stream(&raw, 0, usize::MAX).unwrap().len(), 5);
        // Skip 2, take 2 → messages 2 and 3.
        let mid = parse_stream(&raw, 2, 2).unwrap();
        assert_eq!(mid.len(), 2);
        assert_eq!(mid[0], signed(2));
        assert_eq!(mid[1], signed(3));
        // Skip all → empty.
        assert!(parse_stream(&raw, 5, usize::MAX).unwrap().is_empty());
    }

    #[test]
    fn scan_index_picks_largest_leq() {
        let mut idx = Vec::new();
        entry(&mut idx, 0, 0);
        entry(&mut idx, 100, 5_000_000);
        entry(&mut idx, 250, 10_000_000);
        // Before the first real boundary → base entry.
        assert_eq!(scan_index(&idx, 50), (0, 0));
        // Exactly on a boundary index.
        assert_eq!(scan_index(&idx, 100), (5_000_000, 100));
        // Between boundaries → the lower one.
        assert_eq!(scan_index(&idx, 200), (5_000_000, 100));
        // Past the last → the last.
        assert_eq!(scan_index(&idx, 9999), (10_000_000, 250));
    }

    #[test]
    fn boundary_entry_detects_crossing() {
        // Append that stays within the first chunk → no entry.
        assert_eq!(boundary_entry(0, &[10, 10, 10], 0, 30), None);
        // Append that crosses the 5 MiB boundary on the 2nd message.
        let big = CHUNK_MAX_SIZE as usize; // 5 MiB
        let sizes = [big - 10, 20, 30];
        let appended = (sizes.iter().sum::<usize>()) as u64;
        let (idx, off) = boundary_entry(0, &sizes, 7, appended).expect("should cross a boundary");
        // count = 2 (first message leaves us 10 bytes short, second crosses).
        assert_eq!(idx, 7 + 2);
        assert_eq!(off, (big - 10 + 20) as u64);
    }
}
