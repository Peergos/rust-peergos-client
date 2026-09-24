use peergos_cbor::CborObject;
use peergos_core::error::Result;

/// Per-file sync metadata, matching Java's `FileState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileState {
    /// Relative path from the sync root (forward-slash-separated).
    pub rel_path: String,
    /// Last modification time in milliseconds (truncated to seconds).
    pub modification_time: i64,
    /// File size in bytes.
    pub size: u64,
    /// Root of the file's content hash tree, built at `chunk_size`.
    pub hash: [u8; 32],
    /// The chunk size, and so the scheme, the hash was built with. A local file must
    /// be hashed the way the file it is compared against was hashed, and a local file
    /// has no properties of its own, so the last synced state is where it is kept.
    pub chunk_size: u64,
}

impl FileState {
    pub fn new(rel_path: String, modification_time: i64, size: u64, hash: [u8; 32]) -> Self {
        FileState { rel_path, modification_time, size, hash, chunk_size: peergos_fs::LEGACY_CHUNK_SIZE }
    }

    pub fn with_chunk_size(mut self, chunk_size: u64) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    pub fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map()
            .put("r", CborObject::Str(self.rel_path.clone()))
            .put("m", CborObject::Long(self.modification_time))
            .put("s", CborObject::Long(self.size as i64))
            .put("h", CborObject::ByteString(self.hash.to_vec()));
        // absent means the legacy size, so every state written before this stays readable
        if self.chunk_size != peergos_fs::LEGACY_CHUNK_SIZE {
            b = b.put("cs", CborObject::Long(self.chunk_size.trailing_zeros() as i64));
        }
        b.build()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<Self> {
        Ok(FileState {
            rel_path: cbor.get("r").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            modification_time: cbor.get("m").and_then(|c| c.as_long()).unwrap_or(0),
            size: cbor.get("s").and_then(|c| c.as_long()).unwrap_or(0) as u64,
            hash: {
                let b = cbor.get("h").and_then(|c| c.as_bytes()).unwrap_or(&[]);
                let mut h = [0u8; 32];
                let len = b.len().min(32);
                h[..len].copy_from_slice(&b[..len]);
                h
            },
            chunk_size: match cbor.get("cs").and_then(|c| c.as_long()) {
                Some(log2) => peergos_fs::retrieve::chunk_size_from_log2(log2)?,
                None => peergos_fs::LEGACY_CHUNK_SIZE,
            },
        })
    }
}

impl FileState {
    /// Compare ignoring modification time (check only rel_path, size, hash).
    pub fn equals_ignore_modtime(&self, other: &FileState) -> bool {
        self.rel_path == other.rel_path && self.size == other.size && self.hash == other.hash
    }
}

impl std::fmt::Display for FileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, size: {}, modTime: {}]", self.rel_path, self.size, self.modification_time)
    }
}
