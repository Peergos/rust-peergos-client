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
    /// BLAKE2b-256 hash of the file content.
    pub hash: [u8; 32],
}

impl FileState {
    pub fn new(rel_path: String, modification_time: i64, size: u64, hash: [u8; 32]) -> Self {
        FileState { rel_path, modification_time, size, hash }
    }

    pub fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("r", CborObject::Str(self.rel_path.clone()))
            .put("m", CborObject::Long(self.modification_time))
            .put("s", CborObject::Long(self.size as i64))
            .put("h", CborObject::ByteString(self.hash.to_vec()))
            .build()
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
