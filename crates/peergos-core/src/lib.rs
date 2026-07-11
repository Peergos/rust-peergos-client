//! Networking & storage core for the Peergos client: the HTTP transport
//! ([`poster`]), the content-addressed block store ([`storage`]) and the
//! signing-key data model ([`keys`]).
//!
//! Ported from `peergos.shared.storage` / `peergos.shared.crypto`. This is the
//! direct-to-Peergos-server path; BAT auth, direct-S3, champ lookups, caching
//! and proxying are later increments (see plan.md Phase 2).

pub mod auth;
pub mod boxing;
pub mod buffered;
pub mod cached;
pub mod champ;
pub mod champ_merge;
pub mod direct_s3;
pub mod error;
pub mod keys;
pub mod mutable;
pub mod poster;
pub mod ram;
pub mod storage;
pub mod symmetric;

pub use auth::{Bat, BatId, BatWithId, BlockAuth};
pub use boxing::{BoxingKeyPair, PublicBoxingKey, SecretBoxingKey};
pub use buffered::{BufferedNetwork, BufferedPointers, BufferedStorage};
pub use champ::{identity_key_hasher, Champ, ChampWrapper, KeyElement, Payload};
pub use direct_s3::{hash_to_key, BlockStoreProperties, DirectS3Storage, PresignedUrl};
pub use symmetric::{CipherText, SymmetricKey};
pub use error::{Error, Result};
pub use keys::{
    OwnerProof, PublicKeyHash, PublicSigningKey, SecretSigningKey, SigningKeyPair,
    SigningPrivateKeyAndPublicHash,
};
pub use mutable::{
    HttpMutablePointers, MultiWriterCommit, MutablePointers, PointerUpdate, SignedPointerUpdate,
};
pub use poster::{HttpPoster, ReqwestPoster};
pub use cached::{CachedMutablePointers, CachedStorage};
pub use ram::RamStorage;
pub use storage::{
    build_cid, champ_lookup_local, get_signing_key, hash_to_cid, put_block_signed, sign_block,
    BlockWriteGroup, ChunkMirrorCap, ContentAddressedStorage, FallbackStorage, HttpStorage,
    TransactionId, MAX_CHAMP_GETS,
};

#[cfg(test)]
mod tests;
