use std::fmt;

/// Errors from the networking / storage layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Transport / IO failure talking to the server.
    Http(String),
    /// Server returned a rate-limit / overloaded status (429/502/503/504).
    RateLimited,
    /// Storage quota reached.
    QuotaExceeded(String),
    /// A malformed or unexpected server response.
    Protocol(String),
    /// CBOR decode error.
    Cbor(String),
    /// Multiformat (CID/multihash) error.
    Multiformat(String),
    /// Crypto error (signing, hashing, …).
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Http(s) => write!(f, "http error: {s}"),
            Error::RateLimited => write!(f, "rate limited"),
            Error::QuotaExceeded(s) => write!(f, "storage quota exceeded: {s}"),
            Error::Protocol(s) => write!(f, "protocol error: {s}"),
            Error::Cbor(s) => write!(f, "cbor error: {s}"),
            Error::Multiformat(s) => write!(f, "multiformat error: {s}"),
            Error::Crypto(s) => write!(f, "crypto error: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<peergos_cbor::CborError> for Error {
    fn from(e: peergos_cbor::CborError) -> Self {
        Error::Cbor(e.0)
    }
}
impl From<peergos_multiformats::MfError> for Error {
    fn from(e: peergos_multiformats::MfError) -> Self {
        Error::Multiformat(e.0)
    }
}
impl From<peergos_crypto::CryptoError> for Error {
    fn from(e: peergos_crypto::CryptoError) -> Self {
        Error::Crypto(e.0)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
