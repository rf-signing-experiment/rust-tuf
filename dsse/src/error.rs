//! Error types and converters.

use thiserror::Error;

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for all DSSE related errors.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    /// A value was not encoded the way this crate expects it to be.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
}
