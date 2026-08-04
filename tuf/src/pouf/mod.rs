//! Structures and functions to aid in various TUF data pouf formats.

pub(crate) mod pouf1;
pub(crate) mod pouf2;
pub(crate) mod shims;
pub use pouf1::Pouf1;
pub use pouf2::{PAYLOAD_TYPE, Payload, Pouf2};

use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::Result;
use crate::crypto::{KeyType, PublicKey, Signature, SignatureScheme};

/// The `{"signatures": ..., "signed": ...}` document that the JSON poufs write.
#[derive(serde::Serialize)]
pub struct SignedDocument<'a, R: Serialize> {
    /// The signatures over the signing input of `signed`.
    pub signatures: &'a [Signature],

    /// The signed portion of the metadata.
    pub signed: &'a R,
}

/// The `{"signatures": ..., "signed": ...}` document that the JSON poufs read.
#[derive(serde::Deserialize)]
pub struct SignedDocumentOwned<R> {
    /// The signatures over the signing input of `signed`.
    pub signatures: Vec<Signature>,

    /// The signed portion of the metadata.
    pub signed: R,
}

/// The format used for data interchange, serialization, and deserialization.
///
/// A Pouf answers three separate questions:
///
/// * How the signed portion is read and written ([`RawData`]
/// * How the signed portion is converted to bytes for signing ([`signing_input`])
/// * How the whole document (data + signatures) is read and written ([`serialize_signed`] and
///   [`deserialize_signed`]).
///
/// [`RawData`]: Pouf::RawData
/// [`signing_input`]: Pouf::signing_input
/// [`serialize_signed`]: Pouf::serialize_signed
/// [`deserialize_signed`]: Pouf::deserialize_signed
pub trait Pouf: Sized + Sync {
    /// The type of data that is contained in the `signed` portion of metadata.
    type RawData: PartialEq;

    /// The data pouf's extension.
    fn extension() -> &'static str;

    /// Turns the signed portion of metadata into the byte string that signatures
    /// are computed over. Must be deterministic.
    fn signing_input(raw_data: &Self::RawData) -> Result<Vec<u8>>;

    /// Convert metadata to the signed portion of a document.
    fn to_raw_data<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize;

    /// Read metadata from the signed portion of a document.
    fn from_raw_data<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned;

    /// Encode a public key as a string.
    fn encode_public_key(public_key: &PublicKey) -> Result<String>;

    /// Read back a public key this pouf wrote.
    ///
    /// `public` is the value [`encode_public_key`](Pouf::encode_public_key) produced, and
    /// `key_type` and `scheme` are the ones the metadata listed alongside it.
    fn decode_public_key(
        key_type: KeyType,
        scheme: SignatureScheme,
        public: &str,
    ) -> Result<PublicKey>;

    /// Write signed metadata out in the pouf's wire format.
    ///
    /// This is the format metadata is stored and transported in. It includes both the raw data
    /// and the signatures over it.
    fn serialize_signed(signatures: &[Signature], raw_data: &Self::RawData) -> Result<Vec<u8>>;

    /// Read signed metadata from the pouf's wire format, returning the signatures and the signed
    /// portion of the metadata.
    ///
    /// **WARNING**: This does not verify the signatures.
    fn deserialize_signed(slice: &[u8]) -> Result<(Vec<Signature>, Self::RawData)>;
}
