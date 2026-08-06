use {
    serde::de::DeserializeOwned,
    serde::ser::Serialize,
    tuf::{
        Result,
        crypto::{KeyType, PublicKey, Signature, SignatureScheme},
        pouf::{Pouf, Pouf1, SignedDocument},
    },
};

/// Pretty JSON data pouf.
///
/// This is identical to [tuf::pouf::Pouf1] in all manners except for the `signing_input` method.
/// Instead of writing the metadata in the canonical format, it first canonicalizes it, then pretty
/// prints the metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPretty;

impl Pouf for JsonPretty {
    type RawData = serde_json::Value;

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use tuf::pouf::Pouf;
    /// #
    /// assert_eq!(JsonPretty::extension(), "json");
    /// ```
    fn extension() -> &'static str {
        Pouf1::extension()
    }

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use serde_json::json;
    /// # use tuf::pouf::Pouf;
    /// #
    /// let json = json!({
    ///     "o": {
    ///         "a": [1, 2, 3],
    ///         "s": "string",
    ///         "n": 123,
    ///         "t": true,
    ///         "f": false,
    ///         "0": null,
    ///     },
    /// });
    ///
    /// let bytes = JsonPretty::signing_input(&json).unwrap();
    ///
    /// assert_eq!(&String::from_utf8(bytes).unwrap(), r#"{
    ///   "o": {
    ///     "0": null,
    ///     "a": [
    ///       1,
    ///       2,
    ///       3
    ///     ],
    ///     "f": false,
    ///     "n": 123,
    ///     "s": "string",
    ///     "t": true
    ///   }
    /// }"#);
    /// ```
    fn signing_input(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        let bytes = Pouf1::signing_input(raw_data)?;
        let value: Self::RawData = serde_json::from_slice(&bytes)?;

        Ok(serde_json::to_vec_pretty(&value)?)
    }

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use serde::Deserialize;
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # use tuf::pouf::Pouf;
    /// #
    /// #[derive(Deserialize, Debug, PartialEq)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let de: Thing = JsonPretty::from_raw_data(&jsn).unwrap();
    /// assert_eq!(de, thing);
    /// ```
    fn from_raw_data<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Pouf1::from_raw_data(raw_data)
    }

    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use serde::Serialize;
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # use tuf::pouf::Pouf;
    /// #
    /// #[derive(Serialize)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let se: serde_json::Value = JsonPretty::to_raw_data(&thing).unwrap();
    /// assert_eq!(se, jsn);
    /// ```
    fn to_raw_data<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Pouf1::to_raw_data(data)
    }

    /// Write the document out pretty printed, which is the whole point of this pouf.
    ///
    /// ```
    /// # use interop_tests::JsonPretty;
    /// # use serde_json::json;
    /// # use tuf::pouf::Pouf;
    /// #
    /// let bytes = JsonPretty::serialize_signed(&[], &json!({"b": 1, "a": 2})).unwrap();
    ///
    /// assert_eq!(&String::from_utf8(bytes).unwrap(), "{\n  \"signatures\": [],\n  \"signed\": {\n    \"a\": 2,\n    \"b\": 1\n  }\n}");
    /// ```
    fn serialize_signed(signatures: &[Signature], raw_data: &Self::RawData) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(&SignedDocument {
            signatures,
            signed: raw_data,
        })?)
    }

    fn deserialize_signed(slice: &[u8]) -> Result<(Vec<Signature>, Self::RawData)> {
        Pouf1::deserialize_signed(slice)
    }

    fn encode_public_key(public_key: &PublicKey) -> Result<String> {
        Pouf1::encode_public_key(public_key)
    }

    fn decode_public_key(
        key_type: KeyType,
        scheme: SignatureScheme,
        public: &str,
    ) -> Result<PublicKey> {
        Pouf1::decode_public_key(key_type, scheme, public)
    }
}
