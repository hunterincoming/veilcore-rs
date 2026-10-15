//! A record that names its own key, without showing it, per specification section 3.6.1.
//!
//! The record's key (its ledger identity, `commit(recordSecret)`) is made before the record
//! is sealed. The committed fields carry `keyBinding`, and the fingerprint is built around it:
//!
//! ```text
//! identity    = H("veilcore:v1:commit",    recordSecret)
//! keySalt     = H("veilcore:v1:keysalt",   recordSecret)
//! keyBinding  = H("veilcore:v1:keybind",   identity, keySalt)
//! contentHash = SHA-256 of the canonical serialisation of the committed fields, keyBinding included
//! fingerprint = H("veilcore:v1:keyrecord", keyBinding, contentHash)
//! ```
//!
//! `H` is as in sections 3.7 and 4.5: SHA-256 over 32-byte elements, the first the tag
//! right-padded with zero bytes. Committed fields without `keyBinding` keep
//! `sha256/canonical-json/v1`: their fingerprint is `contentHash` itself, as before.
//!
//! A verifier given the fingerprint, an identity, `keySalt` and `contentHash` recomputes the
//! fingerprint; if it matches, the identity is the key the record named when it was sealed.

use crate::fields::{hash_elements, parse_hex32, Bytes32};
use crate::{canonicalise, sha256_hex, CanonicalError};
use serde_json::Value;
use std::fmt;

/// The algorithm identifier of a key-bound fingerprint.
pub const KEY_BOUND_ALGORITHM: &str = "sha256/key-bound/v1";
/// The algorithm of a fingerprint over committed fields with no `keyBinding` (unchanged).
pub const CANONICAL_JSON_ALGORITHM: &str = "sha256/canonical-json/v1";

/// The tag of the identity: the ledger contract's own `commit()`.
pub const COMMIT_TAG: &str = "veilcore:v1:commit";
/// The tag of the key's salt.
pub const KEY_SALT_TAG: &str = "veilcore:v1:keysalt";
/// The tag of the committed field `keyBinding`.
pub const KEY_BIND_TAG: &str = "veilcore:v1:keybind";
/// The tag of a key-bound fingerprint.
pub const KEY_RECORD_TAG: &str = "veilcore:v1:keyrecord";

fn tag(t: &str) -> Bytes32 {
    let mut b = [0u8; 32];
    b[..t.len()].copy_from_slice(t.as_bytes());
    b
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn read(name: &str, v: &str) -> Result<Bytes32, String> {
    parse_hex32(v).ok_or_else(|| format!("{name} must be 64 lowercase hex characters (spec 3.6.1)"))
}

/// The record's ledger identity, `H("veilcore:v1:commit", recordSecret)`.
pub fn identity_from_secret(record_secret: &str) -> Result<String, String> {
    Ok(hex(&hash_elements(&[&tag(COMMIT_TAG), &read("recordSecret", record_secret)?])))
}

/// The key's salt, `H("veilcore:v1:keysalt", recordSecret)`. Never on the record.
pub fn key_salt_of(record_secret: &str) -> Result<String, String> {
    Ok(hex(&hash_elements(&[&tag(KEY_SALT_TAG), &read("recordSecret", record_secret)?])))
}

/// The committed field, `H("veilcore:v1:keybind", identity, keySalt)`. It says nothing
/// about the identity without the salt.
pub fn key_binding_of(identity: &str, key_salt: &str) -> Result<String, String> {
    let i = read("identity", identity)?;
    let s = read("keySalt", key_salt)?;
    Ok(hex(&hash_elements(&[&tag(KEY_BIND_TAG), &i, &s])))
}

/// A key-bound fingerprint, `H("veilcore:v1:keyrecord", keyBinding, contentHash)`.
pub fn key_bound_fingerprint(key_binding: &str, content_hash: &str) -> Result<String, String> {
    let b = read("keyBinding", key_binding)?;
    let c = read("contentHash", content_hash)?;
    Ok(hex(&hash_elements(&[&tag(KEY_RECORD_TAG), &b, &c])))
}

/// Everything a record needs to name its key, from its secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFromSecret {
    pub identity: String,
    pub key_salt: String,
    pub key_binding: String,
}

/// The identity, the key's salt and the binding, from the record secret.
pub fn binding_for_secret(record_secret: &str) -> Result<KeyFromSecret, String> {
    let identity = identity_from_secret(record_secret)?;
    let key_salt = key_salt_of(record_secret)?;
    let key_binding = key_binding_of(&identity, &key_salt)?;
    Ok(KeyFromSecret { identity, key_salt, key_binding })
}

/// Why committed fields were refused a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordFingerprintError {
    /// The committed fields are not a JSON object.
    NotAnObject,
    /// `keyBinding` is present but is not 64 lowercase hex characters (null, a number,
    /// upper case and `0x...` included). Present means sealed, so it is refused, not hashed.
    InvalidKeyBinding,
    /// The fields cannot be canonicalised (section 4.4).
    Canonical(CanonicalError),
}

impl fmt::Display for RecordFingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject => write!(f, "the committed fields are a JSON object"),
            Self::InvalidKeyBinding => write!(f, "keyBinding must be 64 lowercase hex characters (spec 3.6.1)"),
            Self::Canonical(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RecordFingerprintError {}

/// A fingerprint of committed fields, with what it was computed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordFingerprint {
    /// `sha256/key-bound/v1` when the fields carry `keyBinding`, else `sha256/canonical-json/v1`.
    pub algorithm: &'static str,
    /// SHA-256 of the canonical serialisation of the fields (a holder's link carries it as `cd`).
    pub content_hash: String,
    /// `content_hash` itself, or `H(keyrecord, keyBinding, content_hash)`.
    pub fingerprint: String,
}

/// The fingerprint of committed JSON anchored on its own (section 3.6.1, "Where it
/// applies"), such as the `fields` of an export's `org.veilcore.registered-fingerprint`
/// extension. The fields are hashed as given.
pub fn record_fingerprint(fields: &Value) -> Result<RecordFingerprint, RecordFingerprintError> {
    let obj = fields.as_object().ok_or(RecordFingerprintError::NotAnObject)?;
    let binding = match obj.get("keyBinding") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .filter(|s| parse_hex32(s).is_some())
                .ok_or(RecordFingerprintError::InvalidKeyBinding)?,
        ),
    };
    let content_hash = sha256_hex(&canonicalise(fields).map_err(RecordFingerprintError::Canonical)?);
    Ok(match binding {
        None => RecordFingerprint {
            algorithm: CANONICAL_JSON_ALGORITHM,
            fingerprint: content_hash.clone(),
            content_hash,
        },
        Some(b) => RecordFingerprint {
            algorithm: KEY_BOUND_ALGORITHM,
            fingerprint: key_bound_fingerprint(b, &content_hash).expect("both inputs checked as hex32"),
            content_hash,
        },
    })
}

/// Check a registered fingerprint against the fields it claims to cover, as an export's
/// `org.veilcore.registered-fingerprint` extension carries them (`fields`, `fingerprint`,
/// and optionally `algorithm`, which must then be the one the fields call for). A refusal
/// reads as `false`; a caller that needs the reason calls `record_fingerprint`. This says
/// the fields are the ones fingerprinted; whether a key is the one they name is
/// `key_matches_record`.
pub fn verify_record_fingerprint(registered: &Value) -> bool {
    let Some(claimed) = registered.get("fingerprint").and_then(Value::as_str) else { return false };
    let Ok(r) = record_fingerprint(&registered["fields"]) else { return false };
    match registered.get("algorithm") {
        None => {}
        Some(a) if a.as_str() == Some(r.algorithm) => {}
        Some(_) => return false,
    }
    parse_hex32(claimed).is_some() && r.fingerprint == claimed
}

/// Is this identity the key the record named when it was sealed (section 3.6.1, "What a
/// verifier checks")? Recomputes `H(keyrecord, H(keybind, identity, keySalt), contentHash)`
/// and compares it with the fingerprint. Any input that is not 64 lowercase hex characters
/// does not match. An older record, with no `keyBinding`, matches no key.
pub fn key_matches_record(identity: &str, fingerprint: &str, key_salt: &str, content_hash: &str) -> bool {
    if parse_hex32(fingerprint).is_none() {
        return false;
    }
    match key_binding_of(identity, key_salt).and_then(|b| key_bound_fingerprint(&b, content_hash)) {
        Ok(f) => f == fingerprint,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a03030303030303030303030303030303";

    #[test]
    fn tags_fit_in_one_element() {
        for t in [COMMIT_TAG, KEY_SALT_TAG, KEY_BIND_TAG, KEY_RECORD_TAG] {
            assert!(t.len() <= 32);
        }
    }

    #[test]
    fn refuses_inputs_that_are_not_lowercase_hex32_naming_them() {
        assert!(identity_from_secret(&SECRET.to_uppercase()).unwrap_err().contains("recordSecret"));
        assert!(key_salt_of(&SECRET[2..]).unwrap_err().contains("recordSecret"));
        assert!(key_binding_of(SECRET, &format!("0x{}", &SECRET[2..])).unwrap_err().contains("keySalt"));
        assert!(key_bound_fingerprint("", SECRET).unwrap_err().contains("keyBinding"));
    }

    #[test]
    fn key_match_is_false_not_an_error_on_malformed_input() {
        let k = binding_for_secret(SECRET).unwrap();
        let content = sha256_hex("{}");
        let fp = key_bound_fingerprint(&k.key_binding, &content).unwrap();
        assert!(key_matches_record(&k.identity, &fp, &k.key_salt, &content));
        assert!(!key_matches_record(&k.identity, &fp.to_uppercase(), &k.key_salt, &content));
        assert!(!key_matches_record("", &fp, &k.key_salt, &content));
        assert!(!key_matches_record(&k.identity, &fp, &k.key_salt, &content[1..]));
    }

    #[test]
    fn fields_must_be_an_object_and_null_keybinding_is_refused() {
        assert_eq!(record_fingerprint(&json!([])), Err(RecordFingerprintError::NotAnObject));
        assert_eq!(record_fingerprint(&json!(null)), Err(RecordFingerprintError::NotAnObject));
        assert_eq!(record_fingerprint(&json!({ "keyBinding": null })), Err(RecordFingerprintError::InvalidKeyBinding));
        assert!(matches!(record_fingerprint(&json!({ "a": null })), Err(RecordFingerprintError::Canonical(_))));
    }

    #[test]
    fn verify_reads_false_on_anything_malformed() {
        let k = binding_for_secret(SECRET).unwrap();
        let fields = json!({ "nonce": SECRET, "keyBinding": k.key_binding });
        let r = record_fingerprint(&fields).unwrap();
        assert!(verify_record_fingerprint(&json!({ "fields": fields, "fingerprint": r.fingerprint })));
        assert!(verify_record_fingerprint(&json!({ "fields": fields, "fingerprint": r.fingerprint, "algorithm": KEY_BOUND_ALGORITHM })));
        assert!(!verify_record_fingerprint(&json!({ "fields": fields, "fingerprint": r.fingerprint, "algorithm": CANONICAL_JSON_ALGORITHM })));
        assert!(!verify_record_fingerprint(&json!({ "fields": fields, "fingerprint": r.fingerprint, "algorithm": 1 })));
        assert!(!verify_record_fingerprint(&json!({ "fields": fields })));
        assert!(!verify_record_fingerprint(&json!({ "fingerprint": r.fingerprint })));
        assert!(!verify_record_fingerprint(&json!(null)));
    }
}
