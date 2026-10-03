//! An independent implementation of the VeilCore record format.
//!
//! Written from the specification rather than translated from the TypeScript or Python
//! implementations. That is the point of it: if three implementations written
//! separately in three languages produce identical commitments, the specification is
//! unambiguous. If they diverge, the specification is wrong, and a registry adopting it
//! would find out the expensive way.
//!
//! Dependencies are SHA-256, a JSON parser, and Unicode normalisation - nothing else.
//! A format that needs more than that to compute a commitment is a format that cannot
//! be implemented by whoever needs to implement it.

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub mod fields;
pub use fields::{field_set_summary, FieldError, FieldSet, FieldSetSummary, FIELDS_ALGORITHM, FIELD_SLOTS};

/// Why a record was refused.
///
/// These are refusals, not failures of this library. The specification says such a
/// record is invalid and an implementation must reject it; rejecting is returning this
/// to the caller, not aborting the caller's process. A registry embedding this crate
/// must be able to receive a hostile record and answer "no" rather than stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// A null appeared in a committed field. Invalid at any nesting depth, per
    /// specification section 4.4 rule 4. Absent optional fields are omitted; a field
    /// whose value is null makes the record invalid.
    NullInCommittedField { key: Option<String> },
    /// Two keys in the same object are identical after Unicode NFC normalisation, per
    /// section 4.4 rule 1. Emitting both would produce an object with a duplicate key,
    /// which is not valid JSON; resolving it means two implementations resolve
    /// differently.
    KeyCollisionAfterNormalisation { key: String },
    /// A number above 2^53 - 1 in magnitude, per section 4.4 rule 8. Past it a double
    /// no longer holds every integer, so an implementation that keeps big integers
    /// exactly and one that rounds them commit different values for the same text.
    NumberOutOfRange { text: String },
    /// A `sha256/fields/v1` record whose `fieldSetRoot` or `fieldSchema` is missing or
    /// is not exactly 64 lowercase hexadecimal characters, per section 4.5. Names the
    /// field at fault.
    InvalidFieldBinding { field: &'static str },
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalError::NullInCommittedField { key: Some(k) } => write!(
                f,
                "null cannot be committed (field \"{}\"): omit the field instead (spec 4.4 rule 4)",
                k
            ),
            CanonicalError::NullInCommittedField { key: None } => write!(
                f,
                "null cannot be committed at any depth: omit the field instead (spec 4.4 rule 4)"
            ),
            CanonicalError::KeyCollisionAfterNormalisation { key } => write!(
                f,
                "two keys are identical after Unicode normalisation (\"{}\"); the record is invalid (spec 4.4 rule 1)",
                key
            ),
            CanonicalError::NumberOutOfRange { text } => write!(
                f,
                "the number {} is above 2^53 - 1 in magnitude and cannot be committed: use a string (spec 4.4 rule 8)",
                text
            ),
            CanonicalError::InvalidFieldBinding { field } => write!(
                f,
                "sha256/fields/v1 needs {} as 64 lowercase hex characters (spec 4.5)",
                field
            ),
        }
    }
}

impl std::error::Error for CanonicalError {}

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// Serialise a number per RFC 8785 3.2.2.3: ECMAScript's Number.prototype.toString.
///
/// JSON gives no way to tell 95 from 95.0, and JavaScript cannot, so a float with an
/// integral value serialises as an integer.
fn number(n: &serde_json::Number) -> Result<String, CanonicalError> {
    let out_of_range = || CanonicalError::NumberOutOfRange { text: n.to_string() };
    if let Some(i) = n.as_i64() {
        if (i as i128).abs() > 9_007_199_254_740_991 {
            return Err(out_of_range());
        }
        return Ok(i.to_string());
    }
    if n.as_u64().is_some() {
        // Every u64 not representable as i64 is far above 2^53.
        return Err(out_of_range());
    }
    let f = n.as_f64().ok_or_else(out_of_range)?;
    if !f.is_finite() || f.abs() > MAX_SAFE {
        return Err(out_of_range());
    }
    // ryu-js implements ECMAScript's Number::toString exactly, including which of two
    // equally short digit strings to choose; Rust's own formatting can pick the other.
    Ok(ryu_js::Buffer::new().format(f).to_string())
}

/// Canonical serialisation, per specification section 4.4.
///
/// Object keys sorted by Unicode code point. Absent optionals omitted rather than
/// serialised as null. UTF-8, NFC normalised. No insignificant whitespace. Array order
/// preserved, because parent order is meaningful in some domains and sorting it would
/// silently discard that meaning.
pub fn canonicalise(value: &Value) -> Result<String, CanonicalError> {
    match value {
        // Rule 4 applies at any nesting depth, including inside an array. Catching it
        // here rather than only where objects are walked is what makes that true.
        Value::Null => Err(CanonicalError::NullInCommittedField { key: None }),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => number(n),
        Value::String(s) => {
            // NFC first: an accented character composed one way and the same character
            // composed another are visually identical and hash differently.
            let normalised: String = s.nfc().collect();
            Ok(serde_json::to_string(&normalised).expect("string is always serialisable"))
        }
        Value::Array(items) => {
            let mut parts: Vec<String> = Vec::with_capacity(items.len());
            for item in items {
                parts.push(canonicalise(item)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(map) => {
            // Keys are NFC-normalised before sorting, and a post-normalisation collision
            // makes the record invalid. Both were unstated in the specification until an
            // external review in August 2026 pointed out that implementations had each
            // guessed differently.
            let mut normalised: Vec<(String, &Value)> = Vec::new();
            for (k, v) in map {
                if v.is_null() {
                    // Named here because a caller fixing the record wants to know which
                    // field. Nulls reached through an array surface without a key.
                    return Err(CanonicalError::NullInCommittedField {
                        key: Some(k.clone()),
                    });
                }
                let n: String = k.nfc().collect();
                // Any second key normalising to the same value is a collision, whether or
                // not the originals differ.
                if normalised.iter().any(|(existing, _)| *existing == n) {
                    return Err(CanonicalError::KeyCollisionAfterNormalisation { key: n });
                }
                normalised.push((n, v));
            }

            // Rust's String ordering is byte order over UTF-8, which agrees with code
            // point order. That is the specified comparison.
            normalised.sort_by(|a, b| a.0.cmp(&b.0));

            let mut parts: Vec<String> = Vec::with_capacity(normalised.len());
            for (k, v) in &normalised {
                let key = serde_json::to_string(k).expect("key is serialisable");
                parts.push(format!("{}:{}", key, canonicalise(v)?));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex(&h.finalize())
}

/// The fields a commitment covers, per section 4.2.
///
/// `anchor` is excluded because it is a statement *about* the commitment and cannot be
/// inside it - which is also what permits the same commitment to be anchored in more
/// than one place. `terms` is excluded because terms are issued and revoked after
/// sealing.
pub fn committed_fields(envelope: &Value) -> Value {
    const COMMITTED: [&str; 17] = [
        "formatVersion", "recordId", "subjectType", "profile", "commitmentAlgorithm",
        "sealedAt", "holder", "attestations", "parents", "profileData",
        "supersedes", "jurisdictionBindings", "extensions",
        // What every subject has, wherever it comes from.
        "subject", "identification", "registrations",
        // The schema a field set is sealed under (section 4.5). The field set root is
        // not here: it is bound by the commitment itself, not by the JSON digest.
        "fieldSchema",
    ];
    const ALWAYS_PRESENT: [&str; 2] = ["attestations", "parents"];

    let mut out = serde_json::Map::new();
    for field in COMMITTED {
        match envelope.get(field) {
            Some(v) if !v.is_null() => { out.insert(field.to_string(), v.clone()); }
            _ if ALWAYS_PRESENT.contains(&field) => {
                out.insert(field.to_string(), Value::Array(vec![]));
            }
            _ => {}
        }
    }
    Value::Object(out)
}

/// Compute a record commitment, per section 4.1.
///
/// Plain SHA-256 over the canonical serialisation. No ledger, no specialised runtime.
///
/// Returns the reason rather than a bare failure: a party sealing a record needs to know
/// which field was refused, not only that something was.
///
/// For `sha256/fields/v1` (section 4.5) the commitment is
/// `H("veilcore:v1:frecord", fieldSetRoot, that same JSON digest)`, so it also binds a
/// field set whose slots can be proved one at a time. Every other algorithm name gets
/// the JSON digest; whether the name is a supported one is the verifier's question.
pub fn compute_commitment(envelope: &Value) -> Result<String, CanonicalError> {
    let json_digest: [u8; 32] = Sha256::digest(canonicalise(&committed_fields(envelope))?.as_bytes()).into();
    if envelope.get("commitmentAlgorithm").and_then(Value::as_str) != Some(FIELDS_ALGORITHM) {
        return Ok(hex(&json_digest));
    }
    let hex32 = |field: &'static str| {
        envelope
            .get(field)
            .and_then(Value::as_str)
            .and_then(fields::parse_hex32)
            .ok_or(CanonicalError::InvalidFieldBinding { field })
    };
    let set_root = hex32("fieldSetRoot")?;
    hex32("fieldSchema")?;
    Ok(hex(&fields::field_record_commitment(&set_root, &json_digest)))
}

/// The bytes an attester signs, per section 7.
///
/// The attester's identity goes in whole rather than by its key alone. An
/// implementation that signs `publicKey` and leaves `displayName`, `role` or
/// `accreditation` outside the signature produces attestations that anyone holding
/// one can rewrite: a small laboratory's genuine report becomes an accredited one,
/// the signature unchanged and still verifying, and section 7.2 reports the tier it
/// reads from those very fields. This was the shape of a real defect in the
/// TypeScript implementation, found in September 2026 and covered by vectors since.
///
/// They remain claims. Signing them establishes that the attester made the claim,
/// not that an accreditor ever issued it.
pub fn attestation_payload(attestation: &Value) -> Result<String, CanonicalError> {
    const ATTESTER_FIELDS: [&str; 3] = ["displayName", "role", "accreditation"];
    const TOP_FIELDS: [&str; 6] = [
        "attestationId", "documentHash", "hashAlgorithm",
        "issuedAt", "subjectCommitment", "type",
    ];

    let mut attester = serde_json::Map::new();
    if let Some(key) = attestation.pointer("/attester/publicKey") {
        attester.insert("publicKey".to_string(), key.clone());
    }
    for field in ATTESTER_FIELDS {
        match attestation.pointer(&format!("/attester/{field}")) {
            Some(v) if !v.is_null() => { attester.insert(field.to_string(), v.clone()); }
            _ => {}
        }
    }

    let mut out = serde_json::Map::new();
    out.insert("attester".to_string(), Value::Object(attester));
    for field in TOP_FIELDS {
        match attestation.get(field) {
            Some(v) if !v.is_null() => { out.insert(field.to_string(), v.clone()); }
            _ => {}
        }
    }

    canonicalise(&Value::Object(out))
}

/// Verify a record commitment.
///
/// This establishes that the record is unaltered since sealing. It does not establish
/// that the record is true - see specification section 9.3.
///
/// An invalid record is not a verified record, so a refusal reads as `false` here. A
/// caller that needs the reason should call `compute_commitment` directly.
pub fn verify_commitment(envelope: &Value) -> bool {
    match envelope.get("commitment").and_then(|c| c.as_str()) {
        Some(claimed) => match compute_commitment(envelope) {
            Ok(computed) => computed == claimed,
            Err(_) => false,
        },
        None => false,
    }
}

// ---- inclusion proofs, per section 5 ----

/// Leaf and interior nodes are domain-separated so a leaf can never be presented as an
/// interior node, per section 5.2.
///
/// The prefix is the two ASCII characters `0` `0`, not the byte 0x00, and the input is
/// the hexadecimal string rather than decoded bytes. Both were unstated in the
/// specification until August 2026; either reading produces a different root everywhere.
pub fn hash_leaf(commitment: &str) -> String {
    sha256_hex(&format!("00{}", commitment))
}

/// An interior node. ASCII prefix `0` `1`, then the two children as hex strings.
pub fn hash_node(left: &str, right: &str) -> String {
    sha256_hex(&format!("01{}{}", left, right))
}

/// One step of an inclusion path.
///
/// `sibling_is_left` describes the SIBLING, not the node being folded. The inverse
/// reading is the most likely divergence in section 5, and roughly half of any given
/// proof still verifies under it, which makes the error hard to see.
pub struct ProofStep {
    pub sibling: String,
    pub sibling_is_left: bool,
}

/// The deepest path a verifier will fold, per section 5.4.
///
/// 64 levels covers any batch anyone will ever build. An unbounded path is an unbounded
/// amount of work handed to a verifier by whoever supplied the proof.
pub const MAX_PROOF_DEPTH: usize = 64;

/// Fold a path from a commitment to a root, and return the root.
///
/// `verify_inclusion` answers yes or no, which is what a verifier wants. A conformance
/// runner wants the value: a disagreement between two implementations is only
/// diagnosable if each reports the root it computed rather than only that they differed.
/// Both go through here, so there is one fold rather than two that can drift apart.
///
/// The depth cap is enforced by the caller, because a caller that wants the value of a
/// deliberately oversized path - a test, for instance - should be able to ask for it.
pub fn fold_path(commitment: &str, path: &[ProofStep]) -> String {
    let mut node = hash_leaf(commitment);
    for step in path {
        node = if step.sibling_is_left {
            hash_node(&step.sibling, &node)
        } else {
            hash_node(&node, &step.sibling)
        };
    }
    node
}

/// Verify that an inclusion path folds to the root it names.
///
/// Requires no network access: this proves membership in the batch whose root the proof
/// names. Whether that root was anchored, and when, is a separate lookup - kept separate
/// so a proof can be checked entirely offline.
pub fn verify_inclusion(commitment: &str, path: &[ProofStep], root: &str) -> bool {
    if path.len() > MAX_PROOF_DEPTH {
        return false;
    }
    fold_path(commitment, path) == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- rejections: the record is invalid and must be refused, not crashed on ----

    #[test]
    fn a_null_at_the_top_level_is_refused() {
        let v = json!({ "a": null });
        assert_eq!(
            canonicalise(&v),
            Err(CanonicalError::NullInCommittedField {
                key: Some("a".to_string())
            })
        );
    }

    #[test]
    fn a_nested_null_is_refused() {
        let v = json!({ "a": { "b": { "c": null } } });
        assert!(matches!(
            canonicalise(&v),
            Err(CanonicalError::NullInCommittedField { .. })
        ));
    }

    #[test]
    fn a_null_inside_an_array_is_refused() {
        // Rule 4 says any nesting depth. An array element is a depth like any other, and
        // this case was silently accepted before August 2026.
        let v = json!({ "a": [1, null, 3] });
        assert!(matches!(
            canonicalise(&v),
            Err(CanonicalError::NullInCommittedField { .. })
        ));
    }

    #[test]
    fn keys_identical_after_normalisation_are_refused() {
        // Composed and decomposed forms of the same character.
        let mut map = serde_json::Map::new();
        map.insert("\u{00e9}".to_string(), json!(1));
        map.insert("e\u{0301}".to_string(), json!(2));
        let v = Value::Object(map);
        assert!(matches!(
            canonicalise(&v),
            Err(CanonicalError::KeyCollisionAfterNormalisation { .. })
        ));
    }

    #[test]
    fn a_refusal_does_not_abort_the_caller() {
        // The point of the change: a caller can receive a hostile record, be told no, and
        // carry on serving.
        let hostile = json!({ "a": null });
        let mut served = 0;
        for _ in 0..3 {
            if canonicalise(&hostile).is_err() {
                served += 1;
            }
        }
        assert_eq!(served, 3);
    }

    // ---- canonicalisation still behaves ----

    #[test]
    fn keys_are_sorted_by_code_point() {
        let v = json!({ "b": 1, "a": 2, "C": 3 });
        assert_eq!(canonicalise(&v).unwrap(), "{\"C\":3,\"a\":2,\"b\":1}");
    }

    #[test]
    fn array_order_is_preserved() {
        let v = json!(["b", "a", "c"]);
        assert_eq!(canonicalise(&v).unwrap(), "[\"b\",\"a\",\"c\"]");
    }

    #[test]
    fn nested_objects_are_sorted_at_every_level() {
        let v = json!({ "z": { "b": 1, "a": 2 }, "a": 3 });
        assert_eq!(canonicalise(&v).unwrap(), "{\"a\":3,\"z\":{\"a\":2,\"b\":1}}");
    }

    #[test]
    fn an_invalid_record_does_not_verify() {
        let v = json!({ "commitment": "0".repeat(64), "holder": null });
        assert!(!verify_commitment(&v));
    }

    // ---- field sets bound into the commitment (section 4.5) ----

    fn fields_record() -> Value {
        json!({
            "formatVersion": "0.1", "recordId": "vc_rec_conformance_fields_01",
            "subjectType": "plant-genetic-material", "profile": "veilcore/profile/cannabis/v0.1",
            "commitment": "", "commitmentAlgorithm": "sha256/fields/v1",
            "anchor": { "chain": "midnight", "network": "undeployed" },
            "sealedAt": "2026-01-01T00:00:00Z", "holder": { "id": "vc_hld_conformance" },
            "parents": [], "attestations": [],
            "profileData": { "cultivarName": "Reference Cultivar", "nonce": "0".repeat(64) },
            "fieldSchema": "9dd68c656b770881cad6e2be6dfc04a9b495fb90d83b78a8b295a425a7690861",
            "fieldSetRoot": "bcc7a07c54b73978c378b1056f52c7fb34fa7a92f85470d7f8c33f15f8758dec"
        })
    }

    #[test]
    fn a_fields_record_binds_its_field_set() {
        // conformance/vectors.json, "a sha256/fields/v1 record binds its field set".
        assert_eq!(
            compute_commitment(&fields_record()).unwrap(),
            "afb6bcdecc4c3cb7a17389d2fc0eea664ff43277209a359d048a355f4f599a9f"
        );
    }

    #[test]
    fn a_fields_record_without_a_lowercase_binding_is_refused() {
        let mut no_root = fields_record();
        no_root.as_object_mut().unwrap().remove("fieldSetRoot");
        assert_eq!(
            compute_commitment(&no_root),
            Err(CanonicalError::InvalidFieldBinding { field: "fieldSetRoot" })
        );

        let mut upper = fields_record();
        upper["fieldSetRoot"] = json!(upper["fieldSetRoot"].as_str().unwrap().to_uppercase());
        assert!(compute_commitment(&upper).is_err());

        let mut no_schema = fields_record();
        no_schema.as_object_mut().unwrap().remove("fieldSchema");
        assert_eq!(
            compute_commitment(&no_schema),
            Err(CanonicalError::InvalidFieldBinding { field: "fieldSchema" })
        );
    }

    #[test]
    fn the_field_schema_is_committed_under_either_algorithm() {
        let mut a = fields_record();
        a["commitmentAlgorithm"] = json!("sha256/canonical-json/v1");
        let mut b = a.clone();
        b["fieldSchema"] = json!("0".repeat(64));
        assert_ne!(compute_commitment(&a).unwrap(), compute_commitment(&b).unwrap());
    }

    // ---- inclusion proofs ----

    #[test]
    fn a_path_deeper_than_the_maximum_is_refused() {
        let path: Vec<ProofStep> = (0..MAX_PROOF_DEPTH + 1)
            .map(|_| ProofStep {
                sibling: "a".repeat(64),
                sibling_is_left: true,
            })
            .collect();
        assert!(!verify_inclusion(&"b".repeat(64), &path, &"c".repeat(64)));
    }

    #[test]
    fn a_single_step_path_folds() {
        let commitment = "b".repeat(64);
        let sibling = "a".repeat(64);
        let root = hash_node(&hash_leaf(&commitment), &sibling);
        let path = vec![ProofStep {
            sibling,
            sibling_is_left: false,
        }];
        assert!(verify_inclusion(&commitment, &path, &root));
    }

    #[test]
    fn an_empty_path_folds_to_the_leaf_hash() {
        // A single-leaf batch has a root equal to the leaf hash and an empty path. It is
        // the first case anyone implements and the specification left it undefined until
        // August 2026.
        let commitment = "0".repeat(64);
        assert_eq!(fold_path(&commitment, &[]), hash_leaf(&commitment));
    }

    #[test]
    fn the_direction_flag_describes_the_sibling() {
        // If this were read the other way round, the two roots below would swap. Half of
        // any given proof still verifies under the inverse reading, which is what makes
        // that error hard to see without a test that names it.
        let commitment = "b".repeat(64);
        let sibling = "a".repeat(64);
        let leaf = hash_leaf(&commitment);

        let sibling_left = fold_path(
            &commitment,
            &[ProofStep { sibling: sibling.clone(), sibling_is_left: true }],
        );
        let sibling_right = fold_path(
            &commitment,
            &[ProofStep { sibling: sibling.clone(), sibling_is_left: false }],
        );

        assert_eq!(sibling_left, hash_node(&sibling, &leaf));
        assert_eq!(sibling_right, hash_node(&leaf, &sibling));
        assert_ne!(sibling_left, sibling_right);
    }

    #[test]
    fn leaves_and_interior_nodes_are_domain_separated() {
        // Without the differing prefixes, a leaf preimage and an interior preimage could
        // collide, and a leaf could be presented as an interior node.
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert_ne!(hash_leaf(&a), sha256_hex(&a));
        assert_ne!(hash_node(&a, &b), sha256_hex(&format!("{}{}", a, b)));
    }
}
