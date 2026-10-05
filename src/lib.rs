//! A Rust implementation of the VeilCore record format.
//!
//! Written from the specification rather than translated from the TypeScript or Python
//! implementations. All three have the same author, so agreement shows the rules give one
//! answer across languages, not that a stranger could implement them from the text alone.
//! Where they diverge, the specification is wrong, and a registry adopting it would find
//! out the expensive way.
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
    /// A `sha256/canonical-json/v1` record carrying `fieldSchema` or `fieldSetRoot`. The
    /// bindings mean nothing under that algorithm, so committing them would publish a
    /// root nothing checks.
    FieldBindingWithoutFieldsAlgorithm,
    /// A commitment algorithm other than exactly `sha256/canonical-json/v1` or
    /// `sha256/fields/v1`, including a missing or non-string one. A name that only looks
    /// like a supported one, with a trailing space say, is refused rather than guessed at.
    UnsupportedCommitmentAlgorithm { algorithm: String },
    /// A record without one of the committed fields every record has (section 3.1).
    /// Hashing it anyway would give a commitment to something that is not a record.
    MissingRequiredField { field: &'static str },
    /// A `ledgerIdentity` that is not an object with a non-empty string `chain`, a 64
    /// lowercase hex `identity`, an optional 64 lowercase hex `contractAddress` and
    /// nothing else (section 3.6). Says which rule it broke.
    InvalidLedgerIdentity { reason: String },
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
            CanonicalError::FieldBindingWithoutFieldsAlgorithm => write!(
                f,
                "fieldSchema and fieldSetRoot belong only to sha256/fields/v1 records (spec 4.5)"
            ),
            CanonicalError::UnsupportedCommitmentAlgorithm { algorithm } => {
                write!(f, "unsupported commitment algorithm: {}", algorithm)
            }
            CanonicalError::MissingRequiredField { field } => {
                write!(f, "a record needs {} (spec 3.1)", field)
            }
            CanonicalError::InvalidLedgerIdentity { reason } => write!(f, "{} (spec 3.6)", reason),
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
            let mut normalised: Vec<(String, &Value)> = Vec::with_capacity(map.len());
            // A set rather than a scan of the list: the scan was quadratic in the number of
            // keys, so one object with a few hundred thousand keys tied up a verifier.
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::with_capacity(map.len());
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
                if !seen.insert(n.clone()) {
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
///
/// A field written as null is copied as null, so that canonicalising the result refuses
/// the record (section 4.4 rule 4). Absent and null are different: an absent optional
/// field is omitted and an absent `attestations` or `parents` is the empty list, but a
/// null is never quietly read as either. Dropping nulls here, as this function did until
/// October 2026, committed a record the other implementations refuse.
pub fn committed_fields(envelope: &Value) -> Value {
    const COMMITTED: [&str; 19] = [
        "formatVersion", "recordId", "subjectType", "profile", "commitmentAlgorithm",
        "sealedAt", "holder", "attestations", "parents", "profileData",
        "supersedes", "jurisdictionBindings", "extensions",
        // What every subject has, wherever it comes from.
        "subject", "identification", "registrations",
        // The field set binding (section 4.5). The root is also bound by the commitment
        // itself; having it in the JSON as well means anyone shown the JSON sees which
        // field set it belongs to, and one JSON cannot be paired with two field sets.
        "fieldSchema", "fieldSetRoot",
        // Which ledger identity the record is bound to (section 3.6), when it is.
        "ledgerIdentity",
    ];
    const ALWAYS_PRESENT: [&str; 2] = ["attestations", "parents"];

    let mut out = serde_json::Map::new();
    for field in COMMITTED {
        match envelope.get(field) {
            Some(v) => { out.insert(field.to_string(), v.clone()); }
            None if ALWAYS_PRESENT.contains(&field) => {
                out.insert(field.to_string(), Value::Array(vec![]));
            }
            _ => {}
        }
    }
    Value::Object(out)
}

/// Committed fields every record has, per section 3.1. A record missing one is refused
/// rather than hashed.
pub const REQUIRED_COMMITTED: [&str; 7] =
    ["formatVersion", "recordId", "subjectType", "profile", "sealedAt", "holder", "profileData"];

/// Check an optional `ledgerIdentity`, per section 3.6: an object with `chain` a
/// non-empty string, `identity` 64 lowercase hex characters, `contractAddress` the same
/// if present, and no other key. Absent is fine; null is present and refused. Checked
/// under both commitment algorithms.
pub fn check_ledger_identity(envelope: &Value) -> Result<(), CanonicalError> {
    let refuse = |reason: String| Err(CanonicalError::InvalidLedgerIdentity { reason });
    let o = match envelope.get("ledgerIdentity") {
        None => return Ok(()),
        Some(Value::Object(o)) => o,
        Some(_) => return refuse("ledgerIdentity is an object".into()),
    };
    if let Some(k) = o.keys().find(|k| !matches!(k.as_str(), "chain" | "contractAddress" | "identity")) {
        return refuse(format!("ledgerIdentity has an unknown field: {k}"));
    }
    if !matches!(o.get("chain"), Some(Value::String(c)) if !c.is_empty()) {
        return refuse("ledgerIdentity.chain is a non-empty string".into());
    }
    let hex32 = |v: Option<&Value>| v.and_then(Value::as_str).and_then(fields::parse_hex32).is_some();
    if !hex32(o.get("identity")) {
        return refuse("ledgerIdentity.identity is 64 lowercase hex characters".into());
    }
    if o.get("contractAddress").is_some() && !hex32(o.get("contractAddress")) {
        return refuse("ledgerIdentity.contractAddress is 64 lowercase hex characters".into());
    }
    Ok(())
}

/// Compute a record commitment, per section 4.1.
///
/// Plain SHA-256 over the canonical serialisation. No ledger, no specialised runtime.
///
/// Returns the reason rather than a bare failure: a party sealing a record needs to know
/// which field was refused, not only that something was.
///
/// Two algorithms, matched exactly; any other name is refused:
///
/// - `sha256/canonical-json/v1`: SHA-256 of the canonical JSON of the committed fields.
///   A record carrying `fieldSchema` or `fieldSetRoot` is refused.
/// - `sha256/fields/v1` (section 4.5): `H("veilcore:v1:frecord", fieldSetRoot, that same
///   JSON digest)`, so the commitment also binds a field set whose slots can be proved
///   one at a time. Both bindings must be 64 lowercase hex characters.
pub fn compute_commitment(envelope: &Value) -> Result<String, CanonicalError> {
    // Absent, not null: a null here is present, and the canonicaliser refuses it below
    // with the field named (section 4.4 rule 4).
    for field in REQUIRED_COMMITTED {
        if envelope.get(field).is_none() {
            return Err(CanonicalError::MissingRequiredField { field });
        }
    }
    check_ledger_identity(envelope)?;
    let json_digest = || -> Result<[u8; 32], CanonicalError> {
        Ok(Sha256::digest(canonicalise(&committed_fields(envelope))?.as_bytes()).into())
    };
    match envelope.get("commitmentAlgorithm") {
        Some(Value::String(a)) if a == "sha256/canonical-json/v1" => {
            // Present at all, null included, as the reference reads it.
            if envelope.get("fieldSchema").is_some() || envelope.get("fieldSetRoot").is_some() {
                return Err(CanonicalError::FieldBindingWithoutFieldsAlgorithm);
            }
            return Ok(hex(&json_digest()?));
        }
        Some(Value::String(a)) if a == FIELDS_ALGORITHM => {}
        other => {
            return Err(CanonicalError::UnsupportedCommitmentAlgorithm {
                algorithm: match other {
                    Some(Value::String(a)) => a.clone(),
                    Some(v) => v.to_string(),
                    None => "undefined".to_string(),
                },
            })
        }
    }
    let json_digest = json_digest()?;
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

/// Check an inclusion proof's shape, per sections 5.1, 5.2 and 5.4: the commitment and
/// every sibling are 64 lowercase hex characters, and the path is at most
/// `MAX_PROOF_DEPTH` steps. Nodes are hashed as hex TEXT, so a sibling of another length
/// or case is a different preimage, and "01" || left || right stops saying where one
/// operand ends.
pub fn check_proof(commitment: &str, path: &[ProofStep]) -> Result<(), &'static str> {
    if fields::parse_hex32(commitment).is_none() {
        return Err("a commitment is 64 lowercase hex characters (spec 5.1)");
    }
    if path.len() > MAX_PROOF_DEPTH {
        return Err("proof path exceeds maximum depth (spec 5.4)");
    }
    if path.iter().any(|s| fields::parse_hex32(&s.sibling).is_none()) {
        return Err("each sibling is 64 lowercase hex characters (spec 5.2)");
    }
    Ok(())
}

/// Verify that an inclusion path folds to the root it names.
///
/// Requires no network access: this proves membership in the batch whose root the proof
/// names. Whether that root was anchored, and when, is a separate lookup - kept separate
/// so a proof can be checked entirely offline. A malformed proof (see `check_proof`) or
/// root does not verify.
pub fn verify_inclusion(commitment: &str, path: &[ProofStep], root: &str) -> bool {
    if check_proof(commitment, path).is_err() || fields::parse_hex32(root).is_none() {
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
            "fieldSchema": "53304a427e34f78ebbb162464ca1a2fe67a51ed70b28ac2f1a61bee19c37d754",
            "fieldSetRoot": "c2d318520d0c3273ac0dae976dbeeece5b81adf841bf09b894cb42feec141b17"
        })
    }

    #[test]
    fn a_fields_record_binds_its_field_set() {
        // conformance/vectors.json, "a sha256/fields/v1 record binds its field set".
        assert_eq!(
            compute_commitment(&fields_record()).unwrap(),
            "929b42f5025a494a04fd1c8fb1ec20f2bdbe9675f0059fe6ebfd05efdfdaa1c5"
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

        let mut listed = fields_record();
        listed["fieldSchema"] = json!([listed["fieldSchema"].clone()]);
        assert_eq!(
            compute_commitment(&listed),
            Err(CanonicalError::InvalidFieldBinding { field: "fieldSchema" })
        );

        let mut no_schema = fields_record();
        no_schema.as_object_mut().unwrap().remove("fieldSchema");
        assert_eq!(
            compute_commitment(&no_schema),
            Err(CanonicalError::InvalidFieldBinding { field: "fieldSchema" })
        );
    }

    #[test]
    fn a_committed_field_written_as_null_is_refused() {
        for field in ["supersedes", "subject", "attestations", "parents", "holder", "extensions"] {
            for algorithm in ["sha256/canonical-json/v1", "sha256/fields/v1"] {
                let mut r = fields_record();
                if algorithm != FIELDS_ALGORITHM {
                    let o = r.as_object_mut().unwrap();
                    o.remove("fieldSchema");
                    o.remove("fieldSetRoot");
                }
                r["commitmentAlgorithm"] = json!(algorithm);
                r[field] = Value::Null;
                assert_eq!(
                    compute_commitment(&r),
                    Err(CanonicalError::NullInCommittedField { key: Some(field.to_string()) }),
                    "{field} under {algorithm}"
                );
                assert!(!verify_commitment(&r));
            }
        }
    }

    #[test]
    fn a_record_missing_a_required_field_is_refused() {
        for field in REQUIRED_COMMITTED {
            for algorithm in ["sha256/canonical-json/v1", "sha256/fields/v1"] {
                let mut r = fields_record();
                if algorithm != FIELDS_ALGORITHM {
                    let o = r.as_object_mut().unwrap();
                    o.remove("fieldSchema");
                    o.remove("fieldSetRoot");
                }
                r["commitmentAlgorithm"] = json!(algorithm);
                r.as_object_mut().unwrap().remove(field);
                assert_eq!(
                    compute_commitment(&r),
                    Err(CanonicalError::MissingRequiredField { field }),
                    "{field} under {algorithm}"
                );
            }
        }
        // Optional committed fields may be absent.
        let mut r = fields_record();
        for optional in ["supersedes", "subject", "extensions", "attestations", "parents"] {
            r.as_object_mut().unwrap().remove(optional);
        }
        assert!(compute_commitment(&r).is_ok());
        // Not an object at all.
        assert!(compute_commitment(&json!([1])).is_err());
    }

    fn with_ledger_identity(li: Value) -> Value {
        let mut r = fields_record();
        r["ledgerIdentity"] = li;
        r
    }

    #[test]
    fn a_well_formed_ledger_identity_is_committed() {
        let li = json!({ "chain": "midnight", "identity": "a".repeat(64) });
        let r = with_ledger_identity(li.clone());
        assert_eq!(committed_fields(&r)["ledgerIdentity"], li);
        let c = compute_commitment(&r).unwrap();
        assert_ne!(c, compute_commitment(&fields_record()).unwrap());

        let with_contract = with_ledger_identity(json!({
            "chain": "midnight", "identity": "a".repeat(64), "contractAddress": "b".repeat(64)
        }));
        assert_ne!(compute_commitment(&with_contract).unwrap(), c);

        // Under the other algorithm too.
        let mut plain = r.clone();
        let o = plain.as_object_mut().unwrap();
        o.remove("fieldSchema");
        o.remove("fieldSetRoot");
        plain["commitmentAlgorithm"] = json!("sha256/canonical-json/v1");
        assert!(compute_commitment(&plain).is_ok());
    }

    #[test]
    fn a_malformed_ledger_identity_is_refused() {
        let id = "a".repeat(64);
        let bad = [
            Value::Null,
            json!("midnight"),
            json!([]),
            json!({ "identity": id }),
            json!({ "chain": "", "identity": id }),
            json!({ "chain": 1, "identity": id }),
            json!({ "chain": "midnight" }),
            json!({ "chain": "midnight", "identity": id.to_uppercase() }),
            json!({ "chain": "midnight", "identity": "a".repeat(63) }),
            json!({ "chain": "midnight", "identity": id, "contractAddress": null }),
            json!({ "chain": "midnight", "identity": id, "contractAddress": "B".repeat(64) }),
            json!({ "chain": "midnight", "identity": id, "network": "mainnet" }),
        ];
        for li in bad {
            for algorithm in ["sha256/canonical-json/v1", "sha256/fields/v1"] {
                let mut r = with_ledger_identity(li.clone());
                if algorithm != FIELDS_ALGORITHM {
                    let o = r.as_object_mut().unwrap();
                    o.remove("fieldSchema");
                    o.remove("fieldSetRoot");
                }
                r["commitmentAlgorithm"] = json!(algorithm);
                assert!(
                    matches!(compute_commitment(&r), Err(CanonicalError::InvalidLedgerIdentity { .. })),
                    "accepted {li} under {algorithm}"
                );
            }
        }
    }

    #[test]
    fn absent_attestations_and_parents_are_empty_lists() {
        let mut absent = fields_record();
        let o = absent.as_object_mut().unwrap();
        o.remove("attestations");
        o.remove("parents");
        assert_eq!(compute_commitment(&absent), compute_commitment(&fields_record()));
        assert_eq!(committed_fields(&absent)["parents"], json!([]));
    }

    #[test]
    fn a_field_outside_the_commitment_may_be_null() {
        // anchor and terms are not committed, so a null there is not this function's concern.
        let mut r = fields_record();
        r["anchor"] = Value::Null;
        r["terms"] = Value::Null;
        assert_eq!(compute_commitment(&r), compute_commitment(&fields_record()));
    }

    #[test]
    fn the_field_set_root_is_in_the_committed_json() {
        assert!(committed_fields(&fields_record()).get("fieldSetRoot").is_some());
        assert!(committed_fields(&fields_record()).get("fieldSchema").is_some());
    }

    #[test]
    fn a_canonical_json_record_carrying_a_field_binding_is_refused() {
        for field in ["fieldSchema", "fieldSetRoot"] {
            let mut r = fields_record();
            r["commitmentAlgorithm"] = json!("sha256/canonical-json/v1");
            let other = if field == "fieldSchema" { "fieldSetRoot" } else { "fieldSchema" };
            r.as_object_mut().unwrap().remove(other);
            assert_eq!(compute_commitment(&r), Err(CanonicalError::FieldBindingWithoutFieldsAlgorithm));
            r[field] = Value::Null; // present, even as null
            assert_eq!(compute_commitment(&r), Err(CanonicalError::FieldBindingWithoutFieldsAlgorithm));
            r.as_object_mut().unwrap().remove(field);
            assert!(compute_commitment(&r).is_ok());
        }
    }

    #[test]
    fn only_the_two_algorithm_names_are_accepted() {
        for name in [json!("sha256/fields/v1 "), json!("sha256/fields/v2"), json!("SHA256/fields/v1"), json!(1)] {
            let mut r = fields_record();
            r["commitmentAlgorithm"] = name;
            assert!(matches!(
                compute_commitment(&r),
                Err(CanonicalError::UnsupportedCommitmentAlgorithm { .. })
            ));
        }
        let mut missing = fields_record();
        missing.as_object_mut().unwrap().remove("commitmentAlgorithm");
        assert!(matches!(
            compute_commitment(&missing),
            Err(CanonicalError::UnsupportedCommitmentAlgorithm { .. })
        ));
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
    fn a_malformed_proof_does_not_verify() {
        let commitment = "b".repeat(64);
        let sibling = "a".repeat(64);
        let root = hash_node(&hash_leaf(&commitment), &sibling);
        let step = |s: &str| vec![ProofStep { sibling: s.to_string(), sibling_is_left: false }];
        assert!(verify_inclusion(&commitment, &step(&sibling), &root));
        // Uppercase, short, padded or empty siblings; an uppercase commitment or root.
        for bad in ["A".repeat(64), "a".repeat(62), format!("{sibling} "), String::new()] {
            assert!(!verify_inclusion(&commitment, &step(&bad), &root), "{bad:?}");
        }
        assert!(!verify_inclusion(&"B".repeat(64), &step(&sibling), &root));
        assert!(!verify_inclusion(&commitment, &step(&sibling), &root.to_uppercase()));
        assert!(check_proof("", &[]).is_err());
    }

    #[test]
    fn many_keys_are_checked_for_collisions_in_linear_time() {
        let mut m = serde_json::Map::new();
        for i in 0..200_000 {
            m.insert(format!("k{i}"), json!(1));
        }
        assert!(canonicalise(&Value::Object(m)).is_ok());
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
