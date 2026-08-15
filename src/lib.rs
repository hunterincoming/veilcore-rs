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

/// Canonical serialisation, per specification section 4.4.
///
/// Object keys sorted by Unicode code point. Absent optionals omitted rather than
/// serialised as null. UTF-8, NFC normalised. No insignificant whitespace. Array order
/// preserved, because parent order is meaningful in some domains and sorting it would
/// silently discard that meaning.
pub fn canonicalise(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            // NFC first: an accented character composed one way and the same character
            // composed another are visually identical and hash differently.
            let normalised: String = s.nfc().collect();
            serde_json::to_string(&normalised).expect("string is always serialisable")
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonicalise).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            // Keys are NFC-normalised before sorting, and a post-normalisation collision
            // makes the record invalid. Both were unstated in the specification until an
            // external review in August 2026 pointed out that implementations had each
            // guessed differently.
            let mut normalised: Vec<(String, &Value)> = Vec::new();
            for (k, v) in map {
                if v.is_null() {
                    panic!("null cannot be committed: omit the field instead (spec 4.4 rule 4)");
                }
                let n: String = k.nfc().collect();
                // Any second key normalising to the same value is a collision, whether or
                // not the originals differ: emitting both would produce an object with a
                // duplicate key, which is not valid JSON.
                if normalised.iter().any(|(existing, _)| *existing == n) {
                    panic!(
                        "two keys are identical after Unicode normalisation (\"{}\"); \
                         the record is invalid (spec 4.4 rule 1)",
                        n
                    );
                }
                normalised.push((n, v));
            }

            // Rust's String ordering is byte order over UTF-8, which agrees with code
            // point order. That is the specified comparison.
            normalised.sort_by(|a, b| a.0.cmp(&b.0));

            let parts: Vec<String> = normalised
                .iter()
                .map(|(k, v)| {
                    let key = serde_json::to_string(k).expect("key is serialisable");
                    format!("{}:{}", key, canonicalise(v))
                })
                .collect();
            format!("{{{}}}", parts.join(","))
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
    const COMMITTED: [&str; 16] = [
        "formatVersion", "recordId", "subjectType", "profile", "commitmentAlgorithm",
        "sealedAt", "holder", "attestations", "parents", "profileData",
        "supersedes", "jurisdictionBindings", "extensions",
        // What every subject has, wherever it comes from.
        "subject", "identification", "registrations",
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
pub fn compute_commitment(envelope: &Value) -> String {
    sha256_hex(&canonicalise(&committed_fields(envelope)))
}

/// Verify a record commitment.
///
/// This establishes that the record is unaltered since sealing. It does not establish
/// that the record is true - see specification section 9.3.
pub fn verify_commitment(envelope: &Value) -> bool {
    match envelope.get("commitment").and_then(|c| c.as_str()) {
        Some(claimed) => compute_commitment(envelope) == claimed,
        None => false,
    }
}

// ---- inclusion proofs, per section 5 ----

/// Leaf and interior nodes are domain-separated so a leaf can never be presented as an
/// interior node.
fn hash_leaf(commitment: &str) -> String {
    sha256_hex(&format!("00{}", commitment))
}

fn hash_node(left: &str, right: &str) -> String {
    sha256_hex(&format!("01{}{}", left, right))
}

pub struct ProofStep {
    pub sibling: String,
    pub sibling_is_left: bool,
}

/// Fold a path from a commitment to a root.
///
/// Requires no network access: this proves membership in the batch whose root the proof
/// names. Whether that root was anchored, and when, is a separate lookup - kept separate
/// so a proof can be checked entirely offline.
pub fn verify_inclusion(commitment: &str, path: &[ProofStep], root: &str) -> bool {
    if path.len() > 64 {
        return false;
    }
    let mut node = hash_leaf(commitment);
    for step in path {
        node = if step.sibling_is_left {
            hash_node(&step.sibling, &node)
        } else {
            hash_node(&node, &step.sibling)
        };
    }
    node == root
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_deeper_than_the_maximum_is_refused() {
        let path: Vec<ProofStep> = (0..65)
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
}
