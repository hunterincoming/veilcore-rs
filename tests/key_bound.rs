//! Every vector of spec 3.6.1, a record that names its own key.
//!
//! `vectors/key-bound-v1.json` is a byte-for-byte copy of the file the VeilCore web
//! application publishes (its contract/vectors/key-bound-v1.json), which veilcore-sdk's
//! shared set also carries as its keyBound* sections. It was written with node:crypto and
//! a canonicaliser only, so this crate is checked against values it did not compute.

use serde_json::Value;
use veilcore_records::{
    binding_for_secret, canonicalise, identity_from_secret, key_binding_of, key_bound_fingerprint, key_matches_record,
    key_salt_of, record_fingerprint, verify_record_fingerprint, RecordFingerprintError,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/key-bound-v1.json")).expect("the vector file is JSON")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} is a string"))
}

fn list<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap_or_else(|| panic!("{k} is a list"))
}

#[test]
fn the_vector_file_is_whole() {
    let v = vectors();
    let counts: Vec<usize> = ["keys", "records", "checks", "refusals"].iter().map(|k| list(&v, k).len()).collect();
    assert_eq!(counts, [2, 4, 9, 5]);
    let checks = list(&v, "checks");
    assert!(checks.iter().any(|c| c["matches"] == true) && checks.iter().any(|c| c["matches"] == false));
}

#[test]
fn keys_from_the_record_secret() {
    for k in list(&vectors(), "keys") {
        let secret = s(k, "recordSecret");
        assert_eq!(identity_from_secret(secret).unwrap(), s(k, "identity"));
        assert_eq!(key_salt_of(secret).unwrap(), s(k, "keySalt"));
        assert_eq!(key_binding_of(s(k, "identity"), s(k, "keySalt")).unwrap(), s(k, "keyBinding"));
        let b = binding_for_secret(secret).unwrap();
        assert_eq!((b.identity.as_str(), b.key_salt.as_str(), b.key_binding.as_str()), (s(k, "identity"), s(k, "keySalt"), s(k, "keyBinding")));
    }
}

#[test]
fn every_record_older_and_bound() {
    for r in list(&vectors(), "records") {
        let name = s(r, "name");
        let fields = &r["fields"];
        assert_eq!(canonicalise(fields).unwrap(), s(r, "canonical"), "{name}");
        let got = record_fingerprint(fields).unwrap();
        assert_eq!(got.algorithm, s(r, "algorithm"), "{name}");
        assert_eq!(got.content_hash, s(r, "contentHash"), "{name}");
        assert_eq!(got.fingerprint, s(r, "fingerprint"), "{name}");
        let registered = serde_json::json!({ "fields": fields, "fingerprint": r["fingerprint"], "algorithm": r["algorithm"] });
        assert!(verify_record_fingerprint(&registered), "{name}");
        if let Some(kb) = fields.get("keyBinding").and_then(Value::as_str) {
            assert_eq!(key_bound_fingerprint(kb, s(r, "contentHash")).unwrap(), s(r, "fingerprint"), "{name}");
        } else {
            // An older record: the fingerprint is the content hash, as before.
            assert_eq!(got.fingerprint, got.content_hash, "{name}");
        }
    }
}

#[test]
fn every_check_a_key_matches_only_the_record_that_named_it() {
    for c in list(&vectors(), "checks") {
        let expected = c["matches"].as_bool().expect("matches is a boolean");
        assert_eq!(
            key_matches_record(s(c, "identity"), s(c, "fingerprint"), s(c, "keySalt"), s(c, "contentHash")),
            expected,
            "{}",
            s(c, "name")
        );
    }
}

#[test]
fn every_refusal_a_malformed_key_binding_is_refused_not_hashed() {
    for r in list(&vectors(), "refusals") {
        assert_eq!(record_fingerprint(&r["fields"]), Err(RecordFingerprintError::InvalidKeyBinding), "{}", s(r, "name"));
        let registered = serde_json::json!({ "fields": r["fields"], "fingerprint": "ab".repeat(32) });
        assert!(!verify_record_fingerprint(&registered), "{}", s(r, "name"));
    }
}

#[test]
fn a_key_swapped_or_dropped_after_sealing_does_not_verify() {
    let v = vectors();
    let records = list(&v, "records");
    let bound = records.iter().find(|r| r["fields"].get("keyBinding").is_some()).unwrap();
    let other = list(&v, "keys").iter().map(|k| s(k, "keyBinding")).find(|k| *k != s(&bound["fields"], "keyBinding")).unwrap();
    let mut swapped = bound["fields"].clone();
    swapped["keyBinding"] = Value::from(other);
    let mut dropped = bound["fields"].clone();
    dropped.as_object_mut().unwrap().remove("keyBinding");
    for fields in [swapped, dropped] {
        assert!(!verify_record_fingerprint(&serde_json::json!({ "fields": fields, "fingerprint": bound["fingerprint"] })));
    }
}
