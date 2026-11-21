// SPDX-License-Identifier: Apache-2.0
//! Document records (spec 11.11, final): every vector.
//!
//! `vectors/document-v1.json` is a byte-for-byte copy of veilcore-sdk's
//! conformance/document-v1.json, written with node:crypto and a canonicaliser only, so this
//! crate is checked against values it did not compute. The profile changes no fingerprint
//! rule: `record_fingerprint` gives every record's fingerprint, and `document_fingerprint`
//! gives the same after checking the profile's form, refusing every set of fields in
//! `refusals`.

use serde_json::Value;
use veilcore_records::{
    binding_for_secret, canonicalise, document_fingerprint, document_problems, record_fingerprint, DOCUMENT_PROFILE,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/document-v1.json")).expect("the vector file is JSON")
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
    assert_eq!(s(&v, "profile"), DOCUMENT_PROFILE);
    let counts: Vec<usize> = ["keys", "records", "refusals"].iter().map(|k| list(&v, k).len()).collect();
    assert_eq!(counts, [2, 5, 31]);
}

#[test]
fn the_keys_are_made_from_their_secrets() {
    for k in list(&vectors(), "keys") {
        let b = binding_for_secret(s(k, "recordSecret")).unwrap();
        assert_eq!(b.key_binding, s(k, "keyBinding"));
    }
}

#[test]
fn every_record_its_canonical_form_and_fingerprint() {
    for r in list(&vectors(), "records") {
        let name = s(r, "name");
        let fields = &r["fields"];
        assert_eq!(document_problems(fields), Vec::<String>::new(), "{name}");
        assert_eq!(canonicalise(fields).unwrap(), s(r, "canonical"), "{name}");
        for got in [record_fingerprint(fields).unwrap(), document_fingerprint(fields).unwrap()] {
            assert_eq!(got.algorithm, s(r, "algorithm"), "{name}");
            assert_eq!(got.content_hash, s(r, "contentHash"), "{name}");
            assert_eq!(got.fingerprint, s(r, "fingerprint"), "{name}");
        }
    }
}

#[test]
fn every_refusal_is_refused() {
    for r in list(&vectors(), "refusals") {
        assert!(document_fingerprint(&r["fields"]).is_err(), "{}", s(r, "name"));
    }
}
