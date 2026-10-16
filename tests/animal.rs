//! Animal records (spec 11.8, a draft): their fingerprints, computed exactly as any record's.
//!
//! `vectors/animal-individual-v1.json` is a byte-for-byte copy of the file the VeilCore web
//! application publishes (its contract/vectors/animal-individual-v1.json), which veilcore-sdk's
//! shared set also carries as its animalRecords and animalRefusals sections. It was written with
//! node:crypto and a canonicaliser only. The profile changes no fingerprint rule, so this crate
//! needs no new code for it: `record_fingerprint` gives every animal record's fingerprint as
//! published. Checking the profile's own form (the refusals) is not implemented here; the SDK's
//! TypeScript and Python implementations do it.

use serde_json::Value;
use veilcore_records::{canonicalise, key_bound_fingerprint, record_fingerprint, verify_record_fingerprint};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/animal-individual-v1.json")).expect("the vector file is JSON")
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
    assert_eq!(s(&v, "profile"), "veilcore/profile/animal-individual/v1");
    assert_eq!(list(&v, "records").len(), 5);
    assert_eq!(list(&v, "refusals").len(), 25);
    let algorithms: Vec<&str> = list(&v, "records").iter().map(|r| s(r, "algorithm")).collect();
    assert!(algorithms.contains(&"sha256/key-bound/v1") && algorithms.contains(&"sha256/canonical-json/v1"));
}

#[test]
fn every_animal_record_fingerprints_as_published() {
    for r in list(&vectors(), "records") {
        let name = s(r, "name");
        let fields = &r["fields"];
        assert_eq!(s(fields, "profile"), "veilcore/profile/animal-individual/v1", "{name}");
        assert_eq!(canonicalise(fields).unwrap(), s(r, "canonical"), "{name}");
        let got = record_fingerprint(fields).unwrap();
        assert_eq!(got.algorithm, s(r, "algorithm"), "{name}");
        assert_eq!(got.content_hash, s(r, "contentHash"), "{name}");
        assert_eq!(got.fingerprint, s(r, "fingerprint"), "{name}");
        let registered = serde_json::json!({ "fields": fields, "fingerprint": r["fingerprint"], "algorithm": r["algorithm"] });
        assert!(verify_record_fingerprint(&registered), "{name}");
        match fields.get("keyBinding").and_then(Value::as_str) {
            Some(kb) => assert_eq!(key_bound_fingerprint(kb, s(r, "contentHash")).unwrap(), s(r, "fingerprint"), "{name}"),
            None => assert_eq!(got.fingerprint, got.content_hash, "{name}"),
        }
    }
}

#[test]
fn a_changed_animal_field_changes_the_fingerprint() {
    let v = vectors();
    let r = &list(&v, "records")[0];
    let mut fields = r["fields"].clone();
    fields["individualId"] = Value::from("0000000018");
    assert_ne!(record_fingerprint(&fields).unwrap().fingerprint, s(r, "fingerprint"));
    let mut fields = r["fields"].clone();
    fields["parents"][0]["individualId"] = Value::from("0000000026");
    assert_ne!(record_fingerprint(&fields).unwrap().fingerprint, s(r, "fingerprint"));
}
