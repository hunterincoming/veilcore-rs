// SPDX-License-Identifier: Apache-2.0
//! Record ids and white space in the profiles (spec 11.8, used by 11.9 and 11.11): every vector
//! this crate is asked to check.
//!
//! `vectors/profile-forms-v1.json` is a byte-for-byte copy of veilcore-sdk's
//! conformance/profile-forms-v1.json. Each case is a record of the animal, strain or document
//! profile with one `recordId` or one line of text changed. Document cases are checked in full.
//! This crate does not check the animal or strain profile's own form (spec 11.8 and 11.9 say the
//! Rust implementation computes those records' fingerprints), so for those it checks the
//! fingerprints of the cases that stand, and leaves their refusals to the SDK.

use serde_json::Value;
use veilcore_records::{canonicalise, document_fingerprint, record_fingerprint};

fn vectors() -> Vec<Value> {
    let v: Value = serde_json::from_str(include_str!("vectors/profile-forms-v1.json")).expect("the vector file is JSON");
    v["profileForms"].as_array().expect("profileForms is a list").clone()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} is a string"))
}

#[test]
fn the_vector_file_is_whole() {
    let v = vectors();
    let count = |p: &str| v.iter().filter(|c| c["profile"] == p).count();
    assert_eq!((v.len(), count("document"), count("animal"), count("strain")), (41, 29, 6, 6));
}

#[test]
fn every_document_case_stands_or_is_refused() {
    for c in vectors().iter().filter(|c| c["profile"] == "document") {
        let name = s(c, "name");
        let got = document_fingerprint(&c["fields"]);
        if c["refused"] == true {
            assert!(got.is_err(), "{name}");
        } else {
            let got = got.unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(canonicalise(&c["fields"]).unwrap(), s(c, "canonical"), "{name}");
            assert_eq!(got.algorithm, s(c, "algorithm"), "{name}");
            assert_eq!(got.content_hash, s(c, "contentHash"), "{name}");
            assert_eq!(got.fingerprint, s(c, "fingerprint"), "{name}");
        }
    }
}

#[test]
fn every_animal_and_strain_case_that_stands_has_its_fingerprint() {
    for c in vectors().iter().filter(|c| c["profile"] != "document" && c["refused"] == false) {
        let name = s(c, "name");
        let got = record_fingerprint(&c["fields"]).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(got.fingerprint, s(c, "fingerprint"), "{name}");
    }
}
