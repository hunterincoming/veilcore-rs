// SPDX-License-Identifier: Apache-2.0
//! Laboratory results, version 2 (spec 11.12, a draft): every vector.
//!
//! `vectors/lab-result-v2.json` is a byte-for-byte copy of veilcore-sdk's
//! conformance/lab-result-v2.json, computed there by conformance/lab-result-vectors.mjs with
//! node:crypto and the canonicaliser only.

use serde_json::Value;
use veilcore_records::{
    dna_mark_seal, lab_binding_problems, lab_name_binding, lab_statement_file, lab_viability_pair_problems, HeldResult,
    LAB_RESULT_FILE_NAME,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/lab-result-v2.json")).expect("the vector file is JSON")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} is a string"))
}

fn list<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap_or_else(|| panic!("{k} is a list"))
}

/// A vector's statement. One with `statementText` is the statement as written (`12.0`, `1e1`,
/// `1e400`), parsed here as any JSON reader would; text a reader cannot parse is refused.
fn statement(v: &Value) -> Result<Value, String> {
    match v.get("statementText") {
        Some(t) => serde_json::from_str(t.as_str().expect("statementText is a string")).map_err(|e| e.to_string()),
        None => Ok(v["statement"].clone()),
    }
}

#[test]
fn the_vector_file_is_whole() {
    let v = vectors();
    let sections = [
        "labStatements",
        "labStatementRefusals",
        "labBindings",
        "markSeals",
        "markRefusals",
        "labNameBindings",
        "labNameBindingRefusals",
        "labViabilityPairs",
    ];
    let counts: Vec<usize> = sections.iter().map(|k| list(&v, k).len()).collect();
    assert_eq!(counts, [28, 82, 39, 3, 5, 4, 3, 20]);
    assert_eq!(counts.iter().sum::<usize>(), 184);
}

#[test]
fn every_statement_and_its_file_entry() {
    for v in list(&vectors(), "labStatements") {
        let st = statement(v).unwrap_or_else(|e| panic!("{}: {e}", s(v, "name")));
        let f = lab_statement_file(&st).unwrap_or_else(|e| panic!("{}: {e}", s(v, "name")));
        assert_eq!((f.name, f.sha256.as_str(), f.size), (LAB_RESULT_FILE_NAME, s(v, "sha256"), v["size"].as_u64().unwrap()));
    }
}

#[test]
fn every_statement_refusal_is_refused() {
    for v in list(&vectors(), "labStatementRefusals") {
        assert!(statement(v).map_or(true, |st| lab_statement_file(&st).is_err()), "{}", s(v, "name"));
    }
}

#[test]
fn every_binding_binds_or_is_refused() {
    let all = vectors();
    for v in list(&all, "labBindings") {
        let st = statement(v).unwrap_or_else(|e| panic!("{}: {e}", s(v, "name")));
        let problems = lab_binding_problems(&v["fields"], &st, &v["values"], &all["schemas"]);
        assert_eq!(problems.is_empty(), v["bound"].as_bool().unwrap(), "{}: {problems:?}", s(v, "name"));
    }
}

#[test]
fn every_mark_seal_and_refusal() {
    let all = vectors();
    for v in list(&all, "markSeals") {
        assert_eq!(dna_mark_seal(s(v, "sequence"), s(v, "salt")).unwrap(), s(v, "seal"), "{}", s(v, "name"));
    }
    for v in list(&all, "markRefusals") {
        assert!(dna_mark_seal(s(v, "sequence"), s(v, "salt")).is_err(), "{}", s(v, "name"));
    }
}

#[test]
fn every_name_binding_and_refusal() {
    let all = vectors();
    for v in list(&all, "labNameBindings") {
        assert_eq!(lab_name_binding(s(v, "key"), s(v, "subject"), s(v, "salt")).unwrap(), s(v, "nameBinding"), "{}", s(v, "name"));
    }
    for v in list(&all, "labNameBindingRefusals") {
        assert!(lab_name_binding(s(v, "key"), s(v, "subject"), s(v, "salt")).is_err(), "{}", s(v, "name"));
    }
}

#[test]
fn every_viability_pair_pairs_or_does_not() {
    for v in list(&vectors(), "labViabilityPairs") {
        let held: Vec<HeldResult<'_>> = v["held"]
            .as_array()
            .map(|h| h.iter().map(|h| HeldResult { statement: &h["statement"], code: s(h, "code") }).collect())
            .unwrap_or_default();
        let problems = lab_viability_pair_problems(&v["after"], &v["before"], s(v, "beforeCode"), Some(s(v, "afterCode")), &held);
        assert_eq!(problems.is_empty(), v["paired"].as_bool().unwrap(), "{}: {problems:?}", s(v, "name"));
    }
}
