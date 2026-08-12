//! Conformance runner.
//!
//! Reads a job on stdin, writes a result on stdout, so the published runner can test
//! this implementation exactly as it tests the TypeScript one. Neither implementation
//! knows anything about the other; both were written from the specification.

use std::io::Read;
use serde_json::{json, Value};
use veilcore_records::{canonicalise, compute_commitment};

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("read stdin");
    let job: Value = serde_json::from_str(&input).expect("parse job");

    let result = match job["op"].as_str() {
        Some("canonicalise") => json!({ "result": canonicalise(&job["input"]) }),
        Some("commit") => json!({ "result": compute_commitment(&job["input"]) }),
        other => json!({ "error": format!("unknown op {:?}", other) }),
    };

    println!("{}", result);
}
