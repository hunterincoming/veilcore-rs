//! Conformance runner.
//!
//! Reads a job on stdin, writes a result on stdout, so the published runner can test
//! this implementation exactly as it tests the TypeScript one. Neither implementation
//! knows anything about the other; both were written from the specification.
//!
//! A refused record is reported as an error rather than crashing the runner. That is
//! what lets the vector set's `rejections` section be run against this implementation:
//! a suite that only tests agreement on valid input can never catch disagreement about
//! what is invalid.

use std::io::Read;
use serde_json::{json, Value};
use veilcore_records::{canonicalise, compute_commitment};

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("read stdin");
    let job: Value = serde_json::from_str(&input).expect("parse job");

    let result = match job["op"].as_str() {
        Some("canonicalise") => match canonicalise(&job["input"]) {
            Ok(s) => json!({ "result": s }),
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        Some("commit") => match compute_commitment(&job["input"]) {
            Ok(s) => json!({ "result": s }),
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        other => json!({ "error": format!("unknown op {:?}", other) }),
    };

    println!("{}", result);
}
