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
use veilcore_records::{canonicalise, compute_commitment, fold_path, ProofStep, MAX_PROOF_DEPTH};

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
        // Fold an inclusion proof and return the root, rather than a yes or no. A
        // disagreement between two implementations is only diagnosable if each reports
        // the root it computed.
        Some("fold") => {
            let commitment = job["input"]["commitment"].as_str().unwrap_or("");
            let steps = job["input"]["path"].as_array().cloned().unwrap_or_default();

            if steps.len() > MAX_PROOF_DEPTH {
                json!({
                    "error": "proof path exceeds maximum depth (spec 5.4)",
                    "rejected": true
                })
            } else {
                let path: Vec<ProofStep> = steps
                    .iter()
                    .map(|s| ProofStep {
                        sibling: s["sibling"].as_str().unwrap_or("").to_string(),
                        sibling_is_left: s["siblingIsLeft"].as_bool().unwrap_or(false),
                    })
                    .collect();
                json!({ "result": fold_path(commitment, &path) })
            }
        }
        other => json!({ "error": format!("unknown op {:?}", other) }),
    };

    println!("{}", result);
}
