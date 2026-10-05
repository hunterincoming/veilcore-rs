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
use veilcore_records::{
    attestation_payload, canonicalise, check_proof, compute_commitment, field_set_summary, fold_path, ProofStep,
};

/// Read a fold job strictly. A missing commitment, a step that is not an object, a
/// sibling that is not a string or a flag that is not a boolean is refused. This used to
/// read each of them as "" or false and fold anyway, so a malformed proof got a root.
fn read_proof(input: &Value) -> Result<(String, Vec<ProofStep>), String> {
    let commitment = input["commitment"].as_str().ok_or("the commitment is a string")?;
    let steps = input["path"].as_array().ok_or("the path is a list")?;
    let mut path = Vec::with_capacity(steps.len().min(veilcore_records::MAX_PROOF_DEPTH + 1));
    for s in steps.iter().take(veilcore_records::MAX_PROOF_DEPTH + 1) {
        let sibling = s.get("sibling").and_then(Value::as_str).ok_or("each step has a sibling string")?;
        let left = s.get("siblingIsLeft").and_then(Value::as_bool).ok_or("each step has a boolean siblingIsLeft")?;
        path.push(ProofStep { sibling: sibling.to_string(), sibling_is_left: left });
    }
    if steps.len() > veilcore_records::MAX_PROOF_DEPTH {
        return Err("proof path exceeds maximum depth (spec 5.4)".into());
    }
    check_proof(commitment, &path)?;
    Ok((commitment.to_string(), path))
}

fn main() {
    // Input this implementation cannot read is refused like any other invalid input, not
    // crashed on. serde_json refuses an unpaired surrogate escape at parse time, which is
    // the refusal spec 4.4 rule 1 asks for; it should arrive as one.
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        println!("{}", json!({ "error": format!("could not read the job: {e}"), "rejected": true }));
        return;
    }
    let job: Value = match serde_json::from_str(&input) {
        Ok(job) => job,
        Err(e) => {
            println!("{}", json!({ "error": format!("could not parse the job: {e}"), "rejected": true }));
            return;
        }
    };

    let result = match job["op"].as_str() {
        Some("canonicalise") => match canonicalise(&job["input"]) {
            Ok(s) => json!({ "result": s }),
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        Some("commit") => match compute_commitment(&job["input"]) {
            Ok(s) => json!({ "result": s }),
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        Some("attestationPayload") => match attestation_payload(&job["input"]) {
            Ok(s) => json!({ "result": s }),
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        // Fold an inclusion proof and return the root, rather than a yes or no. A
        // disagreement between two implementations is only diagnosable if each reports
        // the root it computed.
        Some("fold") => match read_proof(&job["input"]) {
            Ok((commitment, path)) => json!({ "result": fold_path(&commitment, &path) }),
            Err(e) => json!({ "error": e, "rejected": true }),
        },
        // Field sets (spec 4.5). The summary is written as text rather than through a
        // serde_json map, which would sort its keys: the runner compares the text, and the
        // vectors fix the key order.
        Some("fieldSet") => match field_set_summary(&job["input"]) {
            Ok(s) => {
                println!("{{\"result\":{}}}", s.to_json());
                return;
            }
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        other => json!({ "error": format!("unknown op {:?}", other) }),
    };

    println!("{}", result);
}
