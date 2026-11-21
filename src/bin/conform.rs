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
    attestation_payload, binding_for_secret, canonicalise, check_proof, compute_commitment, dna_mark_seal,
    dna_pair_binding, document_fingerprint, field_set_summary, fold_path, key_matches_record, lab_binding_problems,
    lab_name_binding, lab_statement_file, lab_viability_pair_problems, record_fingerprint, HeldResult, ProofStep,
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

/// `{"result": true}` when nothing stops it, else a refusal giving every reason.
fn refused_or_true(problems: Vec<String>) -> Value {
    if problems.is_empty() {
        json!({ "result": true })
    } else {
        json!({ "error": format!("{} (spec 11.12)", problems.join("; ")), "rejected": true })
    }
}

/// Read a viability pair job's codes and held results strictly: a code that is not text,
/// or a held result without a statement and a code, is refused rather than read as "".
fn read_pair(input: &Value) -> Result<(&str, Option<&str>, Vec<HeldResult<'_>>), String> {
    let before_code = input["beforeCode"].as_str().ok_or("beforeCode is text")?;
    let after_code = match input.get("afterCode") {
        None => None,
        Some(c) => Some(c.as_str().ok_or("afterCode is text")?),
    };
    let held = match input.get("held") {
        None => Vec::new(),
        Some(h) => h
            .as_array()
            .ok_or("held is a list")?
            .iter()
            .map(|h| match (h.get("statement"), h["code"].as_str()) {
                (Some(statement), Some(code)) => Ok(HeldResult { statement, code }),
                _ => Err("each held result has a statement and a code".to_string()),
            })
            .collect::<Result<_, _>>()?,
    };
    Ok((before_code, after_code, held))
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
        // A report paired on a ledger (spec 3.7): the binding the pairing publishes.
        Some("dnaPair") => {
            let i = &job["input"];
            let field = |k: &str| i[k].as_str().unwrap_or("");
            match dna_pair_binding(field("reportHash"), field("identity"), field("salt")) {
                Ok(s) => json!({ "result": s }),
                Err(e) => json!({ "error": e, "rejected": true }),
            }
        }
        // A record that names its own key (spec 3.6.1): the key from its secret, the
        // fingerprint of committed fields old and new, and whether a key is the record's.
        Some("keyFromSecret") => match binding_for_secret(job["input"]["recordSecret"].as_str().unwrap_or("")) {
            Ok(k) => json!({ "result": { "identity": k.identity, "keySalt": k.key_salt, "keyBinding": k.key_binding } }),
            Err(e) => json!({ "error": e, "rejected": true }),
        },
        Some("recordFingerprint") => match record_fingerprint(&job["input"]) {
            Ok(r) => json!({ "result": { "algorithm": r.algorithm, "contentHash": r.content_hash, "fingerprint": r.fingerprint } }),
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        // Malformed input is a key that does not match, not an error.
        Some("keyMatch") => {
            let i = &job["input"];
            let field = |k: &str| i[k].as_str().unwrap_or("");
            json!({ "result": key_matches_record(field("identity"), field("fingerprint"), field("keySalt"), field("contentHash")) })
        }
        // Document records (spec 11.11): the profile's form checked, then the fingerprint.
        Some("documentFingerprint") => match document_fingerprint(&job["input"]) {
            Ok(r) => json!({ "result": { "algorithm": r.algorithm, "contentHash": r.content_hash, "fingerprint": r.fingerprint } }),
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        // Laboratory results, version 2 (spec 11.12).
        Some("labStatement") => match lab_statement_file(&job["input"]) {
            Ok(f) => json!({ "result": { "name": f.name, "sha256": f.sha256, "size": f.size } }),
            Err(e) => json!({ "error": e.to_string(), "rejected": true }),
        },
        Some("labBinding") => {
            let i = &job["input"];
            refused_or_true(lab_binding_problems(&i["fields"], &i["statement"], &i["values"], &i["schemas"]))
        }
        Some("dnaMarkSeal") => {
            let i = &job["input"];
            match (i["sequence"].as_str(), i["salt"].as_str()) {
                (Some(seq), Some(salt)) => match dna_mark_seal(seq, salt) {
                    Ok(s) => json!({ "result": s }),
                    Err(e) => json!({ "error": e.to_string(), "rejected": true }),
                },
                _ => json!({ "error": "the sequence and the salt are text", "rejected": true }),
            }
        }
        Some("labNameBinding") => {
            let i = &job["input"];
            match (i["key"].as_str(), i["subject"].as_str(), i["salt"].as_str()) {
                (Some(key), Some(subject), Some(salt)) => match lab_name_binding(key, subject, salt) {
                    Ok(s) => json!({ "result": s }),
                    Err(e) => json!({ "error": e.to_string(), "rejected": true }),
                },
                _ => json!({ "error": "the key, the subject and the salt are text", "rejected": true }),
            }
        }
        Some("labViabilityPair") => match read_pair(&job["input"]) {
            Ok((before_code, after_code, held)) => refused_or_true(lab_viability_pair_problems(
                &job["input"]["after"],
                &job["input"]["before"],
                before_code,
                after_code,
                &held,
            )),
            Err(e) => json!({ "error": e, "rejected": true }),
        },
        other => json!({ "error": format!("unknown op {:?}", other) }),
    };

    println!("{}", result);
}
