// SPDX-License-Identifier: Apache-2.0
//! Laboratory results, version 2 (`veilcore/lab-result/v2`), per specification section
//! 11.12 (a draft).
//!
//! A version 2 result is a document record (section 11.11) with a field set (section 4.5),
//! signed by the laboratory over its record commitment. Among its files is
//! `lab-result.json`: the canonical bytes (section 4.4) of a result statement naming the
//! record the sample came from (`subject`), the sample, the method and what was found. This
//! module checks a statement's form, gives its file entry, checks that a statement binds to
//! a record, seals DNA marks, computes the laboratory's salted name binding, and decides
//! whether a viability result taken after a kill step pairs with the one taken before it.
//!
//! Signatures are not checked here: which key signed which result, and that it is the same
//! key for two results, is the caller's (section 11.12, "What a verifier shall check").

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

use crate::canonicalise;
use crate::document::document_problems;
use crate::fields::{field_schema_id, parse_hex32};
use crate::form::{is_date, is_format_char, is_hex32, one_line, only, whole_number};

/// The statement's format.
pub const LAB_RESULT_FORMAT: &str = "veilcore/lab-result/v2";
/// The name of the statement's file entry on the record.
pub const LAB_RESULT_FILE_NAME: &str = "lab-result.json";
/// The kinds of result.
pub const LAB_RESULT_KINDS: [&str; 7] = ["numbers", "pathogen", "match", "lineage", "dna-mark", "viability", "retraction"];
/// Why a result replaces an earlier one.
pub const LAB_REPLACE_REASONS: [&str; 3] = ["re-test", "correction", "retraction"];
/// The field-set form of each kind but `numbers`, whose form the statement names.
pub const LAB_CALL_SCHEMAS: [(&str, &str); 6] = [
    ("pathogen", "veilcore/schema/pathogen/v1"),
    ("match", "veilcore/schema/genetic-match/v1"),
    ("lineage", "veilcore/schema/lineage-check/v1"),
    ("dna-mark", "veilcore/schema/dna-mark/v1"),
    ("viability", "veilcore/schema/viability/v1"),
    ("retraction", "veilcore/schema/lab-retraction/v1"),
];

const QC_MAX: usize = 12;
const CULTURES_MAX: usize = 4;
const COUNT_MAX: u64 = 1_000_000_000;
const MARK_TAG: &[u8] = b"veilcore:dnamark:v1\0";
const NAME_TAG: &[u8] = b"veilcore:lab-result-binding:v2:salted\0";

type O = Map<String, Value>;

fn call_schema(kind: &str) -> Option<&'static str> {
    LAB_CALL_SCHEMAS.iter().find(|(k, _)| *k == kind).map(|(_, f)| *f)
}

/// One-line text in a statement: not empty, at most `max` characters, no control
/// character, no format character (category Cf) and no white space at either end.
fn line(v: Option<&Value>, max: usize) -> bool {
    v.and_then(|v| one_line(v, max).ok()).is_some_and(|s| !s.is_empty() && !s.chars().any(is_format_char))
}

fn hex(v: Option<&Value>) -> bool {
    v.is_some_and(is_hex32)
}

fn obj(v: Option<&Value>) -> Option<&O> {
    v.and_then(Value::as_object)
}

fn boolean(v: Option<&Value>) -> bool {
    v.is_some_and(Value::is_boolean)
}

fn date(v: Option<&Value>) -> Option<&str> {
    v.filter(|d| is_date(d)).and_then(Value::as_str)
}

/// A count: a whole number from 0 to 10^9.
fn count(v: Option<&Value>) -> Option<u64> {
    v.and_then(|v| whole_number(v, COUNT_MAX))
}

/// A method or panel: `{ id, version }`, each one line.
fn reference(v: Option<&Value>) -> bool {
    obj(v).is_some_and(|r| only(r, &["id", "version"], &[]) && line(r.get("id"), 200) && line(r.get("version"), 200))
}

/// A salt: 64 lowercase hex characters, not all one byte value.
fn is_salt(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).and_then(parse_hex32).is_some_and(|b| b.iter().any(|&x| x != b[0]))
}

/// A cycle threshold: a decimal under 100 with at most two places, no leading zero.
fn is_ct(s: &str) -> bool {
    let (w, f) = match s.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (s, None),
    };
    let whole = !w.is_empty() && w.len() <= 2 && w.bytes().all(|c| c.is_ascii_digit()) && (w == "0" || !w.starts_with('0'));
    whole && f.map_or(true, |f| (1..=2).contains(&f.len()) && f.bytes().all(|c| c.is_ascii_digit()))
}

/// A decimal as a report prints it: 1 to 15 digits, no leading zero unless it is the only
/// one, then optionally a point and 1 to 6 digits. No sign, no exponent, no separators.
fn is_decimal(s: &str) -> bool {
    let (w, f) = match s.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (s, None),
    };
    let whole = (1..=15).contains(&w.len()) && w.bytes().all(|c| c.is_ascii_digit()) && (w == "0" || !w.starts_with('0'));
    whole && f.map_or(true, |f| (1..=6).contains(&f.len()) && f.bytes().all(|c| c.is_ascii_digit()))
}

/// Zero, however many places it is written to.
fn is_zero(s: &str) -> bool {
    s.bytes().all(|c| c == b'0' || c == b'.')
}

/// A whole part that is not 0, a point, then exactly three digits ("1.000", "1234.567"):
/// read a thousand times bigger where the point separates thousands.
fn is_ambiguous(s: &str) -> bool {
    s.split_once('.').is_some_and(|(w, f)| !w.starts_with('0') && f.len() == 3)
}

/// A limit of detection or a count: `{ value, unit }`, the value a decimal above 0 that
/// cannot be read as a thousand times itself, the unit one line of at most 60 characters.
fn amount(v: Option<&Value>) -> bool {
    obj(v).is_some_and(|a| {
        only(a, &["value", "unit"], &[])
            && a["value"].as_str().is_some_and(|s| is_decimal(s) && !is_ambiguous(s) && !is_zero(s))
            && line(a.get("unit"), 60)
    })
}

fn viability_problems(r: &O, out: &mut Vec<&'static str>) {
    if !only(
        r,
        &["batch", "stage", "strain", "sampled", "target", "portion", "cultures", "lod", "detected", "controls"],
        &["killStep", "before", "count"],
    ) {
        out.push("the viability result has a missing field or one it shouldn't");
    }
    if !line(r.get("batch"), 200) {
        out.push("batch is one line");
    }
    let stage = r.get("stage").and_then(Value::as_str);
    if !matches!(stage, Some("before" | "after")) {
        out.push("stage is before or after");
    }
    let kill_ok = if stage == Some("after") { line(r.get("killStep"), 200) } else { !r.contains_key("killStep") };
    if !kill_ok {
        out.push("killStep is one line, given for an after-sample and only for it");
    }
    if r.contains_key("before") && !(stage == Some("after") && hex(r.get("before"))) {
        out.push("before is a result code, named only by an after-sample");
    }
    if !hex(r.get("strain")) {
        out.push("strain is a record's proof code");
    }
    if date(r.get("sampled")).is_none() {
        out.push("sampled is a date");
    }
    if !line(r.get("target"), 200) {
        out.push("target is one line");
    }
    if !line(r.get("portion"), 200) {
        out.push("portion is one line");
    }
    let cultures_ok = r.get("cultures").and_then(Value::as_array).is_some_and(|c| {
        (1..=CULTURES_MAX).contains(&c.len())
            && c.iter().all(|x| {
                obj(Some(x)).is_some_and(|x| {
                    only(x, &["medium", "time", "temperature"], &[])
                        && line(x.get("medium"), 200)
                        && line(x.get("time"), 60)
                        && line(x.get("temperature"), 60)
                })
            })
            // "No two the same": the same after NFC, as the canonical form writes them.
            && c.iter().filter_map(|x| canonicalise(x).ok()).collect::<HashSet<_>>().len() == c.len()
    });
    if !cultures_ok {
        out.push("cultures are 1 to 4 media, each with its time and temperature, none repeated");
    }
    if !amount(r.get("lod")) {
        out.push("lod is a decimal above 0 and its unit");
    }
    let detected = r.get("detected").and_then(Value::as_bool);
    if detected.is_none() {
        out.push("detected is true or false");
    }
    // None recovered is below the limit of detection, never a count of 0.
    if detected == Some(false) && r.contains_key("count") {
        out.push("count is left out when none were recovered");
    }
    if detected == Some(true) && r.contains_key("count") && !amount(r.get("count")) {
        out.push("count, when given, is a decimal above 0 and its unit");
    }
    let controls_ok = obj(r.get("controls")).is_some_and(|k| {
        only(k, &["positive", "positiveGrew"], &["negativeGrew"])
            && line(k.get("positive"), 200)
            && k.get("positiveGrew") == Some(&Value::Bool(true))
            && k.get("negativeGrew").map_or(true, |n| n == &Value::Bool(false))
    });
    if !controls_ok {
        out.push("controls name the positive control, which grew, and a negative control, if run, which did not");
    }
}

fn result_problems(kind: &str, subject: Option<&Value>, result: Option<&Value>, out: &mut Vec<&'static str>) {
    if kind == "retraction" {
        if result.is_some() {
            out.push("a withdrawal carries no result");
        }
        return;
    }
    let Some(r) = obj(result) else { return out.push("result is missing") };
    let other_code = |v: Option<&Value>| hex(v) && v != subject;
    match kind {
        "numbers" => {
            if !(only(r, &["form"], &[]) && line(r.get("form"), 200)) {
                out.push("a numbers result names its form");
            }
        }
        "pathogen" => {
            let ok = only(r, &["target", "sampleType", "detected"], &["ct"])
                && line(r.get("target"), 200)
                && line(r.get("sampleType"), 200)
                && boolean(r.get("detected"))
                && r.get("ct").map_or(true, |c| c.as_str().is_some_and(is_ct));
            if !ok {
                out.push("a pathogen result is a target, a sample type, detected, and optionally ct");
            }
        }
        "match" => {
            let compared = count(r.get("compared"));
            let differing = count(r.get("differing"));
            let ok = only(r, &["other", "matches"], &["otherSampleId", "compared", "differing"])
                && other_code(r.get("other"))
                && boolean(r.get("matches"))
                && (!r.contains_key("otherSampleId") || line(r.get("otherSampleId"), 200))
                && (!r.contains_key("compared") || compared.is_some_and(|c| c >= 1))
                && (!r.contains_key("differing") || differing.is_some())
                && !matches!((compared, differing), (Some(c), Some(d)) if d > c);
            if !ok {
                out.push("a match result names another record, the call, and counts that fit");
            }
        }
        "lineage" => {
            let parents = r.get("parents").and_then(Value::as_array);
            let compared = count(r.get("compared"));
            let parents_ok = parents.is_some_and(|p| {
                (1..=2).contains(&p.len())
                    && p.iter().all(|x| other_code(Some(x)))
                    && p.iter().filter_map(Value::as_str).collect::<HashSet<_>>().len() == p.len()
            });
            let conflicts_ok = match r.get("conflicts") {
                None => true,
                Some(c) => c.as_array().is_some_and(|c| {
                    parents.is_some_and(|p| p.len() == c.len())
                        && c.iter().all(|x| count(Some(x)).is_some_and(|x| compared.map_or(true, |m| x <= m)))
                }),
            };
            let ok = only(r, &["parents", "consistent"], &["compared", "conflicts"])
                && parents_ok
                && boolean(r.get("consistent"))
                && (!r.contains_key("compared") || compared.is_some_and(|c| c >= 1))
                && conflicts_ok;
            if !ok {
                out.push("a lineage result names one or two other records, the call, and counts that fit");
            }
        }
        "dna-mark" => {
            let label_ok = r.get("label").map_or(true, |l| line(Some(l), 200) && !l.as_str().is_some_and(has_sequence_run));
            if !(only(r, &["seal", "found"], &["label"]) && hex(r.get("seal")) && boolean(r.get("found")) && label_ok) {
                out.push("a DNA-mark result is a seal, found, and a label that is not a sequence");
            }
        }
        "viability" => viability_problems(r, out),
        _ => {}
    }
}

/// Ten or more of A, C, G, T in a row, in either case: a label that could be the mark.
fn has_sequence_run(s: &str) -> bool {
    let mut run = 0;
    for c in s.chars() {
        run = if matches!(c.to_ascii_uppercase(), 'A' | 'C' | 'G' | 'T') { run + 1 } else { 0 };
        if run >= 10 {
            return true;
        }
    }
    false
}

/// What is wrong with a result statement, one sentence each; empty when nothing is
/// (section 11.12, "The result statement" and "Results, by kind").
pub fn lab_statement_problems(statement: &Value) -> Vec<&'static str> {
    let Some(s) = statement.as_object() else { return vec!["a statement is an object"] };
    let mut out = Vec::new();
    if s.get("format").and_then(Value::as_str) != Some(LAB_RESULT_FORMAT) {
        out.push("format must be veilcore/lab-result/v2");
    }
    if !only(
        s,
        &["format", "kind", "subject", "sampleId", "accession", "method", "tested"],
        &["panel", "received", "qc", "result", "replaces", "bindingSalt"],
    ) {
        out.push("the statement has a missing field or one it shouldn't");
    }
    let kind = s.get("kind").and_then(Value::as_str).filter(|k| LAB_RESULT_KINDS.contains(k));
    if kind.is_none() {
        out.push("kind is not one of the kinds");
    }
    if !hex(s.get("subject")) {
        out.push("subject is 64 lowercase hex characters");
    }
    if !line(s.get("sampleId"), 200) {
        out.push("sampleId is one line");
    }
    if !line(s.get("accession"), 200) {
        out.push("accession is one line");
    }
    if !reference(s.get("method")) {
        out.push("method is an id and a version");
    }
    if s.contains_key("panel") && !reference(s.get("panel")) {
        out.push("panel is an id and a version");
    }
    let tested = date(s.get("tested"));
    if tested.is_none() {
        out.push("tested is a date");
    }
    let received = date(s.get("received"));
    if s.contains_key("received") && !matches!((received, tested), (Some(r), Some(t)) if r <= t) {
        out.push("received is a date, not after tested");
    }
    if let Some(q) = s.get("qc") {
        let ok = q.as_array().is_some_and(|q| {
            (1..=QC_MAX).contains(&q.len())
                && q.iter().all(|x| {
                    obj(Some(x)).is_some_and(|x| only(x, &["name", "value"], &[]) && line(x.get("name"), 60) && line(x.get("value"), 60))
                })
                && q.iter().filter_map(|x| x["name"].as_str()).collect::<HashSet<_>>().len() == q.len()
        });
        if !ok {
            out.push("qc is 1 to 12 names and values, names not repeated");
        }
    }
    if s.contains_key("bindingSalt") && !is_salt(s.get("bindingSalt")) {
        out.push("bindingSalt is 64 lowercase hex characters, not all one byte value");
    }
    if let Some(kind) = kind {
        result_problems(kind, s.get("subject"), s.get("result"), &mut out);
    }
    // A sample is not taken after it is received or tested.
    if kind == Some("viability") {
        if let (Some(sampled), Some(tested)) = (date(s.get("result").and_then(|r| r.get("sampled"))), tested) {
            if sampled > tested || received.is_some_and(|r| sampled > r) {
                out.push("sampled is not after received or tested");
            }
        }
    }
    let replaces = s.get("replaces");
    if let Some(rep) = replaces {
        let ok = obj(Some(rep)).is_some_and(|r| {
            only(r, &["result", "reason"], &[])
                && hex(r.get("result"))
                && r.get("reason").and_then(Value::as_str).is_some_and(|x| LAB_REPLACE_REASONS.contains(&x))
        });
        if !ok {
            out.push("replaces is a result code and a reason");
        }
    }
    let reason = replaces.and_then(|r| r.get("reason")).and_then(Value::as_str);
    if (s.get("kind").and_then(Value::as_str) == Some("retraction")) != (reason == Some("retraction")) {
        out.push("a withdrawal, and only a withdrawal, names a result with the reason retraction");
    }
    out
}

/// Why a statement, a binding, a mark or a pair was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabError(pub Vec<String>);

impl LabError {
    fn of<S: ToString>(problems: &[S]) -> Self {
        LabError(problems.iter().map(ToString::to_string).collect())
    }
    fn one(why: &str) -> Self {
        LabError(vec![why.to_string()])
    }
}

impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (spec 11.12)", self.0.join("; "))
    }
}

impl std::error::Error for LabError {}

/// The file entry a record carries for a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabStatementFile {
    /// Always `lab-result.json`.
    pub name: &'static str,
    /// SHA-256 of the statement's canonical bytes, hex.
    pub sha256: String,
    /// The number of those bytes.
    pub size: u64,
}

/// A statement's file entry: its form checked, then the SHA-256 and size of its canonical
/// serialisation (section 4.4) in UTF-8.
pub fn lab_statement_file(statement: &Value) -> Result<LabStatementFile, LabError> {
    let problems = lab_statement_problems(statement);
    if !problems.is_empty() {
        return Err(LabError::of(&problems));
    }
    let bytes = canonicalise(statement).map_err(|e| LabError::one(&e.to_string()))?;
    Ok(LabStatementFile {
        name: LAB_RESULT_FILE_NAME,
        sha256: crate::sha256_hex(&bytes),
        size: bytes.len() as u64,
    })
}

/// The field-set values a statement's call makes, as decimal text, absent slots `None`
/// (section 11.12, "Binding", the table). `None` for a `numbers` result, whose values are
/// the laboratory's own under its form. The statement is taken as already checked.
pub fn lab_call_values(statement: &Value) -> Option<[Option<String>; 16]> {
    let mut v: [Option<String>; 16] = Default::default();
    let r = &statement["result"];
    let b = |x: &Value| Some(if x.as_bool() == Some(true) { "1" } else { "0" }.to_string());
    let n = |x: &Value| count(Some(x)).map(|c| c.to_string());
    match statement["kind"].as_str()? {
        "pathogen" => {
            v[0] = b(&r["detected"]);
            if let Some(ct) = r["ct"].as_str() {
                let (w, f) = ct.split_once('.').unwrap_or((ct, ""));
                let hundredths: u64 = format!("{f:0<2}").parse().ok()?;
                v[1] = Some((w.parse::<u64>().ok()? * 100 + hundredths).to_string());
            }
        }
        "match" => {
            v[0] = b(&r["matches"]);
            v[1] = n(&r["compared"]);
            v[2] = n(&r["differing"]);
        }
        "lineage" => {
            v[0] = b(&r["consistent"]);
            v[1] = n(&r["compared"]);
            v[2] = n(&r["conflicts"][0]);
            v[3] = n(&r["conflicts"][1]);
        }
        "dna-mark" => v[0] = b(&r["found"]),
        "viability" => {
            v[0] = b(&r["detected"]);
            v[1] = Some(if r["stage"] == "after" { "1" } else { "0" }.to_string());
        }
        "retraction" => v[0] = Some("1".to_string()),
        _ => return None,
    }
    Some(v)
}

/// What stops a statement from binding to a record (section 11.12, "Binding"); empty when
/// it binds. `fields` are the record's committed fields, `values` the field set's sixteen
/// values (decimal text or null), and `schemas` the published schema documents by id.
/// The field set's root and the laboratory's signature are not checked here.
pub fn lab_binding_problems(fields: &Value, statement: &Value, values: &Value, schemas: &Value) -> Vec<String> {
    let want = match lab_statement_file(statement) {
        Ok(w) => w,
        Err(e) => return e.0,
    };
    let mut out = document_problems(fields);
    if !out.is_empty() {
        return out;
    }
    let (f, s) = (&fields, &statement);
    if f["type"] != "lab-report" {
        out.push("type must be lab-report".into());
    }
    let entries: Vec<&Value> = f["files"].as_array().into_iter().flatten().filter(|x| x["name"] == LAB_RESULT_FILE_NAME).collect();
    match entries.as_slice() {
        [e] if e["sha256"] == want.sha256.as_str() && whole_number(&e["size"], u64::MAX) == Some(want.size) => {}
        [_] => out.push("the statement file's SHA-256 or size is not the statement's".into()),
        _ => out.push(format!("exactly one file is named {LAB_RESULT_FILE_NAME}")),
    }
    if f["issued"] != s["tested"] {
        out.push("issued is the date tested".into());
    }
    let about = f["about"].as_array().map(Vec::as_slice).unwrap_or_default();
    if !matches!(about, [a] if a["name"] == s["sampleId"] && a.get("recordId").is_none()) {
        out.push("about names the sample ID, and only it".into());
    }
    if f["reference"] != s["accession"] {
        out.push("reference is the accession number".into());
    }
    if f["issuer"] != f["holder"] {
        out.push("issuer and holder are both the laboratory's name, the same".into());
    }
    let Some(field_schema) = f.get("fieldSchema").and_then(Value::as_str) else {
        out.push("a laboratory result carries a field set".into());
        return out;
    };
    let kind = s["kind"].as_str().unwrap_or_default();
    let form = match call_schema(kind) {
        Some(form) => form,
        None => {
            let form = s["result"]["form"].as_str().unwrap_or_default();
            if LAB_CALL_SCHEMAS.iter().any(|(_, f)| *f == form) {
                out.push("a numbers result is not under a call form".into());
                return out;
            }
            form
        }
    };
    match schemas.get(form).map(field_schema_id) {
        None => {
            out.push(format!("no schema document for {form}"));
            return out;
        }
        Some(Err(e)) => out.push(format!("the schema document for {form} is not a schema: {e}")),
        Some(Ok(id)) if crate::hex(&id) != field_schema => out.push("fieldSchema is not the id of the kind's form".into()),
        Some(Ok(_)) => {}
    }
    let Some(values) = values.as_array().filter(|v| v.len() == 16) else {
        out.push("values are sixteen".into());
        return out;
    };
    if let Some(want) = lab_call_values(statement) {
        let agrees = want.iter().zip(values).all(|(w, v)| match w {
            Some(w) => v.as_str() == Some(w.as_str()),
            None => v.is_null(),
        });
        if !agrees {
            out.push("the field set's values do not agree with the statement".into());
        }
    }
    out
}

/// `seal = hex(SHA-256("veilcore:dnamark:v1" || 0x00 || salt || sequence))`: a DNA mark,
/// sealed. The sequence is 10 to 100,000 of `A`, `C`, `G`, `T`, upper case, and nothing else.
pub fn dna_mark_seal(sequence: &str, salt: &str) -> Result<String, LabError> {
    if !(10..=100_000).contains(&sequence.len()) || !sequence.bytes().all(|c| matches!(c, b'A' | b'C' | b'G' | b'T')) {
        return Err(LabError::one("a mark is 10 to 100,000 of A, C, G and T"));
    }
    let salt = parse_hex32(salt).ok_or_else(|| LabError::one("the salt is 64 lowercase hex characters"))?;
    let mut h = Sha256::new();
    h.update(MARK_TAG);
    h.update(salt);
    h.update(sequence.as_bytes());
    Ok(crate::hex(&h.finalize()))
}

/// The laboratory's salted name binding on a result:
/// `hex(SHA-256("veilcore:lab-result-binding:v2:salted" || 0x00 || key || subject || bindingSalt))`.
/// `key` is the signing key as the result file carries it, x then y (128 hex characters).
pub fn lab_name_binding(key: &str, subject: &str, binding_salt: &str) -> Result<String, LabError> {
    let key_ok = key.len() == 128 && key.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    let (Some(x), Some(y)) = (key_ok.then(|| parse_hex32(&key[..64])).flatten(), key_ok.then(|| parse_hex32(&key[64..])).flatten())
    else {
        return Err(LabError::one("the key is 128 lowercase hex characters, x then y"));
    };
    let subject = parse_hex32(subject).ok_or_else(|| LabError::one("the subject is 64 lowercase hex characters"))?;
    if !is_salt(Some(&Value::from(binding_salt))) {
        return Err(LabError::one("the salt is 64 lowercase hex characters, not all one byte value"));
    }
    let salt = parse_hex32(binding_salt).expect("checked as a salt");
    let mut h = Sha256::new();
    for part in [NAME_TAG, &x, &y, &subject, &salt] {
        h.update(part);
    }
    Ok(crate::hex(&h.finalize()))
}

/// Whether `later` replaces (or, for the reason `retraction`, withdraws) `earlier` (section
/// 11.12, "Replacing"): it names it, for the same subject, not tested before it, and
/// `earlier` does not name `later` back. That both are signed by the same key is the
/// caller's to check.
fn replaces(later: &Value, later_code: &str, earlier: &Value, earlier_code: &str) -> bool {
    later["replaces"].is_object()
        && later["replaces"]["result"] == earlier_code
        && later_code != earlier_code
        && later["subject"] == earlier["subject"]
        && later["tested"].as_str() >= earlier["tested"].as_str()
        && earlier["replaces"]["result"] != later_code
}

/// One result a verifier holds besides the two of a pair: its statement and its code.
#[derive(Debug, Clone)]
pub struct HeldResult<'a> {
    pub statement: &'a Value,
    pub code: &'a str,
}

/// What stops an after-sample's viability result from pairing with the before-sample
/// result it names (section 11.12, "The pair"); empty when they pair. `before_code` and
/// `after_code` are the two results' codes. `held` are the other results the verifier holds,
/// signed by the same key (the caller's check): one that replaces or withdraws either result
/// breaks the pair, and so does either of the two replacing the other. Statements in `held`
/// that are not in their form are not results, and are passed over.
pub fn lab_viability_pair_problems(
    after: &Value,
    before: &Value,
    before_code: &str,
    after_code: Option<&str>,
    held: &[HeldResult<'_>],
) -> Vec<String> {
    let mut out: Vec<String> = lab_statement_problems(after).into_iter().chain(lab_statement_problems(before)).map(String::from).collect();
    if !out.is_empty() {
        return out;
    }
    if after["kind"] != "viability" || before["kind"] != "viability" {
        return vec!["both are viability results".into()];
    }
    let (ar, br) = (&after["result"], &before["result"]);
    if ar["stage"] != "after" || br["stage"] != "before" {
        out.push("one is an after-sample and the other a before-sample".into());
    }
    if ar["before"] != before_code {
        out.push("the after-sample does not name this result".into());
    }
    if ar["batch"] != br["batch"] {
        out.push("the batch is not the same".into());
    }
    if ar["strain"] != br["strain"] {
        out.push("the strain record is not the same".into());
    }
    if ar["target"] != br["target"] {
        out.push("the two tests recover different things (target)".into());
    }
    if br["sampled"].as_str() > ar["sampled"].as_str() {
        out.push("the before-sample was taken after the after-sample".into());
    }
    if replaces(after, after_code.unwrap_or_default(), before, before_code) {
        out.push("the after-sample's result replaces the before-sample's".into());
    }
    if let Some(ac) = after_code {
        if replaces(before, before_code, after, ac) {
            out.push("the before-sample's result replaces the after-sample's".into());
        }
    }
    for h in held {
        if !lab_statement_problems(h.statement).is_empty() {
            continue;
        }
        let how = if h.statement["replaces"]["reason"] == "retraction" { "withdrawn" } else { "replaced" };
        if replaces(h.statement, h.code, before, before_code) {
            out.push(format!("the before-sample's result was {how}"));
        }
        if let Some(ac) = after_code {
            if replaces(h.statement, h.code, after, ac) {
                out.push(format!("the after-sample's result was {how}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals_as_a_report_prints_them() {
        for ok in ["0", "1", "1.5", "0.125", "1000", "1234.5670", "999999999999999.999999"] {
            assert!(is_decimal(ok), "{ok}");
        }
        for bad in ["", ".5", "1.", "01", "1,000", "1 000", "-1", "+1", "1e3", "1.1234567", "1000000000000000", "１"] {
            assert!(!is_decimal(bad), "{bad}");
        }
        for amb in ["1.000", "12.500", "1234.567", "1000.000"] {
            assert!(is_ambiguous(amb), "{amb}");
        }
        for plain in ["0.125", "1.5", "1.0000", "1000"] {
            assert!(!is_ambiguous(plain), "{plain}");
        }
        assert!(is_zero("0") && is_zero("0.000") && !is_zero("0.001"));
    }

    #[test]
    fn cycle_thresholds() {
        for ok in ["0", "9", "31.5", "99.99", "0.5"] {
            assert!(is_ct(ok), "{ok}");
        }
        for bad in ["100", "05", "31.", "31.555", ".5", "-1", ""] {
            assert!(!is_ct(bad), "{bad}");
        }
    }

    #[test]
    fn a_label_is_not_a_sequence() {
        assert!(has_sequence_run("acgtacgtac"));
        assert!(!has_sequence_run("mark ACGTACGTA 7"));
    }

    #[test]
    fn salts_are_not_one_byte_repeated() {
        assert!(!is_salt(Some(&Value::from("ab".repeat(32)))));
        assert!(is_salt(Some(&Value::from(format!("{}cd", "ab".repeat(31))))));
    }
}
