// SPDX-License-Identifier: Apache-2.0
//! Document records: the profile `veilcore/profile/document/v1`, per specification
//! section 11.11 (final).
//!
//! A document record dates the exact bytes of one or more files: it holds each file's
//! SHA-256, name and size, never the file. The profile changes no fingerprint rule; it only
//! says which committed fields a document record has and in what form. Fields in any other
//! form are refused, never tidied, and otherwise the fingerprint is
//! [`record_fingerprint`](crate::record_fingerprint)'s.

use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt;

use crate::form::{is_date, is_hex32, one_line, whole_number, MAX_SAFE};
use crate::key_binding::{record_fingerprint, RecordFingerprint};

/// The profile's identifier.
pub const DOCUMENT_PROFILE: &str = "veilcore/profile/document/v1";

/// The kinds of document.
pub const DOCUMENT_TYPES: [&str; 8] =
    ["permit", "certificate-of-analysis", "lab-report", "contract", "protocol", "transport", "invoice", "other"];

/// Every committed field a document record must have.
const REQUIRED: [&str; 12] =
    ["about", "files", "holder", "issued", "issuer", "loggedAt", "nonce", "notes", "profile", "reference", "title", "type"];
/// The optional ones: a key (section 3.6.1) and a field set (section 4.5).
const OPTIONAL: [&str; 3] = ["keyBinding", "fieldSchema", "fieldSetRoot"];
/// The one-line fields.
const LINES: [&str; 4] = ["title", "issuer", "reference", "holder"];

const LINE_MAX: usize = 200;
const NOTES_MAX: usize = 20_000;
const FILES_MAX: usize = 20;
const ABOUT_MAX: usize = 20;

/// A record id (section 11.8, which section 11.11 points to): 1 to 128 characters, an ASCII
/// letter or digit, then only ASCII letters, digits, `.`, `_`, `:` and `-`.
fn is_record_id(v: &Value) -> bool {
    let Some(s) = v.as_str() else { return false };
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

fn is_nonce(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        (64..=128).contains(&s.len()) && s.len() % 2 == 0 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn file_problems(files: &Value, out: &mut Vec<String>) {
    let Some(list) = files.as_array() else { return out.push("files must be a list".into()) };
    if list.is_empty() {
        return out.push("a document needs at least one file".into());
    }
    if list.len() > FILES_MAX {
        return out.push(format!("files may list at most {FILES_MAX}"));
    }
    let mut seen = HashSet::new();
    let mut repeated = false;
    for (i, x) in list.iter().enumerate() {
        let at = format!("file {}", i + 1);
        let Some(x) = x.as_object() else {
            out.push(format!("{at} must be an object"));
            continue;
        };
        for k in x.keys().filter(|k| !matches!(k.as_str(), "name" | "sha256" | "size")) {
            out.push(format!("{at}: {k} is not a file field"));
        }
        match x.get("name").map(|n| one_line(n, LINE_MAX)) {
            None => out.push(format!("{at}: name is missing")),
            Some(Err(e)) => out.push(format!("{at}: name {e}")),
            Some(Ok("")) => out.push(format!("{at}: name must not be empty")),
            Some(Ok(_)) => {}
        }
        match x.get("sha256") {
            Some(h) if is_hex32(h) => repeated |= !seen.insert(h.as_str()),
            _ => out.push(format!("{at}: sha256 must be 64 lowercase hex characters")),
        }
        if x.get("size").and_then(|n| whole_number(n, MAX_SAFE)).is_none() {
            out.push(format!("{at}: size must be a whole number of bytes, 0 or more"));
        }
    }
    if repeated {
        out.push("each file is listed once (no two with the same SHA-256)".into());
    }
}

fn about_problems(about: &Value, out: &mut Vec<String>) {
    let Some(list) = about.as_array() else { return out.push("about must be a list".into()) };
    if list.len() > ABOUT_MAX {
        return out.push(format!("about may name at most {ABOUT_MAX} records"));
    }
    for (i, a) in list.iter().enumerate() {
        let at = format!("about {}", i + 1);
        let Some(a) = a.as_object() else {
            out.push(format!("{at} must be an object"));
            continue;
        };
        for k in a.keys().filter(|k| !matches!(k.as_str(), "name" | "recordId")) {
            out.push(format!("{at}: {k} is not an about field"));
        }
        match a.get("name").map(|n| one_line(n, LINE_MAX)) {
            None => out.push(format!("{at}: name is missing")),
            Some(Err(e)) => out.push(format!("{at}: name {e}")),
            Some(Ok(name)) => {
                if name.is_empty() && !a.contains_key("recordId") {
                    out.push(format!("{at}: needs a name or a linked record"));
                }
            }
        }
        if a.get("recordId").is_some_and(|r| !is_record_id(r)) {
            out.push(format!("{at}: recordId is not a record id"));
        }
    }
}

/// What is wrong with a document record's committed fields, one sentence each; empty when
/// nothing is (section 11.11).
pub fn document_problems(fields: &Value) -> Vec<String> {
    let Some(f) = fields.as_object() else { return vec!["the fields must be an object".into()] };
    let mut out = Vec::new();
    if f.get("profile").and_then(Value::as_str) != Some(DOCUMENT_PROFILE) {
        out.push(format!("profile must be {DOCUMENT_PROFILE}"));
    }
    out.extend(REQUIRED.iter().filter(|k| !f.contains_key(**k)).map(|k| format!("{k} is missing")));
    out.extend(
        f.keys()
            .filter(|k| !REQUIRED.contains(&k.as_str()) && !OPTIONAL.contains(&k.as_str()))
            .map(|k| format!("{k} is not a field of this profile")),
    );
    for k in LINES {
        match f.get(k).map(|v| one_line(v, LINE_MAX)) {
            Some(Err(e)) => out.push(format!("{k} {e}")),
            Some(Ok("")) if matches!(k, "title" | "holder") => out.push(format!("{k} must not be empty")),
            _ => {}
        }
    }
    if let Some(t) = f.get("type") {
        if !t.as_str().is_some_and(|t| DOCUMENT_TYPES.contains(&t)) {
            out.push(format!("type must be one of {}", DOCUMENT_TYPES.join(", ")));
        }
    }
    if let Some(files) = f.get("files") {
        file_problems(files, &mut out);
    }
    if let Some(about) = f.get("about") {
        about_problems(about, &mut out);
    }
    if f.get("notes").is_some_and(|n| !n.as_str().is_some_and(|n| n.chars().count() <= NOTES_MAX)) {
        out.push(format!("notes must be text of at most {NOTES_MAX} characters"));
    }
    if f.get("issued").is_some_and(|d| d.as_str() != Some("") && !is_date(d)) {
        out.push("issued must be empty or a date written YYYY-MM-DD".into());
    }
    if f.get("loggedAt").is_some_and(|n| whole_number(n, MAX_SAFE).is_none()) {
        out.push("loggedAt must be a whole number of milliseconds, 0 or more".into());
    }
    if f.get("nonce").is_some_and(|n| !is_nonce(n)) {
        out.push("nonce must be 32 to 64 bytes of lowercase hex".into());
    }
    if f.get("keyBinding").is_some_and(|k| !is_hex32(k)) {
        out.push("keyBinding must be 64 lowercase hex characters".into());
    }
    field_set_problems(f, &mut out);
    out
}

fn field_set_problems(f: &Map<String, Value>, out: &mut Vec<String>) {
    if f.contains_key("fieldSchema") != f.contains_key("fieldSetRoot") {
        out.push("fieldSchema and fieldSetRoot come together, or neither".into());
    }
    for k in ["fieldSchema", "fieldSetRoot"] {
        if f.get(k).is_some_and(|v| !is_hex32(v)) {
            out.push(format!("{k} must be 64 lowercase hex characters"));
        }
    }
}

/// Why a document record was refused a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentError(pub Vec<String>);

impl fmt::Display for DocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a valid document record (spec 11.11): {}", self.0.join("; "))
    }
}

impl std::error::Error for DocumentError {}

/// A document record's fingerprint: its form checked (section 11.11), then exactly
/// [`record_fingerprint`].
pub fn document_fingerprint(fields: &Value) -> Result<RecordFingerprint, DocumentError> {
    let problems = document_problems(fields);
    if !problems.is_empty() {
        return Err(DocumentError(problems));
    }
    record_fingerprint(fields).map_err(|e| DocumentError(vec![e.to_string()]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> Value {
        json!({
            "profile": DOCUMENT_PROFILE, "type": "permit", "title": "Permit", "issuer": "", "reference": "",
            "issued": "", "files": [{ "name": "permit.pdf", "sha256": "ab".repeat(32), "size": 0 }],
            "about": [], "holder": "Holder", "notes": "", "loggedAt": 0, "nonce": "cd".repeat(32)
        })
    }

    #[test]
    fn the_least_a_document_record_carries() {
        assert_eq!(document_problems(&minimal()), Vec::<String>::new());
        assert!(document_fingerprint(&minimal()).is_ok());
    }

    #[test]
    fn about_by_record_id_alone_and_its_form() {
        let mut f = minimal();
        f["about"] = json!([{ "name": "", "recordId": "VEIL-0007" }]);
        assert!(document_problems(&f).is_empty());
        f["about"] = json!([{ "name": "", "recordId": "-VEIL" }]);
        assert!(!document_problems(&f).is_empty());
        f["about"] = json!([{ "name": "" }]);
        assert!(!document_problems(&f).is_empty());
    }

    #[test]
    fn notes_count_characters_not_bytes() {
        let mut f = minimal();
        f["notes"] = json!("é".repeat(NOTES_MAX));
        assert!(document_problems(&f).is_empty());
        f["notes"] = json!("é".repeat(NOTES_MAX + 1));
        assert!(!document_problems(&f).is_empty());
    }

    #[test]
    fn not_an_object() {
        assert!(document_fingerprint(&json!([])).is_err());
    }
}
