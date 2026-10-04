//! Field sets: commitment algorithm `sha256/fields/v1`, per specification section 4.5.
//!
//! A record sealed this way commits each of 16 slots as a salted leaf under one root, and
//! binds that root into the record commitment. A holder can later prove one fact about
//! one slot - that it holds a value, that a number meets a bound - without disclosing the
//! rest. The proofs run on Midnight; everything here is plain SHA-256, so sealing a field
//! set and checking a commitment needs nothing else.
//!
//! Most hashes are SHA-256 over a sequence of 32-byte elements, the first of which is a
//! domain tag: an ASCII string right-padded with zero bytes to 32. A leaf is SHA-256 of
//! the value and a 23-byte salt (55 bytes, one block) and the set root is SHA-256 of a
//! 16-byte tag, the schema id and the 16 leaves (560 bytes); no other hash takes those
//! lengths. Compact's `persistentHash` hashes exactly these byte strings, which is what
//! lets the claims contract recompute the same values in-circuit, and the layout keeps
//! the in-circuit cost low enough to prove on an ordinary computer.

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{canonicalise, hex};

/// The commitment algorithm name for records that bind a field set.
pub const FIELDS_ALGORITHM: &str = "sha256/fields/v1";

/// Every field set has exactly this many slots.
pub const FIELD_SLOTS: usize = 16;

/// A slot salt: the first 23 bytes of `H("veilcore:v1:fsalt", fieldSecret, slot)`.
pub type Salt = [u8; 23];

/// One element: a slot value, a salt, a node, a root.
pub type Bytes32 = [u8; 32];

/// An absent slot. A present number never has this value, because of its marker byte.
pub const ABSENT_VALUE: Bytes32 = [0u8; 32];

/// Why a field set was refused.
///
/// As with [`crate::CanonicalError`], a refusal is returned to the caller, never a panic:
/// a holder or registry handed a malformed schema or value must be able to say no and
/// carry on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError(pub String);

impl FieldError {
    fn new(s: impl Into<String>) -> Self {
        FieldError(s.into())
    }
}

impl std::fmt::Display for FieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FieldError {}

impl From<crate::CanonicalError> for FieldError {
    fn from(e: crate::CanonicalError) -> Self {
        FieldError(e.to_string())
    }
}

// ---- primitives ----

fn sha256(bytes: &[u8]) -> Bytes32 {
    Sha256::digest(bytes).into()
}

/// Exactly 64 lowercase hexadecimal characters, as 32 bytes. Anything else is `None`:
/// uppercase hex is refused rather than folded, so one value has one spelling.
pub fn parse_hex32(s: &str) -> Option<Bytes32> {
    let b = s.as_bytes();
    if b.len() != 64 || !b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let nibble = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
    }
    Some(out)
}

/// A domain tag: the ASCII name right-padded with zeros to 32 bytes.
fn tag(t: &str) -> Bytes32 {
    let e = t.as_bytes();
    assert!(e.len() <= 32, "tag too long: {t}");
    let mut b = [0u8; 32];
    b[..e.len()].copy_from_slice(e);
    b
}

/// SHA-256 over 32-byte elements, concatenated (Compact's `persistentHash` over
/// `Vector<n, Bytes<32>>`).
pub fn hash_elements(parts: &[&Bytes32]) -> Bytes32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A count, mask or index as 32 bytes, little-endian. Not a slot value.
pub fn count_bytes(n: u64) -> Bytes32 {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&n.to_le_bytes());
    b
}

/// An unsigned 64-bit slot value: little-endian in bytes 0-7, byte 8 set to 1.
///
/// Without the marker the number 0 and an absent slot would be the same 32 bytes, and a
/// record with no test result could prove "at most 0.3%".
pub fn number_slot_value(n: u64) -> Bytes32 {
    let mut b = count_bytes(n);
    b[8] = 1;
    b
}

/// Read a number slot value back, refusing anything that is not one.
pub fn number_from_slot_value(v: &Bytes32) -> Result<u64, FieldError> {
    if v[8] != 1 || v[9..].iter().any(|&x| x != 0) {
        return Err(FieldError::new("not a number slot value"));
    }
    let mut le = [0u8; 8];
    le.copy_from_slice(&v[..8]);
    Ok(u64::from_le_bytes(le))
}

/// A text slot value: SHA-256 of its UTF-8 after NFC normalisation.
pub fn text_slot_value(text: &str) -> Bytes32 {
    let normalised: String = text.nfc().collect();
    sha256(normalised.as_bytes())
}

/// A 16-slot mask as a number (slot i is bit i), little-endian in 32 bytes.
pub fn mask_slot_value(mask: &[bool; FIELD_SLOTS]) -> Bytes32 {
    let n = mask
        .iter()
        .enumerate()
        .fold(0u64, |acc, (i, &b)| if b { acc | (1 << i) } else { acc });
    count_bytes(n)
}

// ---- schemas ----

/// A JSON number that is an integer, read the way ECMAScript's `Number.isInteger` reads
/// it: `3.0` is the integer 3. `None` for anything else, including non-numbers.
fn json_integer(v: &Value) -> Option<i128> {
    let n = v.as_number()?;
    if let Some(i) = n.as_i64() {
        return Some(i as i128);
    }
    if let Some(u) = n.as_u64() {
        return Some(u as i128);
    }
    let f = n.as_f64()?;
    // Beyond i128 the value is out of every range checked here anyway.
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e30 {
        Some(f as i128)
    } else {
        None
    }
}

/// SHA-256 of the canonical JSON of a published schema document.
pub fn schema_document_digest(schema: &Value) -> Result<Bytes32, FieldError> {
    Ok(sha256(canonicalise(schema)?.as_bytes()))
}

/// The kind of value a slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotType {
    Uint,
    Text,
}

/// The canonical form a text slot's values must be written in.
///
/// Distinctness compares bytes, so one genotype written two ways ("180/184" and
/// "184/180") would count as a difference. A comparable text slot therefore declares a
/// format, and only its canonical form is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldFormat {
    /// Two allele sizes, decimal, at most 9 digits, no leading zeros, smaller first: `180/184`.
    AllelePair,
    /// One allele size: `233`.
    Allele,
    /// Upper-case letters, digits, `.`, `_` or `-`, starting with a letter or digit, at
    /// most 64 characters.
    Code,
}

impl FieldFormat {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "allele-pair" => Some(FieldFormat::AllelePair),
            "allele" => Some(FieldFormat::Allele),
            "code" => Some(FieldFormat::Code),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            FieldFormat::AllelePair => "allele-pair",
            FieldFormat::Allele => "allele",
            FieldFormat::Code => "code",
        }
    }
}

/// An allele size: `0` or a decimal of at most 9 digits with no leading zero.
fn allele(s: &str) -> Option<u32> {
    let ok = !s.is_empty()
        && s.len() <= 9
        && s.bytes().all(|c| c.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

/// Refuse text that is not in the canonical form of `format`.
pub fn check_format(format: FieldFormat, text: &str) -> Result<(), FieldError> {
    let not_in_form = || FieldError(format!("not in {} form: {:?}", format.name(), text));
    match format {
        FieldFormat::Allele => allele(text).map(|_| ()).ok_or_else(not_in_form),
        FieldFormat::AllelePair => {
            let (a, b) = text.split_once('/').ok_or_else(not_in_form)?;
            let (a, b) = (allele(a).ok_or_else(not_in_form)?, allele(b).ok_or_else(not_in_form)?);
            if a > b {
                return Err(FieldError(format!("an allele pair is written smaller first: {:?}", text)));
            }
            Ok(())
        }
        FieldFormat::Code => {
            let b = text.as_bytes();
            let ok = (1..=64).contains(&b.len())
                && (b[0].is_ascii_uppercase() || b[0].is_ascii_digit())
                && b.iter().all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'));
            if ok { Ok(()) } else { Err(not_in_form()) }
        }
    }
}

/// What a schema says about one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotDecl {
    pub slot_type: SlotType,
    pub format: Option<FieldFormat>,
    pub comparable: bool,
}

/// A checked schema: what it declares for each slot (None where it is silent), and the
/// two masks hashed into its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMasks {
    pub slots: [Option<SlotDecl>; FIELD_SLOTS],
    /// Slots that count towards distinctness.
    pub comparable: [bool; FIELD_SLOTS],
    /// Slots that hold numbers, so the claims contract can refuse a range claim on any other.
    pub numeric: [bool; FIELD_SLOTS],
}

/// Check a schema document and return what it declares.
///
/// The schema is an object with a non-empty string `id`, a string `title` and a `slots`
/// list. Each slot entry is an object: `slot` 0 to 15 and described once, `type` `uint` or
/// `text`, `path` a non-empty string, `unit` a string if present, `scale` a positive
/// integer if present, `comparable` a boolean if present, `format` only on a text slot
/// and one of `allele-pair`, `allele`, `code`. A comparable text slot must declare a format.
pub fn schema_masks(schema: &Value) -> Result<SchemaMasks, FieldError> {
    let entries = schema
        .as_object()
        .and_then(|o| o.get("slots"))
        .and_then(Value::as_array)
        .ok_or_else(|| FieldError::new("a schema lists its slots"))?;
    if !matches!(schema.get("id"), Some(Value::String(id)) if !id.is_empty()) {
        return Err(FieldError::new("a schema has an id"));
    }
    if !matches!(schema.get("title"), Some(Value::String(_))) {
        return Err(FieldError::new("a schema has a title"));
    }
    let mut out = SchemaMasks { slots: [None; FIELD_SLOTS], comparable: [false; FIELD_SLOTS], numeric: [false; FIELD_SLOTS] };
    for s in entries {
        if !s.is_object() {
            return Err(FieldError::new("a slot entry is an object"));
        }
        let raw = s.get("slot").unwrap_or(&Value::Null);
        let slot = match json_integer(raw) {
            Some(i) if (0..FIELD_SLOTS as i128).contains(&i) => i as usize,
            _ => return Err(FieldError(format!("slot out of range: {}", raw))),
        };
        if out.slots[slot].is_some() {
            return Err(FieldError(format!("slot {slot} is listed twice")));
        }
        let slot_type = match s.get("type").and_then(Value::as_str) {
            Some("uint") => SlotType::Uint,
            Some("text") => SlotType::Text,
            _ => return Err(FieldError(format!("slot {slot} has an unknown type"))),
        };
        if !matches!(s.get("path"), Some(Value::String(p)) if !p.is_empty()) {
            return Err(FieldError(format!("slot {slot} has no path")));
        }
        if !matches!(s.get("unit"), None | Some(Value::String(_))) {
            return Err(FieldError(format!("slot {slot}: unit is a string")));
        }
        if let Some(scale) = s.get("scale") {
            if !matches!(json_integer(scale), Some(n) if n >= 1) {
                return Err(FieldError(format!("slot {slot}: scale is a positive integer")));
            }
        }
        let comparable = match s.get("comparable") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(FieldError(format!("slot {slot}: comparable is true or false"))),
        };
        let format = match s.get("format") {
            None => None,
            Some(f) => match (slot_type, f.as_str().and_then(FieldFormat::from_name)) {
                (SlotType::Text, Some(f)) => Some(f),
                _ => return Err(FieldError(format!("slot {slot}: format is allele-pair, allele or code, on a text slot"))),
            },
        };
        if comparable && slot_type == SlotType::Text && format.is_none() {
            return Err(FieldError(format!("slot {slot}: a comparable text slot declares a format")));
        }
        out.slots[slot] = Some(SlotDecl { slot_type, format, comparable });
        out.comparable[slot] = comparable;
        out.numeric[slot] = slot_type == SlotType::Uint;
    }
    Ok(out)
}

/// Which slots count towards distinctness. Validates the schema as [`schema_masks`] does.
pub fn comparable_mask(schema: &Value) -> Result<[bool; FIELD_SLOTS], FieldError> {
    Ok(schema_masks(schema)?.comparable)
}

/// The schema's terms in one 32-byte element: the comparable mask in bytes 0-1 and the
/// numeric mask in bytes 2-3 (slot i is bit i, little-endian), k in byte 4, the rest zero.
pub fn schema_terms_bytes(comparable: &[bool; FIELD_SLOTS], numeric: &[bool; FIELD_SLOTS], k: u8) -> Bytes32 {
    let mask = |m: &[bool; FIELD_SLOTS]| m.iter().enumerate().fold(0u16, |acc, (i, &b)| if b { acc | 1 << i } else { acc });
    let mut out = [0u8; 32];
    out[0..2].copy_from_slice(&mask(comparable).to_le_bytes());
    out[2..4].copy_from_slice(&mask(numeric).to_le_bytes());
    out[4] = k;
    out
}

/// `schemaId = H("veilcore:v1:fschema", SHA-256(canonical schema), terms)`.
///
/// The masks and k are hashed in alongside the document so a claim cannot choose them,
/// and the numeric mask lets the claims contract refuse a range claim on a slot that is
/// not a number.
pub fn field_schema_id(schema: &Value) -> Result<Bytes32, FieldError> {
    let masks = schema_masks(schema)?;
    let k = match schema.get("k").and_then(json_integer) {
        Some(k) if (1..=FIELD_SLOTS as i128).contains(&k) => k as u8,
        _ => return Err(FieldError::new("k is 1 to 16")),
    };
    if masks.comparable.iter().filter(|&&b| b).count() < k as usize {
        return Err(FieldError::new("k is more than the number of comparable slots"));
    }
    Ok(hash_elements(&[
        &tag("veilcore:v1:fschema"),
        &schema_document_digest(schema)?,
        &schema_terms_bytes(&masks.comparable, &masks.numeric, k),
    ]))
}

// ---- leaves and root ----

/// The first 23 bytes of `H("veilcore:v1:fsalt", fieldSecret, slot)`.
pub fn field_salt(field_secret: &Bytes32, slot: usize) -> Salt {
    let h = hash_elements(&[&tag("veilcore:v1:fsalt"), field_secret, &count_bytes(slot as u64)]);
    let mut out = [0u8; 23];
    out.copy_from_slice(&h[..23]);
    out
}

/// `SHA-256(value || salt)`: 55 bytes, one SHA-256 block.
pub fn field_leaf(value: &Bytes32, salt: &Salt) -> Bytes32 {
    let mut b = [0u8; 55];
    b[..32].copy_from_slice(value);
    b[32..].copy_from_slice(salt);
    sha256(&b)
}

/// `SHA-256("veilcore:v1:fset" || schemaId || leaf_0 || ... || leaf_15)`: the tag is those
/// 16 ASCII bytes, unpadded, so the input is 560 bytes.
pub fn field_set_root_from_leaves(schema_id: &Bytes32, leaves: &[Bytes32; FIELD_SLOTS]) -> Bytes32 {
    let mut b = Vec::with_capacity(560);
    b.extend_from_slice(b"veilcore:v1:fset");
    b.extend_from_slice(schema_id);
    for l in leaves {
        b.extend_from_slice(l);
    }
    sha256(&b)
}

/// `H("veilcore:v1:frecord", fieldSetRoot, SHA-256 of the canonical committed fields)`.
pub fn field_record_commitment(set_root: &Bytes32, json_digest: &Bytes32) -> Bytes32 {
    hash_elements(&[&tag("veilcore:v1:frecord"), set_root, json_digest])
}

/// The holder's private field set. Never disclosed with the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSet {
    pub schema_id: Bytes32,
    pub values: [Bytes32; FIELD_SLOTS],
    pub salts: [Salt; FIELD_SLOTS],
}

/// Seal 16 slot values under a schema.
///
/// `field_secret` is 32 random bytes kept with the holder's private copy, never in the
/// disclosed record: anyone who could derive the salts could guess low-entropy hidden
/// values back.
pub fn seal_field_set(schema_id: Bytes32, values: [Bytes32; FIELD_SLOTS], field_secret: &Bytes32) -> FieldSet {
    let salts = std::array::from_fn(|i| field_salt(field_secret, i));
    FieldSet { schema_id, values, salts }
}

/// The 16 leaves. Each reveals nothing about its value without its salt.
pub fn field_leaves_of(fs: &FieldSet) -> [Bytes32; FIELD_SLOTS] {
    std::array::from_fn(|i| field_leaf(&fs.values[i], &fs.salts[i]))
}

/// The public root of a field set. Reveals nothing about the values.
pub fn field_set_root_of(fs: &FieldSet) -> Bytes32 {
    field_set_root_from_leaves(&fs.schema_id, &field_leaves_of(fs))
}

/// One slot, opened: its value and salt, and all 16 leaves. The other 15 are salted
/// hashes and disclose nothing about their values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotOpening {
    pub slot: usize,
    pub value: Bytes32,
    pub salt: Salt,
    pub leaves: [Bytes32; FIELD_SLOTS],
}

pub fn open_field_slot(fs: &FieldSet, slot: usize) -> Result<SlotOpening, FieldError> {
    if slot >= FIELD_SLOTS {
        return Err(FieldError::new("slot is 0 to 15"));
    }
    Ok(SlotOpening { slot, value: fs.values[slot], salt: fs.salts[slot], leaves: field_leaves_of(fs) })
}

/// Recompute the set root from one opened slot (what a verifier of an opening does).
/// Refused when the value and salt do not make that slot's leaf.
pub fn root_from_opening(schema_id: &Bytes32, o: &SlotOpening) -> Result<Bytes32, FieldError> {
    if o.slot >= FIELD_SLOTS {
        return Err(FieldError::new("slot is 0 to 15"));
    }
    if field_leaf(&o.value, &o.salt) != o.leaves[o.slot] {
        return Err(FieldError::new("the opened value and salt do not make that slot's leaf"));
    }
    Ok(field_set_root_from_leaves(schema_id, &o.leaves))
}

/// Check a holder's private field set against a record: same schema, same root.
pub fn verify_field_set(envelope: &Value, fs: &FieldSet) -> bool {
    envelope.get("commitmentAlgorithm").and_then(Value::as_str) == Some(FIELDS_ALGORITHM)
        && envelope.get("fieldSchema").and_then(Value::as_str) == Some(hex(&fs.schema_id).as_str())
        && envelope.get("fieldSetRoot").and_then(Value::as_str) == Some(hex(&field_set_root_of(fs)).as_str())
}

// ---- typed values and the conformance summary ----

/// A typed slot value as written in a private copy and in the conformance vectors:
/// `{"uint":"<decimal>"}`, `{"text":"..."}` or `null` for absent.
pub fn slot_value_of(v: &Value) -> Result<Bytes32, FieldError> {
    let obj = match v {
        Value::Null => return Ok(ABSENT_VALUE),
        Value::Object(o) => o,
        _ => return Err(FieldError::new("a slot value is {uint}, {text} or null")),
    };
    if obj.len() != 1 {
        return Err(FieldError::new("a slot value has exactly one of uint or text"));
    }
    if let Some(u) = obj.get("uint") {
        let s = u.as_str().unwrap_or("");
        let canonical = !s.is_empty()
            && s.bytes().all(|c| c.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'));
        if !canonical {
            return Err(FieldError::new("uint is a decimal string with no leading zeros"));
        }
        let n: u64 = s.parse().map_err(|_| FieldError::new("a count is 0 to 2^64 - 1"))?;
        return Ok(number_slot_value(n));
    }
    if let Some(t) = obj.get("text") {
        let s = t.as_str().ok_or_else(|| FieldError::new("text is a string"))?;
        return Ok(text_slot_value(s));
    }
    Err(FieldError::new("a slot value is {uint}, {text} or null"))
}

/// Typed values for all 16 slots, checked against the schema, as 32-byte slot values.
///
/// A non-null value must match its slot's declared type, and a slot the schema does not
/// describe must be empty: otherwise a text hash could sit in a number slot and a range
/// claim would run over it.
pub fn typed_slot_values(schema: &Value, values: &[Value]) -> Result<[Bytes32; FIELD_SLOTS], FieldError> {
    if values.len() != FIELD_SLOTS {
        return Err(FieldError::new("a field set has 16 slots"));
    }
    let declared = schema_masks(schema)?.slots;
    let mut out = [ABSENT_VALUE; FIELD_SLOTS];
    for (i, v) in values.iter().enumerate() {
        // Arrays count as objects here, as they do for the reference's `typeof`: an array
        // has neither kind and is refused below or by slot_value_of.
        if v.is_object() || v.is_array() {
            let kind = match (v.get("uint"), v.get("text")) {
                (Some(_), _) => Some(SlotType::Uint),
                (None, Some(_)) => Some(SlotType::Text),
                (None, None) => None,
            };
            let decl = declared[i]
                .ok_or_else(|| FieldError(format!("slot {i} is not described by the schema, so it must be empty")))?;
            if kind != Some(decl.slot_type) {
                let t = if decl.slot_type == SlotType::Uint { "uint" } else { "text" };
                return Err(FieldError(format!("slot {i} holds {t} values")));
            }
            if let Some(format) = decl.format {
                let text = v.get("text").and_then(Value::as_str).ok_or_else(|| FieldError::new("text is a string"))?;
                check_format(format, text)?;
            }
        }
        out[i] = slot_value_of(v)?;
    }
    Ok(out)
}

/// Everything public or checkable about a sealed field set: what the conformance
/// vectors compare across implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSetSummary {
    pub schema_document_digest: Bytes32,
    pub schema_id: Bytes32,
    pub slot_values: [Bytes32; FIELD_SLOTS],
    pub salts: [Salt; FIELD_SLOTS],
    pub leaves: [Bytes32; FIELD_SLOTS],
    pub set_root: Bytes32,
}

impl FieldSetSummary {
    /// The summary as JSON, keys in the order the vectors use: schemaDocumentDigest,
    /// schemaId, slotValues, salts, leaves, setRoot. Written by hand because a serde_json
    /// map sorts its keys, and the runner compares the text.
    pub fn to_json(&self) -> String {
        fn list<T: AsRef<[u8]>>(xs: &[T]) -> String {
            let items: Vec<String> = xs.iter().map(|x| format!("\"{}\"", hex(x.as_ref()))).collect();
            format!("[{}]", items.join(","))
        }
        format!(
            "{{\"schemaDocumentDigest\":\"{}\",\"schemaId\":\"{}\",\"slotValues\":{},\"salts\":{},\"leaves\":{},\"setRoot\":\"{}\"}}",
            hex(&self.schema_document_digest),
            hex(&self.schema_id),
            list(&self.slot_values),
            list(&self.salts),
            list(&self.leaves),
            hex(&self.set_root),
        )
    }
}

/// Seal typed values under a schema and report the summary.
///
/// Input: `{"schema":{...}, "values":[16 typed values], "fieldSecret":"<64 hex>"}`.
pub fn field_set_summary(input: &Value) -> Result<FieldSetSummary, FieldError> {
    let typed = match input.get("values").and_then(Value::as_array) {
        Some(v) if v.len() == FIELD_SLOTS => v,
        _ => return Err(FieldError::new("a field set has 16 slots")),
    };
    let secret = input
        .get("fieldSecret")
        .and_then(Value::as_str)
        .and_then(parse_hex32)
        .ok_or_else(|| FieldError::new("fieldSecret is 64 lowercase hex characters"))?;
    let schema = input.get("schema").unwrap_or(&Value::Null);
    let schema_id = field_schema_id(schema)?;

    let values = typed_slot_values(schema, typed)?;
    let fs = seal_field_set(schema_id, values, &secret);

    Ok(FieldSetSummary {
        schema_document_digest: schema_document_digest(schema)?,
        schema_id,
        slot_values: fs.values,
        salts: fs.salts,
        leaves: field_leaves_of(&fs),
        set_root: field_set_root_of(&fs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The example schema from the sdk's profiles/fields, as the vectors carry it.
    const SCHEMA: &str = r#"{"id":"veilcore/fields/plant-variety-dus-example/v1","title":"EXAMPLE field schema: 12 SSR loci and four traits for a plant variety","status":"example only, not adopted by any body; a real schema names the crop and marker panel, and takes k from the examining body's guidance","note":"Paths name the holder's private `fields` object. A value in a field set shall not also appear in the record's committed JSON, or disclosing the JSON would disclose it.","slots":[{"slot":0,"path":"fields.loci[0]","type":"text","format":"allele-pair","comparable":true},{"slot":1,"path":"fields.loci[1]","type":"text","format":"allele-pair","comparable":true},{"slot":2,"path":"fields.loci[2]","type":"text","format":"allele-pair","comparable":true},{"slot":3,"path":"fields.loci[3]","type":"text","format":"allele-pair","comparable":true},{"slot":4,"path":"fields.loci[4]","type":"text","format":"allele-pair","comparable":true},{"slot":5,"path":"fields.loci[5]","type":"text","format":"allele-pair","comparable":true},{"slot":6,"path":"fields.loci[6]","type":"text","format":"allele-pair","comparable":true},{"slot":7,"path":"fields.loci[7]","type":"text","format":"allele-pair","comparable":true},{"slot":8,"path":"fields.loci[8]","type":"text","format":"allele-pair","comparable":true},{"slot":9,"path":"fields.loci[9]","type":"text","format":"allele-pair","comparable":true},{"slot":10,"path":"fields.loci[10]","type":"text","format":"allele-pair","comparable":true},{"slot":11,"path":"fields.loci[11]","type":"text","format":"allele-pair","comparable":true},{"slot":12,"path":"fields.germinationPercent","type":"uint","scale":100,"unit":"percent"},{"slot":13,"path":"fields.purityPercent","type":"uint","scale":100,"unit":"percent"},{"slot":14,"path":"fields.varietyName","type":"text"},{"slot":15,"path":"fields.yieldKgPerHa","type":"uint","scale":1,"unit":"kg/ha"}],"k":3}"#;

    /// conformance/vectors.json fieldSets[0].expected, verbatim.
    const FIRST_VECTOR: &str = r#"{"schemaDocumentDigest":"385c5055fc315e4dd20566abda6a79709d22dcfe2a0e96e240cdcb15fd10b223","schemaId":"875d8a6c21137ec1aae6d2c8ad6b929c4ef53b09a247a834f39b126dc910f5f9","slotValues":["a70dfed1d20bc248a82f687043bf842ff3e8450e4face9a1b4a73354b87ad4b6","10579c4c91c494b285b2417e68ed12c873b9d0389dc01d8d38315f683500de50","0eb2c9301347120ba0f0f7a41bcea892b1472431f3420d7d50bff1529d0bbc82","37da373c58b805b2459a6e8a94886a37158d9fb329df201cd7e52e87c9ba21a1","53fea90639640594be768ad931f128ac7100c894531eb9f2f69abe79a33dfa73","9361c2085e721f3a61b699c233b488d0652216afa2ee0d51c01322a6d1104516","90b3f983db40984723e059d544061e323eff55d5b81205383630a9b0068b64e3","b87281da2638775719aeeed1c9995c30141895b7bfdb320e1954295d9b4c59a6","2f8d90b3bbb7acdc26027eabdc828310df2387dc9da5528ab2022dfb1aeb0d1f","2da1e2c4855358a6faf21f046083a33c4a1b15b343a14fbc373887886d1932ac","4e6a61d8baafd7042e9d1b31ead836d023375e61efc9202971d4fb62541b06ea","fc6144d28fc3a540ad6cd21c00e87303a9aff664c497f7e32931583851596247","b225000000000000010000000000000000000000000000000000000000000000","fc26000000000000010000000000000000000000000000000000000000000000","7774ad14e6e1de7ddea14d6c0e443173f408ed12fd04e91c259d9c8b9a131ff2","0019000000000000010000000000000000000000000000000000000000000000"],"salts":["05177a4d698cefc094277881301d6052b45ef07252d013","12ae01188b7ee74a73111e9deef3b8b3c1e8ff8e09ccc9","1eba963044069ce2677d14c30f258becbc66df2d388578","3410be0c50c014f465d9c08710ed8c1270219c77e87ee2","aa7bd08038416a2195c43247b6f7fb06af310de2d46971","73c1a1d6b0c6541c596e658a2d3d1fe27c85a0c879d51d","c35b5a91e9da9d9ce0f6f94e014eb1004ba03d3512b050","eb50f397b1bf77e16950c2ddf925153521de562665cb8c","3759af9e38defb05962766ff635f4e4a284e447d9b6059","e8454f1912311c505d9c21db038d7a22137dd7daea625f","1fc229d4af3ffcc44f96c2490f521d553633e835604dc5","add98991cf4ffa72da510b1f32ee297dc23ebe90991a45","ae27b23ad0f0641df99060c7690e0489a6784c61a47f60","85841a2ec8aad9fe070dd399c83da7aaad8e3d6c6bf6bf","916e7627a6a806ff90bbb54dcb4f3d7740812d8634257a","a0ffed7125631f1421c916a84ad727f183f202ae43c29d"],"leaves":["28947e9756e75371b854b892cf4dc29e11a5c6e6284139ad0230613bbd716b35","ef86d387b09aeb0e7aa3dc014c3686de41ea54caf33f3cce2c8065f42b6b19bc","8f765b6b045c0ce5c6a5a5d1186826bbe5b7c27afc97895710b983c29eff924f","0fef5178cc0279d5df1fe9b125c2a81cf633f2a01bb890d8e1618c5ad5ec9353","f13aa5655dd6f8e7efb8296dccf305f87a1e53124c2f75a51a61549b41f1c15c","d2ef841a20f8469a3d2a82e8930bfd75fcd6331e52b84e5ea3bc7b8c46c10ba9","856a6d31a25caef607dd7c7234612ec218e52db69b07f76ad6514355628443a9","c7f19fadd00560e3d9e36f8d21892a846f8a98f4164a4bd9dd13c36d0c53d8ca","5bc0843c1ce6f13adcaa0d50d18bf1a46db5da23b607ee0525d453435c95aaa4","c7f39495dc244fb87db0fdc0259bade476de6a34d6a66a4ab47fb0981b9f4720","481055df8021f8bcfdc8c2daa37d5a20dfc906fc1133735753948d7f12db9e24","401a7ec96f92e3c8b65ab82a145bd64bf5815972883598956f6c5882dd1804fa","d9be56bf324b03041c47ea0fb5dd79d5ece5f417383679631b1bb2c1eda76586","933b790ef5acca37c57f0213920346490b70364dfff792fcde48638c081ed8ab","22ab0200fb7f77b9c3929ff5ac17feb9248c963368ff92b089e3d5d4542e1a2e","fc6453eb4d78616c9e902ab18618c2e1af4d5fb59c0349264c2e73b457cc5db4"],"setRoot":"784e7567d56ae3b96c69156a8bf35138d878c8efd1ac6976ee748da8cb22d823"}"#;

    fn schema() -> Value {
        serde_json::from_str(SCHEMA).unwrap()
    }

    fn first_input() -> Value {
        json!({
            "schema": schema(),
            "values": [
                {"text":"233/233"},{"text":"180/184"},{"text":"201/201"},{"text":"155/159"},
                {"text":"312/318"},{"text":"140/140"},{"text":"222/226"},{"text":"199/199"},
                {"text":"260/264"},{"text":"175/175"},{"text":"290/290"},{"text":"133/137"},
                {"uint":"9650"},{"uint":"9980"},{"text":"Harbour Mist"},{"uint":"6400"}
            ],
            "fieldSecret": "1".repeat(64)
        })
    }

    fn expect_refused(input: Value) {
        assert!(field_set_summary(&input).is_err(), "accepted: {input}");
    }

    #[test]
    fn a_full_summary_matches_the_first_vector() {
        assert_eq!(field_set_summary(&first_input()).unwrap().to_json(), FIRST_VECTOR);
    }

    #[test]
    fn every_opening_folds_to_the_set_root() {
        let s = field_set_summary(&first_input()).unwrap();
        let fs = seal_field_set(s.schema_id, s.slot_values, &[0x11; 32]);
        for slot in 0..FIELD_SLOTS {
            let o = open_field_slot(&fs, slot).unwrap();
            assert_eq!(root_from_opening(&s.schema_id, &o), Ok(s.set_root));
            // A wrong value, or another slot's leaf in its place, is refused.
            let mut wrong = o.clone();
            wrong.value[0] ^= 1;
            assert!(root_from_opening(&s.schema_id, &wrong).is_err());
            let mut moved = o.clone();
            moved.slot = (slot + 1) % FIELD_SLOTS;
            assert!(root_from_opening(&s.schema_id, &moved).is_err());
        }
    }

    #[test]
    fn the_number_0_is_not_an_absent_slot() {
        let zero = slot_value_of(&json!({"uint":"0"})).unwrap();
        assert_ne!(zero, ABSENT_VALUE);
        assert_eq!(hex(&zero), "0000000000000000010000000000000000000000000000000000000000000000");
        assert_eq!(slot_value_of(&Value::Null).unwrap(), ABSENT_VALUE);
        assert_eq!(number_from_slot_value(&zero), Ok(0));
        assert!(number_from_slot_value(&ABSENT_VALUE).is_err());
        let max = slot_value_of(&json!({"uint":"18446744073709551615"})).unwrap();
        assert_eq!(hex(&max), "ffffffffffffffff010000000000000000000000000000000000000000000000");
    }

    #[test]
    fn text_is_nfc_normalised_before_hashing() {
        let decomposed = slot_value_of(&json!({"text":"Cafe\u{0301}"})).unwrap();
        let composed = slot_value_of(&json!({"text":"Caf\u{00e9}"})).unwrap();
        assert_eq!(decomposed, composed);
        // conformance/vectors.json fieldSets[2], slot 14.
        assert_eq!(hex(&decomposed), "73473dcc12b763085904a5279d048c4d5b3b008c46f1f32443b99de04aa83a14");
    }

    #[test]
    fn the_schema_id_matches_the_vectors() {
        assert_eq!(
            hex(&schema_document_digest(&schema()).unwrap()),
            "385c5055fc315e4dd20566abda6a79709d22dcfe2a0e96e240cdcb15fd10b223"
        );
        assert_eq!(
            hex(&field_schema_id(&schema()).unwrap()),
            "875d8a6c21137ec1aae6d2c8ad6b929c4ef53b09a247a834f39b126dc910f5f9"
        );
    }

    #[test]
    fn malformed_values_are_refused() {
        for bad in [
            json!({"uint":"18446744073709551616"}),
            json!({"uint":"01"}),
            json!({"uint":"-1"}),
            json!({"uint":""}),
            json!({"uint":5}),
            json!({"uint":"1","text":"x"}),
            json!({}),
            json!({"text":1}),
            json!({"other":"x"}),
            json!("x"),
            json!([]),
        ] {
            assert!(slot_value_of(&bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn malformed_field_sets_are_refused() {
        let mut fifteen = first_input();
        fifteen["values"].as_array_mut().unwrap().pop();
        expect_refused(fifteen);

        let mut upper = first_input();
        upper["fieldSecret"] = json!("A".repeat(64));
        expect_refused(upper);

        for k in [json!(0), json!(17), json!(13), json!("3"), json!(2.5)] {
            let mut i = first_input();
            i["schema"]["k"] = k;
            expect_refused(i);
        }

        let mut twice = first_input();
        twice["schema"]["slots"][1]["slot"] = json!(0);
        expect_refused(twice);

        let mut out_of_range = first_input();
        out_of_range["schema"]["slots"][0]["slot"] = json!(16);
        expect_refused(out_of_range);

        let mut bad_type = first_input();
        bad_type["schema"]["slots"][0]["type"] = json!("float");
        expect_refused(bad_type);

        let mut bad_comparable = first_input();
        bad_comparable["schema"]["slots"][0]["comparable"] = json!("yes");
        expect_refused(bad_comparable);
    }

    #[test]
    fn a_value_must_match_its_slot_type() {
        let mut text_in_uint = first_input();
        text_in_uint["values"][12] = json!({"text":"9650"});
        expect_refused(text_in_uint);

        let mut uint_in_text = first_input();
        uint_in_text["values"][0] = json!({"uint":"233"});
        expect_refused(uint_in_text);
    }

    #[test]
    fn a_slot_the_schema_does_not_describe_must_be_empty() {
        let mut i = first_input();
        i["schema"]["slots"].as_array_mut().unwrap().pop(); // slot 15 no longer described
        i["values"][15] = Value::Null;
        assert!(field_set_summary(&i).is_ok(), "an undescribed slot may be empty");
        i["values"][15] = json!({"uint":"6400"});
        expect_refused(i);
    }

    #[test]
    fn the_numeric_mask_is_in_the_schema_id() {
        let m = schema_masks(&schema()).unwrap();
        let numeric: Vec<usize> = (0..FIELD_SLOTS).filter(|&i| m.numeric[i]).collect();
        assert_eq!(numeric, vec![12, 13, 15]);
        let terms = schema_terms_bytes(&m.comparable, &m.numeric, 3);
        // comparable: slots 0-11 (0x0fff); numeric: 12, 13, 15 (0xb000); k = 3.
        assert_eq!(hex(&terms[..5]), "ff0f00b003");
        assert!(terms[5..].iter().all(|&b| b == 0));
        let with = field_schema_id(&schema()).unwrap();
        let without = hash_elements(&[
            &tag("veilcore:v1:fschema"),
            &schema_document_digest(&schema()).unwrap(),
            &schema_terms_bytes(&m.comparable, &[false; FIELD_SLOTS], 3),
        ]);
        assert_ne!(with, without);
        assert_eq!(
            with,
            hash_elements(&[&tag("veilcore:v1:fschema"), &schema_document_digest(&schema()).unwrap(), &terms])
        );
    }

    #[test]
    fn schema_documents_are_checked() {
        let mutate = |f: &dyn Fn(&mut Value)| {
            let mut i = first_input();
            f(&mut i["schema"]);
            i
        };
        let refused: Vec<(&str, Value)> = vec![
            ("no id", mutate(&|s| { s.as_object_mut().unwrap().remove("id"); })),
            ("empty id", mutate(&|s| s["id"] = json!(""))),
            ("id not a string", mutate(&|s| s["id"] = json!(7))),
            ("no title", mutate(&|s| { s.as_object_mut().unwrap().remove("title"); })),
            ("title not a string", mutate(&|s| s["title"] = json!(["x"]))),
            ("schema not an object", mutate(&|s| *s = json!([1]))),
            ("slot entry not an object", mutate(&|s| s["slots"][0] = json!(0))),
            ("no path", mutate(&|s| { s["slots"][15].as_object_mut().unwrap().remove("path"); })),
            ("empty path", mutate(&|s| s["slots"][15]["path"] = json!(""))),
            ("unit not a string", mutate(&|s| s["slots"][15]["unit"] = json!(1))),
            ("scale zero", mutate(&|s| s["slots"][15]["scale"] = json!(0))),
            ("scale negative", mutate(&|s| s["slots"][15]["scale"] = json!(-1))),
            ("scale fractional", mutate(&|s| s["slots"][15]["scale"] = json!(1.5))),
            ("scale a string", mutate(&|s| s["slots"][15]["scale"] = json!("100"))),
            ("format on a uint slot", mutate(&|s| s["slots"][15]["format"] = json!("allele"))),
            ("unknown format", mutate(&|s| s["slots"][0]["format"] = json!("dna"))),
            ("format inherited from Object", mutate(&|s| s["slots"][0]["format"] = json!("toString"))),
            ("format as a list", mutate(&|s| s["slots"][0]["format"] = json!(["code"]))),
            ("comparable text without format", mutate(&|s| { s["slots"][0].as_object_mut().unwrap().remove("format"); })),
        ];
        for (name, input) in refused {
            assert!(field_set_summary(&input).is_err(), "accepted: {name}");
        }
        // A non-comparable text slot needs no format; scale 2.0 is the integer 2.
        let ok = mutate(&|s| s["slots"][15]["scale"] = json!(2.0));
        assert!(field_set_summary(&ok).is_ok());
    }

    #[test]
    fn formats_accept_only_their_canonical_form() {
        use FieldFormat::*;
        for (f, t) in [
            (AllelePair, "180/184"), (AllelePair, "233/233"), (AllelePair, "0/0"),
            (AllelePair, "999999999/999999999"), (Allele, "233"), (Allele, "0"),
            (Code, "A"), (Code, "9"), (Code, "SNP-12_B.3"),
        ] {
            assert_eq!(check_format(f, t), Ok(()), "{t}");
        }
        let long_code = "A".repeat(65);
        for (f, t) in [
            (AllelePair, "184/180"), (AllelePair, "090/184"), (AllelePair, "180 / 184"),
            (AllelePair, "180"), (AllelePair, "180/184/190"), (AllelePair, "1000000000/1000000000"),
            (AllelePair, "/184"), (AllelePair, "+1/2"), (Allele, "01"), (Allele, ""),
            (Allele, "233\n"), (Allele, "２３３"), (Code, ""), (Code, "-A"), (Code, "abc"),
            (Code, "A B"), (Code, long_code.as_str()),
        ] {
            assert!(check_format(f, t).is_err(), "accepted {t:?}");
        }
    }

    #[test]
    fn values_in_a_formatted_slot_are_checked() {
        for bad in ["184/180", "090/184", "180 / 184"] {
            let mut i = first_input();
            i["values"][0] = json!({ "text": bad });
            expect_refused(i);
        }
        // An unformatted text slot takes any text.
        let mut i = first_input();
        i["values"][14] = json!({"text":"anything at all / 2"});
        assert!(field_set_summary(&i).is_ok());
    }

    #[test]
    fn an_integral_float_is_an_integer_as_in_ecmascript() {
        let mut i = first_input();
        i["schema"]["k"] = json!(3.0);
        assert!(field_set_summary(&i).is_ok());
    }

    #[test]
    fn tags_are_zero_padded_to_32_bytes() {
        let t = tag("veilcore:v1:frecord");
        assert_eq!(&t[..19], b"veilcore:v1:frecord");
        assert!(t[19..].iter().all(|&b| b == 0));
    }
}
