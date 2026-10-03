//! Field sets: commitment algorithm `sha256/fields/v1`, per specification section 4.5.
//!
//! A record sealed this way commits each of 16 slots as a salted leaf under a root, and
//! binds that root into the record commitment. A holder can later prove one fact about
//! one slot - that it holds a value, that a number meets a bound - without disclosing the
//! rest. The proofs run on Midnight; everything here is plain SHA-256, so sealing a field
//! set and checking a commitment needs nothing else.
//!
//! Every hash is SHA-256 over a sequence of 32-byte elements, the first of which is a
//! domain tag: an ASCII string right-padded with zero bytes to 32. That is the shape
//! Compact's `persistentHash` takes, which is what lets the claims contract recompute
//! the same values in-circuit.

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{canonicalise, hex};

/// The commitment algorithm name for records that bind a field set.
pub const FIELDS_ALGORITHM: &str = "sha256/fields/v1";

/// Every field set has exactly this many slots.
pub const FIELD_SLOTS: usize = 16;

/// The depth of the slot tree: 16 leaves, 4 levels.
const TREE_DEPTH: usize = 4;

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

/// Which slots count towards distinctness. Also validates the slot list: each slot
/// 0 to 15 and described once, type `uint` or `text`, `comparable` a boolean if present.
pub fn comparable_mask(schema: &Value) -> Result<[bool; FIELD_SLOTS], FieldError> {
    let slots = schema
        .get("slots")
        .and_then(Value::as_array)
        .ok_or_else(|| FieldError::new("a schema lists its slots"))?;
    let mut mask = [false; FIELD_SLOTS];
    let mut seen = [false; FIELD_SLOTS];
    for s in slots {
        let raw = s.get("slot").unwrap_or(&Value::Null);
        let slot = match json_integer(raw) {
            Some(i) if (0..FIELD_SLOTS as i128).contains(&i) => i as usize,
            _ => return Err(FieldError(format!("slot out of range: {}", raw))),
        };
        if seen[slot] {
            return Err(FieldError(format!("slot {slot} is listed twice")));
        }
        seen[slot] = true;
        match s.get("type").and_then(Value::as_str) {
            Some("uint") | Some("text") => {}
            _ => return Err(FieldError(format!("slot {slot} has an unknown type"))),
        }
        match s.get("comparable") {
            None => {}
            Some(Value::Bool(b)) => mask[slot] = *b,
            Some(_) => return Err(FieldError(format!("slot {slot}: comparable is true or false"))),
        }
    }
    Ok(mask)
}

/// `schemaId = H("veilcore:v1:fschema", SHA-256(canonical schema), comparable mask, k)`.
///
/// The mask and k are hashed in alongside the document so a claim cannot use a
/// different threshold or set of slots than the schema publishes.
pub fn field_schema_id(schema: &Value) -> Result<Bytes32, FieldError> {
    let k = match schema.get("k").and_then(json_integer) {
        Some(k) if (1..=FIELD_SLOTS as i128).contains(&k) => k as u64,
        _ => return Err(FieldError::new("k is 1 to 16")),
    };
    let mask = comparable_mask(schema)?;
    if (mask.iter().filter(|&&b| b).count() as u64) < k {
        return Err(FieldError::new("k is more than the number of comparable slots"));
    }
    Ok(hash_elements(&[
        &tag("veilcore:v1:fschema"),
        &schema_document_digest(schema)?,
        &mask_slot_value(&mask),
        &count_bytes(k),
    ]))
}

// ---- the tree ----

/// `H("veilcore:v1:fsalt", fieldSecret, slot)`.
pub fn field_salt(field_secret: &Bytes32, slot: usize) -> Bytes32 {
    hash_elements(&[&tag("veilcore:v1:fsalt"), field_secret, &count_bytes(slot as u64)])
}

/// `H("veilcore:v1:field", value, salt)`.
pub fn field_leaf(value: &Bytes32, salt: &Bytes32) -> Bytes32 {
    hash_elements(&[&tag("veilcore:v1:field"), value, salt])
}

/// `H("veilcore:v1:fnode", left, right)`.
pub fn field_node(l: &Bytes32, r: &Bytes32) -> Bytes32 {
    hash_elements(&[&tag("veilcore:v1:fnode"), l, r])
}

/// `H("veilcore:v1:fset", schemaId, tree root)`.
pub fn field_set_root(schema_id: &Bytes32, tree: &Bytes32) -> Bytes32 {
    hash_elements(&[&tag("veilcore:v1:fset"), schema_id, tree])
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
    pub salts: [Bytes32; FIELD_SLOTS],
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

/// Every level of the tree, leaves first, root last.
fn levels(fs: &FieldSet) -> Vec<Vec<Bytes32>> {
    let mut out: Vec<Vec<Bytes32>> =
        vec![fs.values.iter().zip(&fs.salts).map(|(v, s)| field_leaf(v, s)).collect()];
    while out[out.len() - 1].len() > 1 {
        let next = out[out.len() - 1].chunks(2).map(|p| field_node(&p[0], &p[1])).collect();
        out.push(next);
    }
    out
}

/// The public root of a field set. Reveals nothing about the values.
pub fn field_set_root_of(fs: &FieldSet) -> Bytes32 {
    field_set_root(&fs.schema_id, &levels(fs)[TREE_DEPTH][0])
}

/// One slot, opened: what the claims contract needs to prove a value or a range.
///
/// `siblings` and `bits` run from the leaf to the root. A set bit means the node being
/// folded is the RIGHT child, so its sibling is on the left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotOpening {
    pub value: Bytes32,
    pub salt: Bytes32,
    pub siblings: [Bytes32; TREE_DEPTH],
    pub bits: [bool; TREE_DEPTH],
}

pub fn open_field_slot(fs: &FieldSet, slot: usize) -> Result<SlotOpening, FieldError> {
    if slot >= FIELD_SLOTS {
        return Err(FieldError::new("slot is 0 to 15"));
    }
    let lv = levels(fs);
    let mut siblings = [[0u8; 32]; TREE_DEPTH];
    let mut bits = [false; TREE_DEPTH];
    let mut i = slot;
    for level in 0..TREE_DEPTH {
        bits[level] = i & 1 == 1;
        siblings[level] = lv[level][i ^ 1];
        i >>= 1;
    }
    Ok(SlotOpening { value: fs.values[slot], salt: fs.salts[slot], siblings, bits })
}

/// Recompute the set root from one opened slot (what a verifier of an opening does).
pub fn root_from_opening(schema_id: &Bytes32, o: &SlotOpening) -> Bytes32 {
    let mut h = field_leaf(&o.value, &o.salt);
    for level in 0..TREE_DEPTH {
        h = if o.bits[level] {
            field_node(&o.siblings[level], &h)
        } else {
            field_node(&h, &o.siblings[level])
        };
    }
    field_set_root(schema_id, &h)
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
    comparable_mask(schema)?; // validates the slot list, so every entry below is well formed
    let mut declared: [Option<&str>; FIELD_SLOTS] = [None; FIELD_SLOTS];
    for s in schema.get("slots").and_then(Value::as_array).into_iter().flatten() {
        if let (Some(i), Some(t)) = (s.get("slot").and_then(json_integer), s.get("type").and_then(Value::as_str)) {
            declared[i as usize] = Some(t);
        }
    }
    let mut out = [ABSENT_VALUE; FIELD_SLOTS];
    for (i, v) in values.iter().enumerate() {
        // Arrays count as objects here, as they do for the reference's `typeof`: an array
        // has neither kind and is refused below or by slot_value_of.
        if v.is_object() || v.is_array() {
            let kind = v.get("uint").map(|_| "uint").or_else(|| v.get("text").map(|_| "text"));
            match declared[i] {
                None => return Err(FieldError(format!("slot {i} is not described by the schema, so it must be empty"))),
                Some(t) if kind != Some(t) => return Err(FieldError(format!("slot {i} holds {t} values"))),
                Some(_) => {}
            }
        }
        out[i] = slot_value_of(v)?;
    }
    Ok(out)
}

/// One opened slot as the conformance vectors report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningSummary {
    pub slot: usize,
    pub siblings: [Bytes32; TREE_DEPTH],
    pub bits: [bool; TREE_DEPTH],
}

/// Everything public or checkable about a sealed field set: what the conformance
/// vectors compare across implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSetSummary {
    pub schema_document_digest: Bytes32,
    pub schema_id: Bytes32,
    pub slot_values: [Bytes32; FIELD_SLOTS],
    pub salts: [Bytes32; FIELD_SLOTS],
    pub set_root: Bytes32,
    pub openings: Vec<OpeningSummary>,
}

impl FieldSetSummary {
    /// The summary as JSON, keys in the order the vectors use: schemaDocumentDigest,
    /// schemaId, slotValues, salts, setRoot, openings. Written by hand because a
    /// serde_json map sorts its keys, and the runner compares the text.
    pub fn to_json(&self) -> String {
        let list = |xs: &[Bytes32]| {
            let items: Vec<String> = xs.iter().map(|x| format!("\"{}\"", hex(x))).collect();
            format!("[{}]", items.join(","))
        };
        let openings: Vec<String> = self
            .openings
            .iter()
            .map(|o| {
                let bits: Vec<&str> = o.bits.iter().map(|&b| if b { "true" } else { "false" }).collect();
                format!(
                    "{{\"slot\":{},\"siblings\":{},\"bits\":[{}]}}",
                    o.slot,
                    list(&o.siblings),
                    bits.join(",")
                )
            })
            .collect();
        format!(
            "{{\"schemaDocumentDigest\":\"{}\",\"schemaId\":\"{}\",\"slotValues\":{},\"salts\":{},\"setRoot\":\"{}\",\"openings\":[{}]}}",
            hex(&self.schema_document_digest),
            hex(&self.schema_id),
            list(&self.slot_values),
            list(&self.salts),
            hex(&self.set_root),
            openings.join(",")
        )
    }
}

/// Seal typed values under a schema and report the summary.
///
/// Input: `{"schema":{...}, "values":[16 typed values], "fieldSecret":"<64 hex>",
/// "open":[slot, ...]}`, `open` optional.
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

    let requested: &[Value] = match input.get("open") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(a)) => a,
        Some(_) => return Err(FieldError::new("open is a list of slots")),
    };
    let mut openings = Vec::with_capacity(requested.len());
    for r in requested {
        let slot = match json_integer(r) {
            Some(i) if (0..FIELD_SLOTS as i128).contains(&i) => i as usize,
            _ => return Err(FieldError::new("slot is 0 to 15")),
        };
        let o = open_field_slot(&fs, slot)?;
        openings.push(OpeningSummary { slot, siblings: o.siblings, bits: o.bits });
    }

    Ok(FieldSetSummary {
        schema_document_digest: schema_document_digest(schema)?,
        schema_id,
        slot_values: fs.values,
        salts: fs.salts,
        set_root: field_set_root_of(&fs),
        openings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The example schema from the sdk's profiles/fields, as the vectors carry it.
    const SCHEMA: &str = r#"{"id":"veilcore/fields/plant-variety-dus-example/v1","title":"EXAMPLE field schema: 12 marker loci and four traits for a plant variety","status":"example — not adopted by any body; a real schema names the crop, the panel and k from the examining body's guidance","slots":[{"slot":0,"path":"identification.data.loci[0]","type":"text","comparable":true},{"slot":1,"path":"identification.data.loci[1]","type":"text","comparable":true},{"slot":2,"path":"identification.data.loci[2]","type":"text","comparable":true},{"slot":3,"path":"identification.data.loci[3]","type":"text","comparable":true},{"slot":4,"path":"identification.data.loci[4]","type":"text","comparable":true},{"slot":5,"path":"identification.data.loci[5]","type":"text","comparable":true},{"slot":6,"path":"identification.data.loci[6]","type":"text","comparable":true},{"slot":7,"path":"identification.data.loci[7]","type":"text","comparable":true},{"slot":8,"path":"identification.data.loci[8]","type":"text","comparable":true},{"slot":9,"path":"identification.data.loci[9]","type":"text","comparable":true},{"slot":10,"path":"identification.data.loci[10]","type":"text","comparable":true},{"slot":11,"path":"identification.data.loci[11]","type":"text","comparable":true},{"slot":12,"path":"profileData.germinationPercent","type":"uint","scale":100,"unit":"percent"},{"slot":13,"path":"profileData.purityPercent","type":"uint","scale":100,"unit":"percent"},{"slot":14,"path":"profileData.yieldKgPerHa","type":"uint","scale":1,"unit":"kg/ha"},{"slot":15,"path":"profileData.moisturePercent","type":"uint","scale":100,"unit":"percent"}],"k":3}"#;

    /// conformance/vectors.json fieldSets[0].expected, verbatim.
    const FIRST_VECTOR: &str = r#"{"schemaDocumentDigest":"579a4560eab2755276ee7b35e585c229eb0b07c42af4d01486225be12c64bff7","schemaId":"9dd68c656b770881cad6e2be6dfc04a9b495fb90d83b78a8b295a425a7690861","slotValues":["a70dfed1d20bc248a82f687043bf842ff3e8450e4face9a1b4a73354b87ad4b6","10579c4c91c494b285b2417e68ed12c873b9d0389dc01d8d38315f683500de50","0eb2c9301347120ba0f0f7a41bcea892b1472431f3420d7d50bff1529d0bbc82","37da373c58b805b2459a6e8a94886a37158d9fb329df201cd7e52e87c9ba21a1","53fea90639640594be768ad931f128ac7100c894531eb9f2f69abe79a33dfa73","9361c2085e721f3a61b699c233b488d0652216afa2ee0d51c01322a6d1104516","90b3f983db40984723e059d544061e323eff55d5b81205383630a9b0068b64e3","b87281da2638775719aeeed1c9995c30141895b7bfdb320e1954295d9b4c59a6","2f8d90b3bbb7acdc26027eabdc828310df2387dc9da5528ab2022dfb1aeb0d1f","2da1e2c4855358a6faf21f046083a33c4a1b15b343a14fbc373887886d1932ac","4e6a61d8baafd7042e9d1b31ead836d023375e61efc9202971d4fb62541b06ea","fc6144d28fc3a540ad6cd21c00e87303a9aff664c497f7e32931583851596247","b225000000000000010000000000000000000000000000000000000000000000","fc26000000000000010000000000000000000000000000000000000000000000","0019000000000000010000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000"],"salts":["05177a4d698cefc094277881301d6052b45ef07252d013796a109e9ce94758b2","12ae01188b7ee74a73111e9deef3b8b3c1e8ff8e09ccc92a4e37eab8861feec9","1eba963044069ce2677d14c30f258becbc66df2d388578ad910e9bb3d049be0f","3410be0c50c014f465d9c08710ed8c1270219c77e87ee2751d15e1a090db6e02","aa7bd08038416a2195c43247b6f7fb06af310de2d4697173922913f62f4b3898","73c1a1d6b0c6541c596e658a2d3d1fe27c85a0c879d51db76ea596dc263d9a7b","c35b5a91e9da9d9ce0f6f94e014eb1004ba03d3512b050a5c611b4e4e1768daa","eb50f397b1bf77e16950c2ddf925153521de562665cb8c6d39767956777ebf7a","3759af9e38defb05962766ff635f4e4a284e447d9b60594ed4aeef268d0edfc3","e8454f1912311c505d9c21db038d7a22137dd7daea625fbd0c96f19d84dfbbf5","1fc229d4af3ffcc44f96c2490f521d553633e835604dc544b3dd91c4e2a2b88a","add98991cf4ffa72da510b1f32ee297dc23ebe90991a4583152406231e8db32c","ae27b23ad0f0641df99060c7690e0489a6784c61a47f60627d49d0b48309d04a","85841a2ec8aad9fe070dd399c83da7aaad8e3d6c6bf6bf2b822896dbdb969792","916e7627a6a806ff90bbb54dcb4f3d7740812d8634257ac5fc045d28b4876ff9","a0ffed7125631f1421c916a84ad727f183f202ae43c29dfd6f38ee0f672ae2f2"],"setRoot":"bcc7a07c54b73978c378b1056f52c7fb34fa7a92f85470d7f8c33f15f8758dec","openings":[{"slot":3,"siblings":["a9bf65ca4d6f527e7df4a2cc25ea9abe62a22b21f00a87711be4ec276f3f8b29","2ca62b36834ff43c88c1de28b543ea863f297ba025af2bf79a70b84e526f9c27","f72bc244a43ce77e9f3f64a7ae0f8737d93da6d3dcc2d05959e22e52da406680","df761378c8d618ce1f8e1cd012f79279cd372fef2fe0c5195f186e41010c23da"],"bits":[true,true,false,false]},{"slot":12,"siblings":["7f330dd8c8bb3c5ebbec9fcd2d1fbb7ef264729a8eaed2f5ab987d047d13884f","3b7ccd70eb0446844e9ae20f6e431b938cdd8a19056958e29d5069a6f0082177","3e207ea25bd86009c31b229cacb858238a5a052de6e3121482ec668c5109e031","3c8310cff5db406aa52178b7b5c952e6977a6036ffcf187a2295cd2e483e348f"],"bits":[false,false,true,true]},{"slot":15,"siblings":["77a5f49b927b7821f1fc24765cea9e8e3cec0f77eb7fe2b7572f4d8a451c2e7b","f800efde4dbbb4901dbdd87e8655b60c6d083b7fbb42b4a4a65c13af87d65288","3e207ea25bd86009c31b229cacb858238a5a052de6e3121482ec668c5109e031","3c8310cff5db406aa52178b7b5c952e6977a6036ffcf187a2295cd2e483e348f"],"bits":[true,true,true,true]}]}"#;

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
                {"uint":"9650"},{"uint":"9980"},{"uint":"6400"},null
            ],
            "fieldSecret": "1".repeat(64),
            "open": [3, 12, 15]
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
            assert_eq!(root_from_opening(&s.schema_id, &o), s.set_root);
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
        // conformance/vectors.json fieldSets[2], slot 0.
        assert_eq!(hex(&decomposed), "73473dcc12b763085904a5279d048c4d5b3b008c46f1f32443b99de04aa83a14");
    }

    #[test]
    fn the_schema_id_matches_the_vectors() {
        assert_eq!(
            hex(&schema_document_digest(&schema()).unwrap()),
            "579a4560eab2755276ee7b35e585c229eb0b07c42af4d01486225be12c64bff7"
        );
        assert_eq!(
            hex(&field_schema_id(&schema()).unwrap()),
            "9dd68c656b770881cad6e2be6dfc04a9b495fb90d83b78a8b295a425a7690861"
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

        let mut bad_open = first_input();
        bad_open["open"] = json!([16]);
        expect_refused(bad_open);
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
        i["schema"]["k"] = json!(3);
        assert!(field_set_summary(&i).is_ok(), "slot 15 is null in the first vector");
        i["values"][15] = json!({"uint":"1"});
        expect_refused(i);
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
