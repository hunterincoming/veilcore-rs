//! A report paired on a ledger, per specification section 3.7.
//!
//! What a ledger pairing publishes for a report is not the report's hash but
//! `H("veilcore:v1:dnapair", reportHash, identity, salt)`: SHA-256 over four 32-byte
//! elements, the first the tag right-padded with zero bytes. A published hash could be
//! copied and paired under another identity first; the binding reveals nothing about the
//! report without the salt and holds only for the identity inside it.

use crate::fields::{hash_elements, parse_hex32, Bytes32};

/// The domain tag of a report pairing.
pub const DNA_PAIR_TAG: &str = "veilcore:v1:dnapair";

fn tag(t: &str) -> Bytes32 {
    let mut b = [0u8; 32];
    b[..t.len()].copy_from_slice(t.as_bytes());
    b
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The binding a pairing publishes, as 64 lowercase hex characters. Each input is 64
/// lowercase hex characters; anything else is refused, naming the input.
pub fn dna_pair_binding(report_hash: &str, identity: &str, salt: &str) -> Result<String, String> {
    let read = |name: &str, v: &str| {
        parse_hex32(v).ok_or_else(|| format!("{name} must be 64 lowercase hex characters (spec 3.7)"))
    };
    let r = read("reportHash", report_hash)?;
    let i = read("identity", identity)?;
    let s = read("salt", salt)?;
    Ok(hex(&hash_elements(&[&tag(DNA_PAIR_TAG), &r, &i, &s])))
}

/// A salt that hides nothing: one byte value repeated (all zero included). Spec 3.7 says a
/// salt shall not be one; whoever makes a pairing refuses it. Computing a binding does not.
pub fn is_weak_salt(salt: &Bytes32) -> bool {
    salt.iter().all(|&b| b == salt[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = "18bc28bc2feb83c05c28cc04bdda0aab7d88f668c329f7c8ae19574a79c67e8e";
    const IDENTITY: &str = "80ffc834e847d281ceba9a196e5643e68bbd9951b81cc81892035b5bd748930b";
    const SALT: &str = "1c2a98a182af6fee2dece33938396d45bd76b72c869ef8f4af6b8af975be02b1";

    #[test]
    fn matches_the_published_vector() {
        assert_eq!(
            dna_pair_binding(REPORT, IDENTITY, SALT).unwrap(),
            "d58e4e9a8c031f45dda92d0e934a782807c2f477a6738916e26e8bb432d3dc43"
        );
    }

    #[test]
    fn holds_only_for_its_own_identity_and_salt() {
        let b = dna_pair_binding(REPORT, IDENTITY, SALT).unwrap();
        assert_ne!(b, dna_pair_binding(REPORT, SALT, IDENTITY).unwrap());
        assert_ne!(b, REPORT);
    }

    #[test]
    fn refuses_inputs_that_are_not_lowercase_hex32() {
        assert!(dna_pair_binding(&REPORT.to_uppercase(), IDENTITY, SALT).unwrap_err().contains("reportHash"));
        assert!(dna_pair_binding(REPORT, &IDENTITY[..62], SALT).unwrap_err().contains("identity"));
        assert!(dna_pair_binding(REPORT, IDENTITY, &format!("0x{}", &SALT[2..])).unwrap_err().contains("salt"));
    }

    #[test]
    fn weak_salts() {
        assert!(is_weak_salt(&[0u8; 32]));
        assert!(is_weak_salt(&[7u8; 32]));
        assert!(!is_weak_salt(&parse_hex32(SALT).unwrap()));
    }
}
