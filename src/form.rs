// SPDX-License-Identifier: Apache-2.0
//! Checks shared by the profiles' canonical forms (sections 11.11 and 11.12).
//!
//! A value in any other form is refused, never tidied, so these only answer yes or no.

use serde_json::{Map, Value};

use crate::fields::parse_hex32;

/// The largest integer a JSON number carries exactly (section 4.4).
pub(crate) const MAX_SAFE: u64 = (1u64 << 53) - 1;

/// White space at either end of one-line text, as section 11.8 defines it: exactly what
/// ECMAScript's `String.prototype.trim()` removes, which is U+0009 to U+000D, U+0020, U+00A0,
/// U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000 and U+FEFF.
pub(crate) fn is_end_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{0B}'
            | '\u{0C}'
            | '\r'
            | ' '
            | '\u{A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// Unicode general category Cf (format characters), Unicode 17.0.0: the version of the
/// NFC tables this crate pins, and of Node's ICU that produced the vectors.
const FORMAT_RANGES: [(u32, u32); 21] = [
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// A format character (category Cf): bidirectional controls, zero-width spaces.
pub(crate) fn is_format_char(c: char) -> bool {
    let c = c as u32;
    FORMAT_RANGES.iter().any(|&(a, b)| (a..=b).contains(&c))
}

/// One-line text as the profiles define it: at most `max` characters (code points), no
/// control character (category Cc), no white space at either end. Empty is allowed here;
/// a field that must not be empty says so.
pub(crate) fn one_line(v: &Value, max: usize) -> Result<&str, &'static str> {
    let s = v.as_str().ok_or("must be text")?;
    if s.chars().count() > max {
        return Err("is too long");
    }
    if s.chars().any(char::is_control) {
        return Err("must be one line, with no tabs or control characters");
    }
    if s.starts_with(is_end_space) || s.ends_with(is_end_space) {
        return Err("must not start or end with a space");
    }
    Ok(s)
}

/// A real calendar date written `YYYY-MM-DD`.
pub(crate) fn is_date(v: &Value) -> bool {
    let Some(s) = v.as_str() else { return false };
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        b[r].iter().try_fold(0u32, |n, &c| c.is_ascii_digit().then(|| n * 10 + u32::from(c - b'0')))
    };
    let (Some(y), Some(m), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) else { return false };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d)
}

/// A JSON number with a whole value from 0 to `max`, read by value as section 11.12 says
/// counts are: `95.0` and `9.5e1` are the number 95 (section 4.4 serialises them as `95`),
/// `-0` is 0; `95.5`, `-1` and `"95"` are not whole numbers here.
pub(crate) fn whole_number(v: &Value, max: u64) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return (n <= max).then_some(n);
    }
    let f = v.as_f64()?;
    (f.fract() == 0.0 && f >= 0.0 && f <= max as f64).then_some(f as u64)
}

/// Exactly 64 lowercase hex characters.
pub(crate) fn is_hex32(v: &Value) -> bool {
    v.as_str().and_then(parse_hex32).is_some()
}

/// Every key in `required` present, and no key outside `required` and `optional`.
pub(crate) fn only(o: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|k| o.contains_key(*k)) && o.keys().all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dates_are_real_ones() {
        for ok in ["2026-11-05", "2024-02-29", "2000-02-29", "0001-01-01"] {
            assert!(is_date(&json!(ok)), "{ok}");
        }
        for bad in ["2026-02-29", "1900-02-29", "2026-13-01", "2026-00-10", "2026-1-05", "2026/11/05", "２026-11-05", ""] {
            assert!(!is_date(&json!(bad)), "{bad}");
        }
        assert!(!is_date(&json!(20261105)));
    }

    #[test]
    fn one_line_text() {
        assert!(one_line(&json!(""), 200).is_ok());
        assert!(one_line(&json!("a b"), 200).is_ok());
        assert!(one_line(&json!("é".repeat(200)), 200).is_ok());
        assert!(one_line(&json!("é".repeat(201)), 200).is_err());
        for bad in [" a", "a ", "a\n", "a\u{85}b", "\u{FEFF}a", "a\u{3000}", "a\tb"] {
            assert!(one_line(&json!(bad), 200).is_err(), "{bad:?}");
        }
        assert!(one_line(&json!(1), 200).is_err());
    }

    #[test]
    fn format_characters() {
        for c in ['\u{AD}', '\u{200B}', '\u{200E}', '\u{202E}', '\u{2066}', '\u{FEFF}', '\u{E0041}'] {
            assert!(is_format_char(c), "{c:?}");
        }
        for c in ['a', ' ', '\u{200A}', '\u{2070}', '\u{FFFC}'] {
            assert!(!is_format_char(c), "{c:?}");
        }
    }

    #[test]
    fn whole_numbers() {
        assert_eq!(whole_number(&json!(0), MAX_SAFE), Some(0));
        assert_eq!(whole_number(&json!(95.0), MAX_SAFE), Some(95));
        assert_eq!(whole_number(&json!(MAX_SAFE), MAX_SAFE), Some(MAX_SAFE));
        assert_eq!(whole_number(&json!(MAX_SAFE + 1), MAX_SAFE), None);
        for bad in [json!(-1), json!(1.5), json!("1"), json!(null), json!(true)] {
            assert_eq!(whole_number(&bad, MAX_SAFE), None, "{bad}");
        }
    }
}
