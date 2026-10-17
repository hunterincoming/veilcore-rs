# veilcore-records (Rust)

[![conformance](https://github.com/hunterincoming/veilcore-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hunterincoming/veilcore-rs/actions/workflows/ci.yml)
· Apache-2.0 · [the specification](https://github.com/hunterincoming/veilcore-sdk/blob/main/SPEC.md)

A Rust implementation of the VeilCore record format: canonical serialisation, record
fingerprints (including records that name their own key), inclusion proofs, field sets and
the report pairing. It passes the same published conformance vectors as the TypeScript and
Python implementations in [veilcore-sdk](https://github.com/hunterincoming/veilcore-sdk).

All three have the same author, so this shows the vectors hold across languages. It does not
show that a third party could implement the format from the specification alone; that still
needs an implementation by someone unrelated.

Dependencies: SHA-256, a JSON parser, Unicode normalisation. Nothing else. A format that
needs more than that to compute a commitment is a format that cannot be implemented by
whoever needs to implement it.

## Tests

    cargo test

Sixty of them, and they cover what the format requires an implementation to REFUSE
as much as what it must accept: a null at any depth, a key collision after Unicode
normalisation, a non-finite number, a proof path over the depth cap, a malformed field
schema or slot value, comparable text not in its declared format, a commitment algorithm
name that is not exactly one of the two, a field binding on the wrong algorithm, a
`keyBinding` that is not 64 lowercase hex characters. An implementation
that only agrees on valid input has not been shown to agree.

## Conformance

    cargo build --release

    git clone https://github.com/hunterincoming/veilcore-sdk
    node veilcore-sdk/conformance/run-cli.mjs "$PWD/target/release/conform"

All 121 vectors (126 with the animal records), including field sets (`sha256/fields/v1`, spec 4.5), the report
pairing (spec 3.7) and records that name their own key (spec 3.6.1), and the five animal
records of spec 11.8 (a draft). This crate doesn't check the animal profile's own form, so
run the SDK's runner with `--without-animal-profile`: its 25 refusals are then left out, and
the result says so. The runner speaks over stdin and stdout, so it drives any
implementation in any language, and it fails rather than skips when one cannot answer an
operation — a check that reports nothing is worse than a check that is missing.

## Changes

**0.4.0** — animal records (spec 11.8, a draft): `tests/animal.rs` runs the five
records of `tests/vectors/animal-individual-v1.json`, a byte-for-byte copy of the file the
VeilCore web application publishes, through `record_fingerprint`. The profile changes no
fingerprint rule, so no code changed; checking the profile's form is left to the SDK.

Also a record that names its own key (spec 3.6.1): the `key_binding` module.
`record_fingerprint` gives the fingerprint of committed fields as given, `sha256/key-bound/v1`
(`H("veilcore:v1:keyrecord", keyBinding, contentHash)`) when they carry `keyBinding` and,
unchanged, the content hash when they do not; a `keyBinding` that is present but not 64
lowercase hex characters is refused with the new `RecordFingerprintError`, a separate type
so `CanonicalError` keeps its variants. `verify_record_fingerprint` checks an export's
registered-fingerprint block, `key_matches_record` says whether a key is the one a record
named, and `identity_from_secret`, `key_salt_of`, `key_binding_of`, `key_bound_fingerprint`
and `binding_for_secret` make the pieces. The conformance binary answers the
`keyFromSecret`, `recordFingerprint` and `keyMatch` ops, and `tests/key_bound.rs` runs every
vector of `tests/vectors/key-bound-v1.json`, a byte-for-byte copy of the file the VeilCore
web application publishes. Nothing about existing hashes changes.

Also a report paired on a ledger (spec 3.7): `dna_pair_binding` computes
`H("veilcore:v1:dnapair", reportHash, identity, salt)` and the conformance binary answers
the `dnaPair` op; `is_weak_salt` says whether a salt is one byte value repeated, which
whoever makes a pairing refuses. Also hardening, no change to any hash or vector:

- `verify_inclusion` now returns `false` unless the commitment, the root and every
  sibling are 64 lowercase hex characters (spec 5.1, 5.2). New `check_proof` says why.
- The conformance binary's `fold` op refuses a malformed proof (missing commitment, a
  step that is not an object, a sibling that is not a string, a flag that is not a
  boolean). It used to read each as `""` or `false` and fold anyway.
- Key-collision detection in `canonicalise` is a set lookup rather than a scan, so an
  object with very many keys no longer takes quadratic time.
- `unicode-normalization` is pinned to `=0.1.25` (Unicode 17.0.0, the version the vectors
  were generated with), and `rust-version = "1.71"` is declared (the dependency floor).

**0.3.0** — field sets, commitment algorithm `sha256/fields/v1` (spec 4.5): the
`fields` module, `fieldSchema` in the committed fields, and the `fieldSet` conformance
op. Schemas are checked in full and their id includes a numeric-slot mask; comparable
text slots declare a format (`allele-pair`, `allele`, `code`) and only its canonical
form is accepted. Breaking:

- `CanonicalError` has five new variants, returned by `compute_commitment`:
  `InvalidFieldBinding` (a `sha256/fields/v1` record whose `fieldSetRoot` or
  `fieldSchema` is missing or not 64 lowercase hex characters),
  `FieldBindingWithoutFieldsAlgorithm` (a `sha256/canonical-json/v1` record carrying
  either), `UnsupportedCommitmentAlgorithm`, `MissingRequiredField` and
  `InvalidLedgerIdentity`. A caller
  matching `CanonicalError` exhaustively needs arms for them.
- `compute_commitment` now refuses any algorithm name other than exactly
  `sha256/canonical-json/v1` or `sha256/fields/v1`, including a missing one. It used
  to return the JSON digest for any name.
- `fieldSchema` and `fieldSetRoot` are committed fields.
- A committed field written as null (`supersedes`, `subject`, ... and `attestations` or
  `parents`) is refused with `NullInCommittedField`, as spec 4.4 rule 4 says. Until
  0.3.0 `committed_fields` dropped it, so such a record got a commitment the other
  implementations refuse. Absent `attestations` and `parents` still mean `[]`.
- A record missing a required committed field (`formatVersion`, `recordId`,
  `subjectType`, `profile`, `sealedAt`, `holder`, `profileData`) is refused with
  `MissingRequiredField` rather than hashed.
- `ledgerIdentity` (spec 3.6) is an optional committed field: an object with `chain` a
  non-empty string, `identity` 64 lowercase hex characters, `contractAddress` the same
  if present, and no other key. Anything else is refused with `InvalidLedgerIdentity`
  under either algorithm.

The conformance binary now answers unreadable input with `{"error":...}` instead of
panicking.

**0.2.0** — numbers as spec 4.4 rule 8 now says: written per ECMAScript
`Number::toString` (so 95.0 commits as `95` and 1e16 as `10000000000000000`), parsed with
correct rounding, and refused with `NumberOutOfRange` above 2^53 - 1. Before 0.2.0 this
implementation disagreed with the TypeScript and Python ones on such numbers; a
three-way differential test found it. Passes all 55 vectors of veilcore-sdk 0.14.0.

Apache-2.0
