# veilcore-records (Rust)

A Rust implementation of the VeilCore record format:
https://github.com/hunterincoming/veilcore-sdk/blob/main/SPEC.md

It passes the same published conformance vectors as the TypeScript and Python
implementations. All three have the same author, so this shows the vectors hold across
languages. It does not show that a third party could implement the format from the
specification alone; that still needs an implementation by someone unrelated.

Dependencies: SHA-256, a JSON parser, Unicode normalisation. Nothing else. A format that
needs more than that to compute a commitment is a format that cannot be implemented by
whoever needs to implement it.

## Tests

    cargo test

Twenty-eight of them, and they cover what the format requires an implementation to REFUSE
as much as what it must accept: a null at any depth, a key collision after Unicode
normalisation, a non-finite number, a proof path over the depth cap, a malformed field
schema or slot value, a `sha256/fields/v1` record without a lowercase field binding. An implementation
that only agrees on valid input has not been shown to agree.

## Conformance

    cargo build --release

    git clone https://github.com/hunterincoming/veilcore-sdk
    node veilcore-sdk/conformance/run-cli.mjs "$PWD/target/release/conform"

Seventy-seven vectors, including field sets (`sha256/fields/v1`, spec 4.5). The runner speaks over stdin and stdout, so it drives any
implementation in any language, and it fails rather than skips when one cannot answer an
operation — a check that reports nothing is worse than a check that is missing.

## Changes

**0.3.0** — field sets, commitment algorithm `sha256/fields/v1` (spec 4.5): the
`fields` module, `fieldSchema` in the committed fields, and the `fieldSet` conformance
op. Breaking: `CanonicalError` has a new variant, `InvalidFieldBinding`, returned by
`compute_commitment` for a `sha256/fields/v1` record whose `fieldSetRoot` or
`fieldSchema` is missing or not 64 lowercase hex characters. A caller matching
`CanonicalError` exhaustively needs an arm for it. The conformance binary now answers
unreadable input with `{"error":...}` instead of panicking.

Apache-2.0
