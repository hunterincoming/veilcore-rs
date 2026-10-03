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

Fourteen of them, and they cover what the format requires an implementation to REFUSE
as much as what it must accept: a null at any depth, a key collision after Unicode
normalisation, a non-finite number, a proof path over the depth cap. An implementation
that only agrees on valid input has not been shown to agree.

## Conformance

    cargo build --release

    git clone https://github.com/hunterincoming/veilcore-sdk
    node veilcore-sdk/conformance/run-cli.mjs "$PWD/target/release/conform"

Fifty-five vectors. The runner speaks over stdin and stdout, so it drives any
implementation in any language, and it fails rather than skips when one cannot answer an
operation — a check that reports nothing is worse than a check that is missing.

## Changes

**0.2.0** — numbers as spec 4.4 rule 8 now says: written per ECMAScript
`Number::toString` (so 95.0 commits as `95` and 1e16 as `10000000000000000`), parsed with
correct rounding, and refused with `NumberOutOfRange` above 2^53 - 1. Before 0.2.0 this
implementation disagreed with the TypeScript and Python ones on such numbers; a
three-way differential test found it. Passes all 55 vectors of veilcore-sdk 0.14.0.

Apache-2.0
