# veilcore-records (Rust)

An independent implementation of the VeilCore record format:
https://github.com/hunterincoming/veilcore-sdk/blob/main/SPEC.md

Written from the specification rather than translated from the TypeScript or Python
implementations. It passes the same published conformance vectors, which is the evidence
that the specification is unambiguous enough for a third party to implement without
consulting its authors.

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

Forty-one vectors. The runner speaks over stdin and stdout, so it drives any
implementation in any language, and it fails rather than skips when one cannot answer an
operation — a check that reports nothing is worse than a check that is missing.

Apache-2.0
