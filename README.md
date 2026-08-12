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

## Conformance

    cargo build --release
    node ../veilcore-sdk/conformance/run-cli.mjs target/release/conform

Apache-2.0
