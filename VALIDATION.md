# Validation

Recorded on 2026-10-02 for the final selected implementation. 13 unittest cases passed. Runtime dependencies: cryptography==50.0.2; PyNaCl==1.6.2 for native Ed25519 public-point validation. Python 3.14 on macOS arm64 was exercised. Other operating systems and Python versions remain untested.

The suite covers valid declared inputs, malformed/unsupported input, duplicate and nonfinite JSON, lone-surrogate input rejected through both API and CLI, bounded local regular-file reads (symlink/FIFO rejection), and failing CLI exit status. Project-specific tests cover the cryptographic or static semantics listed below. Each project with a cryptographic input also rejects identity, torsion and noncanonical Ed25519 points through its concrete application API and CLI; CRL/OCSP additionally reject certificate/CRL inner-versus-outer AlgorithmIdentifier mismatches. Shared tests reject signature key-family/hash mismatches and noncanonical signature scalars. Normal tests use temporary files and never rewrite saved examples.

## Independent or standard comparison

```json
{
  "reference": "python-tuf source commit 1db152642ec023448a9dde7f199ddd63e920a108 + securesystemslib 1.3.1",
  "full_top_level_chain_accepted_by_both": true,
  "canonical_supported_subset_vectors_in_test_suite": 3
}
```

This comparison is validation-only. Upstream application packages are not runtime dependencies. The canonical oracle is explicitly pinned in requirements-test.txt and installed before unittest in CI.

## Packaging and isolation

A wheel was built and installed into a separate per-project virtual environment with source import paths removed. The imported module resided in that environment. The installed CLI accepted the saved valid request (exit 0), rejected an empty object (exit 1), and the installed audit completed with socket creation blocked. This proves the exercised offline input profile and installed artifact; it does not prove all code paths, real deployment, program eligibility or acceptance. Final wheel SHA-256 and installation details are recorded by the aggregate publication evidence.

## Review and limits

Every new production source file was reviewed, including file handling, parser bounds, trust binding, result semantics and unsupported branches. Fixed upstream source review boundaries are listed in ORIGIN.md and provenance/SOURCE_REVIEW.json. No delegated targets, DSSE envelope, network/update client, signing or key storage. Metadata links require SHA-256+length, even where the base TUF spec permits omission. Caller must authenticate pinned root and rollback floors; no persistent state is changed. Canonical profile rejects control characters and Unicode surrogate codepoints; this makes its JSON bytes equal to traditional TUF canonical encoding within the supported subset. Missing targets or unsupported metadata semantics fail closed.

Cryptographic PASS asserts only the explicit signed input contract where `verified=true`. Static audits retain `verified=false`. An authenticated revoked status can be FAIL with `complete=true`; an unsupported or invalid input is FAIL with `complete=false`. No repository count, package build, or synthetic test is used as evidence of CVP eligibility.
