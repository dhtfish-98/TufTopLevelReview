# TufTopLevelReview

Offline pinned-root Ed25519 TUF 1.x traditional top-level metadata chain, sequential root rotation, independent-key thresholds, expiry, caller-supplied rollback floors, byte hashes and every declared target.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. Cryptographic primitives use cryptography; no upstream application is called.

## Contract

Run `tuf-top-level-review request.json` or pipe JSON to `tuf-top-level-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- No delegated targets, DSSE envelope, network/update client, signing or key storage. Metadata links require SHA-256+length, even where the base TUF spec permits omission. Caller must authenticate pinned root and rollback floors; no persistent state is changed. Canonical profile rejects control characters and Unicode surrogate codepoints; this makes its JSON bytes equal to traditional TUF canonical encoding within the supported subset. Missing targets or unsupported metadata semantics fail closed.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required `trusted_root` and `trusted_root_sha256` pin the initial traditional TUF JSON bytes. Required `root_updates` is an ordered base64 list of sequential root versions; each meets both old and new root thresholds. Required base64 `timestamp`, `snapshot`, `targets`, complete base64 `target_files`, caller-authenticated `prior_versions` for all four roles and timezone-aware `now` bind the full selected chain and every target. Only TUF 1.x semver strings, Ed25519 root keys, exact four top-level roles, UTC-second metadata expiry and explicit SHA-256+length links are supported. Independent key thresholds, final root expiry, rollback floors, signature bytes, metadata version/link hashes and all target hashes/lengths are verified. Control characters, Unicode surrogates and floats are excluded from canonical JSON so supported bytes match traditional TUF canonical encoding. Delegations and missing bytes fail closed. No whole-TUF/update-client equivalence or persisted rollback protection is claimed.

All accepted Ed25519 public keys are canonical nonidentity points in the main subgroup, checked through libsodium. Ed25519 signature R points must also be canonical nonidentity main-subgroup points and S must be below the group order. Certificates and CRLs require exactly matching inner/outer AlgorithmIdentifiers; the strict profile permits only RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and Ed25519 with absent parameters. OCSP permits the same explicit algorithm encodings and key-family/hash binding.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m pip install -r requirements-test.txt
python -m unittest discover -s tests -v
tuf-top-level-review examples/valid.json
```

See [ORIGIN.md](ORIGIN.md), [VALIDATION.md](VALIDATION.md), [LICENSE](LICENSE) and [UPSTREAM_LICENSE](UPSTREAM_LICENSE) for scope, evidence and attribution.
