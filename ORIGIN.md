# Origin and implementation scope

TufTopLevelReview independently implements this selected scope: Offline pinned-root Ed25519 TUF 1.x traditional top-level metadata chain, sequential root rotation, independent-key thresholds, expiry, caller-supplied rollback floors, byte hashes and every declared target.

The research source is [theupdateframework/python-tuf](https://github.com/theupdateframework/python-tuf) at fixed commit `1db152642ec023448a9dde7f199ddd63e920a108`. Source archive SHA-256: `b993b46c70ae7217bb209b87e13cc8fe6412292a76881002e84053c9703afce8`. Its license is MIT OR Apache-2.0; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [tuf/ngclient/_internal/trusted_metadata_set.py](https://github.com/theupdateframework/python-tuf/blob/1db152642ec023448a9dde7f199ddd63e920a108/tuf/ngclient/_internal/trusted_metadata_set.py) — SHA-256 `97ecbb5d42bf7228b56d1a65ebdebe26569470dc165e7a4386db689afbe44417`.
- [tuf/api/metadata.py](https://github.com/theupdateframework/python-tuf/blob/1db152642ec023448a9dde7f199ddd63e920a108/tuf/api/metadata.py) — SHA-256 `fbc1511c7c3485343209857b445c10277622516000ea7fd0071ca8a18b3ab175`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on traditional pinned top-level metadata chain and root rotation, expiry/version/hash linkage and selected metadata serialization. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required `trusted_root` and `trusted_root_sha256` pin the initial traditional TUF JSON bytes. Required `root_updates` is an ordered base64 list of sequential root versions; each meets both old and new root thresholds. Required base64 `timestamp`, `snapshot`, `targets`, complete base64 `target_files`, caller-authenticated `prior_versions` for all four roles and timezone-aware `now` bind the full selected chain and every target. Only TUF 1.x semver strings, Ed25519 root keys, exact four top-level roles, UTC-second metadata expiry and explicit SHA-256+length links are supported. Independent key thresholds, final root expiry, rollback floors, signature bytes, metadata version/link hashes and all target hashes/lengths are verified. Control characters, Unicode surrogates and floats are excluded from canonical JSON so supported bytes match traditional TUF canonical encoding. Delegations and missing bytes fail closed. No whole-TUF/update-client equivalence or persisted rollback protection is claimed.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.
