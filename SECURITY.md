# Security policy

## Reporting

Email **security@mandateco.ca** (also published at https://mandateco.ca/.well-known/security.txt). We acknowledge every report within three business days and do not pursue legal action against good-faith reporters.

Please do not open a public issue for a vulnerability before we've had a chance to respond.

## In scope for this repository

- A tampered record that exits `0`: any way to alter, add, or remove content in a signed record or access record, or in the records inside it, that this verifier still reports as VALID with the right `--expect-fingerprint`. This includes the sealed documents in `assessments/` (assessments, reviews of findings, artifact versions, measure values, impact assessment versions), the final decisions, a finding's review decision and an assessment's sign-off.
- A tampered checkpoint file that exits `0` with the right `--expect-fingerprint`.
- An outside timestamp the verifier reports as valid when it is not over its checkpoint, was not signed by a certificate for timestamping only, does not lead to a root the verifier ships or you named, or was signed outside a certificate's validity; or any input that makes the verifier report a time for a token it did not verify.
- A signed record whose checkpoints were stamped out of the order of their records, or that lacks a timestamp before a checkpoint that has one, which the verifier still reports as VALID.
- Two exports that disagree about a record, a change-trail entry or a decision's readable row inside the time both cover, which the verifier still reports as a VALID sequence.
- Fingerprint misreporting: any input that makes the verifier print a key fingerprint other than the SHA-256 of the key that actually verified, or print VALID for a key that was not named.
- Resource exhaustion within the documented caps: inputs at or under 50 MB and 1,032 entries, or a timestamp token at or under 64 KB, that hang the verifier or exhaust memory disproportionately.
- The test suite passing on a verifier that violates any of the above.

## Out of scope

- Inputs beyond the documented caps being rejected (that's the design).
- A record made before checker 2.7.0 being reported INVALID by 2.7.0 or later. CHANGELOG.md documents it; check such a record with 2.6.0.
- Whether a time-stamp authority, or a root you name with `--timestamp-root`, deserves trust.
- Vulnerabilities in Node.js itself, or in a modified copy of the verifier.
- The sample records' fictional contents.

## Reproduction material

Never attach a real record exported from a production deployment; reproduce with the records under `samples/` or a synthetic pack built the way `test/check.mjs` builds one (its ZIP writer, its test time-stamp authority and its vector signing key are public and test-only).
