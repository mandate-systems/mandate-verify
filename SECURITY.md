# Security policy

## Reporting

Email **security@mandateco.ca** (also published at https://mandateco.ca/.well-known/security.txt). We acknowledge every report within three business days and do not pursue legal action against good-faith reporters.

Please do not open a public issue for a vulnerability before we've had a chance to respond.

## In scope for this repository

- A tampered record that exits `0`: any way to alter, add, or remove content in a signed record or access record, or in the records inside it, that this verifier still reports as VALID with the right `--expect-fingerprint`.
- Two exports that disagree about a record, a change-trail entry or a decision's readable row inside the time both cover, which the verifier still reports as a VALID sequence.
- Fingerprint misreporting: any input that makes the verifier print a key fingerprint other than the SHA-256 of the key that actually verified, or print VALID for a key that was not named.
- Resource exhaustion within the documented caps: inputs at or under 50 MB and 1,032 entries that hang the verifier or exhaust memory disproportionately.
- The test suite passing on a verifier that violates any of the above.

## Out of scope

- Inputs beyond the documented caps being rejected (that's the design).
- Vulnerabilities in Node.js itself, or in a modified copy of the verifier.
- The sample records' fictional contents.

## Reproduction material

Never attach a real record exported from a production workspace; reproduce with the records under `samples/` or a synthetic pack built the way `test/check.mjs` builds one (its ZIP writer and vector signing key are public and test-only).
