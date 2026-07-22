# Security policy

## Reporting

Email **security@mandateco.ca** (also published at https://mandateco.ca/.well-known/security.txt). You'll get a reply within one business day, from the founder.

Please do not open a public issue for a vulnerability before we've had a chance to respond.

## In scope for this repository

- A tampered pack that exits `0`: any way to alter, add, or remove content in an evidence pack that this verifier still reports as VALID.
- Fingerprint misreporting: any input that makes the verifier print a key fingerprint other than the SHA-256 of the key that actually verified.
- Resource exhaustion within the documented caps: inputs at or under 50 MB and 1,032 entries that hang the verifier or exhaust memory disproportionately.
- The test suite passing on a verifier that violates any of the above.

## Out of scope

- Inputs beyond the documented caps being rejected (that's the design).
- Vulnerabilities in Node.js itself, or in a modified copy of the verifier.
- The sample packs' fictional contents.

## Reproduction material

Never attach a real evidence pack from a production installation; reproduce with the packs under `samples/` or a synthetic pack built the way `test/check.mjs` builds one (its ZIP writer and vector signing key are public and test-only).
