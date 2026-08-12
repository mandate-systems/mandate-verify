# Changelog

## Unreleased

Samples and documentation refresh; the verifier itself is byte-unchanged at 1.0.0.

- The three sample packs regenerated from the current exporter. Each now carries `assurance/detector-catch-rate.json`, a control-effectiveness attestation of the shipped detector library (measured catch rate against the vendor's synthetic annotated corpus, with an in-file scope statement), plus `register/mandates.json` (the authority-grant registry, added to the exporter 2026-08-06). Same sample signing key; the published fingerprint is unchanged.
- `docs/evidence-pack-format.md` inventory updated for both files. Verification never depended on the inventory: the signed manifest's content list remains authoritative in both directions.
- Test-suite synthetic pack gains the two filenames, mirroring the private harness fixture.
- The three sample packs regenerated again, adding `summary/framework-coverage.json`: the tenant's own rule-to-framework references (a closed six-id vocabulary on policy rules) and a per-framework decision rollup with an `unmapped` bucket. Its in-file scope statement carries the limit: a reference is the tenant's own annotation, recorded and not verified, and the file is not a compliance assessment. Same sample signing key; the published fingerprint is unchanged.
- Inventory and test-suite synthetic pack updated for the new filename; the signed manifest's content list remains authoritative in both directions.

## 1.0.0 (2026-07-20)

First public release. The same file has been downloadable from https://mandateco.ca/downloads/mandate-verify.mjs since July 2026; this repository adds version history, the cross-language test vectors, the test suite, sample packs, and a public format specification.

- Entry-count cap corrected from 202 to 1,032 (`EvidencePackAssembler.MaxCheckpoints` = 1,000 checkpoint files + 32 headroom for base files). The earlier cap, borrowed from an unrelated 200-entry document-import limit, made the verifier reject legitimate packs carrying roughly 194 or more checkpoints.
- `--version` flag added: prints the tool version and both supported payload domain tags.
- SPDX license header added (Apache-2.0).
