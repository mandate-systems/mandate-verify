# Changelog

## 1.0.0 (2026-07-20)

First public release. The same file has been downloadable from https://mandateco.ca/downloads/mandate-verify.mjs since July 2026; this repository adds version history, the cross-language test vectors, the test suite, sample packs, and a public format specification.

- Entry-count cap corrected from 202 to 1,032 (`EvidencePackAssembler.MaxCheckpoints` = 1,000 checkpoint files + 32 headroom for base files). The earlier cap, borrowed from an unrelated 200-entry document-import limit, made the verifier reject legitimate packs carrying roughly 194 or more checkpoints.
- `--version` flag added: prints the tool version and both supported payload domain tags.
- SPDX license header added (Apache-2.0).
