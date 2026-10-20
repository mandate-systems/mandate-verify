# Changelog

## 2.5.0 (2026-10-20)

The first release here since 1.0.0. The versions between were served from https://mandateco.ca/downloads/mandate-verify.mjs only; this entry covers everything since 1.0.0.

Formats
- Signed records are format 3. The payload domain is now `mandate.evidence-pack.manifest-sig.v3`, which adds a third signed completeness flag, `mutationsTruncated`, for the change trail. A record in another format gets a plain "different format" answer and exit 3, not INVALID.
- Access records, the export that answers one person's privacy request, are checked too (payload domain `mandate.dsr.access-manifest-sig.v4`). The kind is read off the manifest.
- The manifest may carry no member its signature does not cover, and a declared fingerprint that names another key is refused rather than ignored.

The records inside a signed record
- `chain/links.json` carries every sealed record as its hashed bytes. The verifier decodes each one, checks that each names the hash of the one before, and recomputes every checkpoint root from the records. A checkpoint or record that names another workspace fails.
- Each decision in the register is tied to its sealed record field by field, the person included, and each policy version's text to its hash.
- A record erased at a person's request or under the retention setting keeps its place by its hash and names the entry in `chain/erasures.json` that records its erasure.
- Each change-trail entry, including who acted and the reason given, is sealed in the chain and must match it.
- The printed report names the SHA-256 of the summary it was drawn from, and the summary counts must match the decisions when the register is whole.
- A rule's list of names is sealed in the policy text; `policy/lists.json` carries the seal and count, and the names only when the export includes them. Included names must reproduce the seal.
- A records file that says it is partial needs a signed manifest that says so.

Several records
- Several files, or a folder of them, are checked one by one and then as a sequence: one workspace, one key or keys you named, no gap between periods, each continuing from the one before. A folder is read one neighbour at a time.
- An earlier and a later export are compared both ways over the time each covers. A record or change-trail entry that one holds and the other lacks or reads differently fails and is named; a decision erased between them is named; with keys you named, the comparison continues across a key change.

ZIP reader
- Every entry's CRC-32 is checked, and archive or entry comments, a name that differs between the local and central headers, and bytes outside the listed files are refused, so an archive passes only if every common unzip tool would read the same files.

Command line
- Without `--expect-fingerprint` the script never prints VALID: it prints NOT VERIFIED and exits 4.
- `--expect-fingerprint` accepts pairs separated by colons or spaces, in either case, and may be given more than once after a key change; every key in a record, its checkpoints included, must be one you named.
- Output reads like https://mandateco.ca/verify.html (signed record, Workspace, Period, Complete), and a VALID result ends with the decisions counted by outcome.
- `--version` prints the three payload domain tags.

Samples and repository
- The samples are three fictional firms, `samples/mandate-sample-record-{accounting,legal,litigation}.zip`, replacing the three `mandate-sample-evidence-pack-*.zip` files. Same sample signing key; the published fingerprint is unchanged.
- `test/vectors/` holds three vectors: checkpoint v1 (unchanged), evidence-pack v3 (replacing v2) and the new access-record v4.
- `test/check.mjs` carries the product's verifier suite: the record walk, the two-export comparison and the script's own output, besides the vectors and the tamper matrix. Its pack section also checks that the sample fingerprint in this README is the key that signed the samples.
- README, SECURITY.md and `docs/evidence-pack-format.md` rewritten for 2.5.0.

## After 1.0.0 (2026-08, repository only)

Samples and documentation refresh; the verifier itself was byte-unchanged at 1.0.0.

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
