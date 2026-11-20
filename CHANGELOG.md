# Changelog

## 2.21.0 (2026-11-20)

The first release here since 2.6.0. Versions 2.7.0 to 2.20.0 were not released in this repository; each has its own entry below, and this release carries all of them.

Records made before 2.7.0
- A record exported before checker 2.7.0 (2026-10-25) seals its change-trail entries under `mandate.change-trail-entry.v1`, and its `report/summary.json` has no section on other AI tools. Versions 2.7.0 to 2.20.0 reported such a record as INVALID, though it had not changed. This version answers DIFFERENT FORMAT (exit 3) and names checker 2.6.0 (tag `v2.6.0`), which reads it.
- It does so only when every entry whose change record is in the record reproduces its seal under v1 and none under a later layout, no entry carries a mandate's, an assessment's or a record's facts, the report has no section on other AI tools, and every checkpoint is format 1. The signature, the files, the checkpoints, the records and the decisions are still checked: a record changed after it was signed, a mix of layouts or a key you did not name is INVALID.
- A record of that time with no sealed change-trail entry gives the checker nothing to recognise, and is still reported INVALID. Check it with the checker released with it.
- 2.6.0 still reports a current record as INVALID. Check a current record with this version.

Fixed
- A part named `part-K-of-N.zip` with N greater than 1, given alone or alone in a folder, passed as VALID. It now fails the sequence, and the parts it lacks are named.
- When a part was not verified for a reason of its own, such as the outside timestamps `--require-timestamps` asks for, `SEQUENCE:` said VALID and `OVERALL:` gave the unchecked key as the reason. Both now say NOT VERIFIED and give that part's reason.
- A sequence holding a part in a format this checker does not read was INVALID. It now reads NOT CHECKED (exit 3), and the pairs without that part are still compared.
- `--json` printed nothing when a file could not be read (exit 2). It now prints a document naming the file and the error.
- The usage text gives exit 4 both its reasons, and says a later export must start by a minute before one in progress was made, as the check does.

Repository
- `test/vectors/checkpoint-timestamp-v1.vector.json` is new: a real RFC 3161 token from DigiCert's public timestamp service over the checkpoint of `checkpoint-signed-payload-v1.vector.json`.
- `test/check.mjs` carries every case added from 2.7.0 to 2.21.0, in sections numbered 1 to 7, each label naming the release that first carried its check. Four options write synthetic records signed with the test key (`--write-joined-pair`, `--write-final-decisions`, `--write-sign-off`, `--write-earlier-layout`), so an earlier checker can be run on the same files.
- The three sample records were exported again. Each carries an assessment, a review of one of its findings and an artifact version, and every checkpoint carries an outside timestamp. Same sample signing key; the published fingerprint is unchanged.
- README, SECURITY.md and `docs/evidence-pack-format.md` updated for everything since 2.6.0. The README defines the terms the output uses.

## 2.20.0 (2026-11-17)

Fixed
- A remediation can be linked to the problem it answers: a measure value that went past its limit. In the artifact version's sealed record the link is `{ "target": "breach", "id": "<measure value id>" }`; in the readable row of `assessments/artifacts.json` it names the same value as `measureValueId`. Another value, or none, fails as a changed link. 2.19.0 read such a row's link as naming nothing and failed the pack.

## 2.19.0 (2026-11-16)

Stricter
- A finding's review decision in `assessments/findings.json` (`reviewState`, `reviewedResult`, `reviewedConfidence`, `reviewedAt`, `reviewedBy`) must be the one its latest review in `assessments/reviews.json` gives, or empty when no review decides it. This is checked while the reviews file is whole.
- An assessment shows as signed off exactly when every finding has a decision, at the time and by the person of the last decision. Its sign-off is a change-trail entry that records the assessment and the SHA-256 of its document; it must name the document the pack carries, there may be only one, and a pack whose change trail is whole fails when it shows a sign-off the trail does not carry.
- 2.18.0 passed a pack whose findings showed a review decision or a sign-off their sealed reviews do not give.

## 2.18.0 (2026-11-12)

Outside timestamps
- A checkpoint may carry an RFC 3161 timestamp from an independent timestamp authority, which shows the checkpoint existed by that time. Checkpoint format 2 adds `timestampTokenBase64`: the token, over the checkpoint's signed payload, then its signature, then its public key, or `null` while none has been obtained. Format 1 checkpoints are read as before.
- Each token is checked offline: SHA-256 over those bytes; signed by a certificate whose only use is timestamping; a chain to a root the checker ships (DigiCert Trusted Root G4) or one you name with `--timestamp-root`; every certificate valid at the stamped time; the authority's stated accuracy within a minute. A token that fails makes its checkpoint INVALID. A token whose chain leads to no root the checker holds is reported as one it cannot check, never as valid or invalid.
- In a signed record, a checkpoint without a token before a checkpoint with one, or a checkpoint stamped more than five minutes before a checkpoint that seals earlier records, makes the record INVALID: Mandate stamps checkpoints in the order of their records, so either means a checkpoint was replaced, or its token removed, after the fact. A token the checker cannot check before one it can makes the result NOT VERIFIED (exit 4) until its authority's root is named.
- The output names each checkpoint's stamp and authority, the checkpoints without one, how far the records are shown sealed by an outside time, and any token more than a day after its records.
- `--timestamp-root <file>` names a root certificate (PEM or DER) to trust as well. `--require-timestamps` reports NOT VERIFIED (exit 4) unless every checkpoint carries a token the checker can check, stamped within a day of its last record; in a record, only checkpoints of its last two hours may have none yet.
- A checkpoint file of a format other than 1 or 2 is a different format (exit 3).

## 2.17.0 (2026-11-12)

Sealed documents in the assessment files
- `assessments/findings.json`, `reviews.json`, `artifacts.json`, `measure-values.json` and `impact-assessments.json` carry each document as the exact text Mandate hashed. The checker recomputes each one: it must equal the SHA-256 beside it and the SHA-256 its change-trail entry carries, and the readable row beside it must say what the document says.
- A file not cut at its size limit must hold every document the change trail seals in its period, or name it as deleted with its AI system. A review must name the assessment document the pack carries.
- A document whose change-trail entry is not sealed in the export is counted as not checked. A file of a later version is not compared, and the output says why.
- An export whose assessment files were cut at their size limit is reported as partial and names them.
- A record exported before these files verifies as before.

## 2.16.0 (2026-11-10)

Final decisions
- `assessments/final-decisions.json` lists the final decisions a system's case system recorded in Mandate, batch by batch. Each batch's record is the exact text Mandate hashed, and its SHA-256 is carried by a change-trail entry sealed like any other.
- Each decision is a document and a salt, so one decision can be shown and checked without disclosing the others. The SHA-256 of the salt and the document must be a digest the batch's record lists, and every listed digest must be carried once. An erased decision keeps only its digest and is counted as erased.
- A decision or batch record that names another Mandate ID, batch or AI system fails. A batch whose change-trail entry is not sealed in the export is counted as not checked, never as a pass. A file of a later version is not compared.
- The output has one line for the file. A record without it verifies as before.

## 2.15.0 (2026-11-09)

Imported activity
- A version 2 `imports/<feed>.json` lists Mandate's own notes on reading a row (`notes`) apart from the rules that fired on it (`ruleHits`), and the report counts the rows Mandate could not read in full. The checker recomputes that count. A row that lists a note among the rules that fired, or a rule among the notes, fails. A version 1 file is read as before; a later version is not compared, and the output says why.

Complete exports
- A complete export, the single archive Mandate downloads for a long period, is known by what it holds, whatever its name: records named `part-K-of-N.zip` and no `manifest.json`. It is not signed, so it is never checked as a record. Given alone, the script says what it holds, names any part it lacks, and exits 2. In a folder beside its unzipped parts, it is set aside with a note. 2.14.0 refused only a file whose name ended in `-packs.zip`.
- Records named as the parts of one complete export must all be there: a part missing, or given twice, fails the sequence and is named.

Command line
- A check of several files ends with one line, `OVERALL:`, whose word always matches the exit code. `SEQUENCE:` never says VALID while a part failed its own check.
- `--json` for several files adds `result` (the overall word) and `setAside`.

## 2.14.0 (2026-11-02)

- A record chained as a test-set prompt (outcome `test`) links and verifies like any other, and is counted as a test prompt, not as a decision.

## 2.13.0 (2026-11-01)

- A change-trail entry that records a governance record, such as the review of a finding or a version of an artifact, carries `record` (its kind, its id and the SHA-256 of its document) and is sealed under `mandate.change-trail-entry.v5`. Its facts rewritten or removed after sealing fail. An entry, sealed yet or not, that carries a field the seal does not cover is refused, and a sealed entry that carries the facts of more than one kind fails.

## 2.12.0 (2026-10-31)

- A change-trail entry that records a concluded assessment carries `assessment` (its id and the SHA-256 of its document) and is sealed under `mandate.change-trail-entry.v4`, with the same rules.

## 2.11.0 (2026-10-31)

- A change-trail entry that records what a mandate approves or ends carries `mandate` (its code, its tools, its purposes, its dates, and on an end what the agent does next and the mandate that took it over) and is sealed under `mandate.change-trail-entry.v3`, with the same rules.

## 2.10.0 (2026-10-29)

In progress
- A record made before its period ended (its signed `generatedAt` before its signed `windowTo`) is in progress. It is valid; the result reads `VALID, IN PROGRESS` and says it holds what was recorded up to when it was made, or nothing of its period when it was made before the period began. Its `report/summary.json` must say so, and must not say so when the record was made after its period ended. An access record whose range ends after it was made is in progress too.
- In a sequence, a part in progress covers its period up to a minute before it was made, so the next part must start by then or the time between is in neither. A sequence whose parts hold less than their period reads `SEQUENCE: VALID, IN PROGRESS` and says how far they cover.

Checkpoint files
- A checkpoint downloaded from Mandate's Checkpoints page, a file whose name ends in `.json`, is checked on its own: its members, its signature, its declared fingerprint and its key. Its times are not signed, and the output says so. Given beside records, or found in a folder of them, it is checked after them and apart from their sequence. A checkpoint renamed `.zip` is not read as a record.

Command line
- The output and messages say `Mandate ID` where they said `workspace`. In `--json`, a sequence of two Mandate IDs fails with kind `mandate-id`.
- With several files, the exit code is the most serious of them: 1 first, then 3, then 2, then 4, then 0. Before, a different format (3) or an unreadable file (2) outranked a failed check.
- `--json` prints one JSON document. For a folder or several files it lists every file with its own result and exit code, the sequence when there is one, and the exit code for them all.
- Without `--expect-fingerprint`, nothing printed calls the record unchanged: the result reads `NOT VERIFIED (signed by a key that was not checked: ...)`.

## 2.9.0 (2026-10-27)

- Two exports: a change-trail entry that a later export lacks because its change record was erased with the records it belongs to is not a failure; the erased record is named. An entry not yet sealed when the earlier export was made, and absent from the later one, is named in a note and not compared, unless the later export still carries its change record.

## 2.8.0 (2026-10-26)

- `report/summary.json` must say what the organization's other AI tools reported in their own logs, and its figures must be the ones the pack's `imports/<feed>.json` files give: the feeds, the rows, the rows a rule fired on, and the earliest and latest times the vendor reported. The `imports` block of `summary/decision-mix.json` must say the same. A record exported before 2.8.0 has no such section and failed this check until 2.21.0, which answers a record in the change-trail layout used before 2.7.0 as a different format (see the 2.21.0 entry).

## 2.7.0 (2026-10-25)

- A change-trail entry's seal covers what a policy version changed (`transition.changes`), under `mandate.change-trail-entry.v2`. A change to a list of names says how many names were added and removed, never which. An entry that names a list's entries is refused whether or not it is sealed yet, as is a change with a field the seal does not cover.
- A record exported before 2.7.0 seals its entries under v1, which this version does not read, so it fails, as it does with every version up to 2.20.0. See the 2.21.0 entry.

## 2.6.0 (2026-10-20)

Edge cases found while the format specification was written. A genuine record that passed 2.5.0 passes 2.6.0.

Stricter
- A checkpoint's own `publicKeyFingerprint` must name the key that signed it, as the manifest's must since 2.5.0.
- The access record follows the signed record's manifest rules: no member its signature does not cover, a declared fingerprint that names the signing key, and format 3; an access record of another format gets the plain "different format" answer and exit 3.
- Each file's length must equal the `byteLength` the manifest signs, and a negative or fractional `byteLength` makes the manifest INVALID.

Fixed
- A manifest key that does not decode to 32 bytes is INVALID with a plain reason (exit 1). 2.5.0 reported it as a runtime without Ed25519 (exit 3).
- Two exports no longer disagree over `actorSalt`, the salt that seals who acted on a change-trail entry. It is not compared: an entry exported before it was sealed carries none, and an entry that no longer names who acted is a note, as intended.
- Two exports of one workspace compare its id as the 16 bytes the signatures bind, so a `tenantId` written in capitals no longer reads as another workspace.
- The usage text gives exit 3 both meanings: a format this script does not read, or no Ed25519 in this runtime.

Repository
- The descriptions in `test/vectors/` say what each vector holds and name nothing from the product's own code.
- `test/check.mjs` covers each case above; with `MIRROR=1` it also checks the version and SHA-256 that verify.html names for this file.

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

- The three sample packs regenerated from the current exporter. Each now carries `assurance/detector-catch-rate.json`, a control-effectiveness attestation of the shipped detector library (measured catch rate against the vendor's synthetic annotated corpus, with an in-file scope statement), plus `register/mandates.json` (the list of mandates). Same sample signing key; the published fingerprint is unchanged.
- `docs/evidence-pack-format.md` inventory updated for both files. Verification never depended on the inventory: the signed manifest's content list remains authoritative in both directions.
- Test-suite synthetic pack gains the two filenames.
- The three sample packs regenerated again, adding `summary/framework-coverage.json`: the organization's own rule-to-framework references (a closed six-id vocabulary on policy rules) and a per-framework decision rollup with an `unmapped` bucket. Its in-file scope statement carries the limit: a reference is the organization's own annotation, recorded and not verified, and the file is not a compliance assessment. Same sample signing key; the published fingerprint is unchanged.
- Inventory and test-suite synthetic pack updated for the new filename; the signed manifest's content list remains authoritative in both directions.

## 1.0.0 (2026-07-20)

First public release. The same file has been downloadable from https://mandateco.ca/downloads/mandate-verify.mjs since July 2026; this repository adds version history, the cross-language test vectors, the test suite, sample packs, and a public format specification.

- Entry-count cap corrected from 202 to 1,032 (1,000 checkpoint files + 32 other files). The earlier cap rejected genuine records with roughly 194 or more checkpoints.
- `--version` flag added: prints the tool version and both supported payload domain tags.
- SPDX license header added (Apache-2.0).
