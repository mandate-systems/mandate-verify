# mandate-verify

Offline checker for the signed records that [Mandate](https://mandateco.ca) exports. One file, zero dependencies, Node.js 20 or newer. It proves that a record you hold is the one its signer signed, and that the records inside it still link in order, without contacting Mandate or anyone else.

A signed record (the format calls it an evidence pack) is a ZIP of JSON files exported from Mandate: the decision register, the policy text behind each decision, the change trail, the underlying records as their sealed bytes, signed checkpoints over those records, the assessments of AI systems with the documents behind them, a printed report, and a `manifest.json` that lists every file's SHA-256 under one Ed25519 signature. The same script checks access records, the export Mandate makes to answer one person's privacy request, and a checkpoint saved on its own. The formats are specified in [docs/evidence-pack-format.md](docs/evidence-pack-format.md).

## Run it

Two ways, same file:

```
# git
git clone https://github.com/mandate-systems/mandate-verify
node mandate-verify/mandate-verify.mjs record.zip --expect-fingerprint <fingerprint from your agreement>

# direct download (the canonical artifact; this repository mirrors it)
curl -O https://mandateco.ca/downloads/mandate-verify.mjs
node mandate-verify.mjs record.zip --expect-fingerprint <fingerprint from your agreement>
```

No packages are installed or downloaded at run time. The only imports are Node built-ins (`fs`, `path`, `zlib`, `url`), signatures are checked with the runtime's own WebCrypto, and CI enforces the imports with a grep.

## Quick start with a sample record

Three sample records of fictional firms, exported the same way a customer's record is, live in [`samples/`](samples/). They are signed with a key used only for them. Check one and name that key, so the trust step runs instead of being skipped:

```
node mandate-verify.mjs samples/mandate-sample-record-accounting.zip \
  --expect-fingerprint 9a914bf1310855175c7d868ad434987075412f627b2e8c18e5634e0bfcba045f
```

The same fingerprint is published at https://mandateco.ca/verify.html, which runs this file's checks in the browser. Every checkpoint in the samples carries an outside timestamp from DigiCert's public timestamp service, which the script checks offline.

## Terms used here

- **Mandate** is the company and its product. A **mandate**, in lower case, is an approval that lets an AI agent use named tools for named purposes.
- A **checkpoint** is a signed statement over a run of records: how many there are, the first and last record's ids, and the root of a hash tree over them.
- **Sealed** means fixed by a hash that a signed checkpoint covers, directly or through a record in the chain, so it cannot change without a check failing.
- The **change trail** is the list of changes made to an organization's policies, settings and approvals, each entry sealed into the records.
- An **assessment** checks one AI system against a framework, a set of requirements, at one time. A **finding** is its result for one requirement: met, partially met, not met, not applicable or unable to determine.
- An **artifact version** is one dated version of something the organization gives as evidence, such as a document, an approval, an attestation, a link or a remediation.
- A **measure value** is one reading of a number Mandate tracks about an AI system, compared with a limit set for it.
- A **case system** is the organization's own system for the cases an AI system helps with. A **final decision** is the decision a person recorded there, which the case system sends to Mandate.
- An **access record** is the export Mandate makes to answer one person's request to see the records about them (a data subject request, DSR).
- **OSCAL** is the Open Security Controls Assessment Language, a NIST format for assessment results. A record carries its assessments in that format as well.

## What VALID means

- Every file matches the SHA-256 and the byte length the signed manifest lists for it, and the file sets match both ways: nothing added, nothing removed. The manifest itself, in a signed record or an access record, carries nothing its signature does not cover.
- The manifest's Ed25519 signature verifies over a canonical payload that binds the Mandate ID, the format version, when the export was made, the period it covers, three completeness flags, and every filename, hash and byte length.
- Every checkpoint's signature verifies, and every checkpoint root is recomputed from the records in `chain/links.json`. Each record names the hash of the one before it, so an edited or reordered record, or one taken out from between two others, breaks the chain. A record erased at a person's request or under the retention setting keeps its place by its hash and names the entry that records its erasure.
- Every outside timestamp (RFC 3161) the script can check, one whose certificates lead to a root it ships or one you named, is over its checkpoint, signed by a certificate for timestamping only, and valid at the time it states. The checkpoints were stamped in the order of the records they seal, and none without a timestamp comes before one with a timestamp.
- Each decision in the register matches its sealed record field by field, the person included. Each change-trail entry matches its sealed record, each policy version's text matches its hash, and the printed report names the summary it was drawn from. When the register is whole, the summary counts must match the decisions. What the report says other AI tools reported matches the pack's imported rows.
- A rule's list of names (a client list, for example) is sealed in the policy text as a seal and a count. When the export includes the names, they must reproduce the seal; when it leaves them out, the script says so.
- Each assessment, review of a finding, artifact version, measure value and impact assessment version in `assessments/` is the exact document Mandate sealed, and the readable row beside it says what the document says. Each finding shows the decision its latest sealed review gives, and an assessment shows as signed off only once every finding has a decision, as its sealed sign-off records. Each final decision a case system recorded matches the digest its sealed batch lists.
- Every key that signed the record, its checkpoints included, is one you named with `--expect-fingerprint`. The fingerprint printed is the SHA-256 of the key that actually verified, and a manifest or checkpoint that declares a different fingerprint is refused.

A record made before its period ended is valid and in progress: the result reads `VALID, IN PROGRESS` and says it holds what was recorded up to when it was made.

## What VALID does not mean

- **It does not prove the recorded events are true**, only that the record has not changed since it was signed.
- **It does not prove who holds the key.** A signature binds a record to a key, and which keys you trust is your step: the sample key above, or the fingerprint in your agreement for a real record. Without `--expect-fingerprint` the script never prints VALID; it prints NOT VERIFIED and exits 4.
- **One export alone cannot catch the key holder.** Whoever holds the signing key can leave out the last record of a period and sign again, and that export passes on its own. Check it together with an earlier export of the same period and the script names any record or change-trail entry that went missing or reads differently. Outside timestamps narrow this: a checkpoint replaced after a later checkpoint was stamped is out of order, and the record fails; one stamped more than a day after its records is named as late.
- **An outside timestamp shows when a checkpoint existed, not that its records are true.** One stamped more than a day after its records shows only that the checkpoint existed by then, and the script names it. A timestamp from an authority whose root the script does not hold is reported, never counted as valid or invalid; name that root with `--timestamp-root` to check it. A checkpoint without a timestamp is named, and fails only with `--require-timestamps`.
- **Complete means what the signed manifest says.** A capped export says so in its signed flags, or in the signed files that were cut, and the script reports it as partial, naming what was cut. Traffic that never passed through Mandate was never in scope.
- **An assessment's result is what Mandate's record showed against a requirement.** The script proves the documents are the ones sealed; it does not judge whether a system meets a framework.

## Several records

Give the script several files, or a folder (every `.zip` in it, in name order), and it checks each one and then checks them together: the parts of one long export, or an earlier and a later export. They must have one Mandate ID, be signed by one key or by keys you named, leave no gap between their periods, and each continue from the one before. No record or change-trail entry that one holds inside the time the other covers may be missing from the other or read differently there, who acted included: a later export cannot drop the name of whoever acted on an entry an earlier export names, and a copy of an entry must match the sealed record the other export carries. Each export is held to its period up to a minute before it says it was made, or only to the span its records hold when it says it is partial, and what that leaves out is named, as is any decision erased between the two exports. A part made before its period ended covers it up to a minute before it was made, so the next part must start by then. Any two exports whose periods or records overlap in time, or that hold the same record or decision, are compared, not only neighbours (exports next to each other in order). A change-trail entry that any two hold must read the same in both, whatever their periods. A folder is read a part at a time: the script keeps two parts, the change-trail entries it has read and the id of every record and decision it has read, and reads two parts again to compare them when they are not neighbours but overlap or hold the same record or decision.

A long period downloads as one archive of parts, a complete export. Unzip it and give the script the folder. The archive itself is not signed, so the script never checks it as a record: given alone, it says what the archive holds and exits 2; left in the folder beside its parts, it is set aside. Parts named `part-K-of-N.zip` must all be there, even when one part is given alone: a missing part is named and the sequence fails.

A check of several files, or of one part of several, ends with one line, `OVERALL:`, whose word matches the exit code. When nothing failed and a file is not verified for a reason of its own, such as the outside timestamps `--require-timestamps` asks for, the `SEQUENCE:` and `OVERALL:` lines give that reason.

## A checkpoint on its own

A checkpoint saved from Mandate's Checkpoints page is a `.json` file. The script checks it on its own: its members, its Ed25519 signature over the Mandate ID, the first and last record's ids, how many records there are and their root, its key, and its outside timestamp when it carries one. The window times in the file are not signed, and the output says so. An export of the same period checks the records themselves. A checkpoint given beside records, or found in a folder of them, is checked after them and apart from their sequence.

## Exit codes and JSON output

```
0  valid, and every key is one you named with --expect-fingerprint
1  invalid, signed by a key you did not name, or records that do not join or lack a part
2  usage error, unreadable file, not a readable ZIP archive, or a complete export given as one file
3  a different format than this script reads, such as a record in the change-trail layout used before 2.7.0 (below),
   or no WebCrypto Ed25519 in this runtime (use Node 20 or newer)
4  not verified: signed by a key that was not checked (no fingerprint named), or outside timestamps the script could not check (below)
```

With several files the exit code is the most serious of theirs: 1 first, then 3, then 2, then 4, then 0.

`--json` prints one JSON document: for one file, that file's result, or the error when the file cannot be read; for a folder, several files or one part of several, every file with its own result and exit code, the sequence when there is one, any complete export set aside, and the result and exit code for them all. `--version` prints the tool version and the three payload domain tags it reads. `--expect-fingerprint` takes 64 hex characters, plain or in pairs separated by colons or spaces, in either case; give it more than once after a key change.

`--timestamp-root <file>` names a root certificate (PEM or DER) to trust for outside timestamps, beside the one the script ships (DigiCert Trusted Root G4); give it more than once for several. A timestamp the script cannot check, placed before one it can, makes the result NOT VERIFIED until its authority's root is named. `--require-timestamps` reports NOT VERIFIED unless every checkpoint carries a timestamp the script can check, stamped within a day of its last record; in a record, only checkpoints of its last two hours may have none yet.

## How it works

Read the file; it is meant to be read top to bottom. In outline:

1. A hand-rolled ZIP reader with hardened limits: 50 MB total, 1,032 entries, no zip64, no encryption, no comments, stored and deflate entries only, duplicate names rejected, every entry's CRC-32 checked, and no bytes outside the listed files. An archive passes only if every common unzip tool would read the same files the script checked.
2. Per-file SHA-256 recomputation against `manifest.json`, then set equality both ways.
3. The manifest's canonical signed payload rebuilt and verified with WebCrypto Ed25519: domain tag `mandate.evidence-pack.manifest-sig.v3` for a signed record, `mandate.dsr.access-manifest-sig.v4` for an access record.
4. The same for each checkpoint (domain tag `mandate.audit.checkpoint-sig.v1`, a fixed 119-byte payload), then each checkpoint's outside timestamp: a strict DER reader for the RFC 3161 token, its RSA or ECDSA signatures checked with WebCrypto, and its certificate chain walked to a root.
5. The walk over the records and the readable files tied to them, as listed under What VALID means, then the order of the outside timestamps along the records.
6. With several records, the comparison between them.

Byte layouts, the manifest schemas and the trust model are in [docs/evidence-pack-format.md](docs/evidence-pack-format.md). The payload layouts are pinned by the cross-language test vectors in [`test/vectors/`](test/vectors/), the same vectors the product's own test suites assert; the signing seed in the vectors is all zeros and test-only. The timestamp vector holds a real token from DigiCert's public timestamp service.

## Records made with earlier versions

A record exported before checker 2.7.0 (2026-10-25) seals its change-trail entries in an earlier layout, which this version does not read. When every sealed entry is in that layout and nothing in the record comes from a later version, this version answers DIFFERENT FORMAT and exits 3, naming checker 2.6.0 (tag `v2.6.0`), which reads it. It still checks the signature, the files, the checkpoints and the records, so a record changed after it was signed, or signed by a key you did not name, is INVALID.

A record of that time with no sealed change-trail entry gives this version nothing to recognise, so it is reported INVALID: check it with the checker released with it. [CHANGELOG.md](CHANGELOG.md) lists what each version reads.

## Test suite

```
node test/check.mjs             # offline: vectors, tamper matrix, record walk, two-export comparison, timestamps, sample records
MIRROR=1 node test/check.mjs    # also byte-compare this repository against the live site
```

The tamper matrix covers content flip, injected file, metadata flips on the completeness flags, missing file, duplicate entry, entry-count bomb, declared-size bomb, non-ZIP input, fingerprint spoofing in the manifest and in a checkpoint, unsigned manifest members, malformed manifest entries, a key that is not 32 bytes, a signed length that is not the file's, and a legitimate high-compression pack that must still pass. The record walk covers edited, swapped and foreign records, a register row, person, change-trail entry, erasure, policy text, sealed list, imported figure or printed report that no longer matches, a sealed assessment, review, artifact version, measure value or impact assessment version rewritten or left out, a finding's review decision or an assessment's sign-off that its sealed reviews do not give, a final decision changed after sealing, and a records file that claims to be partial under a manifest that says complete. The comparison covers a record left out of a re-signed later export, in either order, decisions erased between exports, a key change, a change-trail entry that no longer names who acted or was sealed between the exports, a part in progress, and a Mandate ID written in capitals. The timestamp checks run a real DigiCert token, every one-byte change to it, and a test authority built by the suite that signs tokens with each flaw the script refuses. The suite also runs the script itself the way an auditor would and checks its exit codes and result lines, for records, checkpoint files, folders and complete exports. The same file matrix runs over a synthetic access record, with its manifest rules and a format the script does not read.

`node test/check.mjs --write-joined-pair <dir>`, `--write-final-decisions <dir>`, `--write-sign-off <dir>` and `--write-earlier-layout <dir>` write synthetic records signed with the test key into `<dir>` and stop, so an earlier version of the script, or verify.html, can be run on the same files.

## Provenance

The canonical artifact is the file served at `https://mandateco.ca/downloads/mandate-verify.mjs`. This repository mirrors it, and the weekly `mirror` CI job byte-compares the two (plus the checker core embedded in verify.html). You can run the same comparison yourself with `MIRROR=1`, or just `diff` the downloads. Releases carry a `SHA256SUMS` file; the same hash is published on verify.html, so the site and this repository attest each other.

## Relationship to the product repository

Checker changes originate in Mandate's product repository, where the payload builders are tested against the implementation that produces real records, and are published here and on the site together. Issues and documentation fixes are welcome in this repository; for changes to verification logic, open an issue first so the change lands through that path rather than diverging the mirror.

## Security

See [SECURITY.md](SECURITY.md). Report to security@mandateco.ca; never attach a real customer record, reproduce with the samples.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
