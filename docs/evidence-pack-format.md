# Mandate evidence pack: format specification

This document specifies what is needed to check a Mandate evidence pack (the site and the CLI call it a signed record) independently: the container, the manifest, the three signed payloads, the checkpoints and their outside timestamps, the records inside the pack, what ties the readable files to those records, the rules for comparing several packs, and the access record. It is the public companion to `mandate-verify.mjs` 2.23.0, which implements exactly what is written here.

Version note: the manifest signature format is `v3`, the checkpoint signature format is `v1`, the access-record signature format is `v4`, the manifest schema version is `3`, checkpoint files are formats `1` and `2`, records use layouts `1` to `9`, and change-trail entries are sealed under layouts `v2` to `v5`. These numbers move independently. `node mandate-verify.mjs --version` prints the tool version and the three domain tags. A record exported before checker 2.7.0 (2026-10-25) seals its change trail under layout `v1`, which this version answers as a different format (section 6.3).

Conventions: integers are big-endian (ZIP structures excepted, which are little-endian as ZIP defines them). A UUID is 16 bytes in RFC 4122 wire order, which is the 32 hex digits of its text form, in order; two UUIDs are the same when their 16 bytes are. Hex is accepted in either case and compared case-insensitively, unless a rule below says lowercase. `||` is concatenation. Absent means a member that is missing or `null`.

## 1. Container

An evidence pack is a ZIP archive. The reader accepts one only if every common unzip tool would read the same files from it:

| Rule | Value |
| --- | --- |
| Archive size | at most 52,428,800 bytes (50 MB) |
| Sum of declared uncompressed sizes | at most 52,428,800 bytes |
| Entry count (folders included) | at most 1,032 (1,000 checkpoint files + 32 headroom for base files) |
| zip64 | rejected (entry count `0xFFFF`, or any size or offset `0xFFFFFFFF`) |
| Encrypted entries (flag bit 0) | rejected |
| Compression methods | stored (0) and deflate (8) only |
| Duplicate file names | rejected |
| Archive comment, entry comments | rejected |
| CRC-32 | checked on every file (since 2.5.0) |

The reader also requires:

- The archive ends with a 22-byte end-of-central-directory record, and the central directory ends exactly where that record starts.
- A folder entry (name ending in `/`) holds no data. Folders are not files and need no manifest entry.
- Each entry's local header carries the same name as its central-directory entry. Names are read as UTF-8.
- A deflated file inflates to no more than its declared uncompressed size; every file comes out at exactly that size, and its CRC-32 (the ZIP polynomial) equals the one in the central directory.
- No unaccounted bytes: ordered by local-header offset, the entries (local header, data, and, when flag bit 3 is set, a data descriptor of 16 bytes if it starts with `0x08074b50`, otherwise 12) run back to back from offset 0 to the start of the central directory.

The CRC check makes the files a checker reads the files any unzip tool extracts. Integrity itself rests on the signed SHA-256 list.

A pack produced by the current exporter contains:

```
README.txt                                 plain-language description, inside the signed set
manifest.json                              the signed manifest (the only file not listed in itself)
assessments/artifacts.json                 artifact versions supplied in the window, each with its sealed record (section 6.11)
assessments/final-decisions.json           final decisions a case system recorded in the window, batch by batch (section 6.13)
assessments/findings.json                  assessments concluded in the window, each with its findings and its sealed document (section 6.11)
assessments/impact-assessments.json        versions of impact assessments recorded in the window, each with its sealed record (section 6.11)
assessments/measure-values.json            values recorded for measures in the window, each with its sealed record (section 6.11)
assessments/oscal-assessment-results.json  the same assessments as one OSCAL assessment-results document
assessments/reviews.json                   reviews of findings made in the window, each with its sealed record (section 6.11)
assurance/detector-catch-rate.json         measured catch rate of the shipped detector library, with its own scope statement
chain/links.json                           the records of the sealed windows and the export window, in chain order (section 5)
chain/erasures.json                        the change-trail entries that erased the removed records (section 6.4)
checkpoints/<uuid>.json                    one file per embedded audit checkpoint (section 4)
imports/<feed>.json                        when present, what an AI vendor reported through its own audit feed (section 6.10)
mutations/policy-trail.json                the change trail for the export window
policy/active.json                         the policy in force at export time
policy/lists.json                          each sealed list of names in a rule, with or without the names (section 6.6)
policy/versions.json                       policy versions, each with its text and SHA-256
register/ai-systems.json                   the AI system register at export time
register/decisions.json                    the decision register for the export window, with its change-trail entries
register/mandates.json                     the authority-grant registry, revoked and expired grants included
register/purposes.json                     purpose tags referenced by the register
report/report.pdf                          the printed report, naming the SHA-256 of report/summary.json
report/summary.json                        the figures the printed report shows
scope/blind-spots.json                     what the export window does not cover, stated explicitly
summary/agent-exposure.json                registered agents, their credentials and mandates, their holds and calls
summary/attachments.json                   decisions counted by the kind of attachment the request carried
summary/decision-mix.json                  aggregate decision counts
summary/framework-coverage.json            the organization's own rule-to-framework references and a per-framework decision rollup, recorded not verified, with its own scope statement
```

The manifest's content list is authoritative, and the set of files in the archive must equal it exactly (minus `manifest.json` itself), in both directions. A file in the archive but not the list, or in the list but not the archive, fails verification. Of the files above, the checker requires `manifest.json` and `chain/links.json`, and reads `checkpoints/`, `chain/erasures.json`, `imports/`, `mutations/policy-trail.json`, `policy/lists.json`, `policy/versions.json`, `register/decisions.json`, `report/`, `summary/decision-mix.json` and every file under `assessments/` but `oscal-assessment-results.json` when present. The signature covers every listed file whether the checker reads it or not.

## 2. Manifest (`manifest.json`, schema version 3)

```json
{
  "manifestVersion": 3,
  "tenantId": "<uuid>",
  "generatedAt": "<ISO 8601 timestamp>",
  "windowFrom": "<ISO 8601 timestamp>",
  "windowTo": "<ISO 8601 timestamp>",
  "truncated": false,
  "checkpointsTruncated": false,
  "mutationsTruncated": false,
  "contents": [
    { "filename": "policy/active.json", "sha256Hex": "<64 hex chars>", "byteLength": 1166 }
  ],
  "checkpointIds": ["<uuid>"],
  "signatureHex": "<128 hex chars>",
  "publicKeyBase64": "<32-byte Ed25519 public key, base64>",
  "publicKeyFingerprint": "<64 hex chars>"
}
```

- `tenantId` is the Mandate ID: it names whose records the pack holds. The CLI prints it as `Mandate ID`.
- The three timestamps are required and must match `YYYY-MM-DDTHH:MM:SS`, an optional fraction of 1 to 9 digits, then `Z` or `+HH:MM` / `-HH:MM`.
- `truncated` is true when the register, or `chain/links.json`, holds only part of the window; `checkpointsTruncated` when the checkpoint files were capped; `mutationsTruncated` when the change trail was. All three flags are inside the signed payload, so a capped pack cannot be re-labelled complete or the reverse.
- `contents` lists every file except `manifest.json`. Each `sha256Hex` is compared with the file, and since 2.6.0 each `byteLength`, which the signature binds, must equal the file's length.
- `publicKeyBase64` must decode to 32 bytes. A key of any other length makes the manifest INVALID; it is not reported as a runtime without Ed25519.

Rules on the manifest as a whole, applied once the signature verifies (the first that fails is reported):

- **No members outside the signature.** The manifest may carry only the 13 members above. The payload (section 3) binds the first nine; `signatureHex` and `publicKeyBase64` are what verifies it; `publicKeyFingerprint` and `checkpointIds` are checked against signed data below. Any other member makes the manifest INVALID, because nothing binds it.
- **The declared fingerprint must match the key.** When `publicKeyFingerprint` is present it must equal the SHA-256 of the decoded `publicKeyBase64`. Since 2.5.0 a mismatch is refused, not ignored. The checker reports the fingerprint it computed, never the declared one.
- **Checkpoint ids.** When `checkpointIds` is an array, it must list exactly the ids of the `checkpoints/<uuid>.json` files in the archive, each once, in any order.

**In progress.** A pack is in progress when `generatedAt` is before `windowTo`, compared as the integer Unix milliseconds the signature binds (since 2.10.0). It holds what was recorded up to when it was made, and has not begun when `generatedAt` is before `windowFrom` as well. An in-progress pack is valid; the CLI prints `RESULT: VALID, IN PROGRESS` and says what it holds, and `--json` reports `"inProgress": true` and `"notBegun"`. Its report must say so (section 6.9).

**Other formats.** When `manifestVersion` is not 3, nothing further is checked and the checker reports a different format, not INVALID: the CLI prints `RESULT: DIFFERENT FORMAT` naming the pack's format and the checker to use, and exits 3; `--json` reports `"overall": "unsupported"` with `"format"`. The access record has its own format number (section 8).

## 3. Signed payload (`mandate.evidence-pack.manifest-sig.v3`)

The manifest's `signatureHex` is an Ed25519 signature over this byte string:

```
field                  bytes  encoding
domain tag             37     ASCII "mandate.evidence-pack.manifest-sig.v3" (no length prefix)
tenantId               16     UUID
manifestVersion        4      u32
generatedAt            8      i64 Unix milliseconds
windowFrom             8      i64 Unix milliseconds
windowTo               8      i64 Unix milliseconds
truncated              1      0x01 if true, else 0x00
checkpointsTruncated   1      0x01 if true, else 0x00
mutationsTruncated     1      0x01 if true, else 0x00
content count          4      u32
for each content entry, in ascending filename order:
  filename length      4      u32, byte length of the UTF-8 name
  filename             n      UTF-8
  sha256               32     raw bytes of sha256Hex (no length prefix)
  byteLength           8      u64
```

The timestamps are bound as integer Unix milliseconds, not as formatted strings: parse each and truncate to the millisecond (fraction digits past the third are dropped, not rounded). Offset form or `Z`, and any number of fraction digits, give the same bytes. An absent flag counts as false. The checker sorts the entries itself before rebuilding, so their order in the JSON is not load-bearing; filenames are compared code unit by code unit (UTF-16), which for the ASCII names a pack uses is plain byte order. A u32 field that is not an integer from 0 to 4,294,967,295 makes the payload unbuildable and the manifest INVALID; it is never coerced. `byteLength` must be a non-negative integer no larger than 2^53 − 1; a negative one is never written as its two's complement.

## 4. Checkpoints (`mandate.audit.checkpoint-sig.v1`)

### 4.1 The file

Each `checkpoints/<uuid>.json` file:

```json
{
  "schemaVersion": 2,
  "checkpointId": "<uuid>",
  "tenantId": "<uuid>",
  "windowStartEventId": "<uuid>",
  "windowEndEventId": "<uuid>",
  "windowStartOccurredAt": "<ISO 8601 timestamp>",
  "windowEndOccurredAt": "<ISO 8601 timestamp>",
  "eventCount": 5,
  "merkleRootHex": "<64 hex chars>",
  "signatureHex": "<128 hex chars>",
  "publicKeyBase64": "<32-byte Ed25519 public key, base64>",
  "publicKeyFingerprint": "<64 hex chars>",
  "createdAt": "<ISO 8601 timestamp>",
  "timestampTokenBase64": "<RFC 3161 token, base64, or null>"
}
```

Format 1 (`"schemaVersion": 1`) has the first 13 members. Format 2 (since 2.18.0) adds `timestampTokenBase64`, the outside timestamp of section 4.3, or `null` while none has been obtained; inside a pack, a checkpoint whose `schemaVersion` is not 1 must carry the member, or it fails.

Every member of format 1 is required: `schemaVersion` is an integer and `eventCount` a non-negative integer, the four ids are UUIDs in text form, the rest are non-empty strings. The root must decode to 32 bytes, the signature to 64 and the key to 32. `signatureHex` is an Ed25519 signature over a fixed 119-byte payload:

```
offset  length  field
0       31      domain tag             ASCII "mandate.audit.checkpoint-sig.v1"
31      16      tenantId               UUID
47      16      windowStartEventId     UUID
63      16      windowEndEventId       UUID
79      8       eventCount             i64
87      32      merkleRootHex          32 raw bytes
```

- **Mandate ID.** A checkpoint whose `tenantId` names another Mandate ID than the manifest's fails, even though its own signature holds.
- The signature attests the tuple, not the bare root, so a checkpoint's metadata cannot be swapped without invalidating it. `windowStartOccurredAt`, `windowEndOccurredAt`, `checkpointId`, `createdAt` and `schemaVersion` are not signed: the id bounds, the count and the root define the sealed window, and section 5.5 recomputes the root from the records.
- **The declared fingerprint must match the key.** Since 2.6.0 the checkpoint's own `publicKeyFingerprint` must equal the SHA-256 of its decoded `publicKeyBase64` (in either case), as the manifest's must; once the signature verifies, a mismatch fails the checkpoint. The checker reports the fingerprint it computed.
- Once the signature verifies, the outside timestamp is checked (section 4.3). A token that is invalid fails the checkpoint.

### 4.2 A checkpoint on its own

A checkpoint can be saved alone from Mandate's Checkpoints page. The CLI reads any file whose name ends in `.json` (in any case) as such a checkpoint, and checks it on its own:

- The file must read as UTF-8 JSON; a byte-order mark and surrounding whitespace are allowed. A file that does not read as JSON cannot be checked (exit 2).
- An integer `schemaVersion` other than 1 or 2 is a different format (exit 3).
- The members of section 4.1, with their types. A format 1 file carries exactly the 13 members of format 1; a format 2 file carries those and `timestampTokenBase64`, which must be present and may be `null`. Any other member, a missing member or a member of the wrong type makes the file INVALID: it is not a Mandate checkpoint.
- The signature, the declared fingerprint and the outside timestamp, as in section 4.1. `--expect-fingerprint` applies to its key.

The CLI prints `Kind: checkpoint`, what it seals (the count and the first and last record's ids), its root, and its window times, which it says are not signed. A checkpoint alone proves that the key signed that count, those bounds and that root for that Mandate ID; an export of the same period checks the records themselves. A checkpoint named on the command line beside records, or found in a folder of them, is checked after them and apart from their sequence. A checkpoint file renamed `.zip` is read as a record, which it is not: alone it cannot be read (exit 2), and among the parts of a sequence it fails the sequence.

### 4.3 Outside timestamps

`timestampTokenBase64` is the base64 of an RFC 3161 timestamp token: a CMS signed-data structure, in DER, holding a TSTInfo. It shows that the checkpoint existed by the time the token states.

**What the token is over.** The imprint is the 215 bytes made of the checkpoint's 119-byte signed payload (section 4.1), then its 64-byte signature, then its 32-byte public key. The token's message imprint must be the SHA-256 of those bytes.

**What the checker checks**, offline:

- The token is at most 65,536 bytes and reads as strict DER: one-byte tags, definite lengths in their shortest form, nothing after its end.
- Its content type is signed data; the signed content is a TSTInfo; it carries at most 16 certificates and exactly one signer.
- The TSTInfo is version 1. Its message imprint uses SHA-256 and equals the SHA-256 of the imprint above. Its time is a GeneralizedTime in UTC. Its accuracy, when given, is at most one minute.
- The signer is named by issuer and serial number, or by subject key identifier, among the certificates the token carries. Its digest algorithm is SHA-256, SHA-384 or SHA-512. It signs attributes, which must include the content type (TSTInfo), the message digest of the TSTInfo, and an ESS signing-certificate attribute that names the signer's certificate by its hash (and by issuer and serial number when it gives them). The signature over the attributes, as the DER set they are, must verify with the signer's key.
- Signatures: RSA PKCS #1 v1.5 with a modulus of at least 2,048 bits, or ECDSA on P-256 or P-384, each with SHA-256, SHA-384 or SHA-512.
- The signer's certificate has an extended key usage, marked critical, whose only purpose is timestamping; its key usage, when present, allows signing.
- Its chain leads to a root: from the signer upward, at most six steps, each certificate's issuer is looked for first among the roots, then among the certificates the token carries, and its signature must verify with the issuer's key. Every certificate on the path, the root included, is valid at the stamped time. An issuing certificate is a certificate authority (basic constraints) allowed to sign certificates, within its path length.
- The roots are the one the checker ships, DigiCert Trusted Root G4 (SHA-256 of its DER: `552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988`), and any root named with `--timestamp-root`.

**Results.** A token that passes is valid: the CLI gives its time and its authority (the organization and common name of the signer's certificate). A token whose certificates lead to no root the checker holds, or that uses a hash or signature algorithm the rules above do not list, an RSA key shorter than 2,048 bits, another curve, or a critical extension the checker does not read, is one it cannot check: reported, never counted as valid or invalid. A token that breaks any other rule above is INVALID, and so is its checkpoint. Only a valid token's time is given. A checkpoint without a token is reported as having none.

### 4.4 Timestamps along the records

In a signed record, each checkpoint whose records are in `chain/links.json` is placed by the position of the last record it seals. Mandate stamps checkpoints one after another in that order and never goes back, so, in that order:

- A checkpoint without a token before one with a valid token makes the pack INVALID: it was replaced, or its token removed, after the later one was stamped.
- A valid token whose time is more than five minutes before the latest valid token of a checkpoint placed earlier makes the pack INVALID: a checkpoint stamped after a later one was replaced after the fact. The five minutes absorb the difference between authorities' clocks.
- A token the checker cannot check, placed before a valid one, leaves the order unknown: the result is NOT VERIFIED (exit 4) until its authority's root is named with `--timestamp-root`.
- A valid token more than a day after the checkpoint's last record is named as late: it shows only that the checkpoint existed by then.
- The last placed valid token shows that the records up to that checkpoint's last record were sealed no later than its time; the CLI says so.
- A checkpoint the records file does not cover has its token checked, but not its order.

`--require-timestamps` reports NOT VERIFIED (exit 4) unless every checkpoint carries a token the checker can check, stamped within a day of its last record; only checkpoints whose last record is within two hours of `generatedAt` may have none yet. A checkpoint on its own has no record times, so for it the option asks only for a token the checker can check.

## 5. Records (`chain/links.json`)

### 5.1 The file

```json
{
  "schemaVersion": 1,
  "scope": "<plain-language statement>",
  "from": "<ISO 8601 timestamp>",
  "to": "<ISO 8601 timestamp>",
  "truncated": false,
  "links": [
    { "id": "<uuid>", "occurredAt": "<ISO 8601 timestamp>", "record": "<base64>" },
    { "id": "<uuid>", "occurredAt": "<ISO 8601 timestamp>", "deletedRecordSha256": "<64 hex chars>", "erasedBy": "<uuid>" }
  ]
}
```

`links` holds every record of the sealed windows the pack carries and of the export window, running on to the change records that seal the window's change-trail entries, in chain order (ascending time, then id).

- A live record carries `record`: the exact bytes that were hashed, base64. Its hash is the SHA-256 of those bytes.
- A record removed under a privacy request or by retention carries `deletedRecordSha256` instead (the SHA-256 it had, 64 hex digits) and `erasedBy`, the id of the change-trail entry that recorded its erasure (section 6.4). It keeps its place in the chain and in every Merkle window.
- A link with neither fails.
- `truncated: true` says the file holds part of its span. It requires the manifest's `truncated` to be true as well; otherwise the pack is INVALID.
- `scope`, `from` and `to` are informative. For a live record the checker takes the time from the record's own `occurred_at`; a link's `occurredAt` is read only for removed records.

Each live record must decode (section 5.2), carry the link's `id` as its `id`, and name the manifest's Mandate ID as its `tenant_id`.

### 5.2 Record bytes

```
byte 0    layout version, 1 to 9
byte 1    0x00 (a live record; the checker reads no other value)
then      the layout's fields in the order of section 5.3, with nothing after the last
```

Each field is encoded as:

```
required field   u32 length L || L bytes
optional field   0x00 || u32 length L || L bytes      present (L may be 0)
                 0xFF || 00 00 00 00                   absent
```

A layout outside 1 to 9, any other flag byte, a non-zero length after `0xFF`, a length that runs past the end, or bytes after the last field make the record unreadable and the pack INVALID.

| Type | Value bytes |
| --- | --- |
| uuid | 16 bytes, RFC 4122 wire order |
| hash | raw bytes (32 for a SHA-256) |
| text | UTF-8; invalid UTF-8 is rejected where the checker reads it |
| json | UTF-8 JSON text |
| time | UTF-8 ISO 8601 in UTC with seven fraction digits, as `2026-10-19T21:37:09.1016340Z` |

### 5.3 Layouts

`R` is a required field, `o` an optional field, `.` a field the layout does not have. In every layout the fields appear in ascending byte order of their names, which is the row order below.

| Field | Type | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| agent_action | json | . | o | o | o | o | o | o | o | o |
| agent_id | uuid | . | o | o | o | o | o | o | o | o |
| agent_principal_id | uuid | . | o | o | o | o | o | o | o | o |
| chain_prev_hash | hash | R | R | R | R | R | R | R | R | R |
| connector | text | R | R | R | R | R | R | R | R | R |
| correlation_id | uuid | R | R | R | R | R | R | R | R | R |
| id | uuid | R | R | R | R | R | R | R | R | R |
| mandate_slug | text | . | . | . | . | R | o | o | o | o |
| model | text | R | R | R | R | R | R | R | R | R |
| occurred_at | time | R | R | R | R | R | R | R | R | R |
| person_seal | hash | . | . | . | . | . | . | . | . | R |
| policy_decision | text | R | R | R | R | R | R | R | R | R |
| policy_version_id | uuid | o | o | o | o | o | o | o | o | o |
| policy_version_sha256 | hash | . | . | . | . | . | . | . | R | o |
| provider | text | R | R | R | R | R | R | R | R | R |
| purpose_slug | text | . | . | . | R | o | o | o | o | o |
| purpose_source | text | . | . | . | R | o | o | o | o | o |
| request_body_hash | hash | R | R | R | R | R | R | R | R | R |
| request_body_hash_outbound | hash | o | o | o | o | o | o | o | o | o |
| response_body_hash | hash | . | . | o | o | o | o | o | o | o |
| rule_hits | json | R | R | R | R | R | R | R | R | R |
| subject_hash | hash | . | . | . | . | . | . | R | o | R |
| tenant_id | uuid | R | R | R | R | R | R | R | R | R |
| upstream_id | uuid | . | . | . | . | . | R | o | o | o |
| (field count) | | 13 | 16 | 17 | 19 | 20 | 21 | 22 | 23 | 24 |

`policy_decision` is the outcome: `allow`, `warn`, `redact`, `escalate` or `block` for a decision (the CLI says allowed, warned, masked, held, refused), `result` for an answer relayed back, `imported` for an imported record, `change` for a change record (section 6.3), and `test` for a test-set prompt (since 2.14.0). The checker counts any other value as a decision. `model` is empty text when there is none. The checker decodes every field but does not interpret `agent_action`, `agent_principal_id`, `connector`, `request_body_hash_outbound`, `response_body_hash`, `subject_hash` or `upstream_id`; they are covered by the record's hash.

### 5.4 Links

A link's hash is the SHA-256 of its record bytes, or its `deletedRecordSha256`. Every live record after the first link must carry, as `chain_prev_hash`, the hash of the link immediately before it, live or removed. The first link's `chain_prev_hash` is not checked within one pack (at the start of a chain it is 32 zero bytes); section 7 uses it to join packs.

### 5.5 Merkle roots

For each `checkpoints/<uuid>.json`:

1. Find `windowStartEventId` and `windowEndEventId` among the link ids. If either is missing, or the end comes before the start, the walk fails, unless `chain/links.json` says `truncated`, in which case it is reported as not covered and skipped.
2. The leaves are the hashes of the links from start to end inclusive, in file order. Their number must equal `eventCount`.
3. The recomputed root must equal `merkleRootHex`:

```
leaf(h)      = SHA-256(0x00 || h)            h: a 32-byte link hash
node(l, r)   = SHA-256(0x01 || l || r)
level 0      = leaf(h) for each link hash, in order
level k + 1  = node(a, b) for each pair (a, b) of level k, in order; a last unpaired node x gives node(x, x)
root         = the one node left (for a single link, its leaf)
```

## 6. What ties the readable files to the records

### 6.1 Register rows

Each row of `register/decisions.json` with `"source": "decision"` that carries `recordSha256` must name a live record: the link with the row's `id` holds a record whose SHA-256 equals `recordSha256`. Each field must then agree. On the row, absent means missing or `null`; in the record, a field the layout lacks or one encoded absent.

| Reported as | Record | Row | Agrees when |
| --- | --- | --- | --- |
| outcome | `policy_decision` | `action` | equal |
| provider | `provider` | `provider` | equal; an absent row value reads as `""` |
| model | `model` | `model` | equal; an absent row value reads as `""` |
| policy version | `policy_version_id` | `policyVersionId` | equal UUID text, or both absent |
| time | `occurred_at` | `occurredAt` | the same instant (below) |
| rules | `rule_hits` | `rules` | the same set (below) |
| correlation id | `correlation_id` | `correlationId` | equal UUID text |
| agent | `agent_id` | `actorId`, `actorType` | `actorId` equals `agent_id` or both are absent, and `actorType` is `agent` when the record has an `agent_id`, else `system` |
| purpose | `purpose_slug`, `purpose_source` | `purpose`, `purposeSource` | `purpose_slug` equals `purpose` and `purpose_source` equals `purposeSource`, absent matching absent |
| mandate | `mandate_slug` | `mandateSlug` | equal, absent matching absent |
| person | `person_seal` | `person`, `personSalt` | section 6.2 |

- Time: when both values are in UTC (`Z`, `+00:00` or `-00:00`) they must agree to the microsecond (fraction digits past the sixth dropped); otherwise to the millisecond. Every "same instant" in this document follows this rule.
- Rules: from the record's `rule_hits` (a JSON array) take each hit that has a string `ruleId` and a `detectorType` other than `policy`; from the row's `rules` take every entry. Each side becomes a set of `ruleId|detectorType|action` strings, an absent `detectorType` or `action` written as empty. The two sets must be equal.

A decision row without `recordSha256` is reported as outside the records file and is not checked. Rows of other sources are not tied here; change-trail rows are section 6.3.

### 6.2 Person seal

A decision made for a person is a layout 9 record, and its `person_seal` is the name seal of that person:

```
name seal = SHA-256( ASCII "mandate.name-seal.v1" || 0x00 || salt || UTF-8(name) )
            salt: 16 bytes; name: no length prefix
```

The register row must carry `person` and `personSalt` (32 hex digits), and their name seal must equal `person_seal`. A row tied to a record of layouts 1 to 8 must not name a person. The same seal binds who acted on a change-trail entry (section 6.3).

### 6.3 Change-trail entries

A change-trail entry is sealed into the chain by a change record: a live record whose `policy_decision` is `change`, whose `correlation_id` is the entry's `id`, and whose `request_body_hash` is the entry's seal. Entries appear in `mutations/policy-trail.json`, in `register/decisions.json` (rows with `"source": "mutation"`), in `chain/erasures.json` (its `entries`) and in `assessments/final-decisions.json` (each batch's `entry`).

- Every entry must carry a string `id`.
- Every entry, sealed yet or not, is read for the facts below first. A change that names a list's entries, or a member the seal does not cover or of the wrong type (in a change, a mandate, a mandate's tool, an assessment or a record), makes the pack INVALID.
- Every copy of an entry whose change record is in `chain/links.json` must reproduce that record's seal; such an entry that carries the facts of more than one of a mandate, an assessment and a record is malformed and fails. An entry with no change record in the pack is reported as not sealed yet or outside the records file, and is not checked against a seal in this pack (section 7 checks it against another pack's).
- Mandate seals an entry once, so `chain/links.json` may hold at most one change record per entry: two records whose `correlation_id` is the same entry make the pack INVALID.

```
seal = SHA-256(
  ASCII domain || 0x00
  || F(id)                          UUID
  || F(Mandate ID)                  UUID: the manifest's tenantId
  || F(occurredAt)                  i64 ticks (below)
  || F(action)                      UTF-8
  || F(actorType)                   UTF-8
  || O(actorId)                     UUID
  || O(actor seal)                  32 bytes: the name seal of actorDisplay with actorSalt
  || O(mutationReason)              UTF-8
  || O(transition.kind)             UTF-8
  || O(transition.reason)           UTF-8
  || O(transition.policyId)         UUID
  || O(transition.versionId)        UUID
  || O(transition.priorVersionId)   UUID
  || O(transition.version)          UTF-8 of the value as text (a number in decimal)
  || O(changes)                     transition.changes, below
  [ || O(mandate) | O(assessment) | O(record) ]   at most one, below
)
F(b)       = u32 length || b
O(absent)  = 0xFF || 00 00 00 00
O(b)       = 0x00 || u32 length || b
```

The domain names the layout: `mandate.change-trail-entry.v2` for an entry with none of the three last fields, `v3` with `mandate`, `v4` with `assessment`, `v5` with `record`.

```
changes     = u32 count || for each change: F(kind) || F(ruleId) || O(reason) || O(from) || O(to)
                                            || O(added) || O(removed) || O(addedCount) || O(removedCount)
added       = u32 count || F(UTF-8 entry) for each, in order        (removed the same)

mandate     = F(slug) || O(tools) || O(purposes) || O(validFrom) || O(validUntil) || O(then) || O(successor)
tools       = u32 count || for each tool: F(server) || O(tool) || F(flags)
flags       = one byte: 0x01 when includesLaterTools is true, | 0x02 when awaitingFirstList is true
purposes    = u32 count || F(UTF-8 purpose) for each, in order
validFrom   = i64 ticks (validUntil the same)

assessment  = F(assessmentId as UUID) || F(sha256 as 32 raw bytes)

record      = F(UTF-8 kind) || F(id as UUID) || F(sha256 as 32 raw bytes)
```

- Absent means missing or `null`; an absent `transition` makes all its fields absent. Text fields take the value's string form; `addedCount` and `removedCount` are non-negative integers sealed as decimal text. Members not listed (such as `source`, `actorSalt` itself) are not sealed.
- A change carries only `kind`, `ruleId`, `reason`, `from`, `to`, `added`, `removed`, `addedCount` and `removedCount`; `kind` and `ruleId` are strings and `added` and `removed` lists of strings. A change of kind `keywords` (a list of names) never carries `added` or `removed`: it says how many names were added and removed, never which.
- A `mandate` carries only `slug` (a string), `tools`, `purposes`, `validFrom`, `validUntil`, `then` and `successor`; a tool carries only `server` (a string), `tool` (a string or absent), `includesLaterTools` and `awaitingFirstList` (booleans or absent). An `assessment` carries only `assessmentId` and `sha256`; a `record` carries only `kind` (a non-empty string), `id` and `sha256`. Each `sha256` is 64 lowercase hex digits.
- Ticks are 100-nanosecond units since 1970-01-01T00:00:00Z: the Unix milliseconds of the time without its fraction, times 10,000, plus the first seven fraction digits as an integer (padded on the right with zeros; further digits dropped). The time must match `YYYY-MM-DDTHH:MM:SS`, an optional fraction, then `Z` or `+HH:MM` / `-HH:MM`.
- `action` and `actorType` must be strings. An entry that names `actorDisplay` must carry `actorSalt` (hex).

**The layout before 2.7.0.** A record exported before checker 2.7.0 (2026-10-25) seals each entry under the domain `mandate.change-trail-entry.v1`: the fields above from `id` to `transition.version`, and nothing after them. A list's change in such a record may name its entries. The checker takes a record to be in that layout when every entry whose change record is in the pack reproduces its seal under `v1` and none under a later layout, no entry carries a mandate's, an assessment's or a record's facts, `report/summary.json` has no `imported` section (section 6.10) and every checkpoint is format 1. Such a record is not read against `v2` to `v5`, an entry not sealed yet may name a list's entries, and its report is held neither to section 6.10 nor, when it says nothing of being in progress, to section 6.9. Every other check still runs. Only when all of them pass does the record answer DIFFERENT FORMAT (exit 3), naming checker 2.6.0, which reads it; a failure there, or a key not named, is INVALID. Any other mix of layouts fails as above, and a record with no sealed entry is read as any other.

The record kinds the checker reads are `finding_review`, `artifact`, `measure_value` and `impact_assessment` (section 6.11), `assessment_sign_off` (section 6.12) and `final_decisions` (section 6.13). An entry of another kind is sealed and checked like any other, and its document is not read.

### 6.4 Erasures

Every removed link must carry `erasedBy`, and `chain/erasures.json` (`{ "schemaVersion": 1, "scope": "...", "entries": [...] }`) must carry an entry with that `id`. The entry's `action` must record an erasure: `dsr.delete` (a privacy request) or any action starting with `retention.` (the retention setting). Its `occurredAt` must be a readable time (section 6.3). These entries are change-trail entries and tie to their change records as in section 6.3. The CLI names, for each entry, how many records it removed and when.

### 6.5 Policy text

Each element of `policy/versions.json` (an array) must carry `yamlSource` and `contentSha256`, and the SHA-256 of the UTF-8 `yamlSource` must equal `contentSha256`. A live record with a present `policy_version_sha256`, whose `policy_version_id` names a version in the file, must carry that version's hash: a record decided under text that no longer matches fails. A record whose version is not in the file is not compared.

### 6.6 Lists of names

A rule's list of names appears in the policy text only sealed, as `sealed: <64 lowercase hex>` with its count. `policy/lists.json` is optional:

```json
{
  "schemaVersion": 1,
  "scope": "<plain-language statement>",
  "namesIncluded": false,
  "lists": [
    { "versionId": "<uuid>", "ruleId": "<rule id>", "sealed": "<64 hex chars>", "count": 30 }
  ]
}
```

When the export includes the names, each list also carries `"salt": "<32 hex chars>"` and `"keywords": ["<name>", ...]`, and `namesIncluded` is `true`.

```
list seal = SHA-256( ASCII "mandate.list-seal.v1" || 0x00 || salt || for each name, in file order: u32 length || UTF-8(name) )
            salt: 16 bytes
```

- The file must carry a `lists` array. Each list must carry a 64-hex `sealed`, and the `yamlSource` of policy version `versionId` in `policy/versions.json` must contain `sealed: <that seal in lowercase>`.
- A list with no `keywords` member and no `salt` member is reported as sealed with its names left out, unless `namesIncluded` is `true`, in which case it fails.
- Otherwise `keywords` must be an array of strings and `salt` 32 hex digits, and their list seal must equal `sealed`.
- `count` is informative.

### 6.7 Printed report

When the pack carries `report/report.pdf`, its bytes read as Latin-1 must contain `/Keywords (mandate-summary-sha256:<64 lowercase hex>)` (the first occurrence counts), and `report/summary.json` must exist with that SHA-256.

### 6.8 Summary counts

The counts are compared unless `chain/links.json` says `truncated` (reported as "the records file is partial") or the manifest does ("the register is partial"). Count the rows of `register/decisions.json` with `"source": "decision"` by `action`. In `report/summary.json` (its `decisions.byOutcome`) and in `summary/decision-mix.json` (its `decisions`), a list of `{ "decision": "<outcome>", "count": <n> }` must give every listed outcome the register's count (0 when the register has none), and must list every outcome the register has, with its count. A file without such a list is skipped.

### 6.9 In progress

When the pack carries `report/summary.json`, its `period.inProgress` must be `true` exactly when the pack is in progress (section 2). A report that does not say so for a pack in progress, or says so for a pack made after its period ended, fails.

### 6.10 Imported activity

`imports/<feed>.json` lists what an AI vendor reported through its own audit feed. Mandate did not see or decide these requests, and the register and the decision counts never include them.

```json
{
  "schemaVersion": 2,
  "feed": "<feed>",
  "truncated": false,
  "rows": [
    { "id": "<uuid>", "sourceTime": "<ISO 8601 timestamp>", "payloadSha256": "<64 hex chars>", "ruleHits": ["<rule id>"], "notes": ["policy.body_unscannable"] }
  ]
}
```

In version 2, `ruleHits` lists the rules that fired on a row and `notes` Mandate's own notes on reading it, such as `policy.body_unscannable` for a row it could not read in full. A note's id starts with `policy.`, which no rule a customer writes may carry. Version 1 lists both under `ruleHits` and has no `notes`.

When the pack carries `report/summary.json`, it must carry `imported.byFeed`, a list with one entry per feed: `{ "feed", "rows", "rowsWithRuleHits", "rowsNotReadInFull", "coversWindow", "sourceFrom", "sourceTo" }`, `rowsNotReadInFull` only for a version 2 file. A report without the list fails. Then, unless an imports file has a `schemaVersion` above 2, in which case nothing below is compared and the CLI says why:

- In a version 2 file, no row lists an id starting with `policy.` in `ruleHits`, and every entry of every row's `notes` is a string starting with `policy.`.
- The list names exactly the feeds the pack carries files for (the `<feed>` of each `imports/<feed>.json`), in ascending name order.
- For each feed: `rowsNotReadInFull` is present exactly when the file is version 2, and in version 2 every row carries `ruleHits` and `notes` lists. Counting the file's rows, the rows whose `ruleHits` is not empty, and (version 2) the rows whose `notes` include `policy.body_unscannable`: a file not cut must give `rows`, `rowsWithRuleHits` and `rowsNotReadInFull` exactly, and `sourceFrom` and `sourceTo` must be the earliest and latest `sourceTime` as instants (absent when there are none). A file with `"truncated": true` holds part of the rows: `rows` must be no lower than the rows it holds, and each other count no lower than its rows give and no higher than `rows`.
- When the pack carries `summary/decision-mix.json`, its `imports` list must have the same entries in the same order: `feed`, `rows`, `rowsWithRuleHits`, `rowsNotReadInFull`, `coversWindow` equal, and `sourceFrom` and `sourceTo` the same instants.

### 6.11 Sealed documents in the assessment files

Five files carry documents Mandate sealed, each as the exact text it hashed, beside a readable row:

| File | List | Document member | Hash member | Its change-trail entry carries | Kind |
| --- | --- | --- | --- | --- | --- |
| `assessments/findings.json` | `assessments` | `document` | `contentSha256` | `assessment` (`assessmentId`, `sha256`) | assessment |
| `assessments/reviews.json` | `reviews` | `record` | `contentSha256` | `record` of kind `finding_review` | review of a finding |
| `assessments/artifacts.json` | `artifacts` | `record` | `recordSha256` | `record` of kind `artifact` | artifact version |
| `assessments/measure-values.json` | `values` | `record` | `recordSha256` | `record` of kind `measure_value` | measure value |
| `assessments/impact-assessments.json` | `impactAssessments` | `record` | `recordSha256` | `record` of kind `impact_assessment` | impact assessment version |

Each file is `{ "schemaVersion": 1, "scope": "...", "truncated": false, "<list>": [...], "removed": [...] }`. A file whose `schemaVersion` is not 1 is not compared, and the CLI says why; a file that is not such an object fails. `truncated: true` says the file stopped at its size limit and holds the earliest rows of its period. Every row carries `id` and `auditEntryId` (UUIDs, `auditEntryId` naming the change-trail entry that seals it), the document member and the hash member. For each row:

1. No two rows carry the same `id`.
2. The SHA-256 of the UTF-8 document must equal the hash member (lowercase hex), and the document must read as JSON with `"version": 1`.
3. When the change-trail entry `auditEntryId` is in the pack (section 6.3's sources), it must record this document (the kind above, and the row's `id`), and the hash it carries must equal the document's. A document that differs from its entry fails, whatever its row says.
4. The readable row must say what the document says (the table below). The document's id is `assessment.id` for an assessment and `id` for the others.
5. A review whose assessment the pack carries must name, as its document's `assessmentSha256`, the hash of that assessment's document.

A document whose entry is in the pack and sealed in `chain/links.json` is counted as matching its sealed record; one whose entry is not, as not checked.

Then, for every change-trail entry in the pack that records a document of a file the pack carries: when the file holds that document, its hash must equal the entry's and its row must name that entry; when the file does not hold it and is not cut, it must name it under `removed`, or it fails as left out.

`removed` lists the documents deleted with their AI system, each `{ "id", "auditEntryId", "deletedBy", "deletedAt" }` (`deletedBy` naming the change-trail entry that recorded the deletion). A document may not be both carried and removed, or removed twice. When the entry `auditEntryId` is in the pack, it must record this document; when the entry `deletedBy` is in the pack, its `action` must be `ai_system.deleted`. When it is not, and the change trail is whole (the manifest's `mutationsTruncated` is false) and `deletedAt` falls inside the window, the pack fails: a deletion inside the period is in the change trail.

What the readable row must say. Values are compared as equal JSON values, absent matching absent; ids as UUIDs; lists of roles in order; times as the same instant (section 6.1).

| File | Reported as | Row | Document |
| --- | --- | --- | --- |
| findings | AI system | `aiSystemId` | `assessment.aiSystemId` |
| findings | framework | `frameworkId`, `frameworkVersionId` | `assessment.frameworkId`, `assessment.frameworkVersionId` |
| findings | trigger | `trigger` | `assessment.trigger` |
| findings | period | `windowFrom`, `windowTo` | `assessment.windowFrom`, `assessment.windowTo` |
| findings | time | `concludedAt` | `assessment.concludedAt` |
| findings | counts | `requirements`, `met`, `partiallyMet`, `notMet`, `notApplicable`, `unableToDetermine` | the number of `findings`, and of those whose `result` is `met`, `partially_met`, `not_met`, `not_applicable`, `unable_to_determine` |
| findings | confidence | `confidence` | the lowest `findings[].confidence.value`, absent when none has one |
| findings | coverage | `coverage` | `assessment.snapshot.coverage.value`, within 0.00005 (the row keeps four decimal places) |
| findings | findings | the number of `findings` | the number of `findings` |
| findings | finding (by label) | `findings[i]`: `requirementId`, `label`, `result`, `reason`, `confidence` | `findings[i]`: the same, `confidence.value` for `confidence` |
| reviews | assessment | `assessmentId` | `assessmentId` |
| reviews | finding | `findingId`, `requirementId` | the same |
| reviews | action | `action` | `action` |
| reviews | result | `result`, `confidence` | the same |
| reviews | reviewer | `reviewerId`, `reviewerRoles` | the same |
| reviews | time | `createdAt` | `createdAt` |
| artifacts | version | `lineageId`, `version`, `supersedesId` | `lineageId`, `artifactVersion`, `supersedesId` |
| artifacts | kind, title, description, link, statement, withdrawn | the member of that name | the same |
| artifacts | file | `file`: `name`, `contentType`, `size`, `sha256` | the same |
| artifacts | status | `status`, `externalRef` | the same |
| artifacts | dates | `effectiveOn`, `reviewBy` | the same |
| artifacts | supplier | `suppliedBy`, `suppliedRole`, `suppliedRoles` | the same |
| artifacts | time | `createdAt` | `createdAt` |
| artifacts | links | each link's `target`, the one id it names (`aiSystemId`, `controlId`, `findingId` or `measureValueId`), `frameworkId`, `requirementId` | each link's `target`, `id`, `frameworkId`, `requirementId`, in any order |
| measure values | measure | `measureId`, `aiSystemId`, `source` | the same |
| measure values | value | `value`, `status` | the same |
| measure values | period | `observedAt`, `windowFrom`, `windowTo` | the same |
| measure values | test run | `testSetRunId` | `testSetRunId` |
| measure values | supplier | `suppliedBy`, `suppliedRoles` | the same |
| measure values | time | `createdAt` | `createdAt` |
| impact assessments | AI system | `aiSystemId` | `aiSystemId` |
| impact assessments | version | `version` | `assessmentVersion` |
| impact assessments | questionnaire | `source`, `questionnaireVersion`, `fileVersion` | the same |
| impact assessments | scores | `rawImpactScore`, `mitigationScore`, `currentScore`, `mitigationDeducted` | the same |
| impact assessments | level | `level` | `level` |
| impact assessments | date completed | `completedOn` | `completedOn` |
| impact assessments | supplier | `suppliedBy`, `suppliedRoles` | the same |
| impact assessments | time | `createdAt` | `createdAt` |

Every file also compares the row's `id` with the document's. A remediation linked to the problem it answers, a measure value that went past its limit, names that value: `{ "target": "breach", "id": "<uuid>" }` in the document, `measureValueId` in the row (since 2.20.0). A pack whose assessment files were cut is reported partial, naming them.

### 6.12 Review decisions and sign-off

Mandate keeps each finding's review decision and each assessment's sign-off beside the sealed documents, so they are read against them (since 2.19.0). This applies when the pack carries `assessments/findings.json`.

A sign-off is a change-trail entry whose `record` has kind `assessment_sign_off`, the assessment's id and the hash of the assessment's document. For an assessment the pack carries, its sign-off must name the document the pack carries, and there may be only one.

Each assessment row carries `status`, `concluded` or `signed_off`, and `signedOffAt` and `signedOffBy` exactly when it is `signed_off`. When a sign-off entry for it is in the pack, the row must be signed off at that entry's `occurredAt`. When the row is signed off, no sign-off entry is in the pack, and the change trail is whole, it fails.

The rest is checked while `assessments/reviews.json` is whole (not cut). Each finding's latest review is, among the review documents with `action` `accept`, `reject` or `change` for that assessment and finding, the one with the latest `createdAt`. Each finding row of `assessments/findings.json` (by its `id`) must then show:

| Latest review | `reviewState` | `reviewedResult` | `reviewedConfidence` |
| --- | --- | --- | --- |
| none | absent | absent | absent (and no `reviewedAt` or `reviewedBy`) |
| `accept` | `accepted` | the review's `computedResult` | the review's `computedConfidence` |
| `reject` | `rejected` | absent | absent |
| `change` | `changed` | the review's `result` | the review's `confidence`, or, when absent and the result is still the computed one, `computedConfidence` |

with `reviewedAt` the review's `createdAt`, `reviewedBy` its `reviewerId`, and the same `requirementId`. A review may not decide a finding the assessment does not hold. An assessment is signed off exactly when every finding has a decision: a signed-off assessment with a finding no review decides fails, its `signedOffAt` and `signedOffBy` must be the time and reviewer of the last decision, and an assessment whose every finding has a decision must be signed off.

### 6.13 Final decisions

`assessments/final-decisions.json` lists the final decisions a system's case system recorded in Mandate, batch by batch (since 2.16.0):

```json
{
  "schemaVersion": 1,
  "scope": "<plain-language statement>",
  "truncated": false,
  "batches": [
    {
      "batchId": "<uuid>",
      "aiSystemId": "<uuid>",
      "receivedAt": "<ISO 8601 timestamp>",
      "entryId": "<uuid>",
      "entry": { "id": "<uuid>", "action": "final_decisions.recorded", "record": { "kind": "final_decisions", "id": "<batchId>", "sha256": "<64 hex chars>" }, "...": "..." },
      "record": "<the batch record, as the exact text Mandate hashed>",
      "decisions": [
        { "sha256": "<64 hex chars>", "salt": "<64 hex chars>", "document": "<the decision, as the exact text Mandate hashed>" },
        { "sha256": "<64 hex chars>", "erased": true }
      ]
    }
  ]
}
```

A file whose `schemaVersion` is not 1 is not compared, and the CLI says why. Otherwise, for each batch:

- `batchId`, `aiSystemId` and `entryId` are UUIDs, and no two batches share a `batchId`.
- `entry` is a change-trail entry (section 6.3) with `action` `final_decisions.recorded`, `id` equal to `entryId`, and a `record` of kind `final_decisions` naming `batchId`. The SHA-256 of the UTF-8 `record` must equal the entry's `record.sha256`.
- `record` reads as JSON with `"version": 1`, names this pack's Mandate ID as `tenantId`, the batch's `batchId` and `aiSystemId`, and the same `receivedAt` instant, and lists `decisionSha256s`: 64 lowercase hex digits each, in ascending order, each once.
- Each decision carries `sha256`, 64 lowercase hex digits, carried once and listed by the record. An erased decision (`"erased": true`) keeps only its digest and is counted as erased. Any other carries `salt` (64 hex digits, 32 bytes) and `document`, and `SHA-256(salt || UTF-8 document)` must equal its `sha256`. The document reads as JSON and names this pack's Mandate ID as `tenantId`, and the batch's `batchId` and `aiSystemId`.
- Every digest the record lists must be carried.

The salt lets one decision be shown and checked without disclosing the others. A batch whose entry has no change record in `chain/links.json` is counted as not checked, never as a pass; the others are counted with their decisions. `truncated: true` says the file holds the earliest batches of its period, and the pack is reported partial.

## 7. Several packs

The CLI takes several packs, or a folder. A folder stands for the files in it, in name order: each `.zip` is a pack, each `.json` a checkpoint checked on its own (section 4.2), and other files are ignored. Each pack is first checked alone. Every input must be a readable signed record, not an access record, or the sequence fails. A pack in a format this checker does not read (section 6.3 names one) is not compared: every pair without it still is, and the sequence reads NOT CHECKED (exit 3) unless one of them fails.

Packs named one by one are put in order of `windowFrom`. When any input is a folder, the inputs are taken in the order given (a folder's files in name order). Each pair of neighbours is checked as follows, earlier window first:

1. **One Mandate ID.** The two `tenantId` values are the same UUID, compared as the 16 bytes the signatures bind, so the case of their hex digits does not matter (since 2.6.0).
2. **One key.** The two computed fingerprints are equal, unless both packs passed as VALID with fingerprints named by `--expect-fingerprint` (as after a key change).
3. **No gap.** The later `windowFrom` is at most 1 millisecond after the earlier `windowTo`; overlap is allowed. When the earlier pack is in progress (section 2), the later `windowFrom` is at most 1 millisecond after a minute before the earlier `generatedAt`, since the earlier pack covers its period only to then.
4. **Both record walks passed** (sections 5 and 6).
5. **The records agree** (below).
6. **Continuity.** When both packs hold links, the later pack's first link is in the earlier pack, or is a live record whose `chain_prev_hash` is the hash of the earlier pack's last link.

Packs that are not neighbours are compared too (since 2.23.0). Two of them are held to rule 5, the earlier `windowFrom` first, when their times overlap or when they hold a link or a register row with the same `id`. A pack's time runs from the earlier of its `windowFrom` and its earliest link to the later of its `windowTo` and its latest link, since `chain/links.json` can reach past the window; an end that cannot be read is open. Every change-trail entry must also read one way and carry one seal across all the packs, whatever their times. Each copy must read the same as the first copy read. Each change record for the entry must be the same record as the first one read, and each copy's seal must equal that record's `request_body_hash` (rule 5 below). In a folder, the checker reads the two packs of each such pair again, a pair at a time, so it needs the memory of two packs beside the change-trail entries it has read and the id of every link and register row it has read; the sequence fails if a file changed since it was first checked or cannot be read again. Until 2.22.0 only neighbours were compared, so a pack whose window starts between those of two others could keep those two from being compared.

What an export is held to: its window, `windowFrom` to `windowTo` inclusive, cut to one minute before its `generatedAt` when that is earlier. When the file in question says it is partial (for links, `chain/links.json` `truncated`; for `mutations/policy-trail.json`, the manifest's `mutationsTruncated`; for the register's change-trail rows, the manifest's `truncated`), the export is held only to the span strictly between the earliest and latest times that file holds, where those fall inside, and to nothing if it holds none.

The records agree when, in both directions:

- **Nothing is missing.** A link, live or removed, that one pack holds at a time the other is held to must be in the other. A link inside the other's window but outside what it is held to is named in a note (`N records of A inside the period of B not compared: <reason>`).
- **No erased record comes back.** A record live in one pack and removed in the other is named in a note (`N decisions erased between A and B: <id> (<outcome>, <time>), ...`). It fails instead when the pack in which it is removed says, by `generatedAt`, that it was made before the other.
- **Register rows read the same.** A row (`source` `decision` or `imported`) in both packs must agree on `person`, `actorType`, `actorId`, `actorDisplay`, `action`, `occurredAt`, `provider`, `model`, `policyVersionId`, `correlationId`, and every other member that rows of both packs carry. Times compare as instants to 100 nanoseconds; other values as JSON with object keys sorted, an absent member as `null`. A different `actorDisplay` for the same agent (`actorType` `agent`, same `actorId`) is a note, not a failure.
- **Sealed records match.** A link in both packs has the same hash in both.
- **Change-trail entries read the same**, separately for `mutations/policy-trail.json` and for register rows with `"source": "mutation"`. An entry in both must agree on every member (times as instants). `actorSalt` is never compared: it is how the seal of who acted is checked, not part of what the entry says, and an entry exported before it was sealed carries none. Who acted is compared like every other member (`actorType`, `actorId`, `actorDisplay`), and a copy that names no one (`actorType` `mandate_support`, no `actorId`, no `actorDisplay`) where the other copy names someone fails: the reason names the entry, the export that names no one, and which export, if either, carries the entry's sealed record. Mandate prints every copy of a sealed entry with who acted as its seal fixed it, whether or not the pack carries the change record, so genuine copies agree.
- **Every copy is compared.** An entry may appear in `mutations/policy-trail.json`, in the register's rows with `"source": "mutation"`, in `chain/erasures.json` and in `assessments/final-decisions.json`. Every copy one pack carries is compared with every copy the other carries, whichever lists they are in.
- **One seal per entry.** When both packs carry a change record for an entry, it must be the same record. When one pack carries the change record and the other carries a copy without it, that copy's seal (section 6.3) must equal the record's `request_body_hash`; a copy that names who acted without `actorSalt` cannot be sealed and is not checked this way.
- **What remains unbound.** A copy whose pack lacks the change record is bound only through another pack that carries the record or a copy of the entry.
- **No change-trail entry is missing.** An entry one pack holds at a time the other is held to must be in the other, with two exceptions (since 2.9.0). When the other pack shows the entry's change record as removed, the entry went with it under the retention setting, and the removal is named among the erased records. When the entry has no change record in its own pack and the other pack carries none for it either, it was not yet sealed when its pack was made: a note names it and it is not compared.

The sequence is in progress when the latest point its parts cover (a part in progress: a minute before its `generatedAt`; any other: its `windowTo`) is before the latest `windowTo`.

**Complete exports.** A long period downloads as one archive of parts, a complete export: an archive that holds records named `part-K-of-N.zip` and no `manifest.json`. The CLI knows one by those names, read from the archive's central directory (ZIP64 end records included), whatever the archive is named. The archive is not signed, so it is never checked as a record. Given alone, the CLI says what it holds and any part it lacks, and exits 2; given beside other records, as unzipping it in place leaves it, it is set aside with a note. When every pack given is named `part-K-of-N.zip` with the same `N`, every part from 1 to `N` must be there once: a part missing or given twice fails the sequence and is named. This holds for one part given alone too, when its `N` is above 1.

The CLI prints `SEQUENCE: VALID` (with `, IN PROGRESS` and how far the parts cover when the sequence is in progress), `SEQUENCE: NOT VERIFIED` (no fingerprint named, or a part not verified for a reason of its own, which it names), `SEQUENCE: NOT CHECKED` (a part in a format this checker does not read) or `SEQUENCE: INVALID` with the first failure, then the notes. It never prints `SEQUENCE: VALID` while a part failed its own check or was not verified. A failed sequence exits 1. A check of several files, or of one part of several, ends with `OVERALL:` and a word that matches the exit code: `VALID`, `INVALID`, `NOT CHECKED` or `NOT VERIFIED`, naming the first file that set it, or giving the sequence's reason when only the sequence failed. In `--json` a failed pair carries a `kind`: `mandate-id`, `key`, `gap`, `unreadable`, `missing`, `erased-first`, `changed` or `continuity`; a sequence not checked carries `format`.

## 8. Access record (`mandate.dsr.access-manifest-sig.v4`)

An access record answers one person's access request. It is a ZIP under the section 1 rules, with a `manifest.json` that lists every other file. The kind is read off the manifest: when its `subjectHashHex` is a string the archive is an access record; anything else (no manifest, or one that does not parse) is checked as a signed record. The CLI prints `Kind: access record`.

```json
{
  "manifestVersion": 3,
  "tenantId": "<uuid>",
  "subjectHashHex": "<64 hex chars>",
  "generatedAt": "<ISO 8601 timestamp>",
  "windowFrom": "<ISO 8601 timestamp or null>",
  "windowTo": "<ISO 8601 timestamp or null>",
  "truncated": false,
  "unscannableRows": 0,
  "degradedRows": 0,
  "partiallyScannableRows": 0,
  "opaqueRegions": 0,
  "opaqueBytes": 0,
  "contents": [
    { "filename": "audit/events.json", "sha256Hex": "<64 hex chars>", "byteLength": 11 }
  ],
  "signatureHex": "<128 hex chars>",
  "publicKeyBase64": "<32-byte Ed25519 public key, base64>",
  "publicKeyFingerprint": "<64 hex chars>"
}
```

`subjectHashHex` is a hash that stands for the person (the CLI prints it as `Person`). `truncated` and the five counters state how complete the answer is; all are signed. `signatureHex` is an Ed25519 signature over:

```
field                   bytes   encoding
domain tag              34      ASCII "mandate.dsr.access-manifest-sig.v4" (no length prefix)
tenantId                16      UUID
subjectHashHex          32      raw bytes
manifestVersion         4       u32
generatedAt             8       i64 Unix milliseconds
windowFrom              1 or 9  0x00 when absent; else 0x01 || i64 Unix milliseconds
windowTo                1 or 9  0x00 when absent; else 0x01 || i64 Unix milliseconds
truncated               1       0x01 if true, else 0x00
unscannableRows         4       u32
degradedRows            4       u32
partiallyScannableRows  4       u32
opaqueRegions           4       u32
opaqueBytes             8       u64
content count           4       u32
for each content entry, in ascending filename order: as in section 3
```

Timestamps, sorting and u32 ranges follow section 3; `opaqueBytes` must be a non-negative integer, and a window bound is absent when missing or `null`. The checks are the file checks of section 1 (both directions, hashes and lengths) and this signature. An access record has no checkpoints or records. Since 2.6.0 the section 2 rules apply to it as well: its `manifestVersion` must be 3 (any other value is reported as a different format and exits 3, as in section 2), it may carry only the 16 members shown above, and a declared `publicKeyFingerprint` must equal the SHA-256 of its key. `--expect-fingerprint` applies to its key as to a signed record. Since 2.10.0 an access record whose `windowTo` is after its `generatedAt` is in progress, as a signed record is (section 2); one with no `windowTo` is not.

## 9. Keys and fingerprints

- Keys are Ed25519, verified through WebCrypto (Node 20 or newer). A fingerprint is the SHA-256 of the 32 raw public-key bytes, rendered as 64 lowercase hex characters.
- One installation key signs manifests and checkpoints. Domain separation comes from the distinct domain tags, so a signature for one payload type cannot be replayed as another.
- Every manifest and checkpoint carries the public key that verifies it, so a pack keeps verifying on its own terms after a key change, and checkpoints sealed before the change carry the earlier key. Trust in a key is established out of band, by comparing its fingerprint with the one in your agreement.
- `--expect-fingerprint <hex>` names a trusted fingerprint. The value is lowercased and stripped of colons and whitespace, then must be 64 hex digits (otherwise exit 2), so plain hex, pairs separated by colons and pairs separated by spaces are all accepted, in any case. Give it more than once after a key change: the manifest key and every checkpoint key of every pack must each be one of the fingerprints named, or the pack fails.
- With no fingerprint named, a pack that passes every check is reported `RESULT: NOT VERIFIED` and the CLI exits 4: the key was not checked. The CLI never prints `RESULT: VALID` with the key unchecked.
- Outside timestamps (section 4.3) are trusted through their roots: the one the checker ships and any named with `--timestamp-root <file>` (a certificate in PEM or DER; give the option more than once for several). `--require-timestamps` asks for a checkable timestamp on every checkpoint (section 4.4).

| Exit code | Meaning |
| --- | --- |
| 0 | valid, signed by keys you named |
| 1 | invalid, signed by a key you did not name, or a sequence that fails |
| 2 | usage, file or ZIP error, or a complete export given as one file |
| 3 | no Ed25519 support in this runtime, or a pack or checkpoint of a different format, such as a pack in the change-trail layout before 2.7.0 (section 6.3) |
| 4 | not verified: no fingerprint was named, or outside timestamps the checker could not check (section 4.4) |

Given several files, the CLI exits with the most serious code, ranked 1, 3, 2, 4, 0 from most to least serious (since 2.10.0). `--json` prints one JSON document instead of text, with the same exit codes: for one file named directly, that file's result, or `{ "pack": <file>, "error": <message> }` when it cannot be read; for a folder, several files or one part of several, `{ "files": [...], "sequence": ..., "setAside": [...], "result": "<word>", "exitCode": <n> }`, each file with its own result and `exitCode`, `sequence` when there is one and `setAside` when a complete export was set aside.

## 10. Verification procedure

1. Read the ZIP under the section 1 rules.
2. Read the kind off `manifest.json` (section 8). The steps below are for a signed record.
3. Parse `manifest.json`; `contents` must be an array. If `manifestVersion` is not 3, stop and report a different format.
4. For every entry in `contents`, recompute the named file's SHA-256 and compare it with `sha256Hex`, and compare the file's length with `byteLength`; a missing file is a failure.
5. Set equality, the other direction: every archive file except `manifest.json` must appear in `contents`.
6. Rebuild the section 3 payload from the manifest and verify `signatureHex` with `publicKeyBase64`; then apply the section 2 rules.
7. For each checkpoint file, check its members and its Mandate ID, rebuild the section 4 payload, verify its signature with its own `publicKeyBase64`, check that its declared fingerprint names that key, and check its outside timestamp (section 4.3).
8. Walk `chain/links.json`: decode each record, check its id, Mandate ID and link to the one before (sections 5.1 to 5.4), and recompute every checkpoint's root (section 5.5).
9. Check the ties of section 6: policy text and lists, register rows and persons, change-trail entries, final decisions, erasures, the sealed documents with their review decisions and sign-offs, the printed report, the summary counts, the in-progress flag and the imported activity.
10. Check the order of the outside timestamps along the records (section 4.4).
11. Compute the fingerprint of the manifest key and of every checkpoint key, and compare each with the fingerprints you trust (section 9).
12. Given several packs, apply section 7.

A pack is VALID only if every step passes. A pack in the change-trail layout before 2.7.0 that passes every step it is held to is a different format (section 6.3). Reference behaviour for every failure mode, including the tamper matrix, is pinned by `test/check.mjs` and the vectors under `test/vectors/`.

## 11. Golden vectors

`test/vectors/` contains one vector per payload type, and one for the outside timestamp:

| File | Payload |
| --- | --- |
| `evidence-pack-signed-payload-v3.vector.json` | section 3 |
| `checkpoint-signed-payload-v1.vector.json` | section 4.1 |
| `dsr-access-signed-payload-v4.vector.json` | section 8 |
| `checkpoint-timestamp-v1.vector.json` | section 4.3 |

Each payload vector holds the input fields, the expected payload bytes (`payloadHex`), a signature, the public key and its fingerprint, generated from an all-zeros test-only seed (`seedBase64`). The same vector files are asserted byte for byte by the producing implementation's own tests, which is what makes this specification enforceable rather than descriptive. The signed-record vector carries `manifestVersion` 2: it pins the byte layout, which does not depend on that value, while a real manifest of version 2 is still reported as a different format.

The timestamp vector holds the checkpoint of `checkpoint-signed-payload-v1.vector.json` as the imprinted bytes (`imprintedHex`, 215 bytes) and their SHA-256, and the RFC 3161 answer DigiCert's public timestamp service gave to a request for them (`responseBase64`), with the token inside it (`tokenBase64`), its nonce, its time and its authority. The token verifies against those bytes and DigiCert Trusted Root G4.
