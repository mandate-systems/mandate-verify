# Mandate evidence pack: format specification

This document specifies what is needed to check a Mandate evidence pack (the site and the CLI call it a signed record) independently: the container, the manifest, the three signed payloads, the records inside the pack, what ties the readable files to those records, the rules for comparing several packs, and the access record. It is the public companion to `mandate-verify.mjs` 2.5.0, which implements exactly what is written here.

Version note: the manifest signature format is `v3`, the checkpoint signature format is `v1`, the access-record signature format is `v4`, the manifest schema version is `3`, and records use layouts `1` to `9`. These numbers move independently. `node mandate-verify.mjs --version` prints the tool version and the three domain tags.

Conventions: integers are big-endian (ZIP structures excepted, which are little-endian as ZIP defines them). A UUID is 16 bytes in RFC 4122 wire order, which is the 32 hex digits of its text form, in order. Hex is accepted in either case and compared case-insensitively, unless a rule below says lowercase. `||` is concatenation.

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
| CRC-32 | checked on every file (since 2.3.1) |

The reader also requires:

- The archive ends with a 22-byte end-of-central-directory record, and the central directory ends exactly where that record starts.
- A folder entry (name ending in `/`) holds no data. Folders are not files and need no manifest entry.
- Each entry's local header carries the same name as its central-directory entry. Names are read as UTF-8.
- A deflated file inflates to no more than its declared uncompressed size; every file comes out at exactly that size, and its CRC-32 (the ZIP polynomial) equals the one in the central directory.
- No unaccounted bytes: ordered by local-header offset, the entries (local header, data, and, when flag bit 3 is set, a data descriptor of 16 bytes if it starts with `0x08074b50`, otherwise 12) run back to back from offset 0 to the start of the central directory.

The CRC check makes the files a verifier reads the files any unzip tool extracts. Integrity itself rests on the signed SHA-256 list.

A pack produced by the current exporter contains:

```
README.txt                          plain-language description, inside the signed set
manifest.json                       the signed manifest (the only file not listed in itself)
assurance/detector-catch-rate.json  measured catch rate of the shipped detector library, with its own scope statement
chain/links.json                    the records of the sealed windows and the export window, in chain order (section 5)
chain/erasures.json                 the change-trail entries that erased the removed records (section 6.4)
checkpoints/<uuid>.json             one file per embedded audit checkpoint (section 4)
mutations/policy-trail.json         the change trail for the export window
policy/active.json                  the policy in force at export time
policy/lists.json                   each sealed list of names in a rule, with or without the names (section 6.6)
policy/versions.json                policy versions, each with its text and SHA-256
register/decisions.json             the decision register for the export window, with its change-trail entries
register/mandates.json              the authority-grant registry, revoked and expired grants included
register/purposes.json              purpose tags referenced by the register
report/report.pdf                   the printed report, naming the SHA-256 of report/summary.json
report/summary.json                 the figures the printed report shows
scope/blind-spots.json              what the export window does not cover, stated explicitly
summary/agent-exposure.json         registered agents, their credentials and mandates, their holds and calls
summary/attachments.json            decisions counted by the kind of attachment the request carried
summary/decision-mix.json           aggregate decision counts
summary/framework-coverage.json     the workspace's own rule-to-framework references and a per-framework decision rollup, recorded not verified, with its own scope statement
```

The manifest's content list is authoritative, and the set of files in the archive must equal it exactly (minus `manifest.json` itself), in both directions. A file in the archive but not the list, or in the list but not the archive, fails verification. Of the files above, the verifier requires `manifest.json` and `chain/links.json`, and reads `checkpoints/`, `chain/erasures.json`, `mutations/policy-trail.json`, `policy/lists.json`, `policy/versions.json`, `register/decisions.json`, `report/` and `summary/decision-mix.json` when present. The signature covers every listed file whether the verifier reads it or not.

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

- `tenantId` names the workspace the pack belongs to; the CLI prints it as `Workspace`.
- The three timestamps are required and must match `YYYY-MM-DDTHH:MM:SS`, an optional fraction of 1 to 9 digits, then `Z` or `+HH:MM` / `-HH:MM`.
- `truncated` is true when the register, or `chain/links.json`, holds only part of the window; `checkpointsTruncated` when the checkpoint files were capped; `mutationsTruncated` when the change trail was. All three flags are inside the signed payload, so a capped pack cannot be re-labelled complete or the reverse.
- `contents` lists every file except `manifest.json`. Each `sha256Hex` is compared with the file. `byteLength` is bound by the signature but not compared with the file's length.

Rules on the manifest as a whole, applied once the signature verifies (the first that fails is reported):

- **No members outside the signature.** The manifest may carry only the 13 members above. The payload (section 3) binds the first nine; `signatureHex` and `publicKeyBase64` are what verifies it; `publicKeyFingerprint` and `checkpointIds` are checked against signed data below. Any other member makes the manifest INVALID, because nothing binds it.
- **The declared fingerprint must match the key.** When `publicKeyFingerprint` is present it must equal the SHA-256 of the decoded `publicKeyBase64`. Since 2.4.0 a mismatch is refused, not ignored. The verifier reports the fingerprint it computed, never the declared one.
- **Checkpoint ids.** When `checkpointIds` is an array, it must list exactly the ids of the `checkpoints/<uuid>.json` files in the archive, each once, in any order.

**Other formats.** When `manifestVersion` is not 3, nothing further is checked and the verifier reports a different format, not INVALID: the CLI prints `RESULT: DIFFERENT FORMAT` naming the pack's format and the verifier to use, and exits 3; `--json` reports `"overall": "unsupported"` with `"format"`. This rule applies to the signed record only (the access record is section 8).

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

The timestamps are bound as integer Unix milliseconds, not as formatted strings: parse each and truncate to the millisecond (fraction digits past the third are dropped, not rounded). Offset form or `Z`, and any number of fraction digits, give the same bytes. An absent flag counts as false. The verifier sorts the entries itself before rebuilding, so their order in the JSON is not load-bearing; filenames are compared code unit by code unit (UTF-16), which for the ASCII names a pack uses is plain byte order. A u32 field that is not an integer from 0 to 4,294,967,295 makes the payload unbuildable and the manifest INVALID; it is never coerced. `byteLength` must be an integer.

## 4. Checkpoint payload (`mandate.audit.checkpoint-sig.v1`)

Each `checkpoints/<uuid>.json` file:

```json
{
  "schemaVersion": 1,
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
  "createdAt": "<ISO 8601 timestamp>"
}
```

Every member is required: `schemaVersion` is an integer and `eventCount` a non-negative integer, the four ids are UUIDs in text form, the rest are non-empty strings. The root must decode to 32 bytes, the signature to 64 and the key to 32. `signatureHex` is an Ed25519 signature over a fixed 119-byte payload:

```
offset  length  field
0       31      domain tag             ASCII "mandate.audit.checkpoint-sig.v1"
31      16      tenantId               UUID
47      16      windowStartEventId     UUID
63      16      windowEndEventId       UUID
79      8       eventCount             i64
87      32      merkleRootHex          32 raw bytes
```

- **Workspace.** A checkpoint whose `tenantId` names another workspace than the manifest's fails, even though its own signature holds.
- The signature attests the tuple, not the bare root, so a checkpoint's metadata cannot be swapped without invalidating it. `windowStartOccurredAt`, `windowEndOccurredAt`, `checkpointId`, `createdAt` and `schemaVersion` are not signed: the id bounds, the count and the root define the sealed window, and section 5.5 recomputes the root from the records.
- The checkpoint's own `publicKeyFingerprint` must be present but is not compared with its key; the verifier reports the SHA-256 of `publicKeyBase64`.

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
- `scope`, `from` and `to` are informative. For a live record the verifier takes the time from the record's own `occurred_at`; a link's `occurredAt` is read only for removed records.

Each live record must decode (section 5.2), carry the link's `id` as its `id`, and name the manifest's workspace as its `tenant_id`.

### 5.2 Record bytes

```
byte 0    layout version, 1 to 9
byte 1    0x00 (a live record; the verifier reads no other value)
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
| text | UTF-8; invalid UTF-8 is rejected where the verifier reads it |
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

`policy_decision` is the outcome: `allow`, `warn`, `redact`, `escalate` or `block` for a decision (the CLI says allowed, warned, masked, held, refused), `result` for an answer relayed back, `imported` for an imported record, and `change` for a change record (section 6.3). The verifier counts any other value as a decision. `model` is empty text when there is none. The verifier decodes every field but does not interpret `agent_action`, `agent_principal_id`, `connector`, `request_body_hash_outbound`, `response_body_hash`, `subject_hash` or `upstream_id`; they are covered by the record's hash.

### 5.4 Links

A link's hash is the SHA-256 of its record bytes, or its `deletedRecordSha256`. Every live record after the first link must carry, as `chain_prev_hash`, the hash of the link immediately before it, live or removed. The first link's `chain_prev_hash` is not checked within one pack (at the start of a workspace's chain it is 32 zero bytes); section 7 uses it to join packs.

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

- Time: when both values are in UTC (`Z`, `+00:00` or `-00:00`) they must agree to the microsecond (fraction digits past the sixth dropped); otherwise to the millisecond.
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

A change-trail entry is sealed into the chain by a change record: a live record whose `policy_decision` is `change`, whose `correlation_id` is the entry's `id`, and whose `request_body_hash` is the entry's seal. Entries appear in `mutations/policy-trail.json`, in `register/decisions.json` (rows with `"source": "mutation"`) and in `chain/erasures.json` (its `entries`). Every entry must carry a string `id`. Every copy of an entry whose change record is in `chain/links.json` must reproduce that record's seal; an entry with no change record in the pack is reported as not sealed yet or outside the records file, and is not checked.

```
seal = SHA-256(
  ASCII "mandate.change-trail-entry.v1" || 0x00
  || F(id)                          UUID
  || F(workspace)                   UUID: the manifest's tenantId
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
)
F(b)       = u32 length || b
O(absent)  = 0xFF || 00 00 00 00
O(b)       = 0x00 || u32 length || b
```

- Absent means missing or `null`; an absent `transition` makes all six of its fields absent. Text fields take the value's string form. Members not listed (such as `source`, `actorSalt` itself, or `transition.changes`) are not sealed.
- Ticks are 100-nanosecond units since 1970-01-01T00:00:00Z: the Unix milliseconds of `occurredAt` without its fraction, times 10,000, plus the first seven fraction digits as an integer (padded on the right with zeros; further digits dropped). `occurredAt` must match `YYYY-MM-DDTHH:MM:SS`, an optional fraction, then `Z` or `+HH:MM` / `-HH:MM`.
- `action` and `actorType` must be strings. An entry that names `actorDisplay` must carry `actorSalt` (hex).

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

## 7. Several packs

The CLI takes several packs, or a folder, which stands for every `.zip` file in it. A complete export of a long period is several packs; unzip it and give the verifier the folder (a file whose name ends in `-packs.zip` is refused with exit 2 until it is unzipped). Each pack is first checked alone. Every input must be a readable signed record, not an access record, or the sequence fails.

Packs named one by one are put in order of `windowFrom` and each neighbouring pair is compared. When any input is a folder, the inputs are taken in the order given (a folder's files in name order) and compared one neighbour at a time, so a long export needs no more memory than two packs. For each pair, earlier window first:

1. **One workspace.** The two `tenantId` values are the same string.
2. **One key.** The two computed fingerprints are equal, unless both packs passed as VALID with fingerprints named by `--expect-fingerprint` (as after a key change).
3. **No gap.** The later `windowFrom` is at most 1 millisecond after the earlier `windowTo`; overlap is allowed.
4. **Both record walks passed** (sections 5 and 6).
5. **The records agree** (below).
6. **Continuity.** When both packs hold links, the later pack's first link is in the earlier pack, or is a live record whose `chain_prev_hash` is the hash of the earlier pack's last link.

What an export is held to: its window, `windowFrom` to `windowTo` inclusive, cut to one minute before its `generatedAt` when that is earlier. When the file in question says it is partial (for links, `chain/links.json` `truncated`; for `mutations/policy-trail.json`, the manifest's `mutationsTruncated`; for the register's change-trail rows, the manifest's `truncated`), the export is held only to the span strictly between the earliest and latest times that file holds, where those fall inside, and to nothing if it holds none.

The records agree when, in both directions:

- **Nothing is missing.** A link, live or removed, that one pack holds at a time the other is held to must be in the other. A link inside the other's window but outside what it is held to is named in a note (`N records of A inside the period of B not compared: <reason>`).
- **No erased record comes back.** A record live in one pack and removed in the other is named in a note (`N decisions erased between A and B: <id> (<outcome>, <time>), ...`). It fails instead when the pack in which it is removed says, by `generatedAt`, that it was made before the other.
- **Register rows read the same.** A row (`source` `decision` or `imported`) in both packs must agree on `person`, `actorType`, `actorId`, `actorDisplay`, `action`, `occurredAt`, `provider`, `model`, `policyVersionId`, `correlationId`, and every other member that rows of both packs carry. Times compare as instants to 100 nanoseconds; other values as JSON with object keys sorted, an absent member as `null`. A different `actorDisplay` for the same agent (`actorType` `agent`, same `actorId`) is a note, not a failure.
- **Sealed records match.** A link in both packs has the same hash in both.
- **Change-trail entries read the same**, separately for `mutations/policy-trail.json` and for register rows with `"source": "mutation"`. An entry in both must agree on every member (times as instants). When only one copy no longer names who acted (`actorType` `mandate_support`, no `actorId`, no `actorDisplay`), those three members are skipped and a note says the account was removed between the exports. An entry one pack holds at a time the other is held to must be in the other.

The CLI prints `SEQUENCE: VALID`, `SEQUENCE: NOT VERIFIED` (no fingerprint named) or `SEQUENCE: INVALID` with the first failure, then the notes. A failed sequence exits 1. In `--json` a failed pair carries a `kind`: `workspace`, `key`, `gap`, `unreadable`, `missing`, `erased-first`, `changed` or `continuity`.

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

Timestamps, sorting and u32 ranges follow section 3; `opaqueBytes` must be a non-negative integer, and a window bound is absent when missing or `null`. The checks are the file checks of section 1 (both directions) and this signature. An access record has no checkpoints or records, and the section 2 rules (members, declared fingerprint, format) are not applied to it; its `manifestVersion` is signed but not checked against a value. `--expect-fingerprint` applies to its key as to a signed record.

## 9. Keys and fingerprints

- Keys are Ed25519, verified through WebCrypto (Node 20 or newer). A fingerprint is the SHA-256 of the 32 raw public-key bytes, rendered as 64 lowercase hex characters.
- One installation key signs manifests and checkpoints. Domain separation comes from the distinct domain tags, so a signature for one payload type cannot be replayed as another.
- Every manifest and checkpoint carries the public key that verifies it, so a pack keeps verifying on its own terms after a key change, and checkpoints sealed before the change carry the earlier key. Trust in a key is established out of band, by comparing its fingerprint with the one in your agreement.
- `--expect-fingerprint <hex>` names a trusted fingerprint. The value is lowercased and stripped of colons and whitespace, then must be 64 hex digits (otherwise exit 2), so plain hex, pairs separated by colons and pairs separated by spaces are all accepted, in any case. Give it more than once after a key change: the manifest key and every checkpoint key of every pack must each be one of the fingerprints named, or the pack fails.
- With no fingerprint named, a pack that passes every check is reported `RESULT: NOT VERIFIED` and the CLI exits 4: unchanged since signing, but the key was not checked. The CLI never prints `RESULT: VALID` with the key unchecked.

| Exit code | Meaning |
| --- | --- |
| 0 | valid, signed by keys you named |
| 1 | invalid, signed by a key you did not name, or a sequence that fails |
| 2 | usage, file or ZIP error |
| 3 | no Ed25519 support in this runtime, or a pack of a different format |
| 4 | not verified: unchanged since signing, but no fingerprint was named |

Given several packs, the CLI exits with the worst code, ranked 0, 4, 1, 2, 3 from best to worst. `--json` prints the results as JSON instead of text, with the same exit codes.

## 10. Verification procedure

1. Read the ZIP under the section 1 rules.
2. Read the kind off `manifest.json` (section 8). The steps below are for a signed record.
3. Parse `manifest.json`; `contents` must be an array. If `manifestVersion` is not 3, stop and report a different format.
4. For every entry in `contents`, recompute the named file's SHA-256 and compare it with `sha256Hex`; a missing file is a failure.
5. Set equality, the other direction: every archive file except `manifest.json` must appear in `contents`.
6. Rebuild the section 3 payload from the manifest and verify `signatureHex` with `publicKeyBase64`; then apply the section 2 rules.
7. For each checkpoint file, check its members and its workspace, rebuild the section 4 payload and verify its signature with its own `publicKeyBase64`.
8. Walk `chain/links.json`: decode each record, check its id, workspace and link to the one before (sections 5.1 to 5.4), and recompute every checkpoint's root (section 5.5).
9. Check the ties of section 6: policy text and lists, register rows and persons, change-trail entries, erasures, the printed report, and the summary counts.
10. Compute the fingerprint of the manifest key and of every checkpoint key, and compare each with the fingerprints you trust (section 9).
11. Given several packs, apply section 7.

A pack is VALID only if every step passes. Reference behaviour for every failure mode, including the tamper matrix, is pinned by `test/check.mjs` and the vectors under `test/vectors/`.

## 11. Golden vectors

`test/vectors/` contains one vector per payload type:

| File | Payload |
| --- | --- |
| `evidence-pack-signed-payload-v3.vector.json` | section 3 |
| `checkpoint-signed-payload-v1.vector.json` | section 4 |
| `dsr-access-signed-payload-v4.vector.json` | section 8 |

Each vector holds the input fields, the expected payload bytes (`payloadHex`), a signature, the public key and its fingerprint, generated from an all-zeros test-only seed (`seedBase64`). The same vector files are asserted byte for byte by the producing implementation's own tests, which is what makes this specification enforceable rather than descriptive. The signed-record vector carries `manifestVersion` 2: it pins the byte layout, which does not depend on that value, while a real manifest of version 2 is still reported as a different format.
