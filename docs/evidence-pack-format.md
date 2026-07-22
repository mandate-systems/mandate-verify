# Mandate evidence pack: format specification

This document specifies the parts of the evidence-pack format needed to verify a pack independently: the container, the manifest schema, and the two canonical signed payloads. It is the public companion to `mandate-verify.mjs`, which implements exactly what is written here. The deeper specification of the per-event hash chain and the Merkle leaf construction inside a checkpoint window is shared under NDA during evaluation; it is optional extra depth, not a prerequisite for proving a pack unaltered.

Version note: the manifest signature format is `v2` (domain tag below), the checkpoint signature format is `v1`, and the manifest schema version is `1`. These version numbers move independently.

## 1. Container

An evidence pack is a ZIP archive. Verifiers apply hardened limits when reading it:

| Limit | Value |
| --- | --- |
| Total size (declared and actual) | 50 MB (52,428,800 bytes) |
| Entry count | 1,032 (1,000 checkpoint files + 32 headroom for base files) |
| zip64 | rejected |
| Encrypted entries | rejected |
| Compression methods | stored (0) and deflate (8) only |
| Duplicate entry names | rejected |

CRC-32 values in the ZIP are ignored: file integrity is established against the signed SHA-256 list, and a CRC check would add nothing the signature does not already provide.

A pack produced by the current exporter contains:

```
README.txt                       plain-language description, inside the signed set
manifest.json                    the signed manifest (the only file not listed in itself)
policy/active.json               the policy in force at export time
policy/versions.json             policy version history
register/decisions.json          the decision register for the export window
register/purposes.json           purpose tags referenced by the register
scope/blind-spots.json           what the export window does not cover, stated explicitly
summary/decision-mix.json        aggregate decision counts
mutations/policy-trail.json      policy mutation history
checkpoints/<uuid>.json          one file per embedded audit checkpoint
```

Verification does not depend on this inventory: the manifest's content list is authoritative, and the set of files in the archive must equal it exactly (minus `manifest.json` itself), in both directions. A file in the archive but not the list, or in the list but not the archive, fails verification.

## 2. Manifest schema (`manifest.json`, schema version 1)

```json
{
  "manifestVersion": 1,
  "tenantId": "<uuid>",
  "generatedAt": "<ISO 8601 timestamp>",
  "windowFrom": "<ISO 8601 timestamp>",
  "windowTo": "<ISO 8601 timestamp>",
  "truncated": false,
  "checkpointsTruncated": false,
  "contents": [
    { "filename": "policy/active.json", "sha256Hex": "<64 hex chars>", "byteLength": 1166 }
  ],
  "checkpointIds": ["<uuid>"],
  "signatureHex": "<128 hex chars>",
  "publicKeyBase64": "<32-byte Ed25519 public key, base64>",
  "publicKeyFingerprint": "<64 hex chars>"
}
```

- `truncated` is true when the register-row cap (10,000 rows) overflowed; `checkpointsTruncated` when the checkpoint cap (1,000) did. Both flags are inside the signed payload, so a capped pack cannot be re-labelled complete or the reverse.
- `publicKeyFingerprint` is self-declared convenience metadata and is NOT part of the signed payload. Verifiers must ignore it and report the SHA-256 of `publicKeyBase64`'s raw bytes, the key that actually verified. A forger controls the declared field; they cannot make a chosen key verify without its private key.

## 3. Evidence-pack signed payload (`mandate.evidence-pack.manifest-sig.v2`)

The manifest's `signatureHex` is an Ed25519 signature over the following byte string. All integers are big-endian; the payload is length-prefixed where noted because the content list is dynamic.

```
domain tag            ASCII "mandate.evidence-pack.manifest-sig.v2" (no length prefix; constant)
tenant_id             16 bytes (RFC 4122 wire order)
manifest_version      u32
generated_at          i64 Unix milliseconds
window_from           i64 Unix milliseconds
window_to             i64 Unix milliseconds
truncated             1 byte (0x00 / 0x01)
checkpoints_truncated 1 byte (0x00 / 0x01)
content_count         u32
for each content entry, in ASCENDING ordinal filename order:
  filename            u32 length + UTF-8 bytes
  sha256              32 raw bytes (no length prefix)
  byte_length         u64
```

The three timestamps are bound as integer Unix milliseconds, not as formatted strings, so a verifier reproduces them from the manifest's JSON timestamps with any parser that truncates to milliseconds, regardless of how the producer's serializer rendered the timestamp (offset form versus `Z`, fractional-digit trimming). The window bounds are required. The content list must be sorted ascending by ordinal (byte-wise) filename comparison with no duplicates; producers sort before signing and verifiers sort before reconstructing, so entry order in the JSON is not load-bearing.

## 4. Checkpoint signed payload (`mandate.audit.checkpoint-sig.v1`)

Each `checkpoints/<uuid>.json` file carries its own Ed25519 signature (`signatureHex`) over a fixed-length 119-byte payload:

```
offset  length  field
0       31      domain tag             ASCII "mandate.audit.checkpoint-sig.v1"
31      16      tenant_id              RFC 4122 wire order
47      16      window_start_event_id  RFC 4122 wire order
63      16      window_end_event_id    RFC 4122 wire order
79      8       event_count            i64 big-endian
87      32      merkle_root
```

The signature attests the tuple, not the bare Merkle root, so a checkpoint's metadata cannot be swapped without invalidating it. The checkpoint file's `windowStartOccurredAt` / `windowEndOccurredAt` timestamps, `checkpointId`, and `createdAt` are deliberately not signed: the event-id bounds, event count, and Merkle root define the sealed window cryptographically, and the timestamps are operational convenience derived from the same rows. The `merkle_root` is a 32-byte root over the checkpoint's event window; its leaf construction is part of the NDA-level specification and is not needed to verify the signature.

## 5. Keys and fingerprints

- Keys are Ed25519. A fingerprint is the SHA-256 of the 32 raw public-key bytes, rendered as 64 lowercase hex characters.
- One installation key signs both manifests and checkpoints; domain separation comes from the distinct domain tags, so a signature for one payload type cannot be replayed as the other.
- Every pack and checkpoint carries the public key that verifies it, so a pack keeps verifying on its own terms after a key rotation. Trust in the key itself is established out of band by comparing fingerprints.

## 6. Verification procedure

1. Read the ZIP under the section 1 limits.
2. Parse `manifest.json`.
3. For every entry in `contents`: recompute the named file's SHA-256 and compare (case-insensitive hex); a missing file is a failure.
4. Set equality, the other direction: every archive file except `manifest.json` must appear in `contents`.
5. Reconstruct the section 3 payload from the manifest fields and verify `signatureHex` with `publicKeyBase64`.
6. For each checkpoint file: reconstruct the section 4 payload from its fields and verify its signature with its own `publicKeyBase64`.
7. Report the SHA-256 fingerprint of every key that verified. Comparing those fingerprints to ones you trust is the caller's step.

A pack is VALID only if every step passes. Reference behavior for every failure mode, including the tamper matrix, is pinned by `test/check.mjs` and the vectors under `test/vectors/`.

## 7. Golden vectors

`test/vectors/` contains one vector per payload type. Each vector holds the input fields, the expected payload bytes (`payloadHex`), a signature, the public key, and its fingerprint, generated from an all-zeros test-only seed. The same vector files are asserted byte-for-byte by the producing implementation's C# tests and the product TypeScript verifier's tests, which is what makes this specification enforceable rather than descriptive.
