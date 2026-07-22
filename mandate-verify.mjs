#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Mandate Systems Inc.
/**
 * mandate-verify.mjs - offline verifier for Mandate evidence packs.
 *
 * Verifies a downloaded evidence-pack ZIP without contacting Mandate:
 *   1. Recomputes every file's SHA-256 and compares it to the signed manifest.
 *   2. Confirms every file in the pack is listed in the manifest (and vice versa).
 *   3. Reconstructs the manifest's canonical signed payload (ADR-0032 layout) and
 *      verifies its Ed25519 signature with the public key carried in the manifest.
 *   4. Verifies each embedded audit checkpoint's Ed25519 signature the same way.
 *
 * A pass proves the pack matches the signing key whose fingerprint is printed.
 * Comparing that fingerprint to one you trust is your step, not the tool's.
 *
 * Usage:
 *   node mandate-verify.mjs <pack.zip> [--expect-fingerprint <hex>] [--json]
 *
 * Options:
 *   --expect-fingerprint <hex>  Also require the manifest key and every embedded
 *                               checkpoint key to match this SHA-256 fingerprint.
 *   --json                      Print the full result as JSON instead of text.
 *   --version                   Print the tool version and supported payload formats.
 *
 * Exit codes:
 *   0  pack is valid (and matches --expect-fingerprint when given)
 *   1  pack is invalid, or the fingerprint does not match
 *   2  usage error, unreadable file, or not a readable ZIP archive
 *   3  this runtime lacks WebCrypto Ed25519 support (use Node 20 or newer)
 *
 * Requirements: Node.js 20 or newer. No packages are installed or downloaded;
 * the only imports are Node built-ins (fs, zlib, crypto, url).
 */

import { readFile } from "node:fs/promises";
import { inflateRawSync } from "node:zlib";
import { pathToFileURL } from "node:url";

/** Tool version (release tag), independent of the payload format versions in the domain tags below. */
const TOOL_VERSION = "1.0.0";

// ================================================================================================
// VERIFIER-CORE-BEGIN v1
// Twinned, byte for byte, between www/downloads/mandate-verify.mjs and the inline module script
// in www/verify.html. scripts/check-verifier-ports.mjs asserts the two copies are identical and
// pins the payload layouts to the cross-language golden vectors shared with the product
// (src/Mandate.Web/src/lib/audit/*.vector.json). Edit both copies together or the check fails.
// The verification logic is a faithful port of the product verifiers:
//   src/Mandate.Web/src/lib/audit/verifyCheckpoint.ts
//   src/Mandate.Web/src/lib/audit/verifyEvidencePack.ts
// ================================================================================================

/** ASCII domain-separation tag for the v1 checkpoint signed payload (ADR-0011). */
export const CHECKPOINT_SIGNED_PAYLOAD_DOMAIN_V1 = "mandate.audit.checkpoint-sig.v1";

/** ASCII domain-separation tag for the v2 evidence-pack manifest signed payload (ADR-0032); binds the export window. */
export const EVIDENCE_PACK_SIGNED_PAYLOAD_DOMAIN_V2 = "mandate.evidence-pack.manifest-sig.v2";

// Decompression-bomb caps, mirroring the product verifier's limits (absolute size + file count; no
// expansion-ratio cap, which the product verifier also omits and which false-positives on legitimately
// compressible packs).
export const ZIP_MAX_TOTAL_BYTES = 52428800; // 50 MB
export const ZIP_MAX_FILE_COUNT = 1032; // EvidencePackAssembler.MaxCheckpoints (1000) + 32 headroom, mirroring verifyEvidencePack.ts

export class ZipError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ZipError";
    this.code = code;
  }
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length");
  // Number.parseInt is lenient: parseInt("1z", 16) === 1 and parseInt("+f", 16) === 15, so a
  // byte pair with a stray non-hex nibble would be silently accepted. Validate the whole string
  // strictly so a tampered signature cannot pass decoding with a wrong-but-plausible byte.
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("hex string has non-hex characters");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Parse a UUID string into its 16 RFC 4122 wire-order bytes (hex digits in string order, hyphens
 * removed). Strict validation so a malformed id cannot decode to a wrong-but-plausible value.
 */
export function uuidToRfc4122Bytes(uuid) {
  const hex = uuid.replace(/-/g, "");
  if (hex.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(hex)) {
    throw new Error(`invalid uuid: ${uuid}`);
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Reconstruct the exact bytes the server signs for a checkpoint (CheckpointSignedPayload v1).
 * Layout (fixed length, big-endian):
 *   domain tag (31 ASCII bytes) | tenantId (16) | windowStartEventId (16) | windowEndEventId (16)
 *   | eventCount (Int64 BE, 8) | merkleRoot (32)
 */
export function buildCheckpointSignedPayload(tenantId, windowStartEventId, windowEndEventId, eventCount, merkleRoot) {
  if (merkleRoot.length !== 32) {
    throw new Error(`merkle root must be 32 bytes, got ${merkleRoot.length}`);
  }
  if (!Number.isSafeInteger(eventCount) || eventCount < 0) {
    throw new Error(`event count must be a non-negative integer, got ${eventCount}`);
  }

  const domain = new TextEncoder().encode(CHECKPOINT_SIGNED_PAYLOAD_DOMAIN_V1);
  const out = new Uint8Array(domain.length + 16 + 16 + 16 + 8 + 32);
  let offset = 0;
  out.set(domain, offset);
  offset += domain.length;
  out.set(uuidToRfc4122Bytes(tenantId), offset);
  offset += 16;
  out.set(uuidToRfc4122Bytes(windowStartEventId), offset);
  offset += 16;
  out.set(uuidToRfc4122Bytes(windowEndEventId), offset);
  offset += 16;
  new DataView(out.buffer, out.byteOffset, out.byteLength).setBigInt64(offset, BigInt(eventCount), false);
  offset += 8;
  out.set(merkleRoot, offset);
  return out;
}

/**
 * Reconstruct the exact bytes the server signs for an evidence-pack manifest
 * (EvidencePackSignedPayload v2). generatedAt and the export window (windowFrom, windowTo) are each
 * bound as Unix milliseconds (big-endian); content entries are bound in ascending ordinal filename
 * order. The window bounds are required (the export endpoint always supplies them).
 */
export function buildEvidencePackSignedPayload(tenantId, manifestVersion, generatedAt, windowFrom, windowTo, truncated, checkpointsTruncated, contents) {
  const sorted = [...contents].sort((a, b) => (a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0));
  const enc = new TextEncoder();
  const parts = [];

  const pushU32 = (n) => {
    parts.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  };
  const pushU64 = (n) => {
    for (let shift = 56n; shift >= 0n; shift -= 8n) parts.push(Number((n >> shift) & 0xffn));
  };
  const pushBytes = (b) => {
    for (const x of b) parts.push(x);
  };

  const pushTimestampMs = (label, value) => {
    const ms = Date.parse(value);
    if (Number.isNaN(ms)) throw new Error(`invalid ${label}: ${value}`);
    pushU64(BigInt(ms));
  };

  pushBytes(enc.encode(EVIDENCE_PACK_SIGNED_PAYLOAD_DOMAIN_V2));
  pushBytes(uuidToRfc4122Bytes(tenantId));
  pushU32(manifestVersion);

  // generated_at, then the export window bounds, each Unix ms (mirrors EvidencePackSignedPayload.cs).
  pushTimestampMs("generatedAt", generatedAt);
  pushTimestampMs("windowFrom", windowFrom);
  pushTimestampMs("windowTo", windowTo);

  parts.push(truncated ? 1 : 0);
  parts.push(checkpointsTruncated ? 1 : 0);

  pushU32(sorted.length);
  for (const c of sorted) {
    const nameBytes = enc.encode(c.filename);
    pushU32(nameBytes.length);
    pushBytes(nameBytes);
    const sha = hexToBytes(c.sha256Hex);
    if (sha.length !== 32) throw new Error(`content ${c.filename} sha256 must be 32 bytes`);
    pushBytes(sha);
    pushU64(BigInt(c.byteLength));
  }

  return new Uint8Array(parts);
}

/**
 * Verify a raw Ed25519 signature over payload with a raw 32-byte public key, via WebCrypto.
 * Returns { status: "valid" } | { status: "invalid", reason } | { status: "unsupported", reason }.
 */
export async function verifyEd25519(payload, signature, publicKey, invalidReason = "signature does not verify") {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return { status: "unsupported", reason: "WebCrypto SubtleCrypto unavailable" };
  }

  let key;
  try {
    key = await subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  } catch (err) {
    return { status: "unsupported", reason: `Ed25519 not supported: ${err.message}` };
  }

  let ok;
  try {
    ok = await subtle.verify({ name: "Ed25519" }, key, signature, payload);
  } catch (err) {
    return { status: "unsupported", reason: `verify failed: ${err.message}` };
  }

  return ok ? { status: "valid" } : { status: "invalid", reason: invalidReason };
}

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Validate the shape of a checkpoint export bundle (the same 13 fields the product's schema
 * requires). Throws with the offending field name; returns the bundle unchanged when well formed.
 */
export function validateCheckpointBundle(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("checkpoint bundle is not an object");
  }
  const requireUuid = (field) => {
    if (typeof value[field] !== "string" || !UUID_RE.test(value[field])) {
      throw new Error(`checkpoint bundle field ${field} is not a uuid`);
    }
  };
  const requireString = (field) => {
    if (typeof value[field] !== "string" || value[field].length === 0) {
      throw new Error(`checkpoint bundle field ${field} is not a string`);
    }
  };
  const requireInt = (field) => {
    if (typeof value[field] !== "number" || !Number.isSafeInteger(value[field])) {
      throw new Error(`checkpoint bundle field ${field} is not an integer`);
    }
  };
  requireInt("schemaVersion");
  requireUuid("checkpointId");
  requireUuid("tenantId");
  requireUuid("windowStartEventId");
  requireUuid("windowEndEventId");
  requireString("windowStartOccurredAt");
  requireString("windowEndOccurredAt");
  requireInt("eventCount");
  requireString("merkleRootHex");
  requireString("signatureHex");
  requireString("publicKeyBase64");
  requireString("publicKeyFingerprint");
  requireString("createdAt");
  return value;
}

/**
 * Verify a checkpoint export bundle's Ed25519 signature against its embedded public key. The signed
 * payload is reconstructed from the bundle fields, so a tampered tenantId, window bound, event
 * count, or Merkle root fails verification.
 */
export async function verifyCheckpointBundle(bundle) {
  let rootBytes;
  let signatureBytes;
  let publicKeyBytes;
  try {
    rootBytes = hexToBytes(bundle.merkleRootHex);
    signatureBytes = hexToBytes(bundle.signatureHex);
    publicKeyBytes = base64ToBytes(bundle.publicKeyBase64);
  } catch (err) {
    return { status: "invalid", reason: `bundle decoding failed: ${err.message}` };
  }

  if (rootBytes.length !== 32) {
    return { status: "invalid", reason: `merkle root must be 32 bytes, got ${rootBytes.length}` };
  }
  if (signatureBytes.length !== 64) {
    return { status: "invalid", reason: `signature must be 64 bytes, got ${signatureBytes.length}` };
  }
  if (publicKeyBytes.length !== 32) {
    return { status: "invalid", reason: `public key must be 32 bytes, got ${publicKeyBytes.length}` };
  }

  let signedPayload;
  try {
    signedPayload = buildCheckpointSignedPayload(
      bundle.tenantId,
      bundle.windowStartEventId,
      bundle.windowEndEventId,
      bundle.eventCount,
      rootBytes,
    );
  } catch (err) {
    return { status: "invalid", reason: `signed payload reconstruction failed: ${err.message}` };
  }

  return verifyEd25519(
    signedPayload,
    signatureBytes,
    publicKeyBytes,
    "signature does not match checkpoint metadata and merkle root",
  );
}

export async function sha256Hex(bytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto SubtleCrypto unavailable");
  const digest = await subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Minimal ZIP reader for evidence packs. Parses the end-of-central-directory record and the
 * central directory, extracts stored (method 0) and deflate (method 8) entries, and enforces the
 * decompression-bomb caps above. Rejects zip64, encryption, and duplicate entry names. CRC-32 is
 * deliberately not checked: every content byte is already verified against the signed manifest's
 * SHA-256 list, which supersedes the ZIP container's own checksum.
 *
 * inflateRaw is injected by the host: raw-deflate decompression via node:zlib in the CLI and via
 * DecompressionStream("deflate-raw") in the browser.
 */
export async function readZipEntries(buffer, inflateRaw) {
  if (buffer.length > ZIP_MAX_TOTAL_BYTES) {
    throw new ZipError("too-large", "archive exceeds the 50 MB size cap");
  }
  if (buffer.length < 22) {
    throw new ZipError("malformed", "file is too small to be a ZIP archive");
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  // End-of-central-directory record: signature 50 4b 05 06, within the last 65557 bytes
  // (22-byte minimum record plus a comment of at most 65535 bytes).
  let eocd = -1;
  const scanFloor = Math.max(0, buffer.length - 65557);
  for (let i = buffer.length - 22; i >= scanFloor; i--) {
    // Require the signature AND a comment-length field that points exactly at end-of-file, so a comment
    // that happens to embed the EOCD signature bytes is not mistaken for the real record.
    if (buffer[i] === 0x50 && buffer[i + 1] === 0x4b && buffer[i + 2] === 0x05 && buffer[i + 3] === 0x06
        && view.getUint16(i + 20, true) === buffer.length - (i + 22)) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) {
    throw new ZipError("malformed", "no end-of-central-directory record found (not a ZIP archive?)");
  }

  const entryCount = view.getUint16(eocd + 10, true);
  const cdSize = view.getUint32(eocd + 12, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  if (entryCount === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new ZipError("zip64", "zip64 archives are not supported");
  }
  if (entryCount > ZIP_MAX_FILE_COUNT) {
    throw new ZipError("file-count", `archive contains ${entryCount} entries; limit is ${ZIP_MAX_FILE_COUNT}`);
  }
  if (cdOffset + cdSize > buffer.length) {
    throw new ZipError("malformed", "central directory extends past the end of the archive");
  }

  // Walk the central directory. Sizes and offsets are taken from here (authoritative even when a
  // writer used streaming data descriptors, general-purpose flag bit 3).
  const dec = new TextDecoder();
  const records = [];
  let pos = cdOffset;
  let totalUncompressed = 0;
  for (let i = 0; i < entryCount; i++) {
    if (pos + 46 > buffer.length || view.getUint32(pos, true) !== 0x02014b50) {
      throw new ZipError("malformed", `central directory record ${i} is malformed`);
    }
    const flags = view.getUint16(pos + 8, true);
    const method = view.getUint16(pos + 10, true);
    const compressedSize = view.getUint32(pos + 20, true);
    const uncompressedSize = view.getUint32(pos + 24, true);
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    const localOffset = view.getUint32(pos + 42, true);
    const name = dec.decode(buffer.subarray(pos + 46, pos + 46 + nameLen));
    pos += 46 + nameLen + extraLen + commentLen;

    if ((flags & 0x0001) !== 0) {
      throw new ZipError("encrypted", `entry ${name} is encrypted; encrypted archives are not supported`);
    }
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
      throw new ZipError("zip64", "zip64 archives are not supported");
    }
    if (name.endsWith("/")) continue; // directory record
    if (method !== 0 && method !== 8) {
      throw new ZipError("method", `entry ${name} uses unsupported compression method ${method}`);
    }
    if (records.some((r) => r.name === name)) {
      throw new ZipError("duplicate", `entry ${name} appears more than once in the archive`);
    }
    totalUncompressed += uncompressedSize;
    records.push({ name, method, compressedSize, uncompressedSize, localOffset });
  }

  if (totalUncompressed > ZIP_MAX_TOTAL_BYTES) {
    throw new ZipError("total-bytes", "declared uncompressed size exceeds the 50 MB cap");
  }

  const entries = new Map();
  for (const r of records) {
    if (r.localOffset + 30 > buffer.length || view.getUint32(r.localOffset, true) !== 0x04034b50) {
      throw new ZipError("malformed", `local header for ${r.name} is malformed`);
    }
    // Name and extra lengths in the LOCAL header can differ from the central directory's; the data
    // starts after the local copies.
    const localNameLen = view.getUint16(r.localOffset + 26, true);
    const localExtraLen = view.getUint16(r.localOffset + 28, true);
    const dataStart = r.localOffset + 30 + localNameLen + localExtraLen;
    if (dataStart + r.compressedSize > buffer.length) {
      throw new ZipError("malformed", `entry ${r.name} extends past the end of the archive`);
    }
    const raw = buffer.subarray(dataStart, dataStart + r.compressedSize);
    const data = r.method === 0 ? new Uint8Array(raw) : await inflateRaw(raw);
    if (data.length !== r.uncompressedSize) {
      throw new ZipError("malformed", `entry ${r.name} decompressed to ${data.length} bytes, expected ${r.uncompressedSize}`);
    }
    entries.set(r.name, data);
  }
  return entries;
}

/**
 * Verify an evidence-pack ZIP entirely offline:
 *   (a)  recompute every file's SHA-256 and compare it to the manifest,
 *   (a2) confirm every packed file except manifest.json is listed in the manifest,
 *   (b)  verify the manifest's Ed25519 signature over the reconstructed signed payload,
 *   (c)  verify each embedded checkpoint independently.
 * Throws ZipError when the container itself cannot be read; otherwise always returns a result.
 */
export async function verifyEvidencePackBytes(zipBytes, inflateRaw) {
  const fileBytes = await readZipEntries(zipBytes, inflateRaw);

  const invalid = (reason) => ({
    manifest: { status: "invalid", reason },
    files: [],
    checkpoints: [],
    overall: "invalid",
  });

  const manifestBytes = fileBytes.get("manifest.json");
  if (!manifestBytes) return invalid("manifest.json missing");

  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
  } catch (err) {
    return invalid(`manifest parse failed: ${err.message}`);
  }
  if (!Array.isArray(manifest.contents)) return invalid("manifest.contents is not an array");

  // (a) per-file SHA-256 against the manifest.
  const files = [];
  for (const entry of manifest.contents) {
    // A malformed content entry (missing/non-string filename or sha) is a tampered/garbage manifest, not
    // a crash: flag it invalid rather than throwing on entry.sha256Hex.toLowerCase().
    if (typeof entry?.filename !== "string" || typeof entry?.sha256Hex !== "string") {
      files.push({ path: String(entry?.filename ?? "(unnamed)"), status: "invalid", reason: "manifest content entry is malformed" });
      continue;
    }
    const bytes = fileBytes.get(entry.filename);
    if (!bytes) {
      files.push({ path: entry.filename, status: "missing", reason: "file not present in pack" });
      continue;
    }
    const actual = await sha256Hex(bytes);
    files.push(
      actual === entry.sha256Hex.toLowerCase()
        ? { path: entry.filename, status: "valid" }
        : { path: entry.filename, status: "invalid", reason: "SHA-256 does not match manifest" },
    );
  }

  // (a2) set-equality the other direction: every packed file (bar manifest.json, which carries the
  // hashes and is not listed in itself) must appear in manifest.contents. An entry absent from the
  // signed content list is an injected file.
  const listed = new Set(manifest.contents.map((c) => c.filename));
  for (const name of fileBytes.keys()) {
    if (name === "manifest.json" || listed.has(name)) continue;
    files.push({ path: name, status: "invalid", reason: "file present in pack but not listed in manifest.contents" });
  }

  // (b) manifest signature over the reconstructed canonical payload.
  let manifestResult;
  // The fingerprint is the SHA-256 of the key that verifies the signature, NOT the manifest's
  // self-declared publicKeyFingerprint (unsigned metadata a forged pack could set to any value). Trust
  // comparisons must anchor on the computed value.
  let manifestFingerprint;
  try {
    const payload = buildEvidencePackSignedPayload(
      manifest.tenantId,
      manifest.manifestVersion,
      manifest.generatedAt,
      manifest.windowFrom ?? "",
      manifest.windowTo ?? "",
      manifest.truncated,
      manifest.checkpointsTruncated,
      manifest.contents,
    );
    const signature = hexToBytes(manifest.signatureHex);
    const publicKey = base64ToBytes(manifest.publicKeyBase64);
    manifestFingerprint = await sha256Hex(publicKey);
    manifestResult = await verifyEd25519(payload, signature, publicKey, "manifest signature does not match the pack contents");
  } catch (err) {
    manifestResult = { status: "invalid", reason: `manifest verification failed: ${err.message}` };
  }

  // (c) embedded checkpoints, each verified independently.
  const checkpoints = [];
  for (const [name, bytes] of fileBytes) {
    if (!name.startsWith("checkpoints/") || !name.endsWith(".json")) continue;
    try {
      const bundle = validateCheckpointBundle(JSON.parse(new TextDecoder().decode(bytes)));
      // Fingerprint from the checkpoint's own public key, not its self-declared field (same reason as
      // the manifest key above). Undefined if the key cannot be decoded (a fingerprint check fails closed).
      let checkpointFingerprint;
      try {
        checkpointFingerprint = await sha256Hex(base64ToBytes(bundle.publicKeyBase64));
      } catch {
        checkpointFingerprint = undefined;
      }
      checkpoints.push({
        checkpointId: bundle.checkpointId,
        publicKeyFingerprint: checkpointFingerprint,
        result: await verifyCheckpointBundle(bundle),
      });
    } catch (err) {
      checkpoints.push({
        checkpointId: name,
        publicKeyFingerprint: undefined,
        result: { status: "invalid", reason: `checkpoint parse failed: ${err.message}` },
      });
    }
  }

  const anyUnsupported =
    manifestResult.status === "unsupported" || checkpoints.some((c) => c.result.status === "unsupported");
  const anyInvalid =
    manifestResult.status === "invalid"
    || files.some((f) => f.status !== "valid")
    || checkpoints.some((c) => c.result.status === "invalid");

  return {
    manifest: manifestResult,
    files,
    checkpoints,
    overall: anyUnsupported ? "unsupported" : anyInvalid ? "invalid" : "valid",
    publicKeyFingerprint: manifestFingerprint,
    truncated: manifest.truncated,
    checkpointsTruncated: manifest.checkpointsTruncated,
    identity: {
      tenantId: manifest.tenantId,
      generatedAt: manifest.generatedAt,
      windowFrom: manifest.windowFrom ?? null,
      windowTo: manifest.windowTo ?? null,
    },
  };
}

// ================================================================================================
// VERIFIER-CORE-END
// ================================================================================================

function usage() {
  return [
    "Usage: node mandate-verify.mjs <pack.zip> [--expect-fingerprint <hex>] [--json] [--version]",
    "",
    "Verifies a Mandate evidence pack offline. Exit codes:",
    "  0 valid   1 invalid or fingerprint mismatch   2 usage/IO/ZIP error   3 no Ed25519 support",
  ].join("\n");
}

async function main(argv) {
  let packPath = null;
  let expectFingerprint = null;
  let asJson = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--json") {
      asJson = true;
    } else if (arg === "--version") {
      console.log(`mandate-verify ${TOOL_VERSION} (payloads: ${EVIDENCE_PACK_SIGNED_PAYLOAD_DOMAIN_V2}, ${CHECKPOINT_SIGNED_PAYLOAD_DOMAIN_V1})`);
      return 0;
    } else if (arg === "--expect-fingerprint") {
      expectFingerprint = argv[++i];
      if (!expectFingerprint) {
        console.error("--expect-fingerprint requires a value\n\n" + usage());
        return 2;
      }
    } else if (arg === "--help" || arg === "-h") {
      console.log(usage());
      return 0;
    } else if (arg.startsWith("--")) {
      console.error(`unknown option: ${arg}\n\n` + usage());
      return 2;
    } else if (packPath === null) {
      packPath = arg;
    } else {
      console.error("only one pack path may be given\n\n" + usage());
      return 2;
    }
  }

  if (!packPath) {
    console.error(usage());
    return 2;
  }

  let bytes;
  try {
    bytes = new Uint8Array(await readFile(packPath));
  } catch (err) {
    console.error(`cannot read ${packPath}: ${err.message}`);
    return 2;
  }

  const inflateRaw = async (raw) => {
    try {
      return new Uint8Array(inflateRawSync(raw));
    } catch (err) {
      throw new ZipError("deflate", `a compressed entry is corrupt and cannot be decompressed: ${err.message}`);
    }
  };

  let result;
  try {
    result = await verifyEvidencePackBytes(bytes, inflateRaw);
  } catch (err) {
    // Any failure to read/interpret the file (a bad ZIP container, or an unexpected error) is a
    // usage/IO problem, not an invalid-but-readable pack: exit 2 with a message, never a stack trace.
    const detail = err instanceof ZipError ? err.message : `unexpected error: ${err.message}`;
    console.error(`cannot read ${packPath} as an evidence pack: ${detail}`);
    return 2;
  }

  // Fingerprint expectation: applies to the manifest key and every embedded checkpoint key.
  const expected = expectFingerprint ? expectFingerprint.toLowerCase() : null;
  const fingerprintMismatches = [];
  if (expected) {
    if ((result.publicKeyFingerprint ?? "").toLowerCase() !== expected) {
      fingerprintMismatches.push(`manifest key is ${result.publicKeyFingerprint ?? "(none)"}`);
    }
    for (const c of result.checkpoints) {
      if ((c.publicKeyFingerprint ?? "").toLowerCase() !== expected) {
        fingerprintMismatches.push(`checkpoint ${c.checkpointId} key is ${c.publicKeyFingerprint ?? "(none)"}`);
      }
    }
  }

  if (asJson) {
    console.log(JSON.stringify({ pack: packPath, expectedFingerprint: expected, fingerprintMismatches, ...result }, null, 2));
  } else {
    const flag = (b) => (b ? "yes" : "no");
    console.log(`Pack           : ${packPath}`);
    if (result.identity) {
      console.log(`Tenant         : ${result.identity.tenantId}`);
      console.log(`Generated at   : ${result.identity.generatedAt}`);
      console.log(`Window         : ${result.identity.windowFrom ?? "(open)"} .. ${result.identity.windowTo ?? "(open)"}`);
    }
    if (result.truncated !== undefined) {
      console.log(`Truncated      : register ${flag(result.truncated)}, checkpoints ${flag(result.checkpointsTruncated)}`);
    }
    if (result.publicKeyFingerprint) {
      console.log(`Signing key    : ${result.publicKeyFingerprint}`);
      console.log("                 Compare this fingerprint to one you trust before relying on the result.");
    }
    console.log("");
    console.log("Files:");
    for (const f of result.files) {
      const tag = f.status === "valid" ? "[ ok ]" : f.status === "missing" ? "[MISS]" : "[FAIL]";
      console.log(`  ${tag} ${f.path}${f.reason ? `  (${f.reason})` : ""}`);
    }
    console.log("");
    const m = result.manifest;
    console.log(`Manifest signature: ${m.status === "valid" ? "ok" : `${m.status.toUpperCase()} (${m.reason})`}`);
    console.log("");
    console.log(`Checkpoints (${result.checkpoints.length}):`);
    for (const c of result.checkpoints) {
      const tag = c.result.status === "valid" ? "[ ok ]" : c.result.status === "unsupported" ? "[ ?? ]" : "[FAIL]";
      const key = c.publicKeyFingerprint ? `  key ${c.publicKeyFingerprint.slice(0, 12)}..` : "";
      console.log(`  ${tag} ${c.checkpointId}${key}${c.result.reason ? `  (${c.result.reason})` : ""}`);
    }
    for (const mm of fingerprintMismatches) {
      console.log(`  [FAIL] fingerprint expectation: ${mm}`);
    }
    console.log("");
  }

  if (result.overall === "unsupported") {
    if (!asJson) console.log("RESULT: UNSUPPORTED (this runtime lacks WebCrypto Ed25519; use Node 20 or newer)");
    return 3;
  }
  const failed = result.overall === "invalid" || fingerprintMismatches.length > 0;
  if (!asJson) console.log(`RESULT: ${failed ? "INVALID" : "VALID"}`);
  return failed ? 1 : 0;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  process.exitCode = await main(process.argv.slice(2));
}
