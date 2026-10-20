#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Mandate Systems Inc.

import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { inflateRawSync } from "node:zlib";
import { pathToFileURL } from "node:url";

const TOOL_VERSION = "2.5.0";

const VERIFIER_CORE_BEGIN = "VERIFIER-CORE-BEGIN v2";

export const CHECKPOINT_SIGNED_PAYLOAD_DOMAIN_V1 = "mandate.audit.checkpoint-sig.v1";

export const EVIDENCE_PACK_SIGNED_PAYLOAD_DOMAIN_V3 = "mandate.evidence-pack.manifest-sig.v3";

export const ZIP_MAX_TOTAL_BYTES = 52428800;
export const ZIP_MAX_FILE_COUNT = 1032;

export class ZipError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ZipError";
    this.code = code;
  }
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length");

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

export function buildEvidencePackSignedPayload(tenantId, manifestVersion, generatedAt, windowFrom, windowTo, truncated, checkpointsTruncated, mutationsTruncated, contents) {
  const sorted = [...contents].sort((a, b) => (a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0));
  const enc = new TextEncoder();
  const parts = [];

  const pushU32 = (label, n) => {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`invalid ${label}: ${n}`);
    parts.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  };
  const pushU64 = (n) => {
    for (let shift = 56n; shift >= 0n; shift -= 8n) parts.push(Number((n >> shift) & 0xffn));
  };
  const pushBytes = (b) => {
    for (const x of b) parts.push(x);
  };

  const pushTimestampMs = (label, value) => {
    if (!STRICT_ISO_TIMESTAMP.test(String(value))) throw new Error(`invalid ${label}: ${value} is not an ISO 8601 timestamp`);
    const ms = Date.parse(value);
    if (Number.isNaN(ms)) throw new Error(`invalid ${label}: ${value}`);
    pushU64(BigInt(ms));
  };

  pushBytes(enc.encode(EVIDENCE_PACK_SIGNED_PAYLOAD_DOMAIN_V3));
  pushBytes(uuidToRfc4122Bytes(tenantId));
  pushU32("manifestVersion", manifestVersion);

  pushTimestampMs("generatedAt", generatedAt);
  pushTimestampMs("windowFrom", windowFrom);
  pushTimestampMs("windowTo", windowTo);

  parts.push(truncated ? 1 : 0);
  parts.push(checkpointsTruncated ? 1 : 0);
  parts.push(mutationsTruncated ? 1 : 0);

  pushU32("contents count", sorted.length);
  for (const c of sorted) {
    const nameBytes = enc.encode(c.filename);
    pushU32(`content ${c.filename} filename length`, nameBytes.length);
    pushBytes(nameBytes);
    const sha = hexToBytes(c.sha256Hex);
    if (sha.length !== 32) throw new Error(`content ${c.filename} sha256 must be 32 bytes`);
    pushBytes(sha);
    pushU64(BigInt(c.byteLength));
  }

  return new Uint8Array(parts);
}

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

export async function readZipEntries(buffer, inflateRaw) {
  if (buffer.length > ZIP_MAX_TOTAL_BYTES) {
    throw new ZipError("too-large", "archive exceeds the 50 MB size cap");
  }
  if (buffer.length < 22) {
    throw new ZipError("malformed", "file is too small to be a ZIP archive");
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let eocd = -1;
  const scanFloor = Math.max(0, buffer.length - 65557);
  for (let i = buffer.length - 22; i >= scanFloor; i--) {

    if (buffer[i] === 0x50 && buffer[i + 1] === 0x4b && buffer[i + 2] === 0x05 && buffer[i + 3] === 0x06
        && view.getUint16(i + 20, true) === buffer.length - (i + 22)) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) {
    throw new ZipError("malformed", "no end-of-central-directory record found (not a ZIP archive?)");
  }

  if (view.getUint16(eocd + 20, true) !== 0) {
    throw new ZipError("comment", "the archive carries a comment, which a Mandate record never does");
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
  if (cdOffset + cdSize !== eocd) {
    throw new ZipError("gap", "the archive holds bytes that no listed file accounts for");
  }

  const dec = new TextDecoder();
  const records = [];
  const spans = [];
  let pos = cdOffset;
  let totalUncompressed = 0;
  for (let i = 0; i < entryCount; i++) {
    if (pos + 46 > buffer.length || view.getUint32(pos, true) !== 0x02014b50) {
      throw new ZipError("malformed", `central directory record ${i} is malformed`);
    }
    const flags = view.getUint16(pos + 8, true);
    const method = view.getUint16(pos + 10, true);
    const crc = view.getUint32(pos + 16, true);
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
    if (commentLen !== 0) {
      throw new ZipError("comment", `entry ${name} carries a comment, which a Mandate record never does`);
    }
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
      throw new ZipError("zip64", "zip64 archives are not supported");
    }
    spans.push({ localOffset, compressedSize, flags, name });
    if (name.endsWith("/")) {
      if (compressedSize !== 0 || uncompressedSize !== 0) {
        throw new ZipError("folder", `the folder entry ${name} holds data, which a Mandate record never does`);
      }
      continue;
    }
    if (method !== 0 && method !== 8) {
      throw new ZipError("method", `entry ${name} uses unsupported compression method ${method}`);
    }
    if (records.some((r) => r.name === name)) {
      throw new ZipError("duplicate", `entry ${name} appears more than once in the archive`);
    }
    totalUncompressed += uncompressedSize;
    records.push({ name, method, compressedSize, uncompressedSize, localOffset, crc });
  }

  if (totalUncompressed > ZIP_MAX_TOTAL_BYTES) {
    throw new ZipError("total-bytes", "declared uncompressed size exceeds the 50 MB cap");
  }

  const entries = new Map();
  for (const r of records) {
    if (r.localOffset + 30 > buffer.length || view.getUint32(r.localOffset, true) !== 0x04034b50) {
      throw new ZipError("malformed", `local header for ${r.name} is malformed`);
    }

    const localNameLen = view.getUint16(r.localOffset + 26, true);
    const localExtraLen = view.getUint16(r.localOffset + 28, true);
    if (dec.decode(buffer.subarray(r.localOffset + 30, r.localOffset + 30 + localNameLen)) !== r.name) {
      throw new ZipError("name", `entry ${r.name} has a different name in its local header, so unzip tools would disagree on its name`);
    }
    const dataStart = r.localOffset + 30 + localNameLen + localExtraLen;
    if (dataStart + r.compressedSize > buffer.length) {
      throw new ZipError("malformed", `entry ${r.name} extends past the end of the archive`);
    }
    const raw = buffer.subarray(dataStart, dataStart + r.compressedSize);
    const data = r.method === 0 ? new Uint8Array(raw) : await inflateRaw(raw, r.uncompressedSize);
    if (data.length !== r.uncompressedSize) {
      throw new ZipError("malformed", `entry ${r.name} decompressed to ${data.length} bytes, expected ${r.uncompressedSize}`);
    }
    if (crc32(data) !== r.crc) {
      throw new ZipError("crc", `entry ${r.name} does not match its CRC-32, so unzip tools would refuse it`);
    }
    entries.set(r.name, data);
  }
  let cursor = 0;
  for (const s of spans.sort((a, b) => a.localOffset - b.localOffset)) {
    if (s.localOffset !== cursor || s.localOffset + 30 > buffer.length || view.getUint32(s.localOffset, true) !== 0x04034b50) {
      throw new ZipError("gap", "the archive holds bytes that no listed file accounts for");
    }
    const localNameLength = view.getUint16(s.localOffset + 26, true);
    if (dec.decode(buffer.subarray(s.localOffset + 30, s.localOffset + 30 + localNameLength)) !== s.name) {
      throw new ZipError("name", `entry ${s.name} has a different name in its local header, so unzip tools would disagree on its name`);
    }
    cursor = s.localOffset + 30 + view.getUint16(s.localOffset + 26, true) + view.getUint16(s.localOffset + 28, true) + s.compressedSize;
    if ((s.flags & 0x0008) !== 0) cursor += cursor + 4 <= buffer.length && view.getUint32(cursor, true) === 0x08074b50 ? 16 : 12;
  }
  if (cursor !== cdOffset) {
    throw new ZipError("gap", "the archive holds bytes that no listed file accounts for");
  }
  return entries;
}

export const SUPPORTED_MANIFEST_VERSION = 3;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const STRICT_ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

const CANONICAL_FIELDS = (() => {
  const v1 = [
    ["chain_prev_hash", false], ["connector", false], ["correlation_id", false], ["id", false], ["model", false],
    ["occurred_at", false], ["policy_decision", false], ["policy_version_id", true], ["provider", false],
    ["request_body_hash", false], ["request_body_hash_outbound", true], ["rule_hits", false], ["tenant_id", false],
  ];
  const after = (list, name, items) => {
    const i = list.findIndex((f) => f[0] === name);
    return [...list.slice(0, i + 1), ...items, ...list.slice(i + 1)];
  };
  const optional = (list, ...names) => list.map((f) => (names.includes(f[0]) ? [f[0], true] : f));
  const v2 = [["agent_action", true], ["agent_id", true], ["agent_principal_id", true], ...v1];
  const v3 = after(v2, "request_body_hash_outbound", [["response_body_hash", true]]);
  const v4 = after(v3, "provider", [["purpose_slug", false], ["purpose_source", false]]);
  const v5 = optional(after(v4, "id", [["mandate_slug", false]]), "purpose_slug", "purpose_source");
  const v6 = [...optional(v5, "mandate_slug"), ["upstream_id", false]];
  const v7 = optional(after(v6, "rule_hits", [["subject_hash", false]]), "upstream_id");
  const v8 = optional(after(v7, "policy_version_id", [["policy_version_sha256", false]]), "subject_hash");
  const required = (list, ...names) => list.map((f) => (names.includes(f[0]) ? [f[0], false] : f));
  const v9 = required(optional(after(v8, "occurred_at", [["person_seal", false]]), "policy_version_sha256"), "subject_hash");
  return { 1: v1, 2: v2, 3: v3, 4: v4, 5: v5, 6: v6, 7: v7, 8: v8, 9: v9 };
})();

export function decodeCanonicalRecord(bytes) {
  const fields = CANONICAL_FIELDS[bytes[0]];
  if (!fields || bytes[1] !== 0) throw new Error(`record layout ${bytes[0]} is not one this verifier reads`);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 2;
  const take = () => {
    if (at + 4 > bytes.length) throw new Error("record ends early");
    const length = view.getUint32(at);
    at += 4;
    if (at + length > bytes.length) throw new Error("record ends early");
    const value = bytes.subarray(at, at + length);
    at += length;
    return value;
  };
  const record = { version: bytes[0] };
  for (const [name, isOptional] of fields) {
    if (isOptional) {
      const flag = bytes[at++];
      if (flag === 0xff) {
        if (take().length !== 0) throw new Error(`record field ${name} is malformed`);
        record[name] = null;
        continue;
      }
      if (flag !== 0x00) throw new Error(`record field ${name} is malformed`);
    }
    record[name] = take();
  }
  if (at !== bytes.length) throw new Error("record has trailing bytes");
  return record;
}

const RECORD_TEXT = new TextDecoder("utf-8", { fatal: true });

export function recordText(value) {
  return value === null || value === undefined ? null : RECORD_TEXT.decode(value);
}

export function recordUuid(value) {
  if (value === null || value === undefined) return null;
  const h = bytesToHex(value);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export async function sha256Bytes(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export async function merkleRoot(recordHashes) {
  if (recordHashes.length === 0) return new Uint8Array(32);
  let level = [];
  for (const h of recordHashes) level.push(await sha256Bytes(concatBytes(Uint8Array.of(0), h)));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(await sha256Bytes(concatBytes(Uint8Array.of(1), level[i], level[i + 1] ?? level[i])));
    }
    level = next;
  }
  return level[0];
}

const UTF8 = new TextEncoder();

export async function nameSeal(saltHex, name) {
  return sha256Bytes(concatBytes(UTF8.encode("mandate.name-seal.v1"), Uint8Array.of(0), hexToBytes(saltHex), UTF8.encode(name)));
}

function sealField(bytes) {
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, bytes.length);
  return concatBytes(length, bytes);
}

export async function listSeal(saltHex, names) {
  return sha256Bytes(concatBytes(UTF8.encode("mandate.list-seal.v1"), Uint8Array.of(0), hexToBytes(saltHex), ...names.map((n) => sealField(UTF8.encode(n)))));
}

function sealOptional(bytes) {
  return bytes === null ? concatBytes(Uint8Array.of(0xff), sealField(new Uint8Array(0))) : concatBytes(Uint8Array.of(0), sealField(bytes));
}

export async function changeTrailEntrySeal(row, tenantId) {
  const text = (v) => (v === null || v === undefined ? null : UTF8.encode(String(v)));
  const uuid = (v) => (v === null || v === undefined ? null : uuidToRfc4122Bytes(String(v)));
  const ticks = instantTicks(row.occurredAt);
  if (ticks === null || typeof row.action !== "string" || typeof row.actorType !== "string") throw new Error("it is malformed");
  const time = new Uint8Array(8);
  new DataView(time.buffer).setBigInt64(0, ticks);
  if (row.actorDisplay != null && typeof row.actorSalt !== "string") throw new Error("it names who acted without the salt that seals the name");
  const actorSeal = row.actorDisplay == null ? null : await nameSeal(row.actorSalt, String(row.actorDisplay));
  const t = row.transition ?? null;
  return sha256Bytes(concatBytes(
    UTF8.encode("mandate.change-trail-entry.v1"), Uint8Array.of(0),
    sealField(uuidToRfc4122Bytes(String(row.id))), sealField(uuidToRfc4122Bytes(String(tenantId))), sealField(time),
    sealField(UTF8.encode(row.action)), sealField(UTF8.encode(row.actorType)),
    sealOptional(uuid(row.actorId)), sealOptional(actorSeal), sealOptional(text(row.mutationReason)),
    sealOptional(text(t?.kind)), sealOptional(text(t?.reason)), sealOptional(uuid(t?.policyId)),
    sealOptional(uuid(t?.versionId)), sealOptional(uuid(t?.priorVersionId)), sealOptional(text(t?.version))));
}

const ERASURE_REASONS = (action) => (action === "dsr.delete" ? "privacy request" : String(action).startsWith("retention.") ? "retention" : null);

function sameBytes(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function sameInstant(recordValue, rowValue) {
  const micros = (text) => {
    const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]00:00)$/.exec(String(text));
    return m ? `${m[1]}.${(m[2] ?? "").padEnd(7, "0").slice(0, 6)}` : null;
  };
  const a = micros(recordValue);
  const b = micros(rowValue);
  return a !== null && b !== null ? a === b : Date.parse(recordValue) === Date.parse(rowValue);
}

function instantTicks(text) {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/.exec(String(text));
  const ms = m ? Date.parse(`${m[1]}${m[3]}`) : Number.NaN;
  return Number.isNaN(ms) ? null : BigInt(ms) * 10000n + BigInt((m[2] ?? "").padEnd(7, "0").slice(0, 7));
}

function sameWorkspace(a, b) {
  try {
    return bytesToHex(uuidToRfc4122Bytes(String(a))) === bytesToHex(uuidToRfc4122Bytes(String(b)));
  } catch {
    return false;
  }
}

function recordRules(record) {
  const hits = JSON.parse(recordText(record.rule_hits));
  return Array.isArray(hits)
    ? hits.filter((h) => h && typeof h.ruleId === "string" && h.detectorType !== "policy")
      .map((h) => `${h.ruleId}|${h.detectorType ?? ""}|${h.action ?? ""}`)
    : [];
}

export async function verifyChainFiles(fileBytes, expect = {}) {
  try {
    return await walkChainFiles(fileBytes, expect);
  } catch (err) {
    return { status: "invalid", reason: `the records could not be read: ${err.message}` };
  }
}

async function walkChainFiles(fileBytes, expect) {
  const invalid = (reason) => ({ status: "invalid", reason });
  const read = (name) => {
    const bytes = fileBytes.get(name);
    return bytes ? JSON.parse(RECORD_TEXT.decode(bytes)) : null;
  };
  let chain;
  try {
    chain = read("chain/links.json");
  } catch (err) {
    return invalid(`chain/links.json parse failed: ${err.message}`);
  }
  if (!chain || !Array.isArray(chain.links)) return invalid("chain/links.json is missing or malformed");

  if (chain.truncated === true && expect.registerPartial !== true) {
    return invalid("chain/links.json says it holds part of its period, but the signed manifest says the export is complete");
  }

  const links = [];
  const byId = new Map();
  let deleted = 0;
  for (const link of chain.links) {
    const id = String(link?.id ?? "").toLowerCase();
    let hash;
    let record = null;
    let at = null;
    let erasedBy = null;
    try {
      if (typeof link.record === "string") {
        const bytes = base64ToBytes(link.record);
        hash = await sha256Bytes(bytes);
        record = decodeCanonicalRecord(bytes);
        if (recordUuid(record.id) !== id) return invalid(`record ${id} carries a different id`);
        if (expect.tenantId !== undefined && !sameWorkspace(recordUuid(record.tenant_id), expect.tenantId)) {
          return invalid(`record ${id} names workspace ${recordUuid(record.tenant_id)}, not this export's workspace ${expect.tenantId}`);
        }
        at = instantTicks(recordText(record.occurred_at));
      } else if (typeof link.deletedRecordSha256 === "string" && link.deletedRecordSha256.length === 64) {
        hash = hexToBytes(link.deletedRecordSha256);
        at = instantTicks(link.occurredAt);
        erasedBy = typeof link.erasedBy === "string" ? link.erasedBy.toLowerCase() : null;
        deleted++;
      } else {
        return invalid(`link ${id} has neither a record nor a removed record's hash`);
      }
    } catch (err) {
      return invalid(`record ${id}: ${err.message}`);
    }
    if (record && links.length > 0 && !sameBytes(record.chain_prev_hash, links[links.length - 1].hash)) {
      return invalid(`record ${id} does not follow the record before it`);
    }
    byId.set(id, links.length);
    links.push({ id, hash, record, at, erasedBy });
  }

  let recomputed = 0;
  let notCovered = 0;
  for (const [name, bytes] of fileBytes) {
    if (!name.startsWith("checkpoints/") || !name.endsWith(".json")) continue;
    const checkpoint = JSON.parse(RECORD_TEXT.decode(bytes));
    const start = byId.get(String(checkpoint.windowStartEventId).toLowerCase());
    const end = byId.get(String(checkpoint.windowEndEventId).toLowerCase());
    if (start === undefined || end === undefined || end < start) {
      if (chain.truncated === true) {
        notCovered++;
        continue;
      }
      return invalid(`checkpoint ${checkpoint.checkpointId}: its records are not in chain/links.json`);
    }
    const leaves = links.slice(start, end + 1).map((l) => l.hash);
    if (leaves.length !== checkpoint.eventCount) {
      return invalid(`checkpoint ${checkpoint.checkpointId} seals ${checkpoint.eventCount} records, chain/links.json holds ${leaves.length} in its window`);
    }
    if (bytesToHex(await merkleRoot(leaves)) !== String(checkpoint.merkleRootHex).toLowerCase()) {
      return invalid(`checkpoint ${checkpoint.checkpointId}: its records no longer reproduce its signed root`);
    }
    recomputed++;
  }

  const versionHash = new Map();
  const versionText = new Map();
  for (const version of read("policy/versions.json") ?? []) {
    if (typeof version.yamlSource !== "string" || typeof version.contentSha256 !== "string") {
      return invalid(`policy version ${version.id} carries no text or no hash`);
    }
    const actual = bytesToHex(await sha256Bytes(new TextEncoder().encode(version.yamlSource)));
    if (actual !== version.contentSha256.toLowerCase()) return invalid(`policy version ${version.id}: its text does not match its hash`);
    versionHash.set(String(version.id).toLowerCase(), actual);
    versionText.set(String(version.id).toLowerCase(), version.yamlSource);
  }

  let listsSealed = 0;
  let listsChecked = 0;
  const lists = read("policy/lists.json");
  if (lists !== null) {
    if (!lists || !Array.isArray(lists.lists)) return invalid("policy/lists.json is malformed");
    for (const list of lists.lists) {
      const seal = typeof list?.sealed === "string" ? list.sealed.toLowerCase() : "";
      if (!/^[0-9a-f]{64}$/.test(seal)) return invalid("policy/lists.json: a list carries no seal");
      if (!(versionText.get(String(list.versionId).toLowerCase()) ?? "").includes(`sealed: ${seal}`)) {
        return invalid(`policy version ${list.versionId}: the seal of rule ${list.ruleId} is not in its text`);
      }
      listsSealed++;
      if (list.keywords === undefined && list.salt === undefined) {
        if (lists.namesIncluded === true) return invalid(`policy/lists.json says it includes the names, but rule ${list.ruleId} carries none`);
        continue;
      }
      if (!Array.isArray(list.keywords) || list.keywords.some((k) => typeof k !== "string") || !/^[0-9a-fA-F]{32}$/.test(String(list.salt))) {
        return invalid(`policy/lists.json: the names or salt of rule ${list.ruleId} are malformed`);
      }
      if (bytesToHex(await listSeal(list.salt, list.keywords)) !== seal) {
        return invalid(`policy version ${list.versionId}: the names of rule ${list.ruleId} do not match their seal`);
      }
      listsChecked++;
    }
  }
  for (const link of links) {
    if (!link.record || !link.record.policy_version_sha256) continue;
    const expected = versionHash.get(recordUuid(link.record.policy_version_id));
    if (expected !== undefined && expected !== bytesToHex(link.record.policy_version_sha256)) {
      return invalid(`record ${link.id} was decided under policy text that no longer matches its version`);
    }
  }

  let tied = 0;
  let notTied = 0;
  let peopleTied = 0;
  for (const row of read("register/decisions.json") ?? []) {
    if (row.source !== "decision") continue;
    if (typeof row.recordSha256 !== "string") {
      notTied++;
      continue;
    }
    const at = byId.get(String(row.id).toLowerCase());
    const link = at === undefined ? undefined : links[at];
    if (!link || !link.record || bytesToHex(link.hash) !== row.recordSha256.toLowerCase()) {
      return invalid(`decision ${row.id} does not match a record in chain/links.json`);
    }
    const r = link.record;
    const rows = (row.rules ?? []).map((h) => `${h.ruleId}|${h.detectorType ?? ""}|${h.action ?? ""}`).sort();
    let personSame = r.person_seal ? false : row.person === undefined || row.person === null;
    if (r.person_seal && typeof row.person === "string" && typeof row.personSalt === "string" && /^[0-9a-fA-F]{32}$/.test(row.personSalt)) {
      personSame = sameBytes(await nameSeal(row.personSalt, row.person), r.person_seal);
    }
    if (r.person_seal && personSame) peopleTied++;
    const lower = (v) => (v === null || v === undefined ? null : String(v).toLowerCase());
    const mismatched = [
      ["outcome", recordText(r.policy_decision) === row.action],
      ["provider", recordText(r.provider) === (row.provider ?? "")],
      ["model", recordText(r.model) === (row.model ?? "")],
      ["policy version", recordUuid(r.policy_version_id) === lower(row.policyVersionId)],
      ["time", sameInstant(recordText(r.occurred_at), row.occurredAt)],
      ["rules", JSON.stringify([...new Set(recordRules(r))].sort()) === JSON.stringify([...new Set(rows)])],
      ["correlation id", recordUuid(r.correlation_id) === lower(row.correlationId)],
      ["agent", recordUuid(r.agent_id) === lower(row.actorId) && (r.agent_id ? "agent" : "system") === row.actorType],
      ["purpose", recordText(r.purpose_slug) === (row.purpose ?? null) && recordText(r.purpose_source) === (row.purposeSource ?? null)],
      ["mandate", recordText(r.mandate_slug) === (row.mandateSlug ?? null)],
      ["person", personSame],
    ].filter(([, same]) => !same).map(([field]) => field);
    if (mismatched.length > 0) return invalid(`decision ${row.id}: the readable row differs from its record: its ${mismatched.join(", ")}`);
    tied++;
  }

  const changeRecords = new Map();
  for (const l of links) {
    if (l.record && recordText(l.record.policy_decision) === "change") changeRecords.set(recordUuid(l.record.correlation_id), l.record);
  }
  const erasureFile = read("chain/erasures.json");
  const erasureEntries = Array.isArray(erasureFile?.entries) ? erasureFile.entries : [];
  const changeSources = [
    ["mutations/policy-trail.json", read("mutations/policy-trail.json")],
    ["register/decisions.json", (read("register/decisions.json") ?? []).filter((row) => row?.source === "mutation")],
    ["chain/erasures.json", erasureEntries],
  ];
  const changesTiedIds = new Set();
  const changesNotTiedIds = new Set();
  for (const [file, list] of changeSources) {
    for (const row of Array.isArray(list) ? list : []) {
      if (!row || typeof row.id !== "string") return invalid(`${file} holds a change-trail entry with no id`);
      const id = row.id.toLowerCase();
      const sealed = changeRecords.get(id);
      if (!sealed) {
        changesNotTiedIds.add(id);
        continue;
      }
      let digest;
      try {
        digest = await changeTrailEntrySeal(row, expect.tenantId);
      } catch (err) {
        return invalid(`change-trail entry ${row.id} in ${file} cannot be checked: ${err.message}`);
      }
      if (!sameBytes(digest, sealed.request_body_hash)) {
        return invalid(`change-trail entry ${row.id} (${row.action}) in ${file} differs from its sealed record`);
      }
      changesTiedIds.add(id);
    }
  }
  for (const id of changesTiedIds) changesNotTiedIds.delete(id);

  const erasureById = new Map(erasureEntries.filter((e) => e && typeof e.id === "string").map((e) => [e.id.toLowerCase(), e]));
  const erasures = new Map();
  for (const l of links) {
    if (l.record) continue;
    if (!l.erasedBy) return invalid(`record ${l.id} was removed, and no entry records its erasure`);
    const entry = erasureById.get(l.erasedBy);
    if (!entry) return invalid(`record ${l.id} names erasure entry ${l.erasedBy}, which chain/erasures.json does not carry`);
    const reason = ERASURE_REASONS(entry.action);
    if (!reason) return invalid(`record ${l.id} names entry ${l.erasedBy} (${entry.action}), which records no erasure`);
    if (instantTicks(entry.occurredAt) === null) return invalid(`erasure entry ${l.erasedBy} has no readable time`);
    const e = erasures.get(l.erasedBy) ?? { id: l.erasedBy, reason, at: entry.occurredAt, removed: 0, removedInPeriod: 0 };
    e.removed++;
    erasures.set(l.erasedBy, e);
  }

  let reportTied = false;
  const report = fileBytes.get("report/report.pdf");
  if (report) {
    const named = /\/Keywords \(mandate-summary-sha256:([0-9a-f]{64})\)/.exec(new TextDecoder("latin1").decode(report));
    if (!named) return invalid("report/report.pdf does not name the summary it was drawn from");
    const summaryBytes = fileBytes.get("report/summary.json");
    if (!summaryBytes || bytesToHex(await sha256Bytes(summaryBytes)) !== named[1]) {
      return invalid("report/report.pdf was not drawn from report/summary.json: it names another summary");
    }
    reportTied = true;
  }

  let summaryCompared = false;
  let summaryNotCompared = "";
  if (chain.truncated === true) summaryNotCompared = "the records file is partial";
  else if (expect.registerPartial === true) summaryNotCompared = "the register is partial";
  if (!summaryNotCompared) {
    const counted = new Map();
    for (const row of read("register/decisions.json") ?? []) {
      if (row.source === "decision") counted.set(row.action, (counted.get(row.action) ?? 0) + 1);
    }
    const differs = (list) => list.some((x) => (counted.get(x.decision) ?? 0) !== x.count)
      || [...counted].some(([action, n]) => !list.some((x) => x.decision === action && x.count === n));
    for (const [name, pick] of [["report/summary.json", (s) => s?.decisions?.byOutcome], ["summary/decision-mix.json", (s) => s?.decisions]]) {
      const list = pick(read(name));
      if (!Array.isArray(list)) continue;
      if (differs(list)) return invalid(`${name}: its counts do not match the decisions in register/decisions.json`);
      summaryCompared = true;
    }
  }

  const periodFrom = instantTicks(expect.windowFrom);
  const periodTo = instantTicks(expect.windowTo);
  const inPeriod = (t) => periodFrom === null || periodTo === null || (t !== null && t >= periodFrom && t <= periodTo);
  for (const l of links) if (!l.record && inPeriod(l.at)) erasures.get(l.erasedBy).removedInPeriod++;
  const kinds = { decisions: 0, answers: 0, imported: 0, changes: 0 };
  const outcomes = {};
  for (const l of links) {
    if (!l.record) continue;
    const outcome = recordText(l.record.policy_decision);
    if (outcome === "result") kinds.answers++;
    else if (outcome === "imported") kinds.imported++;
    else if (outcome === "change") kinds.changes++;
    else kinds.decisions++;
  }
  for (const row of read("register/decisions.json") ?? []) {
    if (row?.source === "decision") outcomes[row.action] = (outcomes[row.action] ?? 0) + 1;
  }
  const result = {
    status: "valid",
    records: links.length - deleted,
    removed: deleted,
    removedInPeriod: periodFrom === null || periodTo === null
      ? deleted
      : links.filter((l) => !l.record && l.at !== null && l.at >= periodFrom && l.at <= periodTo).length,
    checkpointsRecomputed: recomputed,
    checkpointsNotCovered: notCovered,
    decisionsTied: tied,
    decisionsNotTied: notTied,
    peopleTied,
    changesTied: changesTiedIds.size,
    changesNotTied: changesNotTiedIds.size,
    erasures: [...erasures.values()],
    reportTied,
    kinds,
    outcomes,
    policyVersions: versionHash.size,
    listsSealed,
    listsChecked,
    summaryCompared,
    summaryNotCompared,
    truncated: chain.truncated === true,
  };
  Object.defineProperty(result, "joins", {
    enumerable: false,
    value: {
      first: links.length ? { id: links[0].id, prev: links[0].record ? bytesToHex(links[0].record.chain_prev_hash) : null } : null,
      last: links.length ? { id: links[links.length - 1].id, hash: bytesToHex(links[links.length - 1].hash) } : null,
      byId: new Map(links.map((l) => [l.id, bytesToHex(l.hash)])),
      atById: new Map(links.map((l) => [l.id, l.at])),
      partial: chain.truncated === true,
      live: new Map(links.filter((l) => l.record).map((l) => [l.id, { outcome: recordText(l.record.policy_decision), when: recordText(l.record.occurred_at) }])),
      trail: changeRowsById(read("mutations/policy-trail.json")),
      registerChanges: changeRowsById((read("register/decisions.json") ?? []).filter((row) => row?.source === "mutation")),
      register: registerDecisions(read("register/decisions.json")),
    },
  });
  return result;
}

function changeRowsById(list) {
  const rows = new Map();
  for (const row of Array.isArray(list) ? list : []) {
    if (row && typeof row.id === "string") rows.set(row.id.toLowerCase(), { at: instantTicks(row.occurredAt), row });
  }
  return rows;
}

function canonicalJson(value) {
  return JSON.stringify(value ?? null, (key, v) => (v && typeof v === "object" && !Array.isArray(v)
    ? Object.fromEntries(Object.entries(v).sort(([m], [n]) => (m < n ? -1 : m > n ? 1 : 0)))
    : v));
}

function changeRowDifference(p, q) {
  const unnamed = (r) => r.actorType === "mandate_support" && r.actorId == null && r.actorDisplay == null;
  const gone = unnamed(p) === unnamed(q) ? 0 : unnamed(p) ? 1 : 2;
  const words = { actorType: "who acted", actorId: "who acted", actorDisplay: "who acted", mutationReason: "reason", occurredAt: "time", action: "action" };
  const fields = new Set();
  for (const key of new Set([...Object.keys(p), ...Object.keys(q)])) {
    if (gone && words[key] === "who acted") continue;
    const same = key === "occurredAt" && instantTicks(p[key]) !== null
      ? instantTicks(p[key]) === instantTicks(q[key])
      : canonicalJson(p[key]) === canonicalJson(q[key]);
    if (!same) fields.add(words[key] ?? key);
  }
  return { fields: [...fields].sort(), gone };
}

function packSpan(p, partial, held) {
  const identity = p.result.identity ?? {};
  const from = instantTicks(identity.windowFrom);
  const to = instantTicks(identity.windowTo);
  if (from === null || to === null) return null;
  const window = { from, to, fromOpen: false, toOpen: false };
  const span = { ...window };
  let cut = "";
  const made = instantTicks(identity.generatedAt);
  if (made !== null && made - 600000000n < span.to) {
    span.to = made - 600000000n;
    cut = `${p.name} says it was made at ${identity.generatedAt}`;
  }
  if (partial) {
    cut = `${p.name} says it holds only part of its period`;
    const times = held.filter((t) => t !== null);
    if (times.length === 0) return { window, span: null, cut };
    const lo = times.reduce((m, t) => (t < m ? t : m));
    const hi = times.reduce((m, t) => (t > m ? t : m));
    if (lo >= span.from) Object.assign(span, { from: lo, fromOpen: true });
    if (hi <= span.to) Object.assign(span, { to: hi, toOpen: true });
  }
  return { window, span, cut };
}

function withinSpan(s, t) {
  return s !== null && t !== null && (s.fromOpen ? t > s.from : t >= s.from) && (s.toOpen ? t < s.to : t <= s.to);
}

function registerDecisions(list) {
  const rows = new Map();
  const fields = new Set();
  for (const row of Array.isArray(list) ? list : []) {
    if (!row || (row.source !== "decision" && row.source !== "imported") || typeof row.id !== "string") continue;
    rows.set(row.id.toLowerCase(), row);
    for (const key of Object.keys(row)) fields.add(key);
  }
  return { rows, fields };
}

function registerRowDifference(p, q, shownA, shownB) {
  const always = { person: "person", actorType: "agent", actorId: "agent", actorDisplay: "agent name", action: "outcome", occurredAt: "time",
    provider: "provider", model: "model", policyVersionId: "policy version", correlationId: "correlation id" };
  const words = { ...always, recordSha256: "sealed record", rules: "rules", purpose: "purpose", purposeSource: "purpose", mandateSlug: "mandate" };
  const keys = new Set([...Object.keys(always), ...[...shownA].filter((k) => shownB.has(k))]);
  const fields = new Set();
  let renamed = false;
  for (const key of keys) {
    const same = key === "occurredAt" && instantTicks(p[key]) !== null
      ? instantTicks(p[key]) === instantTicks(q[key])
      : canonicalJson(p[key]) === canonicalJson(q[key]);
    if (same) continue;
    if (key === "actorDisplay" && p.actorType === "agent" && q.actorType === "agent" && p.actorId && p.actorId === q.actorId) {
      renamed = true;
      continue;
    }
    fields.add(words[key] ?? key);
  }
  return { fields: [...fields].sort(), renamed };
}

function comparePacks(a, b) {
  const ja = a.result.chain.joins;
  const jb = b.result.chain.joins;
  const notes = [];
  const made = (p) => instantTicks(p.result.identity?.generatedAt);
  const [first, second] = made(a) !== null && made(b) !== null && made(b) < made(a) ? [b, a] : [a, b];
  const sides = [[a, ja, b, jb], [b, jb, a, ja]];
  const subjectOf = (id) => ([ja, jb].some((j) => {
    const live = j.live.get(id);
    return j.register.rows.has(id) || (live && live.outcome !== "result" && live.outcome !== "imported");
  }) ? "decision" : "record");
  const erased = [];
  for (const [x, jx, y, jy] of sides) {
    for (const [id, live] of jx.live) {
      if (!jy.byId.has(id) || jy.live.has(id)) continue;
      if (made(x) !== null && made(y) !== null && made(y) < made(x)) {
        return { kind: "erased-first", id, subject: subjectOf(id), detail: `${subjectOf(id)} ${id} is erased in ${y.name} but whole in ${x.name}, though ${y.name} says it was made first` };
      }
      erased.push({ id, outcome: live.outcome, when: live.when });
    }
  }
  if (erased.length > 0) {
    const noun = erased.every((e) => e.outcome !== "result" && e.outcome !== "imported") ? "decision" : "record";
    const named = erased.slice(0, 5).map((e) => `${e.id} (${e.outcome}, ${e.when})`).join(", ");
    notes.push(`${erased.length} ${noun}${erased.length === 1 ? "" : "s"} erased between ${a.name} and ${b.name}: ${named}${erased.length > 5 ? `, and ${erased.length - 5} more` : ""}`);
  }
  for (const [x, jx, y, jy] of sides) {
    const cover = packSpan(y, jy.partial, [...jy.atById.values()]);
    if (cover === null) continue;
    let notCompared = 0;
    for (const [id, t] of jx.atById) {
      if (jy.byId.has(id)) continue;
      if (withinSpan(cover.span, t)) {
        return { kind: "missing", id, subject: subjectOf(id), detail: `${subjectOf(id)} ${id} is in ${x.name} but missing from ${y.name}, inside the period ${y.name} covers` };
      }
      if (withinSpan(cover.window, t)) notCompared++;
    }
    if (notCompared > 0) notes.push(`${notCompared} record${notCompared === 1 ? "" : "s"} of ${x.name} inside the period of ${y.name} not compared: ${cover.cut}`);
  }
  const ids = [...new Set([...ja.byId.keys(), ...ja.register.rows.keys()])];
  for (const id of ids) {
    const row = ja.register.rows.get(id);
    const other = jb.register.rows.get(id);
    if (!row || !other) continue;
    const [p, q] = first === a ? [row, other] : [other, row];
    const diff = registerRowDifference(p, q, ja.register.fields, jb.register.fields);
    if (diff.fields.length > 0) {
      return { kind: "changed", id, subject: "decision", fields: diff.fields, detail: `decision ${id} reads differently in ${second.name} than in ${first.name}: its ${diff.fields.join(", ")}` };
    }
    if (diff.renamed) notes.push(`agent ${row.actorId} is named ${row.actorDisplay ?? "no name"} in ${a.name} and ${other.actorDisplay ?? "no name"} in ${b.name}`);
  }
  for (const [id, hash] of ja.byId) {
    if (jb.byId.has(id) && jb.byId.get(id) !== hash) {
      return { kind: "changed", id, subject: subjectOf(id), fields: ["sealed record"], detail: `${subjectOf(id)} ${id} reads differently in ${second.name} than in ${first.name}: its sealed record` };
    }
  }
  for (const [file, key, partialFlag] of [["mutations/policy-trail.json", "trail", "mutationsTruncated"], ["register/decisions.json", "registerChanges", "truncated"]]) {
    for (const [id, entry] of ja[key]) {
      const other = jb[key].get(id);
      if (!other) continue;
      const diff = changeRowDifference(entry.row, other.row);
      if (diff.fields.length > 0) {
        return {
          kind: "changed", id, subject: "change-trail entry", fields: diff.fields,
          detail: `change-trail entry ${id} (${entry.row.action}) in ${file} reads differently in ${second.name} than in ${first.name}: its ${diff.fields.join(", ")}`,
        };
      }
      if (diff.gone) notes.push(`change-trail entry ${id} (${entry.row.action}) no longer names who acted in ${diff.gone === 1 ? a.name : b.name}: the account was removed between the exports`);
    }
    for (const [x, jx, y, jy] of sides) {
      const cover = packSpan(y, Boolean(y.result[partialFlag]), [...jy[key].values()].map((e) => e.at));
      if (cover === null) continue;
      for (const [id, entry] of jx[key]) {
        if (!jy[key].has(id) && withinSpan(cover.span, entry.at)) {
          return {
            kind: "missing", id, subject: "change-trail entry",
            detail: `change-trail entry ${id} (${entry.row.action}) is in ${x.name} but missing from ${y.name}'s ${file}, inside the period ${y.name} covers`,
          };
        }
      }
    }
  }
  return { notes: [...new Set(notes)], erased };
}

export function checkPackSequence(packs) {
  const ordered = [...packs].sort((a, b) => Date.parse(a.result.identity?.windowFrom ?? 0) - Date.parse(b.result.identity?.windowFrom ?? 0));
  const notes = [];
  const erased = [];
  for (let i = 1; i < ordered.length; i++) {
    const a = ordered[i - 1];
    const b = ordered[i];
    const fail = (kind, detail, extra = {}) => ({ status: "invalid", kind, reason: `${a.name} then ${b.name}: ${detail}`, detail, ...extra });
    if (a.result.identity?.tenantId !== b.result.identity?.tenantId) return fail("workspace", "the packs belong to different workspaces");
    if (a.result.publicKeyFingerprint !== b.result.publicKeyFingerprint && !(a.trusted === true && b.trusted === true)) {
      return fail("key", "the packs are signed by different keys");
    }
    const gap = Date.parse(b.result.identity?.windowFrom) - Date.parse(a.result.identity?.windowTo);
    if (!(gap <= 1)) return fail("gap", "the windows leave a gap between them");
    const ja = a.result.chain?.joins;
    const jb = b.result.chain?.joins;
    if (!ja || !jb) {
      return fail("unreadable", [a, b].some((p) => p.result.chain?.status === "invalid") ? "the records in one of the packs fail their own check" : "a pack carries no records file");
    }
    const compared = comparePacks(a, b);
    if (compared.kind) return fail(compared.kind, compared.detail, { id: compared.id, subject: compared.subject, fields: compared.fields ?? [] });
    notes.push(...compared.notes);
    erased.push(...compared.erased);
    if (!ja.last || !jb.first) continue;
    if (!ja.byId.has(jb.first.id) && jb.first.prev !== ja.last.hash) return fail("continuity", "the later pack does not continue from the earlier one");
  }
  return { status: "valid", packs: ordered.length, notes, erased };
}

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
  if (manifest.manifestVersion !== SUPPORTED_MANIFEST_VERSION) {
    return {
      manifest: {
        status: "unsupported",
        reason: `this pack is format ${manifest.manifestVersion}; this verifier reads format ${SUPPORTED_MANIFEST_VERSION}. Use the verifier released with the pack, or the latest from mandateco.ca/verify.html`,
      },
      files: [],
      checkpoints: [],
      overall: "unsupported",
      format: manifest.manifestVersion,
    };
  }

  const files = [];
  for (const entry of manifest.contents) {

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

  const listed = new Set(manifest.contents.map((c) => c.filename));
  for (const name of fileBytes.keys()) {
    if (name === "manifest.json" || listed.has(name)) continue;
    files.push({ path: name, status: "invalid", reason: "file present in pack but not listed in manifest.contents" });
  }

  const MANIFEST_FIELDS = ["manifestVersion", "tenantId", "generatedAt", "windowFrom", "windowTo", "truncated", "checkpointsTruncated",
    "mutationsTruncated", "contents", "checkpointIds", "signatureHex", "publicKeyBase64", "publicKeyFingerprint"];
  const unsignedFields = Object.keys(manifest).filter((k) => !MANIFEST_FIELDS.includes(k));
  let manifestResult;

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
      manifest.mutationsTruncated,
      manifest.contents,
    );
    const signature = hexToBytes(manifest.signatureHex);
    const publicKey = base64ToBytes(manifest.publicKeyBase64);
    manifestFingerprint = await sha256Hex(publicKey);
    manifestResult = await verifyEd25519(payload, signature, publicKey, "manifest signature does not match the pack contents");
    const checkpointFiles = [...fileBytes.keys()].filter((n) => n.startsWith("checkpoints/") && n.endsWith(".json"))
      .map((n) => n.slice("checkpoints/".length, -".json".length).toLowerCase()).sort();
    const namedCheckpoints = Array.isArray(manifest.checkpointIds) ? manifest.checkpointIds.map((c) => String(c).toLowerCase()).sort() : null;
    if (manifestResult.status === "valid" && unsignedFields.length > 0) {
      manifestResult = { status: "invalid", reason: `manifest.json carries ${unsignedFields.join(", ")}, which its signature does not cover` };
    } else if (manifestResult.status === "valid" && manifest.publicKeyFingerprint !== undefined
      && String(manifest.publicKeyFingerprint).toLowerCase() !== manifestFingerprint) {
      manifestResult = { status: "invalid", reason: "manifest.publicKeyFingerprint names another key than the one that signed it" };
    } else if (manifestResult.status === "valid" && namedCheckpoints !== null && namedCheckpoints.join() !== checkpointFiles.join()) {
      manifestResult = { status: "invalid", reason: "manifest.checkpointIds does not list exactly the checkpoint files the pack carries" };
    }
  } catch (err) {
    manifestResult = { status: "invalid", reason: `manifest verification failed: ${err.message}` };
  }

  const checkpoints = [];
  for (const [name, bytes] of fileBytes) {
    if (!name.startsWith("checkpoints/") || !name.endsWith(".json")) continue;
    try {
      const bundle = validateCheckpointBundle(JSON.parse(new TextDecoder().decode(bytes)));

      let checkpointFingerprint;
      try {
        checkpointFingerprint = await sha256Hex(base64ToBytes(bundle.publicKeyBase64));
      } catch {
        checkpointFingerprint = undefined;
      }
      checkpoints.push({
        checkpointId: bundle.checkpointId,
        publicKeyFingerprint: checkpointFingerprint,
        result: sameWorkspace(bundle.tenantId, manifest.tenantId)
          ? await verifyCheckpointBundle(bundle)
          : { status: "invalid", reason: `it names workspace ${bundle.tenantId}, not this export's workspace ${manifest.tenantId}` },
      });
    } catch (err) {
      checkpoints.push({
        checkpointId: name,
        publicKeyFingerprint: undefined,
        result: { status: "invalid", reason: `checkpoint parse failed: ${err.message}` },
      });
    }
  }

  const chain = await verifyChainFiles(fileBytes, {
    tenantId: manifest.tenantId,
    registerPartial: Boolean(manifest.truncated),
    windowFrom: manifest.windowFrom,
    windowTo: manifest.windowTo,
  });
  const checkpointKeysDiffer = manifestFingerprint !== undefined
    && checkpoints.some((c) => c.publicKeyFingerprint !== undefined && c.publicKeyFingerprint !== manifestFingerprint);

  const anyUnsupported =
    manifestResult.status === "unsupported" || checkpoints.some((c) => c.result.status === "unsupported");
  const anyInvalid =
    manifestResult.status === "invalid"
    || files.some((f) => f.status !== "valid")
    || checkpoints.some((c) => c.result.status === "invalid")
    || chain.status === "invalid";

  return {
    manifest: manifestResult,
    files,
    checkpoints,
    chain,
    overall: anyUnsupported ? "unsupported" : anyInvalid ? "invalid" : "valid",
    publicKeyFingerprint: manifestFingerprint,
    checkpointKeysDiffer,
    truncated: manifest.truncated,
    checkpointsTruncated: manifest.checkpointsTruncated,
    mutationsTruncated: manifest.mutationsTruncated,
    identity: {
      tenantId: manifest.tenantId,
      generatedAt: manifest.generatedAt,
      windowFrom: manifest.windowFrom ?? null,
      windowTo: manifest.windowTo ?? null,
    },
  };
}


export const DSR_ACCESS_SIGNED_PAYLOAD_DOMAIN_V4 = "mandate.dsr.access-manifest-sig.v4";

export function buildDsrAccessSignedPayload(tenantId, subjectHashHex, manifestVersion, generatedAt, windowFrom, windowTo, truncated, unscannableRows, degradedRows, partiallyScannableRows, opaqueRegions, opaqueBytes, contents) {
  const sorted = [...contents].sort((a, b) => (a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0));
  const enc = new TextEncoder();
  const parts = [];

  const pushU32 = (label, n) => {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`invalid ${label}: ${n}`);
    parts.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  };
  const pushU64 = (n) => {
    for (let shift = 56n; shift >= 0n; shift -= 8n) parts.push(Number((n >> shift) & 0xffn));
  };
  const pushBytes = (b) => {
    for (const x of b) parts.push(x);
  };
  const pushNullableTimestampMs = (label, iso) => {
    if (iso == null) {
      parts.push(0);
      return;
    }
    if (!STRICT_ISO_TIMESTAMP.test(String(iso))) throw new Error(`invalid ${label}: ${iso} is not an ISO 8601 timestamp`);
    const bound = Date.parse(iso);
    if (Number.isNaN(bound)) throw new Error(`invalid ${label}: ${iso}`);
    parts.push(1);
    pushU64(BigInt(bound));
  };

  pushBytes(enc.encode(DSR_ACCESS_SIGNED_PAYLOAD_DOMAIN_V4));
  pushBytes(uuidToRfc4122Bytes(tenantId));

  const subjectHash = hexToBytes(subjectHashHex);
  if (subjectHash.length !== 32) throw new Error("subject_hash must be 32 bytes");
  pushBytes(subjectHash);

  pushU32("manifestVersion", manifestVersion);

  if (!STRICT_ISO_TIMESTAMP.test(String(generatedAt))) throw new Error(`invalid generatedAt: ${generatedAt} is not an ISO 8601 timestamp`);
  const ms = Date.parse(generatedAt);
  if (Number.isNaN(ms)) throw new Error(`invalid generatedAt: ${generatedAt}`);
  pushU64(BigInt(ms));

  pushNullableTimestampMs("windowFrom", windowFrom);
  pushNullableTimestampMs("windowTo", windowTo);

  parts.push(truncated ? 1 : 0);

  pushU32("unscannableRows", unscannableRows);
  pushU32("degradedRows", degradedRows);
  pushU32("partiallyScannableRows", partiallyScannableRows);
  pushU32("opaqueRegions", opaqueRegions);
  if (!Number.isInteger(opaqueBytes) || opaqueBytes < 0) throw new Error(`invalid opaqueBytes: `);
  pushU64(BigInt(opaqueBytes));

  pushU32("contents count", sorted.length);
  for (const c of sorted) {
    const nameBytes = enc.encode(c.filename);
    pushU32(`content ${c.filename} filename length`, nameBytes.length);
    pushBytes(nameBytes);
    const sha = hexToBytes(c.sha256Hex);
    if (sha.length !== 32) throw new Error(`content ${c.filename} sha256 must be 32 bytes`);
    pushBytes(sha);
    pushU64(BigInt(c.byteLength));
  }

  return new Uint8Array(parts);
}

export async function verifyDsrAccessPackBytes(zipBytes, inflateRaw) {
  const fileBytes = await readZipEntries(zipBytes, inflateRaw);

  const invalid = (reason) => ({
    manifest: { status: "invalid", reason },
    files: [],
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

  const files = [];
  for (const entry of manifest.contents) {
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

  const listed = new Set(manifest.contents.map((c) => c.filename));
  for (const name of fileBytes.keys()) {
    if (name === "manifest.json" || listed.has(name)) continue;
    files.push({ path: name, status: "invalid", reason: "file present in pack but not listed in manifest.contents" });
  }

  let manifestResult;
  let manifestFingerprint;
  try {
    const payload = buildDsrAccessSignedPayload(
      manifest.tenantId,
      manifest.subjectHashHex,
      manifest.manifestVersion,
      manifest.generatedAt,
      manifest.windowFrom ?? null,
      manifest.windowTo ?? null,
      manifest.truncated,
      manifest.unscannableRows,
      manifest.degradedRows,
      manifest.partiallyScannableRows,
      manifest.opaqueRegions,
      manifest.opaqueBytes,
      manifest.contents,
    );
    const signature = hexToBytes(manifest.signatureHex);
    const publicKey = base64ToBytes(manifest.publicKeyBase64);
    manifestFingerprint = await sha256Hex(publicKey);
    manifestResult = await verifyEd25519(payload, signature, publicKey, "manifest signature does not match the pack contents");
  } catch (err) {
    manifestResult = { status: "invalid", reason: `manifest verification failed: ${err.message}` };
  }

  const anyInvalid = manifestResult.status === "invalid" || files.some((f) => f.status !== "valid");
  return {
    manifest: manifestResult,
    files,
    overall: manifestResult.status === "unsupported" ? "unsupported" : anyInvalid ? "invalid" : "valid",
    publicKeyFingerprint: manifestFingerprint,
    subjectHashHex: manifest.subjectHashHex,
    truncated: manifest.truncated,
    unscannableRows: manifest.unscannableRows,
    degradedRows: manifest.degradedRows,
    partiallyScannableRows: manifest.partiallyScannableRows,
    opaqueRegions: manifest.opaqueRegions,
    opaqueBytes: manifest.opaqueBytes,
    identity: {
      tenantId: manifest.tenantId,
      generatedAt: manifest.generatedAt,
      windowFrom: manifest.windowFrom ?? null,
      windowTo: manifest.windowTo ?? null,
    },
  };
}

export async function detectPackKind(zipBytes, inflateRaw) {
  const fileBytes = await readZipEntries(zipBytes, inflateRaw);
  const manifestBytes = fileBytes.get("manifest.json");
  if (!manifestBytes) return "evidence";
  try {
    const manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
    return typeof manifest?.subjectHashHex === "string" ? "dsr" : "evidence";
  } catch {
    return "evidence";
  }
}

const VERIFIER_CORE_END = "VERIFIER-CORE-END";

function usage() {
  return [
    "Usage: node mandate-verify.mjs <record.zip | folder> [...] [--expect-fingerprint <hex>]... [--json] [--version]",
    "",
    "--expect-fingerprint names the fingerprint from your agreement: 64 hex characters, plain or in pairs separated by colons or spaces.",
    "Give it more than once after a key change: every key in a record, its checkpoints included, must be one you named.",
    "",
    "Several records are checked one by one and then together: the parts of one complete export, or an earlier and a later export.",
    "They must name one workspace, be signed by one key or by keys you named, leave no gap between their periods, each continue from the one before,",
    "and no record or change-trail entry one holds inside the time the other covers may be missing from the other or read differently there;",
    "a decision's readable row, the person included, must read the same in both.",
    "Each export covers its period up to a minute before it says it was made, or only the span its records hold when it says it is partial;",
    "what that leaves out is named, and so is any decision erased between the exports.",
    "A folder stands for every record in it, in name order: unzip a complete export and give the verifier its folder. A folder is checked one neighbour at a time, so a long export needs no more memory than two parts.",
    "",
    "Checks a Mandate signed record or access record offline (the kind is read off the manifest). Exit codes:",
    "  0 valid, signed by a key you named   1 invalid or fingerprint mismatch   2 usage/IO/ZIP error   3 no Ed25519 support",
    "  4 not verified: unchanged since signing, but the key was not checked: name the fingerprint from your agreement with --expect-fingerprint",
  ].join("\n");
}

const EXIT_RANK = { 0: 0, 4: 1, 1: 2, 2: 3, 3: 4 };
const worse = (a, b) => (EXIT_RANK[b] > EXIT_RANK[a] ? b : a);

async function main(argv) {
  const packPaths = [];
  const expectFingerprints = [];
  let asJson = false;
  let streamed = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--json") {
      asJson = true;
    } else if (arg === "--version") {
      console.log(`mandate-verify ${TOOL_VERSION} (payloads: ${EVIDENCE_PACK_SIGNED_PAYLOAD_DOMAIN_V3}, ${CHECKPOINT_SIGNED_PAYLOAD_DOMAIN_V1}, ${DSR_ACCESS_SIGNED_PAYLOAD_DOMAIN_V4})`);
      return 0;
    } else if (arg === "--expect-fingerprint") {
      const value = argv[++i];
      if (!value) {
        console.error("--expect-fingerprint requires a value\n\n" + usage());
        return 2;
      }
      const fingerprint = value.toLowerCase().replace(/[\s:]/g, "");
      if (!/^[0-9a-f]{64}$/.test(fingerprint)) {
        console.error(`--expect-fingerprint takes the 64 hex characters of a fingerprint, plain or in pairs separated by colons or spaces, not ${value}\n\n` + usage());
        return 2;
      }
      expectFingerprints.push(fingerprint);
    } else if (arg === "--help" || arg === "-h") {
      console.log(usage());
      return 0;
    } else if (arg.startsWith("--")) {
      console.error(`unknown option: ${arg}\n\n` + usage());
      return 2;
    } else {
      const folder = await stat(arg).then((st) => st.isDirectory(), () => false);
      if (folder) {
        const names = (await readdir(arg)).filter((n) => n.toLowerCase().endsWith(".zip")).sort();
        packPaths.push(...names.map((n) => join(arg, n)));
        streamed = true;
      } else {
        packPaths.push(arg);
      }
    }
  }

  if (packPaths.length === 0) {
    console.error(usage());
    return 2;
  }

  let worst = 0;
  const verified = [];
  // A folder (a complete export, in name order) is checked one neighbour at a time and each pack let go after, so a
  // long export needs no more memory than two packs; packs named one by one are sorted by their windows first.
  let previous = null;
  let streamedSequence = null;
  const streamedNotes = [];
  const streamedErased = [];
  for (const packPath of packPaths) {
    const { code, result, kind } = await verifyOne(packPath, expectFingerprints, asJson);
    worst = worse(worst, code);
    const pack = result && kind === "evidence" ? { name: packPath, result, trusted: code === 0 } : null;
    if (!streamed) {
      if (pack) verified.push(pack);
    } else if (!pack) {
      streamedSequence ??= { status: "invalid", reason: "every part of a sequence must be a readable signed record" };
    } else {
      if (previous && !streamedSequence) {
        const pair = checkPackSequence([previous, pack]);
        if (pair.status !== "valid") streamedSequence = pair;
        else {
          streamedNotes.push(...(pair.notes ?? []));
          streamedErased.push(...(pair.erased ?? []));
        }
      }
      previous = pack;
    }
  }
  if (packPaths.length > 1) {
    const sequence = streamed
      ? streamedSequence ?? { status: "valid", packs: packPaths.length, notes: streamedNotes, erased: streamedErased }
      : verified.length === packPaths.length
        ? checkPackSequence(verified)
        : { status: "invalid", reason: "every part of a sequence must be a readable signed record" };
    const joined = `${sequence.packs} parts join record to record, with no gap between their periods`;
    if (asJson) console.log(JSON.stringify({ sequence }, null, 2));
    else console.log(sequence.status !== "valid"
      ? `SEQUENCE: INVALID (${["changed", "missing", "erased-first"].includes(sequence.kind) ? `the records disagree: ${sequence.detail}` : sequence.reason})`
      : expectFingerprints.length === 0
        ? `SEQUENCE: NOT VERIFIED (${joined}, but the key was not checked: name the fingerprint from your agreement with --expect-fingerprint)`
        : `SEQUENCE: VALID (${joined})`);
    if (!asJson && sequence.status === "valid") for (const note of sequence.notes ?? []) console.log(`  note: ${note}`);
    if (sequence.status !== "valid") worst = worse(worst, 1);
  }
  return worst;
}

async function verifyOne(packPath, expectFingerprints, asJson) {
  if (/-packs\.zip$/i.test(packPath)) {
    console.error(`${packPath} is a complete export that holds several records: unzip it, then give the verifier the folder.`);
    return { code: 2 };
  }

  let bytes;
  try {
    bytes = new Uint8Array(await readFile(packPath));
  } catch (err) {
    console.error(`cannot read ${packPath}: ${err.message}`);
    return { code: 2 };
  }

  const inflateRaw = async (raw, limit) => {
    try {
      return new Uint8Array(inflateRawSync(raw, { maxOutputLength: Math.max(1, limit ?? 52428800) }));
    } catch (err) {
      throw new ZipError("deflate", `a compressed entry is corrupt and cannot be decompressed: ${err.message}`);
    }
  };

  let result;
  let kind;
  try {
    kind = await detectPackKind(bytes, inflateRaw);
    result = kind === "dsr"
      ? await verifyDsrAccessPackBytes(bytes, inflateRaw)
      : await verifyEvidencePackBytes(bytes, inflateRaw);
  } catch (err) {

    const detail = err instanceof ZipError ? err.message : `unexpected error: ${err.message}`;
    console.error(`cannot read ${packPath} as a Mandate record: ${detail}`);
    return { code: 2 };
  }
  const checkpoints = result.checkpoints ?? [];

  const expected = expectFingerprints;
  const named = (fingerprint) => expected.includes((fingerprint ?? "").toLowerCase());
  const fingerprintMismatches = [];
  if (expected.length > 0) {
    if (!named(result.publicKeyFingerprint)) {
      fingerprintMismatches.push(`manifest key is ${result.publicKeyFingerprint ?? "(none)"}`);
    }
    for (const c of checkpoints) {
      if (!named(c.publicKeyFingerprint)) {
        fingerprintMismatches.push(`checkpoint ${c.checkpointId} key is ${c.publicKeyFingerprint ?? "(none)"}`);
      }
    }
  }

  if (asJson) {
    console.log(JSON.stringify({ pack: packPath, kind, expectedFingerprints: expected, fingerprintMismatches, ...result }, null, 2));
  } else {
    console.log(`File           : ${packPath}`);
    console.log(`Kind           : ${kind === "dsr" ? "access record" : "signed record"}`);
    if (result.identity) {
      console.log(`Workspace      : ${result.identity.tenantId}`);
      console.log(`Generated      : ${localTime(result.identity.generatedAt)}`);
      console.log(`Period         : ${result.identity.windowFrom ? localTime(result.identity.windowFrom) : "(open)"} to ${result.identity.windowTo ? localTime(result.identity.windowTo) : "(open)"}`);
    }
    if (kind === "dsr") {
      console.log(`Person         : ${result.subjectHashHex} (keyed hash)`);
      console.log(
        `Complete       : ${result.truncated ? "no, this access record holds part of what was found" : "yes"}; `
        + `unscannable rows ${result.unscannableRows}, degraded rows ${result.degradedRows}`,
      );
    } else if (result.truncated !== undefined) {
      const partial = [["register", result.truncated], ["records", result.chain?.truncated], ["checkpoints", result.checkpointsTruncated], ["change trail", result.mutationsTruncated]]
        .filter(([, cut]) => cut).map(([part]) => part);
      console.log(`Complete       : ${partial.length > 0 ? `no, this export holds part of its period (partial: ${partial.join(", ")})` : "yes, the whole period"}`);
    }
    if (result.publicKeyFingerprint) {
      console.log(`Signing key    : ${result.publicKeyFingerprint}`);
      if (expected.length === 0) console.log("                 Compare this fingerprint with the one in your agreement before relying on the result.");
      else if (named(result.publicKeyFingerprint)) console.log("                 This is the fingerprint you named.");
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
    if (kind !== "dsr") {
      console.log(`Checkpoints (${checkpoints.length}):`);
      for (const c of checkpoints) {
        const tag = c.result.status === "valid" ? "[ ok ]" : c.result.status === "unsupported" ? "[ ?? ]" : "[FAIL]";
        const key = c.publicKeyFingerprint ? `  key ${c.publicKeyFingerprint.slice(0, 12)}..` : "";
        console.log(`  ${tag} ${c.checkpointId}${key}${c.result.reason ? `  (${c.result.reason})` : ""}`);
      }
    }
    for (const mm of fingerprintMismatches) {
      console.log(`  [FAIL] fingerprint expectation: ${mm}`);
    }
    if (result.chain) {
      const ch = result.chain;
      console.log("");
      if (ch.status === "valid") {
        const parts = [[ch.kinds?.decisions, "decision"], [ch.kinds?.answers, "answer relayed"], [ch.kinds?.imported, "imported record"], [ch.kinds?.changes, "change"]]
          .filter(([n]) => n > 0).map(([n, noun]) => `${n} ${noun}${n === 1 ? "" : noun === "answer relayed" ? "" : "s"}`.replace("answer relayed", n === 1 ? "answer relayed" : "answers relayed"));
        console.log(`Records: [ ok ] ${ch.records} records link in order${parts.length ? ` (${parts.join(", ")})` : ""}`);
        for (const e of ch.erasures ?? []) {
          console.log(`         [ ok ] ${e.removed} record${e.removed === 1 ? "" : "s"} removed under ${e.reason === "privacy request" ? "a privacy request" : "the retention setting"} on ${localTime(e.at)} keep${e.removed === 1 ? "s its" : " their"} place (entry ${e.id})`);
        }
        console.log(`         [ ok ] ${ch.checkpointsRecomputed} checkpoint root(s) recomputed from the records${ch.checkpointsNotCovered ? `, ${ch.checkpointsNotCovered} not covered: the records file is partial` : ""}`);
        console.log(`         [ ok ] ${ch.decisionsTied} decision(s) in the register match their records${ch.decisionsNotTied ? `, ${ch.decisionsNotTied} outside the records file` : ""}${ch.peopleTied ? `, ${ch.peopleTied} naming a person` : ""}`);
        console.log(`         [ ok ] ${ch.changesTied} change-trail entr${ch.changesTied === 1 ? "y matches its" : "ies match their"} sealed record${ch.changesTied === 1 ? "" : "s"}${ch.changesNotTied ? `, ${ch.changesNotTied} not sealed in the records file yet or outside it` : ""}`);
        if (ch.reportTied) console.log("         [ ok ] the printed report was drawn from the checked summary");
        console.log(`         [ ok ] ${ch.policyVersions} policy version(s) match their text`);
        if (ch.listsChecked) console.log(`         [ ok ] ${ch.listsChecked} list(s) of names match their seals`);
        else if (ch.listsSealed) console.log(`         [ -- ] ${ch.listsSealed} list(s) of names sealed; this export leaves the names out`);
        if (ch.summaryCompared) console.log("         [ ok ] the summary counts match the decisions");
        else if (ch.summaryNotCompared) console.log(`         [ -- ] the summary counts were not compared: ${ch.summaryNotCompared}`);
      } else {
        console.log(`Records: [FAIL] ${ch.reason}`);
      }
    }
    console.log("");
  }

  if (result.overall === "unsupported") {
    if (!asJson) {
      console.log(result.format !== undefined
        ? `RESULT: DIFFERENT FORMAT (${result.manifest.reason})`
        : "RESULT: UNSUPPORTED (this runtime lacks WebCrypto Ed25519; use Node 20 or newer)");
    }
    return { code: 3, result, kind };
  }
  const failed = result.overall === "invalid" || fingerprintMismatches.length > 0;
  if (failed) {
    if (!asJson) console.log("RESULT: INVALID");
    return { code: 1, result, kind };
  }
  if (expected.length === 0) {
    if (!asJson) {
      if (result.checkpointKeysDiffer) console.log("Some checkpoints are signed by a different key than the record, as after a key change: compare each fingerprint above with your agreement.");
      console.log("RESULT: NOT VERIFIED (unchanged since signing, but the key was not checked: name the fingerprint from your agreement with --expect-fingerprint)");
    }
    return { code: 4, result, kind };
  }
  if (!asJson) {
    console.log("RESULT: VALID");
    if (kind !== "dsr" && result.chain?.outcomes) console.log(headline(result.chain));
  }
  return { code: 0, result, kind };
}

function localTime(text) {
  const at = new Date(text);
  if (Number.isNaN(at.getTime())) return String(text);
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return `${at.toLocaleString("en-CA", { dateStyle: "medium", timeStyle: "short" })} ${zone} (${text})`;
}

function headline(chain) {
  const words = [["allow", "allowed"], ["warn", "warned"], ["redact", "masked"], ["escalate", "held"], ["block", "refused"]];
  const total = Object.values(chain.outcomes).reduce((n, c) => n + c, 0);
  const parts = words.filter(([k]) => chain.outcomes[k]).map(([k, w]) => `${chain.outcomes[k]} ${w}`);
  const list = parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : parts.join("");
  return `Unchanged since it was signed, with the key you named: ${total} decision${total === 1 ? "" : "s"}${list ? `: ${list}` : ""}.`;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  process.exitCode = await main(process.argv.slice(2));
}
