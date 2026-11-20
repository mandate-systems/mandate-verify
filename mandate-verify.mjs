#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Mandate Systems Inc.

import { open, readFile, readdir, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import { inflateRawSync } from "node:zlib";
import { pathToFileURL } from "node:url";

const TOOL_VERSION = "2.20.0";

const VERIFIER_CORE_BEGIN = "VERIFIER-CORE-BEGIN v2";

export const CHECKPOINT_SIGNED_PAYLOAD_DOMAIN_V1 = "mandate.audit.checkpoint-sig.v1";

export const EVIDENCE_PACK_SIGNED_PAYLOAD_DOMAIN_V3 = "mandate.evidence-pack.manifest-sig.v3";

export const ZIP_MAX_TOTAL_BYTES = 52428800;
export const ZIP_MAX_FILE_COUNT = 1032;

// Mandate's own markers sit under a rule-id prefix the policy compiler refuses for any rule a customer writes, so an id
// alone tells a note from a rule.
const NOTE_PREFIX = "policy.";
const NOT_READ_NOTE = "policy.body_unscannable";

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
    if (!Number.isSafeInteger(c.byteLength) || c.byteLength < 0) throw new Error(`invalid content ${c.filename} byteLength: ${c.byteLength}`);
    pushU64(BigInt(c.byteLength));
  }

  return new Uint8Array(parts);
}

export async function verifyEd25519(payload, signature, publicKey, invalidReason = "signature does not verify") {
  if (publicKey.length !== 32) {
    return { status: "invalid", reason: `public key must be 32 bytes, got ${publicKey.length}` };
  }
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

  const result = await verifyEd25519(
    signedPayload,
    signatureBytes,
    publicKeyBytes,
    "signature does not match checkpoint metadata and merkle root",
  );
  if (result.status === "valid" && String(bundle.publicKeyFingerprint).toLowerCase() !== await sha256Hex(publicKeyBytes)) {
    return { status: "invalid", reason: "its publicKeyFingerprint names another key than the one that signed it" };
  }
  return result;
}

// 2.18.0 (ADR-0075): an outside timestamp on each checkpoint. Format 2 of a checkpoint carries timestampTokenBase64, an RFC 3161
// token over the checkpoint's signed payload, its signature and its key, or null while none has been obtained. The token
// is checked offline: over these bytes, signed by a certificate for timestamping only, whose chain leads to a root this
// checker ships, every certificate valid at the stamped time. A checkpoint without one is reported, never invalid.
const TS_OID = {
  signedData: "1.2.840.113549.1.7.2",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingCertificate: "1.2.840.113549.1.9.16.2.12",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
  sha1: "1.3.14.3.2.26",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  rsaEncryption: "1.2.840.113549.1.1.1",
  sha256WithRSA: "1.2.840.113549.1.1.11",
  sha384WithRSA: "1.2.840.113549.1.1.12",
  sha512WithRSA: "1.2.840.113549.1.1.13",
  ecPublicKey: "1.2.840.10045.2.1",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  subjectKeyId: "2.5.29.14",
  authorityKeyId: "2.5.29.35",
  certificatePolicies: "2.5.29.32",
  crlDistributionPoints: "2.5.29.31",
  subjectAltName: "2.5.29.17",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  timeStamping: "1.3.6.1.5.5.7.3.8",
  commonName: "2.5.4.3",
  organization: "2.5.4.10",
};

// The extensions this check understands; any other marked critical makes a certificate unusable here (RFC 5280 4.2).
const TS_KNOWN_EXTENSIONS = new Set([TS_OID.basicConstraints, TS_OID.keyUsage, TS_OID.extKeyUsage, TS_OID.subjectKeyId,
  TS_OID.authorityKeyId, TS_OID.certificatePolicies, TS_OID.crlDistributionPoints, TS_OID.subjectAltName, TS_OID.authorityInfoAccess]);
const TS_HASH = { [TS_OID.sha1]: "SHA-1", [TS_OID.sha256]: "SHA-256", [TS_OID.sha384]: "SHA-384", [TS_OID.sha512]: "SHA-512" };
const TS_RSA_SIG = { [TS_OID.sha256WithRSA]: "SHA-256", [TS_OID.sha384WithRSA]: "SHA-384", [TS_OID.sha512WithRSA]: "SHA-512" };
const TS_ECDSA_SIG = { [TS_OID.ecdsaSha256]: "SHA-256", [TS_OID.ecdsaSha384]: "SHA-384", [TS_OID.ecdsaSha512]: "SHA-512" };
const TS_CURVES = { [TS_OID.p256]: ["P-256", 32], [TS_OID.p384]: ["P-384", 48] };

export const TIMESTAMP_TOKEN_MAX_BYTES = 65536;
const TS_MAX_CERTIFICATES = 16;
const TS_MAX_CHAIN = 6;
const TS_MAX_ACCURACY_MS = 60000;

class TsFormatError extends Error {}
class TsUnsupported extends Error {}

// One TLV at `pos`, read as DER: one-byte tags, definite lengths in their shortest form, nothing past `end`.
function derAt(buf, pos, end) {
  if (pos + 2 > end) throw new TsFormatError("it ends early");
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new TsFormatError("it uses a tag form timestamps do not");
  let len = buf[pos + 1];
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3) throw new TsFormatError("a length is indefinite or too long");
    if (start + n > end || buf[start] === 0) throw new TsFormatError("a length is not in its shortest form");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    if (len < 128) throw new TsFormatError("a length is not in its shortest form");
    start += n;
  }
  if (start + len > end) throw new TsFormatError("it ends early");
  return { tag, start, end: start + len, full: buf.subarray(pos, start + len), body: buf.subarray(start, start + len) };
}

function derKids(buf, node) {
  const out = [];
  for (let p = node.start; p < node.end;) {
    const c = derAt(buf, p, node.end);
    out.push(c);
    p = c.end;
  }
  return out;
}

function derIs(node, tag, what) {
  if (!node || node.tag !== tag) throw new TsFormatError(`${what} is not where the format puts it`);
  return node;
}

function derOid(node) {
  const b = derIs(node, 0x06, "an object identifier").body;
  if (b.length === 0 || (b[b.length - 1] & 0x80)) throw new TsFormatError("an object identifier is malformed");
  const parts = [];
  let v = 0;
  for (const x of b) {
    v = v * 128 + (x & 0x7f);
    if (x & 0x80) continue;
    if (parts.length === 0) {
      const first = v < 40 ? 0 : v < 80 ? 1 : 2;
      parts.push(first, v - first * 40);
    } else parts.push(v);
    v = 0;
  }
  return parts.join(".");
}

function derSmallInt(node, what) {
  const b = derIs(node, 0x02, what).body;
  if (b.length === 0 || b.length > 4 || (b[0] & 0x80)) throw new TsFormatError(`${what} is not a small number`);
  let v = 0;
  for (const x of b) v = v * 256 + x;
  return v;
}

function derTime(node) {
  const text = new TextDecoder().decode(node.body);
  if (node.tag === 0x17) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!m) throw new TsFormatError("a time is not in UTC");
    const yy = Number(m[1]);
    return Date.UTC(yy < 50 ? 2000 + yy : 1900 + yy, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  if (node.tag === 0x18) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,6}))?Z$/.exec(text);
    if (!m) throw new TsFormatError("a time is not in UTC");
    const ms = m[7] ? Math.floor(Number(`0.${m[7]}`) * 1000) : 0;
    return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]), ms);
  }
  throw new TsFormatError("a time is not a time");
}

function tsSame(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function derAlg(buf, node) {
  const [oid, params] = derKids(buf, derIs(node, 0x30, "an algorithm"));
  return { oid: derOid(oid), params };
}

function tsNameText(buf, nameNode) {
  const found = {};
  for (const rdn of derKids(buf, nameNode)) {
    for (const atv of derKids(buf, rdn)) {
      const [type, value] = derKids(buf, atv);
      const oid = derOid(type);
      if ((oid === TS_OID.commonName || oid === TS_OID.organization) && !(oid in found)) found[oid] = new TextDecoder().decode(value.body);
    }
  }
  return [...[found[TS_OID.organization], found[TS_OID.commonName]].filter(Boolean).join(", ")]
    .filter((ch) => { const c = ch.codePointAt(0); return c >= 32 && (c < 127 || c > 159); }).join("").slice(0, 120);
}

function tsRsaBits(buf, spki) {
  const [, bits] = derKids(buf, spki);
  const key = derIs(bits, 0x03, "a public key");
  const seq = derAt(buf, key.start + 1, key.end);
  const [modulus] = derKids(buf, derIs(seq, 0x30, "an RSA key"));
  let m = derIs(modulus, 0x02, "an RSA modulus").body;
  while (m.length > 0 && m[0] === 0) m = m.subarray(1);
  return m.length * 8 - Math.clz32(m[0] ?? 0) + 24;
}

function tsCertificate(buf, node) {
  const [tbs, sigAlg, sigValue] = derKids(buf, derIs(node, 0x30, "a certificate"));
  const fields = derKids(buf, derIs(tbs, 0x30, "a certificate body"));
  let i = fields[0]?.tag === 0xa0 ? 1 : 0;
  const serial = derIs(fields[i++], 0x02, "a serial number");
  const innerAlg = derIs(fields[i++], 0x30, "a certificate's algorithm");
  const issuer = derIs(fields[i++], 0x30, "an issuer name");
  const validity = derKids(buf, derIs(fields[i++], 0x30, "a validity"));
  const subject = derIs(fields[i++], 0x30, "a subject name");
  const spki = derIs(fields[i++], 0x30, "a public key");
  const ext = {};
  for (; i < fields.length; i++) {
    if (fields[i].tag !== 0xa3) continue;
    const [list] = derKids(buf, fields[i]);
    for (const e of derKids(buf, derIs(list, 0x30, "the extensions"))) {
      const parts = derKids(buf, e);
      const id = derOid(parts[0]);
      const critical = parts.length === 3 && parts[1].tag === 0x01 && parts[1].body[0] !== 0;
      const value = derIs(parts[parts.length - 1], 0x04, "an extension value");
      if (id in ext) throw new TsFormatError("a certificate carries an extension twice");
      if (critical && !TS_KNOWN_EXTENSIONS.has(id)) throw new TsUnsupported("a certificate carries a critical extension this checker does not read");
      ext[id] = { critical, value: derAt(buf, value.start, value.end) };
    }
  }
  if (!tsSame(innerAlg.full, sigAlg.full)) throw new TsFormatError("a certificate names two signature algorithms");
  const sig = derIs(sigValue, 0x03, "a certificate signature");
  if (sig.body[0] !== 0) throw new TsFormatError("a certificate signature is malformed");
  return {
    der: node.full, tbs: tbs.full, sigAlg: derAlg(buf, sigAlg), signature: sig.body.subarray(1), serial: serial.body,
    issuer: issuer.full, subject: subject.full, subjectText: tsNameText(buf, subject), notBefore: derTime(validity[0]),
    notAfter: derTime(validity[1]), spki: spki.full, spkiAlg: derAlg(buf, derKids(buf, spki)[0]), spkiNode: spki, ext, buf,
  };
}

export function timestampRootFromDer(der) {
  const bytes = der instanceof Uint8Array ? der : new Uint8Array(der);
  const node = derAt(bytes, 0, bytes.length);
  if (node.end !== bytes.length) throw new TsFormatError("a root certificate has bytes after its end");
  return tsCertificate(bytes, node);
}

// basicConstraints: [isCa, pathLen or undefined].
function tsCaInfo(cert) {
  const bc = cert.ext[TS_OID.basicConstraints];
  if (!bc) return [false, undefined];
  const parts = derKids(cert.buf, derIs(bc.value, 0x30, "basic constraints"));
  const isCa = parts[0]?.tag === 0x01 && parts[0].body[0] !== 0;
  const lenNode = parts.find((p) => p.tag === 0x02);
  return [isCa, lenNode ? derSmallInt(lenNode, "a path length") : undefined];
}

// keyUsage bit n is set (bit 0 = digitalSignature, 1 = nonRepudiation, 5 = keyCertSign); absent allows all.
function tsKeyUsage(cert, ...bitsWanted) {
  const ku = cert.ext[TS_OID.keyUsage];
  if (!ku) return true;
  const b = derIs(ku.value, 0x03, "key usage").body;
  return bitsWanted.some((n) => b.length > 1 + (n >> 3) && (b[1 + (n >> 3)] & (0x80 >> (n & 7))) !== 0);
}

function tsForTimestamping(cert) {
  const eku = cert.ext[TS_OID.extKeyUsage];
  if (!eku) return "its authority's certificate does not say it is for timestamping";
  const purposes = derKids(cert.buf, derIs(eku.value, 0x30, "extended key usage")).map(derOid);
  if (purposes.length !== 1 || purposes[0] !== TS_OID.timeStamping) return "its authority's certificate is for more than timestamping";
  if (!eku.critical) return "its authority's certificate does not mark timestamping as its only use";
  if (!tsKeyUsage(cert, 0, 1)) return "its authority's certificate may not sign";
  return null;
}

function tsEcdsaRaw(sig, size) {
  const seq = derAt(sig, 0, sig.length);
  if (seq.tag !== 0x30 || seq.end !== sig.length) throw new TsFormatError("an ECDSA signature is malformed");
  const halves = derKids(sig, seq);
  if (halves.length !== 2) throw new TsFormatError("an ECDSA signature is malformed");
  const out = new Uint8Array(size * 2);
  halves.forEach((part, k) => {
    let b = derIs(part, 0x02, "an ECDSA signature half").body;
    while (b.length > size && b[0] === 0) b = b.subarray(1);
    if (b.length > size) throw new TsFormatError("an ECDSA signature is malformed");
    out.set(b, k * size + (size - b.length));
  });
  return out;
}

// True when `signature` over `data` verifies with `cert`'s key under `alg`. A SignerInfo may name only the key's own
// algorithm (rsaEncryption, ecPublicKey); `digestHash` then supplies the hash.
async function tsVerifyWith(cert, alg, signature, data, digestHash) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new TsUnsupported("this runtime has no WebCrypto");
  if (cert.spkiAlg.oid === TS_OID.rsaEncryption) {
    const hash = TS_RSA_SIG[alg.oid] ?? (alg.oid === TS_OID.rsaEncryption ? digestHash : undefined);
    if (!hash || hash === "SHA-1") throw new TsUnsupported("a signature uses an algorithm this checker does not accept");
    if (tsRsaBits(cert.buf, cert.spkiNode) < 2048) throw new TsUnsupported("an RSA key is shorter than 2048 bits");
    let key;
    try {
      key = await subtle.importKey("spki", cert.spki, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
    } catch (err) {
      throw new TsUnsupported(`RSA is not available here: ${err.message}`);
    }
    return subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, data);
  }
  if (cert.spkiAlg.oid === TS_OID.ecPublicKey) {
    const curve = TS_CURVES[derOid(cert.spkiAlg.params)];
    if (!curve) throw new TsUnsupported("a key is on a curve this checker does not accept");
    const hash = TS_ECDSA_SIG[alg.oid] ?? (alg.oid === TS_OID.ecPublicKey ? digestHash : undefined);
    if (!hash || hash === "SHA-1") throw new TsUnsupported("a signature uses an algorithm this checker does not accept");
    let key;
    try {
      key = await subtle.importKey("spki", cert.spki, { name: "ECDSA", namedCurve: curve[0] }, false, ["verify"]);
    } catch (err) {
      throw new TsUnsupported(`ECDSA is not available here: ${err.message}`);
    }
    return subtle.verify({ name: "ECDSA", hash }, key, tsEcdsaRaw(signature, curve[1]), data);
  }
  throw new TsUnsupported("a key uses an algorithm this checker does not accept");
}

async function tsDigest(hash, data) {
  return new Uint8Array(await globalThis.crypto.subtle.digest(hash, data));
}

// The ESS signing-certificate attribute must name the signer: its hash, and its issuer and serial when given.
async function tsNamesSigner(buf, attrs, signer) {
  const v2 = attrs[TS_OID.signingCertificateV2];
  const v1 = attrs[TS_OID.signingCertificate];
  if (!v2 && !v1) return false;
  const [list] = derKids(buf, derIs(v2 ?? v1, 0x30, "the signing certificate"));
  const [first] = derKids(buf, derIs(list, 0x30, "the signing certificate"));
  const parts = derKids(buf, derIs(first, 0x30, "the signing certificate"));
  let k = 0;
  let hash = "SHA-1";
  if (v2) {
    hash = "SHA-256";
    if (parts[k]?.tag === 0x30) hash = TS_HASH[derAlg(buf, parts[k++]).oid];
    if (!hash || hash === "SHA-1") return false;
  }
  if (!tsSame(derIs(parts[k++], 0x04, "a certificate hash").body, await tsDigest(hash, signer.der))) return false;
  const issuerSerial = parts[k];
  if (issuerSerial) {
    const [names, serial] = derKids(buf, derIs(issuerSerial, 0x30, "an issuer and serial"));
    if (!tsSame(derIs(serial, 0x02, "a serial").body, signer.serial)) return false;
    const dirNames = derKids(buf, derIs(names, 0x30, "the issuer names")).filter((n) => n.tag === 0xa4).map((n) => derKids(buf, n)[0].full);
    if (!dirNames.some((n) => tsSame(n, signer.issuer))) return false;
  }
  return true;
}

// Checks one RFC 3161 token: that it is over `imprinted` (SHA-256), signed by a certificate for timestamping only, whose
// chain leads to one of `roots` (from timestampRootFromDer), every certificate valid at the stamped time.
// Result: { status: "valid", time, authority } | { status: "invalid" | "untrusted" | "unsupported", reason }.
// Only a valid token's time is given: any other's time is not evidence of anything.
export async function verifyTimestampToken(tokenBytes, imprinted, roots) {
  const invalid = (reason) => ({ status: "invalid", reason });
  try {
    const buf = tokenBytes instanceof Uint8Array ? tokenBytes : new Uint8Array(tokenBytes);
    if (buf.length > TIMESTAMP_TOKEN_MAX_BYTES) return invalid("its token is larger than a timestamp can be");
    const ci = derAt(buf, 0, buf.length);
    if (ci.end !== buf.length) return invalid("its token has bytes after its end");
    const [ciType, ciContent] = derKids(buf, derIs(ci, 0x30, "the token"));
    if (derOid(ciType) !== TS_OID.signedData) return invalid("its token is not signed data");
    const [sd] = derKids(buf, derIs(ciContent, 0xa0, "the signed data"));
    const sdParts = derKids(buf, derIs(sd, 0x30, "the signed data"));
    let k = 1;
    derIs(sdParts[k++], 0x31, "the digest algorithms");
    const [eType, eWrap] = derKids(buf, derIs(sdParts[k++], 0x30, "the signed content"));
    if (derOid(eType) !== TS_OID.tstInfo) return invalid("its token does not hold a timestamp");
    const [eOctets] = derKids(buf, derIs(eWrap, 0xa0, "the timestamp"));
    derIs(eOctets, 0x04, "the timestamp");
    const certs = [];
    if (sdParts[k]?.tag === 0xa0) {
      const nodes = derKids(buf, sdParts[k++]);
      if (nodes.length > TS_MAX_CERTIFICATES) return invalid("its token carries more certificates than a timestamp needs");
      for (const c of nodes) if (c.tag === 0x30) certs.push(tsCertificate(buf, c));
    }
    if (sdParts[k]?.tag === 0xa1) k++;
    const signerInfos = derKids(buf, derIs(sdParts[k++], 0x31, "the signer list"));
    if (k !== sdParts.length) return invalid("its token carries a part the format does not have");
    if (signerInfos.length !== 1) return invalid("its token does not have exactly one signer");

    const tst = derAt(buf, eOctets.start, eOctets.end);
    if (tst.end !== eOctets.end) return invalid("its timestamp has bytes after its end");
    const tf = derKids(buf, derIs(tst, 0x30, "the timestamp"));
    if (derSmallInt(tf[0], "the timestamp's version") !== 1) return invalid("its timestamp is not version 1");
    derOid(tf[1]);
    const [mAlg, mHash] = derKids(buf, derIs(tf[2], 0x30, "the message imprint"));
    if (derAlg(buf, mAlg).oid !== TS_OID.sha256) return { status: "unsupported", reason: "its timestamp is over a hash other than SHA-256" };
    derIs(tf[3], 0x02, "the timestamp's serial number");
    const genTime = derTime(derIs(tf[4], 0x18, "the timestamp's time"));
    for (const extra of tf.slice(5)) {
      if (extra.tag === 0x30) {
        let ms = 0;
        for (const part of derKids(buf, extra)) {
          if (part.tag === 0x02) ms += derSmallInt(part, "an accuracy") * 1000;
          else if (part.tag === 0x80 || part.tag === 0x81) {
            let v = 0;
            for (const x of part.body) v = v * 256 + x;
            ms += part.tag === 0x80 ? v : v / 1000;
          }
        }
        if (ms > TS_MAX_ACCURACY_MS) return invalid("its authority vouches for its time only to within more than a minute");
      } else if (extra.tag === 0xa1) {
        for (const e of derKids(buf, extra)) {
          const parts = derKids(buf, e);
          if (parts.length === 3 && parts[1].tag === 0x01 && parts[1].body[0] !== 0) {
            return { status: "unsupported", reason: "its timestamp carries a critical extension this checker does not read" };
          }
        }
      }
    }
    if (!tsSame(derIs(mHash, 0x04, "the imprinted hash").body, await tsDigest("SHA-256", imprinted))) {
      return invalid("its timestamp is over other bytes than this checkpoint, its signature and its key");
    }

    const si = derKids(buf, derIs(signerInfos[0], 0x30, "the signer"));
    let s = 1;
    const sid = si[s++];
    const digestHash = TS_HASH[derAlg(buf, si[s++]).oid];
    if (!digestHash || digestHash === "SHA-1") return { status: "unsupported", reason: "its signer uses a digest this checker does not accept" };
    if (si[s]?.tag !== 0xa0) return invalid("its signer signs no attributes");
    const attrsNode = si[s++];
    const sigAlg = derAlg(buf, si[s++]);
    const sigValue = derIs(si[s++], 0x04, "the signer's signature").body;

    let signer;
    if (sid.tag === 0x30) {
      const [iss, ser] = derKids(buf, sid);
      signer = certs.find((c) => tsSame(c.issuer, iss.full) && tsSame(c.serial, ser.body));
    } else if (sid.tag === 0x80) {
      signer = certs.find((c) => c.ext[TS_OID.subjectKeyId] && tsSame(c.ext[TS_OID.subjectKeyId].value.body, sid.body));
    }
    if (!signer) return invalid("its token does not carry the certificate that signed it");

    const attrs = {};
    for (const a of derKids(buf, attrsNode)) {
      const [type, values] = derKids(buf, derIs(a, 0x30, "a signed attribute"));
      const id = derOid(type);
      if (id in attrs) return invalid("its signer signs an attribute twice");
      const vs = derKids(buf, derIs(values, 0x31, "an attribute's values"));
      if (vs.length !== 1) return invalid("a signed attribute does not have exactly one value");
      attrs[id] = vs[0];
    }
    if (!attrs[TS_OID.contentType] || derOid(attrs[TS_OID.contentType]) !== TS_OID.tstInfo) return invalid("its signer does not sign what the token holds");
    if (!attrs[TS_OID.messageDigest]
      || !tsSame(derIs(attrs[TS_OID.messageDigest], 0x04, "the message digest").body, await tsDigest(digestHash, eOctets.body))) {
      return invalid("its timestamp was changed after it was signed");
    }
    if (!(await tsNamesSigner(buf, attrs, signer))) return invalid("its signer does not name the certificate it signed with");
    // Signed as the DER SET the attributes are, not under the [0] tag they are stored with; the bytes are never re-sorted.
    const signedAttrs = new Uint8Array(attrsNode.full);
    signedAttrs[0] = 0x31;
    if (!(await tsVerifyWith(signer, sigAlg, sigValue, signedAttrs, digestHash))) return invalid("its token's signature does not verify");
    const purpose = tsForTimestamping(signer);
    if (purpose) return invalid(purpose);

    // Up from the signer, trying the roots first at every step, so a cross-signed copy of a root in the token is never needed.
    let cur = signer;
    const path = [signer];
    for (let depth = 0; depth < TS_MAX_CHAIN; depth++) {
      if (genTime < cur.notBefore || genTime > cur.notAfter) return invalid(`the certificate of ${cur.subjectText || "its authority"} was not valid at the stamped time`);
      for (const root of roots) {
        if (!tsSame(root.subject, cur.issuer)) continue;
        if (await tsVerifyWith(root, cur.sigAlg, cur.signature, cur.tbs)) {
          if (genTime < root.notBefore || genTime > root.notAfter) return invalid("its authority's root was not valid at the stamped time");
          return { status: "valid", time: new Date(genTime).toISOString(), authority: signer.subjectText };
        }
      }
      let next = null;
      let named = false;
      for (const c of certs) {
        if (path.includes(c) || !tsSame(c.subject, cur.issuer)) continue;
        named = true;
        if (await tsVerifyWith(c, cur.sigAlg, cur.signature, cur.tbs)) {
          next = c;
          break;
        }
      }
      if (!next) {
        if (named) return invalid("a certificate in its token does not verify under its issuer");
        return { status: "untrusted", reason: "its authority's certificates lead to no root this checker holds" };
      }
      const [isCa, pathLen] = tsCaInfo(next);
      if (!isCa || !tsKeyUsage(next, 5)) return invalid(`${next.subjectText || "a certificate"} issues certificates without being a certificate authority`);
      if (pathLen !== undefined && path.length - 1 > pathLen) return invalid(`${next.subjectText || "a certificate authority"} has more authorities below it than it allows`);
      path.push(next);
      cur = next;
    }
    return { status: "untrusted", reason: "its authority's certificate chain is longer than this checker follows" };
  } catch (err) {
    if (err instanceof TsUnsupported) return { status: "unsupported", reason: err.message };
    return invalid(`its token does not read as a timestamp: ${err.message}`);
  }
}

// The roots an outside timestamp may lead to (ADR-0075), as DER in base64: the same set as
// src/Mandate.Shared/Audit/timestamp-roots.json, which the server checks a token against before storing it.
export const TIMESTAMP_ROOTS = [
  { name: "DigiCert Trusted Root G4", sha256: "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988", derBase64: "MIIFkDCCA3igAwIBAgIQBZsbV56OITLiOQe9p3d1XDANBgkqhkiG9w0BAQwFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMTMwODAxMTIwMDAwWhcNMzgwMTE1MTIwMDAwWjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wDQYJKoZIhvcNAQEMBQADggIBALth2X2pbL4XxJEbw6GiAI3jZGgPVs93rnD5/ZpKmbnJeFwMDF/k5hQpVgs2SV1EY+CtnJYYZhsjDT156W1r1lT40jzBQ0CuHVD1UvyQO7uYmWlrx8GnqGikJ9yd+SeuMIW59mdNOj6PWTkiU0TryF0Dyu1Qen1iIQqAyHNm0aAFYF/opbSnr6j3bTWcfFqK1qI4mfN4i/RN0iAL3gTujJtHgXINwBQy7zBZLq7gcfJW5GqXb5JQbZaNaHqasjYUegbyJLkJEVDXCLG4iXqEI2FCKeWjzaIgQdfRnGTZ6iahixTXTBmyUEFxPT9NcCOGDErcgdLMMpSEDQgJlxxPwO5rIHQw0uA5NBCFIRUBCOhVMt5xSdkoF1BN5r5N0XWs0Mr7QbhDparTwwVETyw2m+L64kW4I1NsBm9nVX9GtUw/bihaeSbSpKhil9Ie4u1Ki7wb/UdKDd9nZn6yW0HQO+T0O/QEY+nvwlQAUaCKKsnOeMzV6ocEGLPOr0mIr/OSmbaz5mEP0oUA51Aa5BuVnRmhuZyxm7EAHu/QD09CbMkKvO5D+jpxpchNJqU1/YldvIViHTLSoCtU7ZpXwdv6EM8Zt4tKG48BtieVU+i2iW1bvGjUI+iLUaJW+fCmgKDWHrO8Dw9TdSmq6hN35N6MgSGtBxBHEa2HPQfRdbzP82Z+" },
];

// The bytes a checkpoint's token is over: its signed payload, then its signature, then its public key.
export function checkpointTimestampImprint(bundle) {
  const payload = buildCheckpointSignedPayload(bundle.tenantId, bundle.windowStartEventId, bundle.windowEndEventId, bundle.eventCount,
    hexToBytes(bundle.merkleRootHex));
  const signature = hexToBytes(bundle.signatureHex);
  const key = base64ToBytes(bundle.publicKeyBase64);
  if (signature.length !== 64 || key.length !== 32) throw new Error("its signature or key is not the length Ed25519 gives");
  const out = new Uint8Array(payload.length + 96);
  out.set(payload, 0);
  out.set(signature, payload.length);
  out.set(key, payload.length + 64);
  return out;
}

let shippedTimestampRoots = null;

// Extra roots (DER bytes) are ones the person checking chose to trust, such as their own authority's.
export async function checkpointTimestamp(bundle, extraRoots = []) {
  const token = bundle.timestampTokenBase64;
  if (token === undefined || token === null) return { status: "absent" };
  if (typeof token !== "string") return { status: "invalid", reason: "its timestampTokenBase64 is not text" };
  shippedTimestampRoots ??= TIMESTAMP_ROOTS.map((r) => timestampRootFromDer(base64ToBytes(r.derBase64)));
  let roots = shippedTimestampRoots;
  try {
    roots = [...shippedTimestampRoots, ...extraRoots.map(timestampRootFromDer)];
  } catch (err) {
    return { status: "unsupported", reason: `a root you named is not a certificate: ${err.message}` };
  }
  let tokenBytes;
  let imprinted;
  try {
    tokenBytes = base64ToBytes(token);
    imprinted = checkpointTimestampImprint(bundle);
  } catch (err) {
    return { status: "invalid", reason: `its timestamp cannot be read: ${err.message}` };
  }
  return verifyTimestampToken(tokenBytes, imprinted, roots);
}

// Different authorities' clocks differ by a second or so; a checkpoint replaced after a key leak is out of order by far more.
export const TIMESTAMP_ORDER_TOLERANCE_MS = 5 * 60 * 1000;
// Mandate asks for a token a few minutes after signing, and signs within about an hour of a record; past a day, a token
// still proves the checkpoint existed by its time, but not that it was sealed when its records were made.
export const TIMESTAMP_LATE_MS = 24 * 60 * 60 * 1000;
// The newest checkpoints may have no token yet when an export is made: up to two hours of records before it.
export const TIMESTAMP_TAIL_ALLOWANCE_MS = 2 * 60 * 60 * 1000;

// Over the checkpoints of one export, in the order of the records they seal (`position`, from chain/links.json; a
// checkpoint the records file does not cover has none and is left out of the order). Mandate stamps a tenant's
// checkpoints one after another in that order and never goes back, so honest token times never fall along the chain
// and no checkpoint without a token sits before one with a token. Either is what a checkpoint replaced or a token removed
// after the fact looks like: `problem` then says which. `lastRecordMs` is the time of the last record the checkpoint seals.
export function timestampSequence(entries, generatedAtMs, require = false) {
  const placed = entries.filter((e) => Number.isInteger(e.position)).sort((a, b) => a.position - b.position);
  const out = {
    stamped: 0,
    absent: [],
    untrusted: [],
    late: [],
    notPlaced: entries.filter((e) => !Number.isInteger(e.position)).length,
    authorities: [],
    provenThrough: null,
    problem: null,
    notVerified: null,
    gapUnchecked: null,
  };
  let newest = null;
  let gap = null;
  for (const e of placed) {
    const s = e.timestamp?.status;
    if (s === "valid") {
      const t = Date.parse(e.timestamp.time);
      if (gap && gap.absent && !out.problem) {
        out.problem = `checkpoint ${gap.checkpointId} has no outside timestamp, though checkpoint ${e.checkpointId}, which seals later records, has one: `
          + "Mandate stamps checkpoints in the order of their records, so it was replaced, or its timestamp removed, after the later one was stamped";
      } else if (gap && !gap.absent && !out.gapUnchecked) {
        out.gapUnchecked = { checkpointId: gap.checkpointId, later: e.checkpointId };
      }
      if (newest && t < newest.t - TIMESTAMP_ORDER_TOLERANCE_MS && !out.problem) {
        out.problem = `checkpoint ${e.checkpointId} was stamped on ${new Date(t).toISOString()}, before checkpoint ${newest.checkpointId}, which seals `
          + `earlier records, was stamped on ${new Date(newest.t).toISOString()}: a checkpoint stamped after a later one was replaced after the fact`;
      }
      if (!newest || t > newest.t) newest = { t, checkpointId: e.checkpointId };
      out.stamped++;
      if (!out.authorities.includes(e.timestamp.authority)) out.authorities.push(e.timestamp.authority);
      if (Number.isFinite(e.lastRecordMs)) {
        if (t - e.lastRecordMs > TIMESTAMP_LATE_MS) out.late.push({ checkpointId: e.checkpointId, hours: Math.floor((t - e.lastRecordMs) / 3600000) });
        out.provenThrough = { recordMs: e.lastRecordMs, stampedMs: t };
      }
    } else if (s === "absent" || s === "untrusted" || s === "unsupported") {
      (s === "absent" ? out.absent : out.untrusted).push({ checkpointId: e.checkpointId, lastRecordMs: e.lastRecordMs, reason: e.timestamp.reason });
      gap ??= { checkpointId: e.checkpointId, absent: s === "absent" };
    }
  }
  for (const e of entries.filter((x) => !Number.isInteger(x.position))) {
    const s = e.timestamp?.status;
    if (s === "valid") {
      out.stamped++;
      if (!out.authorities.includes(e.timestamp.authority)) out.authorities.push(e.timestamp.authority);
    } else if (s === "absent") out.absent.push({ checkpointId: e.checkpointId });
    else if (s === "untrusted" || s === "unsupported") out.untrusted.push({ checkpointId: e.checkpointId, reason: e.timestamp.reason });
  }
  // A timestamp this checker cannot check, before one it can: the order cannot be judged without that authority's root.
  if (out.gapUnchecked && !out.problem) {
    out.notVerified = `checkpoint ${out.gapUnchecked.checkpointId} carries a timestamp this checker cannot check, before checkpoint `
      + `${out.gapUnchecked.later}, which has one it can: name its authority's root with --timestamp-root`;
  }
  if (require && !out.problem && !out.notVerified) {
    const waiting = out.absent.filter((a) => !(Number.isFinite(a.lastRecordMs) && Number.isFinite(generatedAtMs)
      && a.lastRecordMs >= generatedAtMs - TIMESTAMP_TAIL_ALLOWANCE_MS));
    if (out.untrusted.length > 0) out.notVerified = `${out.untrusted.length} checkpoint(s) carry a timestamp this checker cannot check`;
    else if (waiting.length > 0) out.notVerified = `${waiting.length} checkpoint(s) more than two hours older than this export have no outside timestamp`;
    else if (out.late.length > 0) out.notVerified = `${out.late.length} checkpoint(s) were stamped more than a day after their last record`;
  }
  return out;
}

export const SUPPORTED_CHECKPOINT_SCHEMA_VERSION = 2;
const READ_CHECKPOINT_SCHEMA_VERSIONS = [1, 2];

export function isCheckpointName(name) {
  return /\.json$/i.test(String(name ?? ""));
}

const CHECKPOINT_FIELDS = ["schemaVersion", "checkpointId", "tenantId", "windowStartEventId", "windowEndEventId", "windowStartOccurredAt",
  "windowEndOccurredAt", "eventCount", "merkleRootHex", "signatureHex", "publicKeyBase64", "publicKeyFingerprint", "createdAt"];

export async function verifyCheckpointFileBytes(bytes, options = {}) {
  const notCheckpoint = (detail) => ({
    kind: "checkpoint",
    overall: "invalid",
    signature: { status: "invalid", reason: `it is not a Mandate checkpoint: ${detail}` },
  });
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return { ...notCheckpoint("it does not read as JSON"), unreadable: true };
  }
  if (value !== null && typeof value === "object" && Number.isSafeInteger(value.schemaVersion)
    && !READ_CHECKPOINT_SCHEMA_VERSIONS.includes(value.schemaVersion)) {
    return {
      kind: "checkpoint",
      overall: "unsupported",
      format: value.schemaVersion,
      signature: {
        status: "unsupported",
        reason: `this checkpoint is format ${value.schemaVersion}; this verifier reads formats ${READ_CHECKPOINT_SCHEMA_VERSIONS.join(" and ")}. Use the verifier released with the checkpoint, or the latest from mandateco.ca/verify.html`,
      },
    };
  }
  let bundle;
  try {
    bundle = validateCheckpointBundle(value);
  } catch (err) {
    return notCheckpoint(err.message.replace(/^checkpoint bundle field /, "its field ").replace(/^checkpoint bundle /, "it "));
  }
  const fields = bundle.schemaVersion === 1 ? CHECKPOINT_FIELDS : [...CHECKPOINT_FIELDS, "timestampTokenBase64"];
  const extra = Object.keys(bundle).filter((k) => !fields.includes(k));
  if (extra.length > 0) return notCheckpoint(`it carries ${extra.join(", ")}, which a checkpoint does not`);
  if (bundle.schemaVersion !== 1 && !("timestampTokenBase64" in bundle)) return notCheckpoint("its field timestampTokenBase64 is missing");
  let publicKeyFingerprint;
  try {
    publicKeyFingerprint = await sha256Hex(base64ToBytes(bundle.publicKeyBase64));
  } catch {
    publicKeyFingerprint = undefined;
  }
  const signature = await verifyCheckpointBundle(bundle);
  const timestamp = signature.status === "valid" ? await checkpointTimestamp(bundle, options.timestampRoots) : undefined;
  const timestampNotVerified = options.requireTimestamps && timestamp && timestamp.status !== "valid" && timestamp.status !== "invalid"
    ? (timestamp.status === "absent" ? "the checkpoint has no outside timestamp" : "its timestamp cannot be checked here")
    : undefined;
  return {
    kind: "checkpoint",
    overall: timestamp?.status === "invalid" ? "invalid" : signature.status,
    signature,
    timestamp,
    timestampNotVerified,
    publicKeyFingerprint,
    checkpoint: {
      checkpointId: bundle.checkpointId,
      tenantId: bundle.tenantId,
      windowStartEventId: bundle.windowStartEventId,
      windowEndEventId: bundle.windowEndEventId,
      eventCount: bundle.eventCount,
      merkleRootHex: bundle.merkleRootHex,
      windowStartOccurredAt: bundle.windowStartOccurredAt,
      windowEndOccurredAt: bundle.windowEndOccurredAt,
      createdAt: bundle.createdAt,
    },
  };
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

function u32Bytes(n) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, n);
  return bytes;
}

// What a version changed, as layout v2 seals it: a keyword list's change by its counts, never its entries. Every
// field a change can carry is sealed, so one the trail never has is refused rather than read past.
const TRAIL_CHANGE_FIELDS = ["kind", "ruleId", "reason", "from", "to", "added", "removed", "addedCount", "removedCount"];
function trailChanges(changes) {
  if (changes === null || changes === undefined) return null;
  if (!Array.isArray(changes)) throw new Error("it is malformed");
  const text = (v) => (v === null || v === undefined ? null : UTF8.encode(String(v)));
  const entries = (list) => {
    if (list === null || list === undefined) return null;
    if (!Array.isArray(list) || list.some((e) => typeof e !== "string")) throw new Error("it is malformed");
    return concatBytes(u32Bytes(list.length), ...list.map((e) => sealField(UTF8.encode(e))));
  };
  const count = (v) => v === null || v === undefined || (Number.isInteger(v) && v >= 0);
  return concatBytes(u32Bytes(changes.length), ...changes.map((c) => {
    if (typeof c?.kind !== "string" || typeof c.ruleId !== "string" || !count(c.addedCount) || !count(c.removedCount)) throw new Error("it is malformed");
    if (c.kind === "keywords" && (c.added != null || c.removed != null)) throw new Error("it names a list's entries, which the change trail never carries");
    const extra = Object.keys(c).find((k) => !TRAIL_CHANGE_FIELDS.includes(k));
    if (extra !== undefined) throw new Error(`a change carries a field the change trail never has (${extra})`);
    return concatBytes(sealField(UTF8.encode(c.kind)), sealField(UTF8.encode(c.ruleId)), sealOptional(text(c.reason)), sealOptional(text(c.from)),
      sealOptional(text(c.to)), sealOptional(entries(c.added)), sealOptional(entries(c.removed)), sealOptional(text(c.addedCount)),
      sealOptional(text(c.removedCount)));
  }));
}

// What a mandate entry approves or ends, as layout v3 seals it after v2's fields (2.11.0): its code, its tools (each a
// server and a tool, or a whole server that includes the tools it adds later or awaits its first list), its purposes and
// dates, and on an end what the agent does next and the mandate that took it over. Every field it can carry is sealed, so
// one the trail never has is refused rather than read past.
const TRAIL_MANDATE_FIELDS = ["slug", "tools", "purposes", "validFrom", "validUntil", "then", "successor"];
const TRAIL_MANDATE_TOOL_FIELDS = ["server", "tool", "includesLaterTools", "awaitingFirstList"];
function trailMandate(m) {
  if (m === null || m === undefined) return null;
  if (typeof m !== "object" || Array.isArray(m) || typeof m.slug !== "string") throw new Error("it is malformed");
  const extra = Object.keys(m).find((k) => !TRAIL_MANDATE_FIELDS.includes(k));
  if (extra !== undefined) throw new Error(`a mandate entry carries a field the change trail never has (${extra})`);
  const text = (v) => (v === null || v === undefined ? null : UTF8.encode(String(v)));
  const flag = (v) => {
    if (v !== null && v !== undefined && typeof v !== "boolean") throw new Error("it is malformed");
    return v === true;
  };
  const instant = (v) => {
    if (v === null || v === undefined) return null;
    const ticks = instantTicks(v);
    if (ticks === null) throw new Error("it is malformed");
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigInt64(0, ticks);
    return bytes;
  };
  const list = (v, each) => {
    if (v === null || v === undefined) return null;
    if (!Array.isArray(v)) throw new Error("it is malformed");
    return concatBytes(u32Bytes(v.length), ...v.map(each));
  };
  const tools = list(m.tools, (t) => {
    if (typeof t?.server !== "string" || (t.tool !== null && t.tool !== undefined && typeof t.tool !== "string")) throw new Error("it is malformed");
    const extraTool = Object.keys(t).find((k) => !TRAIL_MANDATE_TOOL_FIELDS.includes(k));
    if (extraTool !== undefined) throw new Error(`a mandate entry's tool carries a field the change trail never has (${extraTool})`);
    return concatBytes(sealField(UTF8.encode(t.server)), sealOptional(text(t.tool)),
      sealField(Uint8Array.of((flag(t.includesLaterTools) ? 1 : 0) | (flag(t.awaitingFirstList) ? 2 : 0))));
  });
  const purposes = list(m.purposes, (p) => {
    if (typeof p !== "string") throw new Error("it is malformed");
    return sealField(UTF8.encode(p));
  });
  return concatBytes(sealField(UTF8.encode(m.slug)), sealOptional(tools), sealOptional(purposes), sealOptional(instant(m.validFrom)),
    sealOptional(instant(m.validUntil)), sealOptional(text(m.then)), sealOptional(text(m.successor)));
}

// What a concluded assessment's entry fixes, as layout v4 seals it after v2's fields (2.12.0): the assessment's
// id and the SHA-256 of its canonical document. Every field it can carry is sealed, so one the trail never has is refused
// rather than read past; an entry never carries both a mandate's facts and an assessment's.
const TRAIL_ASSESSMENT_FIELDS = ["assessmentId", "sha256"];
function trailAssessment(a) {
  if (a === null || a === undefined) return null;
  if (typeof a !== "object" || Array.isArray(a) || typeof a.assessmentId !== "string" || !/^[0-9a-f]{64}$/.test(String(a.sha256))) throw new Error("it is malformed");
  const extra = Object.keys(a).find((k) => !TRAIL_ASSESSMENT_FIELDS.includes(k));
  if (extra !== undefined) throw new Error(`an assessment entry carries a field the change trail never has (${extra})`);
  const sha = new Uint8Array(32);
  for (let i = 0; i < 32; i++) sha[i] = parseInt(a.sha256.slice(2 * i, 2 * i + 2), 16);
  return concatBytes(sealField(uuidToRfc4122Bytes(a.assessmentId)), sealField(sha));
}

// What a governance record's entry fixes, as layout v5 seals it after v2's fields (2.13.0): a finding's
// review or a version of an artifact, by its kind, its id and the SHA-256 of its canonical document. Every field it can carry
// is sealed, so one the trail never has is refused rather than read past; an entry carries at most one of a mandate's, an
// assessment's and a record's facts.
const TRAIL_RECORD_FIELDS = ["kind", "id", "sha256"];
function trailRecord(r) {
  if (r === null || r === undefined) return null;
  if (typeof r !== "object" || Array.isArray(r) || typeof r.kind !== "string" || r.kind.length === 0 || typeof r.id !== "string"
    || !/^[0-9a-f]{64}$/.test(String(r.sha256))) throw new Error("it is malformed");
  const extra = Object.keys(r).find((k) => !TRAIL_RECORD_FIELDS.includes(k));
  if (extra !== undefined) throw new Error(`a record entry carries a field the change trail never has (${extra})`);
  const sha = new Uint8Array(32);
  for (let i = 0; i < 32; i++) sha[i] = parseInt(r.sha256.slice(2 * i, 2 * i + 2), 16);
  return concatBytes(sealField(UTF8.encode(r.kind)), sealField(uuidToRfc4122Bytes(r.id)), sealField(sha));
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
  const mandate = trailMandate(row.mandate);
  const assessment = trailAssessment(row.assessment);
  const record = trailRecord(row.record);
  if ([mandate, assessment, record].filter((x) => x !== null).length > 1) throw new Error("it is malformed");
  return sha256Bytes(concatBytes(
    UTF8.encode(mandate !== null ? "mandate.change-trail-entry.v3" : assessment !== null ? "mandate.change-trail-entry.v4"
      : record !== null ? "mandate.change-trail-entry.v5" : "mandate.change-trail-entry.v2"), Uint8Array.of(0),
    sealField(uuidToRfc4122Bytes(String(row.id))), sealField(uuidToRfc4122Bytes(String(tenantId))), sealField(time),
    sealField(UTF8.encode(row.action)), sealField(UTF8.encode(row.actorType)),
    sealOptional(uuid(row.actorId)), sealOptional(actorSeal), sealOptional(text(row.mutationReason)),
    sealOptional(text(t?.kind)), sealOptional(text(t?.reason)), sealOptional(uuid(t?.policyId)),
    sealOptional(uuid(t?.versionId)), sealOptional(uuid(t?.priorVersionId)), sealOptional(text(t?.version)),
    sealOptional(trailChanges(t?.changes)), ...(mandate === null ? [] : [sealOptional(mandate)]), ...(assessment === null ? [] : [sealOptional(assessment)]),
    ...(record === null ? [] : [sealOptional(record)])));
}

// 2.17.0 (ADR-0071 §14): the sealed documents the pack's assessment files carry, each as the exact text Mandate hashed: an
// assessment's document and the record of a finding's review, an artifact version, a measure's value and a version of an
// impact assessment. Each is recomputed and must equal the hash beside it and the hash its change-trail entry carries,
// whose seal the entry check ties to the records; the readable row beside it must say what the document says, so a reader
// can trust either. A file not cut holds every document the change trail seals in its period, but for those deleted with
// their AI system, which it names, so a document left out fails.
const SEALED_RESULTS = [["met", "met"], ["partiallyMet", "partially_met"], ["notMet", "not_met"], ["notApplicable", "not_applicable"],
  ["unableToDetermine", "unable_to_determine"]];
const sameValue = (a, b) => (a ?? null) === (b ?? null);
const sameOptionalId = (a, b) => (a == null && b == null) || (a != null && b != null && sameMandateId(a, b));
const sameTexts = (a, b) => JSON.stringify(a ?? []) === JSON.stringify(b ?? []);
const lowerOrNull = (v) => (v == null ? null : String(v).toLowerCase());
const sameOptionalInstant = (a, b) => (a == null && b == null) || (a != null && b != null && sameInstant(a, b));

function assessmentDiffers(row, doc) {
  const h = doc.assessment;
  const findings = doc.findings;
  if (!h || typeof h !== "object" || !Array.isArray(findings)) return [["document", false]];
  const readable = Array.isArray(row.findings) ? row.findings : [];
  const confidences = findings.map((f) => f?.confidence?.value).filter((v) => typeof v === "number");
  const coverage = h.snapshot?.coverage?.value;
  return [
    ["AI system", sameOptionalId(row.aiSystemId, h.aiSystemId)],
    ["framework", sameOptionalId(row.frameworkId, h.frameworkId) && sameOptionalId(row.frameworkVersionId, h.frameworkVersionId)],
    ["trigger", sameValue(row.trigger, h.trigger)],
    ["period", sameInstant(h.windowFrom, row.windowFrom) && sameInstant(h.windowTo, row.windowTo)],
    ["time", sameInstant(h.concludedAt, row.concludedAt)],
    ["counts", row.requirements === findings.length && SEALED_RESULTS.every(([k, v]) => row[k] === findings.filter((f) => f?.result === v).length)],
    ["confidence", sameValue(row.confidence, confidences.length ? Math.min(...confidences) : null)],
    // The row's coverage is stored to four decimal places.
    ["coverage", typeof row.coverage === "number" && typeof coverage === "number" && Math.abs(row.coverage - coverage) <= 0.00005 + 1e-9],
    ["findings", readable.length === findings.length],
    ...findings.map((f, i) => [`finding ${f?.label ?? i + 1}`, readable.length !== findings.length || (sameValue(readable[i]?.requirementId, f?.requirementId)
      && sameValue(readable[i]?.label, f?.label) && sameValue(readable[i]?.result, f?.result) && sameValue(readable[i]?.reason, f?.reason)
      && sameValue(readable[i]?.confidence, f?.confidence?.value))]),
  ];
}

function reviewDiffers(row, doc) {
  return [
    ["assessment", sameOptionalId(row.assessmentId, doc.assessmentId)],
    ["finding", sameOptionalId(row.findingId, doc.findingId) && sameValue(row.requirementId, doc.requirementId)],
    ["action", sameValue(row.action, doc.action)],
    ["result", sameValue(row.result, doc.result) && sameValue(row.confidence, doc.confidence)],
    ["reviewer", sameOptionalId(row.reviewerId, doc.reviewerId) && sameTexts(row.reviewerRoles, doc.reviewerRoles)],
    ["time", sameInstant(doc.createdAt, row.createdAt)],
  ];
}

function artifactDiffers(row, doc) {
  const file = (f) => (f == null ? null : JSON.stringify([f.name ?? null, f.contentType ?? null, f.size ?? null, lowerOrNull(f.sha256)]));
  const links = (list, id) => (Array.isArray(list) ? list : []).map((l) => JSON.stringify([l?.target ?? null, lowerOrNull(id(l)),
    lowerOrNull(l?.frameworkId), l?.requirementId ?? null])).sort();
  return [
    ["version", sameOptionalId(row.lineageId, doc.lineageId) && sameValue(row.version, doc.artifactVersion) && sameOptionalId(row.supersedesId, doc.supersedesId)],
    ["kind", sameValue(row.kind, doc.kind)],
    ["title", sameValue(row.title, doc.title)],
    ["description", sameValue(row.description, doc.description)],
    ["link", sameValue(row.link, doc.link)],
    ["file", file(row.file) === file(doc.file)],
    ["statement", sameValue(row.statement, doc.statement)],
    ["status", sameValue(row.status, doc.status) && sameValue(row.externalRef, doc.externalRef)],
    ["dates", sameValue(row.effectiveOn, doc.effectiveOn) && sameValue(row.reviewBy, doc.reviewBy)],
    ["withdrawn", sameValue(row.withdrawn, doc.withdrawn)],
    ["supplier", sameOptionalId(row.suppliedBy, doc.suppliedBy) && sameValue(row.suppliedRole, doc.suppliedRole) && sameTexts(row.suppliedRoles, doc.suppliedRoles)],
    ["time", sameInstant(doc.createdAt, row.createdAt)],
    // A link names one target; the record names it by one id. 2.20.0: a breach's link names its measure value.
    ["links", sameTexts(links(row.links, (l) => l?.aiSystemId ?? l?.controlId ?? l?.findingId ?? l?.measureValueId), links(doc.links, (l) => l?.id))],
  ];
}

function measureValueDiffers(row, doc) {
  return [
    ["measure", sameOptionalId(row.measureId, doc.measureId) && sameOptionalId(row.aiSystemId, doc.aiSystemId) && sameValue(row.source, doc.source)],
    ["value", sameValue(row.value, doc.value) && sameValue(row.status, doc.status)],
    ["period", sameInstant(doc.observedAt, row.observedAt) && sameOptionalInstant(doc.windowFrom, row.windowFrom) && sameOptionalInstant(doc.windowTo, row.windowTo)],
    ["test run", sameOptionalId(row.testSetRunId, doc.testSetRunId)],
    ["supplier", sameOptionalId(row.suppliedBy, doc.suppliedBy) && sameTexts(row.suppliedRoles, doc.suppliedRoles)],
    ["time", sameInstant(doc.createdAt, row.createdAt)],
  ];
}

function impactAssessmentDiffers(row, doc) {
  return [
    ["AI system", sameOptionalId(row.aiSystemId, doc.aiSystemId)],
    ["version", sameValue(row.version, doc.assessmentVersion)],
    ["questionnaire", sameValue(row.source, doc.source) && sameValue(row.questionnaireVersion, doc.questionnaireVersion) && sameValue(row.fileVersion, doc.fileVersion)],
    ["scores", sameValue(row.rawImpactScore, doc.rawImpactScore) && sameValue(row.mitigationScore, doc.mitigationScore)
      && sameValue(row.currentScore, doc.currentScore) && sameValue(row.mitigationDeducted, doc.mitigationDeducted)],
    ["level", sameValue(row.level, doc.level)],
    ["date completed", sameValue(row.completedOn, doc.completedOn)],
    ["supplier", sameOptionalId(row.suppliedBy, doc.suppliedBy) && sameTexts(row.suppliedRoles, doc.suppliedRoles)],
    ["time", sameInstant(doc.createdAt, row.createdAt)],
  ];
}

const SEALED_DOCUMENTS = [
  { key: "assessments", file: "assessments/findings.json", list: "assessments", noun: "assessment", text: "document", sha: "contentSha256",
    facts: (e) => (e?.assessment ? { id: e.assessment.assessmentId, sha256: e.assessment.sha256 } : null), differs: assessmentDiffers },
  { key: "reviews", file: "assessments/reviews.json", list: "reviews", noun: "review", text: "record", sha: "contentSha256",
    facts: (e) => (e?.record?.kind === "finding_review" ? e.record : null), differs: reviewDiffers },
  { key: "artifacts", file: "assessments/artifacts.json", list: "artifacts", noun: "artifact version", text: "record", sha: "recordSha256",
    facts: (e) => (e?.record?.kind === "artifact" ? e.record : null), differs: artifactDiffers },
  { key: "measureValues", file: "assessments/measure-values.json", list: "values", noun: "measure value", text: "record", sha: "recordSha256",
    facts: (e) => (e?.record?.kind === "measure_value" ? e.record : null), differs: measureValueDiffers },
  { key: "impactAssessments", file: "assessments/impact-assessments.json", list: "impactAssessments", noun: "impact assessment version", text: "record",
    sha: "recordSha256", facts: (e) => (e?.record?.kind === "impact_assessment" ? e.record : null), differs: impactAssessmentDiffers },
];

// Every entry naming a document is read against the document the file carries, so a row pointed at another entry, or at
// none, cannot hide one rewritten after it was sealed; a document's entry absent or not sealed in this export leaves it
// counted apart, since nothing outside the file vouches for it.
async function checkSealedDocuments(read, has, entries, sealed, period) {
  const result = {};
  const assessmentHashes = new Map();
  const carried = new Map();
  for (const spec of SEALED_DOCUMENTS) {
    if (!has(spec.file)) {
      result[spec.key] = null;
      continue;
    }
    const fail = (reason) => ({ reason: `${spec.file}: ${reason}` });
    const file = read(spec.file);
    if (!file || typeof file !== "object" || Array.isArray(file) || !Number.isSafeInteger(file.schemaVersion)) return fail("it is malformed");
    const counts = { matched: 0, notChecked: 0, removed: 0, truncated: file.truncated === true, notCompared: "" };
    result[spec.key] = counts;
    if (file.schemaVersion !== 1) {
      counts.notCompared = `${spec.file} is version ${file.schemaVersion}; this checker reads version 1`;
      continue;
    }
    const rows = file[spec.list];
    if (!Array.isArray(rows) || (file.removed !== undefined && !Array.isArray(file.removed))) return fail("it is malformed");
    const docs = new Map();
    for (const row of rows) {
      if (!row || typeof row !== "object" || typeof row.id !== "string" || !UUID_RE.test(row.id) || typeof row.auditEntryId !== "string"
        || !UUID_RE.test(row.auditEntryId) || typeof row[spec.text] !== "string" || typeof row[spec.sha] !== "string") {
        return fail("a row is malformed");
      }
      const id = row.id.toLowerCase();
      if (docs.has(id)) return fail(`${spec.noun} ${id} appears twice`);
      const digest = await sha256Hex(UTF8.encode(row[spec.text]));
      if (digest !== row[spec.sha]) return fail(`${spec.noun} ${id}: its ${spec.text} does not match its SHA-256`);
      let doc;
      try {
        doc = JSON.parse(row[spec.text]);
      } catch {
        return fail(`${spec.noun} ${id}: its ${spec.text} does not read as JSON`);
      }
      if (!doc || typeof doc !== "object" || doc.version !== 1) {
        return fail(`${spec.noun} ${id}: its ${spec.text} is version ${doc?.version}; this checker reads version 1`);
      }
      // The seal is read first: a document that differs from it is the finding that matters, whatever its row says.
      const entryId = row.auditEntryId.toLowerCase();
      const entry = entries.get(entryId);
      const facts = entry ? spec.facts(entry) : null;
      if (entry && (!facts || !sameMandateId(facts.id, id))) return fail(`${spec.noun} ${id}: its change-trail entry ${entryId} records something else`);
      if (facts && facts.sha256 !== digest) return fail(`${spec.noun} ${id} differs from its sealed record`);
      const docId = spec.key === "assessments" ? doc.assessment?.id : doc.id;
      const differs = [["id", sameOptionalId(row.id, docId)], ...spec.differs(row, doc)].filter(([, same]) => !same).map(([word]) => word);
      if (differs.length > 0) return fail(`${spec.noun} ${id}: the readable row differs from its sealed ${spec.text}: its ${differs.join(", ")}`);
      if (spec.key === "assessments") assessmentHashes.set(id, digest);
      // A review names the document it reviewed, so it can be read against the one this pack carries.
      const reviewed = spec.key === "reviews" ? assessmentHashes.get(lowerOrNull(row.assessmentId)) : undefined;
      if (reviewed !== undefined && doc.assessmentSha256 !== reviewed) {
        return fail(`review ${id} names a different document for assessment ${lowerOrNull(row.assessmentId)} than the one assessments/findings.json carries`);
      }
      docs.set(id, { digest, entryId, doc, row });
      if (entry && sealed.has(entryId)) counts.matched++;
      else counts.notChecked++;
    }
    // A system's deletion takes its documents with it while their entries stay, so the file names each one it took and the
    // entry that recorded the deletion.
    const removed = new Set();
    for (const r of file.removed ?? []) {
      if (!r || typeof r !== "object" || [r.id, r.auditEntryId, r.deletedBy].some((v) => typeof v !== "string" || !UUID_RE.test(v))) {
        return fail("a deleted document is malformed");
      }
      const id = r.id.toLowerCase();
      if (docs.has(id) || removed.has(id)) return fail(`${spec.noun} ${id} is both carried and said to be deleted, or said to be deleted twice`);
      const entry = entries.get(r.auditEntryId.toLowerCase());
      const facts = entry ? spec.facts(entry) : null;
      if (entry && (!facts || !sameMandateId(facts.id, id))) {
        return fail(`${spec.noun} ${id}: its change-trail entry ${r.auditEntryId.toLowerCase()} records something else`);
      }
      const deletion = entries.get(r.deletedBy.toLowerCase());
      if (deletion && deletion.action !== "ai_system.deleted") {
        return fail(`${spec.noun} ${id} is said to be deleted with its AI system by entry ${r.deletedBy.toLowerCase()}, which records no such deletion`);
      }
      // A deletion inside the period is in the change trail unless the trail was cut, so its absence then is a claim nothing backs.
      const at = instantTicks(r.deletedAt);
      if (!deletion && period.trailComplete && period.from !== null && period.to !== null && at !== null && at >= period.from && at <= period.to) {
        return fail(`${spec.noun} ${id} is said to be deleted with its AI system by entry ${r.deletedBy.toLowerCase()}, which the change trail of its period does not carry`);
      }
      removed.add(id);
      counts.removed++;
    }
    carried.set(spec, { docs, removed, complete: !counts.truncated });
  }
  // Every row is checked first, so an entry that names the wrong document is reported on that document.
  for (const [spec, { docs, removed, complete }] of carried) {
    for (const [entryId, entry] of entries) {
      const facts = spec.facts(entry);
      if (!facts) continue;
      const id = lowerOrNull(facts.id);
      const doc = docs.get(id);
      if (doc && facts.sha256 !== doc.digest) return { reason: `${spec.file}: ${spec.noun} ${id} differs from its sealed record` };
      if (doc && doc.entryId !== entryId) {
        return { reason: `${spec.file}: ${spec.noun} ${id} names change-trail entry ${doc.entryId}, but entry ${entryId} seals it` };
      }
      if (!doc && complete && !removed.has(id)) {
        return { reason: `${spec.file}: it leaves out ${spec.noun} ${id}, which change-trail entry ${entryId} seals` };
      }
    }
  }
  const decisions = checkReviewDecisions(carried, entries, period);
  return decisions ?? result;
}

// 2.19.0 (ADR-0071 §8): a finding's review decision and an assessment's sign-off are columns Mandate keeps beside the sealed
// records, so each is read against them. A pack shows them as its window left them. Each finding must show the decision
// its latest sealed review of the window gives, or none when no review decides it, whenever the reviews file is whole. An
// assessment shows as signed off exactly when every finding has a decision, at the time and by the person of the last one,
// and the change trail's sign-off (a record of kind assessment_sign_off, sealed by v5 with the assessment's id and its
// document's hash) must name the document the pack carries; with the trail whole, a sign-off it does not carry fails.
const SIGN_OFF_KIND = "assessment_sign_off";
const REVIEW_DECISIONS = ["accept", "reject", "change"];
function reviewDecision(r) {
  if (r.action === "accept") return { state: "accepted", result: r.computedResult ?? null, confidence: r.computedConfidence ?? null };
  if (r.action === "reject") return { state: "rejected", result: null, confidence: null };
  const result = r.result ?? null;
  // A change of the result alone keeps the computed confidence only where the result is still the computed one.
  return { state: "changed", result, confidence: r.confidence ?? (result === r.computedResult ? r.computedConfidence ?? null : null) };
}

function checkReviewDecisions(carried, entries, period) {
  const part = (key) => [...carried].find(([spec]) => spec.key === key)?.[1];
  const assessments = part("assessments")?.docs;
  if (!assessments) return null;
  const fail = (reason) => ({ reason: `assessments/findings.json: ${reason}` });
  const signOffs = new Map();
  for (const [entryId, e] of entries) {
    if (e?.record?.kind !== SIGN_OFF_KIND) continue;
    const id = lowerOrNull(e.record.id);
    const carriedOne = assessments.get(id);
    if (!carriedOne) continue;
    if (e.record.sha256 !== carriedOne.digest) return fail(`assessment ${id}: its sign-off, change-trail entry ${entryId}, names another document`);
    if (signOffs.has(id)) return fail(`assessment ${id} is signed off by two change-trail entries, ${signOffs.get(id)[0]} and ${entryId}`);
    signOffs.set(id, [entryId, e]);
  }
  const reviews = part("reviews");
  const latest = new Map();
  for (const { doc } of reviews?.complete ? reviews.docs.values() : []) {
    if (!REVIEW_DECISIONS.includes(doc.action)) continue;
    const key = `${lowerOrNull(doc.assessmentId)}/${lowerOrNull(doc.findingId)}`;
    const before = latest.get(key);
    if (!before || (instantTicks(doc.createdAt) ?? -1n) >= (instantTicks(before.createdAt) ?? -1n)) latest.set(key, doc);
  }
  for (const [id, { row }] of assessments) {
    const signedOff = row.status === "signed_off";
    if (!signedOff && row.status !== "concluded") return fail(`assessment ${id}: its status is ${row.status}, which no assessment has`);
    if ((row.signedOffAt != null) !== signedOff || (row.signedOffBy != null) !== signedOff) {
      return fail(`assessment ${id}: its status and its sign-off time and person do not agree`);
    }
    const [entryId, entry] = signOffs.get(id) ?? [];
    if (entry && !(signedOff && sameInstant(entry.occurredAt, row.signedOffAt))) {
      return fail(`assessment ${id} does not show the sign-off change-trail entry ${entryId} records`);
    }
    if (signedOff && !entry && period.trailComplete) return fail(`assessment ${id} is shown signed off, and the change trail of its period carries no sign-off of it`);
    if (!reviews?.complete) continue;
    const findings = Array.isArray(row.findings) ? row.findings : [];
    const held = new Set();
    let last = null;
    let undecided = 0;
    for (const [i, f] of findings.entries()) {
      const findingId = lowerOrNull(f?.id);
      held.add(findingId);
      const label = f?.label ?? i + 1;
      const r = latest.get(`${id}/${findingId}`);
      if (!r) {
        undecided++;
        if ([f?.reviewState, f?.reviewedResult, f?.reviewedConfidence, f?.reviewedAt, f?.reviewedBy].some((v) => v != null)) {
          return fail(`assessment ${id}: finding ${label} shows a review decision, and no sealed review of it gives one`);
        }
        continue;
      }
      const d = reviewDecision(r);
      if (!(sameValue(f.reviewState, d.state) && sameValue(f.reviewedResult, d.result) && sameValue(f.reviewedConfidence, d.confidence)
        && sameOptionalInstant(r.createdAt, f.reviewedAt) && sameOptionalId(f.reviewedBy, r.reviewerId) && sameValue(f.requirementId, r.requirementId))) {
        return fail(`assessment ${id}: finding ${label} differs from its latest sealed review, ${lowerOrNull(r.id)}`);
      }
      if (!last || (instantTicks(r.createdAt) ?? -1n) >= (instantTicks(last.createdAt) ?? -1n)) last = r;
    }
    for (const key of latest.keys()) {
      const [of, finding] = key.split("/");
      if (of === id && !held.has(finding)) return fail(`assessment ${id}: a sealed review decides finding ${finding}, which the assessment does not hold`);
    }
    if (signedOff && undecided > 0) {
      return fail(`assessment ${id} is shown signed off, and no sealed review decides ${undecided} of its findings`);
    }
    if (signedOff && (last === null || !(sameInstant(last.createdAt, row.signedOffAt) && sameOptionalId(row.signedOffBy, last.reviewerId)))) {
      return fail(`assessment ${id}: its sign-off is not the decision that left no finding undecided`);
    }
    if (!signedOff && findings.length > 0 && undecided === 0) {
      return fail(`assessment ${id}: a sealed review decides every finding, and the assessment is not shown signed off`);
    }
  }
  return null;
}

// What an export holds only part of, named in the same words by the script and the page, so a file cut at its size limit
// is never read as a whole period.
export function partialParts(result) {
  const sd = result.chain?.sealedDocuments;
  return [["register", result.truncated], ["records", result.chain?.truncated], ["checkpoints", result.checkpointsTruncated],
    ["change trail", result.mutationsTruncated], ["final decisions", result.chain?.finalDecisions?.truncated],
    ["assessments", sd?.assessments?.truncated], ["reviews of findings", sd?.reviews?.truncated], ["artifact versions", sd?.artifacts?.truncated],
    ["measure values", sd?.measureValues?.truncated], ["impact assessment versions", sd?.impactAssessments?.truncated]]
    .filter(([, cut]) => cut === true).map(([part]) => part);
}

// The script and the page say the same words for these files, so the two never describe one pack differently.
export function sealedDocumentsLines(sd) {
  if (!sd) return [];
  const many = (n, one, other) => `${n} ${n === 1 ? one : other}`;
  const kinds = [["assessments", "assessment", "assessments"], ["reviews", "review of a finding", "reviews of findings"],
    ["artifacts", "artifact version", "artifact versions"], ["measureValues", "measure value", "measure values"],
    ["impactAssessments", "impact assessment version", "impact assessment versions"]].filter(([key]) => sd[key]);
  const lines = kinds.filter(([key]) => sd[key].notCompared)
    .map(([key, , other]) => ({ tag: "[ -- ]", label: `the ${other} were not compared: ${sd[key].notCompared}` }));
  const compared = kinds.filter(([key]) => !sd[key].notCompared);
  if (compared.length === 0) return lines;
  const named = (field) => compared.filter(([key]) => sd[key][field] > 0).map(([key, one, other]) => many(sd[key][field], one, other))
    .join(", ").replace(/, ([^,]*)$/, " and $1");
  const sum = (field) => compared.reduce((n, [key]) => n + (sd[key][field] ?? 0), 0);
  const [total, notChecked, removed] = [sum("matched"), sum("notChecked"), sum("removed")];
  const cut = compared.filter(([key]) => sd[key].truncated).map(([key]) => SEALED_DOCUMENTS.find((s) => s.key === key).file);
  const parts = [
    ...(total > 0 ? [`${named("matched")} ${total === 1 ? "matches its sealed record" : "match their sealed records"}`] : []),
    ...(notChecked > 0 ? [`${named("notChecked")} not checked (not sealed in the records file yet or outside it)`] : []),
    ...(removed > 0 ? [`${named("removed")} deleted with an AI system`] : []),
    ...(cut.length > 0 ? [`${cut.join(" and ")} hold${cut.length === 1 ? "s" : ""} the earliest of ${cut.length === 1 ? "its" : "their"} period only`] : []),
  ];
  if (total + notChecked + removed === 0 && cut.length === 0) {
    parts.push(`no ${compared.map(([, , other]) => other).join(", ").replace(/, ([^,]*)$/, " or $1")} were recorded in this period`);
  }
  return [...lines, { tag: total === 0 && (notChecked > 0 || cut.length > 0) ? "[ -- ]" : "[ ok ]", label: parts.join("; ") }];
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

function sameMandateId(a, b) {
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

// 2.16.0 (ADR-0073 §8): the final decisions a department's case system sent, each request one batch whose record's
// SHA-256 rides a change-trail entry sealed like any other. A decision is salted, so one case can be shown and checked
// alone without disclosing the others; an erased decision keeps only its digest in its batch's list. A batch whose entry
// is not sealed in this export's records is counted apart and never passes, since nothing outside the file vouches for it.
const FINAL_DECISIONS_FILE = "assessments/final-decisions.json";
const FINAL_DECISIONS_ACTION = "final_decisions.recorded";
const FINAL_DECISIONS_KIND = "final_decisions";
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

function finalDecisionBatches(file) {
  return file?.schemaVersion === 1 && Array.isArray(file.batches) ? file.batches : [];
}

async function checkFinalDecisions(file, changeRecords, tenantId) {
  const fail = (reason) => ({ reason: `${FINAL_DECISIONS_FILE}: ${reason}` });
  if (!file || typeof file !== "object" || Array.isArray(file) || !Number.isSafeInteger(file.schemaVersion)) return fail("it is malformed");
  const result = { batches: 0, decisions: 0, erased: 0, notChecked: 0, truncated: file.truncated === true, notCompared: "" };
  if (file.schemaVersion !== 1) return { ...result, notCompared: `${FINAL_DECISIONS_FILE} is version ${file.schemaVersion}; this checker reads version 1` };
  if (!Array.isArray(file.batches)) return fail("it is malformed");
  const ofTenant = (v) => tenantId === undefined || sameMandateId(v, tenantId);
  const seen = new Set();
  for (const b of file.batches) {
    if (!b || typeof b !== "object" || [b.batchId, b.aiSystemId, b.entryId].some((v) => typeof v !== "string" || !UUID_RE.test(v))
      || typeof b.record !== "string" || !Array.isArray(b.decisions) || !b.entry || typeof b.entry !== "object") return fail("a batch is malformed");
    const id = b.batchId.toLowerCase();
    if (seen.has(id)) return fail(`batch ${id} appears twice`);
    seen.add(id);
    const entry = b.entry;
    if (entry.action !== FINAL_DECISIONS_ACTION || entry.record?.kind !== FINAL_DECISIONS_KIND) {
      return fail(`batch ${id}: its change-trail entry does not record final decisions`);
    }
    if (!sameMandateId(entry.record.id, b.batchId)) return fail(`batch ${id}: its change-trail entry names another batch`);
    if (!sameMandateId(entry.id, b.entryId)) return fail(`batch ${id}: its change-trail entry is not entry ${b.entryId}`);
    if (await sha256Hex(UTF8.encode(b.record)) !== entry.record.sha256) return fail(`batch ${id} differs from its sealed record`);

    let record;
    try {
      record = JSON.parse(b.record);
    } catch {
      return fail(`batch ${id}: its record does not read as JSON`);
    }
    if (record?.version !== 1) return fail(`batch ${id}: its record is version ${record?.version}; this checker reads version 1`);
    if (!ofTenant(record.tenantId)) return fail(`batch ${id}: its record names Mandate ID ${record.tenantId}, not this export's Mandate ID ${tenantId}`);
    const receivedAt = instantTicks(record.receivedAt);
    const differs = [
      ["batch id", sameMandateId(record.batchId, b.batchId)],
      ["AI system", sameMandateId(record.aiSystemId, b.aiSystemId)],
      ["time", receivedAt !== null && receivedAt === instantTicks(b.receivedAt)],
    ].filter(([, same]) => !same).map(([word]) => word);
    if (differs.length > 0) return fail(`batch ${id}: its record differs from the batch: its ${differs.join(", ")}`);
    const listed = record.decisionSha256s;
    if (!Array.isArray(listed) || listed.some((d, i) => typeof d !== "string" || !LOWER_HEX_64.test(d) || (i > 0 && !(listed[i - 1] < d)))) {
      return fail(`batch ${id}: its record does not list its decisions' digests in order, each once`);
    }

    const carried = new Set();
    let decisions = 0;
    let erased = 0;
    for (const d of b.decisions) {
      const digest = typeof d?.sha256 === "string" && LOWER_HEX_64.test(d.sha256) ? d.sha256 : null;
      if (digest === null) return fail(`batch ${id}: a decision carries no digest`);
      if (carried.has(digest)) return fail(`batch ${id} carries decision ${digest} twice`);
      carried.add(digest);
      if (!listed.includes(digest)) return fail(`batch ${id} carries decision ${digest}, which its sealed record does not list`);
      if (d.erased === true) {
        erased++;
        continue;
      }
      if (typeof d.salt !== "string" || !/^[0-9a-fA-F]{64}$/.test(d.salt) || typeof d.document !== "string") {
        return fail(`batch ${id}: decision ${digest} carries no salt or no document`);
      }
      if (bytesToHex(await sha256Bytes(concatBytes(hexToBytes(d.salt), UTF8.encode(d.document)))) !== digest) {
        return fail(`batch ${id}: decision ${digest} differs from its sealed digest`);
      }
      let document;
      try {
        document = JSON.parse(d.document);
      } catch {
        return fail(`batch ${id}: decision ${digest} does not read as JSON`);
      }
      if (!ofTenant(document?.tenantId)) return fail(`batch ${id}: decision ${digest} names Mandate ID ${document?.tenantId}, not this export's Mandate ID ${tenantId}`);
      const other = [["batch", sameMandateId(document.batchId, b.batchId)], ["AI system", sameMandateId(document.aiSystemId, b.aiSystemId)]]
        .filter(([, same]) => !same).map(([word]) => word);
      if (other.length > 0) return fail(`batch ${id}: decision ${digest} names another ${other.join(" and ")}`);
      decisions++;
    }
    const missing = listed.find((d) => !carried.has(d));
    if (missing !== undefined) return fail(`batch ${id} leaves out decision ${missing}, which its sealed record lists`);

    if (!changeRecords.has(b.entryId.toLowerCase())) {
      result.notChecked++;
      continue;
    }
    result.batches++;
    result.decisions += decisions;
    result.erased += erased;
  }
  return result;
}

// The script and the page say the same words for the file, so the two never describe one pack differently.
export function finalDecisionsLine(fd) {
  if (!fd) return null;
  if (fd.notCompared) return { tag: "[ -- ]", label: `the final decisions were not compared: ${fd.notCompared}` };
  if (fd.batches + fd.notChecked === 0) return { tag: "[ ok ]", label: "no final decisions were received in this period" };
  const many = (n, one, other) => `${n} ${n === 1 ? one : other}`;
  const notChecked = (batch, batches) => `${many(fd.notChecked, batch, batches)} not checked `
    + `(${fd.notChecked === 1 ? "its sealed record is" : "their sealed records are"} outside this export)`;
  const cut = fd.truncated ? "; this export holds the earliest batches of its period only" : "";
  if (fd.batches === 0) return { tag: "[ -- ]", label: `${notChecked("batch of final decisions", "batches of final decisions")}${cut}` };
  const matched = `${many(fd.decisions, "final decision", "final decisions")} in ${many(fd.batches, "batch", "batches")} `
    + `${fd.decisions === 1 ? "matches its sealed record" : "match their sealed records"}`;
  return {
    tag: "[ ok ]",
    label: `${matched}${fd.erased ? `, ${fd.erased} erased` : ""}${fd.notChecked ? `, ${notChecked("batch", "batches")}` : ""}${cut}`,
  };
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
        if (expect.tenantId !== undefined && !sameMandateId(recordUuid(record.tenant_id), expect.tenantId)) {
          return invalid(`record ${id} names Mandate ID ${recordUuid(record.tenant_id)}, not this export's Mandate ID ${expect.tenantId}`);
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
  const checkpointWindows = [];
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
    const lastAt = links[end].at;
    checkpointWindows.push({
      checkpointId: String(checkpoint.checkpointId).toLowerCase(),
      position: end,
      lastRecordMs: typeof lastAt === "bigint" ? Number(lastAt / 10000n) : undefined,
    });
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
  const finalDecisionsFile = read(FINAL_DECISIONS_FILE);
  const changeSources = [
    ["mutations/policy-trail.json", read("mutations/policy-trail.json")],
    ["register/decisions.json", (read("register/decisions.json") ?? []).filter((row) => row?.source === "mutation")],
    ["chain/erasures.json", erasureEntries],
    [FINAL_DECISIONS_FILE, finalDecisionBatches(finalDecisionsFile).map((b) => b?.entry)],
  ];
  const changesTiedIds = new Set();
  const changesNotTiedIds = new Set();
  for (const [file, list] of changeSources) {
    for (const row of Array.isArray(list) ? list : []) {
      if (!row || typeof row.id !== "string") return invalid(`${file} holds a change-trail entry with no id`);
      const id = row.id.toLowerCase();
      // Whether or not its seal is in this export yet, an entry never names a list's entries, nor a mandate, assessment or record fact no seal covers.
      try {
        trailChanges(row.transition?.changes);
        trailMandate(row.mandate);
        trailAssessment(row.assessment);
        trailRecord(row.record);
      } catch (err) {
        return invalid(`change-trail entry ${row.id} in ${file} cannot be checked: ${err.message}`);
      }
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

  const finalDecisions = fileBytes.has(FINAL_DECISIONS_FILE) ? await checkFinalDecisions(finalDecisionsFile, changeRecords, expect.tenantId) : null;
  if (finalDecisions?.reason) return invalid(finalDecisions.reason);

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

  const trailEntries = new Map();
  for (const [, list] of changeSources) {
    for (const row of Array.isArray(list) ? list : []) if (typeof row?.id === "string") trailEntries.set(row.id.toLowerCase(), row);
  }
  const sealedDocuments = await checkSealedDocuments(read, (name) => fileBytes.has(name), trailEntries, changesTiedIds, {
    from: instantTicks(expect.windowFrom), to: instantTicks(expect.windowTo), trailComplete: expect.mutationsPartial === false,
  });
  if (sealedDocuments.reason) return invalid(sealedDocuments.reason);

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
  // 2.8.0: the activity the report says the firm's other AI tools reported, recomputed from the pack's own
  // imports/<feed>.json: the feeds it carries, the rows imported in the window (when the file holds them all), the rows a
  // rule fired on, and the earliest and latest vendor times; summary/decision-mix.json's imports block says the same.
  // 2.15.0: a version 2 file lists Mandate's own notes on reading a row (notes) apart from the rules that fired on it
  // (ruleHits), told apart by the prefix no rule a customer writes may carry, and the figures add the rows Mandate could
  // not read in full. A version 1 file, as packs made before it carry, is recomputed as it always was, its notes counted
  // among the rule hits as they were made; a later version is not compared, and the result says why.
  let importsCompared = false;
  let importsNotCompared = "";
  const reportSummary = read("report/summary.json");
  if (reportSummary) {
    const byFeed = reportSummary.imported?.byFeed;
    if (!Array.isArray(byFeed)) return invalid("report/summary.json does not say what other AI tools reported");
    const instant = (v) => (v === null || v === undefined ? null : Date.parse(String(v)));
    const key = (f) => JSON.stringify([f?.feed, f?.rows, f?.rowsWithRuleHits, f?.rowsNotReadInFull ?? null, f?.coversWindow,
      instant(f?.sourceFrom), instant(f?.sourceTo)]);
    const mix = read("summary/decision-mix.json");
    const carried = [...fileBytes.keys()].filter((n) => /^imports\/[^/]+\.json$/.test(n)).map((n) => n.slice(8, -5)).sort();
    const later = carried.map((feed) => [feed, read(`imports/${feed}.json`)?.schemaVersion]).find(([, v]) => Number.isSafeInteger(v) && v > 2);
    if (later) importsNotCompared = `imports/${later[0]}.json is version ${later[1]}; this checker reads versions 1 and 2`;
    else {
      for (const feed of carried) {
        const file = read(`imports/${feed}.json`);
        if (file?.schemaVersion !== 2 || !Array.isArray(file.rows)) continue;
        if (file.rows.some((r) => Array.isArray(r?.ruleHits) && r.ruleHits.some((id) => typeof id === "string" && id.startsWith(NOTE_PREFIX)))) {
          return invalid(`imports/${feed}.json: a row lists one of Mandate's own notes among the rules that fired on it`);
        }
        if (file.rows.some((r) => Array.isArray(r?.notes) && r.notes.some((id) => typeof id !== "string" || !id.startsWith(NOTE_PREFIX)))) {
          return invalid(`imports/${feed}.json: a row lists a rule among Mandate's own notes on reading it`);
        }
      }
      const recomputed = (f) => {
        const file = read(`imports/${f?.feed}.json`);
        if (!file || !Array.isArray(file.rows)) return false;
        const v2 = file.schemaVersion === 2;
        // Only a version 2 file's figures count the rows not read in full, so the count can be neither dropped nor added.
        if (v2 !== (f.rowsNotReadInFull !== undefined)) return false;
        if (v2 && !file.rows.every((r) => Array.isArray(r?.ruleHits) && Array.isArray(r?.notes))) return false;
        const fired = file.rows.filter((r) => Array.isArray(r?.ruleHits) && r.ruleHits.length > 0).length;
        const unread = v2 ? file.rows.filter((r) => r.notes.includes(NOT_READ_NOTE)).length : 0;
        if (file.truncated === true) {
          // Cut at its row cap, the file holds some of the rows the figures count: no figure may be lower than those
          // rows give, or higher than all the rows.
          const within = (n, held) => Number.isInteger(n) && n >= held && n <= f.rows;
          return Number.isInteger(f.rows) && f.rows >= file.rows.length && within(f.rowsWithRuleHits, fired) && (!v2 || within(f.rowsNotReadInFull, unread));
        }
        const times = file.rows.map((r) => instant(r?.sourceTime)).filter((t) => t !== null && !Number.isNaN(t));
        return f.rows === file.rows.length
          && f.rowsWithRuleHits === fired
          && (!v2 || f.rowsNotReadInFull === unread)
          && instant(f.sourceFrom) === (times.length ? Math.min(...times) : null)
          && instant(f.sourceTo) === (times.length ? Math.max(...times) : null);
      };
      const packed = mix?.imports;
      if ((mix && (!Array.isArray(packed) || byFeed.length !== packed.length || byFeed.some((f, i) => key(f) !== key(packed[i]))))
        || byFeed.length !== carried.length || byFeed.some((f, i) => f?.feed !== carried[i] || !recomputed(f))) {
        return invalid("report/summary.json: the activity it says other AI tools reported does not match the pack's imports");
      }
      importsCompared = true;
    }
    if (expect.inProgress !== undefined && (reportSummary.period?.inProgress === true) !== expect.inProgress) {
      return invalid(expect.inProgress
        ? "report/summary.json does not say that its period had not ended when the record was made"
        : "report/summary.json says that its period had not ended when the record was made, but the record was made after it ended");
    }
  }

  const periodFrom = instantTicks(expect.windowFrom);
  const periodTo = instantTicks(expect.windowTo);
  const inPeriod = (t) => periodFrom === null || periodTo === null || (t !== null && t >= periodFrom && t <= periodTo);
  for (const l of links) if (!l.record && inPeriod(l.at)) erasures.get(l.erasedBy).removedInPeriod++;
  const kinds = { decisions: 0, answers: 0, imported: 0, changes: 0, tests: 0 };
  const outcomes = {};
  for (const l of links) {
    if (!l.record) continue;
    const outcome = recordText(l.record.policy_decision);
    if (outcome === "result") kinds.answers++;
    else if (outcome === "imported") kinds.imported++;
    else if (outcome === "change") kinds.changes++;
    else if (outcome === "test") kinds.tests++;
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
    checkpointWindows,
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
    sealedDocuments,
    summaryCompared,
    summaryNotCompared,
    importsCompared,
    importsNotCompared,
    finalDecisions,
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
      // 2.9.0: each change-trail entry's change record, so a later export that shows the record erased explains the
      // entry's absence: the change record is kept as long as the AI-use records and goes with them.
      changeLinks: new Map(links.filter((l) => l.record && recordText(l.record.policy_decision) === "change")
        .map((l) => [recordUuid(l.record.correlation_id), l.id])),
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
    if (key === "actorSalt" || (gone && words[key] === "who acted")) continue;
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
    return j.register.rows.has(id) || (live && live.outcome !== "result" && live.outcome !== "imported" && live.outcome !== "test");
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
    const noun = erased.every((e) => e.outcome !== "result" && e.outcome !== "imported" && e.outcome !== "test") ? "decision" : "record";
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
        // 2.9.0: an entry whose change record the other export shows erased left with it, under the retention
        // setting; the erased record is named among the erasures.
        const link = jx.changeLinks.get(id);
        if (link !== undefined && jy.byId.has(link) && !jy.live.has(link)) continue;
        if (!jy[key].has(id) && withinSpan(cover.span, entry.at)) {
          // 2.9.0: an entry still queued for its seal when one export was made is tied to no record in it, so its
          // absence from the other is not held against it unless the other carries its change record still.
          if (link === undefined && !jy.changeLinks.has(id)) {
            notes.push(`change-trail entry ${id} (${entry.row.action}) of ${x.name} was not yet sealed when ${x.name} was made and is not in ${y.name}: not compared`);
            continue;
          }
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

function packReach(result) {
  return result.inProgress ? Date.parse(result.identity?.generatedAt) - 60000 : Date.parse(result.identity?.windowTo);
}

export function sequenceProgress(packs) {
  const ends = packs.map((p) => Date.parse(p.result.identity?.windowTo));
  const reached = packs.map((p) => packReach(p.result));
  if (packs.length === 0 || [...ends, ...reached].some((t) => Number.isNaN(t))) return { inProgress: false };
  const end = Math.max(...ends);
  const reach = Math.max(...reached);
  return reach < end ? { inProgress: true, recordedUntil: new Date(reach).toISOString() } : { inProgress: false };
}

export function checkPackSequence(packs) {
  const ordered = [...packs].sort((a, b) => Date.parse(a.result.identity?.windowFrom ?? 0) - Date.parse(b.result.identity?.windowFrom ?? 0));
  const notes = [];
  const erased = [];
  for (let i = 1; i < ordered.length; i++) {
    const a = ordered[i - 1];
    const b = ordered[i];
    const fail = (kind, detail, extra = {}) => ({ status: "invalid", kind, reason: `${a.name} then ${b.name}: ${detail}`, detail, ...extra });
    if (!sameMandateId(a.result.identity?.tenantId, b.result.identity?.tenantId)) return fail("mandate-id", "the packs have different Mandate IDs");
    if (a.result.publicKeyFingerprint !== b.result.publicKeyFingerprint && !(a.trusted === true && b.trusted === true)) {
      return fail("key", "the packs are signed by different keys");
    }
    const gap = Date.parse(b.result.identity?.windowFrom) - Date.parse(a.result.identity?.windowTo);
    if (!(gap <= 1)) return fail("gap", "the windows leave a gap between them");
    if (a.result.inProgress && !(Date.parse(b.result.identity?.windowFrom) - packReach(a.result) <= 1)) {
      return fail("gap", `${a.name} was made at ${a.result.identity.generatedAt}, before its period ended at ${a.result.identity.windowTo}, and covers it to a minute before then, so the time after is in neither`);
    }
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
  return { status: "valid", packs: ordered.length, notes, erased, ...sequenceProgress(ordered) };
}

export async function verifyEvidencePackBytes(zipBytes, inflateRaw, options = {}) {
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
      actual !== entry.sha256Hex.toLowerCase()
        ? { path: entry.filename, status: "invalid", reason: "SHA-256 does not match manifest" }
        : bytes.length !== entry.byteLength
          ? { path: entry.filename, status: "invalid", reason: "length does not match manifest" }
          : { path: entry.filename, status: "valid" },
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
      let result = sameMandateId(bundle.tenantId, manifest.tenantId)
        ? await verifyCheckpointBundle(bundle)
        : { status: "invalid", reason: `it names Mandate ID ${bundle.tenantId}, not this export's Mandate ID ${manifest.tenantId}` };
      if (result.status === "valid" && bundle.schemaVersion !== 1 && !("timestampTokenBase64" in bundle)) {
        result = { status: "invalid", reason: "its field timestampTokenBase64 is missing" };
      }
      const timestamp = result.status === "valid" ? await checkpointTimestamp(bundle, options.timestampRoots) : undefined;
      if (timestamp?.status === "invalid") result = { status: "invalid", reason: `its outside timestamp: ${timestamp.reason}` };
      checkpoints.push({
        checkpointId: bundle.checkpointId,
        publicKeyFingerprint: checkpointFingerprint,
        result,
        timestamp,
      });
    } catch (err) {
      checkpoints.push({
        checkpointId: name,
        publicKeyFingerprint: undefined,
        result: { status: "invalid", reason: `checkpoint parse failed: ${err.message}` },
      });
    }
  }

  const made = Date.parse(manifest.generatedAt);
  const inProgress = made < Date.parse(manifest.windowTo);
  const notBegun = inProgress && made < Date.parse(manifest.windowFrom);
  const chain = await verifyChainFiles(fileBytes, {
    tenantId: manifest.tenantId,
    registerPartial: Boolean(manifest.truncated),
    mutationsPartial: Boolean(manifest.mutationsTruncated),
    windowFrom: manifest.windowFrom,
    windowTo: manifest.windowTo,
    inProgress,
  });
  const windows = new Map((chain.checkpointWindows ?? []).map((w) => [w.checkpointId, w]));
  const timestamps = timestampSequence(
    checkpoints.filter((c) => c.timestamp !== undefined).map((c) => ({
      checkpointId: String(c.checkpointId).toLowerCase(),
      position: windows.get(String(c.checkpointId).toLowerCase())?.position,
      lastRecordMs: windows.get(String(c.checkpointId).toLowerCase())?.lastRecordMs,
      timestamp: c.timestamp,
    })),
    made,
    options.requireTimestamps === true,
  );
  const checkpointKeysDiffer = manifestFingerprint !== undefined
    && checkpoints.some((c) => c.publicKeyFingerprint !== undefined && c.publicKeyFingerprint !== manifestFingerprint);

  const anyUnsupported =
    manifestResult.status === "unsupported" || checkpoints.some((c) => c.result.status === "unsupported");
  const anyInvalid =
    manifestResult.status === "invalid"
    || files.some((f) => f.status !== "valid")
    || checkpoints.some((c) => c.result.status === "invalid")
    || timestamps.problem !== null
    || chain.status === "invalid";

  return {
    manifest: manifestResult,
    files,
    checkpoints,
    chain,
    timestamps,
    overall: anyUnsupported ? "unsupported" : anyInvalid ? "invalid" : "valid",
    publicKeyFingerprint: manifestFingerprint,
    checkpointKeysDiffer,
    truncated: manifest.truncated,
    checkpointsTruncated: manifest.checkpointsTruncated,
    mutationsTruncated: manifest.mutationsTruncated,
    inProgress,
    notBegun,
    identity: {
      tenantId: manifest.tenantId,
      generatedAt: manifest.generatedAt,
      windowFrom: manifest.windowFrom ?? null,
      windowTo: manifest.windowTo ?? null,
    },
  };
}


export const DSR_ACCESS_SIGNED_PAYLOAD_DOMAIN_V4 = "mandate.dsr.access-manifest-sig.v4";

export const SUPPORTED_DSR_MANIFEST_VERSION = 3;

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
    if (!Number.isSafeInteger(c.byteLength) || c.byteLength < 0) throw new Error(`invalid content ${c.filename} byteLength: ${c.byteLength}`);
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
  if (manifest.manifestVersion !== SUPPORTED_DSR_MANIFEST_VERSION) {
    return {
      manifest: {
        status: "unsupported",
        reason: `this access record is format ${manifest.manifestVersion}; this verifier reads format ${SUPPORTED_DSR_MANIFEST_VERSION}. Use the verifier released with the record, or the latest from mandateco.ca/verify.html`,
      },
      files: [],
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
      actual !== entry.sha256Hex.toLowerCase()
        ? { path: entry.filename, status: "invalid", reason: "SHA-256 does not match manifest" }
        : bytes.length !== entry.byteLength
          ? { path: entry.filename, status: "invalid", reason: "length does not match manifest" }
          : { path: entry.filename, status: "valid" },
    );
  }

  const listed = new Set(manifest.contents.map((c) => c.filename));
  for (const name of fileBytes.keys()) {
    if (name === "manifest.json" || listed.has(name)) continue;
    files.push({ path: name, status: "invalid", reason: "file present in pack but not listed in manifest.contents" });
  }

  const MANIFEST_FIELDS = ["manifestVersion", "tenantId", "subjectHashHex", "generatedAt", "windowFrom", "windowTo", "truncated", "unscannableRows",
    "degradedRows", "partiallyScannableRows", "opaqueRegions", "opaqueBytes", "contents", "signatureHex", "publicKeyBase64", "publicKeyFingerprint"];
  const unsignedFields = Object.keys(manifest).filter((k) => !MANIFEST_FIELDS.includes(k));
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
    if (manifestResult.status === "valid" && unsignedFields.length > 0) {
      manifestResult = { status: "invalid", reason: `manifest.json carries ${unsignedFields.join(", ")}, which its signature does not cover` };
    } else if (manifestResult.status === "valid" && manifest.publicKeyFingerprint !== undefined
      && String(manifest.publicKeyFingerprint).toLowerCase() !== manifestFingerprint) {
      manifestResult = { status: "invalid", reason: "manifest.publicKeyFingerprint names another key than the one that signed it" };
    }
  } catch (err) {
    manifestResult = { status: "invalid", reason: `manifest verification failed: ${err.message}` };
  }

  const anyInvalid = manifestResult.status === "invalid" || files.some((f) => f.status !== "valid");
  const made = Date.parse(manifest.generatedAt);
  const inProgress = made < Date.parse(manifest.windowTo);
  return {
    manifest: manifestResult,
    files,
    overall: manifestResult.status === "unsupported" ? "unsupported" : anyInvalid ? "invalid" : "valid",
    publicKeyFingerprint: manifestFingerprint,
    subjectHashHex: manifest.subjectHashHex,
    inProgress,
    notBegun: inProgress && made < Date.parse(manifest.windowFrom),
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

// 2.15.0: the names an archive's directory lists, read from its end through readAt(offset, length), which returns those
// bytes, so an archive of any size is never read whole. Nothing here is trusted: the names only decide what the verifier
// says of a file that is not a record. Null when the bytes do not end as a ZIP archive does.
export async function readZipNames(size, readAt) {
  if (!Number.isSafeInteger(size) || size < 22) return null;
  const tailAt = Math.max(0, size - 65557);
  const tail = await readAt(tailAt, size - tailAt);
  const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);
  let end = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === 0x06054b50 && view.getUint16(i + 20, true) === tail.length - (i + 22)) {
      end = i;
      break;
    }
  }
  if (end === -1) return null;
  let count = view.getUint16(end + 10, true);
  let dirSize = view.getUint32(end + 12, true);
  let dirAt = view.getUint32(end + 16, true);
  if (count === 0xffff || dirSize === 0xffffffff || dirAt === 0xffffffff) {
    // A ZIP64 archive: the locator just before the end record points at the ZIP64 end record, which holds the values.
    if (end < 20 || view.getUint32(end - 20, true) !== 0x07064b50) return null;
    const recordAt = Number(view.getBigUint64(end - 12, true));
    if (!Number.isSafeInteger(recordAt) || recordAt + 56 > size) return null;
    const record = await readAt(recordAt, 56);
    if (record.length < 56) return null;
    const r = new DataView(record.buffer, record.byteOffset, record.byteLength);
    if (r.getUint32(0, true) !== 0x06064b50) return null;
    count = Number(r.getBigUint64(32, true));
    dirSize = Number(r.getBigUint64(40, true));
    dirAt = Number(r.getBigUint64(48, true));
  }
  if (!Number.isSafeInteger(dirAt) || !Number.isSafeInteger(dirSize) || dirSize > ZIP_MAX_TOTAL_BYTES || dirAt + dirSize > size) return null;
  const dir = await readAt(dirAt, dirSize);
  const d = new DataView(dir.buffer, dir.byteOffset, dir.byteLength);
  const dec = new TextDecoder();
  const names = [];
  let pos = 0;
  for (let i = 0; i < count; i++) {
    if (pos + 46 > dir.length || d.getUint32(pos, true) !== 0x02014b50) return null;
    const nameLength = d.getUint16(pos + 28, true);
    const next = pos + 46 + nameLength + d.getUint16(pos + 30, true) + d.getUint16(pos + 32, true);
    if (next > dir.length) return null;
    names.push(dec.decode(dir.subarray(pos + 46, pos + 46 + nameLength)));
    pos = next;
  }
  return names;
}

const PART_NAME = /^part-(\d+)-of-(\d+)\.zip$/;

// Which part is not there, and how many are not, or which is there twice, when every name given is one a complete export
// gives its parts; null when any is not. The names are not signed: this says what was handed over, not whether anything
// changed.
function partNumbering(names) {
  const read = names.map((n) => PART_NAME.exec(n));
  if (read.length === 0 || read.some((m) => !m || m[2] !== read[0][2])) return null;
  const of = Number(read[0][2]);
  const numbers = read.map((m) => Number(m[1]));
  if (!Number.isSafeInteger(of) || of < 1 || numbers.some((k) => k < 1 || k > of)) return null;
  const name = (k) => `part-${String(k).padStart(read[0][1].length, "0")}-of-${read[0][2]}.zip`;
  const seen = new Set();
  let twice = null;
  for (const k of numbers) {
    if (seen.has(k)) twice ??= name(k);
    seen.add(k);
  }
  let firstMissing = null;
  for (let k = 1; k <= of && firstMissing === null; k++) if (!seen.has(k)) firstMissing = name(k);
  return { of, missing: of - seen.size, firstMissing, twice };
}

// 2.15.0: why records named as the parts of one complete export cannot stand for all of it, or "" when they can or are
// not named so.
export function partsMissing(names) {
  const n = partNumbering(names);
  if (!n) return "";
  if (n.twice) return `${n.twice} was given twice`;
  if (n.missing === 0) return "";
  return `${n.firstMissing}${n.missing > 1 ? ` and ${n.missing - 1} more are` : " is"} missing, so ${n.of - n.missing} of the ${n.of} parts were given`;
}

// 2.15.0: a complete export, the archive the console downloads for a long period (ADR-0032), is known by what it holds,
// whatever it is named: records named part-K-of-N.zip and no manifest.json, the rule the console's own check uses. It
// is not signed, so it is never checked as a record. Null for anything else.
export function completeExportOf(names) {
  if (!Array.isArray(names) || names.includes("manifest.json")) return null;
  const parts = names.filter((n) => PART_NAME.test(n)).sort();
  if (parts.length === 0) return null;
  const n = partNumbering(parts);
  return { parts: parts.length, of: n?.of ?? null, first: parts[0], last: parts[parts.length - 1], missing: n?.missing ?? 0,
    firstMissing: n?.firstMissing ?? null };
}

const VERIFIER_CORE_END = "VERIFIER-CORE-END";

function usage() {
  return [
    "Usage: node mandate-verify.mjs <record.zip | checkpoint.json | folder> [...] [--expect-fingerprint <hex>]... [--timestamp-root <file>]... [--require-timestamps] [--json] [--version]",
    "",
    "--expect-fingerprint names the fingerprint from your agreement: 64 hex characters, plain or in pairs separated by colons or spaces.",
    "Give it more than once after a key change: every key in a record, its checkpoints included, must be one you named.",
    "",
    "Several records are checked one by one and then together: the parts of one complete export, or an earlier and a later export.",
    "They must have one Mandate ID, be signed by one key or by keys you named, leave no gap between their periods, each continue from the one before,",
    "and no record or change-trail entry one holds inside the time the other covers may be missing from the other or read differently there;",
    "a decision's readable row, the person included, must read the same in both.",
    "Each export covers its period up to a minute before it says it was made, or only the span its records hold when it says it is partial;",
    "what that leaves out is named, and so is any decision erased between the exports.",
    "An export made before its period ended is in progress: it holds what was recorded up to when it was made, and says so.",
    "A later export must then start no later than when the one in progress was made, or the time between is in neither.",
    "A folder stands for every record in it, in name order: unzip a complete export and give the verifier its folder. A folder is checked one neighbour at a time, so a long export needs no more memory than two parts.",
    "A complete export downloaded as one archive is known by what it holds, whatever its name: unzip it and give the verifier the folder.",
    "Parts named as a complete export names them (part-0001-of-0012.zip) must all be there: a part missing is named.",
    "",
    "Checks a Mandate signed record or access record offline (the kind is read off the manifest). Exit codes:",
    "  0 valid, signed by a key you named   1 invalid or fingerprint mismatch   2 usage/IO/ZIP error, or a complete export given as one file",
    "  3 not checked: a format this verifier does not read (DIFFERENT FORMAT), or no Ed25519 in this runtime (UNSUPPORTED)",
    "  4 not verified: signed by a key that was not checked: name the fingerprint from your agreement with --expect-fingerprint",
    "With several files the exit code is the most serious of theirs: 1 first, then 3, then 2, then 4, then 0.",
    "The last line, OVERALL, says the same in words.",
    "",
    "--json prints one JSON document. For one file it is that file's result; for a folder or several files, it lists every file with",
    "its own result and exit code, the sequence when there is one, any complete export set aside, and the result and exit code for them all.",
    "",
    "A checkpoint downloaded from the Checkpoints page (a file whose name ends in .json) is checked on its own: its signature over the records it seals",
    "(the Mandate ID, the first and last record's ids, how many there are, and their root) and its key. An export of the same period checks the records themselves.",
    "Given beside records, or found in a folder with them, it is still checked on its own, after them and apart from their sequence.",
    "",
    "Outside timestamps: a checkpoint may carry a timestamp from an independent time-stamp authority (RFC 3161), which shows it existed",
    "by that time. Each is checked offline against the roots this verifier ships (DigiCert Trusted Root G4). A checkpoint without one is",
    "named. In a record, a checkpoint without one before a checkpoint with one, or one stamped before an earlier checkpoint, is INVALID:",
    "Mandate stamps checkpoints in the order of their records, so either means a checkpoint was replaced after the fact. One this verifier",
    "cannot check before one it can is NOT VERIFIED (exit 4) until its authority's root is named.",
    "--timestamp-root names a root certificate (PEM or DER) to trust as well, such as your own authority's. Give it more than once for several.",
    "--require-timestamps reports NOT VERIFIED (exit 4) unless every checkpoint carries a timestamp this verifier can check, stamped",
    "within a day of its last record; in a record, only checkpoints of its last two hours may have none yet. A checkpoint checked on its",
    "own has no record times, so only its token is checked.",
  ].join("\n");
}

const EXIT_RANK = { 0: 0, 4: 1, 2: 2, 3: 3, 1: 4 };
const worse = (a, b) => (EXIT_RANK[b] > EXIT_RANK[a] ? b : a);

async function main(argv) {
  const packPaths = [];
  const expectFingerprints = [];
  let asJson = false;
  let streamed = false;
  const checkpointPaths = [];
  const folderCheckpoints = [];
  const timestampRoots = [];
  let requireTimestamps = false;

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
    } else if (arg === "--timestamp-root") {
      const value = argv[++i];
      if (!value) {
        console.error("--timestamp-root requires a file\n\n" + usage());
        return 2;
      }
      try {
        timestampRoots.push(certificateBytes(await readFile(value)));
      } catch (err) {
        console.error(`--timestamp-root: cannot read ${value} as a certificate: ${err.message}\n\n` + usage());
        return 2;
      }
    } else if (arg === "--require-timestamps") {
      requireTimestamps = true;
    } else if (arg === "--help" || arg === "-h") {
      console.log(usage());
      return 0;
    } else if (arg.startsWith("--")) {
      console.error(`unknown option: ${arg}\n\n` + usage());
      return 2;
    } else {
      const folder = await stat(arg).then((st) => st.isDirectory(), () => false);
      if (folder) {
        const names = (await readdir(arg)).sort();
        packPaths.push(...names.filter((n) => n.toLowerCase().endsWith(".zip")).map((n) => join(arg, n)));
        folderCheckpoints.push(...names.filter(isCheckpointName).map((n) => join(arg, n)));
        streamed = true;
      } else if (isCheckpointName(arg)) {
        checkpointPaths.push(arg);
      } else {
        packPaths.push(arg);
      }
    }
  }

  if (packPaths.length === 0 && checkpointPaths.length === 0 && folderCheckpoints.length === 0) {
    console.error(usage());
    return 2;
  }

  let worst = 0;
  const several = streamed || packPaths.length + checkpointPaths.length + folderCheckpoints.length > 1;
  const files = [];
  const outcomes = [];
  const emit = (r) => {
    if (asJson && r.entry) files.push({ ...r.entry, exitCode: r.code });
    return r;
  };
  // A complete export is told by what it holds before any file is read whole. Beside other records, as unzipping it in
  // place leaves it, it is set aside; with none, it is said to be one, and never checked as a record.
  const archives = [];
  for (const packPath of packPaths) {
    const found = await completeExportAt(packPath);
    if (found) archives.push({ path: packPath, found });
  }
  const recordPaths = packPaths.filter((p) => !archives.some((a) => a.path === p));
  const setAside = recordPaths.length > 0 ? archives.map((a) => a.path) : [];
  if (!asJson) for (const path of setAside) console.log(`  note: ${path} is a complete export, an archive of records, not one record; it was set aside`);
  if (recordPaths.length === 0) {
    for (const { path, found } of archives) {
      const message = completeExportWords(path, found);
      console.error(message);
      if (asJson) files.push({ pack: path, error: message, completeExport: found, exitCode: 2 });
      worst = worse(worst, 2);
      outcomes.push({ path, code: 2, words: "is a complete export: unzip it and give the verifier the folder" });
    }
  }
  let sequence = null;
  let sequenceWords = "";
  const verified = [];
  let previous = null;
  let streamedSequence = null;
  const streamedNotes = [];
  const streamedErased = [];
  const streamedReach = [];
  let parts = 0;
  const partCodes = [];
  for (const packPath of recordPaths) {
    const { code, result, kind } = emit(await verifyOne(packPath, expectFingerprints, asJson, { timestampRoots, requireTimestamps }));
    worst = worse(worst, code);
    parts++;
    partCodes.push(code);
    outcomes.push({ path: packPath, code, inProgress: result?.inProgress === true, format: result?.format !== undefined });
    const pack = result && kind === "evidence" ? { name: packPath, result, trusted: code === 0 } : null;
    if (pack) streamedReach.push({ result: { identity: result.identity, inProgress: result.inProgress } });
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
  if (parts > 1) {
    const missing = partsMissing(recordPaths.map((p) => basename(p)));
    sequence = missing
      ? { status: "invalid", reason: missing }
      : streamed
        ? streamedSequence ?? { status: "valid", packs: parts, notes: streamedNotes, erased: streamedErased, ...sequenceProgress(streamedReach) }
        : verified.length === parts
          ? checkPackSequence(verified)
          : { status: "invalid", reason: "every part of a sequence must be a readable signed record" };
    const joined = `${sequence.packs} parts join record to record, with no gap between their periods`;
    // How the parts join says nothing of each part, so the line never says VALID while one failed its own check.
    const partFailed = sequence.status === "valid" && partCodes.includes(1);
    if (sequence.status !== "valid") {
      sequenceWords = ["changed", "missing", "erased-first"].includes(sequence.kind) ? `the records disagree: ${sequence.detail}` : sequence.reason;
    }
    if (!asJson) console.log(sequence.status !== "valid"
      ? `SEQUENCE: INVALID (${sequenceWords})`
      : partFailed
        ? "SEQUENCE: INVALID (the parts join, but at least one part failed its own check above)"
        : expectFingerprints.length === 0
          ? `SEQUENCE: NOT VERIFIED (${joined}, but the key was not checked: name the fingerprint from your agreement with --expect-fingerprint)`
          : `SEQUENCE: VALID${sequence.inProgress ? ", IN PROGRESS" : ""} (${joined})`);
    if (!asJson && sequence.status === "valid" && !partFailed && sequence.inProgress) {
      console.log(`  in progress: their period had not ended when they were made; together they cover it up to ${localTime(sequence.recordedUntil)}`);
    }
    if (!asJson && sequence.status === "valid" && !partFailed) for (const note of sequence.notes ?? []) console.log(`  note: ${note}`);
    if (sequence.status !== "valid") worst = worse(worst, 1);
  }
  for (const path of [...checkpointPaths, ...folderCheckpoints]) {
    const { code, result } = emit(await verifyCheckpointOne(path, expectFingerprints, asJson, { timestampRoots, requireTimestamps }));
    worst = worse(worst, code);
    outcomes.push({ path, code, checkpoint: true, format: result?.format !== undefined });
  }
  // A reader who looks only at the end of a long run reads the result for every file there, in the exit code's word.
  if (several && !asJson) {
    console.log("");
    console.log(overallLine(worst, outcomes, sequence, sequenceWords));
  }
  if (asJson && several) {
    console.log(JSON.stringify({ files, ...(sequence ? { sequence } : {}), ...(setAside.length ? { setAside } : {}), result: RESULT_WORDS[worst],
      exitCode: worst }, null, 2));
  } else if (asJson && files[0] && !files[0].error) {
    const { exitCode, ...one } = files[0];
    console.log(JSON.stringify(one, null, 2));
  }
  return worst;
}

const RESULT_WORDS = { 0: "valid", 1: "invalid", 2: "not checked", 3: "not checked", 4: "not verified" };

function overallLine(worst, outcomes, sequence, sequenceWords) {
  if (worst === 1) {
    const failed = outcomes.filter((o) => o.code === 1);
    if (failed.length === 0) return `OVERALL: INVALID (${sequenceWords})`;
    return failed.length === 1
      ? `OVERALL: INVALID (${failed[0].path} failed its check)`
      : `OVERALL: INVALID (${failed.length} of ${outcomes.length} files failed their checks, the first ${failed[0].path})`;
  }
  if (worst === 3) {
    const first = outcomes.find((o) => o.code === 3);
    return first.format
      ? `OVERALL: NOT CHECKED (${first.path} is in a format this verifier does not read)`
      : "OVERALL: NOT CHECKED (this runtime lacks WebCrypto Ed25519; use Node 20 or newer)";
  }
  if (worst === 2) {
    const first = outcomes.find((o) => o.code === 2);
    return `OVERALL: NOT CHECKED (${first.path} ${first.words ?? "could not be read"})`;
  }
  if (worst === 4) return "OVERALL: NOT VERIFIED (signed by a key that was not checked: name the fingerprint from your agreement with --expect-fingerprint)";
  const records = outcomes.filter((o) => !o.checkpoint).length;
  const checkpoints = outcomes.length - records;
  const counted = [records ? `${records} record${records === 1 ? "" : "s"}` : "", checkpoints ? `${checkpoints} checkpoint${checkpoints === 1 ? "" : "s"}` : ""]
    .filter(Boolean).join(" and ");
  const inProgress = sequence ? sequence.inProgress === true : outcomes.some((o) => o.inProgress);
  return `OVERALL: VALID${inProgress ? ", IN PROGRESS" : ""} (${counted}, each unchanged since it was signed with a key you named`
    + `${sequence ? `; the ${sequence.packs} parts join with no gap between their periods` : ""})`;
}

// Only the archive's end and its directory are read, so a complete export of any size is told before anything is read whole.
async function completeExportAt(path) {
  let handle;
  try {
    handle = await open(path, "r");
    const { size } = await handle.stat();
    const names = await readZipNames(size, async (at, length) => {
      const buffer = new Uint8Array(length);
      const { bytesRead } = await handle.read(buffer, 0, length, at);
      return buffer.subarray(0, bytesRead);
    });
    return names ? completeExportOf(names) : null;
  } catch {
    return null;
  } finally {
    await handle?.close();
  }
}

function completeExportWords(path, found) {
  const range = found.parts > 1 ? `, ${found.first} to ${found.last}` : `, ${found.first}`;
  const missing = found.missing > 0
    ? ` It does not hold ${found.firstMissing}${found.missing > 1 ? ` and ${found.missing - 1} more` : ""}, so the folder will not cover the whole period.`
    : "";
  return `${path} is a complete export: an archive of ${found.parts} record${found.parts === 1 ? "" : "s"}${range}.${missing} `
    + "The archive itself is not signed, so it is not checked as a record. Unzip it into a folder, then give the verifier the folder:\n"
    + "    node mandate-verify.mjs <folder> --expect-fingerprint <hex>";
}

function certificateBytes(bytes) {
  const text = new TextDecoder().decode(bytes);
  const pem = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(text);
  const der = pem ? base64ToBytes(pem[1].replace(/\s+/g, "")) : new Uint8Array(bytes);
  timestampRootFromDer(der);
  return der;
}

function timestampWords(t) {
  if (!t) return "";
  if (t.status === "valid") return `stamped ${localTime(t.time)} by ${t.authority}`;
  if (t.status === "absent") return "no outside timestamp";
  return `outside timestamp ${t.status === "invalid" ? "INVALID" : "not checked"}: ${t.reason}`;
}

function timestampLines(ts) {
  const lines = [];
  if (!ts) return lines;
  if (ts.problem) lines.push(`[FAIL] ${ts.problem}`);
  if (ts.stamped > 0) {
    const through = ts.provenThrough
      ? `: the records up to ${localTime(new Date(ts.provenThrough.recordMs).toISOString())} were sealed no later than ${localTime(new Date(ts.provenThrough.stampedMs).toISOString())}`
      : "";
    lines.push(`[ ok ] ${ts.stamped} checkpoint(s) carry an outside timestamp, from ${ts.authorities.join("; ")}${through}`);
  }
  if (ts.absent.length > 0) lines.push(`[ -- ] ${ts.absent.length} checkpoint(s) have no outside timestamp: ${ts.absent.map((a) => a.checkpointId).join(", ")}`);
  if (ts.untrusted.length > 0) {
    lines.push(`[ -- ] ${ts.untrusted.length} checkpoint(s) carry a timestamp this verifier cannot check (${ts.untrusted[0].reason}); name its authority's root with --timestamp-root: ${ts.untrusted.map((a) => a.checkpointId).join(", ")}`);
  }
  for (const l of ts.late) lines.push(`[ -- ] checkpoint ${l.checkpointId} was stamped ${l.hours} hours after its last record, so its timestamp shows only that it existed by then`);
  if (ts.notPlaced > 0) lines.push(`[ -- ] ${ts.notPlaced} checkpoint(s) outside the records file: their timestamps are checked, their order is not`);
  return lines;
}

async function verifyOne(packPath, expectFingerprints, asJson, options = {}) {
  const failed = (message) => {
    console.error(message);
    return { code: 2, entry: { pack: packPath, error: message } };
  };

  let bytes;
  try {
    bytes = new Uint8Array(await readFile(packPath));
  } catch (err) {
    return failed(`cannot read ${packPath}: ${err.message}`);
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
      : await verifyEvidencePackBytes(bytes, inflateRaw, options);
  } catch (err) {

    const detail = err instanceof ZipError ? err.message : `unexpected error: ${err.message}`;
    return failed(`cannot read ${packPath} as a Mandate record: ${detail}`);
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

  const entry = { pack: packPath, kind, expectedFingerprints: expected, fingerprintMismatches, ...result };
  if (!asJson) {
    console.log(`File           : ${packPath}`);
    console.log(`Kind           : ${kind === "dsr" ? "access record" : "signed record"}`);
    if (result.identity) {
      console.log(`Mandate ID     : ${result.identity.tenantId}`);
      console.log(`Generated      : ${localTime(result.identity.generatedAt)}`);
      console.log(`Period         : ${result.identity.windowFrom ? localTime(result.identity.windowFrom) : "(open)"} to ${result.identity.windowTo ? localTime(result.identity.windowTo) : "(open)"}`);
    }
    if (kind === "dsr" && result.subjectHashHex !== undefined) {
      console.log(`Person         : ${result.subjectHashHex} (keyed hash)`);
      console.log(
        `Complete       : ${result.inProgress
          ? `no, in progress: ${progressWords(result)}${result.truncated ? "; this access record holds part of what was found" : ""}`
          : result.truncated ? "no, this access record holds part of what was found" : "yes"}; `
        + `unscannable rows ${result.unscannableRows}, degraded rows ${result.degradedRows}`,
      );
    } else if (result.truncated !== undefined) {
      const partial = partialParts(result);
      const cut = partial.length > 0 ? `this export holds part of its period (partial: ${partial.join(", ")})` : "";
      console.log(`Complete       : ${result.inProgress
        ? `no, in progress: ${progressWords(result)}${cut ? `; ${cut}` : ""}`
        : cut ? `no, ${cut}` : "yes, the whole period"}`);
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
        console.log(`  ${tag} ${c.checkpointId}${key}${c.result.reason ? `  (${c.result.reason})` : ""}${c.timestamp && c.result.status === "valid" ? `  ${timestampWords(c.timestamp)}` : ""}`);
      }
      for (const line of timestampLines(result.timestamps)) console.log(`  ${line}`);
    }
    for (const mm of fingerprintMismatches) {
      console.log(`  [FAIL] fingerprint expectation: ${mm}`);
    }
    if (result.chain) {
      const ch = result.chain;
      console.log("");
      if (ch.status === "valid") {
        const parts = [[ch.kinds?.decisions, "decision"], [ch.kinds?.answers, "answer relayed"], [ch.kinds?.imported, "imported record"], [ch.kinds?.changes, "change"], [ch.kinds?.tests, "test prompt"]]
          .filter(([n]) => n > 0).map(([n, noun]) => `${n} ${noun}${n === 1 ? "" : noun === "answer relayed" ? "" : "s"}`.replace("answer relayed", n === 1 ? "answer relayed" : "answers relayed"));
        console.log(`Records: [ ok ] ${ch.records} records link in order${parts.length ? ` (${parts.join(", ")})` : ""}`);
        for (const e of ch.erasures ?? []) {
          console.log(`         [ ok ] ${e.removed} record${e.removed === 1 ? "" : "s"} removed under ${e.reason === "privacy request" ? "a privacy request" : "the retention setting"} on ${localTime(e.at)} keep${e.removed === 1 ? "s its" : " their"} place (entry ${e.id})`);
        }
        console.log(`         [ ok ] ${ch.checkpointsRecomputed} checkpoint root(s) recomputed from the records${ch.checkpointsNotCovered ? `, ${ch.checkpointsNotCovered} not covered: the records file is partial` : ""}`);
        console.log(`         [ ok ] ${ch.decisionsTied} decision(s) in the register match their records${ch.decisionsNotTied ? `, ${ch.decisionsNotTied} outside the records file` : ""}${ch.peopleTied ? `, ${ch.peopleTied} naming a person` : ""}`);
        console.log(`         [ ok ] ${ch.changesTied} change-trail entr${ch.changesTied === 1 ? "y matches its" : "ies match their"} sealed record${ch.changesTied === 1 ? "" : "s"}${ch.changesNotTied ? `, ${ch.changesNotTied} not sealed in the records file yet or outside it` : ""}`);
        for (const line of sealedDocumentsLines(ch.sealedDocuments)) console.log(`         ${line.tag} ${line.label}`);
        if (ch.reportTied) console.log("         [ ok ] the printed report was drawn from the checked summary");
        console.log(`         [ ok ] ${ch.policyVersions} policy version(s) match their text`);
        if (ch.listsChecked) console.log(`         [ ok ] ${ch.listsChecked} list(s) of names match their seals`);
        else if (ch.listsSealed) console.log(`         [ -- ] ${ch.listsSealed} list(s) of names sealed; this export leaves the names out`);
        if (ch.summaryCompared) console.log("         [ ok ] the summary counts match the decisions");
        else if (ch.summaryNotCompared) console.log(`         [ -- ] the summary counts were not compared: ${ch.summaryNotCompared}`);
        if (ch.importsCompared) console.log("         [ ok ] what the report says other AI tools reported matches imports/");
        else if (ch.importsNotCompared) console.log(`         [ -- ] what the report says other AI tools reported was not compared: ${ch.importsNotCompared}`);
        const decided = finalDecisionsLine(ch.finalDecisions);
        if (decided) console.log(`         ${decided.tag} ${decided.label}`);
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
    return { code: 3, result, kind, entry };
  }
  if (result.overall === "invalid" || fingerprintMismatches.length > 0) {
    if (!asJson) console.log("RESULT: INVALID");
    return { code: 1, result, kind, entry };
  }
  if (result.timestamps?.notVerified) {
    if (!asJson) console.log(`RESULT: NOT VERIFIED (outside timestamps: ${result.timestamps.notVerified})`);
    return { code: 4, result, kind, entry };
  }
  if (expected.length === 0) {
    if (!asJson) {
      if (result.checkpointKeysDiffer) console.log("Some checkpoints are signed by a different key than the record, as after a key change: compare each fingerprint above with your agreement.");
      console.log("RESULT: NOT VERIFIED (signed by a key that was not checked: name the fingerprint from your agreement with --expect-fingerprint)");
    }
    return { code: 4, result, kind, entry };
  }
  if (!asJson) {
    console.log(result.inProgress ? `RESULT: VALID, IN PROGRESS (${progressWords(result, true)})` : "RESULT: VALID");
    if (kind !== "dsr" && result.chain?.outcomes) console.log(headline(result.chain, result.inProgress));
  }
  return { code: 0, result, kind, entry };
}

function progressWords(result, when = false) {
  const at = localTime(result.identity.generatedAt);
  return result.notBegun
    ? `the period had not begun when this record was made${when ? `, on ${at}` : ""}, so it holds nothing of it`
    : `the period had not ended when this record was made, so it holds what was recorded up to ${when ? at : "then"}`;
}

async function verifyCheckpointOne(path, expected, asJson, options = {}) {
  const failed = (message) => {
    console.error(message);
    return { code: 2, kind: "checkpoint", entry: { pack: path, kind: "checkpoint", error: message } };
  };
  let bytes;
  try {
    bytes = new Uint8Array(await readFile(path));
  } catch (err) {
    return failed(`cannot read ${path}: ${err.message}`);
  }
  const result = await verifyCheckpointFileBytes(bytes, options);
  if (result.unreadable) return failed(`cannot read ${path} as a Mandate record or checkpoint: ${result.signature.reason}`);
  const fingerprintMismatches = expected.length > 0 && result.checkpoint && !expected.includes(result.publicKeyFingerprint ?? "")
    ? [`checkpoint key is ${result.publicKeyFingerprint ?? "(none)"}`]
    : [];
  const entry = { pack: path, expectedFingerprints: expected, fingerprintMismatches, ...result };
  if (!asJson) {
    const c = result.checkpoint;
    console.log(`File           : ${path}`);
    console.log("Kind           : checkpoint");
    if (c) {
      console.log(`Mandate ID     : ${c.tenantId}`);
      console.log(`Checkpoint     : ${c.checkpointId}`);
      console.log(`Records sealed : ${c.eventCount}, from record ${c.windowStartEventId} to record ${c.windowEndEventId}`);
      console.log(`Root           : ${c.merkleRootHex}`);
      console.log(`Window         : ${localTime(c.windowStartOccurredAt)} to ${localTime(c.windowEndOccurredAt)}, as the file says (the times are not signed)`);
    }
    if (result.publicKeyFingerprint) {
      console.log(`Signing key    : ${result.publicKeyFingerprint}`);
      if (expected.length === 0) console.log("                 Compare this fingerprint with the one in your agreement before relying on the result.");
      else if (fingerprintMismatches.length === 0) console.log("                 This is the fingerprint you named.");
    }
    console.log("");
    const sig = result.signature;
    console.log(`Checkpoint signature: ${sig.status === "valid" ? "ok" : `${sig.status.toUpperCase()} (${sig.reason})`}`);
    if (result.timestamp) console.log(`Outside timestamp   : ${result.timestamp.status === "valid" ? `ok, ${timestampWords(result.timestamp)}` : timestampWords(result.timestamp)}`);
    for (const mm of fingerprintMismatches) console.log(`  [FAIL] fingerprint expectation: ${mm}`);
    console.log("");
    if (c) {
      console.log("The signature covers the Mandate ID, the first and last record's ids, how many records there are and their root.");
      console.log("An export of the same period checks the records themselves against this checkpoint.");
      console.log("");
    }
  }
  if (result.overall === "unsupported") {
    if (!asJson) {
      console.log(result.format !== undefined
        ? `RESULT: DIFFERENT FORMAT (${result.signature.reason})`
        : "RESULT: UNSUPPORTED (this runtime lacks WebCrypto Ed25519; use Node 20 or newer)");
    }
    return { code: 3, result, kind: "checkpoint", entry };
  }
  if (result.overall === "invalid" || fingerprintMismatches.length > 0) {
    if (!asJson) console.log("RESULT: INVALID (checkpoint)");
    return { code: 1, result, kind: "checkpoint", entry };
  }
  if (result.timestampNotVerified) {
    if (!asJson) console.log(`RESULT: NOT VERIFIED (checkpoint, --require-timestamps: ${result.timestampNotVerified})`);
    return { code: 4, result, kind: "checkpoint", entry };
  }
  if (expected.length === 0) {
    if (!asJson) console.log("RESULT: NOT VERIFIED (checkpoint, signed by a key that was not checked: name the fingerprint from your agreement with --expect-fingerprint)");
    return { code: 4, result, kind: "checkpoint", entry };
  }
  if (!asJson) console.log("RESULT: VALID (checkpoint)");
  return { code: 0, result, kind: "checkpoint", entry };
}

function localTime(text) {
  const at = new Date(text);
  if (Number.isNaN(at.getTime())) return String(text);
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return `${at.toLocaleString("en-CA", { dateStyle: "medium", timeStyle: "short" })} ${zone} (${text})`;
}

function headline(chain, inProgress) {
  const words = [["allow", "allowed"], ["warn", "warned"], ["redact", "masked"], ["escalate", "held"], ["block", "refused"]];
  const total = Object.values(chain.outcomes).reduce((n, c) => n + c, 0);
  const parts = words.filter(([k]) => chain.outcomes[k]).map(([k, w]) => `${chain.outcomes[k]} ${w}`);
  const list = parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : parts.join("");
  return `Unchanged since it was signed, with the key you named: ${total} decision${total === 1 ? "" : "s"}${inProgress ? " so far" : ""}${list ? `: ${list}` : ""}.`;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  process.exitCode = await main(process.argv.slice(2));
}
