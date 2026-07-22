#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Mandate Systems Inc.
/**
 * check.mjs - test suite for mandate-verify.
 *
 * Sections:
 *   1. MIRROR - (opt-in: MIRROR=1) the file in this repository is byte-identical to the copy
 *               served at https://mandateco.ca/downloads/mandate-verify.mjs, and the verifier
 *               core embedded in https://mandateco.ca/verify.html matches this file's core.
 *               Requires network access; the default run is fully offline and skips it.
 *   2. VECTOR - both payload builders reproduce the cross-language golden vectors exactly
 *               (the same vectors asserted by the product's C# and TypeScript test suites),
 *               signatures verify, a flipped bit fails, and the key fingerprint derivation
 *               matches.
 *   3. TAMPER - a synthetic pack signed with the (public, test-only) vector seed verifies,
 *               and every tamper class is caught: content flip, injected file, metadata flip,
 *               missing file, duplicate entry, entry-count bomb, declared-size bomb, non-zip.
 *   4. PACKS  - the committed sample packs under samples/ verify end to end.
 *
 * Usage: node test/check.mjs            (offline)
 *        MIRROR=1 node test/check.mjs   (also compare against the live site)
 * Exits non-zero on any failure.
 */

import { readFile, readdir } from "node:fs/promises";
import { inflateRawSync, deflateRawSync } from "node:zlib";
import { createPrivateKey, sign as signNode } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  hexToBytes,
  bytesToHex,
  base64ToBytes,
  buildCheckpointSignedPayload,
  buildEvidencePackSignedPayload,
  verifyEd25519,
  sha256Hex,
  readZipEntries,
  verifyEvidencePackBytes,
  ZipError,
} from "../mandate-verify.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const inflateRaw = async (raw) => new Uint8Array(inflateRawSync(raw));

let failures = 0;
let checks = 0;
function ok(name, cond, detail = "") {
  checks++;
  if (cond) {
    console.log(`  [PASS] ${name}`);
  } else {
    failures++;
    console.log(`  [FAIL] ${name}${detail ? `  (${detail})` : ""}`);
  }
}
async function throws(name, fn, codeOrMessagePart) {
  try {
    await fn();
    ok(name, false, "expected an error, none thrown");
  } catch (err) {
    const text = `${err.code ?? ""} ${err.message}`;
    ok(name, text.includes(codeOrMessagePart), `got: ${text}`);
  }
}

// ── 1. MIRROR: this repository vs the live site (opt-in; needs network) ──────────────────────
console.log("\nMIRROR check (repository vs mandateco.ca)");
function extractCore(text, file) {
  const begin = text.indexOf("VERIFIER-CORE-BEGIN");
  const end = text.indexOf("VERIFIER-CORE-END");
  if (begin === -1 || end === -1 || end <= begin) throw new Error(`no VERIFIER-CORE block in ${file}`);
  const afterBegin = text.indexOf("\n", begin) + 1;
  const lineStartOfEnd = text.lastIndexOf("\n", end) + 1;
  return text.slice(afterBegin, lineStartOfEnd);
}
const localText = await readFile(join(root, "mandate-verify.mjs"), "utf8");
if (process.env.MIRROR !== "1") {
  console.log("  [SKIP] offline run (set MIRROR=1 to compare against the live site)");
} else {
  const liveCli = await (await fetch("https://mandateco.ca/downloads/mandate-verify.mjs")).text();
  ok("repository file is byte-identical to the site download", liveCli === localText,
    "the repository and https://mandateco.ca/downloads/mandate-verify.mjs have diverged");
  const livePage = await (await fetch("https://mandateco.ca/verify.html")).text();
  const pageCore = extractCore(livePage, "verify.html");
  const localCore = extractCore(localText, "mandate-verify.mjs");
  ok("verify.html core matches this file's core", pageCore === localCore);
}

// ── 2. VECTOR: golden-vector byte equality + signature checks ────────────────────────────────
console.log("\nVECTOR checks (cross-language golden vectors)");
const cpVector = JSON.parse(await readFile(join(root, "test/vectors/checkpoint-signed-payload-v1.vector.json"), "utf8"));
const epVector = JSON.parse(await readFile(join(root, "test/vectors/evidence-pack-signed-payload-v2.vector.json"), "utf8"));

const cpPayload = buildCheckpointSignedPayload(
  cpVector.tenantId,
  cpVector.windowStartEventId,
  cpVector.windowEndEventId,
  cpVector.eventCount,
  hexToBytes(cpVector.merkleRootHex),
);
ok("checkpoint payload matches vector bytes", bytesToHex(cpPayload) === cpVector.payloadHex);

const cpSig = hexToBytes(cpVector.signatureHex);
const cpKey = base64ToBytes(cpVector.publicKeyBase64);
ok("checkpoint signature verifies", (await verifyEd25519(cpPayload, cpSig, cpKey)).status === "valid");
{
  const flipped = new Uint8Array(cpSig);
  flipped[0] ^= 0x01;
  ok("flipped checkpoint signature fails", (await verifyEd25519(cpPayload, flipped, cpKey)).status === "invalid");
  const mutated = new Uint8Array(cpPayload);
  mutated[mutated.length - 1] ^= 0x01;
  ok("mutated checkpoint payload fails", (await verifyEd25519(mutated, cpSig, cpKey)).status === "invalid");
}
ok("fingerprint = SHA-256 of raw public key", (await sha256Hex(cpKey)) === cpVector.publicKeyFingerprint);

const epPayload = buildEvidencePackSignedPayload(
  epVector.tenantId,
  epVector.manifestVersion,
  epVector.generatedAt,
  epVector.windowFrom,
  epVector.windowTo,
  epVector.truncated,
  epVector.checkpointsTruncated,
  epVector.contents,
);
ok("evidence-pack payload matches vector bytes", bytesToHex(epPayload) === epVector.payloadHex);

const epPayloadReversed = buildEvidencePackSignedPayload(
  epVector.tenantId,
  epVector.manifestVersion,
  epVector.generatedAt,
  epVector.windowFrom,
  epVector.windowTo,
  epVector.truncated,
  epVector.checkpointsTruncated,
  [...epVector.contents].reverse(),
);
ok("builder sorts contents (reversed input, same bytes)", bytesToHex(epPayloadReversed) === epVector.payloadHex);

const epSig = hexToBytes(epVector.signatureHex);
const epKey = base64ToBytes(epVector.publicKeyBase64);
ok("evidence-pack signature verifies", (await verifyEd25519(epPayload, epSig, epKey)).status === "valid");

// ── 3. TAMPER: synthetic pack signed with the public test-vector seed ─────────────────────────
console.log("\nTAMPER matrix (synthetic pack, test-vector key)");

// Sign with the vector's all-zeros seed. This key is public and test-only; the committed sample
// packs are signed with a dedicated sample key whose seed is not in this repository.
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";
const vectorPrivateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from(PKCS8_ED25519_PREFIX, "hex"), Buffer.from(cpVector.seedBase64, "base64")]),
  format: "der",
  type: "pkcs8",
});
const signWithVectorKey = (payload) => new Uint8Array(signNode(null, payload, vectorPrivateKey));

// Minimal stored-entry (method 0) ZIP writer. CRC fields are zero: the reader deliberately
// ignores CRC because content is verified against the signed manifest's SHA-256 list.
function writeZip(entries) {
  const enc = new TextEncoder();
  const chunks = [];
  const central = [];
  let offset = 0;
  const u16 = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
  const u32 = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  for (const e of entries) {
    const name = enc.encode(e.name);
    // e.deflate stores the entry with raw-deflate (method 8) so a high-ratio (compressible) pack can be
    // exercised; otherwise method 0 (stored). declaredUncompressedSize overrides the central-dir size.
    const method = e.deflate ? 8 : 0;
    const body = e.deflate ? new Uint8Array(deflateRawSync(e.data)) : e.data;
    const declared = e.declaredUncompressedSize ?? e.data.length;
    const local = [u32(0x04034b50), u16(20), u16(0), u16(method), u16(0), u16(0), u32(0), u32(body.length), u32(declared), u16(name.length), u16(0), name, body];
    const cd = [u32(0x02014b50), u16(20), u16(20), u16(0), u16(method), u16(0), u16(0), u32(0), u32(body.length), u32(declared), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), name];
    central.push(cd);
    for (const part of local) chunks.push(part);
    offset += local.reduce((n, p) => n + p.length, 0);
  }
  const cdStart = offset;
  for (const cd of central) for (const part of cd) chunks.push(part);
  const cdSize = chunks.slice().reduce((n, p) => n + p.length, 0) - cdStart;
  chunks.push(u32(0x06054b50), u16(0), u16(0), u16(central.length), u16(central.length), u32(cdSize), u32(cdStart), u16(0));
  const total = chunks.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of chunks) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

async function buildSyntheticPack() {
  const enc = new TextEncoder();
  const tenantId = epVector.tenantId;

  // A synthetic embedded checkpoint, signed over the canonical checkpoint payload.
  const cp = {
    schemaVersion: 1,
    checkpointId: "11111111-2222-4333-8444-555555555555",
    tenantId,
    windowStartEventId: cpVector.windowStartEventId,
    windowEndEventId: cpVector.windowEndEventId,
    windowStartOccurredAt: "2026-01-15T11:00:00+00:00",
    windowEndOccurredAt: "2026-01-15T11:59:00+00:00",
    eventCount: cpVector.eventCount,
    merkleRootHex: cpVector.merkleRootHex,
    signatureHex: cpVector.signatureHex,
    publicKeyBase64: cpVector.publicKeyBase64,
    publicKeyFingerprint: cpVector.publicKeyFingerprint,
    createdAt: "2026-01-15T12:00:00+00:00",
  };

  const files = new Map([
    ["policy/active.json", enc.encode('{"policy":"synthetic"}')],
    ["register/decisions.json", enc.encode('[{"decision":"allow"},{"decision":"block"}]')],
    ["README.txt", enc.encode("Synthetic pack for the verifier test suite.\n")],
    ["checkpoints/11111111-2222-4333-8444-555555555555.json", enc.encode(JSON.stringify(cp))],
  ]);

  const contents = [];
  for (const [name, data] of files) {
    contents.push({ filename: name, sha256Hex: await sha256Hex(data), byteLength: data.length });
  }

  const manifest = {
    manifestVersion: 1,
    tenantId,
    generatedAt: "2026-01-15T12:00:00.0000000+00:00",
    windowFrom: "2026-01-15T00:00:00+00:00",
    windowTo: "2026-01-15T12:00:00+00:00",
    truncated: false,
    checkpointsTruncated: false,
    contents,
    checkpointIds: [cp.checkpointId],
    signatureHex: "",
    publicKeyBase64: epVector.publicKeyBase64,
    publicKeyFingerprint: epVector.publicKeyFingerprint,
  };
  const payload = buildEvidencePackSignedPayload(
    tenantId, 1, manifest.generatedAt, manifest.windowFrom, manifest.windowTo, false, false, contents);
  manifest.signatureHex = bytesToHex(signWithVectorKey(payload));

  const entries = [...files].map(([name, data]) => ({ name, data }));
  entries.push({ name: "manifest.json", data: enc.encode(JSON.stringify(manifest)) });
  return { entries, manifest };
}

const synthetic = await buildSyntheticPack();
const baseline = await verifyEvidencePackBytes(writeZip(synthetic.entries), inflateRaw);
ok("baseline synthetic pack is valid", baseline.overall === "valid", JSON.stringify(baseline.manifest));
ok("baseline embeds one valid checkpoint", baseline.checkpoints.length === 1 && baseline.checkpoints[0].result.status === "valid");

{
  // Content flip: one byte of a listed file changes -> that file fails, manifest signature holds.
  const entries = synthetic.entries.map((e) => ({ ...e, data: new Uint8Array(e.data) }));
  const target = entries.find((e) => e.name === "register/decisions.json");
  target.data[0] ^= 0x01;
  const r = await verifyEvidencePackBytes(writeZip(entries), inflateRaw);
  const file = r.files.find((f) => f.path === "register/decisions.json");
  ok("content flip -> file invalid", r.overall === "invalid" && file?.status === "invalid");
  ok("content flip -> manifest signature still valid", r.manifest.status === "valid");
}
{
  // Injected file: present in the ZIP, absent from manifest.contents.
  const entries = [...synthetic.entries, { name: "evil.txt", data: new TextEncoder().encode("injected") }];
  const r = await verifyEvidencePackBytes(writeZip(entries), inflateRaw);
  const file = r.files.find((f) => f.path === "evil.txt");
  ok("injected file -> set-equality invalid", r.overall === "invalid" && file?.status === "invalid");
}
{
  // Metadata flip: truncated=true in the manifest without re-signing -> signature fails.
  const manifest = { ...synthetic.manifest, truncated: true };
  const entries = synthetic.entries.map((e) =>
    e.name === "manifest.json" ? { name: e.name, data: new TextEncoder().encode(JSON.stringify(manifest)) } : e,
  );
  const r = await verifyEvidencePackBytes(writeZip(entries), inflateRaw);
  ok("metadata flip -> manifest signature invalid", r.overall === "invalid" && r.manifest.status === "invalid");
}
{
  // Missing file: listed in the manifest but removed from the ZIP.
  const entries = synthetic.entries.filter((e) => e.name !== "policy/active.json");
  const r = await verifyEvidencePackBytes(writeZip(entries), inflateRaw);
  const file = r.files.find((f) => f.path === "policy/active.json");
  ok("dropped file -> reported missing", r.overall === "invalid" && file?.status === "missing");
}
await throws("duplicate entry name -> reader rejects", async () => {
  const dup = synthetic.entries.find((e) => e.name === "README.txt");
  await readZipEntries(writeZip([...synthetic.entries, dup]), inflateRaw);
}, "duplicate");
await throws("1033 entries -> reader rejects", async () => {
  const enc = new TextEncoder();
  const many = Array.from({ length: 1033 }, (_, i) => ({ name: `f${i}.txt`, data: enc.encode("x") }));
  await readZipEntries(writeZip(many), inflateRaw);
}, "file-count");
{
  // The cap itself must admit a maximal legitimate pack: MaxCheckpoints (1000) + 32 headroom.
  const enc = new TextEncoder();
  const max = Array.from({ length: 1032 }, (_, i) => ({ name: `f${i}.txt`, data: enc.encode("x") }));
  const entries = await readZipEntries(writeZip(max), inflateRaw);
  ok("1032 entries (cap) -> reader accepts", entries.size === 1032);
}
await throws("declared size over 50 MB -> reader rejects", async () => {
  const enc = new TextEncoder();
  const bomb = [{ name: "big.bin", data: enc.encode("tiny"), declaredUncompressedSize: 60 * 1024 * 1024 }];
  await readZipEntries(writeZip(bomb), inflateRaw);
}, "total-bytes");
await throws("non-zip input -> reader rejects", async () => {
  await readZipEntries(new TextEncoder().encode("this is not a zip archive, just text ".repeat(4)), inflateRaw);
}, "malformed");
{
  // Fingerprint spoof: the manifest DECLARES a different fingerprint than its key. A green result must
  // report the SHA-256 of the key that actually verified (which a forger cannot fake without the private
  // key), never the self-declared field, or the whole "compare the fingerprint" trust step is defeated.
  const realFp = await sha256Hex(base64ToBytes(epVector.publicKeyBase64));
  const lying = { ...synthetic.manifest, publicKeyFingerprint: "0".repeat(64) };
  const entries = synthetic.entries.map((e) =>
    e.name === "manifest.json" ? { name: e.name, data: new TextEncoder().encode(JSON.stringify(lying)) } : e,
  );
  const r = await verifyEvidencePackBytes(writeZip(entries), inflateRaw);
  ok("fingerprint spoof -> signature still valid for its own key", r.overall === "valid");
  ok("fingerprint spoof -> reported fingerprint is the key hash, not the declared lie",
    r.publicKeyFingerprint === realFp && r.publicKeyFingerprint !== "0".repeat(64));
  ok("computed manifest fingerprint matches the published vector fingerprint", realFp === epVector.publicKeyFingerprint);
  ok("checkpoint fingerprint is computed from its own key",
    r.checkpoints[0]?.publicKeyFingerprint === cpVector.publicKeyFingerprint);
}
{
  // Malformed manifest: a content entry with no sha256Hex must return overall "invalid", not throw a
  // TypeError on entry.sha256Hex.toLowerCase().
  const bad = { ...synthetic.manifest, contents: [{ filename: "policy/active.json" }] };
  const entries = synthetic.entries.map((e) =>
    e.name === "manifest.json" ? { name: e.name, data: new TextEncoder().encode(JSON.stringify(bad)) } : e,
  );
  let threw = false;
  let r;
  try { r = await verifyEvidencePackBytes(writeZip(entries), inflateRaw); } catch { threw = true; }
  ok("malformed manifest entry -> invalid, not a thrown error", !threw && r?.overall === "invalid");
}
{
  // High-ratio (but under the absolute cap): a highly compressible deflate entry expands far past a
  // naive ratio cap. There is deliberately no expansion-ratio cap (it false-positives on legitimately
  // compressible packs); a legitimate compressible pack still verifies.
  const enc = new TextEncoder();
  const big = enc.encode("A".repeat(300000)); // ~300 KB, deflates to a few hundred bytes (>1000x)
  const bigFiles = new Map([
    ["policy/active.json", enc.encode('{"policy":"synthetic"}')],
    ["big/repetitive.txt", big],
    ["README.txt", enc.encode("High-ratio pack.\n")],
  ]);
  const bigContents = [];
  for (const [name, data] of bigFiles) bigContents.push({ filename: name, sha256Hex: await sha256Hex(data), byteLength: data.length });
  const bigManifest = {
    manifestVersion: 1, tenantId: epVector.tenantId, generatedAt: "2026-01-15T12:00:00.0000000+00:00",
    windowFrom: "2026-01-15T00:00:00+00:00", windowTo: "2026-01-15T12:00:00+00:00",
    truncated: false, checkpointsTruncated: false, contents: bigContents, checkpointIds: [],
    signatureHex: "", publicKeyBase64: epVector.publicKeyBase64, publicKeyFingerprint: epVector.publicKeyFingerprint,
  };
  const bigPayload = buildEvidencePackSignedPayload(
    bigManifest.tenantId, 1, bigManifest.generatedAt, bigManifest.windowFrom, bigManifest.windowTo, false, false, bigContents);
  bigManifest.signatureHex = bytesToHex(signWithVectorKey(bigPayload));
  const bigEntries = [...bigFiles].map(([name, data]) => ({ name, data, deflate: name === "big/repetitive.txt" }));
  bigEntries.push({ name: "manifest.json", data: enc.encode(JSON.stringify(bigManifest)) });
  const r = await verifyEvidencePackBytes(writeZip(bigEntries), inflateRaw);
  ok("high-ratio deflate pack (>100x, under 50 MB) verifies", r.overall === "valid", JSON.stringify(r.manifest));
}

// ── 4. PACKS: committed sample packs verify end to end ───────────────────────────────────────
console.log("\nPACKS check (committed sample packs)");
const samplesDir = join(root, "samples");
const packNames = (await readdir(samplesDir)).filter((f) => f.startsWith("mandate-sample-evidence-pack-") && f.endsWith(".zip"));
if (packNames.length === 0) {
  console.log("  [SKIP] no committed sample packs");
} else {
  for (const name of packNames.sort()) {
    const bytes = new Uint8Array(await readFile(join(samplesDir, name)));
    try {
      const r = await verifyEvidencePackBytes(bytes, inflateRaw);
      ok(`${name} verifies`, r.overall === "valid", JSON.stringify(r.manifest));
      ok(`${name} embeds at least one checkpoint`, r.checkpoints.length >= 1);
      ok(`${name} is complete (no truncation)`, r.truncated === false && r.checkpointsTruncated === false);
    } catch (err) {
      ok(`${name} verifies`, false, err.message);
    }
  }
}

console.log(`\n${checks} checks, ${failures} failure(s)`);
process.exitCode = failures === 0 ? 0 : 1;
