#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Mandate Systems Inc.
/**
 * check.mjs - test suite for mandate-verify.
 *
 * Sections:
 *   1. MIRROR - (opt-in: MIRROR=1) the file in this repository is byte-identical to the copy
 *               served at https://mandateco.ca/downloads/mandate-verify.mjs, the verifier core
 *               embedded in https://mandateco.ca/verify.html matches this file's core, and the
 *               page publishes one sample key fingerprint. Needs network access; the default run
 *               is fully offline and skips it.
 *   2. VECTOR - all three payload builders (checkpoint, signed record, access record) reproduce
 *               the cross-language golden vectors exactly (the same vectors the product's own test
 *               suites assert), signatures verify, a flipped bit fails, and the key fingerprint
 *               derivation matches.
 *   3. TAMPER - a synthetic pack signed with the (public, test-only) vector seed verifies, and
 *               every tamper class is caught: content flip, injected file, metadata flip, missing
 *               file, duplicate entry, entry-count bomb, declared-size bomb, non-zip; the records
 *               inside the pack are walked (an edited, swapped or foreign record, a register row,
 *               person, change-trail entry, erasure, policy text, sealed list or printed report
 *               that no longer matches); two exports are compared both ways; the script itself is
 *               run the way an auditor runs it; the same file matrix runs over an access record.
 *   4. PACKS  - the committed sample packs under samples/ verify end to end, and the fingerprint
 *               the README publishes for them is the key that actually signed them.
 *
 * Usage: node test/check.mjs            (offline)
 *        MIRROR=1 node test/check.mjs   (also compare against the live site)
 * Exits non-zero on any failure.
 */

import { readFile, readdir } from "node:fs/promises";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { inflateRawSync, deflateRawSync } from "node:zlib";
import { createHash, createPrivateKey, sign as signNode } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  hexToBytes,
  bytesToHex,
  base64ToBytes,
  buildCheckpointSignedPayload,
  buildEvidencePackSignedPayload,
  buildDsrAccessSignedPayload,
  verifyEd25519,
  sha256Hex,
  readZipEntries,
  verifyEvidencePackBytes,
  checkPackSequence,
  verifyDsrAccessPackBytes,
  detectPackKind,
  crc32,
  listSeal,
} from "../mandate-verify.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
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
const localText = await readFile(join(repoRoot, "mandate-verify.mjs"), "utf8");
// The fingerprint verify.html publishes for the samples, when the live page was fetched; section 4
// binds it to the README's.
let livePublishedFingerprint = null;
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
  livePublishedFingerprint = /id="sample-key-fingerprint"[^>]*>([0-9a-f]{64})</.exec(livePage)?.[1] ?? null;
  const liveSnippetFingerprint = /--expect-fingerprint\s+([0-9a-f]{64})/.exec(livePage)?.[1] ?? null;
  ok("verify.html publishes one sample fingerprint in both places",
    livePublishedFingerprint !== null && livePublishedFingerprint === liveSnippetFingerprint,
    `note=${livePublishedFingerprint} cli=${liveSnippetFingerprint}`);
}

// ── 2. VECTOR: golden-vector byte equality + signature checks ────────────────────────────────
console.log("\nVECTOR checks (cross-language golden vectors)");
const cpVector = JSON.parse(await readFile(join(repoRoot, "test/vectors/checkpoint-signed-payload-v1.vector.json"), "utf8"));
const epVector = JSON.parse(await readFile(join(repoRoot, "test/vectors/evidence-pack-signed-payload-v3.vector.json"), "utf8"));
const dsrVector = JSON.parse(await readFile(join(repoRoot, "test/vectors/dsr-access-signed-payload-v4.vector.json"), "utf8"));

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
  epVector.mutationsTruncated,
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
  epVector.mutationsTruncated,
  [...epVector.contents].reverse(),
);
ok("builder sorts contents (reversed input, same bytes)", bytesToHex(epPayloadReversed) === epVector.payloadHex);

const epSig = hexToBytes(epVector.signatureHex);
const epKey = base64ToBytes(epVector.publicKeyBase64);
ok("evidence-pack signature verifies", (await verifyEd25519(epPayload, epSig, epKey)).status === "valid");

// u32 range: `>>>` coerces through ToUint32, so 2 + 2**32 and 2.5 would both serialize as 2. The
// signature would still verify while the manifest JSON a reader opens said something else. The
// builder must reject, not coerce.
const buildWithVersion = (manifestVersion) => buildEvidencePackSignedPayload(
  epVector.tenantId, manifestVersion, epVector.generatedAt, epVector.windowFrom, epVector.windowTo,
  epVector.truncated, epVector.checkpointsTruncated, epVector.mutationsTruncated, epVector.contents);
await throws("manifestVersion at 2^32 -> builder rejects", async () => buildWithVersion(epVector.manifestVersion + 2 ** 32), "manifestVersion");
await throws("fractional manifestVersion -> builder rejects", async () => buildWithVersion(epVector.manifestVersion + 0.5), "manifestVersion");

// Access record (DSR access pack) payload: the third builder, pinned by its own shared vector.
const dsrPublicKeyBase64 = dsrVector.publicKeyBase64 ?? epVector.publicKeyBase64;
const buildDsr = (overrides = {}) => {
  const v = { ...dsrVector, ...overrides };
  return buildDsrAccessSignedPayload(
    v.tenantId, v.subjectHashHex, v.manifestVersion, v.generatedAt, v.windowFrom, v.windowTo,
    v.truncated, v.unscannableRows, v.degradedRows, v.partiallyScannableRows, v.opaqueRegions, v.opaqueBytes, v.contents);
};
const dsrPayload = buildDsr();
ok("DSR payload matches vector bytes", bytesToHex(dsrPayload) === dsrVector.payloadHex);
ok("DSR builder sorts contents (reversed input, same bytes)",
  bytesToHex(buildDsr({ contents: [...dsrVector.contents].reverse() })) === dsrVector.payloadHex);
const dsrSig = hexToBytes(dsrVector.signatureHex);
const dsrKey = base64ToBytes(dsrPublicKeyBase64);
ok("DSR signature verifies", (await verifyEd25519(dsrPayload, dsrSig, dsrKey)).status === "valid");
{
  const flipped = new Uint8Array(dsrSig);
  flipped[0] ^= 0x01;
  ok("flipped DSR signature fails", (await verifyEd25519(dsrPayload, flipped, dsrKey)).status === "invalid");
  ok("DSR payload with degradedRows changed differs", bytesToHex(buildDsr({ degradedRows: dsrVector.degradedRows + 1 })) !== dsrVector.payloadHex);
  ok("DSR payload with partiallyScannableRows changed differs", bytesToHex(buildDsr({ partiallyScannableRows: dsrVector.partiallyScannableRows + 1 })) !== dsrVector.payloadHex);
  ok("DSR payload with opaqueBytes changed differs", bytesToHex(buildDsr({ opaqueBytes: dsrVector.opaqueBytes + 1 })) !== dsrVector.payloadHex);
  ok("DSR payload with a null windowFrom differs", bytesToHex(buildDsr({ windowFrom: null })) !== dsrVector.payloadHex);
}
await throws("DSR manifestVersion at 2^32 -> builder rejects", async () => buildDsr({ manifestVersion: dsrVector.manifestVersion + 2 ** 32 }), "manifestVersion");
await throws("DSR subject hash of the wrong length -> builder rejects", async () => buildDsr({ subjectHashHex: "abcd" }), "subject_hash");

// ── 3. TAMPER: synthetic pack signed with the public test-vector seed ─────────────────────────
console.log("\nTAMPER matrix (synthetic pack, test-vector key)");

// Sign with the vector's all-zeros seed. This key is public and test-only; the committed sample
// packs are signed with a dedicated sample key that never appears in this repository.
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";
const vectorPrivateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from(PKCS8_ED25519_PREFIX, "hex"), Buffer.from(cpVector.seedBase64, "base64")]),
  format: "der",
  type: "pkcs8",
});
const signWithVectorKey = (payload) => new Uint8Array(signNode(null, payload, vectorPrivateKey));

// Minimal stored-entry (method 0) ZIP writer. Each entry carries its CRC-32, which the reader checks
// (2.3.1: an archive passes only if every common unzip tool would read the same files).
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
    const crc = crc32(e.data);
    const local = [u32(0x04034b50), u16(20), u16(0), u16(method), u16(0), u16(0), u32(crc), u32(body.length), u32(declared), u16(name.length), u16(0), name, body];
    const cd = [u32(0x02014b50), u16(20), u16(20), u16(0), u16(method), u16(0), u16(0), u32(crc), u32(body.length), u32(declared), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), name];
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

// Canonical records built by a small encoder written from the record layouts in docs/evidence-pack-format.md,
// independent of the verifier's decoder, so the suite proves the decoder against bytes it did not produce.
function encodeRecord(version, fields) {
  const parts = [Uint8Array.of(version, 0)];
  const u32 = (n) => Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  const enc = new TextEncoder();
  for (const [kind, value] of fields) {
    const bytes = value === null ? null : value instanceof Uint8Array ? value : enc.encode(value);
    if (kind === "opt") {
      if (bytes === null) parts.push(Uint8Array.of(0xff), u32(0));
      else parts.push(Uint8Array.of(0), u32(bytes.length), bytes);
    } else {
      parts.push(u32(bytes.length), bytes);
    }
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
const sha = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const uuidBytes = (u) => hexToBytes(u.replace(/-/g, ""));
const SYN_POLICY_VERSION = "77777777-1111-4111-8111-111111111111";
const SYN_OTHER_WORKSPACE = "99999999-2222-4222-8222-222222222222";
const SYN_AGENT = "ffffffff-0000-4000-8000-000000000001";
// 2.5.0: the policy text seals its list of names; policy/lists.json carries the names and salt. The seal below is a
// cross-language vector the product's own tests pin too.
const SYN_LIST_SALT = "000102030405060708090a0b0c0d0e0f";
const SYN_LIST_NAMES = ["Harrowgate Logistics", "Kestrel Marine Supply", "Québec Inc."];
const SYN_LIST_SEAL = "fc393a0f12ee79c23ab0f4c5324277676186c26f3d2992216144c9317d9a12b3";
const SYN_POLICY_YAML = "rules:\n  - id: pii-sin\n    action: block\n    detector:\n      type: sin_canada\n"
  + `  - id: clients\n    action: block\n    detector:\n      type: keyword_list\n      keywords:\n        sealed: ${SYN_LIST_SEAL}\n        count: 3\n`;
const SYN_LISTS = { schemaVersion: 1, namesIncluded: true, lists: [
  { versionId: SYN_POLICY_VERSION, ruleId: "clients", sealed: SYN_LIST_SEAL, count: 3, salt: SYN_LIST_SALT, keywords: SYN_LIST_NAMES }] };

function v1Record(id, prev, occurredAt) {
  return encodeRecord(1, [
    ["bare", prev], ["bare", "gateway"], ["bare", uuidBytes("cccccccc-0000-4000-8000-000000000001")], ["bare", uuidBytes(id)],
    ["bare", ""], ["bare", occurredAt], ["bare", "allow"], ["opt", null], ["bare", "openai"], ["bare", Uint8Array.of(1)],
    ["opt", null], ["bare", "[]"], ["bare", uuidBytes(epVector.tenantId)],
  ]);
}

function v8Record(id, prev, occurredAt, decision, policyHash, ruleHits, tenant = epVector.tenantId, agentId = null) {
  return encodeRecord(8, [
    ["opt", null], ["opt", agentId ? uuidBytes(agentId) : null], ["opt", null], ["bare", prev], ["bare", "gateway"],
    ["bare", uuidBytes("cccccccc-0000-4000-8000-000000000002")], ["bare", uuidBytes(id)], ["opt", null], ["bare", "gpt-4o"],
    ["bare", occurredAt], ["bare", decision], ["opt", uuidBytes(SYN_POLICY_VERSION)], ["bare", policyHash], ["bare", "openai"],
    ["opt", null], ["opt", null], ["bare", Uint8Array.of(2)], ["opt", null], ["opt", null], ["bare", ruleHits], ["opt", null],
    ["bare", uuidBytes(tenant)], ["opt", null],
  ]);
}

// 2.4.0: layout 9, a person's decision: v8's fields with person_seal after occurred_at, policy_version_sha256 behind the
// sentinel and subject_hash bare.
function v9Record(id, prev, occurredAt, decision, policyHash, ruleHits, personSeal) {
  return encodeRecord(9, [
    ["opt", null], ["opt", null], ["opt", null], ["bare", prev], ["bare", "proxy"],
    ["bare", uuidBytes("cccccccc-0000-4000-8000-000000000002")], ["bare", uuidBytes(id)], ["opt", null], ["bare", "gpt-4o"],
    ["bare", occurredAt], ["bare", personSeal], ["bare", decision], ["opt", uuidBytes(SYN_POLICY_VERSION)], ["opt", policyHash],
    ["bare", "openai"], ["opt", null], ["opt", null], ["bare", Uint8Array.of(2)], ["opt", null], ["opt", null], ["bare", ruleHits],
    ["bare", new Uint8Array(32).fill(0x5a)], ["bare", uuidBytes(epVector.tenantId)], ["opt", null],
  ]);
}

// 2.4.0: a change-trail entry sealed into the chain, layout 1 with the entry's id as its correlation id and the SHA-256 of
// its readable facts as its request hash.
function changeRecord(id, prev, occurredAt, entryId, digest) {
  return encodeRecord(1, [
    ["bare", prev], ["bare", "change_trail"], ["bare", uuidBytes(entryId)], ["bare", uuidBytes(id)], ["bare", ""],
    ["bare", occurredAt], ["bare", "change"], ["opt", null], ["bare", "mandate"], ["bare", digest], ["opt", null], ["bare", "[]"],
    ["bare", uuidBytes(epVector.tenantId)],
  ]);
}

// The suite's own seals, written from the documented layouts (name seal; change-trail entry seal v1), not the verifier's.
const SYN_SALT = "000102030405060708090a0b0c0d0e0f";
const synNameSeal = (saltHex, name) => sha(new Uint8Array([...new TextEncoder().encode("mandate.name-seal.v1"), 0, ...hexToBytes(saltHex), ...new TextEncoder().encode(name)]));
function synChangeSeal(row) {
  const enc = new TextEncoder();
  const u32 = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  const field = (b) => [...u32(b.length), ...b];
  const opt = (b) => (b === null ? [0xff, ...u32(0)] : [0, ...field(b)]);
  const ticks = BigInt(Date.parse(row.occurredAt.replace(/\.\d+/, ""))) * 10000n;
  const time = new Uint8Array(8);
  new DataView(time.buffer).setBigInt64(0, ticks);
  return sha(new Uint8Array([
    ...enc.encode("mandate.change-trail-entry.v1"), 0, ...field(uuidBytes(row.id)), ...field(uuidBytes(epVector.tenantId)), ...field(time),
    ...field(enc.encode(row.action)), ...field(enc.encode(row.actorType)), ...opt(row.actorId ? uuidBytes(row.actorId) : null),
    ...opt(row.actorDisplay ? synNameSeal(row.actorSalt, row.actorDisplay) : null), ...opt(row.mutationReason ? enc.encode(row.mutationReason) : null),
    ...opt(null), ...opt(null), ...opt(null), ...opt(null), ...opt(null), ...opt(null),
  ]));
}

async function merkleRootNode(hashes) {
  let level = hashes.map((h) => sha(Uint8Array.of(0, ...h)));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha(Uint8Array.of(1, ...level[i], ...(level[i + 1] ?? level[i]))));
    level = next;
  }
  return level[0];
}

const SYN_ERASURE = "e1e1e1e1-0000-4000-8000-000000000001";
const SYN_ERASURE_LATER = "e2e2e2e2-0000-4000-8000-000000000002";

// The synthetic pack, as the product writes one since 2.4.0: a v1 record, a v9 decision whose person is sealed, the first
// change-trail entry's change record, a record removed under a privacy request (naming the dsr.delete entry), the second
// entry's change record and a v8 agent decision, sealed by one checkpoint, with the register rows, the trail, the erasure
// entries, the policy text and a printed report that describe them. `tweak` edits the inputs before signing, the way a
// database edit would reach an honest export.
async function buildSyntheticPack(tweak = {}) {
  const enc = new TextEncoder();
  const tenantId = epVector.tenantId;
  const policyYaml = tweak.policyYaml ?? SYN_POLICY_YAML;
  const policyHash = sha(enc.encode(SYN_POLICY_YAML));
  const hit = '[{"action":"block","detectorType":"sin_canada","ruleId":"pii-sin"}]';
  const ids = ["aaaaaaaa-0000-4000-8000-000000000001", "aaaaaaaa-0000-4000-8000-000000000002",
    "aaaaaaaa-0000-4000-8000-000000000003", "aaaaaaaa-0000-4000-8000-000000000004"];
  const changeIds = ["bbbbbbbb-0000-4000-8000-000000000001", "bbbbbbbb-0000-4000-8000-000000000002"];
  const at = ["2026-01-15T11:00:00.0000000Z", "2026-01-15T11:10:00.0000000Z", "2026-01-15T11:20:00.0000000Z", "2026-01-15T11:30:00.0000000Z"];
  const changeAt = ["2026-01-15T11:15:30.0000000Z", "2026-01-15T11:25:30.0000000Z"];
  const person = "s.patel@workspace.example";
  const changes = [
    { source: "mutation", id: "dddddddd-0000-4000-8000-000000000001", occurredAt: "2026-01-15T11:15:00+00:00", actorType: "tenant_admin",
      actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT,
      action: "held_decision.denied", mutationReason: "Confirmed by phone." },
    { source: "mutation", id: "dddddddd-0000-4000-8000-000000000002", occurredAt: "2026-01-15T11:25:00+00:00", actorType: "tenant_admin",
      actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT,
      action: "held_decision.denied", mutationReason: "Not through an AI tool." },
  ];
  const r1 = v1Record(ids[0], new Uint8Array(32), at[0]);
  const r2 = v9Record(ids[1], sha(r1), at[1], tweak.forgeR2 ? "allow" : "block", policyHash, hit, synNameSeal(SYN_SALT, person));
  const c1 = changeRecord(changeIds[0], sha(r2), changeAt[0], changes[0].id, synChangeSeal(changes[0]));
  const removedHash = sha(enc.encode("a record removed under a privacy request"));
  const c2 = changeRecord(changeIds[1], removedHash, changeAt[1], changes[1].id, synChangeSeal(changes[1]));
  const r4 = v8Record(ids[3], sha(c2), at[3], "allow", policyHash, "[]", tweak.otherWorkspaceRecord ? SYN_OTHER_WORKSPACE : tenantId, SYN_AGENT);
  const positions = [ids[0], ids[1], changeIds[0], ids[2], changeIds[1], ids[3]];
  const sealed = [sha(r1), sha(r2), sha(c1), removedHash, sha(c2), sha(r4)];
  const root = await merkleRootNode(sealed);
  const signedR2 = tweak.editR2 ? v9Record(ids[1], sha(r1), at[1], "allow", policyHash, hit, synNameSeal(SYN_SALT, person)) : r2;
  const b64 = (b) => Buffer.from(b).toString("base64");
  let links = [
    { id: ids[0], occurredAt: at[0], record: b64(r1) },
    { id: ids[1], occurredAt: at[1], record: b64(signedR2) },
    { id: changeIds[0], occurredAt: changeAt[0], record: b64(c1) },
    tweak.erasureNamed === false
      ? { id: ids[2], occurredAt: at[2], deletedRecordSha256: bytesToHex(removedHash) }
      : { id: ids[2], occurredAt: at[2], deletedRecordSha256: bytesToHex(removedHash), erasedBy: tweak.erasedBy ?? SYN_ERASURE },
    { id: changeIds[1], occurredAt: changeAt[1], record: b64(c2) },
    { id: ids[3], occurredAt: at[3], record: b64(r4) },
  ];
  if (tweak.swap) links = [links[0], links[5], links[2], links[3], links[4], links[1]];
  // 2.3.2: an erased record keeps its place by its hash; a re-signed export can drop its last record and the checkpoint
  // that sealed it; a record or checkpoint can name another workspace.
  if (tweak.eraseR4) links[5] = { id: ids[3], occurredAt: at[3], deletedRecordSha256: bytesToHex(sha(r4)), erasedBy: SYN_ERASURE_LATER };
  if (tweak.dropLast) links = links.slice(0, 5);
  const sealedCount = tweak.dropLast ? 5 : 6;
  const sealedRoot = tweak.dropLast ? await merkleRootNode(sealed.slice(0, 5)) : root;
  const cpTenant = tweak.otherWorkspaceCheckpoint ? SYN_OTHER_WORKSPACE : tenantId;

  const cpPayload = buildCheckpointSignedPayload(cpTenant, positions[0], positions[sealedCount - 1], sealedCount, sealedRoot);
  const cp = {
    schemaVersion: 1,
    checkpointId: "11111111-2222-4333-8444-555555555555",
    tenantId: cpTenant,
    windowStartEventId: positions[0],
    windowEndEventId: positions[sealedCount - 1],
    windowStartOccurredAt: "2026-01-15T11:00:00+00:00",
    windowEndOccurredAt: tweak.dropLast ? "2026-01-15T11:25:30+00:00" : "2026-01-15T11:30:00+00:00",
    eventCount: sealedCount,
    merkleRootHex: bytesToHex(sealedRoot),
    signatureHex: bytesToHex(signWithVectorKey(cpPayload)),
    publicKeyBase64: cpVector.publicKeyBase64,
    publicKeyFingerprint: cpVector.publicKeyFingerprint,
    createdAt: "2026-01-15T12:00:00+00:00",
  };
  const decisions = [
    { source: "decision", id: ids[1], occurredAt: "2026-01-15T11:10:00+00:00", actorType: "system", action: tweak.rowAction ?? (tweak.forgeR2 ? "allow" : "block"),
      correlationId: "cccccccc-0000-4000-8000-000000000002", provider: "openai", model: "gpt-4o", policyVersionId: SYN_POLICY_VERSION,
      person: tweak.person ?? person, personSalt: SYN_SALT, rules: [{ ruleId: "pii-sin", detectorType: "sin_canada", action: "block" }],
      recordSha256: bytesToHex(sha(signedR2)) },
    { source: "decision", id: ids[3], occurredAt: "2026-01-15T11:30:00+00:00", actorType: "agent", actorId: tweak.rowAgent ?? SYN_AGENT,
      actorDisplay: tweak.agentName ?? "Invoice bot", action: "allow", correlationId: tweak.rowCorrelation ?? "cccccccc-0000-4000-8000-000000000002",
      provider: "openai", model: "gpt-4o", policyVersionId: SYN_POLICY_VERSION, recordSha256: bytesToHex(sha(r4)) },
  ];
  if (tweak.dropLast || tweak.eraseR4) decisions.pop();
  if (tweak.trailEdit) changes[0] = { ...changes[0], actorDisplay: "someone.else@workspace.example", mutationReason: "Approved by phone." };
  if (tweak.trailGone) {
    const { actorId, actorDisplay, actorSalt, ...rest } = changes[0];
    changes[0] = { ...rest, actorType: "mandate_support" };
  }
  if (tweak.trailDrop) changes.pop();
  const erasures = [
    { source: "mutation", id: SYN_ERASURE, occurredAt: "2026-01-15T11:40:00+00:00", actorType: "tenant_admin", actorId: "eeeeeeee-0000-4000-8000-000000000001",
      actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT, action: tweak.erasureAction ?? "dsr.delete" },
    ...(tweak.eraseR4 ? [{ source: "mutation", id: SYN_ERASURE_LATER, occurredAt: "2026-01-15T12:30:00+00:00", actorType: "tenant_admin",
      actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT, action: "dsr.delete" }] : []),
  ];
  const outcomes = new Map();
  for (const d of decisions) outcomes.set(d.action, (outcomes.get(d.action) ?? 0) + 1);
  if (tweak.summary === "zeroed") outcomes.delete("block");
  const versions = [{ id: SYN_POLICY_VERSION, version: 1, yamlSource: policyYaml, contentSha256: bytesToHex(sha(enc.encode(policyYaml))) }];
  const reportSummary = enc.encode('{"period":{"kind":"window"}}');
  const named = tweak.report === "other" ? "ab".repeat(32) : bytesToHex(sha(reportSummary));
  const report = enc.encode(`%PDF-1.4\n1 0 obj << ${tweak.report === "unnamed" ? "" : `/Keywords (mandate-summary-sha256:${named}) `}>> endobj\n%%EOF\n`);

  const files = new Map([
    ["policy/active.json", enc.encode('{"policy":"synthetic"}')],
    ["policy/versions.json", enc.encode(JSON.stringify(versions))],
    ["policy/lists.json", enc.encode(JSON.stringify(tweak.lists ?? SYN_LISTS))],
    ["register/decisions.json", enc.encode(JSON.stringify([...decisions, ...changes]))],
    ["mutations/policy-trail.json", enc.encode(JSON.stringify(changes))],
    ...(tweak.summary ? [["summary/decision-mix.json", enc.encode(JSON.stringify({ decisions: [...outcomes].map(([decision, count]) => ({ decision, count })) }))]] : []),
    ["chain/links.json", enc.encode(JSON.stringify({ schemaVersion: 1, truncated: tweak.chainTruncated === true, links }))],
    ["chain/erasures.json", enc.encode(JSON.stringify({ schemaVersion: 1, entries: tweak.erasuresDropped ? [] : erasures }))],
    ["register/mandates.json", enc.encode('{"asOf":"generatedAt","mandates":[]}')],
    ["assurance/detector-catch-rate.json", enc.encode('{"schemaVersion":1,"scope":"synthetic"}')],
    ["summary/framework-coverage.json", enc.encode('{"schemaVersion":1,"frameworkMix":[]}')],
    ["report/summary.json", reportSummary],
    ["report/report.pdf", report],
    ["README.txt", enc.encode("Synthetic pack for the verifier test suite.\n")],
    ["checkpoints/11111111-2222-4333-8444-555555555555.json", enc.encode(JSON.stringify(cp))],
  ]);

  const contents = [];
  for (const [name, data] of files) {
    contents.push({ filename: name, sha256Hex: await sha256Hex(data), byteLength: data.length });
  }
  const manifestVersion = tweak.manifestVersion ?? 3;
  const manifest = {
    manifestVersion,
    tenantId,
    generatedAt: tweak.generatedAt ?? "2026-01-15T12:00:00.0000000+00:00",
    windowFrom: tweak.windowFrom ?? "2026-01-15T00:00:00+00:00",
    windowTo: tweak.windowTo ?? "2026-01-15T12:00:00+00:00",
    truncated: tweak.manifestTruncated === true,
    checkpointsTruncated: false,
    mutationsTruncated: false,
    contents,
    checkpointIds: [cp.checkpointId],
    signatureHex: "",
    publicKeyBase64: epVector.publicKeyBase64,
    publicKeyFingerprint: epVector.publicKeyFingerprint,
  };
  const payload = buildEvidencePackSignedPayload(
    tenantId, manifestVersion, manifest.generatedAt, manifest.windowFrom, manifest.windowTo, manifest.truncated, false, false, contents);
  manifest.signatureHex = bytesToHex(signWithVectorKey(payload));

  const entries = [...files].map(([name, data]) => ({ name, data }));
  entries.push({ name: "manifest.json", data: enc.encode(JSON.stringify(manifest)) });
  return { entries, manifest };
}

const synthetic = await buildSyntheticPack();
const baseline = await verifyEvidencePackBytes(writeZip(synthetic.entries), inflateRaw);
ok("baseline synthetic pack is valid", baseline.overall === "valid", JSON.stringify({ m: baseline.manifest, c: baseline.chain }));
ok("baseline embeds one valid checkpoint", baseline.checkpoints.length === 1 && baseline.checkpoints[0].result.status === "valid");
ok("baseline walks the records: 5 live, 1 removed, the root recomputed, 2 decisions tied, 1 policy text",
  baseline.chain?.records === 5 && baseline.chain?.removed === 1 && baseline.chain?.checkpointsRecomputed === 1
    && baseline.chain?.decisionsTied === 2 && baseline.chain?.policyVersions === 1, JSON.stringify(baseline.chain));
ok("2.5.0: the list seal reproduces the cross-language vector", bytesToHex(await listSeal(SYN_LIST_SALT, SYN_LIST_NAMES)) === SYN_LIST_SEAL);
ok("2.5.0 baseline: the sealed list's names match its seal", baseline.chain?.listsSealed === 1 && baseline.chain?.listsChecked === 1, JSON.stringify(baseline.chain));
{
  const leftOut = { schemaVersion: 1, namesIncluded: false, lists: [{ versionId: SYN_POLICY_VERSION, ruleId: "clients", sealed: SYN_LIST_SEAL, count: 3 }] };
  const r = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ lists: leftOut })).entries), inflateRaw);
  ok("2.5.0: an export that leaves the names out is valid and says the list is sealed",
    r.overall === "valid" && r.chain?.listsSealed === 1 && r.chain?.listsChecked === 0, JSON.stringify(r.chain));
}
ok("2.4.0 baseline: the person and both change-trail entries tie to their records, the erasure is named, the report ties",
  baseline.chain?.peopleTied === 1 && baseline.chain?.changesTied === 2 && baseline.chain?.reportTied === true
    && baseline.chain?.erasures?.length === 1 && baseline.chain.erasures[0].reason === "privacy request" && baseline.chain.erasures[0].id === SYN_ERASURE,
  JSON.stringify(baseline.chain));
for (const [label, tweak, expect] of [
  // Since 2.4.0 a change record follows the edited decision, so the broken link to it is what is named first.
  ["a record edited after sealing -> the record after it no longer follows it", { editR2: true }, /does not follow the record before it|no longer reproduce its signed root/],
  ["two records swapped -> the links break", { swap: true }, /does not follow the record before it/],
  ["a readable row that differs from its record -> invalid", { rowAction: "allow" }, /readable row differs from its record/],
  ["policy text rewritten after the decisions -> invalid", { policyYaml: SYN_POLICY_YAML.replace("block", "warn") }, /no longer matches its version/],
  // 2.4.0: what used to be signed only with the export is now tied to the chain, so one export alone catches it.
  ["2.4.0: the person on a decision re-attributed -> invalid alone, the person named", { person: "k.wong@workspace.example" }, /readable row differs from its record: its person$/],
  ["2.4.0: a change-trail entry's approver and reason rewritten -> invalid alone", { trailEdit: true },
    /change-trail entry dddddddd-0000-4000-8000-000000000001 \(held_decision\.denied\) in mutations\/policy-trail\.json differs from its sealed record/],
  ["2.4.0: a change-trail entry that no longer names who acted -> invalid alone (the seal names them)", { trailGone: true }, /differs from its sealed record/],
  ["2.4.0: a record removed with no entry recording its erasure -> invalid", { erasureNamed: false }, /no entry records its erasure/],
  ["2.4.0: a removal naming an entry the export does not carry -> invalid", { erasuresDropped: true }, /which chain\/erasures\.json does not carry/],
  ["2.4.0: a removal naming an entry that records no erasure -> invalid", { erasureAction: "policy.update" }, /which records no erasure/],
  ["2.4.0: a printed report naming another summary -> invalid", { report: "other" }, /was not drawn from report\/summary\.json/],
  ["2.4.0: a printed report naming no summary -> invalid", { report: "unnamed" }, /does not name the summary it was drawn from/],
  ["2.4.0: a records file that says partial under a manifest that says complete -> invalid", { chainTruncated: true }, /signed manifest says the export is complete/],
  ["2.5.0: a name in a sealed list changed -> invalid", { lists: { ...SYN_LISTS, lists: [{ ...SYN_LISTS.lists[0], keywords: ["Harrowgate Logistics", "Kestrel Marine", "Québec Inc."] }] } },
    /names of rule clients do not match their seal/],
  ["2.5.0: a seal the policy text does not carry -> invalid", { lists: { ...SYN_LISTS, lists: [{ ...SYN_LISTS.lists[0], sealed: "ab".repeat(32) }] } },
    /seal of rule clients is not in its text/],
  ["2.5.0: names promised and not carried -> invalid", { lists: { schemaVersion: 1, namesIncluded: true, lists: [{ versionId: SYN_POLICY_VERSION, ruleId: "clients", sealed: SYN_LIST_SEAL, count: 3 }] } },
    /says it includes the names/],
]) {
  const r = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack(tweak)).entries), inflateRaw);
  ok(label, r.overall === "invalid" && r.manifest.status === "valid" && expect.test(r.chain?.reason ?? ""), r.chain?.reason);
}
{
  const later = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" })).entries), inflateRaw);
  const gapped = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T13:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" })).entries), inflateRaw);
  ok("two consecutive packs of one export -> the sequence joins", checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: later }]).status === "valid");
  ok("a gap between two packs -> the sequence is invalid", /gap/.test(checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: gapped }]).reason ?? ""));
}
{
  // 2.3.2: whoever holds the signing key can drop the last record of a period and sign
  // again, and that export passes alone. An earlier export of the same period still holds the record, and a genuine
  // export never leaves one out (an erased record keeps its place by its hash), so the two checked together fail and
  // name it, in either order.
  const pack = async (tweak) => verifyEvidencePackBytes(writeZip((await buildSyntheticPack(tweak)).entries), inflateRaw);
  const lastId = "aaaaaaaa-0000-4000-8000-000000000004";
  const dropped = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", dropLast: true });
  ok("a later export with its last record dropped and signed again -> passes alone", dropped.overall === "valid", JSON.stringify(dropped.chain));
  const missing = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: dropped }]);
  ok("that export next to an earlier one -> the sequence names the record left out",
    missing.status === "invalid" && missing.reason.includes(lastId) && /is in a but missing from b/.test(missing.reason), missing.reason);
  const reversed = checkPackSequence([{ name: "b", result: dropped }, { name: "a", result: baseline }]);
  ok("the same two given in the other order -> still named", reversed.status === "invalid" && reversed.reason.includes(lastId), reversed.reason);
  const erased = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", eraseR4: true });
  ok("a later export in which that record was erased since -> it keeps its place, the sequence joins",
    erased.overall === "valid" && checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: erased }]).status === "valid",
    JSON.stringify(erased.chain));
  // 2.3.3: which export was made first no longer decides the direction. An export made before a record existed is not
  // held to it: it covers its period up to a minute before it says it was made, and what that leaves out is named.
  const madeBefore = await pack({ generatedAt: "2026-01-15T11:28:00.0000000+00:00", dropLast: true });
  const grown = checkPackSequence([{ name: "a", result: madeBefore }, { name: "b", result: baseline }]);
  ok("an export made before a record existed, next to one made after -> joins, and names the record it could not hold",
    grown.status === "valid" && grown.notes.length === 1 && /^1 record of b inside the period of a not compared: a says it was made at 2026-01-15T11:28/.test(grown.notes[0]),
    JSON.stringify(grown));
  const erasedNote = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: erased }]);
  ok("a decision erased between the exports -> named, by id, outcome and time",
    erasedNote.status === "valid" && erasedNote.notes.some((n) => n === `1 decision erased between a and b: ${lastId} (allow, 2026-01-15T11:30:00.0000000Z)`),
    JSON.stringify(erasedNote));
  const erasedFirst = await pack({ generatedAt: "2026-01-15T11:59:00.0000000+00:00", eraseR4: true });
  const resurrected = checkPackSequence([{ name: "a", result: erasedFirst }, { name: "b", result: baseline }]);
  ok("a decision erased in the export that says it was made first, whole in the later -> invalid",
    resurrected.status === "invalid" && resurrected.kind === "erased-first" && resurrected.reason.includes(`decision ${lastId} is erased in a but whole in b`), resurrected.reason);
  const backdated = await pack({ generatedAt: "2026-01-15T11:59:00.0000000+00:00", dropLast: true });
  const backdatedPair = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: backdated }]);
  ok("a trimmed export dated before the full one -> still named (the order no longer comes from the dates)",
    backdatedPair.status === "invalid" && backdatedPair.kind === "missing" && backdatedPair.reason.includes(`decision ${lastId} is in a but missing from b`), backdatedPair.reason);
  const shorter = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", dropLast: true, windowTo: "2026-01-15T11:25:00+00:00" });
  ok("what remains: a trimmed export whose period ends before the dropped record -> not compared, the shorter period shows",
    checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: shorter }]).status === "valid" && shorter.identity.windowTo === "2026-01-15T11:25:00+00:00");
  const trailEdited = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", trailEdit: true });
  const trailEditPair = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: trailEdited }]);
  ok("a change-trail entry whose approver and reason changed -> the later export fails its own check, so the pair cannot join",
    trailEdited.overall === "invalid" && trailEditPair.status === "invalid" && trailEditPair.kind === "unreadable", trailEditPair.reason);
  const trailDropped = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", trailDrop: true });
  const trailDropPair = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: trailDropped }]);
  ok("a change-trail entry left out of the later export -> invalid, named",
    trailDropPair.status === "invalid" && trailDropPair.reason.includes("change-trail entry dddddddd-0000-4000-8000-000000000002 (held_decision.denied) is in a but missing from b"),
    trailDropPair.reason);
  // 2.4.0: a sealed entry keeps who acted, so an account removed later no longer changes the export; an export that
  // drops the name fails its own check (the 2.4.0 case above).
  const counted = await pack({ summary: "match" });
  ok("summary counts with an erased record in the export -> still compared, and match",
    counted.overall === "valid" && counted.chain.removed === 1 && counted.chain.summaryCompared === true, JSON.stringify(counted.chain));
  const zeroed = await pack({ summary: "zeroed" });
  ok("summary that hides the refusals, with an erased record in the export -> invalid",
    zeroed.overall === "invalid" && /summary\/decision-mix\.json: its counts do not match/.test(zeroed.chain?.reason ?? ""), zeroed.chain?.reason);
  const registerCut = await pack({ summary: "zeroed", manifestTruncated: true });
  ok("summary counts when the signed manifest says the register is partial -> not compared, and said",
    registerCut.overall === "valid" && registerCut.chain.summaryNotCompared === "the register is partial", JSON.stringify(registerCut.chain));

  // 2.3.4: every register field both exports show is compared, the person included; a failed
  // comparison carries a kind the page can word; each readable decision ties to every field its record seals.
  ok("a record left out has its own kind, and is named as a decision",
    missing.kind === "missing" && missing.subject === "decision" && missing.id === lastId, JSON.stringify(missing));
  const reattributed = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", person: "k.wong@workspace.example" });
  ok("2.4.0: the person on a decision changed in the register only -> fails alone (the person is sealed)",
    reattributed.overall === "invalid" && /its person$/.test(reattributed.chain?.reason ?? ""), JSON.stringify(reattributed.chain));
  const forgedLater = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", forgeR2: true });
  const forgedPair = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: forgedLater }]);
  ok("a decision re-sealed with another outcome -> the records disagree about that decision, outcome and sealed record named",
    forgedLater.overall === "valid" && forgedPair.kind === "changed" && forgedPair.id === "aaaaaaaa-0000-4000-8000-000000000002"
      && forgedPair.fields.join() === "outcome,sealed record", JSON.stringify(forgedPair));
  const renamedPair = checkPackSequence([{ name: "a", result: baseline },
    { name: "b", result: await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", agentName: "Payments bot" }) }]);
  ok("an agent renamed between the exports, same sealed agent id -> joins, and named",
    renamedPair.status === "valid" && renamedPair.notes.includes(`agent ${SYN_AGENT} is named Invoice bot in a and Payments bot in b`), JSON.stringify(renamedPair));
  const otherAgent = await pack({ rowAgent: "ffffffff-0000-4000-8000-000000000009" });
  ok("a register row naming another agent than its record -> invalid alone, the field named",
    otherAgent.overall === "invalid" && /readable row differs from its record: its agent$/.test(otherAgent.chain?.reason ?? ""), otherAgent.chain?.reason);
  const otherCorrelation = await pack({ rowCorrelation: "cccccccc-0000-4000-8000-000000000009" });
  ok("a register row with another correlation id than its record -> invalid alone",
    otherCorrelation.overall === "invalid" && /its correlation id$/.test(otherCorrelation.chain?.reason ?? ""), otherCorrelation.chain?.reason);
  ok("a pair that cannot be compared keeps a structural kind (different keys)",
    checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: { ...dropped, publicKeyFingerprint: "ab".repeat(32) } }]).kind === "key");
  ok("a valid pair lists the decisions erased between the exports",
    erasedNote.erased.length === 1 && erasedNote.erased[0].id === lastId && erasedNote.erased[0].outcome === "allow", JSON.stringify(erasedNote.erased));
  const laterStart = await pack({ windowFrom: "2026-01-15T11:25:00+00:00" });
  ok("an export counts the erased records of its own period",
    baseline.chain.removedInPeriod === 1 && laterStart.chain.removed === 1 && laterStart.chain.removedInPeriod === 0,
    JSON.stringify({ baseline: baseline.chain, laterStart: laterStart.chain }));
  const droppedPartial = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", dropLast: true, chainTruncated: true, manifestTruncated: true });
  ok("a later export whose signed manifest says partial -> held only to the span its records cover",
    droppedPartial.overall === "valid" && checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: droppedPartial }]).status === "valid");

  // A key change no longer switches the comparison off, when the reader trusts both keys.
  const otherKey = "ab".repeat(32);
  ok("packs signed by different keys, not both trusted -> refused as before",
    /signed by different keys/.test(checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: { ...dropped, publicKeyFingerprint: otherKey } }]).reason ?? ""));
  const acrossKeys = checkPackSequence([{ name: "a", result: baseline, trusted: true }, { name: "b", result: { ...dropped, publicKeyFingerprint: otherKey }, trusted: true }]);
  ok("packs signed by different keys, both trusted -> still compared record by record",
    acrossKeys.status === "invalid" && acrossKeys.reason.includes(lastId), acrossKeys.reason);
  const next = await pack({ windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" });
  ok("consecutive packs across a trusted key change -> the sequence joins",
    checkPackSequence([{ name: "a", result: baseline, trusted: true }, { name: "b", result: { ...next, publicKeyFingerprint: otherKey }, trusted: true }]).status === "valid");

  // Since 2.4.0 the product sets the signed flag whenever the records file is partial, so a
  // records file that says partial under a manifest that says complete fails (the 2.4.0 case above).
  const bothPartial = await pack({ chainTruncated: true, manifestTruncated: true });
  ok("records file and signed manifest both say partial -> valid, and reported partial",
    bothPartial.overall === "valid" && bothPartial.truncated === true && bothPartial.chain?.truncated === true, JSON.stringify(bothPartial.chain));
  const registerOnly = await pack({ manifestTruncated: true });
  ok("signed manifest says the register is partial, records file whole -> valid (the register cap can cut the register alone)",
    registerOnly.overall === "valid", JSON.stringify(registerOnly.chain));

  // A record or a checkpoint that names another workspace.
  const foreignRecord = await pack({ otherWorkspaceRecord: true });
  ok("a record naming another workspace -> invalid, and named",
    foreignRecord.overall === "invalid" && foreignRecord.manifest.status === "valid"
      && /record aaaaaaaa-0000-4000-8000-000000000004 names workspace 99999999-2222-4222-8222-222222222222/.test(foreignRecord.chain?.reason ?? ""),
    foreignRecord.chain?.reason);
  const foreignCheckpoint = await pack({ otherWorkspaceCheckpoint: true });
  ok("a checkpoint naming another workspace -> invalid, though its signature holds",
    foreignCheckpoint.overall === "invalid" && foreignCheckpoint.manifest.status === "valid"
      && /names workspace 99999999-2222-4222-8222-222222222222/.test(foreignCheckpoint.checkpoints[0]?.result.reason ?? ""),
    JSON.stringify(foreignCheckpoint.checkpoints[0]));

  // The script itself, run as an auditor runs it.
  const dir = mkdtempSync(join(tmpdir(), "mandate-verify-gate-"));
  try {
    const save = async (name, tweak) => {
      const path = join(dir, name);
      writeFileSync(path, writeZip((await buildSyntheticPack(tweak)).entries));
      return path;
    };
    const one = await save("a.zip", {});
    const later = await save("b.zip", { generatedAt: "2026-01-15T13:00:00.0000000+00:00", dropLast: true });
    const following = await save("c.zip", { windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" });
    const cli = (...args) => {
      const r = spawnSync(process.execPath, [join(repoRoot, "mandate-verify.mjs"), ...args], { encoding: "utf8" });
      return { code: r.status, out: `${r.stdout}${r.stderr}` };
    };
    const fp = epVector.publicKeyFingerprint;
    const pairs = fp.match(/../g);
    const unchecked = cli(one);
    ok("script, no fingerprint -> exit 4, and no result line starts with RESULT: VALID",
      unchecked.code === 4 && /^RESULT: NOT VERIFIED \(unchanged since signing, but the key was not checked: name the fingerprint from your agreement with --expect-fingerprint\)$/m.test(unchecked.out)
        && !/^RESULT: VALID/m.test(unchecked.out), unchecked.out.slice(-400));
    ok("script labels read as the page's: signed record, Workspace, Period, Complete",
      /^Kind\s+: signed record$/m.test(unchecked.out) && /^Workspace\s+: /m.test(unchecked.out) && /^Period\s+: .+ to .+$/m.test(unchecked.out)
        && /^Complete\s+: yes, the whole period$/m.test(unchecked.out) && !/^(Tenant|Pack|Truncated)\s+:/m.test(unchecked.out), unchecked.out.slice(0, 400));
    ok("script, the fingerprint in upper-case colon-separated pairs -> exit 0", cli(one, "--expect-fingerprint", pairs.join(":").toUpperCase()).code === 0);
    ok("script, the fingerprint in space-separated pairs -> exit 0", cli(one, "--expect-fingerprint", pairs.join(" ")).code === 0);
    ok("script, the right fingerprint then a wrong one -> exit 0 (every fingerprint named is trusted)",
      cli(one, "--expect-fingerprint", fp, "--expect-fingerprint", "cd".repeat(32)).code === 0);
    ok("script, only a wrong fingerprint -> exit 1", cli(one, "--expect-fingerprint", "cd".repeat(32)).code === 1);
    ok("script, a fingerprint that is not 64 hex characters -> exit 2", cli(one, "--expect-fingerprint", "abc").code === 2);
    const leftOutRun = cli(one, later, "--expect-fingerprint", fp);
    ok("script, an earlier and a later export, the later missing a record -> exit 1, the record named",
      leftOutRun.code === 1 && /^SEQUENCE: INVALID \(.*aaaaaaaa-0000-4000-8000-000000000004.*\)$/m.test(leftOutRun.out), leftOutRun.out.slice(-400));
    const joinedUnchecked = cli(one, following);
    ok("script, two parts that join, no fingerprint -> exit 4 and SEQUENCE: NOT VERIFIED",
      joinedUnchecked.code === 4 && /^SEQUENCE: NOT VERIFIED \(2 parts join record to record/m.test(joinedUnchecked.out) && !/^SEQUENCE: VALID/m.test(joinedUnchecked.out),
      joinedUnchecked.out.slice(-400));
    ok("script, two parts that join, fingerprint named -> exit 0 and SEQUENCE: VALID",
      /^SEQUENCE: VALID \(2 parts join record to record/m.test(cli(one, following, "--expect-fingerprint", fp).out));
    const erasedLater = await save("e.zip", { generatedAt: "2026-01-15T13:00:00.0000000+00:00", eraseR4: true });
    const erasedRun = cli(one, erasedLater, "--expect-fingerprint", fp);
    ok("script, a decision erased between two exports -> exit 0, SEQUENCE: VALID and a note naming it",
      erasedRun.code === 0 && /^SEQUENCE: VALID \(/m.test(erasedRun.out)
        && /^  note: 1 decision erased between .*a\.zip and .*e\.zip: aaaaaaaa-0000-4000-8000-000000000004 \(allow, /m.test(erasedRun.out), erasedRun.out.slice(-500));
    const who = await save("w.zip", { generatedAt: "2026-01-15T13:00:00.0000000+00:00", person: "k.wong@workspace.example" });
    const whoRun = cli(who, "--expect-fingerprint", fp);
    ok("script, the person changed in one export -> exit 1, the decision and the person named",
      whoRun.code === 1 && /^Records: \[FAIL\] decision aaaaaaaa-0000-4000-8000-000000000002: the readable row differs from its record: its person$/m.test(whoRun.out),
      whoRun.out.slice(-400));
    const named = cli(one, "--expect-fingerprint", fp);
    ok("script, valid with the fingerprint named -> prints the page's line and does not ask to compare the fingerprint again",
      named.code === 0 && /^Unchanged since it was signed, with the key you named: 2 decisions: 1 allowed and 1 refused\.$/m.test(named.out)
        && /This is the fingerprint you named\./.test(named.out) && !/Compare this fingerprint/.test(named.out), named.out.slice(-600));
    ok("script prints what the records are and what removed one",
      /^Records: \[ ok \] 5 records link in order \(3 decisions, 2 changes\)$/m.test(named.out)
        && /1 record removed under a privacy request on .* keeps its place \(entry e1e1e1e1-0000-4000-8000-000000000001\)/.test(named.out), named.out);
    ok("script --version reports 2.5.0", /^mandate-verify 2\.5\.0 /.test(cli("--version").out));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
{
  const r = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ manifestVersion: 2 })).entries), inflateRaw);
  ok("a format 2 pack -> a different format, not INVALID", r.overall === "unsupported" && /format 2/.test(r.manifest.reason ?? ""));
}

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
  // The third completeness flag. mutationsTruncated joined the signed payload in the v2 to v3
  // break; flipping it in the manifest without re-signing must fail exactly like the other two. A
  // completeness claim outside the signature is one anybody can edit.
  const manifest = { ...synthetic.manifest, mutationsTruncated: true };
  const entries = synthetic.entries.map((e) =>
    e.name === "manifest.json" ? { name: e.name, data: new TextEncoder().encode(JSON.stringify(manifest)) } : e,
  );
  const r = await verifyEvidencePackBytes(writeZip(entries), inflateRaw);
  ok("mutationsTruncated flip -> manifest signature invalid", r.overall === "invalid" && r.manifest.status === "invalid");
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
  ok("2.4.0: fingerprint spoof -> the manifest is refused for naming another key", r.overall === "invalid" && /names another key/.test(r.manifest.reason ?? ""));
  ok("fingerprint spoof -> reported fingerprint is the key hash, not the declared lie",
    r.publicKeyFingerprint === realFp && r.publicKeyFingerprint !== "0".repeat(64));
  ok("computed manifest fingerprint matches the published vector fingerprint", realFp === epVector.publicKeyFingerprint);
  ok("checkpoint fingerprint is computed from its own key",
    r.checkpoints[0]?.publicKeyFingerprint === cpVector.publicKeyFingerprint);
}
{
  // 2.4.0: the manifest's unsigned members must agree with what is signed.
  const edit = (change) => synthetic.entries.map((e) =>
    e.name === "manifest.json" ? { name: e.name, data: new TextEncoder().encode(JSON.stringify(change({ ...synthetic.manifest }))) } : e);
  const extra = await verifyEvidencePackBytes(writeZip(edit((m) => ({ ...m, note: "added later" }))), inflateRaw);
  ok("2.4.0: a manifest member the signature does not cover -> refused, the member named",
    extra.overall === "invalid" && /carries note, which its signature does not cover/.test(extra.manifest.reason ?? ""), extra.manifest.reason);
  const emptied = await verifyEvidencePackBytes(writeZip(edit((m) => ({ ...m, checkpointIds: [] }))), inflateRaw);
  ok("2.4.0: checkpointIds emptied -> refused", emptied.overall === "invalid" && /checkpointIds does not list/.test(emptied.manifest.reason ?? ""), emptied.manifest.reason);
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
    ["chain/links.json", enc.encode('{"schemaVersion":1,"truncated":false,"links":[]}')],
  ]);
  const bigContents = [];
  for (const [name, data] of bigFiles) bigContents.push({ filename: name, sha256Hex: await sha256Hex(data), byteLength: data.length });
  const bigManifest = {
    manifestVersion: 3, tenantId: epVector.tenantId, generatedAt: "2026-01-15T12:00:00.0000000+00:00",
    windowFrom: "2026-01-15T00:00:00+00:00", windowTo: "2026-01-15T12:00:00+00:00",
    truncated: false, checkpointsTruncated: false, mutationsTruncated: false, contents: bigContents, checkpointIds: [],
    signatureHex: "", publicKeyBase64: epVector.publicKeyBase64, publicKeyFingerprint: epVector.publicKeyFingerprint,
  };
  const bigPayload = buildEvidencePackSignedPayload(
    bigManifest.tenantId, 3, bigManifest.generatedAt, bigManifest.windowFrom, bigManifest.windowTo, false, false, false, bigContents);
  bigManifest.signatureHex = bytesToHex(signWithVectorKey(bigPayload));
  const bigEntries = [...bigFiles].map(([name, data]) => ({ name, data, deflate: name === "big/repetitive.txt" }));
  bigEntries.push({ name: "manifest.json", data: enc.encode(JSON.stringify(bigManifest)) });
  const r = await verifyEvidencePackBytes(writeZip(bigEntries), inflateRaw);
  ok("high-ratio deflate pack (>100x, under 50 MB) verifies", r.overall === "valid", JSON.stringify(r.manifest));
}

// ── 3b. TAMPER, DSR access pack: the same matrix over the other pack a customer receives ─────
console.log("\nTAMPER matrix (synthetic DSR access pack, test-vector key)");

async function buildSyntheticDsrPack() {
  const enc = new TextEncoder();
  const files = new Map([
    ["README.txt", enc.encode("Synthetic DSR access pack for the verifier test suite.\n")],
    ["audit/events.json", enc.encode('[{"id":"e1","policyDecision":"allow"}]')],
    ["usage/events.json", enc.encode("[]")],
  ]);
  const contents = [];
  for (const [name, data] of files) {
    contents.push({ filename: name, sha256Hex: await sha256Hex(data), byteLength: data.length });
  }
  const manifest = {
    manifestVersion: dsrVector.manifestVersion,
    tenantId: dsrVector.tenantId,
    subjectHashHex: dsrVector.subjectHashHex,
    generatedAt: "2026-01-15T12:00:00.0000000+00:00",
    windowFrom: "2026-01-01T00:00:00+00:00",
    windowTo: null,
    truncated: false,
    unscannableRows: 0,
    degradedRows: 0,
    partiallyScannableRows: 0,
    opaqueRegions: 0,
    opaqueBytes: 0,
    contents,
    signatureHex: "",
    publicKeyBase64: dsrPublicKeyBase64,
    publicKeyFingerprint: dsrVector.publicKeyFingerprint,
  };
  const payload = buildDsrAccessSignedPayload(
    manifest.tenantId, manifest.subjectHashHex, manifest.manifestVersion, manifest.generatedAt,
    manifest.windowFrom, manifest.windowTo, manifest.truncated, manifest.unscannableRows, manifest.degradedRows,
    manifest.partiallyScannableRows, manifest.opaqueRegions, manifest.opaqueBytes, contents);
  manifest.signatureHex = bytesToHex(signWithVectorKey(payload));
  const entries = [...files].map(([name, data]) => ({ name, data }));
  entries.push({ name: "manifest.json", data: enc.encode(JSON.stringify(manifest)) });
  return { entries, manifest };
}

const syntheticDsr = await buildSyntheticDsrPack();
{
  const zip = writeZip(syntheticDsr.entries);
  ok("synthetic DSR pack is detected as a DSR pack", (await detectPackKind(zip, inflateRaw)) === "dsr");
  ok("synthetic evidence pack is detected as an evidence pack", (await detectPackKind(writeZip(synthetic.entries), inflateRaw)) === "evidence");
  const r = await verifyDsrAccessPackBytes(zip, inflateRaw);
  ok("baseline synthetic DSR pack is valid", r.overall === "valid", JSON.stringify(r.manifest));
  ok("DSR result reports the subject hash the signature binds", r.subjectHashHex === dsrVector.subjectHashHex);
}
{
  const entries = syntheticDsr.entries.map((e) => ({ ...e, data: new Uint8Array(e.data) }));
  entries.find((e) => e.name === "audit/events.json").data[0] ^= 0x01;
  const r = await verifyDsrAccessPackBytes(writeZip(entries), inflateRaw);
  ok("DSR content flip -> file invalid, signature still valid",
    r.overall === "invalid" && r.files.find((f) => f.path === "audit/events.json")?.status === "invalid" && r.manifest.status === "valid");
}
{
  const entries = [...syntheticDsr.entries, { name: "evil.txt", data: new TextEncoder().encode("injected") }];
  const r = await verifyDsrAccessPackBytes(writeZip(entries), inflateRaw);
  ok("DSR injected file -> set-equality invalid", r.overall === "invalid" && r.files.find((f) => f.path === "evil.txt")?.status === "invalid");
}
{
  // A completeness claim edited outside the signature: the pack must not read as more complete.
  const manifest = { ...syntheticDsr.manifest, unscannableRows: 0, degradedRows: 0, truncated: true };
  const entries = syntheticDsr.entries.map((e) =>
    e.name === "manifest.json" ? { name: e.name, data: new TextEncoder().encode(JSON.stringify(manifest)) } : e,
  );
  const r = await verifyDsrAccessPackBytes(writeZip(entries), inflateRaw);
  ok("DSR metadata flip -> manifest signature invalid", r.overall === "invalid" && r.manifest.status === "invalid");
}
{
  // The subject hash re-labelled: the pack answers for someone else and the signature must fail.
  const manifest = { ...syntheticDsr.manifest, subjectHashHex: "00".repeat(32) };
  const entries = syntheticDsr.entries.map((e) =>
    e.name === "manifest.json" ? { name: e.name, data: new TextEncoder().encode(JSON.stringify(manifest)) } : e,
  );
  const r = await verifyDsrAccessPackBytes(writeZip(entries), inflateRaw);
  ok("DSR subject re-label -> manifest signature invalid", r.overall === "invalid" && r.manifest.status === "invalid");
}
{
  const entries = syntheticDsr.entries.filter((e) => e.name !== "usage/events.json");
  const r = await verifyDsrAccessPackBytes(writeZip(entries), inflateRaw);
  ok("DSR dropped file -> reported missing", r.overall === "invalid" && r.files.find((f) => f.path === "usage/events.json")?.status === "missing");
}

// ── 4. PACKS: committed sample packs verify end to end ───────────────────────────────────────
console.log("\nPACKS check (committed sample packs)");
const samplesDir = join(repoRoot, "samples");
const packNames = (await readdir(samplesDir)).filter((f) => f.startsWith("mandate-sample-record-") && f.endsWith(".zip"));

// The README's quick start names the sample key's fingerprint, and a reader pins it with
// --expect-fingerprint. Re-cutting the samples under another key would leave that anchor stale, so
// bind it to the key that actually signed them (and, with MIRROR=1, to the one verify.html publishes).
const readmeText = await readFile(join(repoRoot, "README.md"), "utf8");
const readmeFingerprint = /--expect-fingerprint\s+([0-9a-f]{64})/.exec(readmeText)?.[1] ?? null;
ok("README names the sample key fingerprint", readmeFingerprint !== null);
if (livePublishedFingerprint !== null) {
  ok("README fingerprint is the one verify.html publishes", readmeFingerprint === livePublishedFingerprint,
    `readme=${readmeFingerprint} page=${livePublishedFingerprint}`);
}

ok("committed sample packs are present", packNames.length > 0, `no mandate-sample-record-*.zip under ${samplesDir}`);
for (const name of packNames.sort()) {
  const bytes = new Uint8Array(await readFile(join(samplesDir, name)));
  try {
    const r = await verifyEvidencePackBytes(bytes, inflateRaw);
    ok(`${name} verifies`, r.overall === "valid", JSON.stringify(r.manifest));
    ok(`${name} embeds at least one checkpoint`, r.checkpoints.length >= 1);
    ok(`${name} is complete (no truncation)`, r.truncated === false && r.checkpointsTruncated === false && r.mutationsTruncated === false);
    ok(`${name} is signed by the key the README names`, r.publicKeyFingerprint === readmeFingerprint,
      `pack=${r.publicKeyFingerprint} readme=${readmeFingerprint}`);
  } catch (err) {
    ok(`${name} verifies`, false, err.message);
  }
}

console.log(`\n${checks} checks, ${failures} failure(s)`);
process.exitCode = failures === 0 ? 0 : 1;
