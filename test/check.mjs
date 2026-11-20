#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Mandate Systems Inc.
/**
 * check.mjs - test suite for mandate-verify.
 *
 * Sections, in the order they run:
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
 *               run the way an auditor runs it.
 *               2.6.0 also: a key that is not 32 bytes, a signed length that is not its file's, a
 *               checkpoint or access record that names another key's fingerprint, an access record
 *               with a member its signature does not cover or of another format, two exports that
 *               differ only in the salt that seals who acted or in how the Mandate ID is written.
 *               2.7.0: a change-trail entry's seal covers what its policy version changed (layout v2), a list's
 *               change by its counts; a change trail that names a list's entries, sealed yet or not, or gives a
 *               change a field the trail never has, is refused.
 *               2.8.0: the period report must say what other AI tools reported, and its figures must be the ones
 *               the pack's imports/<feed>.json files and imports block give.
 *               2.9.0: a change-trail entry a later export lacks because its change record was erased with the
 *               records it belongs to joins the sequence, and the erasure is named. An entry still waiting for its
 *               seal in the earlier export, absent from the later one, is a note, not a failure, unless the later
 *               one still carries its change record.
 *               2.10.0: an export made before its period ended (its signed generatedAt before its signed windowTo,
 *               compared at the millisecond the signature binds) is valid and in progress, and its report must say
 *               so; one made before its period began says it holds nothing of it; a later export must start no
 *               later than a minute before one in progress was made; a sequence whose parts hold less than their
 *               period says it is in progress. A checkpoint file is checked alone, by its signature and its key,
 *               and only when its name ends in .json: a checkpoint renamed .zip is not a record, and one given
 *               beside records or found in a folder of them is checked on its own, apart from their sequence,
 *               the exit code the most serious of all of them.
 *               2.11.0: a change-trail entry that carries what a mandate approves or ends is sealed by layout v3;
 *               a mandate fact rewritten or removed after sealing fails, and an entry, sealed yet or not, carrying
 *               a mandate fact no seal covers is refused.
 *               2.12.0: a change-trail entry that carries a concluded assessment's facts is sealed by layout v4
 *               (the assessment's id and the SHA-256 of its document); the hash rewritten or the facts removed
 *               after sealing fails, and an entry carrying a fact no seal covers, or both a mandate's and an
 *               assessment's facts, is refused.
 *               2.13.0: a change-trail entry that carries a governance record's facts (a finding's review, a version
 *               of an artifact) is sealed by layout v5 (the record's kind, its id and the SHA-256 of its document),
 *               with the same rules.
 *               2.14.0: a record chained as a test-set prompt (decision "test") links and verifies like any other
 *               and is counted as a test prompt, not a decision.
 *               2.15.0: a version 2 imports file keeps Mandate's own notes on reading a row apart from the rules
 *               that fired on it, and the report's count of rows Mandate could not read in full is recomputed;
 *               a complete export (an archive of part-K-of-N.zip records and no manifest.json) is told by what it
 *               holds, whatever its name, and never checked as a record; a part missing from records named as
 *               parts fails the sequence and is named; a check of several files ends with OVERALL, whose word is
 *               always its exit code's.
 *               2.16.0: assessments/final-decisions.json, written by an encoder independent of the checker (section 4).
 *               2.17.0: each sealed document in the assessment files is recomputed and must equal the hash beside
 *               it and the hash its change-trail entry carries, and its readable row must say what it says.
 *               2.18.0: outside RFC 3161 timestamps on checkpoints (section 6).
 *               2.19.0: each finding's review decision and each assessment's sign-off are read against the sealed
 *               reviews and the change trail.
 *               2.20.0: an artifact version linked to a measure value that went past its limit names that value, in
 *               its sealed record and in its readable row.
 *               2.21.0: a record whose change trail is sealed in the layout used before 2.7.0 (every sealed entry
 *               under v1, no later layout's facts, no report section on other AI tools, checkpoints of format 1) is
 *               a different format, never INVALID, and a sequence holding one is not checked rather than invalid; a
 *               changed one, a mix of layouts or a key not named still fails. One part given alone whose name says
 *               there are more fails the sequence; a part not verified for a reason of its own says so on the
 *               SEQUENCE and OVERALL lines; --json prints a document when a file cannot be read; the usage text
 *               states the exit codes and the one-minute rule as the checks apply them.
 *               2.21.1: no line a reader sees calls the tool the verifier; when one copy of a change-trail entry names
 *               who acted and the other does not, the note says which export names who acted and which carries the
 *               entry's sealed record, and gives no reason the checker could not check.
 *               2.22.0: two copies of a change-trail entry, in the trail, the register, chain/erasures.json or the final
 *               decisions, must agree on who acted: a later export cut to start after the entry's sealed record and
 *               rewritten to name no one fails beside the earlier export, in either order, and so does a copy whose own
 *               seal names no one, or an untied copy that does not match the other export's sealed record; one export
 *               whose records seal an entry twice fails alone, and so do two that seal it by different records.
 *               2.23.0: an export placed between two others no longer keeps them from being compared: two that are not
 *               neighbours but whose periods or records overlap, or that hold one record or decision, are compared record
 *               by record, with files named one by one and in a folder (read again a pair at a time), and a change-trail entry
 *               held by two exports far apart is held to one copy and one seal; three exports that joined under 2.22.0 with
 *               one entry named in the first and not in the last, or missing from the last, or a decision rewritten in the
 *               last, fail, and a genuine three and consecutive parts still pass.
 *   4. FINAL DECISIONS (2.16.0) - each batch's record hashes to the record its change-trail entry seals, that entry
 *               ties to its change record like any other, and each decision's salted digest is one its batch lists,
 *               every listed digest carried once; a decision's document, salt or digest changed, one left out or
 *               added, the batch record or its seal changed, or a document or record naming another batch, AI system
 *               or Mandate ID, is INVALID. An erased decision is counted as erased; a batch whose change record is
 *               not in chain/links.json is counted not checked, never a pass; a file of a later version is not
 *               compared and says why; a pack without the file verifies as before.
 *   5. TAMPER, access record - the same file matrix over a synthetic access record, with its manifest rules
 *               and a format the script does not read.
 *   6. OUTSIDE TIMESTAMPS (2.18.0) - DigiCert's real token over the shared test checkpoint verifies, and every
 *               one-byte change to it is answered without a throw or an unverified time; a test authority built
 *               here (root, CA, timestamping certificate) signs tokens that are refused when over other bytes,
 *               outside a certificate's validity, from a certificate not for timestamping only, under a CA that
 *               is not one, signed by another key, rewritten after signing, or vouching for its time to more than
 *               a minute; a token whose root is not held is untrusted, never valid or invalid. In an export:
 *               stamped in order is valid, a checkpoint stamped after a later one or left without a token before
 *               one that has one is INVALID, the newest left unstamped is named, a token over a day after its
 *               records is named late, and --require-timestamps reports NOT VERIFIED.
 *   7. PACKS  - the committed sample packs under samples/ verify end to end, and the fingerprint
 *               the README publishes for them is the key that actually signed them.
 *
 * Usage: node test/check.mjs            (offline)
 *        MIRROR=1 node test/check.mjs   (also compare against the live site)
 * Exits non-zero on any failure.
 *
 * Four options write synthetic records, signed with the test vector's key, into <dir> and stop:
 *   --write-joined-pair <dir>      two parts that join (mandate-part-1.zip, mandate-part-2.zip), a later export of
 *                                  part 1's period with a decision erased (mandate-erased-later.zip), a second part
 *                                  made before its period ended (mandate-part-2-in-progress.zip), and the two parts as
 *                                  a complete export holds them (mandate-complete-export.zip).
 *   --write-final-decisions <dir>  a pack carrying final decisions (mandate-final-decisions.zip) and the same pack with
 *                                  one decision changed after sealing and signed again (mandate-final-decisions-changed.zip).
 *   --write-sign-off <dir>         a pack whose assessment is signed off (mandate-signed-off.zip) and the same pack with
 *                                  a finding's review decision rewritten and signed again (mandate-signed-off-changed.zip).
 *   --write-earlier-layout <dir>   a record as Mandate made one before checker 2.7.0 (mandate-before-2.7.0.zip) and the
 *                                  same record with a change-trail entry rewritten and signed again
 *                                  (mandate-before-2.7.0-changed.zip).
 * They let an earlier version of the checker, or verify.html, be run on the same files.
 */
import { readFile, readdir } from "node:fs/promises";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { inflateRawSync, deflateRawSync } from "node:zlib";
import { createHash, createPrivateKey, generateKeyPairSync, sign as signNode } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  hexToBytes,
  bytesToHex,
  isCheckpointName,
  verifyCheckpointFileBytes,
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
// Read by name, so a checker without them fails the cases that use them instead of the whole run.
import * as checker from "../mandate-verify.mjs";

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
  // The page names the script's version and SHA-256 beside its download link.
  const localSha = createHash("sha256").update(await readFile(join(repoRoot, "mandate-verify.mjs"))).digest("hex");
  const liveSha = /SHA-256 of the file<\/strong>\s*<p[^>]*><code[^>]*>([0-9a-f]{64})</.exec(livePage)?.[1];
  ok("verify.html publishes the SHA-256 of this file", liveSha === localSha, `page=${liveSha} file=${localSha}`);
  const localVersion = /const TOOL_VERSION = "([^"]+)"/.exec(localText)?.[1];
  const liveVersion = /mandate-verify\.mjs<\/a>, version ([0-9.]+)</.exec(livePage)?.[1];
  ok("verify.html names this file's version", localVersion !== undefined && liveVersion === localVersion, `page=${liveVersion} file=${localVersion}`);
}

// ── 2. VECTOR: golden-vector byte equality + signature checks ────────────────────────────────
console.log("\nVECTOR checks (cross-language golden vectors)");
const cpVector = JSON.parse(await readFile(join(repoRoot, "test/vectors/checkpoint-signed-payload-v1.vector.json"), "utf8"));
const epVector = JSON.parse(await readFile(join(repoRoot, "test/vectors/evidence-pack-signed-payload-v3.vector.json"), "utf8"));
const dsrVector = JSON.parse(await readFile(join(repoRoot, "test/vectors/dsr-access-signed-payload-v4.vector.json"), "utf8"));
const tsVector = JSON.parse(await readFile(join(repoRoot, "test/vectors/checkpoint-timestamp-v1.vector.json"), "utf8"));
// 2.6.0: each vector's description says what the vector holds. Every name in it that reads as code (a dotted name, a name
// with an underscore or #, a camelCase name, a name of three or more capitalised words run together, or a document number)
// must be one of the vector's own members, a file in test/vectors or a payload domain tag this checker reads.
const vectorFiles = await readdir(join(repoRoot, "test/vectors"));
const domainTags = [checker.CHECKPOINT_SIGNED_PAYLOAD_DOMAIN_V1, checker.EVIDENCE_PACK_SIGNED_PAYLOAD_DOMAIN_V3, checker.DSR_ACCESS_SIGNED_PAYLOAD_DOMAIN_V4];
const codeLike = /[\w.#-]*(?:\w\.\w|[_#]|\b[a-z]+[A-Z]|\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*){2,}|\b[A-Z]{2,}-\d{4}\b)[\w.#-]*/g;
for (const [name, v] of [["checkpoint", cpVector], ["signed-record", epVector], ["access-record", dsrVector], ["checkpoint-timestamp", tsVector]]) {
  const foreign = (v.description.match(codeLike) ?? []).map((w) => w.replace(/[.-]+$/, ""))
    .filter((w) => !(w in v) && !vectorFiles.includes(w) && !domainTags.includes(w));
  ok(`2.6.0: the ${name} vector's description is self-contained`, foreign.length === 0, foreign.join(", ") || v.description);
}
ok("2.6.0: the description check finds a name from outside the vector",
  ["see notes.txt", "set SOME_SETTING", "a C# class", "SomeClassName", "design note XYZ-0042"].every((t) => (t.match(codeLike) ?? []).length > 0));

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
// 2.6.0: a manifest key that does not decode to 32 bytes.
const SHORT_KEY = Buffer.alloc(31).toString("base64");

// Minimal stored-entry (method 0) ZIP writer. Each entry carries its CRC-32, which the reader checks
// (2.5.0: an archive passes only if every common unzip tool would read the same files).
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

// The same archive with ZIP64 end records, as a writer emits them past 4 GB or 65,535 entries: the classic end record's
// counts, size and offset set to "see ZIP64", and a ZIP64 end record and its locator written before it. 76 bytes longer.
function zip64(zip) {
  const eocd = zip.length - 22;
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  const record = new Uint8Array(56);
  const r = new DataView(record.buffer);
  r.setUint32(0, 0x06064b50, true);
  r.setBigUint64(4, 44n, true);
  r.setUint16(12, 45, true);
  r.setUint16(14, 45, true);
  r.setBigUint64(24, BigInt(view.getUint16(eocd + 8, true)), true);
  r.setBigUint64(32, BigInt(view.getUint16(eocd + 10, true)), true);
  r.setBigUint64(40, BigInt(view.getUint32(eocd + 12, true)), true);
  r.setBigUint64(48, BigInt(view.getUint32(eocd + 16, true)), true);
  const locator = new Uint8Array(20);
  const l = new DataView(locator.buffer);
  l.setUint32(0, 0x07064b50, true);
  l.setBigUint64(8, BigInt(eocd), true);
  l.setUint32(16, 1, true);
  const end = zip.slice(eocd);
  const e = new DataView(end.buffer);
  e.setUint16(8, 0xffff, true);
  e.setUint16(10, 0xffff, true);
  e.setUint32(12, 0xffffffff, true);
  e.setUint32(16, 0xffffffff, true);
  const out = new Uint8Array(zip.length + 76);
  out.set(zip.subarray(0, eocd), 0);
  out.set(record, eocd);
  out.set(locator, eocd + 56);
  out.set(end, eocd + 76);
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

// 2.5.0: layout 9, a person's decision: v8's fields with person_seal after occurred_at, policy_version_sha256 behind the
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

// 2.5.0: a change-trail entry sealed into the chain, layout 1 with the entry's id as its correlation id and the SHA-256 of
// its readable facts as its request hash.
function changeRecord(id, prev, occurredAt, entryId, digest) {
  return encodeRecord(1, [
    ["bare", prev], ["bare", "change_trail"], ["bare", uuidBytes(entryId)], ["bare", uuidBytes(id)], ["bare", ""],
    ["bare", occurredAt], ["bare", "change"], ["opt", null], ["bare", "mandate"], ["bare", digest], ["opt", null], ["bare", "[]"],
    ["bare", uuidBytes(epVector.tenantId)],
  ]);
}

// The suite's own seals, written from the documented layouts (name seal; change-trail entry seal v2 to v5), not the verifier's.
const SYN_SALT = "000102030405060708090a0b0c0d0e0f";
const imported0 = { feed: "imported_m365_copilot", rows: 3, rowsWithRuleHits: 1, rowsNotReadInFull: 1, coversWindow: true,
  sourceFrom: "2026-01-10T09:00:00+00:00", sourceTo: "2026-01-14T17:30:00+00:00" };
// As a pack made before 2.15.0 counts the same rows: Mandate's notes among the rule hits, and no count of rows not read.
const imported0v1 = { feed: "imported_m365_copilot", rows: 3, rowsWithRuleHits: 3, coversWindow: true,
  sourceFrom: "2026-01-10T09:00:00+00:00", sourceTo: "2026-01-14T17:30:00+00:00" };
const synNameSeal = (saltHex, name) => sha(new Uint8Array([...new TextEncoder().encode("mandate.name-seal.v1"), 0, ...hexToBytes(saltHex), ...new TextEncoder().encode(name)]));
// 2.21.0: `v1` seals as Mandate did before checker 2.7.0, under its own domain with v2's fields up to the version and
// nothing after.
function synChangeSeal(row, { v1 = false } = {}) {
  const enc = new TextEncoder();
  const u32 = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  const field = (b) => [...u32(b.length), ...b];
  const opt = (b) => (b === null ? [0xff, ...u32(0)] : [0, ...field(b)]);
  const ticks = BigInt(Date.parse(row.occurredAt.replace(/\.\d+/, ""))) * 10000n;
  const time = new Uint8Array(8);
  new DataView(time.buffer).setBigInt64(0, ticks);
  const text = (v) => (v === null || v === undefined ? null : enc.encode(String(v)));
  const id = (v) => (v ? uuidBytes(v) : null);
  const entries = (list) => (list == null ? null : [...u32(list.length), ...list.flatMap((e) => field(enc.encode(e)))]);
  const t = row.transition ?? null;
  const changes = t?.changes == null ? null : [...u32(t.changes.length), ...t.changes.flatMap((c) => [
    ...field(enc.encode(c.kind)), ...field(enc.encode(c.ruleId)), ...opt(text(c.reason)), ...opt(text(c.from)), ...opt(text(c.to)),
    ...opt(entries(c.added)), ...opt(entries(c.removed)), ...opt(text(c.addedCount)), ...opt(text(c.removedCount))])];
  // v3 (2.11.0): a mandate entry's facts after v2's fields.
  const instant = (v) => {
    if (v == null) return null;
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, BigInt(Date.parse(v.replace(/\.\d+/, ""))) * 10000n);
    return [...b];
  };
  const m = row.mandate ?? null;
  const mandate = m === null ? null : [...field(enc.encode(m.slug)),
    ...opt(m.tools == null ? null : [...u32(m.tools.length), ...m.tools.flatMap((x) => [...field(enc.encode(x.server)), ...opt(text(x.tool)),
      ...field([(x.includesLaterTools ? 1 : 0) | (x.awaitingFirstList ? 2 : 0)])])]),
    ...opt(entries(m.purposes)), ...opt(instant(m.validFrom)), ...opt(instant(m.validUntil)), ...opt(text(m.then)), ...opt(text(m.successor))];
  // v4 (2.12.0): a concluded assessment's id and hash after v2's fields.
  const a = row.assessment ?? null;
  const assessment = a === null ? null : [...field(uuidBytes(a.assessmentId)), ...field(hexToBytes(a.sha256))];
  // v5 (2.13.0): a governance record's kind, id and hash after v2's fields.
  const r = row.record ?? null;
  const record = r === null ? null : [...field(enc.encode(r.kind)), ...field(uuidBytes(r.id)), ...field(hexToBytes(r.sha256))];
  const fields = [...field(uuidBytes(row.id)), ...field(uuidBytes(epVector.tenantId)), ...field(time),
    ...field(enc.encode(row.action)), ...field(enc.encode(row.actorType)), ...opt(id(row.actorId)),
    ...opt(row.actorDisplay ? synNameSeal(row.actorSalt, row.actorDisplay) : null), ...opt(text(row.mutationReason)),
    ...opt(text(t?.kind)), ...opt(text(t?.reason)), ...opt(id(t?.policyId)), ...opt(id(t?.versionId)), ...opt(id(t?.priorVersionId)),
    ...opt(text(t?.version))];
  if (v1) return sha(new Uint8Array([...enc.encode("mandate.change-trail-entry.v1"), 0, ...fields]));
  return sha(new Uint8Array([
    ...enc.encode(mandate !== null ? "mandate.change-trail-entry.v3" : assessment !== null ? "mandate.change-trail-entry.v4"
      : record !== null ? "mandate.change-trail-entry.v5" : "mandate.change-trail-entry.v2"), 0, ...fields,
    ...opt(changes), ...(mandate === null ? [] : opt(mandate)), ...(assessment === null ? [] : opt(assessment)),
    ...(record === null ? [] : opt(record)),
  ]));
}

// 2.11.0: a mandate approval as the change trail carries it.
const SYN_MANDATE_ENTRY = { source: "mutation", id: "dddddddd-0000-4000-8000-000000000001", occurredAt: "2026-01-15T11:15:00+00:00",
  actorType: "tenant_admin", actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT,
  action: "mandate.granted", mandate: { slug: "invoice-bot", tools: [
    { server: "erp", tool: "get_invoice", includesLaterTools: false, awaitingFirstList: false },
    { server: "mail", includesLaterTools: true, awaitingFirstList: false },
    { server: "files", includesLaterTools: false, awaitingFirstList: true }],
  purposes: ["billing.read"], validUntil: "2026-12-31T00:00:00+00:00" } };
// 2.12.0: a concluded assessment as the change trail carries it.
const SYN_ASSESSMENT_ENTRY = { source: "mutation", id: "dddddddd-0000-4000-8000-000000000001", occurredAt: "2026-01-15T11:15:00+00:00",
  actorType: "tenant_admin", actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT,
  action: "assessment.concluded", assessment: { assessmentId: "aaaaaaaa-0000-4000-8000-000000000007",
    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" } };
// 2.13.0: a finding's review as the change trail carries it.
const SYN_RECORD_ENTRY = { source: "mutation", id: "dddddddd-0000-4000-8000-000000000001", occurredAt: "2026-01-15T11:15:00+00:00",
  actorType: "tenant_approver", actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT,
  action: "finding.reviewed", record: { kind: "finding_review", id: "aaaaaaaa-0000-4000-8000-000000000008",
    sha256: "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752" } };

// 2.17.0: an assessment concluded, a review of one of its findings, an artifact version, a measure's value and a version of an
// impact assessment, each as the canonical text
// Mandate hashes and the readable row the pack writes beside it, with the change-trail entry that carries each hash.
// `before` edits the documents before they are hashed, the way an edit made before sealing reaches an honest export;
// `after` edits the files and entries the pack carries once they are hashed. 2.19.0: the changed finding shows its review's
// decision; `signOff` has the other two findings accepted, the last at whole seconds as this suite seals a time, and the
// assessment signed off by that decision, with its sign-off entry.
const SYN_DOC = {
  system: "5a5a5a5a-0000-4000-8000-000000000001", framework: "f0f0f0f0-0000-4000-8000-000000000001",
  frameworkVersion: "f0f0f0f0-0000-4000-8000-000000000002", assessment: "a5a5a5a5-0000-4000-8000-000000000001",
  findings: ["f1f1f1f1-0000-4000-8000-000000000001", "f1f1f1f1-0000-4000-8000-000000000002", "f1f1f1f1-0000-4000-8000-000000000003"],
  review: "e5e5e5e5-0000-4000-8000-000000000001", artifact: "a7a7a7a7-0000-4000-8000-000000000001", person: "eeeeeeee-0000-4000-8000-000000000001",
  control: "c0c0c0c0-0000-4000-8000-000000000001", measure: "3e3e3e3e-0000-4000-8000-000000000001", value: "3e3e3e3e-0000-4000-8000-000000000002",
  impact: "1a1a1a1a-0000-4000-8000-000000000001",
  entries: { assessment: "dddddddd-0000-4000-8000-0000000000a1", review: "dddddddd-0000-4000-8000-0000000000a2", artifact: "dddddddd-0000-4000-8000-0000000000a3",
    measure: "dddddddd-0000-4000-8000-0000000000a4", impact: "dddddddd-0000-4000-8000-0000000000a5", accept0: "dddddddd-0000-4000-8000-0000000000a6",
    accept2: "dddddddd-0000-4000-8000-0000000000a7", signOff: "dddddddd-0000-4000-8000-0000000000a8" },
  accepts: ["e5e5e5e5-0000-4000-8000-000000000002", "e5e5e5e5-0000-4000-8000-000000000003"],
};

function synDocuments(d) {
  const hash = (text) => bytesToHex(sha(new TextEncoder().encode(text)));
  const finding = (i, requirementId, label, result, reason, confidence) => ({ requirementId, label, title: `Requirement ${label}`, groupId: "dadm-6.1",
    result, ...(reason ? { reason } : {}), ...(confidence ? { confidence: { value: confidence, weight: 1, coverage: 1, freshness: 1, label: "medium" } } : {}),
    checks: [], explanationEn: `Requirement ${label}.`, explanationFr: `Exigence ${label}.` });
  const docs = {
    assessment: { version: 1, assessment: { id: SYN_DOC.assessment, aiSystemId: SYN_DOC.system, aiSystemName: "Benefit triage", frameworkId: SYN_DOC.framework,
      frameworkSlug: "gc-dadm", frameworkVersionId: SYN_DOC.frameworkVersion, versionNumber: 1, versionLabel: "2025-06-24", versionSha256: "ab".repeat(32),
      trigger: "manual", windowFrom: "2026-01-08T11:15:00.1234567+00:00", windowTo: "2026-01-15T11:15:00.1234567+00:00",
      concludedAt: "2026-01-15T11:15:00.1234567+00:00", settings: { window_days: 7 },
      snapshot: { facts: { decision_role: "supports" }, links: [], policyVersionIds: [], coverage: { value: 0.666666666666, rows: 3, gradeA: 2, gradeB: 1, gradeC: 0 } } },
    findings: [finding(0, "dadm-6.1.1", "6.1.1", "met", null, 82), finding(1, "dadm-6.1.2", "6.1.2", "not_met", "blocking_failed", 39),
      finding(2, "dadm-6.1.3", "6.1.3", "unable_to_determine", "no_evidence", null)] },
    review: { version: 1, id: SYN_DOC.review, assessmentId: SYN_DOC.assessment, assessmentSha256: null, findingId: SYN_DOC.findings[1],
      requirementId: "dadm-6.1.2", computedResult: "not_met", computedConfidence: 39, action: "change", result: "partially_met", confidence: 55,
      note: "Checked with the system owner.", reviewerId: SYN_DOC.person, reviewerRoles: ["tenant_approver"], createdAt: "2026-01-15T11:20:00.1234567+00:00" },
    artifact: { version: 1, id: SYN_DOC.artifact, lineageId: SYN_DOC.artifact, artifactVersion: 1, kind: "document", title: "Pre-production test report",
      link: "https://intranet.example/ai/test-report", file: { name: "report.pdf", contentType: "application/pdf", size: 1234, sha256: "cd".repeat(32) },
      effectiveOn: "2026-01-10", withdrawn: false, suppliedBy: SYN_DOC.person, suppliedRoles: ["tenant_member"],
      links: [{ target: "ai_system", id: SYN_DOC.system }, { target: "control", id: SYN_DOC.control }, { target: "requirement", frameworkId: SYN_DOC.framework, requirementId: "dadm-6.1.2" }],
      createdAt: "2026-01-15T11:25:00.1234567+00:00" },
    measure: { version: 1, id: SYN_DOC.value, measureId: SYN_DOC.measure, aiSystemId: SYN_DOC.system, measureName: "Data completeness", kind: "data_quality",
      source: "pushed", unit: "share", direction: "higher_better", warningAt: 0.95, breachAt: 0.9, value: 0.93, status: "warning",
      observedAt: "2026-01-15T10:00:00.1234567+00:00", note: "From the nightly load.", suppliedBy: SYN_DOC.person, suppliedRoles: ["tenant_member"],
      createdAt: "2026-01-15T11:26:00.1234567+00:00" },
    impact: { version: 1, id: SYN_DOC.impact, aiSystemId: SYN_DOC.system, assessmentVersion: 2, source: "mandate", questionnaireVersion: "0.13.1",
      surveySha256: "ef".repeat(32), answers: { aboutDataSource1: "item1-2", decisionSector1: ["item3-1"] }, rawImpactScore: 41, mitigationScore: 12.5,
      currentScore: 41, level: 2, mitigationDeducted: false, completedOn: "2026-01-14", suppliedBy: SYN_DOC.person, suppliedRoles: ["tenant_approver"],
      createdAt: "2026-01-15T11:27:00.1234567+00:00" },
  };
  const accept = (n, i, createdAt) => ({ version: 1, id: SYN_DOC.accepts[n], assessmentId: SYN_DOC.assessment, assessmentSha256: null,
    findingId: SYN_DOC.findings[i], requirementId: docs.assessment.findings[i].requirementId, computedResult: docs.assessment.findings[i].result,
    computedConfidence: docs.assessment.findings[i].confidence?.value ?? null, action: "accept", result: null, confidence: null, note: null,
    reviewerId: SYN_DOC.person, reviewerRoles: ["tenant_approver"], createdAt });
  if (d.signOff) docs.accepts = [accept(0, 0, "2026-01-15T11:21:00.1234567+00:00"), accept(1, 2, "2026-01-15T11:22:00.0000000+00:00")];
  d.before?.(docs);
  const text = { assessment: JSON.stringify(docs.assessment) };
  if (docs.review.assessmentSha256 === null) docs.review.assessmentSha256 = hash(text.assessment);
  for (const [n, r] of (docs.accepts ?? []).entries()) {
    if (r.assessmentSha256 === null) r.assessmentSha256 = hash(text.assessment);
    text[`accept${n}`] = JSON.stringify(r);
  }
  text.review = JSON.stringify(docs.review);
  text.artifact = JSON.stringify(docs.artifact);
  text.measure = JSON.stringify(docs.measure);
  text.impact = JSON.stringify(docs.impact);
  const digest = Object.fromEntries(Object.entries(text).map(([k, v]) => [k, hash(v)]));
  const micros = (v) => v.replace(/(\.\d{6})\d/, "$1");
  const a = docs.assessment.assessment;
  const files = {
    findings: { schemaVersion: 1, scope: "synthetic", truncated: false, assessments: [{
      id: a.id, aiSystemId: a.aiSystemId, frameworkId: a.frameworkId, frameworkVersionId: a.frameworkVersionId, trigger: a.trigger, status: "concluded",
      windowFrom: micros(a.windowFrom), windowTo: micros(a.windowTo), concludedAt: micros(a.concludedAt), requirements: 3, met: 1, partiallyMet: 0, notMet: 1,
      notApplicable: 0, unableToDetermine: 1, confidence: 39, coverage: 0.6667, contentSha256: digest.assessment, auditEntryId: SYN_DOC.entries.assessment,
      document: text.assessment, findings: docs.assessment.findings.map((f, i) => ({ id: SYN_DOC.findings[i], requirementId: f.requirementId, label: f.label,
        result: f.result, ...(f.reason ? { reason: f.reason } : {}), ...(f.confidence ? { confidence: f.confidence.value } : {}) })) }] },
    reviews: { schemaVersion: 1, scope: "synthetic", truncated: false, reviews: [{ id: SYN_DOC.review, assessmentId: SYN_DOC.assessment, findingId: SYN_DOC.findings[1],
      requirementId: "dadm-6.1.2", action: "change", result: "partially_met", confidence: 55, reviewerId: SYN_DOC.person, reviewerRoles: ["tenant_approver"],
      createdAt: micros(docs.review.createdAt), contentSha256: digest.review, auditEntryId: SYN_DOC.entries.review, record: text.review }] },
    artifacts: { schemaVersion: 1, scope: "synthetic", truncated: false, artifacts: [{ id: SYN_DOC.artifact, lineageId: SYN_DOC.artifact, version: 1, kind: "document",
      title: "Pre-production test report", link: "https://intranet.example/ai/test-report",
      file: { name: "report.pdf", contentType: "application/pdf", size: 1234, sha256: "cd".repeat(32) }, effectiveOn: "2026-01-10", withdrawn: false,
      suppliedBy: SYN_DOC.person, suppliedRoles: ["tenant_member"], createdAt: micros(docs.artifact.createdAt), recordSha256: digest.artifact,
      auditEntryId: SYN_DOC.entries.artifact, record: text.artifact,
      links: [{ target: "ai_system", aiSystemId: SYN_DOC.system }, { target: "control", controlId: SYN_DOC.control },
        { target: "requirement", frameworkId: SYN_DOC.framework, requirementId: "dadm-6.1.2" }] }] },
    measureValues: { schemaVersion: 1, scope: "synthetic", truncated: false, values: [{ id: SYN_DOC.value, measureId: SYN_DOC.measure, aiSystemId: SYN_DOC.system,
      value: 0.93, status: "warning", observedAt: micros(docs.measure.observedAt), source: "pushed", suppliedBy: SYN_DOC.person, suppliedRoles: ["tenant_member"],
      createdAt: micros(docs.measure.createdAt), recordSha256: digest.measure, auditEntryId: SYN_DOC.entries.measure, record: text.measure }] },
    impactAssessments: { schemaVersion: 1, scope: "synthetic", truncated: false, impactAssessments: [{ id: SYN_DOC.impact, aiSystemId: SYN_DOC.system, version: 2,
      source: "mandate", questionnaireVersion: "0.13.1", level: 2, rawImpactScore: 41, mitigationScore: 12.5, currentScore: 41, mitigationDeducted: false,
      completedOn: "2026-01-14", suppliedBy: SYN_DOC.person, suppliedRoles: ["tenant_approver"], createdAt: micros(docs.impact.createdAt),
      recordSha256: digest.impact, auditEntryId: SYN_DOC.entries.impact, record: text.impact }] },
  };
  // The decision a review leaves on its finding, as Mandate writes it beside the computed result.
  const decided = (r) => ({ reviewState: { accept: "accepted", reject: "rejected", change: "changed" }[r.action],
    ...(r.action === "accept" ? { reviewedResult: r.computedResult, ...(r.computedConfidence != null ? { reviewedConfidence: r.computedConfidence } : {}) }
      : r.action === "change" ? { reviewedResult: r.result, reviewedConfidence: r.confidence } : {}),
    reviewedAt: micros(r.createdAt), reviewedBy: r.reviewerId });
  const row = files.findings.assessments[0];
  Object.assign(row.findings[1], decided(docs.review));
  for (const [n, r] of (docs.accepts ?? []).entries()) {
    Object.assign(row.findings[n === 0 ? 0 : 2], decided(r));
    files.reviews.reviews.push({ id: r.id, assessmentId: r.assessmentId, findingId: r.findingId, requirementId: r.requirementId, action: r.action,
      reviewerId: r.reviewerId, reviewerRoles: r.reviewerRoles, createdAt: micros(r.createdAt), contentSha256: hash(text[`accept${n}`]),
      auditEntryId: SYN_DOC.entries[`accept${n === 0 ? 0 : 2}`], record: text[`accept${n}`] });
  }
  if (d.signOff) Object.assign(row, { status: "signed_off", signedOffAt: "2026-01-15T11:22:00+00:00", signedOffBy: SYN_DOC.person });
  const entry = (kind, action, facts, occurredAt = "2026-01-15T11:15:00+00:00") => ({ source: "mutation", id: SYN_DOC.entries[kind], occurredAt,
    actorType: "tenant_admin", actorId: SYN_DOC.person, actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT, action, ...facts });
  const entries = {
    assessment: entry("assessment", "assessment.concluded", { assessment: { assessmentId: SYN_DOC.assessment, sha256: digest.assessment } }),
    review: entry("review", "finding.reviewed", { record: { kind: "finding_review", id: SYN_DOC.review, sha256: digest.review } }),
    artifact: entry("artifact", "artifact.supplied", { record: { kind: "artifact", id: SYN_DOC.artifact, sha256: digest.artifact } }),
    measure: entry("measure", "measure.value_recorded", { record: { kind: "measure_value", id: SYN_DOC.value, sha256: digest.measure } }),
    impact: entry("impact", "impact_assessment.recorded", { record: { kind: "impact_assessment", id: SYN_DOC.impact, sha256: digest.impact } }),
  };
  if (d.signOff) {
    for (const [n, r] of docs.accepts.entries()) {
      const kind = `accept${n === 0 ? 0 : 2}`;
      entries[kind] = entry(kind, "finding.reviewed", { record: { kind: "finding_review", id: r.id, sha256: hash(text[`accept${n}`]) } });
    }
    entries.signOff = entry("signOff", "assessment.signed_off", { record: { kind: "assessment_sign_off", id: SYN_DOC.assessment, sha256: digest.assessment } },
      "2026-01-15T11:22:00+00:00");
  }
  d.after?.(files, entries, text);
  return { files, entries, sealed: d.sealed ?? "assessment", digest };
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

// 2.6.0: a signer that writes a content's length as a signed 64-bit integer would sign a negative length as its two's
// complement. The script's builder refuses a negative length, so this suite writes those 8 bytes behind the content's SHA-256.
function signedLengths(payload, contents) {
  for (const c of contents.filter((x) => x.byteLength < 0)) {
    const at = Buffer.from(payload).indexOf(Buffer.from(hexToBytes(c.sha256Hex))) + 32;
    new DataView(payload.buffer, payload.byteOffset, payload.byteLength).setBigInt64(at, BigInt(c.byteLength));
  }
  return payload;
}

const SYN_ERASURE = "e1e1e1e1-0000-4000-8000-000000000001";
const SYN_ERASURE_LATER = "e2e2e2e2-0000-4000-8000-000000000002";

// The synthetic pack, as the product writes one since 2.5.0: a v1 record, a v9 decision whose person is sealed, the first
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
    // 2.7.0: a policy change, its client list's change by its counts.
    { source: "mutation", id: "dddddddd-0000-4000-8000-000000000002", occurredAt: "2026-01-15T11:25:00+00:00", actorType: "tenant_admin",
      actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT,
      action: "policy.activated", transition: { kind: "superseded", reason: "New client list", policyId: "77777777-1111-4111-8111-111111111111",
        versionId: "77777777-1111-4111-8111-111111111112", priorVersionId: "77777777-1111-4111-8111-111111111113", version: 2,
        changes: [{ kind: "keywords", ruleId: "client-names", reason: "Names a client", addedCount: 2, removedCount: 1 },
          { kind: "action", ruleId: "pii-sin", reason: "SIN", from: "warn", to: "block" }] } },
  ];
  // 2.11.0: the first entry a mandate approval, sealed by v3.
  if (tweak.mandate) changes[0] = structuredClone(SYN_MANDATE_ENTRY);
  // 2.12.0: the first entry a concluded assessment, sealed by v4.
  if (tweak.assessment) changes[0] = structuredClone(SYN_ASSESSMENT_ENTRY);
  // 2.13.0: the first entry a finding's review, sealed by v5.
  if (tweak.record) changes[0] = structuredClone(SYN_RECORD_ENTRY);
  // 2.17.0: the assessment files with their sealed documents, one kind's entry sealed as the first entry and the other two
  // made after the last seal.
  const docs = tweak.documents ? synDocuments(tweak.documents) : null;
  if (docs && tweak.documents.entries !== false) {
    changes[0] = docs.entries[docs.sealed];
    for (const [kind, entry] of Object.entries(docs.entries)) if (kind !== docs.sealed) changes.push(entry);
  }
  // 2.21.0: a record as Mandate made one before checker 2.7.0: each entry sealed under v1, a list's change naming its
  // entries, and a report that says nothing of other AI tools nor that its period was in progress. "mixed" seals the
  // second entry under v2, as it was written then, a mix Mandate never made.
  if (tweak.before270 && tweak.before270 !== "mixed") {
    changes[1] = { ...changes[1], transition: { ...changes[1].transition, changes: [
      { kind: "keywords", ruleId: "client-names", reason: "Names a client", added: ["Marie Tremblay", "Harrowgate Logistics"], removed: ["Old Client"] },
      changes[1].transition.changes[1]] } };
  }
  // 2.22.0: the first entry sealed naming no one, as a seal fixes an actor that no longer resolved when it was sealed.
  if (tweak.sealedGone) {
    const { actorId, actorDisplay, actorSalt, ...rest } = changes[0];
    changes[0] = { ...rest, actorType: "mandate_support" };
  }
  // 2.14.0: the last record a test-set prompt, chained as its own kind and in no register of decisions.
  const lastDecision = tweak.testPrompt ? "test" : "allow";
  const r1 = v1Record(ids[0], new Uint8Array(32), at[0]);
  const r2 = v9Record(ids[1], sha(r1), at[1], tweak.forgeR2 ? "allow" : "block", policyHash, hit, synNameSeal(SYN_SALT, person));
  const c1 = changeRecord(changeIds[0], sha(r2), changeAt[0], changes[0].id, synChangeSeal(changes[0], { v1: Boolean(tweak.before270) }));
  const removedHash = sha(enc.encode("a record removed under a privacy request"));
  const c2 = changeRecord(changeIds[1], removedHash, changeAt[1], changes[1].id,
    synChangeSeal(changes[1], { v1: Boolean(tweak.before270) && tweak.before270 !== "mixed" }));
  const r4 = v8Record(ids[3], sha(c2), at[3], lastDecision, policyHash, "[]", tweak.otherWorkspaceRecord ? SYN_OTHER_WORKSPACE : tenantId, SYN_AGENT);
  const positions = [ids[0], ids[1], changeIds[0], ids[2], changeIds[1], ids[3]];
  const sealed = [sha(r1), sha(r2), sha(c1), removedHash, sha(c2), sha(r4)];
  const b64 = (b) => Buffer.from(b).toString("base64");
  // 2.16.0: each final-decision batch's change record, sealed after the last decision.
  const finalDecisionLinks = [];
  for (const [i, s] of (tweak.finalDecisions?.seals ?? []).entries()) {
    const changeId = `bbbbbbbb-0000-4000-8000-0000000001${String(i).padStart(2, "0")}`;
    const changeAt = `2026-01-15T11:4${i}:30.0000000Z`;
    const record = changeRecord(changeId, sealed.at(-1), changeAt, s.entryId, s.digest);
    positions.push(changeId);
    sealed.push(sha(record));
    finalDecisionLinks.push({ id: changeId, occurredAt: changeAt, record: b64(record) });
  }
  const root = await merkleRootNode(sealed);
  const signedR2 = tweak.editR2 ? v9Record(ids[1], sha(r1), at[1], "allow", policyHash, hit, synNameSeal(SYN_SALT, person)) : r2;
  let links = [
    { id: ids[0], occurredAt: at[0], record: b64(r1) },
    { id: ids[1], occurredAt: at[1], record: b64(signedR2) },
    { id: changeIds[0], occurredAt: changeAt[0], record: b64(c1) },
    tweak.erasureNamed === false
      ? { id: ids[2], occurredAt: at[2], deletedRecordSha256: bytesToHex(removedHash) }
      : { id: ids[2], occurredAt: at[2], deletedRecordSha256: bytesToHex(removedHash), erasedBy: tweak.erasedBy ?? SYN_ERASURE },
    { id: changeIds[1], occurredAt: changeAt[1], record: b64(c2) },
    { id: ids[3], occurredAt: at[3], record: b64(r4) },
    ...finalDecisionLinks,
  ];
  if (tweak.swap) links = [links[0], links[5], links[2], links[3], links[4], links[1]];
  // 2.5.0: an erased record keeps its place by its hash; a re-signed export can drop its last record and the checkpoint
  // that sealed it; a record or checkpoint can name another Mandate ID.
  if (tweak.eraseR4) links[5] = { id: ids[3], occurredAt: at[3], deletedRecordSha256: bytesToHex(sha(r4)), erasedBy: SYN_ERASURE_LATER };
  // 2.9.0: the policy change's change record erased under the retention setting, its entry gone from the trail with it.
  if (tweak.eraseC2) links[4] = { id: changeIds[1], occurredAt: changeAt[1], deletedRecordSha256: bytesToHex(sha(c2)), erasedBy: SYN_ERASURE_LATER };
  if (tweak.dropLast) links = links.slice(0, 5);
  // 2.22.0: a records file cut so it starts after the first change record, as one capped at its size or at the register's
  // rows starts at a later sealed window; its register then holds only the decisions it ties.
  if (tweak.partialFromR3) links = links.slice(3);
  // 2.23.0: a records file that holds no record, as one cut before its first does.
  if (tweak.noLinks) links = [];
  const sealedCount = tweak.dropLast ? 5 : sealed.length;
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
    publicKeyFingerprint: tweak.checkpointFingerprint ?? cpVector.publicKeyFingerprint,
    createdAt: "2026-01-15T12:00:00+00:00",
  };
  // 2.18.0: the window split between two checkpoints (its first three records, then the rest), and `stamp` giving each an
  // outside timestamp (format 2 of a checkpoint; null for none yet).
  let cps = [cp];
  if (tweak.split) {
    const cut = 3;
    const half = async (id, from, to, start, end, created) => {
      const rootX = await merkleRootNode(sealed.slice(from, to + 1));
      const payload = buildCheckpointSignedPayload(tenantId, positions[from], positions[to], to - from + 1, rootX);
      return { ...cp, checkpointId: id, windowStartEventId: positions[from], windowEndEventId: positions[to], windowStartOccurredAt: start,
        windowEndOccurredAt: end, eventCount: to - from + 1, merkleRootHex: bytesToHex(rootX), signatureHex: bytesToHex(signWithVectorKey(payload)), createdAt: created };
    };
    cps = [await half(cp.checkpointId, 0, cut - 1, "2026-01-15T11:00:00+00:00", "2026-01-15T11:15:00+00:00", "2026-01-15T11:20:00+00:00"),
      await half("11111111-2222-4333-8444-666666666666", cut, sealedCount - 1, "2026-01-15T11:20:00+00:00", "2026-01-15T11:30:00+00:00", "2026-01-15T12:00:00+00:00")];
  }
  if (tweak.stamp) cps = cps.map((c, i) => ({ ...c, schemaVersion: 2, timestampTokenBase64: tweak.stamp(c, i) ?? null }));
  const decisions = [
    { source: "decision", id: ids[1], occurredAt: "2026-01-15T11:10:00+00:00", actorType: "system", action: tweak.rowAction ?? (tweak.forgeR2 ? "allow" : "block"),
      correlationId: "cccccccc-0000-4000-8000-000000000002", provider: "openai", model: "gpt-4o", policyVersionId: SYN_POLICY_VERSION,
      person: tweak.person ?? person, personSalt: SYN_SALT, rules: [{ ruleId: "pii-sin", detectorType: "sin_canada", action: "block" }],
      recordSha256: bytesToHex(sha(signedR2)) },
    { source: "decision", id: ids[3], occurredAt: "2026-01-15T11:30:00+00:00", actorType: "agent", actorId: tweak.rowAgent ?? SYN_AGENT,
      actorDisplay: tweak.agentName ?? "Invoice bot", action: "allow", correlationId: tweak.rowCorrelation ?? "cccccccc-0000-4000-8000-000000000002",
      provider: "openai", model: "gpt-4o", policyVersionId: SYN_POLICY_VERSION, recordSha256: bytesToHex(sha(r4)) },
  ];
  if (tweak.dropLast || tweak.eraseR4 || tweak.testPrompt) decisions.pop();
  if (tweak.partialFromR3) decisions.shift();
  // 2.23.0: the register's decision rows rewritten, as a database edit would reach an honest export.
  if (tweak.editDecisions) decisions.splice(0, decisions.length, ...tweak.editDecisions(decisions));
  if (tweak.trailEdit) changes[0] = { ...changes[0], actorDisplay: "someone.else@workspace.example", mutationReason: "Approved by phone." };
  if (tweak.listCount || tweak.listNames || tweak.listExtra) {
    const [list, ...rest] = changes[1].transition.changes;
    const edited = tweak.listCount ? { ...list, addedCount: 3 }
      : tweak.listExtra ? { ...list, names: ["Marie Tremblay"] }
      : { ...list, added: ["Marie Tremblay", "Harrowgate Logistics"], removed: ["Old Client"] };
    changes[1] = { ...changes[1], transition: { ...changes[1].transition, changes: [edited, ...rest] } };
  }
  // An entry made after the last seal, so the export carries no record for it yet.
  if (tweak.laterNames) changes.push({ ...changes[1], id: "dddddddd-0000-4000-8000-0000000000ff",
    transition: { ...changes[1].transition, changes: [{ ...changes[1].transition.changes[0], added: ["Marie Tremblay"] }] } });
  if (tweak.trailGone) {
    const { actorId, actorDisplay, actorSalt, ...rest } = changes[0];
    changes[0] = { ...rest, actorType: "mandate_support" };
  }
  if (tweak.trailDrop || tweak.eraseC2) changes.pop();
  // 2.23.0: the first entry left out of the trail and the register after it was sealed.
  if (tweak.dropFirstEntry) changes.shift();
  // 2.11.0: a mandate entry edited after sealing: a tool added, its facts removed, or a fact no seal covers.
  if (tweak.mandateToolAdded) changes[0].mandate.tools.push({ server: "erp", tool: "pay_invoice", includesLaterTools: false, awaitingFirstList: false });
  if (tweak.mandateTickFlipped) changes[0].mandate.tools[2].awaitingFirstList = false;
  if (tweak.mandateStripped) delete changes[0].mandate;
  if (tweak.mandateExtra) changes[0].mandate.boundary = "research-readonly";
  if (tweak.mandateToolExtra) changes[0].mandate.tools[0].toolClass = "send";
  if (tweak.mandateLater) changes.push({ ...structuredClone(SYN_MANDATE_ENTRY), id: "dddddddd-0000-4000-8000-0000000000fe",
    mandate: { ...SYN_MANDATE_ENTRY.mandate, scopeToolClasses: ["send"] } });
  // 2.12.0: an assessment entry edited after sealing: its hash rewritten, its facts removed, a fact no seal covers, or a
  // mandate's facts beside its own.
  if (tweak.assessmentHash) changes[0].assessment.sha256 = "ff" + changes[0].assessment.sha256.slice(2);
  if (tweak.assessmentStripped) delete changes[0].assessment;
  if (tweak.assessmentExtra) changes[0].assessment.findings = 45;
  if (tweak.assessmentWithMandate) changes[0].mandate = { slug: "invoice-bot" };
  if (tweak.assessmentLater) changes.push({ ...structuredClone(SYN_ASSESSMENT_ENTRY), id: "dddddddd-0000-4000-8000-0000000000fd",
    assessment: { ...SYN_ASSESSMENT_ENTRY.assessment, met: 12 } });
  // 2.13.0: a record entry edited after sealing: its hash rewritten, its facts removed, a fact no seal covers, or an
  // assessment's facts beside its own.
  if (tweak.recordHash) changes[0].record.sha256 = "ff" + changes[0].record.sha256.slice(2);
  if (tweak.recordStripped) delete changes[0].record;
  if (tweak.recordExtra) changes[0].record.result = "met";
  if (tweak.recordWithAssessment) changes[0].assessment = { ...SYN_ASSESSMENT_ENTRY.assessment };
  if (tweak.recordLater) changes.push({ ...structuredClone(SYN_RECORD_ENTRY), id: "dddddddd-0000-4000-8000-0000000000fc",
    record: { ...SYN_RECORD_ENTRY.record, note: "fine" } });
  // 2.6.0: a change-trail entry the records file does not seal: still queued (no salt), sealed outside this export (a
  // salt), or one that no longer names who acted.
  if (tweak.untied) {
    const entry = { source: "mutation", id: "dddddddd-0000-4000-8000-000000000003", occurredAt: "2026-01-15T11:35:00+00:00", actorType: "tenant_admin",
      actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", action: "policy.update", mutationReason: "Client list widened." };
    changes.push(tweak.untied === "gone" ? { ...entry, actorType: "mandate_support", actorId: null, actorDisplay: null }
      : tweak.untied === "salted" ? { ...entry, actorSalt: SYN_SALT }
        : tweak.untied === "other" ? { ...entry, actorDisplay: "someone.else@workspace.example", actorSalt: SYN_SALT } : entry);
  }
  const erasures = [
    { source: "mutation", id: SYN_ERASURE, occurredAt: "2026-01-15T11:40:00+00:00", actorType: "tenant_admin", actorId: "eeeeeeee-0000-4000-8000-000000000001",
      actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT, action: tweak.erasureAction ?? "dsr.delete" },
    ...(tweak.eraseR4 ? [{ source: "mutation", id: SYN_ERASURE_LATER, occurredAt: "2026-01-15T12:30:00+00:00", actorType: "tenant_admin",
      actorId: "eeeeeeee-0000-4000-8000-000000000001", actorDisplay: "a.martin@workspace.example", actorSalt: SYN_SALT, action: "dsr.delete" }] : []),
    ...(tweak.eraseC2 ? [{ source: "mutation", id: SYN_ERASURE_LATER, occurredAt: "2026-01-15T12:30:00+00:00", actorType: "system",
      action: "retention.row_expiry.started" }] : []),
  ];
  const outcomes = new Map();
  for (const d of decisions) outcomes.set(d.action, (outcomes.get(d.action) ?? 0) + 1);
  if (tweak.summary === "zeroed") outcomes.delete("block");
  const versions = [{ id: SYN_POLICY_VERSION, version: 1, yamlSource: policyYaml, contentSha256: bytesToHex(sha(enc.encode(policyYaml))) }];
  // 2.8.0: one imported feed, its rows as imports/<feed>.json carries them, and the report's figures for it.
  // 2.15.0: version 2 lists Mandate's own notes on reading a row apart from the rules that fired on it; version 1, as packs
  // made before it, lists both as rule hits.
  const importsV1 = tweak.importsV1 === true;
  const importedRows = tweak.importRows ?? (importsV1
    ? [
      { id: "ffffffff-0000-4000-8000-000000000001", sourceTime: "2026-01-10T09:00:00Z", payloadSha256: "ab".repeat(32), ruleHits: ["pii-sin"] },
      { id: "ffffffff-0000-4000-8000-000000000002", sourceTime: "2026-01-14T17:30:00Z", payloadSha256: "cd".repeat(32), ruleHits: ["policy.body_unscannable"] },
      { id: "ffffffff-0000-4000-8000-000000000003", sourceTime: "2026-01-12T12:00:00Z", payloadSha256: "ef".repeat(32), ruleHits: ["policy.attachment_present"] },
    ]
    : [
      { id: "ffffffff-0000-4000-8000-000000000001", sourceTime: "2026-01-10T09:00:00Z", payloadSha256: "ab".repeat(32), ruleHits: ["pii-sin"], notes: [] },
      { id: "ffffffff-0000-4000-8000-000000000002", sourceTime: "2026-01-14T17:30:00Z", payloadSha256: "cd".repeat(32), ruleHits: [],
        notes: ["policy.body_unscannable"] },
      { id: "ffffffff-0000-4000-8000-000000000003", sourceTime: "2026-01-12T12:00:00Z", payloadSha256: "ef".repeat(32), ruleHits: [],
        notes: ["policy.attachment_present"] },
    ]);
  const imported = [importsV1 ? imported0v1 : imported0];
  // 2.10.0: as the product writes it, the report says its period had not ended when the pack was made.
  const generatedAt = tweak.generatedAt ?? "2026-01-15T12:00:00.0000000+00:00";
  const windowTo = tweak.windowTo ?? "2026-01-15T12:00:00+00:00";
  const inProgress = tweak.summaryInProgress ?? (!tweak.before270 && Date.parse(generatedAt) < Date.parse(windowTo));
  const noImported = tweak.noImported ?? Boolean(tweak.before270);
  const reportSummary = enc.encode(JSON.stringify({ period: { kind: "window", ...(inProgress ? { inProgress: true } : {}) },
    ...(noImported ? {} : { imported: { source: "summary/decision-mix.json", grain: "importedRows", byFeed: tweak.imported ?? imported } }) }));
  const named = tweak.report === "other" ? "ab".repeat(32) : bytesToHex(sha(reportSummary));
  const report = enc.encode(`%PDF-1.4\n1 0 obj << ${tweak.report === "unnamed" ? "" : `/Keywords (mandate-summary-sha256:${named}) `}>> endobj\n%%EOF\n`);

  const files = new Map([
    ["policy/active.json", enc.encode('{"policy":"synthetic"}')],
    ["policy/versions.json", enc.encode(JSON.stringify(versions))],
    ["policy/lists.json", enc.encode(JSON.stringify(tweak.lists ?? SYN_LISTS))],
    ["register/decisions.json", enc.encode(JSON.stringify([...decisions, ...changes]))],
    ["mutations/policy-trail.json", enc.encode(JSON.stringify(changes))],
    ...(tweak.summary ? [["summary/decision-mix.json", enc.encode(JSON.stringify({ decisions: [...outcomes].map(([decision, count]) => ({ decision, count })),
      imports: tweak.packedImports ?? imported }))]] : []),
    ["imports/imported_m365_copilot.json", enc.encode(JSON.stringify({ schemaVersion: tweak.importVersion ?? (importsV1 ? 1 : 2), feed: "imported_m365_copilot",
      truncated: tweak.importsTruncated === true, rows: importedRows }))],
    ["chain/links.json", enc.encode(JSON.stringify({ schemaVersion: 1, truncated: tweak.chainTruncated === true, links }))],
    ...(docs ? [["assessments/findings.json", enc.encode(JSON.stringify(docs.files.findings))], ["assessments/reviews.json", enc.encode(JSON.stringify(docs.files.reviews))],
      ["assessments/artifacts.json", enc.encode(JSON.stringify(docs.files.artifacts))],
      ["assessments/measure-values.json", enc.encode(JSON.stringify(docs.files.measureValues))],
      ["assessments/impact-assessments.json", enc.encode(JSON.stringify(docs.files.impactAssessments))]] : []),
    ["chain/erasures.json", enc.encode(JSON.stringify({ schemaVersion: 1, entries: tweak.erasuresDropped ? [] : erasures }))],
    ["register/mandates.json", enc.encode('{"asOf":"generatedAt","mandates":[]}')],
    ["assurance/detector-catch-rate.json", enc.encode('{"schemaVersion":1,"scope":"synthetic"}')],
    ["summary/framework-coverage.json", enc.encode('{"schemaVersion":1,"frameworkMix":[]}')],
    ...(tweak.finalDecisions ? [["assessments/final-decisions.json", enc.encode(JSON.stringify(tweak.finalDecisions.file))]] : []),
    ["report/summary.json", reportSummary],
    ["report/report.pdf", report],
    ["README.txt", enc.encode("Synthetic pack for the verifier test suite.\n")],
    ...cps.map((c) => [`checkpoints/${c.checkpointId}.json`, enc.encode(JSON.stringify(c))]),
  ]);

  const contents = [];
  for (const [name, data] of files) {
    contents.push({ filename: name, sha256Hex: await sha256Hex(data), byteLength: tweak.byteLength?.(name, data.length) ?? data.length });
  }
  const manifestVersion = tweak.manifestVersion ?? 3;
  const manifest = {
    manifestVersion,
    // The signature binds the Mandate ID's 16 bytes, not how its hex is written.
    tenantId: tweak.upperTenant ? tenantId.toUpperCase() : tenantId,
    generatedAt,
    windowFrom: tweak.windowFrom ?? "2026-01-15T00:00:00+00:00",
    windowTo,
    truncated: tweak.manifestTruncated === true,
    checkpointsTruncated: false,
    mutationsTruncated: false,
    contents,
    checkpointIds: cps.map((c) => c.checkpointId),
    signatureHex: "",
    publicKeyBase64: tweak.manifestKey ?? epVector.publicKeyBase64,
    publicKeyFingerprint: epVector.publicKeyFingerprint,
  };
  const payload = signedLengths(buildEvidencePackSignedPayload(
    tenantId, manifestVersion, manifest.generatedAt, manifest.windowFrom, manifest.windowTo, manifest.truncated, false, false,
    contents.map((c) => ({ ...c, byteLength: Math.max(0, c.byteLength) }))), contents);
  manifest.signatureHex = bytesToHex(signWithVectorKey(payload));

  const entries = [...files].map(([name, data]) => ({ name, data }));
  entries.push({ name: "manifest.json", data: enc.encode(JSON.stringify(manifest)) });
  return { entries, manifest };
}

// 2.16.0: assessments/final-decisions.json, its decision documents and batch records written from the
// documented canonical JSON (members in code-point order, six fraction digits, no member left out) and hashed with node's
// own SHA-256, so the checker is proven against bytes it did not produce. Two batches, of two decisions and of one, each
// entry sealed into the chain after the pack's last decision. `fd` edits the inputs before sealing (an honest export of a
// wrong row) or after it (a row changed since), on the first batch unless it says otherwise.
const FD_SYSTEM = "abababab-0000-4000-8000-000000000001";
const FD_OTHER_SYSTEM = "abababab-0000-4000-8000-000000000002";
async function buildFinalDecisions(fd = {}) {
  const enc = new TextEncoder();
  const q = (v) => JSON.stringify(v);
  const documentOf = (d) => `{"aiSystemId":${q(d.aiSystemId)},"batchId":${q(d.batchId)},"caseRef":${q(d.caseRef)},`
    + `"correlationIds":[${d.correlationIds.map(q).join(",")}],"decidedAt":${q(d.decidedAt)},"decidedBy":${q(d.decidedBy)},`
    + `"decisionId":${q(d.decisionId)},"id":${q(d.id)},"outcome":${q(d.outcome)},"receivedAt":${q(d.receivedAt)},"tenantId":${q(d.tenantId)},"version":1}`;
  const recordOf = (r) => `{"aiSystemId":${q(r.aiSystemId)},"batchId":${q(r.batchId)},"decisionSha256s":[${r.decisionSha256s.map(q).join(",")}],`
    + `"receivedAt":${q(r.receivedAt)},"tenantId":${q(r.tenantId)},"version":1}`;
  const salted = (salt, document) => bytesToHex(sha(new Uint8Array([...hexToBytes(salt), ...enc.encode(document)])));
  const byDigest = (a, b) => (a.sha256 < b.sha256 ? -1 : a.sha256 > b.sha256 ? 1 : 0);
  const specs = [
    { batchId: "fdfdfdfd-0000-4000-8000-000000000001", entryId: "dddddddd-0000-4000-8000-000000000101", receivedAt: "2026-01-15T11:31:00.000000Z",
      occurredAt: "2026-01-15T11:31:00+00:00", cases: ["CASE-0001", "CASE-0002"] },
    { batchId: "fdfdfdfd-0000-4000-8000-000000000002", entryId: "dddddddd-0000-4000-8000-000000000102", receivedAt: "2026-01-15T11:32:00.000000Z",
      occurredAt: "2026-01-15T11:32:00+00:00", cases: ["CASE-0003"] },
  ];
  const decisionOf = (n, i, spec, caseRef, edited) => {
    const document = documentOf({
      aiSystemId: edited && fd.docSystem ? FD_OTHER_SYSTEM : FD_SYSTEM,
      batchId: edited && fd.docBatch ? specs[1 - n].batchId : spec.batchId,
      caseRef, correlationIds: ["cccccccc-0000-4000-8000-000000000002"], decidedAt: "2026-01-15T11:05:00.000000Z", decidedBy: `officer-04${n}${i}`,
      decisionId: `D-10${n}${i}`, id: `fdfdfdfd-1111-4000-8000-0000000000${n}${i}`, outcome: "approved", receivedAt: spec.receivedAt,
      tenantId: edited && fd.docTenant ? SYN_OTHER_WORKSPACE : epVector.tenantId,
    });
    const salt = createHash("sha256").update(`final-decision-salt-${n}-${i}`).digest("hex");
    return { sha256: salted(salt, document), salt, document };
  };
  const batches = [];
  const seals = [];
  for (const [n, spec] of specs.entries()) {
    const first = n === 0;
    let decisions = spec.cases.map((caseRef, i) => decisionOf(n, i, spec, caseRef, first && i === 0)).sort(byDigest);
    const record = recordOf({ aiSystemId: FD_SYSTEM, batchId: spec.batchId, decisionSha256s: decisions.map((d) => d.sha256), receivedAt: spec.receivedAt,
      tenantId: first && fd.recordTenant ? SYN_OTHER_WORKSPACE : epVector.tenantId });
    const recordSha256 = bytesToHex(sha(enc.encode(record)));
    const entry = { source: "mutation", id: spec.entryId, occurredAt: spec.occurredAt, actorType: "case_system", action: "final_decisions.recorded",
      record: { kind: "final_decisions", id: spec.batchId, sha256: recordSha256 } };
    const sealedEntry = first && fd.sealFlip ? { ...entry, record: { ...entry.record, sha256: `ff${recordSha256.slice(2)}` } } : entry;
    if (!(fd.unsealed && !first)) seals.push({ entryId: spec.entryId, digest: synChangeSeal(sealedEntry) });
    if (first) {
      if (fd.docFlip) decisions[0] = { ...decisions[0], document: decisions[0].document.replace('"approved"', '"refused"') };
      if (fd.saltFlip) decisions[0] = { ...decisions[0], salt: `${decisions[0].salt[0] === "0" ? "1" : "0"}${decisions[0].salt.slice(1)}` };
      if (fd.shaFlip) decisions[0] = { ...decisions[0], sha256: `${decisions[0].sha256[0] === "0" ? "1" : "0"}${decisions[0].sha256.slice(1)}` };
      if (fd.drop) decisions = decisions.slice(1);
      if (fd.extra) decisions = [...decisions, decisionOf(n, 9, spec, "CASE-0009", false)].sort(byDigest);
      if (fd.erase) decisions[0] = { sha256: decisions[0].sha256, erased: true };
    }
    batches.push({ batchId: spec.batchId, aiSystemId: FD_SYSTEM, receivedAt: spec.receivedAt, entryId: spec.entryId, entry,
      record: first && fd.recordFlip ? record.replace("11:31:00.000000Z", "11:31:01.000000Z") : record, decisions });
  }
  return { file: { schemaVersion: fd.schemaVersion ?? 1, scope: "Final decisions received in this period.", truncated: fd.truncated === true, batches }, seals };
}

// Two parts that join, signed with the test vector's key, and the files a test of several records needs beside them.
const pairAt = process.argv.indexOf("--write-joined-pair");
if (pairAt >= 0) {
  const into = process.argv[pairAt + 1];
  const first = writeZip((await buildSyntheticPack({})).entries);
  const second = writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00",
    windowTo: "2026-01-16T00:00:00+00:00", generatedAt: "2026-01-16T00:30:00.0000000+00:00" })).entries);
  writeFileSync(join(into, "mandate-part-1.zip"), first);
  writeFileSync(join(into, "mandate-part-2.zip"), second);
  // 2.15.0: the two parts as a complete export holds them.
  writeFileSync(join(into, "mandate-complete-export.zip"), writeZip([
    { name: "README.txt", data: new TextEncoder().encode("MANDATE EVIDENCE: A COMPLETE EXPORT\n") },
    { name: "part-0001-of-0002.zip", data: first },
    { name: "part-0002-of-0002.zip", data: second },
  ]));
  // With part 1, a sequence that carries a note.
  writeFileSync(join(into, "mandate-erased-later.zip"), writeZip((await buildSyntheticPack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00",
    eraseR4: true })).entries));
  // With part 1, a sequence in progress.
  writeFileSync(join(into, "mandate-part-2-in-progress.zip"), writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00",
    windowTo: "2026-01-16T00:00:00+00:00", generatedAt: "2026-01-15T18:00:00.0000000+00:00" })).entries));
  process.exit(0);
}

// A pack carrying final decisions, and the same pack with one decision's document changed after sealing and signed again,
// so a checker of any version can be run on both, as a release's notes show an earlier checker beside the new one.
const finalDecisionsAt = process.argv.indexOf("--write-final-decisions");
if (finalDecisionsAt >= 0) {
  const into = process.argv[finalDecisionsAt + 1];
  writeFileSync(join(into, "mandate-final-decisions.zip"), writeZip((await buildSyntheticPack({ finalDecisions: await buildFinalDecisions() })).entries));
  writeFileSync(join(into, "mandate-final-decisions-changed.zip"),
    writeZip((await buildSyntheticPack({ finalDecisions: await buildFinalDecisions({ docFlip: true }) })).entries));
  process.exit(0);
}

// 2.19.0: a pack whose assessment is signed off, and the same pack with a finding's review decision rewritten and signed
// again, so an earlier checker can be run beside this one (it passes both: it does not read the decisions).
const signOffAt = process.argv.indexOf("--write-sign-off");
if (signOffAt >= 0) {
  const into = process.argv[signOffAt + 1];
  writeFileSync(join(into, "mandate-signed-off.zip"), writeZip((await buildSyntheticPack({ documents: { signOff: true, sealed: "signOff" } })).entries));
  writeFileSync(join(into, "mandate-signed-off-changed.zip"), writeZip((await buildSyntheticPack({ documents: { signOff: true, sealed: "signOff",
    after: (f) => { Object.assign(f.findings.assessments[0].findings[1], { reviewedResult: "met", reviewedConfidence: 99 }); } } })).entries));
  process.exit(0);
}

// 2.21.0: a record as Mandate made one before checker 2.7.0, and the same record with a change-trail entry rewritten and
// signed again, so checker 2.6.0 can be run beside this one.
const earlierAt = process.argv.indexOf("--write-earlier-layout");
if (earlierAt >= 0) {
  const into = process.argv[earlierAt + 1];
  writeFileSync(join(into, "mandate-before-2.7.0.zip"), writeZip((await buildSyntheticPack({ before270: true })).entries));
  writeFileSync(join(into, "mandate-before-2.7.0-changed.zip"), writeZip((await buildSyntheticPack({ before270: true, trailEdit: true })).entries));
  process.exit(0);
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
{
  const withMandate = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ mandate: true })).entries), inflateRaw);
  ok("2.11.0: a mandate approval sealed by v3 beside a v2 entry -> valid, both tie to their records",
    withMandate.overall === "valid" && withMandate.chain?.changesTied === 2, JSON.stringify(withMandate.chain ?? withMandate));
}
{
  const withAssessment = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ assessment: true })).entries), inflateRaw);
  ok("2.12.0: a concluded assessment sealed by v4 beside a v2 entry -> valid, both tie to their records",
    withAssessment.overall === "valid" && withAssessment.chain?.changesTied === 2, JSON.stringify(withAssessment.chain ?? withAssessment));
}
{
  const withRecord = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ record: true })).entries), inflateRaw);
  ok("2.13.0: a finding's review sealed by v5 beside a v2 entry -> valid, both tie to their records",
    withRecord.overall === "valid" && withRecord.chain?.changesTied === 2, JSON.stringify(withRecord.chain ?? withRecord));
}
{
  const withTest = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ testPrompt: true })).entries), inflateRaw);
  ok("2.14.0: a test-set prompt links and verifies, counted as a test prompt and not as a decision",
    withTest.overall === "valid" && withTest.chain?.kinds?.tests === 1 && withTest.chain?.kinds?.decisions === (baseline.chain?.kinds?.decisions ?? 0) - 1,
    JSON.stringify(withTest.chain?.kinds ?? withTest));
}
ok("2.5.0 baseline: the person and both change-trail entries tie to their records, the erasure is named, the report ties",
  baseline.chain?.peopleTied === 1 && baseline.chain?.changesTied === 2 && baseline.chain?.reportTied === true
    && baseline.chain?.erasures?.length === 1 && baseline.chain.erasures[0].reason === "privacy request" && baseline.chain.erasures[0].id === SYN_ERASURE,
  JSON.stringify(baseline.chain));
for (const [label, tweak, expect] of [
  // Since 2.5.0 a change record follows the edited decision, so the broken link to it is what is named first.
  ["a record edited after sealing -> the record after it no longer follows it", { editR2: true }, /does not follow the record before it|no longer reproduce its signed root/],
  ["two records swapped -> the links break", { swap: true }, /does not follow the record before it/],
  ["a readable row that differs from its record -> invalid", { rowAction: "allow" }, /readable row differs from its record/],
  ["policy text rewritten after the decisions -> invalid", { policyYaml: SYN_POLICY_YAML.replace("block", "warn") }, /no longer matches its version/],
  // 2.5.0: what used to be signed only with the export is now tied to the chain, so one export alone catches it.
  ["2.5.0: the person on a decision re-attributed -> invalid alone, the person named", { person: "k.wong@workspace.example" }, /readable row differs from its record: its person$/],
  ["2.5.0: a change-trail entry's approver and reason rewritten -> invalid alone", { trailEdit: true },
    /change-trail entry dddddddd-0000-4000-8000-000000000001 \(held_decision\.denied\) in mutations\/policy-trail\.json differs from its sealed record/],
  ["2.5.0: a change-trail entry that no longer names who acted -> invalid alone (the seal names them)", { trailGone: true }, /differs from its sealed record/],
  ["2.7.0: a list change's count rewritten -> invalid alone", { listCount: true },
    /change-trail entry dddddddd-0000-4000-8000-000000000002 \(policy\.activated\) in mutations\/policy-trail\.json differs from its sealed record/],
  ["2.7.0: a change trail that names a list's entries -> invalid", { listNames: true }, /names a list's entries, which the change trail never carries/],
  ["2.7.0: an entry not sealed yet that names a list's entries -> invalid", { laterNames: true }, /names a list's entries, which the change trail never carries/],
  ["2.7.0: a change with a field the trail never has -> invalid", { listExtra: true }, /a field the change trail never has \(names\)/],
  ["2.11.0: a tool added to a sealed mandate approval -> invalid alone", { mandate: true, mandateToolAdded: true },
    /change-trail entry dddddddd-0000-4000-8000-000000000001 \(mandate\.granted\) in mutations\/policy-trail\.json differs from its sealed record/],
  ["2.11.0: a whole server's waiting mark removed after sealing -> invalid alone", { mandate: true, mandateTickFlipped: true }, /differs from its sealed record/],
  ["2.11.0: a mandate approval with its facts removed -> invalid alone (v2 is not v3)", { mandate: true, mandateStripped: true }, /differs from its sealed record/],
  ["2.11.0: a mandate entry with a fact no seal covers -> invalid", { mandate: true, mandateExtra: true },
    /a mandate entry carries a field the change trail never has \(boundary\)/],
  ["2.11.0: a mandate entry's tool with a field no seal covers -> invalid", { mandate: true, mandateToolExtra: true },
    /a mandate entry's tool carries a field the change trail never has \(toolClass\)/],
  ["2.11.0: a mandate entry not sealed yet with a fact no seal covers -> invalid", { mandate: true, mandateLater: true },
    /a mandate entry carries a field the change trail never has \(scopeToolClasses\)/],
  ["2.12.0: an assessment's hash rewritten after sealing -> invalid alone", { assessment: true, assessmentHash: true },
    /change-trail entry dddddddd-0000-4000-8000-000000000001 \(assessment\.concluded\) in mutations\/policy-trail\.json differs from its sealed record/],
  ["2.12.0: an assessment entry with its facts removed -> invalid alone (v2 is not v4)", { assessment: true, assessmentStripped: true }, /differs from its sealed record/],
  ["2.12.0: an assessment entry with a fact no seal covers -> invalid", { assessment: true, assessmentExtra: true },
    /an assessment entry carries a field the change trail never has \(findings\)/],
  ["2.12.0: an assessment entry carrying a mandate's facts too -> invalid", { assessment: true, assessmentWithMandate: true }, /cannot be checked: it is malformed/],
  ["2.12.0: an assessment entry not sealed yet with a fact no seal covers -> invalid", { assessment: true, assessmentLater: true },
    /an assessment entry carries a field the change trail never has \(met\)/],
  ["2.13.0: a review's hash rewritten after sealing -> invalid alone", { record: true, recordHash: true },
    /change-trail entry dddddddd-0000-4000-8000-000000000001 \(finding\.reviewed\) in mutations\/policy-trail\.json differs from its sealed record/],
  ["2.13.0: a review entry with its facts removed -> invalid alone (v2 is not v5)", { record: true, recordStripped: true }, /differs from its sealed record/],
  ["2.13.0: a review entry with a fact no seal covers -> invalid", { record: true, recordExtra: true },
    /a record entry carries a field the change trail never has \(result\)/],
  ["2.13.0: a review entry carrying an assessment's facts too -> invalid", { record: true, recordWithAssessment: true }, /cannot be checked: it is malformed/],
  ["2.13.0: a review entry not sealed yet with a fact no seal covers -> invalid", { record: true, recordLater: true },
    /a record entry carries a field the change trail never has \(note\)/],
  ["2.8.0: a report that says nothing of other AI tools -> invalid", { noImported: true }, /does not say what other AI tools reported/],
  ["2.8.0: a report and an imports block that both count another tool's records wrong -> invalid",
    { summary: true, imported: [{ ...imported0, rows: 4 }], packedImports: [{ ...imported0, rows: 4 }] }, /activity it says other AI tools reported does not match/],
  ["2.8.0: a report that leaves out a feed the pack carries -> invalid", { imported: [] }, /activity it says other AI tools reported does not match/],
  ["2.8.0: a report that moves the vendor's earliest time -> invalid", { imported: [{ ...imported0, sourceFrom: "2026-01-09T09:00:00+00:00" }] },
    /activity it says other AI tools reported does not match/],
  ["2.15.0: a report that counts one more row Mandate could not read in full -> invalid", { imported: [{ ...imported0, rowsNotReadInFull: 2 }] },
    /activity it says other AI tools reported does not match/],
  ["2.15.0: a report and an imports block that agree on a count of rows not read that the rows do not give -> invalid",
    { summary: true, imported: [{ ...imported0, rowsNotReadInFull: 0 }], packedImports: [{ ...imported0, rowsNotReadInFull: 0 }] },
    /activity it says other AI tools reported does not match/],
  ["2.15.0: a report that leaves the count of rows not read out of a version 2 file -> invalid",
    { imported: [(({ rowsNotReadInFull, ...rest }) => rest)(imported0)] }, /activity it says other AI tools reported does not match/],
  ["2.15.0: a report that puts a count of rows not read beside a version 1 file -> invalid",
    { importsV1: true, imported: [{ ...imported0v1, rowsNotReadInFull: 0 }] }, /activity it says other AI tools reported does not match/],
  ["2.15.0: a report and an imports block that disagree on the count of rows not read -> invalid",
    { summary: true, packedImports: [{ ...imported0, rowsNotReadInFull: 0 }] }, /activity it says other AI tools reported does not match/],
  ["2.15.0: a version 2 file that lists one of Mandate's notes among the rules that fired -> invalid",
    { importRows: [{ id: "ffffffff-0000-4000-8000-000000000001", sourceTime: "2026-01-10T09:00:00Z", payloadSha256: "ab".repeat(32), ruleHits: ["pii-sin"], notes: [] },
      { id: "ffffffff-0000-4000-8000-000000000002", sourceTime: "2026-01-14T17:30:00Z", payloadSha256: "cd".repeat(32), ruleHits: ["policy.attachment_present"],
        notes: ["policy.body_unscannable"] },
      { id: "ffffffff-0000-4000-8000-000000000003", sourceTime: "2026-01-12T12:00:00Z", payloadSha256: "ef".repeat(32), ruleHits: [], notes: [] }],
    imported: [{ ...imported0, rowsWithRuleHits: 2 }] },
    /imports\/imported_m365_copilot\.json: a row lists one of Mandate's own notes among the rules that fired on it/],
  ["2.15.0: a version 2 file that lists a rule among Mandate's notes -> invalid",
    { importRows: [{ id: "ffffffff-0000-4000-8000-000000000001", sourceTime: "2026-01-10T09:00:00Z", payloadSha256: "ab".repeat(32), ruleHits: [], notes: ["pii-sin"] },
      { id: "ffffffff-0000-4000-8000-000000000002", sourceTime: "2026-01-14T17:30:00Z", payloadSha256: "cd".repeat(32), ruleHits: [],
        notes: ["policy.body_unscannable"] },
      { id: "ffffffff-0000-4000-8000-000000000003", sourceTime: "2026-01-12T12:00:00Z", payloadSha256: "ef".repeat(32), ruleHits: [], notes: [] }],
    imported: [{ ...imported0, rowsWithRuleHits: 0 }] },
    /imports\/imported_m365_copilot\.json: a row lists a rule among Mandate's own notes on reading it/],
  ["2.15.0: a version 2 file whose rows carry no notes -> invalid",
    { importRows: [{ id: "ffffffff-0000-4000-8000-000000000001", sourceTime: "2026-01-10T09:00:00Z", payloadSha256: "ab".repeat(32), ruleHits: ["pii-sin"] },
      { id: "ffffffff-0000-4000-8000-000000000002", sourceTime: "2026-01-14T17:30:00Z", payloadSha256: "cd".repeat(32), ruleHits: [] },
      { id: "ffffffff-0000-4000-8000-000000000003", sourceTime: "2026-01-12T12:00:00Z", payloadSha256: "ef".repeat(32), ruleHits: [] }],
    imported: [{ ...imported0, rowsNotReadInFull: 0 }] }, /activity it says other AI tools reported does not match/],
  ["2.15.0: a file cut short whose count of rows not read is below what its rows give -> invalid",
    { importsTruncated: true, imported: [{ ...imported0, rows: 5, rowsNotReadInFull: 0 }] }, /activity it says other AI tools reported does not match/],
  ["2.15.0: a file cut short whose count of rows a rule fired on is below what its rows give -> invalid",
    { importsTruncated: true, imported: [{ ...imported0, rows: 5, rowsWithRuleHits: 0 }] }, /activity it says other AI tools reported does not match/],
  ["2.5.0: a record removed with no entry recording its erasure -> invalid", { erasureNamed: false }, /no entry records its erasure/],
  ["2.5.0: a removal naming an entry the export does not carry -> invalid", { erasuresDropped: true }, /which chain\/erasures\.json does not carry/],
  ["2.5.0: a removal naming an entry that records no erasure -> invalid", { erasureAction: "policy.update" }, /which records no erasure/],
  ["2.5.0: a printed report naming another summary -> invalid", { report: "other" }, /was not drawn from report\/summary\.json/],
  ["2.5.0: a printed report naming no summary -> invalid", { report: "unnamed" }, /does not name the summary it was drawn from/],
  ["2.5.0: a records file that says partial under a manifest that says complete -> invalid", { chainTruncated: true }, /signed manifest says the export is complete/],
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
  // 2.17.0: the assessment files' sealed documents, each recomputed against the hash its change-trail entry carries.
  const pack = async (documents, tweak = {}) => verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ ...tweak, documents })).entries), inflateRaw);
  const lines = (r) => (checker.sealedDocumentsLines?.(r.chain?.sealedDocuments) ?? []).map((l) => `${l.tag} ${l.label}`);
  const counts = (r) => JSON.stringify(Object.fromEntries(["assessments", "reviews", "artifacts", "measureValues", "impactAssessments"].map((k) => [k, r.chain?.sealedDocuments?.[k]
    ? [r.chain.sealedDocuments[k].matched, r.chain.sealedDocuments[k].notChecked] : null])));
  const none = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack()).entries), inflateRaw);
  ok("2.17.0: a pack made before the assessment files -> valid, and says nothing of them",
    none.overall === "valid" && counts(none) === JSON.stringify({ assessments: null, reviews: null, artifacts: null, measureValues: null, impactAssessments: null }) && lines(none).length === 0,
    `${counts(none)} ${lines(none).join(" | ")}`);
  const NOT_SEALED = "not checked (not sealed in the records file yet or outside it)";
  for (const [sealed, name, expected, line] of [
    ["assessment", "an assessment", { assessments: [1, 0], reviews: [0, 1], artifacts: [0, 1], measureValues: [0, 1], impactAssessments: [0, 1] },
      `[ ok ] 1 assessment matches its sealed record; 1 review of a finding, 1 artifact version, 1 measure value and 1 impact assessment version ${NOT_SEALED}`],
    ["review", "a review", { assessments: [0, 1], reviews: [1, 0], artifacts: [0, 1], measureValues: [0, 1], impactAssessments: [0, 1] },
      `[ ok ] 1 review of a finding matches its sealed record; 1 assessment, 1 artifact version, 1 measure value and 1 impact assessment version ${NOT_SEALED}`],
    ["artifact", "an artifact version", { assessments: [0, 1], reviews: [0, 1], artifacts: [1, 0], measureValues: [0, 1], impactAssessments: [0, 1] },
      `[ ok ] 1 artifact version matches its sealed record; 1 assessment, 1 review of a finding, 1 measure value and 1 impact assessment version ${NOT_SEALED}`],
    ["measure", "a measure value", { assessments: [0, 1], reviews: [0, 1], artifacts: [0, 1], measureValues: [1, 0], impactAssessments: [0, 1] },
      `[ ok ] 1 measure value matches its sealed record; 1 assessment, 1 review of a finding, 1 artifact version and 1 impact assessment version ${NOT_SEALED}`],
    ["impact", "an impact assessment version", { assessments: [0, 1], reviews: [0, 1], artifacts: [0, 1], measureValues: [0, 1], impactAssessments: [1, 0] },
      `[ ok ] 1 impact assessment version matches its sealed record; 1 assessment, 1 review of a finding, 1 artifact version and 1 measure value ${NOT_SEALED}`],
  ]) {
    const r = await pack({ sealed });
    ok(`2.17.0: ${name} sealed into the records -> valid, `
      + "it matches its seal and the others, whose entries are not sealed yet, are counted apart",
    r.overall === "valid" && counts(r) === JSON.stringify(expected) && lines(r).join(" | ") === line, `${r.chain?.reason ?? ""} ${counts(r)} ${lines(r).join(" | ")}`);
  }
  {
    const r = await pack({ after: (f) => { f.findings.assessments = []; f.findings.truncated = true; } });
    ok("2.17.0: a findings file cut at its size limit, its assessment left out -> valid, and the line says the file holds the earliest of its period",
      r.overall === "valid" && lines(r).join(" | ") === `[ -- ] 1 review of a finding, 1 artifact version, 1 measure value and 1 impact assessment version ${NOT_SEALED}; `
        + "assessments/findings.json holds the earliest of its period only",
      `${r.chain?.reason ?? ""} ${lines(r).join(" | ")}`);
  }
  {
    const r = await pack({ after: (f) => { f.findings.schemaVersion = 2; } });
    ok("2.17.0: a findings file of a later version -> valid, not compared, and the line says why",
      r.overall === "valid" && lines(r)[0] === "[ -- ] the assessments were not compared: assessments/findings.json is version 2; this checker reads version 1",
      `${r.chain?.reason ?? ""} ${lines(r).join(" | ")}`);
  }
  {
    const r = await pack({ entries: false, after: (f) => {
      f.findings.assessments = [];
      f.reviews.reviews = [];
      f.artifacts.artifacts = [];
      f.measureValues.values = [];
      f.impactAssessments.impactAssessments = [];
    } });
    ok("2.17.0: a period with no assessment, review, artifact, measure value or impact assessment -> valid, and the line says so",
      r.overall === "valid" && lines(r).join(" | ")
        === "[ ok ] no assessments, reviews of findings, artifact versions, measure values or impact assessment versions were recorded in this period",
      `${r.chain?.reason ?? ""} ${lines(r).join(" | ")}`);
  }
  const edit = (text, from, to) => {
    if (!text.includes(from)) throw new Error(`the suite's edit does not apply: ${from}`);
    return text.replace(from, to);
  };
  const hashOf = (text) => bytesToHex(sha(new TextEncoder().encode(text)));
  const A = "a5a5a5a5-0000-4000-8000-000000000001";
  const DELETION = "dddddddd-0000-4000-8000-0000000000a9";
  // The system's deletion, an entry made after the last seal like the others.
  const deleted = (e) => ({ source: "mutation", id: DELETION, occurredAt: "2026-01-15T11:40:00+00:00", actorType: "tenant_admin",
    actorId: e.assessment.actorId, actorDisplay: e.assessment.actorDisplay, actorSalt: e.assessment.actorSalt, action: "ai_system.deleted" });
  const goneWithSystem = (f, e) => {
    f.findings.assessments = [];
    f.findings.removed = [{ id: A, auditEntryId: e.assessment.id, aiSystemId: SYN_DOC.system, deletedBy: DELETION, deletedAt: "2026-01-15T11:40:00+00:00" }];
    e.deletion = deleted(e);
  };
  {
    const r = await pack({ after: goneWithSystem });
    const later = await pack({ after: (f, e) => { goneWithSystem(f, e); delete e.deletion; f.findings.removed[0].deletedAt = "2026-01-16T09:00:00+00:00"; } });
    ok("2.17.0: an assessment deleted with its AI system after the period, its deletion outside the change trail -> valid, counted apart",
      later.overall === "valid" && later.chain?.sealedDocuments?.assessments?.removed === 1, later.chain?.reason);
    ok("2.17.0: an assessment deleted with its AI system, the file naming it and the deletion -> valid, counted apart and said so",
      r.overall === "valid" && r.chain?.sealedDocuments?.assessments?.removed === 1 && lines(r)[0]?.includes("; 1 assessment deleted with an AI system"),
      `${r.chain?.reason ?? ""} ${lines(r).join(" | ")}`);
  }
  {
    const r = await pack({ after: (f, e) => { e.report = { ...deleted(e), id: "dddddddd-0000-4000-8000-0000000000b1", action: "report.export",
      record: { kind: "period_report", id: "b1b1b1b1-0000-4000-8000-000000000001", sha256: "ab".repeat(32) } }; } });
    ok("2.17.0: a sealed period report, whose document is an earlier pack's, neither fails nor counts",
      r.overall === "valid" && counts(r) === JSON.stringify({ assessments: [1, 0], reviews: [0, 1], artifacts: [0, 1], measureValues: [0, 1], impactAssessments: [0, 1] }),
      `${r.chain?.reason ?? ""} ${counts(r)}`);
  }
  {
    const r = await pack({ entries: false, after: (f) => {
      f.findings.assessments = [];
      f.findings.truncated = true;
      f.reviews.reviews = [];
      f.artifacts.artifacts = [];
      f.measureValues.values = [];
      f.impactAssessments.impactAssessments = [];
    } });
    ok("2.17.0: a findings file cut to no rows -> valid, the line says it was cut and never that nothing was recorded",
      r.overall === "valid" && lines(r).join(" | ") === "[ -- ] assessments/findings.json holds the earliest of its period only", lines(r).join(" | "));
  }
  for (const [label, documents, expect] of [
    ["a finding's result rewritten in the assessment's document -> invalid",
      { after: (f) => { f.findings.assessments[0].document = edit(f.findings.assessments[0].document, '"result":"not_met"', '"result":"met"'); } },
      new RegExp(`^assessments/findings\\.json: assessment ${A}: its document does not match its SHA-256$`)],
    ["the assessment's document and the hash beside it rewritten together -> invalid, it differs from its sealed record",
      { after: (f) => { const row = f.findings.assessments[0]; row.document = edit(row.document, '"result":"not_met"', '"result":"met"'); row.contentSha256 = hashOf(row.document); } },
      new RegExp(`^assessments/findings\\.json: assessment ${A} differs from its sealed record$`)],
    ["the same rewrite of an assessment whose entry is not sealed yet -> invalid all the same",
      { sealed: "review", after: (f) => { const row = f.findings.assessments[0]; row.document = edit(row.document, '"result":"not_met"', '"result":"met"'); row.contentSha256 = hashOf(row.document); } },
      new RegExp(`^assessments/findings\\.json: assessment ${A} differs from its sealed record$`)],
    ["a finding's readable result changed beside an untouched document -> invalid, the finding named",
      { after: (f) => { f.findings.assessments[0].findings[1].result = "met"; } },
      new RegExp(`^assessments/findings\\.json: assessment ${A}: the readable row differs from its sealed document: its finding 6\\.1\\.2$`)],
    ["the readable counts changed -> invalid", { after: (f) => { Object.assign(f.findings.assessments[0], { met: 2, notMet: 0 }); } },
      /the readable row differs from its sealed document: its counts$/],
    ["the readable coverage changed -> invalid", { after: (f) => { f.findings.assessments[0].coverage = 0.9; } },
      /the readable row differs from its sealed document: its coverage$/],
    ["the readable confidence changed -> invalid", { after: (f) => { f.findings.assessments[0].confidence = 82; } },
      /the readable row differs from its sealed document: its confidence$/],
    ["the readable period changed -> invalid", { after: (f) => { f.findings.assessments[0].windowFrom = "2026-01-01T11:15:00.123456+00:00"; } },
      /the readable row differs from its sealed document: its period$/],
    ["an assessment whose entry names another assessment -> invalid",
      { after: (f) => { f.findings.assessments[0].id = "a5a5a5a5-0000-4000-8000-0000000000ff"; } },
      /assessment a5a5a5a5-0000-4000-8000-0000000000ff: its change-trail entry dddddddd-0000-4000-8000-0000000000a1 records something else$/],
    ["an assessment whose document names another assessment, its entry not in the pack -> invalid",
      { entries: false, after: (f) => { f.findings.assessments[0].id = "a5a5a5a5-0000-4000-8000-0000000000ff"; } },
      /assessment a5a5a5a5-0000-4000-8000-0000000000ff: the readable row differs from its sealed document: its id$/],
    ["an assessment left out of a findings file not cut -> invalid, the assessment and its entry named",
      { after: (f) => { f.findings.assessments = []; } },
      new RegExp(`^assessments/findings\\.json: it leaves out assessment ${A}, which change-trail entry dddddddd-0000-4000-8000-0000000000a1 seals$`)],
    ["the same assessment twice -> invalid", { after: (f) => { f.findings.assessments.push(f.findings.assessments[0]); } }, /assessment a5a5a5a5-.* appears twice$/],
    ["an assessment document of a later version -> invalid", { before: (d) => { d.assessment.version = 2; } },
      /assessment a5a5a5a5-.*: its document is version 2; this checker reads version 1$/],
    ["a review's readable action changed -> invalid", { sealed: "review", after: (f) => { f.reviews.reviews[0].action = "accept"; } },
      /^assessments\/reviews\.json: review e5e5e5e5-.*: the readable row differs from its sealed record: its action$/],
    ["a review's readable reviewer changed -> invalid", { sealed: "review", after: (f) => { f.reviews.reviews[0].reviewerRoles = ["tenant_admin"]; } },
      /the readable row differs from its sealed record: its reviewer$/],
    ["a review's note rewritten in its record -> invalid", { sealed: "review", after: (f) => {
      f.reviews.reviews[0].record = edit(f.reviews.reviews[0].record, "Checked with the system owner.", "Not checked."); } },
      /^assessments\/reviews\.json: review e5e5e5e5-.*: its record does not match its SHA-256$/],
    ["a review that names another document of an assessment the pack carries -> invalid",
      { before: (d) => { d.review.assessmentSha256 = "00".repeat(32); } },
      new RegExp(`^assessments/reviews\\.json: review e5e5e5e5-.* names a different document for assessment ${A} than the one assessments/findings\\.json carries$`)],
    ["a review left out of a reviews file not cut -> invalid", { after: (f) => { f.reviews.reviews = []; } },
      /^assessments\/reviews\.json: it leaves out review e5e5e5e5-0000-4000-8000-000000000001, which change-trail entry dddddddd-0000-4000-8000-0000000000a2 seals$/],
    ["a review whose entry names another review -> invalid", { after: (f, e) => { e.review.record.id = "e5e5e5e5-0000-4000-8000-0000000000ff"; } },
      /^assessments\/reviews\.json: review e5e5e5e5-0000-4000-8000-000000000001: its change-trail entry dddddddd-0000-4000-8000-0000000000a2 records something else$/],
    ["an artifact version's readable title changed -> invalid", { sealed: "artifact", after: (f) => { f.artifacts.artifacts[0].title = "Another report"; } },
      /^assessments\/artifacts\.json: artifact version a7a7a7a7-.*: the readable row differs from its sealed record: its title$/],
    ["an artifact version's readable file hash changed -> invalid", { sealed: "artifact", after: (f) => { f.artifacts.artifacts[0].file.sha256 = "ef".repeat(32); } },
      /the readable row differs from its sealed record: its file$/],
    ["an artifact version's readable links changed -> invalid", { sealed: "artifact", after: (f) => { f.artifacts.artifacts[0].links.pop(); } },
      /the readable row differs from its sealed record: its links$/],
    ["an artifact version's record and hash rewritten together -> invalid", { sealed: "artifact", after: (f) => {
      const row = f.artifacts.artifacts[0]; row.record = edit(row.record, '"withdrawn":false', '"withdrawn":true'); row.recordSha256 = hashOf(row.record); row.withdrawn = true; } },
      /^assessments\/artifacts\.json: artifact version a7a7a7a7-.* differs from its sealed record$/],
    ["an assessment rewritten with its hash and pointed at an entry the pack does not carry -> invalid, its own entry still read",
      { after: (f) => { const row = f.findings.assessments[0]; row.document = edit(row.document, '"aiSystemName":"Benefit triage"', '"aiSystemName":"Benefit review"');
        row.contentSha256 = hashOf(row.document); row.auditEntryId = "dddddddd-0000-4000-8000-0000000000ff";
        // The review names the sealed document too, so it is left out of a file cut short.
        f.reviews.reviews = []; f.reviews.truncated = true; } },
      new RegExp(`^assessments/findings\\.json: assessment ${A} differs from its sealed record$`)],
    ["an assessment pointed at an entry the pack does not carry -> invalid, the entry that seals it named",
      { after: (f) => { f.findings.assessments[0].auditEntryId = "dddddddd-0000-4000-8000-0000000000ff"; } },
      new RegExp(`^assessments/findings\\.json: assessment ${A} names change-trail entry dddddddd-0000-4000-8000-0000000000ff, but entry dddddddd-0000-4000-8000-0000000000a1 seals it$`)],
    ["an assessment said to be deleted by an entry that records no deletion -> invalid",
      { after: (f, e) => { goneWithSystem(f, e); f.findings.removed[0].deletedBy = e.review.id; } },
      /assessment a5a5a5a5-0000-4000-8000-000000000001 is said to be deleted with its AI system by entry dddddddd-0000-4000-8000-0000000000a2, which records no such deletion$/],
    ["an assessment said to be deleted inside the period by an entry the uncut change trail does not carry -> invalid",
      { after: (f, e) => { goneWithSystem(f, e); delete e.deletion; } },
      /assessment a5a5a5a5-0000-4000-8000-000000000001 is said to be deleted with its AI system by entry dddddddd-0000-4000-8000-0000000000a9, which the change trail of its period does not carry$/],
    ["an assessment both carried and said to be deleted -> invalid",
      { after: (f, e) => { const row = f.findings.assessments[0]; goneWithSystem(f, e); f.findings.assessments = [row]; } },
      /assessment a5a5a5a5-0000-4000-8000-000000000001 is both carried and said to be deleted, or said to be deleted twice$/],
    ["an assessment said to be deleted whose entry seals another document -> invalid",
      { after: (f, e) => { goneWithSystem(f, e); f.findings.removed[0].auditEntryId = e.review.id; } },
      /assessment a5a5a5a5-0000-4000-8000-000000000001: its change-trail entry dddddddd-0000-4000-8000-0000000000a2 records something else$/],
    ["an artifact version whose entry is a review's -> invalid", { after: (f, e) => { e.artifact.record.kind = "finding_review"; } },
      /artifact version a7a7a7a7-.*: its change-trail entry dddddddd-0000-4000-8000-0000000000a3 records something else$/],
    ["a measure value's readable value changed -> invalid", { sealed: "measure", after: (f) => { f.measureValues.values[0].value = 0.97; } },
      /^assessments\/measure-values\.json: measure value 3e3e3e3e-.*: the readable row differs from its sealed record: its value$/],
    ["a measure value's readable observation time changed -> invalid", { sealed: "measure", after: (f) => { f.measureValues.values[0].observedAt = "2026-01-14T10:00:00.123456+00:00"; } },
      /the readable row differs from its sealed record: its period$/],
    ["a measure value's record and hash rewritten together -> invalid", { sealed: "measure", after: (f) => {
      const row = f.measureValues.values[0]; row.record = edit(row.record, '"status":"warning"', '"status":"ok"'); row.recordSha256 = hashOf(row.record); row.status = "ok"; } },
      /^assessments\/measure-values\.json: measure value 3e3e3e3e-.* differs from its sealed record$/],
    ["a measure value left out of a file not cut -> invalid", { after: (f) => { f.measureValues.values = []; } },
      /^assessments\/measure-values\.json: it leaves out measure value 3e3e3e3e-0000-4000-8000-000000000002, which change-trail entry dddddddd-0000-4000-8000-0000000000a4 seals$/],
    ["an impact assessment version's readable level changed -> invalid", { sealed: "impact", after: (f) => { f.impactAssessments.impactAssessments[0].level = 1; } },
      /^assessments\/impact-assessments\.json: impact assessment version 1a1a1a1a-.*: the readable row differs from its sealed record: its level$/],
    ["an impact assessment version's answers rewritten in its record -> invalid", { sealed: "impact", after: (f) => {
      const row = f.impactAssessments.impactAssessments[0]; row.record = edit(row.record, '"item1-2"', '"item1-1"'); } },
      /^assessments\/impact-assessments\.json: impact assessment version 1a1a1a1a-.*: its record does not match its SHA-256$/],
    ["an impact assessment version left out of a file not cut -> invalid", { after: (f) => { f.impactAssessments.impactAssessments = []; } },
      /it leaves out impact assessment version 1a1a1a1a-0000-4000-8000-000000000001, which change-trail entry dddddddd-0000-4000-8000-0000000000a5 seals$/],
  ]) {
    const r = await pack(documents);
    ok(`2.17.0: ${label}`, r.overall === "invalid" && r.manifest.status === "valid" && expect.test(r.chain?.reason ?? ""), r.chain?.reason);
  }
  // 2.19.0: each finding's review decision against its latest sealed review, and the sign-off against the
  // decisions and the change trail. 2.18.0 passed the first three.
  const F = SYN_DOC.findings;
  const STRANGER = "99999999-0000-4000-8000-000000000009";
  for (const [label, documents] of [
    ["an assessment with one finding changed by its sealed review, the review's decision beside it", { sealed: "review" }],
    ["an assessment signed off by the decision that left no finding undecided", { signOff: true }],
    ["the same, its sign-off sealed into the records", { signOff: true, sealed: "signOff" }],
    ["the same, the last accept sealed", { signOff: true, sealed: "accept2" }],
    ["a reviews file cut at its size limit, so the decisions are not compared", { sealed: "review", after: (f) => {
      f.reviews.reviews = []; f.reviews.truncated = true;
      Object.assign(f.findings.assessments[0].findings[1], { reviewedResult: "met", reviewedConfidence: 99 }); } }],
  ]) {
    const r = await pack(documents);
    ok(`2.19.0: ${label} -> valid`, r.overall === "valid", r.chain?.reason);
  }
  for (const [label, documents, expect] of [
    ["the findings row says the reviewer changed 6.1.2 to met, the sealed review says partially met",
      { sealed: "review", after: (f) => { Object.assign(f.findings.assessments[0].findings[1], { reviewState: "changed", reviewedResult: "met",
        reviewedConfidence: 99, reviewedAt: "2026-01-15T11:20:00.123456+00:00", reviewedBy: SYN_DOC.person }); } },
      new RegExp(`^assessments/findings\\.json: assessment ${A}: finding 6\\.1\\.2 differs from its latest sealed review, e5e5e5e5-0000-4000-8000-000000000001$`)],
    ["the assessment shown signed off by an unknown person, its findings not reviewed",
      { sealed: "review", after: (f) => { Object.assign(f.findings.assessments[0], { status: "signed_off", signedOffAt: "2026-01-15T11:30:00+00:00", signedOffBy: STRANGER }); } },
      new RegExp(`^assessments/findings\\.json: assessment ${A} is shown signed off, and the change trail of its period carries no sign-off of it$`)],
    ["a finding never reviewed shown rejected",
      { sealed: "review", after: (f) => { Object.assign(f.findings.assessments[0].findings[0], { reviewState: "rejected", reviewedAt: "2026-01-15T11:21:00+00:00",
        reviewedBy: STRANGER }); } },
      new RegExp(`^assessments/findings\\.json: assessment ${A}: finding 6\\.1\\.1 shows a review decision, and no sealed review of it gives one$`)],
    ["the changed finding shown as accepted, its decision's columns left as they were",
      { sealed: "review", after: (f) => { f.findings.assessments[0].findings[1].reviewState = "accepted"; } },
      /: finding 6\.1\.2 differs from its latest sealed review, e5e5e5e5-0000-4000-8000-000000000001$/],
    ["the changed finding shown as decided by another person", { sealed: "review", after: (f) => { f.findings.assessments[0].findings[1].reviewedBy = STRANGER; } },
      /: finding 6\.1\.2 differs from its latest sealed review/],
    ["the changed finding shown as undecided", { sealed: "review", after: (f) => {
      for (const k of ["reviewState", "reviewedResult", "reviewedConfidence", "reviewedAt", "reviewedBy"]) delete f.findings.assessments[0].findings[1][k]; } },
      /: finding 6\.1\.2 differs from its latest sealed review/],
    ["a sealed review of a finding the assessment does not hold", { sealed: "review", after: (f) => {
      const row = f.findings.assessments[0].findings[1];
      row.id = F[2].replace(/3$/, "f");
      for (const k of ["reviewState", "reviewedResult", "reviewedConfidence", "reviewedAt", "reviewedBy"]) delete row[k]; } },
      new RegExp(`: assessment ${A}: a sealed review decides finding ${F[1]}, which the assessment does not hold$`)],
    ["a signed-off assessment shown signed off by another person", { signOff: true, after: (f) => { f.findings.assessments[0].signedOffBy = STRANGER; } },
      new RegExp(`: assessment ${A}: its sign-off is not the decision that left no finding undecided$`)],
    ["a signed-off assessment shown signed off at another time, its entry left out", { signOff: true, after: (f, e) => {
      delete e.signOff; f.findings.assessments[0].signedOffAt = "2026-01-15T11:40:00+00:00"; } },
      /is shown signed off, and the change trail of its period carries no sign-off of it$/],
    ["a signed-off assessment shown as not signed off", { signOff: true, after: (f) => {
      Object.assign(f.findings.assessments[0], { status: "concluded", signedOffAt: null, signedOffBy: null }); } },
      new RegExp(`: assessment ${A} does not show the sign-off change-trail entry dddddddd-0000-4000-8000-0000000000a8 records$`)],
    ["every finding decided and no sign-off anywhere", { signOff: true, after: (f, e) => {
      delete e.signOff; Object.assign(f.findings.assessments[0], { status: "concluded", signedOffAt: null, signedOffBy: null }); } },
      new RegExp(`: assessment ${A}: a sealed review decides every finding, and the assessment is not shown signed off$`)],
    ["a sign-off that names another document", { signOff: true, after: (f, e) => { e.signOff.record.sha256 = "00".repeat(32); } },
      new RegExp(`: assessment ${A}: its sign-off, change-trail entry dddddddd-0000-4000-8000-0000000000a8, names another document$`)],
    ["two sign-offs of one assessment", { signOff: true, after: (f, e) => { e.again = { ...e.signOff, id: "dddddddd-0000-4000-8000-0000000000a9" }; } },
      new RegExp(`: assessment ${A} is signed off by two change-trail entries, dddddddd-0000-4000-8000-0000000000a8 and dddddddd-0000-4000-8000-0000000000a9$`)],
    ["signed off with a finding no sealed review decides", { signOff: true, after: (f, e) => {
      f.reviews.reviews.pop(); delete e.accept2;
      for (const k of ["reviewState", "reviewedResult", "reviewedConfidence", "reviewedAt", "reviewedBy"]) delete f.findings.assessments[0].findings[2][k]; } },
      new RegExp(`: assessment ${A} is shown signed off, and no sealed review decides 1 of its findings$`)],
    ["a status no assessment has", { sealed: "review", after: (f) => { f.findings.assessments[0].status = "approved"; } },
      new RegExp(`: assessment ${A}: its status is approved, which no assessment has$`)],
    ["a sign-off time on an assessment not signed off", { sealed: "review", after: (f) => { f.findings.assessments[0].signedOffAt = "2026-01-15T11:30:00+00:00"; } },
      new RegExp(`: assessment ${A}: its status and its sign-off time and person do not agree$`)],
  ]) {
    const r = await pack(documents);
    ok(`2.19.0: ${label} -> invalid`, r.overall === "invalid" && r.manifest.status === "valid" && expect.test(r.chain?.reason ?? ""), r.chain?.reason);
  }
  // 2.20.0: a remediation linked to a measure value that went past its limit names that value (link target "breach"), and
  // the readable row names it as measureValueId. 2.19.0 read such a row's link as naming nothing and failed it.
  const breachLink = { before: (d) => { d.artifact.kind = "remediation"; d.artifact.links.push({ target: "breach", id: SYN_DOC.value }); } };
  const breachRow = (f) => { const row = f.artifacts.artifacts[0]; row.kind = "remediation"; row.links.push({ target: "breach", measureValueId: SYN_DOC.value }); };
  {
    const r = await pack({ ...breachLink, sealed: "artifact", after: breachRow });
    ok("2.20.0: a remediation linked to a measure value that went past its limit, the readable row naming that value -> valid", r.overall === "valid", r.chain?.reason);
  }
  for (const [label, after] of [
    ["the readable row names another measure value", (f) => { breachRow(f); f.artifacts.artifacts[0].links.at(-1).measureValueId = "3e3e3e3e-0000-4000-8000-0000000000ff"; }],
    ["the readable row leaves the linked measure value out", (f) => { breachRow(f); delete f.artifacts.artifacts[0].links.at(-1).measureValueId; }],
  ]) {
    const r = await pack({ ...breachLink, sealed: "artifact", after });
    ok(`2.20.0: ${label} -> invalid`, r.overall === "invalid" && r.manifest.status === "valid"
      && /the readable row differs from its sealed record: its links$/.test(r.chain?.reason ?? ""), r.chain?.reason);
  }
}
{
  const later = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" })).entries), inflateRaw);
  const gapped = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T13:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" })).entries), inflateRaw);
  ok("two consecutive packs of one export -> the sequence joins", checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: later }]).status === "valid");
  ok("a gap between two packs -> the sequence is invalid", /gap/.test(checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: gapped }]).reason ?? ""));
}
{
  // 2.5.0: whoever holds the signing key can drop the last record of a period and sign
  // again, and that export passes alone. An earlier export of the same period still holds the record, and a genuine
  // export never leaves one out (an erased record keeps its place by its hash), so the two checked together fail and
  // name it, in either order.
  const pack = async (tweak) => verifyEvidencePackBytes(writeZip((await buildSyntheticPack(tweak)).entries), inflateRaw);
  // 2.8.0: a report whose other tools' activity is the pack's own, with the imports block beside it, passes and says so.
  const agreed = await pack({ summary: true });
  ok("2.8.0: a report whose other AI tools' activity is the pack's imports -> valid, and compared",
    agreed.overall === "valid" && agreed.chain?.importsCompared === true, JSON.stringify(agreed.chain));
  const versionOne = await pack({ summary: true, importsV1: true });
  ok("2.15.0: a pack made before 2.15.0, its notes counted among the rule hits as it was made -> valid, and compared",
    versionOne.overall === "valid" && versionOne.chain?.importsCompared === true, JSON.stringify(versionOne.chain));
  const cutShort = await pack({ importsTruncated: true, imported: [{ ...imported0, rows: 5 }] });
  ok("2.15.0: a file cut short whose counts are no lower than its rows give and no higher than all rows -> valid, and compared",
    cutShort.overall === "valid" && cutShort.chain?.importsCompared === true, JSON.stringify(cutShort.chain));
  const nextVersion = await pack({ importVersion: 3 });
  ok("2.15.0: an imports file of a version this checker does not read -> valid, not compared, and said why",
    nextVersion.overall === "valid" && nextVersion.chain?.importsCompared === false
      && nextVersion.chain?.importsNotCompared === "imports/imported_m365_copilot.json is version 3; this checker reads versions 1 and 2",
    JSON.stringify(nextVersion.chain));
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
  // 2.5.0: which export was made first no longer decides the direction. An export made before a record existed is not
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
    trailDropPair.status === "invalid" && trailDropPair.reason.includes("change-trail entry dddddddd-0000-4000-8000-000000000002 (policy.activated) is in a but missing from b"),
    trailDropPair.reason);
  const changeErased = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", eraseC2: true });
  const changeErasedPair = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: changeErased }]);
  ok("2.9.0: a change-trail entry that left with its change record under the retention setting -> the sequence joins, the erasure named",
    changeErased.overall === "valid" && changeErasedPair.status === "valid"
      && changeErasedPair.notes.some((n) => n.includes("bbbbbbbb-0000-4000-8000-000000000002 (change,")),
    JSON.stringify(changeErasedPair));
  // An entry still queued when the first export was made, gone with its change record by the second.
  const queuedThenErased = checkPackSequence([{ name: "a", result: await pack({ untied: true }) }, { name: "b", result: changeErased }]);
  ok("2.9.0: an entry not yet sealed in the earlier export, absent from a later one that erased change records -> joins, and named",
    queuedThenErased.status === "valid" && queuedThenErased.notes.some((n) =>
      n === "change-trail entry dddddddd-0000-4000-8000-000000000003 (policy.update) of a was not yet sealed when a was made and is not in b: not compared"),
    JSON.stringify(queuedThenErased));
  // ...but not when the later export still carries that entry's change record: its entry was left out.
  const keepsRecord = { ...changeErased, chain: Object.defineProperty({ ...changeErased.chain }, "joins", {
    value: { ...changeErased.chain.joins, changeLinks: new Map([...changeErased.chain.joins.changeLinks,
      ["dddddddd-0000-4000-8000-000000000003", "bbbbbbbb-0000-4000-8000-000000000001"]]) } }) };
  const queuedThenDropped = checkPackSequence([{ name: "a", result: await pack({ untied: true }) }, { name: "b", result: keepsRecord }]);
  ok("2.9.0: ...and when the later export still carries its change record, the entry left out -> invalid, named",
    queuedThenDropped.status === "invalid" && queuedThenDropped.kind === "missing"
      && queuedThenDropped.reason.includes("change-trail entry dddddddd-0000-4000-8000-000000000003 (policy.update) is in a but missing from b"),
    queuedThenDropped.reason);
  // 2.5.0: a sealed entry keeps who acted, so an account removed later no longer changes the export; an export that
  // drops the name fails its own check (the 2.5.0 case above).
  const counted = await pack({ summary: "match" });
  ok("summary counts with an erased record in the export -> still compared, and match",
    counted.overall === "valid" && counted.chain.removed === 1 && counted.chain.summaryCompared === true, JSON.stringify(counted.chain));
  const zeroed = await pack({ summary: "zeroed" });
  ok("summary that hides the refusals, with an erased record in the export -> invalid",
    zeroed.overall === "invalid" && /summary\/decision-mix\.json: its counts do not match/.test(zeroed.chain?.reason ?? ""), zeroed.chain?.reason);
  const registerCut = await pack({ summary: "zeroed", manifestTruncated: true });
  ok("summary counts when the signed manifest says the register is partial -> not compared, and said",
    registerCut.overall === "valid" && registerCut.chain.summaryNotCompared === "the register is partial", JSON.stringify(registerCut.chain));

  // 2.5.0: every register field both exports show is compared, the person included; a failed
  // comparison carries a kind the page can word; each readable decision ties to every field its record seals.
  ok("a record left out has its own kind, and is named as a decision",
    missing.kind === "missing" && missing.subject === "decision" && missing.id === lastId, JSON.stringify(missing));
  const reattributed = await pack({ generatedAt: "2026-01-15T13:00:00.0000000+00:00", person: "k.wong@workspace.example" });
  ok("2.5.0: the person on a decision changed in the register only -> fails alone (the person is sealed)",
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

  // Since 2.5.0 the product sets the signed flag whenever the records file is partial, so a
  // records file that says partial under a manifest that says complete fails (the 2.5.0 case above).
  const bothPartial = await pack({ chainTruncated: true, manifestTruncated: true });
  ok("records file and signed manifest both say partial -> valid, and reported partial",
    bothPartial.overall === "valid" && bothPartial.truncated === true && bothPartial.chain?.truncated === true, JSON.stringify(bothPartial.chain));
  const registerOnly = await pack({ manifestTruncated: true });
  ok("signed manifest says the register is partial, records file whole -> valid (the register cap can cut the register alone)",
    registerOnly.overall === "valid", JSON.stringify(registerOnly.chain));

  // A record or a checkpoint that names another Mandate ID.
  const foreignRecord = await pack({ otherWorkspaceRecord: true });
  ok("a record naming another Mandate ID -> invalid, and named",
    foreignRecord.overall === "invalid" && foreignRecord.manifest.status === "valid"
      && /record aaaaaaaa-0000-4000-8000-000000000004 names Mandate ID 99999999-2222-4222-8222-222222222222, not this export's Mandate ID /.test(foreignRecord.chain?.reason ?? ""),
    foreignRecord.chain?.reason);
  const foreignCheckpoint = await pack({ otherWorkspaceCheckpoint: true });
  ok("a checkpoint naming another Mandate ID -> invalid, though its signature holds",
    foreignCheckpoint.overall === "invalid" && foreignCheckpoint.manifest.status === "valid"
      && /names Mandate ID 99999999-2222-4222-8222-222222222222, not this export's Mandate ID /.test(foreignCheckpoint.checkpoints[0]?.result.reason ?? ""),
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
    const following = await save("c.zip", { windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00",
      generatedAt: "2026-01-16T00:30:00.0000000+00:00" });
    const cli = (...args) => {
      const r = spawnSync(process.execPath, [join(repoRoot, "mandate-verify.mjs"), ...args], { encoding: "utf8" });
      return { code: r.status, out: `${r.stdout}${r.stderr}`, std: r.stdout };
    };
    const fp = epVector.publicKeyFingerprint;
    const pairs = fp.match(/../g);
    const unchecked = cli(one);
    ok("script, no fingerprint -> exit 4, and no result line starts with RESULT: VALID",
      unchecked.code === 4 && /^RESULT: NOT VERIFIED \(signed by a key that was not checked: name the fingerprint from your agreement with --expect-fingerprint\)$/m.test(unchecked.out)
        && !/^RESULT: VALID/m.test(unchecked.out), unchecked.out.slice(-400));
    ok("script labels read as the page's: signed record, Mandate ID, Period, Complete",
      /^Kind\s+: signed record$/m.test(unchecked.out) && /^Mandate ID\s+: [0-9a-f-]{36}$/m.test(unchecked.out) && !/workspace/i.test(unchecked.out) && /^Period\s+: .+ to .+$/m.test(unchecked.out)
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
      /^Records: \[ ok \] 5 records link in order \(3 decisions, 2 change records\)$/m.test(named.out)
        && /1 record erased under a privacy request on .* keeps its place \(entry e1e1e1e1-0000-4000-8000-000000000001\)/.test(named.out), named.out);
    // 2.6.0: exit 3 means a format this script does not read or a runtime without Ed25519, and the usage says both; a key
    // that is not 32 bytes is a broken record (exit 1), not a runtime without Ed25519.
    const help = cli("--help").out;
    ok("2.6.0: script usage names both meanings of exit 3",
      /^ {2}3 not checked: a format this checker does not read \(DIFFERENT FORMAT\), or no Ed25519 in this runtime \(UNSUPPORTED\)$/m.test(help), help);
    // 2.10.0: a run that exits 4 never calls a file unchanged, in its text or its --json, and the usage says exit 4 the same way.
    const uncheckedJson = cli(one, "--json");
    ok("2.10.0: script, no fingerprint -> nothing printed for a record, its --json or two parts that join says unchanged, nor the usage's exit 4",
      uncheckedJson.code === 4 && !/unchanged/i.test(unchecked.out) && !/unchanged/i.test(uncheckedJson.out) && !/unchanged/i.test(joinedUnchecked.out)
        && /^ {2}4 not verified: signed by a key that was not checked \(name the fingerprint from your agreement with --expect-fingerprint\),$/m.test(help),
      [unchecked.out, joinedUnchecked.out, help].join("\n").split("\n").filter((l) => /unchanged|^ {2}4 /i.test(l)).join(" | "));
    const otherFormat = cli(await save("f.zip", { manifestVersion: 2 }), "--expect-fingerprint", fp);
    ok("script, a format 2 record -> exit 3 and RESULT: DIFFERENT FORMAT",
      otherFormat.code === 3 && /^RESULT: DIFFERENT FORMAT \(this record is format 2/m.test(otherFormat.out), otherFormat.out.slice(-300));
    const shortKeyRun = cli(await save("k.zip", { manifestKey: SHORT_KEY }));
    ok("2.6.0: script, a manifest key of 31 bytes -> exit 1 and RESULT: INVALID, not a runtime without Ed25519",
      shortKeyRun.code === 1 && /^RESULT: INVALID$/m.test(shortKeyRun.out) && /public key must be 32 bytes, got 31/.test(shortKeyRun.out)
        && !/lacks WebCrypto/.test(shortKeyRun.out), shortKeyRun.out.slice(-500));
    const accessFormat = join(dir, "d4.zip");
    writeFileSync(accessFormat, writeZip((await buildSyntheticDsrPack({ manifestVersion: 4 })).entries));
    const accessFormatRun = cli(accessFormat, "--expect-fingerprint", fp);
    ok("2.6.0: script, an access record of format 4 -> exit 3 and RESULT: DIFFERENT FORMAT",
      accessFormatRun.code === 3 && /^RESULT: DIFFERENT FORMAT \(this access record is format 4/m.test(accessFormatRun.out), accessFormatRun.out.slice(-300));
    // 2.10.0: an export made before its period ended is valid and says it is in progress, alone and as a sequence's last part.
    const open = await save("p.zip", { windowTo: "2026-01-16T00:00:00+00:00" });
    const openRun = cli(open, "--expect-fingerprint", fp);
    ok("2.10.0: script, an export made before its period ended -> exit 0, RESULT: VALID, IN PROGRESS, Complete: no, in progress",
      openRun.code === 0
        && /^RESULT: VALID, IN PROGRESS \(the period had not ended when this record was made, so it holds what was recorded up to .+\)$/m.test(openRun.out)
        && /^Complete\s+: no, in progress: the period had not ended when this record was made, so it holds what was recorded up to then$/m.test(openRun.out)
        && /^Unchanged since it was signed, with the key you named: \d+ decisions so far: /m.test(openRun.out), openRun.out.slice(-700));
    const openJson = cli(open, "--json", "--expect-fingerprint", fp);
    ok("2.10.0: script --json, an export in progress -> inProgress true", openJson.code === 0 && JSON.parse(openJson.out).inProgress === true, openJson.out.slice(0, 300));
    const ended = cli(one, "--expect-fingerprint", fp);
    ok("2.10.0: script, an export made when its period ended -> RESULT: VALID, the whole period",
      /^RESULT: VALID$/m.test(ended.out) && /^Complete\s+: yes, the whole period$/m.test(ended.out), ended.out.slice(-300));
    const openLast = await save("q.zip", { windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" });
    const openSequence = cli(one, openLast, "--expect-fingerprint", fp);
    ok("2.10.0: script, two parts that join, the last made before its period ended -> exit 0 and SEQUENCE: VALID, IN PROGRESS",
      openSequence.code === 0 && /^SEQUENCE: VALID, IN PROGRESS \(2 parts join record to record/m.test(openSequence.out)
        && /^ {2}in progress: their period had not ended when they were made; together they cover it up to .+$/m.test(openSequence.out),
      openSequence.out.slice(-500));
    const folder = mkdtempSync(join(dir, "export-"));
    writeFileSync(join(folder, "part-1-of-2.zip"), writeZip((await buildSyntheticPack({})).entries));
    writeFileSync(join(folder, "part-2-of-2.zip"), writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" })).entries));
    const folderRun = cli(folder, "--expect-fingerprint", fp);
    ok("2.10.0: script, a folder whose last part was made before its period ended -> SEQUENCE: VALID, IN PROGRESS",
      folderRun.code === 0 && /^SEQUENCE: VALID, IN PROGRESS \(2 parts join record to record/m.test(folderRun.out), folderRun.out.slice(-400));
    // A checkpoint in a folder is never a part; named .zip it fails as a part, named .json it is said, not checked.
    const cpInFolder = JSON.stringify(JSON.parse(new TextDecoder().decode(synthetic.entries.find((e) => e.name.startsWith("checkpoints/")).data)));
    writeFileSync(join(folder, "mandate-checkpoint-1.json"), cpInFolder);
    const folderNote = cli(folder, "--expect-fingerprint", fp);
    ok("2.10.0: script, a checkpoint .json in a folder of parts -> checked on its own beside them, the sequence still checked",
      folderNote.code === 0 && /^Kind\s+: checkpoint$/m.test(folderNote.out) && /^RESULT: VALID \(checkpoint\)$/m.test(folderNote.out)
        && /^SEQUENCE: VALID, IN PROGRESS \(2 parts/m.test(folderNote.out) && !/was not checked/.test(folderNote.out), folderNote.out.slice(-500));
    const swapped = mkdtempSync(join(dir, "swapped-"));
    writeFileSync(join(swapped, "part-1-of-3.zip"), writeZip((await buildSyntheticPack({})).entries));
    writeFileSync(join(swapped, "part-2-of-3.zip"), writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00", generatedAt: "2026-01-16T00:30:00.0000000+00:00" })).entries));
    writeFileSync(join(swapped, "part-3-of-3.zip"), cpInFolder);
    const swappedRun = cli(swapped, "--expect-fingerprint", fp);
    ok("2.10.0: script, a folder whose last part is a checkpoint named .zip -> it fails as a part and the sequence is invalid (exit 1)",
      swappedRun.code === 1 && /cannot read .*part-3-of-3\.zip as a Mandate record/.test(swappedRun.out)
        && /^SEQUENCE: INVALID \(every part of a sequence must be a readable signed record\)$/m.test(swappedRun.out), swappedRun.out.slice(-500));
    const afterOpen = await save("r.zip", { windowFrom: "2026-01-16T00:00:00+00:00", windowTo: "2026-01-17T00:00:00+00:00",
      generatedAt: "2026-01-17T00:30:00.0000000+00:00" });
    const openFirst = cli(open, afterOpen, "--expect-fingerprint", fp);
    ok("2.10.0: script, a part in progress then one that starts at its period's end -> exit 1, the time between named",
      openFirst.code === 1
        && /^SEQUENCE: INVALID \(.*p\.zip was made at 2026-01-15T12:00:00\.0000000\+00:00, before its period ended at 2026-01-16T00:00:00\+00:00, and covers it to a minute before then, so the time after is in neither\)$/m.test(openFirst.out),
      openFirst.out.slice(-400));
    const notBegun = cli(await save("n.zip", { windowFrom: "2026-02-01T00:00:00+00:00", windowTo: "2026-03-01T00:00:00+00:00" }), "--expect-fingerprint", fp);
    ok("2.10.0: script, an export made before its period began -> RESULT: VALID, IN PROGRESS, saying it holds nothing of it",
      notBegun.code === 0
        && /^RESULT: VALID, IN PROGRESS \(the period had not begun when this record was made, on .+, so it holds nothing of it\)$/m.test(notBegun.out)
        && /^Complete\s+: no, in progress: the period had not begun when this record was made, so it holds nothing of it$/m.test(notBegun.out), notBegun.out.slice(-500));

    // 2.10.0: a checkpoint downloaded from the Checkpoints page is checked on its own.
    const bundle = JSON.parse(new TextDecoder().decode(synthetic.entries.find((e) => e.name.startsWith("checkpoints/")).data));
    const cpFile = (name, value) => {
      const path = join(dir, name);
      writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
      return path;
    };
    const cpGood = cpFile("mandate-checkpoint-good.json", bundle);
    const cpUnchecked = cli(cpGood);
    ok("2.10.0: script, a checkpoint file, no fingerprint -> exit 4, Kind: checkpoint, its records named, RESULT: NOT VERIFIED, never unchanged",
      cpUnchecked.code === 4 && /^Kind\s+: checkpoint$/m.test(cpUnchecked.out)
        && /^Records sealed : 6, from record [0-9a-f-]{36} to record [0-9a-f-]{36}$/m.test(cpUnchecked.out)
        && /as the file says \(the times are not signed\)$/m.test(cpUnchecked.out)
        && /^RESULT: NOT VERIFIED \(checkpoint, signed by a key that was not checked: name the fingerprint from your agreement with --expect-fingerprint\)$/m.test(cpUnchecked.out)
        && !/unchanged/i.test(cpUnchecked.out), cpUnchecked.out);
    const cpChecked = cli(cpGood, "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("2.10.0: script, a checkpoint file, its key named -> exit 0 and RESULT: VALID (checkpoint)",
      cpChecked.code === 0 && /^Checkpoint signature: ok$/m.test(cpChecked.out) && /^RESULT: VALID \(checkpoint\)$/m.test(cpChecked.out), cpChecked.out.slice(-400));
    // Told by its name alone. A checkpoint renamed as a record is not a record, as before 2.10.0.
    const renamed = cpFile("evidence-pack-2026-01.zip", bundle);
    const renamedRun = cli(renamed, "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("2.10.0: script, a checkpoint saved under a record's .zip name -> exit 2, not read as a record, never VALID",
      renamedRun.code === 2 && /cannot read .*evidence-pack-2026-01\.zip as a Mandate record/.test(renamedRun.out) && !/RESULT: VALID/.test(renamedRun.out), renamedRun.out);
    const cpOtherKey = cli(cpGood, "--expect-fingerprint", "cd".repeat(32));
    ok("2.10.0: script, a checkpoint file, another key named -> exit 1, the mismatch named",
      cpOtherKey.code === 1 && /\[FAIL\] the checkpoint is signed by key [0-9a-f]{64}, which is not one you named$/m.test(cpOtherKey.out)
        && /^RESULT: INVALID \(checkpoint, its signing key is not one you named\)$/m.test(cpOtherKey.out), cpOtherKey.out.slice(-300));
    const cpEdited = cli(cpFile("mandate-checkpoint-edited.json", { ...bundle, eventCount: 7 }), "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("2.10.0: script, a checkpoint file whose record count was changed -> exit 1 and the signature fails",
      cpEdited.code === 1 && /^Checkpoint signature: INVALID \(signature does not match checkpoint metadata and merkle root\)$/m.test(cpEdited.out), cpEdited.out.slice(-300));
    const cpLater = cli(cpFile("mandate-checkpoint-v3.json", { ...bundle, schemaVersion: 3 }), "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("2.10.0: script, a checkpoint file of a later format (3 since 2.18.0) -> exit 3 and RESULT: DIFFERENT FORMAT",
      cpLater.code === 3 && /^RESULT: DIFFERENT FORMAT \(this checkpoint is format 3; this checker reads formats 1 and 2/m.test(cpLater.out), cpLater.out.slice(-300));
    const { merkleRootHex: _root, ...rootless } = bundle;
    const cpMissing = cli(cpFile("mandate-checkpoint-rootless.json", rootless));
    ok("2.10.0: script, a JSON file missing a checkpoint's field -> exit 1, said plainly",
      cpMissing.code === 1 && /it is not a Mandate checkpoint: its field merkleRootHex is not a string/.test(cpMissing.out), cpMissing.out.slice(-300));
    const cpExtra = cli(cpFile("mandate-checkpoint-extra.json", { ...bundle, note: "added later" }), "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("2.10.0: script, a checkpoint file with a field a checkpoint does not carry -> exit 1, said plainly",
      cpExtra.code === 1 && /it is not a Mandate checkpoint: it carries note, which a checkpoint does not/.test(cpExtra.out), cpExtra.out.slice(-300));
    const cpJunk = cli(cpFile("mandate-checkpoint-junk.json", "{ this is not JSON"));
    ok("2.10.0: script, a file that starts like JSON and is not -> exit 2, said plainly",
      cpJunk.code === 2 && /cannot read .+ as a Mandate record or checkpoint: it is not a Mandate checkpoint: it does not read as JSON/.test(cpJunk.out), cpJunk.out);
    const cpBom = cli(cpFile("mandate-checkpoint-bom.json", `\ufeff\n  ${JSON.stringify(bundle)}\n`), "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("2.10.0: script, a checkpoint file saved with a byte-order mark and spaces -> exit 0", cpBom.code === 0, cpBom.out.slice(-300));
    const cpJson = cli(cpGood, "--json", "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("2.10.0: script --json, a checkpoint file -> kind checkpoint, valid", cpJson.code === 0
      && JSON.parse(cpJson.out).kind === "checkpoint" && JSON.parse(cpJson.out).overall === "valid", cpJson.out.slice(0, 300));
    const cpBeside = cli(cpGood, one, following, "--expect-fingerprint", fp);
    ok("2.10.0: script, a checkpoint file beside two parts that join -> exit 0, the checkpoint checked on its own, the parts still join",
      cpBeside.code === 0 && /^SEQUENCE: VALID \(2 parts join record to record/m.test(cpBeside.out) && /^RESULT: VALID \(checkpoint\)$/m.test(cpBeside.out)
        && !/was not checked/.test(cpBeside.out), cpBeside.out.slice(-400));
    const cpBesideJson = cli(cpGood, one, following, "--json", "--expect-fingerprint", fp);
    const besideDoc = (() => { try { return JSON.parse(cpBesideJson.out); } catch { return null; } })();
    ok("2.10.0: script --json, several files -> one document: every file with its result and exit code, the sequence, the exit code",
      cpBesideJson.code === 0 && besideDoc?.exitCode === 0 && besideDoc?.files?.length === 3 && besideDoc.sequence?.status === "valid"
        && besideDoc.files.map((f) => [f.kind, f.exitCode].join()).join("|") === "evidence,0|evidence,0|checkpoint,0", cpBesideJson.out.slice(0, 400));
    const cpEditedBeside = cli(cpFile("mandate-checkpoint-edited-2.json", { ...bundle, eventCount: 9 }), one, following, "--expect-fingerprint", fp);
    ok("2.10.0: script, a changed checkpoint beside two parts that join -> exit 1: nothing invalid is hidden",
      cpEditedBeside.code === 1 && /^RESULT: INVALID \(checkpoint\)$/m.test(cpEditedBeside.out) && /^SEQUENCE: VALID \(2 parts/m.test(cpEditedBeside.out),
      cpEditedBeside.out.slice(-400));
    // A part that changed is never hidden by a checkpoint beside it.
    const tampered = await save("t.zip", { windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00",
      generatedAt: "2026-01-16T00:30:00.0000000+00:00", trailEdit: true });
    const cpBesideTampered = cli(cpGood, one, tampered, "--expect-fingerprint", fp);
    ok("2.10.0: script, a checkpoint file beside two parts, one of them changed -> exit 1, the checkpoint valid beside it",
      cpBesideTampered.code === 1 && /^RESULT: VALID \(checkpoint\)$/m.test(cpBesideTampered.out)
        && /^RESULT: INVALID$/m.test(cpBesideTampered.out), cpBesideTampered.out.slice(-400));
    const tamperedFolder = mkdtempSync(join(dir, "tampered-"));
    writeFileSync(join(tamperedFolder, "part-1-of-2.zip"), writeZip((await buildSyntheticPack({})).entries));
    writeFileSync(join(tamperedFolder, "part-2-of-2.zip"), writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00",
      windowTo: "2026-01-16T00:00:00+00:00", generatedAt: "2026-01-16T00:30:00.0000000+00:00", trailEdit: true })).entries));
    writeFileSync(join(tamperedFolder, "mandate-checkpoint-1.json"), JSON.stringify(bundle));
    const tamperedFolderRun = cli(tamperedFolder, "--expect-fingerprint", fp);
    ok("2.10.0: script, a folder with a checkpoint and a changed part -> exit 1, the checkpoint checked beside it",
      tamperedFolderRun.code === 1 && /^RESULT: VALID \(checkpoint\)$/m.test(tamperedFolderRun.out), tamperedFolderRun.out.slice(-400));
    const onlyCheckpoints = mkdtempSync(join(dir, "only-checkpoints-"));
    writeFileSync(join(onlyCheckpoints, "mandate-checkpoint-1.json"), JSON.stringify(bundle));
    const onlyRun = cli(onlyCheckpoints, "--expect-fingerprint", fp);
    // A changed record always wins the exit code, ahead of a different format (3), an unreadable file (2) and not verified (4).
    const junk17 = cpFile("mandate-checkpoint-junk17.json", '{"schemaVersion":3}');
    const changedCp = cpFile("mandate-checkpoint-changed.json", { ...bundle, eventCount: 9 });
    const reviewer = cli(changedCp, junk17, "--expect-fingerprint", fp);
    ok("2.10.0: script, a changed checkpoint named with a 17-byte file of a later format -> exit 1, not 3",
      reviewer.code === 1 && /^RESULT: INVALID \(checkpoint\)$/m.test(reviewer.out) && /^RESULT: DIFFERENT FORMAT/m.test(reviewer.out), reviewer.out.slice(-400));
    const reviewerFolder = mkdtempSync(join(dir, "reviewer-"));
    writeFileSync(join(reviewerFolder, "mandate-checkpoint-changed.json"), JSON.stringify({ ...bundle, eventCount: 9 }));
    writeFileSync(join(reviewerFolder, "mandate-checkpoint-junk17.json"), '{"schemaVersion":3}');
    const reviewerFolderRun = cli(reviewerFolder, "--expect-fingerprint", fp);
    ok("2.10.0: script, the same two files in a folder -> exit 1", reviewerFolderRun.code === 1, reviewerFolderRun.out.slice(-400));
    const reviewerJson = cli(changedCp, junk17, "--json", "--expect-fingerprint", fp);
    const reviewerDoc = (() => { try { return JSON.parse(reviewerJson.out); } catch { return null; } })();
    ok("2.10.0: script --json, the same two files -> one document, exit code 1, each file's own code",
      reviewerJson.code === 1 && reviewerDoc?.exitCode === 1 && reviewerDoc.files?.map((f) => f.exitCode).join() === "1,3" && !("sequence" in reviewerDoc),
      reviewerJson.out.slice(0, 400));
    const unreadableBeside = cli(cpGood, cpFile("mandate-checkpoint-broken.json", "{ not JSON"), changedCp, "--json", "--expect-fingerprint", fp);
    // The unreadable file's message also goes to stderr, which this suite reads after stdout.
    const unreadableDoc = (() => { try { return JSON.parse(unreadableBeside.out.slice(0, unreadableBeside.out.lastIndexOf("}") + 1)); } catch { return null; } })();
    ok("2.10.0: script --json, an unreadable file beside a changed one -> exit 1, the unreadable file listed with its error and code 2",
      unreadableBeside.code === 1 && unreadableDoc?.files?.some((f) => f.exitCode === 2 && /does not read as JSON/.test(f.error ?? "")), unreadableBeside.out.slice(0, 400));
    // A folder prints the list shape whatever it holds, one pack included; one file named directly prints its own.
    const onePackFolder = mkdtempSync(join(dir, "one-pack-"));
    writeFileSync(join(onePackFolder, "a.zip"), readFileSync(one));
    const folderOneJson = cli(onePackFolder, "--json", "--expect-fingerprint", fp);
    const folderOneDoc = (() => { try { return JSON.parse(folderOneJson.out); } catch { return null; } })();
    ok("2.10.0: script --json, a folder holding one pack -> the list shape: files with one entry and the exit code",
      folderOneJson.code === 0 && folderOneDoc?.exitCode === 0 && folderOneDoc?.files?.length === 1 && folderOneDoc.files[0].exitCode === 0
        && folderOneDoc.files[0].kind === "evidence" && !("pack" in folderOneDoc) && !("sequence" in folderOneDoc), folderOneJson.out.slice(0, 300));
    const namedOneJson = cli(one, "--json", "--expect-fingerprint", fp);
    const namedOneDoc = (() => { try { return JSON.parse(namedOneJson.out); } catch { return null; } })();
    ok("2.10.0: script --json, one pack named directly -> its own result, as before",
      namedOneJson.code === 0 && namedOneDoc?.kind === "evidence" && typeof namedOneDoc.pack === "string" && !("exitCode" in namedOneDoc),
      namedOneJson.out.slice(0, 300));
    ok("2.10.0: script, a checkpoint file names its Mandate ID, and the signature says it covers it",
      /^Mandate ID\s+: [0-9a-f-]{36}$/m.test(cpChecked.out)
        && /^The signature covers the Mandate ID, the first and last record's ids, how many records there are and their root\.$/m.test(cpChecked.out), cpChecked.out);
    ok("2.10.0: script usage says the most serious exit code wins, 1 first, and what --json prints for a folder or several files",
      /^With several files the exit code is the most serious of theirs: 1 first, then 3, then 2, then 4, then 0\.$/m.test(help) && /^--json prints one JSON document\./m.test(help)
        && /for a folder,\n\s*several files or a part of a complete export, it lists every file/.test(help)
        && !/workspace/i.test(help), help);
    ok("2.10.0: script, a folder holding only a checkpoint -> it is checked, exit 0 and no sequence",
      onlyRun.code === 0 && /^RESULT: VALID \(checkpoint\)$/m.test(onlyRun.out) && !/^SEQUENCE:/m.test(onlyRun.out), onlyRun.out);
    const cpAndOne = cli(cpGood, one, "--expect-fingerprint", fp);
    ok("2.10.0: script, a checkpoint file beside one record -> both checked, exit 0 and no sequence",
      cpAndOne.code === 0 && !/^SEQUENCE:/m.test(cpAndOne.out) && /^RESULT: VALID \(checkpoint\)$/m.test(cpAndOne.out) && /^RESULT: VALID$/m.test(cpAndOne.out),
      cpAndOne.out.slice(-300));
    ok("2.10.0: script usage names the checkpoint file", /<record\.zip \| checkpoint\.json \| folder>/.test(help) && /A checkpoint downloaded from the Checkpoints page/.test(help), help);

    // 2.15.0: a complete export, the archive Mandate downloads for a long period's parts, is told by what it holds, whatever its
    // name: it is never checked as one record, so it is never called invalid.
    const partA = writeZip((await buildSyntheticPack({})).entries);
    const partB = writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00",
      generatedAt: "2026-01-16T00:30:00.0000000+00:00" })).entries);
    const readme = { name: "README.txt", data: new TextEncoder().encode("MANDATE EVIDENCE: A COMPLETE EXPORT\n") };
    const archive = writeZip([readme, { name: "part-0001-of-0002.zip", data: partA }, { name: "part-0002-of-0002.zip", data: partB }]);
    const exportNames = ["README.txt", "part-0001-of-0002.zip", "part-0002-of-0002.zip"];
    const fromBytes = (bytes) => async (at, length) => bytes.subarray(at, at + length);
    ok("2.15.0: the core reads a complete export's names from its end",
      typeof checker.readZipNames === "function"
        && JSON.stringify(await checker.readZipNames(archive.length, fromBytes(archive))) === JSON.stringify(exportNames));
    ok("2.15.0: the core reads the names of an archive written with ZIP64 end records",
      typeof checker.readZipNames === "function"
        && JSON.stringify(await checker.readZipNames(archive.length + 76, fromBytes(zip64(archive)))) === JSON.stringify(exportNames));
    ok("2.15.0: the core reads no names from bytes that do not end as an archive does",
      typeof checker.readZipNames === "function" && await checker.readZipNames(17, fromBytes(new TextEncoder().encode('{"schemaVersion":2}'))) === null);
    ok("2.15.0: the core tells a complete export by its parts and no manifest, with Mandate's own rule",
      typeof checker.completeExportOf === "function"
        && JSON.stringify(checker.completeExportOf(exportNames))
          === JSON.stringify({ parts: 2, of: 2, first: "part-0001-of-0002.zip", last: "part-0002-of-0002.zip", missing: 0, firstMissing: null })
        && checker.completeExportOf([...exportNames, "manifest.json"]) === null
        && checker.completeExportOf(["README.txt", "manifest.json", "register/decisions.json"]) === null);
    ok("2.15.0: the core names the parts a set of part names leaves out, and says nothing of names that are not parts",
      typeof checker.partsMissing === "function"
        && checker.partsMissing(["part-1-of-3.zip", "part-2-of-3.zip"]) === "part-3-of-3.zip is missing, so 2 of the 3 parts were given"
        && checker.partsMissing(["part-0001-of-0004.zip", "part-0004-of-0004.zip"]) === "part-0002-of-0004.zip and 1 more are missing, so 2 of the 4 parts were given"
        && checker.partsMissing(["part-1-of-2.zip", "part-2-of-2.zip"]) === "" && checker.partsMissing(["a.zip", "b.zip"]) === ""
        && checker.partsMissing(["part-1-of-2.zip", "b.zip"]) === "");
    const exportPath = join(dir, "trial-record.zip");
    writeFileSync(exportPath, archive);
    const exportAlone = cli(exportPath, "--expect-fingerprint", fp);
    ok("2.15.0: script, a complete export named trial-record.zip -> exit 2, said plainly, never a result or INVALID",
      exportAlone.code === 2
        && exportAlone.out.includes(`${exportPath} is a complete export: an archive of 2 records, part-0001-of-0002.zip to part-0002-of-0002.zip. `
          + "The archive itself is not signed, so it is not checked as a record. Unzip it into a folder, then give the checker the folder:\n"
          + "    node mandate-verify.mjs <folder> --expect-fingerprint <hex>")
        && !/RESULT:/.test(exportAlone.out) && !/INVALID/.test(exportAlone.out), exportAlone.out);
    const packsNamed = join(dir, "x-2-packs.zip");
    writeFileSync(packsNamed, archive);
    const packsNamedRun = cli(packsNamed, "--expect-fingerprint", fp);
    ok("2.15.0: script, the same export under its downloaded name -> the same words",
      packsNamedRun.code === 2 && packsNamedRun.out.includes(`${packsNamed} is a complete export: an archive of 2 records,`), packsNamedRun.out);
    const recordNamedAsExport = join(dir, "y-2-packs.zip");
    writeFileSync(recordNamedAsExport, readFileSync(one));
    const recordNamedRun = cli(recordNamedAsExport, "--expect-fingerprint", fp);
    ok("2.15.0: script, a record saved under a complete export's name -> checked as the record it is",
      recordNamedRun.code === 0 && /^RESULT: VALID$/m.test(recordNamedRun.out), recordNamedRun.out.slice(-300));
    const shortExport = join(dir, "short-export.zip");
    writeFileSync(shortExport, writeZip([readme, { name: "part-0001-of-0003.zip", data: partA }, { name: "part-0002-of-0003.zip", data: partB }]));
    const shortRun = cli(shortExport, "--expect-fingerprint", fp);
    ok("2.15.0: script, a complete export missing a part -> the part named",
      shortRun.code === 2 && shortRun.out.includes("It does not hold part-0003-of-0003.zip, so the folder will not cover the whole period."), shortRun.out);
    const unzippedBeside = mkdtempSync(join(dir, "unzipped-beside-"));
    writeFileSync(join(unzippedBeside, "mandate-evidence-2-packs.zip"), archive);
    writeFileSync(join(unzippedBeside, "part-0001-of-0002.zip"), partA);
    writeFileSync(join(unzippedBeside, "part-0002-of-0002.zip"), partB);
    const besideRun = cli(unzippedBeside, "--expect-fingerprint", fp);
    ok("2.15.0: script, a folder holding a complete export beside its unzipped parts -> the export set aside, the parts checked",
      besideRun.code === 0 && /^ {2}note: .*mandate-evidence-2-packs\.zip is a complete export, an archive of records, not one record; it was set aside$/m.test(besideRun.out)
        && /^SEQUENCE: VALID \(2 parts join record to record/m.test(besideRun.out), besideRun.out.slice(-600));
    const besideJson = cli(unzippedBeside, "--json", "--expect-fingerprint", fp);
    const setAsideDoc = (() => { try { return JSON.parse(besideJson.std); } catch { return null; } })();
    ok("2.15.0: script --json, the same folder -> the export listed as set aside, the parts as files, the result valid",
      besideJson.code === 0 && setAsideDoc?.setAside?.length === 1 && setAsideDoc.files?.length === 2 && setAsideDoc.result === "valid",
      besideJson.out.slice(0, 400));
    const twoOfThree = mkdtempSync(join(dir, "two-of-three-"));
    writeFileSync(join(twoOfThree, "part-0001-of-0003.zip"), partA);
    writeFileSync(join(twoOfThree, "part-0002-of-0003.zip"), partB);
    const twoOfThreeRun = cli(twoOfThree, "--expect-fingerprint", fp);
    ok("2.15.0: script, a folder holding parts 1 and 2 of 3 -> exit 1, the missing part named",
      twoOfThreeRun.code === 1 && /^SEQUENCE: INVALID \(part-0003-of-0003\.zip is missing, so 2 of the 3 parts were given\)$/m.test(twoOfThreeRun.out),
      twoOfThreeRun.out.slice(-400));
    ok("2.15.0: script usage says a complete export is known by what it holds, and that exit 2 covers one given as a file",
      /^A complete export downloaded as one archive is known by what it holds, whatever its name: unzip it and give the checker the folder\.$/m.test(help)
        && /2 a wrong option or value, a file the checker cannot read as a record or checkpoint, or a complete export given as one file/.test(help), help);

    // 2.15.0: a check of several files ends with one line whose word is its exit code's, and the sequence line never
    // says VALID while a part failed its own check.
    const lastLine = (run) => run.std.trimEnd().split("\n").at(-1);
    const WORD = { 0: "VALID", 1: "INVALID", 2: "NOT CHECKED", 3: "NOT CHECKED", 4: "NOT VERIFIED" };
    const several = { leftOutRun, joinedUnchecked, erasedRun, openSequence, folderRun, folderNote, swappedRun, openFirst, cpBesideTampered,
      tamperedFolderRun, onlyRun, reviewer, reviewerFolderRun, cpAndOne, besideRun, twoOfThreeRun };
    const mismatched = Object.entries(several).filter(([, run]) => !new RegExp(`^OVERALL: ${WORD[run.code]}[ ,]`).test(lastLine(run)));
    ok("2.15.0: script, every check of several files ends with OVERALL, its word the exit code's",
      mismatched.length === 0, mismatched.map(([name, run]) => `${name}: exit ${run.code}, last line ${lastLine(run)}`).join("; "));
    ok("2.15.0: script, no check without a fingerprint ends VALID",
      lastLine(joinedUnchecked) === "OVERALL: NOT VERIFIED (signed by a key that was not checked: name the fingerprint from your agreement with --expect-fingerprint)",
      lastLine(joinedUnchecked));
    ok("2.15.0: script, a folder whose second part changed -> the sequence not VALID, the last line naming the part",
      tamperedFolderRun.code === 1 && !/^SEQUENCE: VALID/m.test(tamperedFolderRun.out)
        && /^OVERALL: INVALID \(.*part-2-of-2\.zip failed its check\)$/.test(lastLine(tamperedFolderRun)), tamperedFolderRun.out.slice(-600));
    // A part whose README changed after signing: its own check fails, and its records still join the part before it.
    const changedAfterSigning = async (name) => {
      const { entries } = await buildSyntheticPack({ windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00",
        generatedAt: "2026-01-16T00:30:00.0000000+00:00" });
      entries.find((e) => e.name === "README.txt").data = new TextEncoder().encode("Changed after it was signed.\n");
      const path = join(dir, name);
      writeFileSync(path, writeZip(entries));
      return path;
    };
    const changedPart = cli(one, await changedAfterSigning("u.zip"), "--expect-fingerprint", fp);
    ok("2.15.0: script, two parts that join, one changed -> SEQUENCE: INVALID, the parts join but a part failed",
      changedPart.code === 1 && /^SEQUENCE: INVALID \(the parts join, but at least one part failed its own check above\)$/m.test(changedPart.out)
        && /^OVERALL: INVALID \(.*u\.zip failed its check\)$/.test(lastLine(changedPart)), changedPart.out.slice(-600));
    ok("2.15.0: script, parts that join and verify, in progress -> the last line says so and counts them",
      lastLine(folderRun) === "OVERALL: VALID, IN PROGRESS (2 records, each unchanged since it was signed with a key you named; the 2 parts join with no gap between their periods)",
      lastLine(folderRun));
    ok("2.15.0: script, a record and a checkpoint that verify -> the last line counts both",
      lastLine(cpAndOne) === "OVERALL: VALID (1 record and 1 checkpoint, each unchanged since it was signed with a key you named)", lastLine(cpAndOne));
    ok("2.15.0: script, a part that is not a record -> the last line gives the sequence's reason",
      lastLine(swappedRun) === "OVERALL: INVALID (every part of a sequence must be a readable signed record)", lastLine(swappedRun));
    const changedJson = cli(one, await changedAfterSigning("v.zip"), "--json", "--expect-fingerprint", fp);
    const changedDoc = (() => { try { return JSON.parse(changedJson.std); } catch { return null; } })();
    ok("2.15.0: script --json, a changed part -> result invalid beside exit code 1, the sequence's own status still the join",
      changedDoc?.exitCode === 1 && changedDoc.result === "invalid" && changedDoc.sequence?.status === "valid", changedJson.out.slice(0, 300));
    ok("2.15.0: script usage says the last line gives the result in words",
      /^With several files the exit code is the most serious of theirs: 1 first, then 3, then 2, then 4, then 0\.$/m.test(help)
        && /^The last line, OVERALL, says the same in words\.$/m.test(help), help);
    // 2.21.0: a part's name says how many parts there are, so one given alone, by itself or in a folder, is a sequence with
    // the others missing, as the usage and the format notes promise.
    const lonePart = mkdtempSync(join(dir, "one-of-twelve-"));
    const lonePath = join(lonePart, "part-0001-of-0012.zip");
    writeFileSync(lonePath, partA);
    const LONE = "part-0002-of-0012.zip and 10 more are missing, so 1 of the 12 parts was given";
    ok("2.21.0: the core names the parts missing when one part is given alone",
      checker.partsMissing(["part-0001-of-0012.zip"]) === LONE && checker.partsMissing(["part-1-of-1.zip"]) === "", checker.partsMissing(["part-0001-of-0012.zip"]));
    const loneFolder = cli(lonePart, "--expect-fingerprint", fp);
    ok("2.21.0: script, a folder holding only part 1 of 12 -> exit 1, the part itself VALID, SEQUENCE and OVERALL INVALID naming the parts missing",
      loneFolder.code === 1 && /^RESULT: VALID$/m.test(loneFolder.out) && loneFolder.out.includes(`\nSEQUENCE: INVALID (${LONE})\n`)
        && lastLine(loneFolder) === `OVERALL: INVALID (${LONE})` && !/OVERALL: VALID/.test(loneFolder.out), loneFolder.out.slice(-500));
    const loneFile = cli(lonePath, "--expect-fingerprint", fp);
    ok("2.21.0: script, part 1 of 12 named on its own -> exit 1 and the same SEQUENCE and OVERALL lines",
      loneFile.code === 1 && loneFile.out.includes(`\nSEQUENCE: INVALID (${LONE})\n`) && lastLine(loneFile) === `OVERALL: INVALID (${LONE})`, loneFile.out.slice(-500));
    const loneJson = cli(lonePath, "--json", "--expect-fingerprint", fp);
    const loneDoc = (() => { try { return JSON.parse(loneJson.std); } catch { return null; } })();
    ok("2.21.0: script --json, part 1 of 12 on its own -> the file, the sequence that fails and the result, beside exit 1",
      loneJson.code === 1 && loneDoc?.exitCode === 1 && loneDoc.result === "invalid" && loneDoc.sequence?.reason === LONE && loneDoc.files?.[0]?.exitCode === 0,
      loneJson.out.slice(0, 400));
    const onlyOne = join(mkdtempSync(join(dir, "one-of-one-")), "part-1-of-1.zip");
    writeFileSync(onlyOne, partA);
    const onlyOneRun = cli(onlyOne, "--expect-fingerprint", fp);
    ok("2.21.0: script, part 1 of 1 -> exit 0 and no sequence", onlyOneRun.code === 0 && !/^SEQUENCE:/m.test(onlyOneRun.out), onlyOneRun.out.slice(-300));

    // 2.21.0: a part not verified for a reason of its own says so on the SEQUENCE and OVERALL lines, never the key's reason.
    const STALE = "outside timestamps: 1 checkpoint(s) more than two hours older than this export have no outside timestamp";
    const stamps = cli(one, following, "--expect-fingerprint", fp, "--require-timestamps");
    ok("2.21.0: script, two parts that join, the fingerprint named, a part without the timestamps --require-timestamps asks for -> exit 4, both lines give its reason",
      stamps.code === 4 && stamps.out.includes(`\nRESULT: NOT VERIFIED (${STALE})\n`)
        && stamps.out.includes(`\nSEQUENCE: NOT VERIFIED (2 parts join record to record, with no gap between their periods, but ${following} is not verified: ${STALE})\n`)
        && lastLine(stamps) === `OVERALL: NOT VERIFIED (${following} is not verified: ${STALE})`
        && !/^SEQUENCE: VALID/m.test(stamps.out) && !/was not checked/.test(stamps.out), stamps.out.slice(-700));
    const stampsUnnamed = cli(one, "--require-timestamps", cpGood);
    ok("2.21.0: script, a record whose key was not checked and a checkpoint without the timestamp asked for -> OVERALL gives the checkpoint's own reason",
      stampsUnnamed.code === 4
        && lastLine(stampsUnnamed) === `OVERALL: NOT VERIFIED (${cpGood} is not verified: --require-timestamps: the checkpoint has no outside timestamp)`,
      lastLine(stampsUnnamed));

    // 2.21.0: --json prints one document whatever the exit code, an unreadable file's error included.
    const missingFile = join(dir, "no-such-record.zip");
    const missingJson = cli(missingFile, "--json");
    const missingDoc = (() => { try { return JSON.parse(missingJson.std); } catch { return null; } })();
    ok("2.21.0: script --json, a file that cannot be read -> exit 2 and a JSON document naming the file and the error",
      missingJson.code === 2 && missingDoc?.pack === missingFile && /^cannot read .*no-such-record\.zip/.test(missingDoc.error ?? ""), missingJson.out);
    const notZip = join(dir, "notes.zip");
    writeFileSync(notZip, "not an archive\n");
    const notZipDoc = (() => { try { return JSON.parse(cli(notZip, "--json").std); } catch { return null; } })();
    ok("2.21.0: script --json, a file that is not a record -> a JSON document with the error",
      typeof notZipDoc?.error === "string" && notZipDoc.error.startsWith(`cannot read ${notZip} as a Mandate record`), JSON.stringify(notZipDoc));
    const exportJson = cli(exportPath, "--json");
    const exportDoc = (() => { try { return JSON.parse(exportJson.std); } catch { return null; } })();
    ok("2.21.0: script --json, a complete export given alone -> exit 2 and a JSON document saying what it holds",
      exportJson.code === 2 && exportDoc?.completeExport?.parts === 2 && /is a complete export/.test(exportDoc.error ?? ""), exportJson.out.slice(0, 300));

    // 2.21.0: the usage says what the code does: a minute before, both reasons for exit 4, and one part alone.
    ok("2.21.0: script usage says a later export starts by a minute before one in progress was made, as the check does",
      /^A later export must then start no later than a minute before the one in progress was made, or the time between is in neither\.$/m.test(help)
        && !/no later than when the one in progress was made/.test(help), help);
    ok("2.21.0: script usage gives exit 4 both reasons, exit 1 a key not named and records that do not join, exit 3 the earlier layout, and one part alone",
      /^ {4}or outside timestamps that could not be verified \(below\)$/m.test(help)
        && /^ {4}A record whose change trail is sealed in the layout used before checker 2\.7\.0 is a different format: checker 2\.6\.0 reads it\.$/m.test(help)
        && /^ {2}0 valid, signed by a key you named {3}1 invalid, signed by a key you did not name, or records that do not join$/m.test(help)
        && /must all be there, even when one is given alone: a part missing is named and the check fails\.$/m.test(help), help);

    // 2.21.0: a record made before checker 2.7.0 is a different format, never INVALID; anything its layout does not
    // explain still fails, and so does a key not named.
    const EARLIER = "RESULT: DIFFERENT FORMAT (this record's change trail is sealed in the layout Mandate used until checker 2.7.0 (2026-10-25), "
      + "which this checker does not read. Checker 2.6.0 reads it: tag v2.6.0 at github.com/mandate-systems/mandate-verify)";
    const earlier = await save("before-2.7.0.zip", { before270: true });
    const earlierRun = cli(earlier, "--expect-fingerprint", fp);
    ok("2.21.0: script, a record made before checker 2.7.0 -> exit 3, DIFFERENT FORMAT naming 2.7.0 and the checker that reads it",
      earlierRun.code === 3 && earlierRun.out.includes(`\n${EARLIER}\n`)
        && /^Records: \[ \?\? \] 2 change-trail entries are sealed in the layout used before checker 2\.7\.0, which this checker does not read$/m.test(earlierRun.out)
        && !/INVALID/.test(earlierRun.out), earlierRun.out.slice(-600));
    ok("2.21.0: script, the same record with a key not named -> exit 1, INVALID",
      cli(earlier, "--expect-fingerprint", "cd".repeat(32)).code === 1);
    const earlierJson = (() => { try { return JSON.parse(cli(earlier, "--json", "--expect-fingerprint", fp).std); } catch { return null; } })();
    ok("2.21.0: script --json, the same record -> overall unsupported, the layout and the reason named",
      earlierJson?.overall === "unsupported" && earlierJson.sealedBefore === "2.7.0" && earlierJson.format === 3 && earlierJson.chain?.status === "unsupported"
        && /^this record's change trail is sealed in the layout Mandate used until checker 2\.7\.0/.test(earlierJson.formatReason ?? ""),
      JSON.stringify(earlierJson)?.slice(0, 400));
    const earlierAndCurrent = cli(earlier, following, "--expect-fingerprint", fp);
    ok("2.21.0: script, a part made before checker 2.7.0 then a current one -> OVERALL NOT CHECKED in the checker's own word for a format",
      earlierAndCurrent.code === 3 && /^OVERALL: NOT CHECKED \(.*before-2\.7\.0\.zip is in a format this checker does not read\)$/.test(lastLine(earlierAndCurrent)),
      lastLine(earlierAndCurrent));
    const earlierFollowing = await save("before-2.7.0-b.zip", { before270: true, windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00",
      generatedAt: "2026-01-16T00:30:00.0000000+00:00" });
    const earlierPair = cli(earlier, earlierFollowing, "--expect-fingerprint", fp);
    ok("2.21.0: script, two parts made before checker 2.7.0 -> exit 3, SEQUENCE and OVERALL NOT CHECKED, never INVALID",
      earlierPair.code === 3 && /^SEQUENCE: NOT CHECKED \(.*before-2\.7\.0(-b)?\.zip is in a format this checker does not read\)$/m.test(earlierPair.out)
        && /^OVERALL: NOT CHECKED \(/.test(lastLine(earlierPair)) && !/INVALID/.test(earlierPair.out), earlierPair.out.slice(-600));
    const gapAfter = await save("gap-after.zip", { windowFrom: "2026-01-16T06:00:00+00:00", windowTo: "2026-01-16T12:00:00+00:00",
      generatedAt: "2026-01-16T12:30:00.0000000+00:00" });
    const earlierBeside = cli(earlier, following, gapAfter, "--expect-fingerprint", fp);
    ok("2.21.0: script, a part made before checker 2.7.0 beside two parts with a gap between them -> exit 1, the gap still found",
      earlierBeside.code === 1 && /^SEQUENCE: INVALID \(.*their periods leave a gap between them\)$/m.test(earlierBeside.out), earlierBeside.out.slice(-500));
    // 2.22.0: the script itself, given an earlier export and a later one that dropped who acted on a sealed entry.
    const dropped = await save("dropped-later.zip", { generatedAt: "2026-01-15T13:00:00.0000000+00:00", trailGone: true, partialFromR3: true,
      chainTruncated: true, manifestTruncated: true });
    const droppedRun = cli(one, dropped, "--expect-fingerprint", fp);
    ok("2.22.0: script, a later export that dropped who acted on an entry the earlier one seals -> exit 1, SEQUENCE INVALID naming the entry and the export",
      droppedRun.code === 1 && /^SEQUENCE: INVALID \(the records disagree: change-trail entry dddddddd-0000-4000-8000-000000000001 \(held_decision\.denied\), listed in mutations\/policy-trail\.json, names who acted in .*a\.zip but not in .*dropped-later\.zip; .*a\.zip carries the entry's sealed record, and .*a\.zip's copy of the entry matches it\)$/m.test(droppedRun.out)
        && /^OVERALL: INVALID \(/m.test(droppedRun.out), droppedRun.out.slice(-700));
    // 2.23.0: three exports, the middle one starting between the other two so that each joins its neighbour. In a folder
    // the first and the last are not neighbours: an entry they share is held to one copy as the folder is read, and two
    // whose times overlap are read again and compared.
    const trioFolder = async (name, lastTweak) => {
      const folder = mkdtempSync(join(dir, `${name}-`));
      writeFileSync(join(folder, "1-first.zip"), writeZip((await buildSyntheticPack({})).entries));
      writeFileSync(join(folder, "2-middle.zip"), writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T05:00:00+00:00", windowTo: "2026-01-15T08:00:00+00:00",
        generatedAt: "2026-01-15T08:30:00.0000000+00:00", dropFirstEntry: true, partialFromR3: true, chainTruncated: true, manifestTruncated: true })).entries));
      writeFileSync(join(folder, "3-last.zip"), writeZip((await buildSyntheticPack({ windowFrom: "2026-01-15T06:00:00+00:00", generatedAt: "2026-01-15T13:00:00.0000000+00:00",
        partialFromR3: true, chainTruncated: true, manifestTruncated: true, ...lastTweak })).entries));
      return folder;
    };
    const missingFolder = await trioFolder("trio-missing", { dropFirstEntry: true });
    const missingRun = cli(missingFolder, "--expect-fingerprint", fp);
    ok("2.23.0: script, a folder of three exports, the last missing an entry the first holds, the middle between them -> exit 1, the first and the last read again and compared",
      missingRun.code === 1 && /^SEQUENCE: INVALID \(the records disagree: change-trail entry dddddddd-0000-4000-8000-000000000001 \(held_decision\.denied\) is in .*1-first\.zip but missing from .*3-last\.zip's mutations\/policy-trail\.json, inside the period .*3-last\.zip covers\)$/m.test(missingRun.out),
      missingRun.out.slice(-700));
    const missingFiles = cli(...["1-first.zip", "2-middle.zip", "3-last.zip"].map((n) => join(missingFolder, n)), "--expect-fingerprint", fp);
    ok("2.23.0: script, the same three named one by one -> exit 1, the same failure",
      missingFiles.code === 1 && /^SEQUENCE: INVALID \(the records disagree: change-trail entry dddddddd-0000-4000-8000-000000000001 \(held_decision\.denied\) is in .*1-first\.zip but missing from .*3-last\.zip's/m.test(missingFiles.out),
      missingFiles.out.slice(-700));
    const goneRun = cli(await trioFolder("trio-gone", { trailGone: true }), "--expect-fingerprint", fp);
    ok("2.23.0: script, a folder of three exports, the last naming no one on an entry the first seals -> exit 1, the entry and both exports named",
      goneRun.code === 1 && /^SEQUENCE: INVALID \(the records disagree: change-trail entry dddddddd-0000-4000-8000-000000000001 \(held_decision\.denied\), listed in mutations\/policy-trail\.json, names who acted in .*1-first\.zip but not in .*3-last\.zip; .*1-first\.zip carries the entry's sealed record, and .*1-first\.zip's copy of the entry matches it\)$/m.test(goneRun.out),
      goneRun.out.slice(-700));
    const honestRun = cli(await trioFolder("trio-honest", {}), "--expect-fingerprint", fp);
    ok("2.23.0: script, a folder of three genuine exports, the middle between the other two -> exit 0, SEQUENCE VALID",
      honestRun.code === 0 && /^SEQUENCE: VALID \(3 parts join record to record/m.test(honestRun.out), honestRun.out.slice(-700));
    // 2.23.0: three exports whose periods follow one another, the last holding a row of a decision the first holds, its
    // record outside the last's records file and its outcome and time rewritten: they are read again and compared.
    const apartFolder = mkdtempSync(join(dir, "apart-"));
    const emptyRecords = { noLinks: true, chainTruncated: true, manifestTruncated: true };
    writeFileSync(join(apartFolder, "1-first.zip"), writeZip((await buildSyntheticPack({})).entries));
    writeFileSync(join(apartFolder, "2-middle.zip"), writeZip((await buildSyntheticPack({ ...emptyRecords, windowFrom: "2026-01-15T12:00:00+00:00",
      windowTo: "2026-01-16T00:00:00+00:00", generatedAt: "2026-01-16T00:30:00.0000000+00:00", editDecisions: () => [] })).entries));
    writeFileSync(join(apartFolder, "3-last.zip"), writeZip((await buildSyntheticPack({ ...emptyRecords, windowFrom: "2026-01-16T00:00:00+00:00",
      windowTo: "2026-01-16T12:00:00+00:00", generatedAt: "2026-01-16T12:30:00.0000000+00:00",
      editDecisions: ([row]) => { const { recordSha256, ...untied } = row; return [{ ...untied, action: "allow", occurredAt: "2026-01-16T06:00:00+00:00" }]; } })).entries));
    const apartRun = cli(apartFolder, "--expect-fingerprint", fp);
    ok("2.23.0: script, a folder of three exports apart in time, the last rewriting a decision the first holds -> exit 1, the decision named",
      apartRun.code === 1 && /^SEQUENCE: INVALID \(the records disagree: decision aaaaaaaa-0000-4000-8000-000000000002 reads differently in .*3-last\.zip than in .*1-first\.zip: its .*outcome.*time\)$/m.test(apartRun.out)
        && (apartRun.out.match(/^RESULT: VALID/gm) ?? []).length === 3, apartRun.out.slice(-900));
    ok("2.21.1: the usage and every line of a run call the tool the checker, never the verifier",
      !/verifier/i.test(help) && [unchecked, named, otherFormat, exportAlone, earlierRun, cpLater].every((run) => !/verifier/i.test(run.out)),
      [help, unchecked.out, named.out, otherFormat.out, exportAlone.out, earlierRun.out, cpLater.out].join("\n").split("\n").filter((l) => /verifier/i.test(l)).join(" | "));
    ok("script --version reports 2.23.0", /^mandate-verify 2\.23\.0 /.test(cli("--version").out));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
{
  const r = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ manifestVersion: 2 })).entries), inflateRaw);
  ok("a format 2 pack -> a different format, not INVALID", r.overall === "unsupported" && /format 2/.test(r.manifest.reason ?? ""));
}
{
  // 2.21.0: a record made before checker 2.7.0 is told by every mark of its layout and is a different format; whatever
  // that layout does not explain fails as before, so no changed record can pass for an earlier one.
  const build = async (tweak) => (await buildSyntheticPack({ before270: true, ...tweak })).entries;
  const pack = async (tweak) => verifyEvidencePackBytes(writeZip(await build(tweak)), inflateRaw);
  const earlier = await pack({});
  ok("2.21.0: a record made before checker 2.7.0 -> a different format naming 2.7.0, its signature, checkpoint and decisions checked",
    earlier.overall === "unsupported" && earlier.sealedBefore === "2.7.0" && earlier.format === 3 && earlier.manifest.status === "valid"
      && earlier.chain.status === "unsupported" && earlier.chain.checkpointsRecomputed === 1 && earlier.chain.decisionsTied === 2
      && earlier.checkpoints.every((c) => c.result.status === "valid"), JSON.stringify({ o: earlier.overall, c: earlier.chain }));
  const inProgress = await pack({ windowTo: "2026-01-16T00:00:00+00:00" });
  ok("2.21.0: the same record made before its period ended, its report silent on that as reports were then -> a different format",
    inProgress.overall === "unsupported" && inProgress.inProgress === true, JSON.stringify(inProgress.chain));
  const laterNames = await pack({ laterNames: true });
  ok("2.21.0: the same record with an entry made after the last seal naming a list's entries, as the trail then did -> a different format",
    laterNames.overall === "unsupported", JSON.stringify(laterNames.chain));
  const fails = [
    ["an entry rewritten after sealing", { trailEdit: true }, /^change-trail entry dddddddd-0000-4000-8000-000000000001 \(held_decision\.denied\) in mutations\/policy-trail\.json differs from its sealed record$/],
    ["a decision's readable row changed", { rowAction: "allow" }, /the readable row differs from its record: its outcome$/],
    ["one entry sealed under v1, the other under v2", { before270: "mixed" }, /^change-trail entry dddddddd-0000-4000-8000-000000000001 .* differs from its sealed record$/],
    ["its checkpoints in format 2", { stamp: () => null }, /^change-trail entry dddddddd-0000-4000-8000-000000000001 .* differs from its sealed record$/],
    ["a report that says what other AI tools reported", { noImported: false }, /^change-trail entry dddddddd-0000-4000-8000-000000000001 .* differs from its sealed record$/],
    ["an entry carrying a mandate's facts, which v1 never sealed", { mandate: true }, /^change-trail entry dddddddd-0000-4000-8000-000000000001 .* differs from its sealed record$/],
  ];
  for (const [what, tweak, reason] of fails) {
    const r = await pack(tweak);
    ok(`2.21.0: a record made before checker 2.7.0 with ${what} -> INVALID, as before`, r.overall === "invalid" && reason.test(r.chain?.reason ?? ""),
      JSON.stringify({ o: r.overall, c: r.chain?.reason }));
  }
  const changedFile = await build({});
  changedFile.find((e) => e.name === "README.txt").data = new TextEncoder().encode("Changed after it was signed.\n");
  const changed = await verifyEvidencePackBytes(writeZip(changedFile), inflateRaw);
  ok("2.21.0: a record made before checker 2.7.0 with a file changed after signing -> INVALID",
    changed.overall === "invalid" && changed.files.some((f) => f.path === "README.txt" && f.status === "invalid"), JSON.stringify(changed.files));
}
{
  // 2.10.0: an access record whose range runs past the moment it was made is in progress, as an export is.
  const access = async (tweak) => verifyDsrAccessPackBytes(writeZip((await buildSyntheticDsrPack(tweak)).entries), inflateRaw);
  const open = await access({ windowTo: "2026-02-01T00:00:00+00:00" });
  ok("2.10.0: an access record made before its range ended -> valid and in progress", open.overall === "valid" && open.inProgress === true && open.notBegun === false,
    JSON.stringify({ m: open.manifest, inProgress: open.inProgress }));
  const future = await access({ windowFrom: "2026-02-01T00:00:00+00:00", windowTo: "2026-03-01T00:00:00+00:00" });
  ok("2.10.0: an access record made before its range began -> valid, in progress and not begun", future.overall === "valid" && future.inProgress === true && future.notBegun === true);
  const unbounded = await access({});
  ok("2.10.0: an access record with no end to its range -> not in progress", unbounded.overall === "valid" && unbounded.inProgress === false);
  const dir = mkdtempSync(join(tmpdir(), "mandate-verify-access-"));
  try {
    const file = join(dir, "access-open.zip");
    writeFileSync(file, writeZip((await buildSyntheticDsrPack({ windowTo: "2026-02-01T00:00:00+00:00" })).entries));
    const run = spawnSync(process.execPath, [join(repoRoot, "mandate-verify.mjs"), file, "--expect-fingerprint", dsrVector.publicKeyFingerprint], { encoding: "utf8" });
    ok("2.10.0: script, an access record in progress -> exit 0, RESULT: VALID, IN PROGRESS and Complete: no, in progress",
      run.status === 0 && /^RESULT: VALID, IN PROGRESS \(the period had not ended when this record was made, so it holds what was recorded up to .+\)$/m.test(run.stdout)
        && /^Complete\s+: no, in progress: the period had not ended when this record was made, so it holds what was recorded up to then; unscannable rows/m.test(run.stdout),
      run.stdout.slice(-500));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
{
  // 2.10.0: an export made before its period ended is valid and in progress, and its report says so.
  const pack = async (tweak) => verifyEvidencePackBytes(writeZip((await buildSyntheticPack(tweak)).entries), inflateRaw);
  const day = { windowTo: "2026-01-16T00:00:00+00:00" };
  const open = await pack(day);
  ok("2.10.0: an export made before its period ended -> valid and in progress", open.overall === "valid" && open.inProgress === true,
    JSON.stringify({ m: open.manifest, c: open.chain?.reason }));
  ok("2.10.0: an export made as its period ended -> not in progress", baseline.overall === "valid" && baseline.inProgress === false);
  const future = await pack({ windowFrom: "2026-02-01T00:00:00+00:00", windowTo: "2026-03-01T00:00:00+00:00" });
  ok("2.10.0: an export of a period that had not begun when it was made -> valid, in progress and not begun",
    future.overall === "valid" && future.inProgress === true && future.notBegun === true && open.notBegun === false, JSON.stringify(future.chain?.reason));
  const sameMillisecond = await pack({ generatedAt: "2026-01-15T12:00:00.0004000+00:00", windowTo: "2026-01-15T12:00:00.0009+00:00" });
  ok("2.10.0: an export made in the millisecond its period ends -> not in progress (the signature binds milliseconds)",
    sameMillisecond.overall === "valid" && sameMillisecond.inProgress === false, JSON.stringify({ m: sameMillisecond.manifest, c: sameMillisecond.chain?.reason }));
  const unsaid = await pack({ ...day, summaryInProgress: false });
  ok("2.10.0: an export in progress whose report does not say so -> invalid",
    unsaid.overall === "invalid" && /report\/summary\.json does not say that its period had not ended when the record was made/.test(unsaid.chain?.reason ?? ""),
    unsaid.chain?.reason);
  const missaid = await pack({ summaryInProgress: true });
  ok("2.10.0: an ended export whose report says it is in progress -> invalid",
    missaid.overall === "invalid" && /says that its period had not ended when the record was made, but the record was made after it ended/.test(missaid.chain?.reason ?? ""),
    missaid.chain?.reason);
  const next = await pack({ windowFrom: "2026-01-16T00:00:00+00:00", windowTo: "2026-01-17T00:00:00+00:00", generatedAt: "2026-01-17T00:30:00.0000000+00:00" });
  const gapped = checkPackSequence([{ name: "a", result: open }, { name: "b", result: next }]);
  ok("2.10.0: a part in progress then one that starts at its period's end -> invalid, the time between named",
    gapped.status === "invalid" && gapped.kind === "gap" && /a was made at .+, before its period ended at .+, and covers it to a minute before then, so the time after is in neither/.test(gapped.reason), JSON.stringify(gapped));
  const within = await pack({ windowFrom: "2026-01-15T11:59:30+00:00", windowTo: "2026-01-16T00:00:00+00:00", generatedAt: "2026-01-16T00:30:00.0000000+00:00" });
  const unsettled = checkPackSequence([{ name: "a", result: open }, { name: "b", result: within }]);
  ok("2.10.0: a part in progress then one starting inside the minute before it was made -> invalid, as its span ends a minute before",
    unsettled.status === "invalid" && unsettled.kind === "gap", JSON.stringify(unsettled));
  const settled = await pack({ windowFrom: "2026-01-15T11:59:00+00:00", windowTo: "2026-01-16T00:00:00+00:00", generatedAt: "2026-01-16T00:30:00.0000000+00:00" });
  const joinedSettled = checkPackSequence([{ name: "a", result: open }, { name: "b", result: settled }]);
  ok("2.10.0: a part in progress then one starting a minute before it was made -> they join, and the period is whole",
    joinedSettled.status === "valid" && joinedSettled.inProgress === false, JSON.stringify(joinedSettled));
  const redone = await pack({ ...day, generatedAt: "2026-01-16T00:30:00.0000000+00:00" });
  const redoneSeq = checkPackSequence([{ name: "a", result: open }, { name: "b", result: redone }]);
  ok("2.10.0: an export in progress and a later one of the same period -> they join, and the period is whole",
    redoneSeq.status === "valid" && redoneSeq.inProgress === false, JSON.stringify(redoneSeq));
  const tail = await pack({ windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00", generatedAt: "2026-01-15T18:00:00.0000000+00:00" });
  const tailSeq = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: tail }]);
  ok("2.10.0: the last part made before its period ended -> they join, in progress, recorded up to when it was made",
    tailSeq.status === "valid" && tailSeq.inProgress === true && tailSeq.recordedUntil === "2026-01-15T17:59:00.000Z", JSON.stringify(tailSeq));
}
{
  // 2.10.0: the checkpoint file the Checkpoints page downloads, checked on its own.
  const enc = new TextEncoder();
  const entry = synthetic.entries.find((e) => e.name.startsWith("checkpoints/"));
  const bundle = JSON.parse(new TextDecoder().decode(entry.data));
  const check = (value) => verifyCheckpointFileBytes(enc.encode(typeof value === "string" ? value : JSON.stringify(value)));
  const good = await check(bundle);
  ok("2.10.0: a checkpoint file -> valid, its key's fingerprint taken from the key itself",
    good.kind === "checkpoint" && good.overall === "valid" && good.publicKeyFingerprint === cpVector.publicKeyFingerprint && good.checkpoint?.eventCount === 6,
    JSON.stringify(good));
  ok("2.10.0: a checkpoint file is told from a record by its name alone",
    isCheckpointName("mandate-checkpoint-1.json") && isCheckpointName("C:\\exports\\CHECKPOINT.JSON") && !isCheckpointName("evidence-pack-2026-01.zip")
      && !isCheckpointName("checkpoint.json.zip") && !isCheckpointName(undefined));
  ok("2.10.0: a checkpoint file saved with a byte-order mark and spaces -> valid", (await check(`\ufeff\n  ${JSON.stringify(bundle)}\n`)).overall === "valid");
  const fromVector = await check({
    schemaVersion: 1, checkpointId: "22222222-3333-4444-8555-666666666666", tenantId: cpVector.tenantId,
    windowStartEventId: cpVector.windowStartEventId, windowEndEventId: cpVector.windowEndEventId,
    windowStartOccurredAt: "2026-01-15T11:00:00+00:00", windowEndOccurredAt: "2026-01-15T11:30:00+00:00", eventCount: cpVector.eventCount,
    merkleRootHex: cpVector.merkleRootHex, signatureHex: cpVector.signatureHex, publicKeyBase64: cpVector.publicKeyBase64,
    publicKeyFingerprint: cpVector.publicKeyFingerprint, createdAt: "2026-01-15T12:00:00+00:00",
  });
  ok("2.10.0: the cross-language checkpoint vector, written as a checkpoint file -> valid", fromVector.overall === "valid", JSON.stringify(fromVector.signature));
  const { merkleRootHex: _root, ...rootless } = bundle;
  for (const [label, value, expect] of [
    ["its record count changed", { ...bundle, eventCount: bundle.eventCount + 1 }, /^signature does not match checkpoint metadata and merkle root$/],
    ["its root changed", { ...bundle, merkleRootHex: "00".repeat(32) }, /^signature does not match checkpoint metadata and merkle root$/],
    ["its last record changed", { ...bundle, windowEndEventId: bundle.windowStartEventId }, /^signature does not match checkpoint metadata and merkle root$/],
    ["the Mandate ID it names changed", { ...bundle, tenantId: SYN_OTHER_WORKSPACE }, /^signature does not match checkpoint metadata and merkle root$/],
    ["a declared fingerprint of another key", { ...bundle, publicKeyFingerprint: "cd".repeat(32) }, /names another key than the one that signed it/],
    ["a field missing", rootless, /^it is not a Mandate checkpoint: its field merkleRootHex is not a string$/],
    ["a list, not one checkpoint", [bundle], /^it is not a Mandate checkpoint: it is not an object$/],
    ["a field a checkpoint does not carry", { ...bundle, note: "added later" }, /^it is not a Mandate checkpoint: it carries note, which a checkpoint does not$/],
  ]) {
    const r = await check(value);
    ok(`2.10.0: a checkpoint file, ${label} -> invalid`, r.overall === "invalid" && expect.test(r.signature.reason) && r.unreadable !== true, JSON.stringify(r.signature));
  }
  const later = await check({ ...bundle, schemaVersion: 3 });
  ok("2.10.0: a checkpoint file of a later format (3 since 2.18.0) -> a different format, not invalid",
    later.overall === "unsupported" && later.format === 3 && /^this checkpoint is format 3; this checker reads formats 1 and 2/.test(later.signature.reason), JSON.stringify(later));
  const junk = await check("{ this is not JSON");
  ok("2.10.0: a file that starts like JSON and is not -> unreadable, not a failed signature", junk.overall === "invalid" && junk.unreadable === true, JSON.stringify(junk));
  ok("2.10.0: a checkpoint file's times are not signed, so changing them leaves it valid (the script and page say so)",
    (await check({ ...bundle, windowStartOccurredAt: "2020-01-01T00:00:00+00:00" })).overall === "valid");
}
{
  // 2.6.0: edge cases found while the public format spec was written.
  const pack = async (tweak) => verifyEvidencePackBytes(writeZip((await buildSyntheticPack(tweak)).entries), inflateRaw);
  const shortKey = await pack({ manifestKey: SHORT_KEY });
  ok("2.6.0: a manifest key of 31 bytes -> invalid with a plain reason, not a runtime without Ed25519",
    shortKey.overall === "invalid" && shortKey.manifest.reason === "public key must be 32 bytes, got 31", JSON.stringify(shortKey.manifest));
  const longer = await pack({ byteLength: (name, n) => (name === "README.txt" ? n + 1 : n) });
  ok("2.6.0: a signed length one more than the file's -> the file fails, though the signature holds",
    longer.overall === "invalid" && longer.manifest.status === "valid"
      && longer.files.find((f) => f.path === "README.txt")?.reason === "length does not match manifest", JSON.stringify(longer.files.filter((f) => f.status !== "valid")));
  const negative = await pack({ byteLength: (name, n) => (name === "README.txt" ? -1 : n) });
  ok("2.6.0: a negative signed length -> invalid", negative.overall === "invalid" && /README\.txt byteLength: -1/.test(negative.manifest.reason ?? ""),
    JSON.stringify(negative.manifest));

  // Two exports of a change-trail entry the records file does not seal: who acted is compared, the salt that seals the
  // name is not (an entry exported while queued has none yet), and an entry that no longer names who acted is a note.
  const later = "2026-01-15T13:00:00.0000000+00:00";
  const salted = await pack({ untied: "salted" });
  const gonePair = checkPackSequence([{ name: "a", result: salted }, { name: "b", result: await pack({ generatedAt: later, untied: "gone" }) }]);
  ok("2.22.0: an entry named in one export and not in the other, sealed in neither -> INVALID, the export that dropped the name named",
    gonePair.status === "invalid" && gonePair.kind === "changed" && gonePair.fields.join() === "who acted"
      && gonePair.detail === "change-trail entry dddddddd-0000-4000-8000-000000000003 (policy.update), listed in mutations/policy-trail.json, names who acted in a "
        + "but not in b; neither export carries the entry's sealed record", JSON.stringify(gonePair));
  // 2.22.0: a later export whose records file starts after the entry's sealed record, as one cut at its size or its
  // register's rows does, with the entry's copy rewritten to name no one, while the earlier export's sealed record names
  // who acted. The later export passes alone; with the earlier one, the name taken out is found.
  const firstEntry = "dddddddd-0000-4000-8000-000000000001";
  const sealedFirst = await pack({});
  const droppedLater = await pack({ generatedAt: later, trailGone: true, partialFromR3: true, chainTruncated: true, manifestTruncated: true });
  ok("2.22.0: a later export cut to start after an entry's sealed record, the entry rewritten to name no one -> valid alone",
    droppedLater.overall === "valid" && !droppedLater.chain.joins.changeLinks.has(firstEntry) && droppedLater.chain.truncated === true,
    JSON.stringify({ o: droppedLater.overall, c: droppedLater.chain?.reason }));
  const droppedPair = checkPackSequence([{ name: "a", result: sealedFirst }, { name: "b", result: droppedLater }]);
  ok("2.22.0: ... and after an export whose sealed record names who acted -> INVALID, the entry and the export that dropped the name named",
    droppedPair.status === "invalid" && droppedPair.kind === "changed" && droppedPair.id === firstEntry && droppedPair.fields.join() === "who acted"
      && droppedPair.detail === `change-trail entry ${firstEntry} (held_decision.denied), listed in mutations/policy-trail.json, names who acted in a but not in b; `
        + "a carries the entry's sealed record, and a's copy of the entry matches it", JSON.stringify(droppedPair));
  const droppedReversed = checkPackSequence([{ name: "b", result: droppedLater }, { name: "a", result: sealedFirst }]);
  ok("2.22.0: ... given in the other order -> the same failure", droppedReversed.status === "invalid" && droppedReversed.kind === "changed"
    && / names who acted in a but not in b; a carries the entry's sealed record, and a's copy of the entry matches it$/.test(droppedReversed.detail ?? ""), JSON.stringify(droppedReversed));
  // 2.22.0: a seal naming no one proves nothing, since an entry can be sealed again after its seal row was removed: a later
  // export sealed that way still fails against an earlier export that names who acted, and one export that carries both
  // seals of one entry fails alone.
  const resealed = await pack({ generatedAt: later, sealedGone: true });
  const firstChange = "bbbbbbbb-0000-4000-8000-000000000001";
  const without = (map) => new Map([...map].filter(([k]) => k !== firstChange));
  const earlierUnsealed = { ...sealedFirst, identity: { ...sealedFirst.identity, generatedAt: "2026-01-15T11:15:10.0000000+00:00" },
    chain: Object.defineProperty({ ...sealedFirst.chain }, "joins", { value: { ...sealedFirst.chain.joins, changeLinks: new Map(),
      byId: without(sealedFirst.chain.joins.byId), atById: without(sealedFirst.chain.joins.atById), live: without(sealedFirst.chain.joins.live) } }) };
  const resealedPair = checkPackSequence([{ name: "a", result: earlierUnsealed }, { name: "b", result: resealed }]);
  ok("2.22.0: an earlier export naming who acted and a later one whose own seal names no one -> INVALID, never accepted",
    resealed.overall === "valid" && resealedPair.status === "invalid" && resealedPair.kind === "changed" && resealedPair.fields.join() === "who acted"
      && resealedPair.detail === `change-trail entry ${firstEntry} (held_decision.denied), listed in mutations/policy-trail.json, names who acted in a but not in b; `
        + "only b carries the entry's sealed record",
    JSON.stringify(resealedPair));
  const twice = await verifyEvidencePackBytes(writeZip(await (async () => {
    const { entries } = await buildSyntheticPack({});
    const chainFile = entries.find((e) => e.name === "chain/links.json");
    const chain = JSON.parse(new TextDecoder().decode(chainFile.data));
    const again = changeRecord("bbbbbbbb-0000-4000-8000-0000000000ee", sha(Buffer.from(chain.links.at(-1).record, "base64")), "2026-01-15T11:50:00.0000000Z",
      firstEntry, new Uint8Array(32));
    chain.links.push({ id: "bbbbbbbb-0000-4000-8000-0000000000ee", occurredAt: "2026-01-15T11:50:00.0000000Z", record: Buffer.from(again).toString("base64") });
    chainFile.data = new TextEncoder().encode(JSON.stringify(chain));
    return entries;
  })()), inflateRaw);
  ok("2.22.0: one export whose records seal an entry twice -> INVALID, though only the records file was read for it",
    twice.overall === "invalid" && /^change-trail entry dddddddd-0000-4000-8000-000000000001 is sealed by two records in chain\/links\.json \(bbbbbbbb-0000-4000-8000-000000000001 and bbbbbbbb-0000-4000-8000-0000000000ee\); Mandate seals an entry once$/.test(twice.chain?.reason ?? ""),
    JSON.stringify(twice.chain?.reason));
  // 2.22.0: an erasure entry is a change-trail entry too: its copy in chain/erasures.json is held to the same rule.
  const erasedEarly = await pack({ generatedAt: later });
  const erasureJoins = { ...erasedEarly.chain.joins, erasureEntries: new Map(erasedEarly.chain.joins.erasureEntries) };
  const erasureEntry = "e1e1e1e1-0000-4000-8000-000000000001";
  const { actorId: _eid, actorDisplay: _ename, actorSalt: _esalt, ...erasureRest } = erasureJoins.erasureEntries.get(erasureEntry).row;
  erasureJoins.erasureEntries.set(erasureEntry, { ...erasureJoins.erasureEntries.get(erasureEntry), row: { ...erasureRest, actorType: "mandate_support" } });
  const erasurePair = checkPackSequence([{ name: "a", result: sealedFirst },
    { name: "b", result: { ...erasedEarly, chain: Object.defineProperty({ ...erasedEarly.chain }, "joins", { value: erasureJoins }) } }]);
  ok("2.22.0: an erasure entry named in one export's chain/erasures.json and not in the other's -> INVALID",
    erasurePair.status === "invalid" && erasurePair.kind === "changed" && erasurePair.id === erasureEntry
      && erasurePair.detail === `change-trail entry ${erasureEntry} (dsr.delete), listed in chain/erasures.json, names who acted in a but not in b; `
        + "neither export carries the entry's sealed record", JSON.stringify(erasurePair));
  // 2.22.0: an export that carries an entry's sealed record but not its copy (its trail and register cut at their rows)
  // still binds the other export's copy, which must match that record; and two exports that seal one entry by two
  // different records disagree.
  const recordOnly = { ...sealedFirst, chain: Object.defineProperty({ ...sealedFirst.chain }, "joins", { value: { ...sealedFirst.chain.joins,
    trail: new Map([...sealedFirst.chain.joins.trail].filter(([k]) => k !== firstEntry)),
    registerChanges: new Map([...sealedFirst.chain.joins.registerChanges].filter(([k]) => k !== firstEntry)) } }) };
  const recordOnlyPair = checkPackSequence([{ name: "a", result: recordOnly }, { name: "b", result: droppedLater }]);
  ok("2.22.0: an export carrying only the sealed record, the other an untied copy rewritten to name no one -> INVALID, the copy against the record",
    droppedLater.chain.joins.untiedSeals.has(firstEntry) && recordOnlyPair.status === "invalid" && recordOnlyPair.fields.join() === "sealed record"
      && recordOnlyPair.detail === `change-trail entry ${firstEntry} (held_decision.denied) in b differs from the entry's sealed record, which a carries`, JSON.stringify(recordOnlyPair));
  const otherRecord = { ...sealedFirst, chain: Object.defineProperty({ ...sealedFirst.chain }, "joins", { value: { ...sealedFirst.chain.joins,
    changeLinks: new Map([...sealedFirst.chain.joins.changeLinks].map(([k, v]) => [k, k === firstEntry ? "bbbbbbbb-0000-4000-8000-0000000000ee" : v])) } }) };
  const twoRecords = checkPackSequence([{ name: "a", result: sealedFirst }, { name: "b", result: otherRecord }]);
  ok("2.22.0: two exports that seal one entry by different records -> INVALID",
    twoRecords.status === "invalid" && twoRecords.fields.join() === "sealed record"
      && twoRecords.detail === `change-trail entry ${firstEntry} is sealed by record ${firstChange} in a and by record bbbbbbbb-0000-4000-8000-0000000000ee in b; Mandate seals an entry once`,
    JSON.stringify(twoRecords));
  // 2.22.0: one export may carry an entry in its trail and the other only in chain/erasures.json; the copies are still
  // compared.
  const crossJoins = { ...droppedLater.chain.joins, trail: new Map([...droppedLater.chain.joins.trail].filter(([k]) => k !== firstEntry)),
    registerChanges: new Map([...droppedLater.chain.joins.registerChanges].filter(([k]) => k !== firstEntry)),
    erasureEntries: new Map([...droppedLater.chain.joins.erasureEntries, [firstEntry, droppedLater.chain.joins.trail.get(firstEntry)]]) };
  const crossPair = checkPackSequence([{ name: "a", result: sealedFirst },
    { name: "b", result: { ...droppedLater, chain: Object.defineProperty({ ...droppedLater.chain }, "joins", { value: crossJoins }) } }]);
  ok("2.22.0: an entry in one export's trail and only in the other's chain/erasures.json, named in one -> INVALID, both lists named",
    crossPair.status === "invalid" && crossPair.kind === "changed" && crossPair.detail === `change-trail entry ${firstEntry} (held_decision.denied), listed in `
      + "a's mutations/policy-trail.json and b's chain/erasures.json, names who acted in a but not in b; a carries the entry's sealed record, and a's copy of the entry matches it",
    JSON.stringify(crossPair));

  // 2.23.0: three exports, the middle one placed so that each joins its neighbour: it starts between the other two, and
  // neither carries the first entry nor its sealed record. Under 2.22.0 the first and the last were never compared.
  const middle = await pack({ windowFrom: "2026-01-15T05:00:00+00:00", windowTo: "2026-01-15T08:00:00+00:00", generatedAt: "2026-01-15T08:30:00.0000000+00:00",
    dropFirstEntry: true, partialFromR3: true, chainTruncated: true, manifestTruncated: true });
  const fromSix = { windowFrom: "2026-01-15T06:00:00+00:00", generatedAt: later, partialFromR3: true, chainTruncated: true, manifestTruncated: true };
  const lastGone = await pack({ ...fromSix, trailGone: true });
  const lastDropped = await pack({ ...fromSix, dropFirstEntry: true });
  const lastHonest = await pack(fromSix);
  ok("2.23.0: the middle export and the three last exports are each valid alone",
    [middle, lastGone, lastDropped, lastHonest].every((r) => r.overall === "valid"), JSON.stringify([middle, lastGone, lastDropped, lastHonest].map((r) => r.chain?.reason ?? r.overall)));
  const trio = (last) => checkPackSequence([{ name: "a", result: sealedFirst }, { name: "m", result: middle }, { name: "z", result: last }]);
  ok("2.23.0: ... and each joins its neighbour, as 2.22.0 compared them",
    [lastGone, lastDropped, lastHonest].every((last) => checkPackSequence([{ name: "a", result: sealedFirst }, { name: "m", result: middle }]).status === "valid"
      && checkPackSequence([{ name: "m", result: middle }, { name: "z", result: last }]).status === "valid"));
  const goneTrio = trio(lastGone);
  ok("2.23.0: three exports, the last naming no one on an entry the first seals, the middle starting between them -> INVALID, the first and the last compared",
    goneTrio.status === "invalid" && goneTrio.kind === "changed" && goneTrio.id === firstEntry && goneTrio.fields.join() === "who acted"
      && goneTrio.reason === `a and z: change-trail entry ${firstEntry} (held_decision.denied), listed in mutations/policy-trail.json, names who acted in a but not in z; `
        + "a carries the entry's sealed record, and a's copy of the entry matches it", JSON.stringify(goneTrio));
  const droppedTrio = trio(lastDropped);
  ok("2.23.0: three exports, the last missing an entry of its period the first holds -> INVALID",
    droppedTrio.status === "invalid" && droppedTrio.kind === "missing" && droppedTrio.id === firstEntry
      && droppedTrio.detail === `change-trail entry ${firstEntry} (held_decision.denied) is in a but missing from z's mutations/policy-trail.json, inside the period z covers`,
    JSON.stringify(droppedTrio));
  const reversedTrio = checkPackSequence([{ name: "z", result: lastGone }, { name: "a", result: sealedFirst }, { name: "m", result: middle }]);
  ok("2.23.0: ... given in another order -> the same failure", reversedTrio.status === "invalid" && reversedTrio.reason === goneTrio.reason, JSON.stringify(reversedTrio));
  const honestTrio = trio(lastHonest);
  ok("2.23.0: three genuine exports, the middle starting between the other two -> joins", honestTrio.status === "valid" && honestTrio.packs === 3, JSON.stringify(honestTrio));

  // 2.23.0: exports whose times do not overlap are compared on the change-trail entries they share, as an erasure entry
  // sits in every export whose records it erased. Each is cut here to its entries alone, so only that comparison can fail.
  const entriesOnly = (r, windowFrom, windowTo, joins) => ({ ...r, inProgress: false, truncated: false,
    identity: { ...r.identity, windowFrom, windowTo, generatedAt: windowTo.replace("+00:00", ".0000000+00:00") },
    chain: Object.defineProperty({ ...r.chain }, "joins", { value: { ...r.chain.joins, first: null, last: null, byId: new Map(), atById: new Map(), live: new Map(),
      register: { rows: new Map(), fields: new Set() }, ...joins } }) });
  const none = { trail: new Map(), registerChanges: new Map(), erasureEntries: new Map(), finalDecisionEntries: new Map(), changeLinks: new Map(),
    sealHashes: new Map(), untiedSeals: new Map() };
  const day = (h) => `2026-01-1${5 + Math.floor(h / 24)}T${String(h % 24).padStart(2, "0")}:00:00+00:00`;
  const firstDay = entriesOnly(sealedFirst, day(0), day(12), { trail: new Map(), registerChanges: new Map(), finalDecisionEntries: new Map(),
    changeLinks: new Map(), sealHashes: new Map(), untiedSeals: new Map() });
  const between = entriesOnly(sealedFirst, day(12), day(24), none);
  const { actorId: _lid, actorDisplay: _lname, actorSalt: _lsalt, ...erasureNoOne } = sealedFirst.chain.joins.erasureEntries.get(erasureEntry).row;
  const farErasure = entriesOnly(sealedFirst, day(24), day(36), { ...none,
    erasureEntries: new Map([[erasureEntry, { ...sealedFirst.chain.joins.erasureEntries.get(erasureEntry), row: { ...erasureNoOne, actorType: "mandate_support" } }]]) });
  const extents = [firstDay, between, farErasure].map((r) => checker.packExtent?.(r));
  ok("2.23.0: three exports whose periods follow one another -> no two beyond neighbours overlap", checker.farPairs?.(extents)?.length === 0, JSON.stringify(extents, (k, v) => (typeof v === "bigint" ? String(v) : v)));
  const sharedErasure = checkPackSequence([{ name: "a", result: firstDay }, { name: "m", result: between }, { name: "z", result: farErasure }]);
  ok("2.23.0: an erasure entry named in the first export and not in the third, the periods apart, the second between -> INVALID",
    sharedErasure.status === "invalid" && sharedErasure.kind === "changed" && sharedErasure.id === erasureEntry
      && sharedErasure.reason === `a and z: change-trail entry ${erasureEntry} (dsr.delete), listed in chain/erasures.json, names who acted in a but not in z; `
        + "neither export carries the entry's sealed record", JSON.stringify(sharedErasure));
  const untiedEarly = entriesOnly(droppedLater, day(0), day(12), { ...none, trail: new Map([[firstEntry, droppedLater.chain.joins.trail.get(firstEntry)]]),
    untiedSeals: new Map([[firstEntry, droppedLater.chain.joins.untiedSeals.get(firstEntry)]]) });
  const recordFar = entriesOnly(sealedFirst, day(24), day(36), { ...none, changeLinks: new Map([[firstEntry, firstChange]]),
    sealHashes: new Map([[firstEntry, sealedFirst.chain.joins.sealHashes.get(firstEntry)]]) });
  const sealedLater = checkPackSequence([{ name: "a", result: untiedEarly }, { name: "m", result: between }, { name: "z", result: recordFar }]);
  ok("2.23.0: a copy that does not match the sealed record a later export carries, the periods apart -> INVALID, once the record is read",
    sealedLater.status === "invalid" && sealedLater.fields.join() === "sealed record"
      && sealedLater.reason === `a and z: change-trail entry ${firstEntry} (held_decision.denied) in a differs from the entry's sealed record, which z carries`,
    JSON.stringify(sealedLater));
  const twiceFar = checkPackSequence([{ name: "a", result: entriesOnly(sealedFirst, day(0), day(12), { ...none, changeLinks: new Map([[firstEntry, firstChange]]),
    sealHashes: new Map([[firstEntry, sealedFirst.chain.joins.sealHashes.get(firstEntry)]]) }) }, { name: "m", result: between },
  { name: "z", result: entriesOnly(sealedFirst, day(24), day(36), { ...none, changeLinks: new Map([[firstEntry, "bbbbbbbb-0000-4000-8000-0000000000ee"]]),
    sealHashes: new Map([[firstEntry, sealedFirst.chain.joins.sealHashes.get(firstEntry)]]) }) }]);
  ok("2.23.0: two exports far apart that seal one entry by different records -> INVALID",
    twiceFar.status === "invalid" && twiceFar.reason === `a and z: change-trail entry ${firstEntry} is sealed by record ${firstChange} in a and by record `
      + "bbbbbbbb-0000-4000-8000-0000000000ee in z; Mandate seals an entry once", JSON.stringify(twiceFar));
  const sameFar = checkPackSequence([{ name: "a", result: firstDay }, { name: "m", result: between },
    { name: "z", result: entriesOnly(sealedFirst, day(24), day(36), { ...none, erasureEntries: sealedFirst.chain.joins.erasureEntries }) }]);
  ok("2.23.0: the same erasure entry in two exports far apart -> joins", sameFar.status === "valid", JSON.stringify(sameFar));
  // 2.23.0: two exports whose times are apart are still compared when they hold one record or decision, since an erased
  // record's time is not signed, nor is that of a decision whose record is outside its export's records file.
  const r2 = "aaaaaaaa-0000-4000-8000-000000000002";
  const r4 = "aaaaaaaa-0000-4000-8000-000000000004";
  const { recordSha256: _r2sha, ...r2Untied } = sealedFirst.chain.joins.register.rows.get(r2);
  const movedRow = entriesOnly(sealedFirst, day(24), day(36), { ...none,
    register: { rows: new Map([[r2, { ...r2Untied, action: "allow", occurredAt: "2026-01-16T06:00:00+00:00" }]]), fields: sealedFirst.chain.joins.register.fields } });
  const movedPair = checkPackSequence([{ name: "a", result: sealedFirst }, { name: "m", result: between }, { name: "z", result: movedRow }]);
  ok("2.23.0: a decision whose row in a far later export, outside its records file, gives another outcome and time -> INVALID",
    movedPair.status === "invalid" && movedPair.kind === "changed" && movedPair.id === r2 && movedPair.subject === "decision"
      && ["outcome", "time"].every((f) => movedPair.fields.includes(f)) && movedPair.reason.startsWith(`a and z: decision ${r2} reads differently in z than in a: its `),
    JSON.stringify(movedPair));
  const erasedFar = entriesOnly(sealedFirst, day(24), day(36), { ...none, byId: new Map([[r4, sealedFirst.chain.joins.byId.get(r4)]]), atById: new Map([[r4, null]]) });
  const erasedFirst = checkPackSequence([{ name: "a", result: sealedFirst }, { name: "m", result: between },
    { name: "z", result: { ...erasedFar, identity: { ...erasedFar.identity, generatedAt: "2026-01-15T01:00:00.0000000+00:00" } } }]);
  ok("2.23.0: a record erased in a far export that says it was made first, its time unreadable there -> INVALID",
    erasedFirst.status === "invalid" && erasedFirst.kind === "erased-first" && erasedFirst.id === r4
      && erasedFirst.detail === `decision ${r4} is erased in z but whole in a, though z says it was made first`, JSON.stringify(erasedFirst));
  const queuedPair = checkPackSequence([{ name: "a", result: await pack({ untied: "named" }) }, { name: "b", result: await pack({ generatedAt: later, untied: "salted" }) }]);
  ok("2.6.0: an entry exported while queued, then with the salt of its seal -> joins", queuedPair.status === "valid", JSON.stringify(queuedPair));
  const otherPair = checkPackSequence([{ name: "a", result: salted }, { name: "b", result: await pack({ generatedAt: later, untied: "other" }) }]);
  ok("2.6.0: an entry that names someone else in the later export -> still fails on who acted",
    otherPair.status === "invalid" && otherPair.kind === "changed" && otherPair.fields.join() === "who acted", JSON.stringify(otherPair));

  // 2.6.0: a checkpoint's own declared fingerprint must name the key that signed it, as the manifest's must since 2.5.0.
  const cpOtherKey = await pack({ checkpointFingerprint: "00".repeat(32) });
  ok("2.6.0: a checkpoint that names another key's fingerprint -> refused, though its signature holds",
    cpOtherKey.overall === "invalid" && cpOtherKey.manifest.status === "valid"
      && cpOtherKey.checkpoints[0]?.result.reason === "its publicKeyFingerprint names another key than the one that signed it", JSON.stringify(cpOtherKey.checkpoints));
  const cpUpper = await pack({ checkpointFingerprint: cpVector.publicKeyFingerprint.toUpperCase() });
  ok("2.6.0: a checkpoint that names its key's fingerprint in capitals -> valid", cpUpper.overall === "valid", JSON.stringify(cpUpper.checkpoints));

  // 2.6.0: two exports compare their Mandate ID as the 16 bytes the signature binds, as one export does inside itself.
  const following = { windowFrom: "2026-01-15T12:00:00+00:00", windowTo: "2026-01-16T00:00:00+00:00" };
  const upper = await pack({ ...following, upperTenant: true });
  ok("2.6.0: an export whose Mandate ID is written in capitals -> valid alone", upper.overall === "valid", JSON.stringify(upper.manifest));
  const casePair = checkPackSequence([{ name: "a", result: baseline }, { name: "b", result: upper }]);
  ok("2.6.0: two exports of one Mandate ID, written in capitals in one -> the sequence joins", casePair.status === "valid", JSON.stringify(casePair));
  const elsewhere = await pack(following);
  const otherWorkspace = checkPackSequence([{ name: "a", result: baseline },
    { name: "b", result: { ...elsewhere, identity: { ...elsewhere.identity, tenantId: SYN_OTHER_WORKSPACE } } }]);
  ok("2.6.0: two exports of different Mandate IDs -> still refused, said by Mandate ID",
    otherWorkspace.status === "invalid" && otherWorkspace.kind === "mandate-id" && /they have different Mandate IDs/.test(otherWorkspace.reason), JSON.stringify(otherWorkspace));
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
  // The cap itself must admit a maximal legitimate pack: 1,000 checkpoint files + 32 headroom.
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
  ok("2.5.0: fingerprint spoof -> the manifest is refused for naming another key", r.overall === "invalid" && /names another key/.test(r.manifest.reason ?? ""));
  ok("fingerprint spoof -> reported fingerprint is the key hash, not the declared lie",
    r.publicKeyFingerprint === realFp && r.publicKeyFingerprint !== "0".repeat(64));
  ok("computed manifest fingerprint matches the published vector fingerprint", realFp === epVector.publicKeyFingerprint);
  ok("checkpoint fingerprint is computed from its own key",
    r.checkpoints[0]?.publicKeyFingerprint === cpVector.publicKeyFingerprint);
}
{
  // 2.5.0: the manifest's unsigned members must agree with what is signed.
  const edit = (change) => synthetic.entries.map((e) =>
    e.name === "manifest.json" ? { name: e.name, data: new TextEncoder().encode(JSON.stringify(change({ ...synthetic.manifest }))) } : e);
  const extra = await verifyEvidencePackBytes(writeZip(edit((m) => ({ ...m, note: "added later" }))), inflateRaw);
  ok("2.5.0: a manifest member the signature does not cover -> refused, the member named",
    extra.overall === "invalid" && /carries note, which its signature does not cover/.test(extra.manifest.reason ?? ""), extra.manifest.reason);
  const emptied = await verifyEvidencePackBytes(writeZip(edit((m) => ({ ...m, checkpointIds: [] }))), inflateRaw);
  ok("2.5.0: checkpointIds emptied -> refused", emptied.overall === "invalid" && /the manifest's list of checkpoints does not match the checkpoint files/.test(emptied.manifest.reason ?? ""), emptied.manifest.reason);
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

// ── 4. FINAL DECISIONS (2.16.0): assessments/final-decisions.json, each batch tied to its sealed entry ───
console.log("\nFINAL DECISIONS (2.16.0, synthetic pack, test-vector key)");
{
  const packOf = async (fd) => writeZip((await buildSyntheticPack({ finalDecisions: await buildFinalDecisions(fd) })).entries);
  const verify = async (fd) => verifyEvidencePackBytes(await packOf(fd), inflateRaw);
  const counted = (r, expected) => {
    const got = r.chain?.finalDecisions;
    return got != null && Object.entries({ erased: 0, notChecked: 0, truncated: false, notCompared: "", ...expected }).every(([k, v]) => got[k] === v);
  };
  const good = await verify({});
  ok("2.16.0: a pack carrying final decisions -> valid, 3 decisions in 2 batches matched, none erased or left unchecked",
    good.overall === "valid" && counted(good, { batches: 2, decisions: 3 }), JSON.stringify(good.chain ?? good.manifest));
  ok("2.16.0: each batch's change-trail entry ties to its sealed record like any other entry",
    good.chain?.changesTied === (baseline.chain?.changesTied ?? 0) + 2 && good.chain?.changesNotTied === baseline.chain?.changesNotTied, JSON.stringify(good.chain));
  ok("2.16.0: a pack without the file verifies as before, and says nothing of final decisions",
    baseline.overall === "valid" && baseline.chain?.finalDecisions === null);
  for (const [label, fd, expect] of [
    ["a decision's document changed after sealing", { docFlip: true },
      /^assessments\/final-decisions\.json: batch fdfdfdfd-0000-4000-8000-000000000001: decision [0-9a-f]{64} differs from its sealed digest$/],
    ["a decision's salt changed", { saltFlip: true }, /: decision [0-9a-f]{64} differs from its sealed digest$/],
    ["a decision's digest changed", { shaFlip: true }, /carries decision [0-9a-f]{64}, which its sealed record does not list$/],
    ["a decision left out", { drop: true }, /leaves out decision [0-9a-f]{64}, which its sealed record lists$/],
    ["a decision its batch does not list added", { extra: true }, /carries decision [0-9a-f]{64}, which its sealed record does not list$/],
    ["the batch record changed after sealing", { recordFlip: true },
      /^assessments\/final-decisions\.json: batch fdfdfdfd-0000-4000-8000-000000000001 differs from its sealed record$/],
    ["the batch's change record sealing another record hash", { sealFlip: true },
      /^change-trail entry dddddddd-0000-4000-8000-000000000101 \(final_decisions\.recorded\) in assessments\/final-decisions\.json differs from its sealed record$/],
    ["a document naming another batch", { docBatch: true }, /: decision [0-9a-f]{64} names another batch$/],
    ["a document naming another AI system", { docSystem: true }, /: decision [0-9a-f]{64} names another AI system$/],
    ["a document naming another Mandate ID", { docTenant: true },
      /: decision [0-9a-f]{64} names Mandate ID 99999999-2222-4222-8222-222222222222, not this export's Mandate ID/],
    ["the batch record naming another Mandate ID", { recordTenant: true },
      /batch fdfdfdfd-0000-4000-8000-000000000001: its record names Mandate ID 99999999-2222-4222-8222-222222222222, not this export's Mandate ID/],
  ]) {
    const r = await verify(fd);
    ok(`2.16.0: ${label} -> invalid`, r.overall === "invalid" && r.manifest.status === "valid" && expect.test(r.chain?.reason ?? ""), r.chain?.reason);
  }
  const erased = await verify({ erase: true });
  ok("2.16.0: an erased decision -> valid, counted as erased and never as a failure",
    erased.overall === "valid" && counted(erased, { batches: 2, decisions: 2, erased: 1 }), JSON.stringify(erased.chain?.finalDecisions ?? erased.chain));
  const unsealed = await verify({ unsealed: true });
  ok("2.16.0: a batch whose change record is not in chain/links.json -> counted not checked, never a pass",
    unsealed.overall === "valid" && counted(unsealed, { batches: 1, decisions: 2, notChecked: 1 })
    && unsealed.chain?.changesNotTied === (baseline.chain?.changesNotTied ?? 0) + 1,
    JSON.stringify(unsealed.chain?.finalDecisions ?? unsealed.chain));
  const later = await verify({ schemaVersion: 2 });
  ok("2.16.0: a file of version 2 -> valid, not compared, and said why",
    later.overall === "valid" && counted(later, { batches: 0, decisions: 0,
      notCompared: "assessments/final-decisions.json is version 2; this checker reads version 1" }), JSON.stringify(later.chain?.finalDecisions ?? later.chain));
  const line = checker.finalDecisionsLine;
  ok("2.16.0: the line says what matched, what was erased and what was not checked, in one sentence",
    typeof line === "function"
      && line(good.chain.finalDecisions)?.label === "3 final decisions in 2 batches match their sealed records"
      && line({ batches: 1, decisions: 1, erased: 1, notChecked: 1, truncated: false, notCompared: "" })?.label
        === "1 final decision in 1 batch matches its sealed record, 1 erased, 1 batch not checked (its sealed record is outside this export)"
      && line({ batches: 0, decisions: 0, erased: 0, notChecked: 2, truncated: false, notCompared: "" })?.tag === "[ -- ]"
      && line({ batches: 0, decisions: 0, erased: 0, notChecked: 0, truncated: false, notCompared: "" })?.label === "no final decisions were received in this period"
      && line(later.chain.finalDecisions)?.tag === "[ -- ]" && line(null) === null);
  const dir = mkdtempSync(join(tmpdir(), "mandate-verify-final-"));
  try {
    const save = async (name, fd) => {
      const path = join(dir, name);
      writeFileSync(path, await packOf(fd));
      return path;
    };
    const cli = (...args) => {
      const r = spawnSync(process.execPath, [join(repoRoot, "mandate-verify.mjs"), ...args], { encoding: "utf8" });
      return { code: r.status, out: `${r.stdout}${r.stderr}`, std: r.stdout };
    };
    const fp = epVector.publicKeyFingerprint;
    const printed = cli(await save("partly.zip", { erase: true, unsealed: true, truncated: true }), "--expect-fingerprint", fp);
    ok("2.16.0: script, one line for the file, and the export called partial when the file is cut short",
      printed.code === 0 && /^ {9}\[ ok \] 1 final decision in 1 batch matches its sealed record, 1 erased, 1 batch not checked \(its sealed record is outside this export\); this export holds the earliest batches of its period only$/m.test(printed.out)
        && /^Complete\s+: no, this record holds part of its period \(partial: final decisions\)$/m.test(printed.out), printed.out);
    const cutPath = join(dir, "cut-findings.zip");
    writeFileSync(cutPath, writeZip((await buildSyntheticPack({ documents: { after: (f) => {
      f.findings.assessments = [];
      f.findings.truncated = true;
    } } })).entries));
    const cutFindings = cli(cutPath, "--expect-fingerprint", fp);
    ok("2.17.0: script, an export whose findings file was cut at its size limit is called partial, the assessments named",
      cutFindings.code === 0 && /^Complete\s+: no, this record holds part of its period \(partial: assessments\)$/m.test(cutFindings.out),
      cutFindings.out);
    const asJson = cli(await save("good.zip", {}), "--json", "--expect-fingerprint", fp);
    const doc = (() => { try { return JSON.parse(asJson.std); } catch { return null; } })();
    ok("2.16.0: script --json, the result carries finalDecisions",
      asJson.code === 0 && JSON.stringify(doc?.chain?.finalDecisions) === JSON.stringify({ batches: 2, decisions: 3, erased: 0, notChecked: 0, truncated: false, notCompared: "" }),
      asJson.out.slice(0, 400));
    const changed = cli(await save("changed.zip", { docFlip: true }), "--expect-fingerprint", fp);
    ok("2.16.0: script, a decision changed after sealing -> exit 1, named",
      changed.code === 1 && /^Records: \[FAIL\] assessments\/final-decisions\.json: batch fdfdfdfd-0000-4000-8000-000000000001: decision [0-9a-f]{64} differs from its sealed digest$/m.test(changed.out),
      changed.out.slice(-600));
    const withoutPath = join(dir, "without.zip");
    writeFileSync(withoutPath, writeZip(synthetic.entries));
    const plain = cli(withoutPath, "--expect-fingerprint", fp);
    ok("2.16.0: script, a pack without the file prints no final-decisions line", plain.code === 0 && !/final decision/.test(plain.out), plain.out);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── 5. TAMPER, access record: the same matrix over the other pack a customer receives ─────
console.log("\nTAMPER matrix (synthetic DSR access pack, test-vector key)");

async function buildSyntheticDsrPack(tweak = {}) {
  const enc = new TextEncoder();
  const files = new Map([
    ["README.txt", enc.encode("Synthetic DSR access pack for the verifier test suite.\n")],
    ["audit/events.json", enc.encode('[{"id":"e1","policyDecision":"allow"}]')],
    ["usage/events.json", enc.encode("[]")],
  ]);
  const contents = [];
  for (const [name, data] of files) {
    contents.push({ filename: name, sha256Hex: await sha256Hex(data), byteLength: tweak.byteLength?.(name, data.length) ?? data.length });
  }
  const manifest = {
    manifestVersion: tweak.manifestVersion ?? dsrVector.manifestVersion,
    tenantId: dsrVector.tenantId,
    subjectHashHex: dsrVector.subjectHashHex,
    generatedAt: "2026-01-15T12:00:00.0000000+00:00",
    windowFrom: tweak.windowFrom ?? "2026-01-01T00:00:00+00:00",
    windowTo: tweak.windowTo ?? null,
    truncated: false,
    unscannableRows: 0,
    degradedRows: 0,
    partiallyScannableRows: 0,
    opaqueRegions: 0,
    opaqueBytes: 0,
    contents,
    signatureHex: "",
    publicKeyBase64: tweak.manifestKey ?? dsrPublicKeyBase64,
    publicKeyFingerprint: tweak.fingerprint ?? dsrVector.publicKeyFingerprint,
  };
  const payload = signedLengths(buildDsrAccessSignedPayload(
    manifest.tenantId, manifest.subjectHashHex, manifest.manifestVersion, manifest.generatedAt,
    manifest.windowFrom, manifest.windowTo, manifest.truncated, manifest.unscannableRows, manifest.degradedRows,
    manifest.partiallyScannableRows, manifest.opaqueRegions, manifest.opaqueBytes,
    contents.map((c) => ({ ...c, byteLength: Math.max(0, c.byteLength) }))), contents);
  manifest.signatureHex = bytesToHex(signWithVectorKey(payload));
  const entries = [...files].map(([name, data]) => ({ name, data }));
  entries.push({ name: "manifest.json", data: enc.encode(JSON.stringify({ ...manifest, ...tweak.extra })) });
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
  // 2.6.0: the access record, the same edge cases as the signed record.
  const dsr = async (tweak) => verifyDsrAccessPackBytes(writeZip((await buildSyntheticDsrPack(tweak)).entries), inflateRaw);
  const shortKey = await dsr({ manifestKey: SHORT_KEY });
  ok("2.6.0: an access record whose key is 31 bytes -> invalid with a plain reason, not a runtime without Ed25519",
    shortKey.overall === "invalid" && shortKey.manifest.reason === "public key must be 32 bytes, got 31", JSON.stringify(shortKey.manifest));
  const longer = await dsr({ byteLength: (name, n) => (name === "README.txt" ? n + 1 : n) });
  ok("2.6.0: an access record whose signed length is one more than the file's -> the file fails, though the signature holds",
    longer.overall === "invalid" && longer.manifest.status === "valid"
      && longer.files.find((f) => f.path === "README.txt")?.reason === "length does not match manifest", JSON.stringify(longer.files));
  const negative = await dsr({ byteLength: (name, n) => (name === "README.txt" ? -1 : n) });
  ok("2.6.0: an access record with a negative signed length -> invalid",
    negative.overall === "invalid" && /README\.txt byteLength: -1/.test(negative.manifest.reason ?? ""), JSON.stringify(negative.manifest));

  // 2.6.0: the access record follows the signed record's manifest rules.
  const extra = await dsr({ extra: { note: "added later" } });
  ok("2.6.0: an access record manifest member the signature does not cover -> refused, the member named",
    extra.overall === "invalid" && extra.manifest.reason === "manifest.json carries note, which its signature does not cover", JSON.stringify(extra.manifest));
  const otherKey = await dsr({ fingerprint: "00".repeat(32) });
  ok("2.6.0: an access record that names another key's fingerprint -> refused",
    otherKey.overall === "invalid" && /publicKeyFingerprint names another key/.test(otherKey.manifest.reason ?? ""), JSON.stringify(otherKey.manifest));
  const upperKey = await dsr({ fingerprint: dsrVector.publicKeyFingerprint.toUpperCase() });
  ok("2.6.0: an access record that names its key's fingerprint in capitals -> valid", upperKey.overall === "valid", JSON.stringify(upperKey.manifest));
  const format4 = await dsr({ manifestVersion: 4 });
  ok("2.6.0: an access record of format 4, signed as such -> a different format, not valid",
    format4.overall === "unsupported" && format4.format === 4 && /this access record is format 4; this checker reads format 3/.test(format4.manifest.reason ?? ""),
    JSON.stringify(format4.manifest));
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

// ── 6. OUTSIDE TIMESTAMPS (2.18.0) ───────────────────────────────────────────────────────────
// Each root the checker ships is the certificate it says it is; the real token DigiCert's public service gave for the
// shared test checkpoint verifies; and a test authority built here, with its own root, signs tokens with any time and
// any flaw, so every rule is tried on bytes this suite made and the checker did not.
console.log("\nTIMESTAMP checks (outside timestamps on checkpoints, 2.18.0)");
{
  const shipped = checker.TIMESTAMP_ROOTS ?? [];
  ok("the checker ships at least one timestamp root, each a certificate it can read",
    shipped.length > 0 && shipped.every((r) => { try { checker.timestampRootFromDer(Buffer.from(r.derBase64, "base64")); return true; } catch { return false; } }),
    JSON.stringify(shipped.map((r) => r.name)));
  ok("each shipped root's recorded SHA-256 is its own",
    shipped.every((r) => createHash("sha256").update(Buffer.from(r.derBase64, "base64")).digest("hex") === r.sha256));

  const vecBundle = {
    schemaVersion: 2, checkpointId: "11111111-2222-4333-8444-555555555555", tenantId: cpVector.tenantId,
    windowStartEventId: cpVector.windowStartEventId, windowEndEventId: cpVector.windowEndEventId,
    windowStartOccurredAt: "2026-11-12T15:00:00+00:00", windowEndOccurredAt: "2026-11-12T16:00:00+00:00", eventCount: cpVector.eventCount,
    merkleRootHex: cpVector.merkleRootHex, signatureHex: cpVector.signatureHex, publicKeyBase64: cpVector.publicKeyBase64,
    publicKeyFingerprint: cpVector.publicKeyFingerprint, createdAt: "2026-11-12T16:50:00+00:00", timestampTokenBase64: tsVector.tokenBase64,
  };
  ok("the imprint is the payload, then the signature, then the key, as the vector pins",
    bytesToHex(checker.checkpointTimestampImprint(vecBundle)) === tsVector.imprintedHex);
  const real = await checker.checkpointTimestamp(vecBundle);
  ok("DigiCert's real token over the test checkpoint -> valid, at its time, naming its authority (its cross-signed root copy unused)",
    real.status === "valid" && real.time === "2026-11-12T16:57:11.000Z" && real.authority === tsVector.authority, JSON.stringify(real));
  const realToken = Buffer.from(tsVector.tokenBase64, "base64");
  const flipped = (at, bit = 1) => { const b = Buffer.from(realToken); b[at] ^= bit; return b.toString("base64"); };
  const timeAt = realToken.indexOf(Buffer.from("20261112165711Z"));
  for (const [label, token, expect] of [
    ["its stamped time rewritten", flipped(timeAt + 3, 2), /changed after it was signed/],
    ["its signature changed", flipped(realToken.length - 5), /signature does not verify/],
    ["another checkpoint's bytes", null, /over other bytes/],
    ["bytes after its end", Buffer.concat([realToken, Buffer.from([0])]).toString("base64"), /bytes after its end/],
    ["cut short", realToken.subarray(0, 900).toString("base64"), /does not read as a timestamp/],
  ]) {
    const b = token === null ? { ...vecBundle, eventCount: vecBundle.eventCount } : { ...vecBundle, timestampTokenBase64: token };
    const r = token === null
      ? await checker.verifyTimestampToken(realToken, new Uint8Array(215), checker.TIMESTAMP_ROOTS.map((x) => checker.timestampRootFromDer(Buffer.from(x.derBase64, "base64"))))
      : await checker.checkpointTimestamp(b);
    ok(`the real token, ${label} -> invalid, and no time given`, r.status === "invalid" && expect.test(r.reason) && r.time === undefined, JSON.stringify(r));
  }
  // Every one-byte change anywhere in the token: the check answers, never throws, and never gives a time for a token it did
  // not verify. A change in a certificate the chain never uses (the cross-signed root copy) may leave it valid.
  let fuzzed = 0;
  let fuzzBad = null;
  for (let i = 0; i < realToken.length; i += 7) {
    const r = await checker.checkpointTimestamp({ ...vecBundle, timestampTokenBase64: flipped(i, 0x10) }).catch((err) => ({ status: "threw", reason: err.message }));
    fuzzed++;
    if (!["valid", "invalid", "untrusted", "unsupported"].includes(r.status) || (r.status !== "valid" && r.time !== undefined)) fuzzBad ??= `byte ${i}: ${JSON.stringify(r)}`;
  }
  ok(`${fuzzed} one-byte changes across the real token -> every one answered, none thrown, no unverified time given`, fuzzBad === null, fuzzBad ?? "");

  // A test authority: a root, an intermediate and a timestamping certificate, RSA 2048, signed here with node's crypto.
  const dl = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : n < 65536 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255]);
  const tlv = (tag, ...parts) => { const body = Buffer.concat(parts.map((p) => Buffer.from(p))); return Buffer.concat([Buffer.from([tag, ...dl(body.length)]), body]); };
  const seqD = (...p) => tlv(0x30, ...p);
  const setD = (...p) => tlv(0x31, ...[...p].sort(Buffer.compare));
  const oidD = (s) => { const n = s.split(".").map(Number); const out = [40 * n[0] + n[1]]; for (const v of n.slice(2)) { const st = [v & 0x7f]; let x = Math.floor(v / 128); while (x) { st.unshift((x & 0x7f) | 0x80); x = Math.floor(x / 128); } out.push(...st); } return tlv(0x06, out); };
  const intD = (n) => { let h = BigInt(n).toString(16); if (h.length % 2) h = `0${h}`; if (parseInt(h.slice(0, 2), 16) & 0x80) h = `00${h}`; return tlv(0x02, Buffer.from(h, "hex")); };
  const nullD = tlv(0x05);
  const timeD = (tag, d) => { const iso = new Date(d).toISOString().replace(/[-:T]/g, "").replace(/\.\d+Z$/, "Z"); return tlv(tag, Buffer.from(tag === 0x17 ? iso.slice(2) : iso)); };
  const nameD = (cn) => seqD(setD(seqD(oidD("2.5.4.3"), tlv(0x0c, Buffer.from(cn)))));
  const sha256Rsa = seqD(oidD("1.2.840.113549.1.1.11"), nullD);
  const sha256Alg = seqD(oidD("2.16.840.1.101.3.4.2.1"), nullD);
  const keyPair = (bits = 2048) => generateKeyPairSync("rsa", { modulusLength: bits });
  const spkiOf = (kp) => kp.publicKey.export({ type: "spki", format: "der" });
  const TRUE = tlv(0x01, [0xff]);
  function certD({ serial, issuer, subject, from, to, kp, signer, ca, pathLen, eku = null, ekuCritical = true, ekuExtra = false }) {
    const exts = [];
    if (ca) exts.push(seqD(oidD("2.5.29.19"), TRUE, tlv(0x04, seqD(TRUE, ...(pathLen === undefined ? [] : [intD(pathLen)])))));
    if (eku) exts.push(seqD(oidD("2.5.29.37"), ...(ekuCritical ? [TRUE] : []), tlv(0x04, seqD(oidD(eku), ...(ekuExtra ? [oidD("1.3.6.1.5.5.7.3.3")] : [])))));
    const tbs = seqD(tlv(0xa0, intD(2)), intD(serial), sha256Rsa, nameD(issuer), seqD(timeD(0x17, from), timeD(0x17, to)), nameD(subject), spkiOf(kp),
      ...(exts.length ? [tlv(0xa3, seqD(...exts))] : []));
    return { der: seqD(tbs, sha256Rsa, tlv(0x03, Buffer.concat([Buffer.from([0]), signNode("sha256", tbs, signer.privateKey)]))), issuer: nameD(issuer), serial, kp };
  }
  const rootKp = keyPair();
  const midKp = keyPair();
  const leafKp = keyPair();
  const Y = 365 * 24 * 3600 * 1000;
  const T0 = Date.parse("2026-01-15T00:00:00Z");
  const rootC = certD({ serial: 1, issuer: "Test Root", subject: "Test Root", from: T0 - 2 * Y, to: T0 + 5 * Y, kp: rootKp, signer: rootKp, ca: true });
  const midC = certD({ serial: 2, issuer: "Test Root", subject: "Test CA", from: T0 - Y, to: T0 + 3 * Y, kp: midKp, signer: rootKp, ca: true, pathLen: 0 });
  const leaf = (o = {}) => certD({ serial: 3, issuer: "Test CA", subject: "Test TSA", from: T0 - Y, to: T0 + Y, kp: leafKp, signer: midKp,
    eku: "1.3.6.1.5.5.7.3.8", ...o });
  const goodLeaf = leaf();
  // An RFC 3161 token over `imprinted`, at `at`, signed by `signer` (with `chain` carried), signing-certificate v2.
  function tokenD(imprinted, at, { signer = goodLeaf, chain = [midC], accuracySeconds, signWith = leafKp, digestOf = null } = {}) {
    const tst = seqD(intD(1), oidD("1.3.6.1.4.1.99999.1"), seqD(sha256Alg, tlv(0x04, createHash("sha256").update(imprinted).digest())), intD(at),
      timeD(0x18, at), ...(accuracySeconds === undefined ? [] : [seqD(intD(accuracySeconds))]));
    const attrs = setD(
      seqD(oidD("1.2.840.113549.1.9.3"), setD(oidD("1.2.840.113549.1.9.16.1.4"))),
      seqD(oidD("1.2.840.113549.1.9.4"), setD(tlv(0x04, createHash("sha256").update(digestOf ?? tst).digest()))),
      seqD(oidD("1.2.840.113549.1.9.16.2.47"), setD(seqD(seqD(seqD(tlv(0x04, createHash("sha256").update(signer.der).digest())))))));
    const sig = signNode("sha256", attrs, signWith.privateKey);
    const stored = Buffer.from(attrs);
    stored[0] = 0xa0;
    const si = seqD(intD(1), seqD(signer.issuer, intD(signer.serial)), sha256Alg, stored, sha256Rsa, tlv(0x04, sig));
    const sd = seqD(intD(3), setD(sha256Alg), seqD(oidD("1.2.840.113549.1.9.16.1.4"), tlv(0xa0, tlv(0x04, tst))), tlv(0xa0, signer.der, ...chain.map((c) => c.der)),
      setD(si));
    return seqD(oidD("1.2.840.113549.1.7.2"), tlv(0xa0, sd)).toString("base64");
  }
  const testRoots = [rootC.der];
  const stampedAt = Date.parse("2026-01-15T12:05:00Z");
  const one = (token) => checker.checkpointTimestamp({ ...vecBundle, timestampTokenBase64: token }, testRoots);
  const imprint = checker.checkpointTimestampImprint(vecBundle);
  const good = await one(tokenD(imprint, stampedAt));
  ok("a test authority's token, its root named -> valid, at its time", good.status === "valid" && good.time === "2026-01-15T12:05:00.000Z", JSON.stringify(good));
  const unnamed = await checker.checkpointTimestamp({ ...vecBundle, timestampTokenBase64: tokenD(imprint, stampedAt) });
  ok("the same token, its root not named -> untrusted: reported, never valid or invalid, and no time given",
    unnamed.status === "untrusted" && unnamed.time === undefined, JSON.stringify(unnamed));
  const otherKp = keyPair();
  for (const [label, token, status, expect] of [
    ["over another checkpoint", tokenD(new Uint8Array(215), stampedAt), "invalid", /over other bytes/],
    ["stamped after its certificate expired", tokenD(imprint, T0 + 2 * Y), "invalid", /was not valid at the stamped time/],
    ["stamped before its certificate began", tokenD(imprint, T0 - 2 * Y + 1000), "invalid", /was not valid at the stamped time/],
    ["its certificate not marked for timestamping", tokenD(imprint, stampedAt, { signer: leaf({ eku: null }) }), "invalid", /does not say it is for timestamping/],
    ["its timestamping purpose not critical", tokenD(imprint, stampedAt, { signer: leaf({ ekuCritical: false }) }), "invalid", /only use/],
    ["its certificate for code signing too", tokenD(imprint, stampedAt, { signer: leaf({ ekuExtra: true }) }), "invalid", /more than timestamping/],
    ["its certificate not issued by the CA it names", tokenD(imprint, stampedAt, { signer: leaf({ signer: otherKp }) }), "invalid", /does not verify under its issuer/],
    ["issued by a certificate that is not a CA", tokenD(imprint, stampedAt, { chain: [certD({ serial: 2, issuer: "Test Root", subject: "Test CA",
      from: T0 - Y, to: T0 + 3 * Y, kp: midKp, signer: rootKp, ca: false })] }), "invalid", /without being a certificate authority/],
    ["signed by another key than its certificate's", tokenD(imprint, stampedAt, { signWith: otherKp }), "invalid", /signature does not verify/],
    ["its content not the one signed", tokenD(imprint, stampedAt, { digestOf: Buffer.from("other") }), "invalid", /changed after it was signed/],
    ["vouching for its time only to within two minutes", tokenD(imprint, stampedAt, { accuracySeconds: 120 }), "invalid", /more than a minute/],
    ["its intermediate missing", tokenD(imprint, stampedAt, { chain: [] }), "untrusted", /no root this checker holds/],
    ["an RSA key of 1024 bits", tokenD(imprint, stampedAt, { signer: certD({ serial: 3, issuer: "Test CA", subject: "Test TSA", from: T0 - Y, to: T0 + Y,
      kp: keyPair(1024), signer: midKp, eku: "1.3.6.1.5.5.7.3.8" }) }), "unsupported", /shorter than 2048 bits|signature does not verify/],
  ]) {
    const r = await one(token);
    ok(`a test authority's token ${label} -> ${status}`, r.status === status && expect.test(r.reason ?? "") && r.time === undefined, JSON.stringify(r));
  }

  // Exports: two checkpoints splitting the window, each stamped as the test asks, the export re-signed.
  const at = (iso) => Date.parse(iso);
  const pack = async (stamp, options = {}) => verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ split: true, stamp })).entries), inflateRaw,
    { timestampRoots: testRoots, ...options });
  const stampAt = (times) => (c, i) => (times[i] === null ? null : tokenD(checker.checkpointTimestampImprint(c), at(times[i])));
  const inOrder = await pack(stampAt(["2026-01-15T12:05:00Z", "2026-01-15T12:05:02Z"]));
  ok("an export whose two checkpoints were stamped in order -> valid, both stamped, the records proven sealed by the second's time",
    inOrder.overall === "valid" && inOrder.timestamps?.stamped === 2 && inOrder.timestamps.problem === null
    && inOrder.timestamps.provenThrough?.stampedMs === at("2026-01-15T12:05:02Z") && inOrder.checkpoints.every((c) => c.timestamp?.status === "valid"),
    JSON.stringify(inOrder.timestamps ?? inOrder.chain));
  const skew = await pack(stampAt(["2026-01-15T12:05:02Z", "2026-01-15T12:05:00Z"]));
  ok("two seconds out of order, as two authorities' clocks may be -> valid", skew.overall === "valid" && skew.timestamps.problem === null, JSON.stringify(skew.timestamps));
  const replaced = await pack(stampAt(["2026-01-16T09:00:00Z", "2026-01-15T12:05:00Z"]));
  ok("the earlier checkpoint stamped the next day, after the later one -> INVALID, naming both: what a replacement made with a stolen key looks like",
    replaced.overall === "invalid" && /before checkpoint 11111111-2222-4333-8444-555555555555, which seals earlier records/.test(replaced.timestamps.problem ?? ""),
    JSON.stringify(replaced.timestamps));
  const stripped = await pack(stampAt([null, "2026-01-15T12:05:00Z"]));
  ok("the earlier checkpoint's token removed, the later one's kept -> INVALID: Mandate never stamps out of order",
    stripped.overall === "invalid" && /has no outside timestamp, though checkpoint 11111111-2222-4333-8444-666666666666/.test(stripped.timestamps.problem ?? ""),
    JSON.stringify(stripped.timestamps));
  const foreign = await pack((c, i) => (i === 0 ? tokenD(checker.checkpointTimestampImprint(c), at("2026-01-15T12:05:00Z")) : stampAt([null, "2026-01-15T12:05:01Z"])(c, i)),
    { timestampRoots: [] });
  ok("an earlier token from an authority this checker cannot check, before a later one it can -> not a pass: the later one is untrusted too here, so the order is unknown",
    foreign.overall === "valid" && foreign.timestamps.untrusted.length === 2, JSON.stringify(foreign.timestamps));
  const mixed = await pack((c, i) => (i === 0
    ? tokenD(checker.checkpointTimestampImprint(c), at("2026-01-15T12:05:00Z"), { chain: [] })
    : tokenD(checker.checkpointTimestampImprint(c), at("2026-01-15T12:05:02Z"))));
  ok("an earlier token this checker cannot check, before a later one it can -> not INVALID but not verified: an operator may have changed authorities",
    mixed.overall === "valid" && mixed.timestamps.problem === null
      && /cannot check, before checkpoint 11111111-2222-4333-8444-666666666666, which has one it can$/.test(mixed.timestamps.notVerified ?? ""),
    JSON.stringify(mixed.timestamps));
  const tail = await pack(stampAt(["2026-01-15T12:05:00Z", null]));
  ok("the newest checkpoint not stamped yet -> valid, and named as having none yet",
    tail.overall === "valid" && tail.timestamps.absent.map((a) => a.checkpointId).join() === "11111111-2222-4333-8444-666666666666", JSON.stringify(tail.timestamps));
  const late = await pack(stampAt(["2026-01-17T12:00:00Z", "2026-01-17T12:00:01Z"]));
  ok("stamped two days after its records -> valid, and named as late: it shows only that the checkpoint existed by then",
    late.overall === "valid" && late.timestamps.late.length === 2 && late.timestamps.late[0].hours >= 48, JSON.stringify(late.timestamps));
  const v1 = await verifyEvidencePackBytes(writeZip((await buildSyntheticPack({ split: true })).entries), inflateRaw);
  ok("an export of format 1 checkpoints -> valid, none stamped, nothing invalid", v1.overall === "valid" && v1.timestamps.absent.length === 2 && v1.timestamps.problem === null,
    JSON.stringify(v1.timestamps));
  const bad = await pack((c, i) => (i === 0 ? tokenD(new Uint8Array(215), at("2026-01-15T12:05:00Z")) : null));
  ok("a token over other bytes inside an export -> the checkpoint and the export INVALID",
    bad.overall === "invalid" && /its outside timestamp: its timestamp is over other bytes/.test(bad.checkpoints[0].result.reason ?? ""), JSON.stringify(bad.checkpoints[0]));

  // --require-timestamps: every checkpoint stamped and checkable, within a day of its records; the newest two hours may wait.
  const strict = (r) => r.timestamps?.notVerified;
  ok("--require-timestamps, both stamped in order -> nothing to report", strict(await pack(stampAt(["2026-01-15T12:05:00Z", "2026-01-15T12:05:02Z"]), { requireTimestamps: true })) === null);
  ok("--require-timestamps, the newest not stamped yet and its records within two hours of the export -> nothing to report",
    strict(await pack(stampAt(["2026-01-15T12:05:00Z", null]), { requireTimestamps: true })) === null);
  ok("--require-timestamps, a token this checker cannot check -> not verified",
    /cannot check/.test(strict(await pack(stampAt(["2026-01-15T12:05:00Z", "2026-01-15T12:05:02Z"]), { requireTimestamps: true, timestampRoots: [] })) ?? ""));
  ok("--require-timestamps, stamped two days late -> not verified",
    /more than a day/.test(strict(await pack(stampAt(["2026-01-17T12:00:00Z", "2026-01-17T12:00:01Z"]), { requireTimestamps: true })) ?? ""));

  // The script: the option names a root, and the run says what each checkpoint's token proves.
  const cli = (...args) => {
    const r = spawnSync(process.execPath, [join(repoRoot, "mandate-verify.mjs"), ...args], { encoding: "utf8" });
    return { code: r.status, out: `${r.stdout}${r.stderr}`, std: r.stdout };
  };
  const tsDir = mkdtempSync(join(tmpdir(), "mandate-verify-ts-"));
  try {
    const rootFile = join(tsDir, "test-root.pem");
    writeFileSync(rootFile, `-----BEGIN CERTIFICATE-----\n${rootC.der.toString("base64").replace(/.{64}/g, "$&\n")}\n-----END CERTIFICATE-----\n`);
    const zip = join(tsDir, "mandate-stamped.zip");
    writeFileSync(zip, writeZip((await buildSyntheticPack({ split: true, stamp: stampAt(["2026-01-15T12:05:00Z", "2026-01-15T12:05:02Z"]) })).entries));
    const run = cli(zip, "--expect-fingerprint", epVector.publicKeyFingerprint, "--timestamp-root", rootFile);
    ok("script --timestamp-root, an export stamped in order -> exit 0, the checkpoints stamped by the test authority, the records proven sealed",
      run.code === 0 && /\[ ok \] 2 checkpoint\(s\) carry an outside timestamp, from Test TSA: the records up to /.test(run.out), run.out.slice(-700));
    const noRoot = cli(zip, "--expect-fingerprint", epVector.publicKeyFingerprint, "--require-timestamps");
    ok("script --require-timestamps without the root -> exit 4, NOT VERIFIED and why", noRoot.code === 4
      && /^RESULT: NOT VERIFIED \(outside timestamps: 2 checkpoint\(s\) carry a timestamp this checker cannot check\)/m.test(noRoot.out), noRoot.out.slice(-400));
    const mixedZip = join(tsDir, "mandate-mixed.zip");
    writeFileSync(mixedZip, writeZip((await buildSyntheticPack({ split: true, stamp: (c, i) => (i === 0
      ? tokenD(checker.checkpointTimestampImprint(c), at("2026-01-15T12:05:00Z"), { chain: [] })
      : tokenD(checker.checkpointTimestampImprint(c), at("2026-01-15T12:05:02Z"))) })).entries));
    const mixedRun = cli(mixedZip, "--expect-fingerprint", epVector.publicKeyFingerprint, "--timestamp-root", rootFile);
    ok("script, a timestamp it cannot check before one it can -> exit 4, NOT VERIFIED and why, not INVALID",
      mixedRun.code === 4 && /^RESULT: NOT VERIFIED \(outside timestamps: checkpoint .* carries a timestamp this checker cannot check/m.test(mixedRun.out), mixedRun.out.slice(-500));
    const cpFileTs = join(tsDir, "mandate-checkpoint-stamped.json");
    writeFileSync(cpFileTs, JSON.stringify(vecBundle));
    const cpRun = cli(cpFileTs, "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("script, the test checkpoint with DigiCert's real token -> exit 0 and the outside timestamp line",
      cpRun.code === 0 && /^Outside timestamp   : ok, stamped .* by DigiCert, Inc\., DigiCert SHA256 RSA4096 Timestamp Responder 2026 1$/m.test(cpRun.out), cpRun.out.slice(-500));
    writeFileSync(cpFileTs, JSON.stringify({ ...vecBundle, timestampTokenBase64: flipped(timeAt + 3, 2) }));
    const cpBad = cli(cpFileTs, "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("script, the same checkpoint with its token's time rewritten -> exit 1", cpBad.code === 1 && /^RESULT: INVALID \(checkpoint\)$/m.test(cpBad.out), cpBad.out.slice(-300));
    const { timestampTokenBase64: _drop, ...noField } = vecBundle;
    writeFileSync(cpFileTs, JSON.stringify(noField));
    const cpNoField = cli(cpFileTs, "--expect-fingerprint", cpVector.publicKeyFingerprint);
    ok("script, a format 2 checkpoint without its timestamp field -> exit 1, not a checkpoint", cpNoField.code === 1 && /timestampTokenBase64 is missing/.test(cpNoField.out),
      cpNoField.out.slice(-300));
  } finally {
    rmSync(tsDir, { recursive: true, force: true });
  }
}

// ── 7. PACKS: committed sample packs verify end to end ───────────────────────────────────────
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
    ok(`2.10.0: ${name} was made after its period ended (not in progress)`, r.inProgress === false);
    const sd = r.chain?.sealedDocuments;
    ok(`2.17.0: ${name} carries an assessment, a review and an artifact version, each matching its sealed record`,
      ["assessments", "reviews", "artifacts"].every((k) => sd?.[k]?.matched >= 1 && sd[k].notChecked === 0), JSON.stringify(sd));
    ok(`2.17.0: ${name}: any measure value or impact assessment version it carries matches its sealed record`,
      ["measureValues", "impactAssessments"].every((k) => sd?.[k] === null || (sd?.[k]?.notChecked === 0 && !sd[k].notCompared)), JSON.stringify(sd));
    // The README says the samples' checkpoints carry outside timestamps; each one must verify, in order, against the
    // roots the checker ships.
    ok(`2.18.0: ${name}: every checkpoint carries an outside timestamp the checker verifies, in order`,
      r.timestamps?.problem === null && r.timestamps.stamped === r.checkpoints.length && r.timestamps.absent.length === 0
        && r.timestamps.untrusted.length === 0, JSON.stringify(r.timestamps));
    ok(`${name} is signed by the key the README names`, r.publicKeyFingerprint === readmeFingerprint,
      `pack=${r.publicKeyFingerprint} readme=${readmeFingerprint}`);
  } catch (err) {
    ok(`${name} verifies`, false, err.message);
  }
}

console.log(`\n${checks} checks, ${failures} failure(s)`);
process.exitCode = failures === 0 ? 0 : 1;
