# mandate-verify

Offline checker for the signed records that [Mandate](https://mandateco.ca) exports. One file, zero dependencies, Node.js 20 or newer. It proves that a record you hold is the one its signer signed, and that the records inside it still link in order, without contacting Mandate or anyone else.

A signed record (the format calls it an evidence pack) is a ZIP of JSON files exported from a Mandate workspace: the decision register, the policy text behind each decision, the change trail, the underlying records as their sealed bytes, signed checkpoints over those records, a printed report, and a `manifest.json` that lists every file's SHA-256 under one Ed25519 signature. The same script checks access records, the export Mandate makes to answer one person's privacy request. Both formats are specified in [docs/evidence-pack-format.md](docs/evidence-pack-format.md).

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

Three sample records of fictional firms, exported through the real product path, live in [`samples/`](samples/). They are signed with a key used only for them. Check one and name that key, so the trust step runs instead of being skipped:

```
node mandate-verify.mjs samples/mandate-sample-record-accounting.zip \
  --expect-fingerprint 9a914bf1310855175c7d868ad434987075412f627b2e8c18e5634e0bfcba045f
```

The same fingerprint is published at https://mandateco.ca/verify.html, which runs this file's checks in the browser.

## What VALID means

- Every file matches the SHA-256 and the byte length the signed manifest lists for it, and the file sets match both ways: nothing added, nothing removed. The manifest itself, in a signed record or an access record, carries nothing its signature does not cover.
- The manifest's Ed25519 signature verifies over a canonical payload that binds the workspace id, the format version, when the export was made, the period it covers, three completeness flags, and every filename, hash and byte length.
- Every checkpoint's signature verifies, and every checkpoint root is recomputed from the records in `chain/links.json`. Each record names the hash of the one before it, so an edited or reordered record, or one taken out from between two others, breaks the chain. A record erased at a person's request or under the retention setting keeps its place by its hash and names the entry that records its erasure.
- Each decision in the register matches its sealed record field by field, the person included. Each change-trail entry matches its sealed record, each policy version's text matches its hash, and the printed report names the summary it was drawn from. When the register is whole, the summary counts must match the decisions.
- A rule's list of names (a client list, for example) is sealed in the policy text as a seal and a count. When the export includes the names, they must reproduce the seal; when it leaves them out, the script says so.
- Every key that signed the record, its checkpoints included, is one you named with `--expect-fingerprint`. The fingerprint printed is the SHA-256 of the key that actually verified, and a manifest or checkpoint that declares a different fingerprint is refused.

## What VALID does not mean

- **It does not prove the recorded events are true**, only that the record has not changed since it was signed.
- **It does not prove who holds the key.** A signature binds a record to a key, and which keys you trust is your step: the sample key above, or the fingerprint in your agreement for a real workspace. Without `--expect-fingerprint` the script never prints VALID; it prints NOT VERIFIED and exits 4.
- **One export alone cannot catch the key holder.** Whoever holds the signing key can leave out the last record of a period and sign again, and that export passes on its own. Check it together with an earlier export of the same period and the script names any record or change-trail entry that went missing or reads differently.
- **Complete means what the signed manifest says.** A capped export says so in its signed flags and the script reports it as partial. Traffic that never passed through Mandate was never in scope.

## Several records

Give the script several files, or a folder (every `.zip` in it, in name order), and it checks each one and then checks them together: the parts of one long export, or an earlier and a later export. They must name one workspace, be signed by one key or by keys you named, leave no gap between their periods, and each continue from the one before. No record or change-trail entry that one holds inside the time the other covers may be missing from the other or read differently there. Each export is held to its period up to a minute before it says it was made, or only to the span its records hold when it says it is partial, and what that leaves out is named, as is any decision erased between the two exports. A folder is checked one neighbour at a time, so a long export needs no more memory than two parts.

## Exit codes and JSON output

```
0  valid, and every key is one you named with --expect-fingerprint
1  invalid, or signed by a key you did not name
2  usage error, unreadable file, or not a readable ZIP archive
3  a different format than this script reads, or no WebCrypto Ed25519 in this runtime (use Node 20 or newer)
4  not verified: unchanged since signing, but no fingerprint was named, so the key was not checked
```

`--json` prints the full result object for scripting. `--version` prints the tool version and the three payload domain tags it reads. `--expect-fingerprint` takes 64 hex characters, plain or in pairs separated by colons or spaces, in either case; give it more than once after a key change.

## How it works

Read the file; it is meant to be read top to bottom. In outline:

1. A hand-rolled ZIP reader with hardened limits: 50 MB total, 1,032 entries, no zip64, no encryption, no comments, stored and deflate entries only, duplicate names rejected, every entry's CRC-32 checked, and no bytes outside the listed files. An archive passes only if every common unzip tool would read the same files the script checked.
2. Per-file SHA-256 recomputation against `manifest.json`, then set equality both ways.
3. The manifest's canonical signed payload rebuilt and verified with WebCrypto Ed25519: domain tag `mandate.evidence-pack.manifest-sig.v3` for a signed record, `mandate.dsr.access-manifest-sig.v4` for an access record.
4. The same for each checkpoint (domain tag `mandate.audit.checkpoint-sig.v1`, a fixed 119-byte payload), then each checkpoint's root recomputed from the records it covers.
5. The walk over the records and the readable files tied to them, as listed under What VALID means.
6. With several records, the comparison between them.

Byte layouts, the manifest schemas and the trust model are in [docs/evidence-pack-format.md](docs/evidence-pack-format.md). The payload layouts are pinned by the cross-language test vectors in [`test/vectors/`](test/vectors/), the same vectors the product's own test suites assert; the signing seed in the vectors is all zeros and test-only.

## Test suite

```
node test/check.mjs             # offline: vectors, tamper matrix, record walk, two-export comparison, sample records
MIRROR=1 node test/check.mjs    # also byte-compare this repository against the live site
```

The tamper matrix covers content flip, injected file, metadata flips on the completeness flags, missing file, duplicate entry, entry-count bomb, declared-size bomb, non-ZIP input, fingerprint spoofing in the manifest and in a checkpoint, unsigned manifest members, malformed manifest entries, a key that is not 32 bytes, a signed length that is not the file's, and a legitimate high-compression pack that must still pass. The record walk covers edited, swapped and foreign records, a register row, person, change-trail entry, erasure, policy text, sealed list or printed report that no longer matches, and a records file that claims to be partial under a manifest that says complete. The comparison covers a record left out of a re-signed later export, in either order, decisions erased between exports, a key change, a change-trail entry that no longer names who acted or was sealed between the exports, and a workspace id written in capitals. The suite also runs the script itself the way an auditor would and checks its exit codes and result lines. The same file matrix runs over a synthetic access record, with its manifest rules and a format the script does not read.

## Provenance

The canonical artifact is the file served at `https://mandateco.ca/downloads/mandate-verify.mjs`. This repository mirrors it, and the weekly `mirror` CI job byte-compares the two (plus the verifier core embedded in verify.html). You can run the same comparison yourself with `MIRROR=1`, or just `diff` the downloads. Releases carry a `SHA256SUMS` file; the same hash is published on verify.html, so the site and this repository attest each other.

## Relationship to the product repository

Verifier changes originate in Mandate's product repository, where the payload builders are tested against the implementation that produces real records, and flow here with the site deploy. Issues and documentation fixes are welcome in this repository; for changes to verification logic, open an issue first so the change lands through that path rather than diverging the mirror.

## Security

See [SECURITY.md](SECURITY.md). Report to security@mandateco.ca; never attach a real customer record, reproduce with the samples.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
