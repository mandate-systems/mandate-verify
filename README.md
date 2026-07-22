# mandate-verify

Offline verifier for [Mandate](https://mandateco.ca) evidence packs. One file, zero dependencies, Node.js 20 or newer. It proves that a pack you hold matches the manifest its signer signed, without contacting Mandate or anyone else.

An evidence pack is a ZIP of JSON files exported from a Mandate installation: an AI-traffic decision register, the policy that produced it, signed audit checkpoints, and a `manifest.json` that lists every file's SHA-256 and carries one Ed25519 signature over the whole list plus the pack's identity and export window. The format is specified in [docs/evidence-pack-format.md](docs/evidence-pack-format.md).

## Run it

Two ways, same file:

```
# git
git clone https://github.com/mandate-systems/mandate-verify
node mandate-verify/mandate-verify.mjs pack.zip

# direct download (the canonical artifact; this repository mirrors it)
curl -O https://mandateco.ca/downloads/mandate-verify.mjs
node mandate-verify.mjs pack.zip
```

No packages are installed or downloaded at run time; the only imports are Node built-ins (`fs`, `zlib`, `crypto`, `url`). CI enforces that with a grep.

## Quick start with a sample pack

Three sample packs of fictional data, exported through the real product path, live in [`samples/`](samples/). They are signed by a dedicated sample key. Verify one and pin the expected key, so the trust step is exercised rather than skipped:

```
node mandate-verify.mjs samples/mandate-sample-evidence-pack-legal.zip \
  --expect-fingerprint 9a914bf1310855175c7d868ad434987075412f627b2e8c18e5634e0bfcba045f
```

The same fingerprint is published at https://mandateco.ca/verify.html, which also verifies packs in the browser using this file's verifier core.

## What a PASS means

- Every file in the pack matches the SHA-256 the signed manifest lists for it, and the file sets match in both directions: nothing added, nothing removed.
- The manifest's Ed25519 signature verifies over a canonical payload binding the tenant id, the manifest version, the generation time, the export window bounds, two completeness flags, and every filename, hash, and byte length.
- Every embedded audit checkpoint's signature verifies over its own canonical payload (tenant id, window event ids, event count, Merkle root).
- The fingerprint printed is the SHA-256 of the public key that actually verified. The manifest also carries a self-declared fingerprint field; the verifier deliberately ignores it, because a forger controls that field but cannot make a chosen key verify without its private key.

## What a PASS does not mean

- **It does not prove the key belongs to Mandate or to any particular installation.** A signature binds a pack to a key. Whether you trust that key is your step: compare the printed fingerprint to one you obtained out of band (for the samples, the published one above; for a real installation, the fingerprint recorded at onboarding).
- **It does not prove the recorded events are true**, only that the record has not changed since it was signed.
- **It does not prove completeness beyond what the manifest claims.** The signed payload binds the export window and two truncation flags, so a pack cannot be quietly re-labelled as covering a different period or as complete when it was capped. What never entered the mediated path was never in scope.

## Exit codes and JSON output

```
0  pack is valid (and matches --expect-fingerprint when given)
1  pack is invalid, or the fingerprint does not match
2  usage error, unreadable file, or not a readable ZIP archive
3  this runtime lacks WebCrypto Ed25519 support (use Node 20 or newer)
```

`--json` prints the full result object for scripting. `--version` prints the tool version and the two supported payload domain tags. `--expect-fingerprint <hex>` applies to the manifest key and every embedded checkpoint key.

## How it works

Read the file; it is meant to be read top to bottom. In outline:

1. A hand-rolled ZIP reader with hardened limits: 50 MB total, 1,032 entries, no zip64, no encryption, stored and deflate entries only, duplicate names rejected. CRC-32 is deliberately not checked; content integrity comes from the signed SHA-256 list, which CRC would only weaken into false confidence.
2. Per-file SHA-256 recomputation against `manifest.json`, then set-equality both directions.
3. Reconstruction of the manifest's canonical signed payload (domain tag `mandate.evidence-pack.manifest-sig.v2`) and Ed25519 verification via WebCrypto.
4. The same for each checkpoint file (domain tag `mandate.audit.checkpoint-sig.v1`, a fixed 119-byte payload).

Byte layouts, the manifest schema, and the trust model are in [docs/evidence-pack-format.md](docs/evidence-pack-format.md). The layouts are pinned by the cross-language test vectors in [`test/vectors/`](test/vectors/), the same vectors asserted by the product's C# and TypeScript test suites; the signing seed in the vectors is all zeros and test-only.

## Test suite

```
node test/check.mjs             # offline: vectors, tamper matrix, sample packs
MIRROR=1 node test/check.mjs    # also byte-compare this repository against the live site
```

The tamper matrix covers: content flip, injected file, metadata flip, missing file, duplicate entry, entry-count bomb, declared-size bomb, non-ZIP input, fingerprint spoofing, malformed manifest entries, and a legitimate high-compression pack that must still pass.

## Provenance

The canonical artifact is the file served at `https://mandateco.ca/downloads/mandate-verify.mjs`. This repository mirrors it, and the weekly `mirror` CI job byte-compares the two (plus the verifier core embedded in verify.html). You can run the same comparison yourself with `MIRROR=1`, or just `diff` the downloads. Releases carry a `SHA256SUMS` file; the same hash is published on verify.html so the site and this repository attest each other.

## Relationship to the product repository

Verifier changes originate in Mandate's product repository, where the payload builders are tested against the C# implementations that produce real packs, and flow here with the site deploy. Issues and documentation fixes are welcome in this repository; for changes to verification logic, open an issue first so the change lands through that path rather than diverging the mirror.

## Security

See [SECURITY.md](SECURITY.md). Report to security@mandateco.ca; never attach a real customer pack, reproduce with the samples.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
