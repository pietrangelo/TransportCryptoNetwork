# Security policy

TCN is a remote access system: a vulnerability can open SSH on an entire fleet of
servers. Reports are welcome and are handled with priority.

> **English:** please report vulnerabilities privately through GitHub's
> [private vulnerability reporting](https://github.com/pietrangelo/TransportCryptoNetwork/security/advisories/new).
> Do not open a public issue. Reports in English or Italian are both fine.

## How to report

Use **GitHub's private reporting**:
[Security → Report a vulnerability](https://github.com/pietrangelo/TransportCryptoNetwork/security/advisories/new).

Do **not** open a public issue, a PR or a discussion for a security problem.

A good report contains:

- the version (tag or commit) and the binary involved (`zt-agent`, `zt-relay`, `zt-client`);
- the attack model: who the attacker is (network, compromised relay, authorized client,
  local user) and what they gain;
- the steps to reproduce or a minimal proof of concept;
- the estimated impact.

Do not include private keys, tokens or real production data.

## What to expect

| Stage | Indicative time |
| --- | --- |
| Acknowledgement of receipt | within 3 working days |
| Initial assessment (validity, severity) | within 10 working days |
| Fix for critical issues | as soon as possible, normally within 30 days |

The fix is published with a GitHub Security Advisory (with a CVE when appropriate), and the
reporter is credited, if they wish. We ask you not to disclose the problem until the
fix is available or until 90 days have passed since the report.

## Supported versions

The project is pre-1.0: only the latest release and the `main` branch receive fixes.

## Scope

In scope are, among other things:

- bypasses of the mutual authentication or of the authorization policies of the relay and the agent;
- a relay that manages to read, alter or redirect the end-to-end traffic;
- crashes, panics, memory or CPU exhaustion caused by remote input;
- secrets or SSH payloads that end up in the logs;
- weaknesses in the release process (binaries, SLSA attestations, GitHub Actions workflows).

The threat model and the defences are described in `docs/PROTOCOL.md` and in the reviews in
`docs/adversary/`.

## Verifying a released binary

Every release archive has an SLSA provenance attestation signed by GitHub Actions, and
`SHA256SUMS` carries two detached signatures by the offline release keys (PQ-REL):
`SHA256SUMS.slhdsa.sig` (SLH-DSA-SHA2-128s, post-quantum, hash-based) and
`SHA256SUMS.ed25519.sig` (Ed25519). **Both are required**: checking only one of them strips
the post-quantum (or the classical) half. Verify them with OpenSSL 3.5 or later, never with a
`zt-*` binary you just downloaded (a binary that verifies itself proves nothing).

**Trust the keys through their fingerprints only.** The public keys are in
`packaging/release/keys/` at the release tag, but keys, fingerprints and signatures that come
from the same download or the same tag prove nothing: whoever controls one can supply a
consistent set. Take the fingerprints below out of band **once** (from this file on `main`, or
the signed release announcement), keep them, and check every release against them. The same
lines are built into `packaging/release/tcn-release.sh` and listed in
`packaging/release/release-keys.fingerprints`; the release tests check that the three agree.

Pinned release keys (SHA-256 of the DER public key, as `tcn-release.sh fingerprint` prints it):

```text
(none yet: no release key has been generated; every verification fails until the first
signed release pins its keys here)
```

With the pinned script (it refuses any key that is not pinned, a malformed `SHA256SUMS`, and,
with `--tag`, an archive of another tag):

```bash
set -e
OPENSSL=openssl packaging/release/tcn-release.sh verify --tag vX.Y.Z keys/ SHA256SUMS
grep ' tcn-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz$' SHA256SUMS | sha256sum -c -
gh attestation verify tcn-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz \
  --repo pietrangelo/TransportCryptoNetwork
```

With OpenSSL alone: first check that the fingerprint of each key matches a pinned line, then
the signatures. The commands are chained with `&&`, so a failure stops them: never read an
"OK" further down as a verdict on an earlier step.

```bash
ctx="TCN release SHA256SUMS v1"
echo "slh-dsa-sha2-128s sha256:$(openssl pkey -pubin -in release-slhdsa.pub.pem -outform DER | sha256sum | cut -d' ' -f1)" &&
echo "ed25519 sha256:$(openssl pkey -pubin -in release-ed25519.pub.pem -outform DER | sha256sum | cut -d' ' -f1)" &&
openssl pkeyutl -verify -rawin -pubin -inkey release-slhdsa.pub.pem \
  -in SHA256SUMS -sigfile SHA256SUMS.slhdsa.sig -pkeyopt "context-string:$ctx" &&
openssl pkeyutl -verify -rawin -pubin -inkey release-ed25519.pub.pem \
  -in SHA256SUMS -sigfile SHA256SUMS.ed25519.sig \
  -pkeyopt instance:Ed25519ctx -pkeyopt "context-string:$ctx" &&
grep ' tcn-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz$' SHA256SUMS | sha256sum -c - &&
gh attestation verify tcn-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz \
  --repo pietrangelo/TransportCryptoNetwork &&
echo "release verified"
```

Compare the two printed fingerprint lines with the pinned ones by eye (or with `grep -xF`
against your saved copy) before trusting the `Signature Verified Successfully` lines. The plain
OpenSSL commands do not check the format of `SHA256SUMS`; the script does, and `sign` refuses to
sign a file it would refuse.

**What the offline signatures add, and what they do not.** They add post-quantum authenticity
(SLH-DSA) and independence from GitHub's signing infrastructure: a release whose `SHA256SUMS`
the maintainer did not sign is not published. They add nothing to *build* integrity beyond the
SLSA attestation: the maintainer signs the checksums of what CI built and cannot check that CI
built the tagged source (the build is not reproducible). Do not read them as more than that.

