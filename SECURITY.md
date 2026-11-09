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
`zt-*` binary you just downloaded (a binary that verifies itself proves nothing). The public
keys are in `packaging/release/keys/` at the release tag; check their fingerprints against the
ones published below before trusting them.

```bash
ctx="TCN release SHA256SUMS v1"
openssl pkeyutl -verify -rawin -pubin -inkey release-slhdsa.pub.pem \
  -in SHA256SUMS -sigfile SHA256SUMS.slhdsa.sig -pkeyopt "context-string:$ctx"
openssl pkeyutl -verify -rawin -pubin -inkey release-ed25519.pub.pem \
  -in SHA256SUMS -sigfile SHA256SUMS.ed25519.sig \
  -pkeyopt instance:Ed25519ctx -pkeyopt "context-string:$ctx"
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify tcn-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz \
  --repo pietrangelo/TransportCryptoNetwork
```

`packaging/release/tcn-release.sh verify packaging/release/keys SHA256SUMS` does the same and
also refuses a malformed `SHA256SUMS`. Fingerprints of the release keys (SHA-256 of the DER
public key, `tcn-release.sh fingerprint`): published here with the first signed release.
