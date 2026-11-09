# TCN post-quantum migration: analysis and design input

Status: analysis only (step 0 of a future phase). Nothing in the repository was modified.
Date: 2026-11-09. Repository state: `main` at `dfb3b8b` (Phases 1–6 merged).

> **Note on project instructions.** `CLAUDE.md` says the project instructions, skills and
> agents are encrypted (`.claude/private/CLAUDE.md`, `.claude/agents/adversary.md` start with
> the `SEC\x02` header) and decrypted by a SessionStart hook. They were **not** visible in
> this session, so this analysis follows only the public documents (`docs/METHODOLOGY.md`,
> `docs/PROTOCOL.md`, `docs/OPERATIONS.md`, `docs/phase6-plan.md`, `docs/adversary/*`) and the
> code. If the private instructions constrain the design (e.g. dependency policy), they
> override what follows.

Contents

1. Summary of recommendations
2. Threat model: what is protected by what, today
3. Hybrid KEM handshake options
4. PQ and hybrid signatures: certificates, CA, pinned identities
5. Rust crate maturity (late 2026)
6. Crypto agility and migration
7. Phased plan (PQ-0 … PQ-5)
8. Decisions for the user (with recommendations)
9. Side findings
10. Sources and unverified claims

---

## 1. Summary of recommendations

| # | Recommendation | Why |
| :-: | :- | :- |
| 1 | **First fix harvest-now-decrypt-later (HNDL) and leave authentication for later.** HNDL is the threat that is already happening: recorded traffic gets decrypted once a CRQC exists. Forging authentication needs a CRQC that is running at the time of the attack. | Confidentiality lost later cannot be won back; authentication can be upgraded before the CRQC arrives. |
| 2 | **PQ-1: `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`** (the Noise HFS modifier: an ephemeral ML-KEM-768 key in msg1 and its ciphertext in msg2, mixed into the chaining key after `ee`). Do it on **both** channels in the same release and turn on the end-to-end (E2E) channel first. | Zero key-management change: no new keys, pins, fingerprints or certificates. No extra round trip, about 2.3 KB more per handshake, and no new CPU for an *unauthenticated* msg1 (the responder encapsulates only in `accept()`). E2E needs no relay upgrade because the relay is blind. |
| 3 | Add a small **authenticated handshake-version envelope** (`"TCN" ‖ version ‖ suite`, which is also mixed into the prologue). The **initiator pins** the version per peer and never falls back on its own. The **responder** has `min_handshake_version`. | Today the handshake cannot be negotiated, and the frame version byte does not cover it. This gives a mixed fleet without exposing a downgrade path. |
| 4 | **PQ-2: certificate v2 signed with composite ML-DSA-65 + Ed25519 (AND combiner)**. The certificate carries a CA *fingerprint* and a typed subject fingerprint, and has its own context string. Migrate through the existing two-key `[[authorities]]` rotation. | A live CRQC that forges the CA is the worst authentication failure (access to every node in `allow`). The cert TTL of at most 24 h makes the format cutover take hours instead of months. |
| 5 | **PQ-3: hybrid static identities.** Each node gets an ML-KEM-768 static key derived from its existing Ed25519 seed. Fingerprint v2 is computed over `x25519 ‖ ek`. The handshake is a PQNoise-style hybrid IK (KEM authentication in both directions plus DH). | This gives PQ authentication of relays, agents and clients, and PQ protection of the identities and certificates in msg1. It keeps the invariant "node keys never sign" (PROTOCOL §15.2). |
| 6 | **Crates:** `libcrux-ml-kem` (formally verified portable/AVX2 code) for ML-KEM, with RustCrypto `ml-kem` kept as a test-only differential oracle. RustCrypto `ml-dsa` ≥ 0.1.1 for ML-DSA, with Wycheproof/ACVP tests and `libcrux-ml-dsa` as the oracle. **No** `pqcrypto*`: RustSec marks them unmaintained, so `cargo deny` fails. **No** `aws-lc-rs` unless FIPS is a hard requirement. | Every PQ crate is unaudited. Verification, differential testing and the existing fuzzing budget are what TCN can actually control. |
| 7 | **No FIPS track** unless compliance demands it. Noise `25519/ChaChaPoly/BLAKE2s` is not FIPS-approved, so a FIPS ML-KEM inside it buys no compliance. Real FIPS would mean redesigning on TLS 1.3 with `aws-lc-rs` in FIPS mode. | Avoids taking on a C TCB for no gain. |
| 8 | **SSH inside the tunnel:** document and check `KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com`. OpenSSH 10.0 already defaults to mlkem768x25519 (and 9.0 to sntrup761x25519). TCN's E2E PQ remains necessary for older sshd (EL8/EL9 ship 8.x), for Paramiko-based Ansible and for TCN's own metadata. | Defence in depth, and it is free. |

Phased plan: **PQ-0** groundwork, with no wire change → **PQ-1** hybrid forward secrecy
(HNDL) → **PQ-2** PQ certificates and CA → **PQ-3** hybrid identities and hybrid IK →
**PQ-4** supply chain (PQ release signature) and SSH guidance → **PQ-5** classical-only sunset.

---

## 2. Threat model

### 2.1 Adversaries

| Adversary | Capability | What they want | Urgency |
| :- | :- | :- | :- |
| **A1 Passive recorder (HNDL)** | Records TCP traffic today (ISP, cloud fabric, tap) and gets a CRQC in year *Y* | Decrypt SSH sessions, credentials typed inside them, metadata (who accessed which node, when) | **Now**: anything recorded from today on is at risk up to *Y* + secrecy lifetime |
| **A2 Active-now, decrypt-later** | A1, plus classical MITM today (can drop or modify packets) | Force a classical-only handshake now (downgrade), then record it | Now, once PQ exists but is negotiable |
| **A3 Live CRQC** | Runs Shor in real time, close to a live connection | Impersonate relay, agent or client (recover an X25519/Ed25519 secret from a public key); forge CA certificates | Later; it only matters once a CRQC exists, but migrating pinned keys and CA trust takes fleet time |
| **A4 Compromised relay** (already in the model) | Sees outer plaintext metadata and E2E ciphertext | Read SSH: blocked by E2E. With a later CRQC: decrypt recorded E2E | Covered by the E2E layer |
| **A5 Key theft + CRQC** | Steals a long-term secret (agent seed) at some time and holds recordings | Decrypt past sessions | Second-order; matters for the choice between ephemeral and static KEM |

Symmetric primitives are not the problem. ChaCha20-Poly1305 with 256-bit keys, BLAKE2s-256
and SHA-256 fingerprints keep ≥ 128-bit security against Grover/BHT. The Noise implicit
rekey (§7.4) and the frame format need no change.

### 2.2 Layer by layer, today

| Layer | Mechanism today | HNDL (A1) | Live CRQC (A3) | Notes |
| :- | :- | :- | :- | :- |
| Outer handshake client/agent ↔ relay | `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `TCN/1 outer` | **Broken.** All DH is X25519. The session key, msg1 `s` (client/agent identity) and msg1 payload (client certificate: name, nodes, serial) can be recovered | **Broken.** Recover the relay's X25519 secret from its pinned public key, then impersonate the relay. Recover a client's secret, then impersonate the client | Protects metadata: `Open` targets, stream timing and sizes, identities, certs. The relay sees these anyway |
| Outer transport | ChaCha20-Poly1305, rekey every 1024 messages | Falls with the handshake | — | Symmetric part is fine |
| E2E handshake client ↔ agent (inside `Data`) | Same Noise IK, prologue `TCN/1 end-to-end`, cert in msg1 | **Broken** (same reasons). This is the layer that keeps SSH bytes from the relay, so A1 together with A4 reads the SSH stream unless SSH itself is PQ | **Broken.** Impersonate the agent towards clients; at that point the SSH host key (also classical) is the last line | **The layer that matters most for HNDL** |
| E2E transport | ChaCha20-Poly1305 | Falls with the handshake | — | — |
| `TCN/1 ready` confirmation | Symmetric, from the handshake | — | — | Unchanged |
| Client certificates (Phase 6) | Ed25519 signature from an offline CA, `verify_strict`, pinned CA key | Not a confidentiality item (the cert is not secret); its *contents* leak with msg1 | **Broken.** Recover the CA secret from the pinned public key, then mint certificates for any name and scope inside `allow(A)` until the CA is removed | Highest-impact authentication failure |
| CA key at rest | 32-byte Ed25519 seed, offline | — | Key recovery from the **public** key; being offline does not help | — |
| Static key pinning (relay key on agents/clients, agent key on clients) | X25519 form of Ed25519, fingerprint `SHA-256("TCN fingerprint v1\0" ‖ x25519)` | — | Pin is classical: a CRQC derives the secret | Fingerprint hash itself is PQ-fine |
| Phase 5 rotation (previous key) | Same keys | — | Same | Mechanism is reusable for migration |
| Revocation denylist, policy files | Distributed by the operator (Ansible), integrity outside TCN | — | Depends on the distribution channel (SSH, so see SSH below) | — |
| Release signing / SLSA | GitHub `attest-build-provenance` (Sigstore: Fulcio ECDSA P-256 cert, Rekor), `SHA256SUMS` | n/a | **Broken by a live CRQC** at install time (forged Fulcio/Rekor signatures) | Ecosystem-wide problem; low urgency |
| Signed commits | SSH/GPG (classical) | n/a | Same | Out of TCN's control |
| **SSH inside the tunnel** | OpenSSH KEX: `sntrup761x25519-sha512` default since 9.0, `mlkem768x25519-sha256` available since 9.9 and default since **10.0 (2025-04-09)**; host and user keys Ed25519/RSA (classical) | **Protected** if *both* ends are ≥ 9.0 with defaults. Not protected with OpenSSH 8.x (EL8 8.0, EL9 8.7, Ubuntu 22.04 8.9: sntrup is available but not the default), with RHEL in FIPS mode (sntrup disabled; unverified for mlkem in EL10 FIPS), or with Paramiko (unverified: no PQ KEX) | Host and user authentication are classical; a live CRQC MITMs SSH unless TCN's E2E authentication holds | TCN E2E PQ is defence in depth for modern SSH and the **only** PQ for legacy SSH |

What SSH's PQ KEX does **not** cover: the SSH version banners and KEXINIT lists (TCN encrypts
them, classically today), all of TCN's metadata, and fleets with old sshd. That justifies
PQ-1 even where OpenSSH is modern.

### 2.3 Priorities derived from the model

1. **E2E session-key secrecy against A1/A2**: PQ-1. Urgent.
2. **Outer session-key secrecy against A1** (metadata): PQ-1, same code path.
3. **CA forgery against A3**: PQ-2. Must land before a CRQC, so years ahead of it, because
   CA pins must be rotated across all relays and agents.
4. **Static-key impersonation against A3, plus msg1 identity/cert confidentiality against A1**:
   PQ-3.
5. Supply chain against A3: PQ-4.

A5 (stolen key plus CRQC) is why ephemeral KEM (forward secrecy) is preferred to a static-only
KEM PSK in PQ-1.

---

## 3. Hybrid KEM handshake options

### 3.1 Constraints from the code

- `zt-crypto::noise` wraps `snow` 0.10.0 with a sans-IO typestate (`initiate*` →
  `AwaitingResponse`; `respond`/`respond_any` → `AuthorizationPending` → `accept`). The
  pattern is a `const PATTERN: &str`, and the prologue comes from `Channel::prologue()`.
- `respond_any` already trial-decrypts against the current and previous key (Phase 5). The
  same idea extends to trying versions.
- Handshake messages are length-prefixed with a `u16` (`LengthDelimitedCodec`, max 65 535) on
  the outer channel, and are the first `Data` payloads (≤ 61 440) on the E2E channel.
- `limits.rs`: `NOISE_MSG1_OVERHEAD = 96`, with const assertions that msg1 + `MAX_CERT_LEN`
  fits a `Data` frame and a Noise message; `agent.rs` `MAX_MSG1_LEN` rejects oversized
  msg1 before parsing. These are exactly the places a PQ change touches.
- msg2 payload MUST be empty, so a KEM ciphertext cannot be added as a payload without a spec
  change. KEM tokens are not payload, so HFS does not conflict with this rule.
- The relay is blind to E2E, so **E2E changes need only client and agent upgrades**.
- `deny.toml` denies all RustSec advisories (unmaintained included) and git sources, and allows
  only Apache-2.0, Apache-2.0 WITH LLVM-exception, MIT, BSD-3-Clause, ISC and Unicode-3.0.

### 3.2 Options

**(a) Noise IKpsk2 with a PSK from a static ML-KEM key ("KEM in the prologue").** The initiator
encapsulates to the responder's pinned static ML-KEM ek, sends `ct` ahead of msg1, puts `ct`
into the prologue, and uses `ss` as the PSK. Runs on stock `snow`.
- Gives: PQ session-key secrecy, and implicit PQ authentication of the responder (only the
  `dk` holder gets the PSK).
- Does not give: **PQ forward secrecy**. A5 (agent seed stolen later, plus CRQC) decrypts
  recordings. With `psk2`, msg1 payload and initiator `s` stay classical; `psk0` would cover
  them, but snow's acceptance of `IKpsk0` is unverified.
- Cost: needs new static KEM keys and 1184-byte pins **in PQ-1**, which is the slow part of
  any rollout.
- Variant **(a2) ephemeral KEM pre-round**: the client sends an ephemeral `ek` in a first
  message, the responder returns `ct`, and both bind `ek ‖ ct` into the prologue and
  `ss` → PSK for IKpsk2. It has PQ forward secrecy, needs no static keys and runs on stock
  snow, but costs **+1 RTT per channel**, and on the outer channel the relay encapsulates for
  unauthenticated sources (DoS). Good fallback if (b) is blocked.

**(b) Noise HFS modifier (`IKhfs`).** Tokens `e1` (ephemeral KEM ek, after the first DH of the message: `es` in IK; corrected in PQ-0, see `docs/pq-snow.md` §3) and `ekem1`
(ciphertext after `ee`, then `MixKey(kem_ss)`):

```
<- s
...
-> e, es, e1, s, ss          (e1 = 1184 B + 16 B tag: HFS §5 puts it after es, so encrypted)
<- e, ee, ekem1, se          (ekem1 = 1088 B + 16 B tag, encrypted)
```

- Gives: PQ forward secrecy of the session key (secure if X25519 **or** ML-KEM holds); no new
  long-term keys; no extra RTT. Because of how Noise chains keys, a weak KEM cannot weaken the
  classical security.
- Does not give: PQ authentication; PQ protection of msg1 `s` and payload (encrypted under
  `es`/`ss` only). On E2E, though, msg1 travels inside an outer channel that is itself
  HFS-protected, so only the relay (A4) sees E2E msg1 under classical encryption. The
  residual HNDL exposure is the **outer msg1**: the identity and certificate of the connecting
  client/agent. PQ-3 closes it.
- DoS: the responder's KEM work (encapsulation to `e1`) happens in `accept()`, **after** the
  authorization decision. An unauthenticated msg1 costs the same as today, plus an `ek` bounds
  check.
- Library status: `snow` 0.10.0 has an `hfs` feature, but `KemChoice` is a closed enum with only
  `Kyber1024` (round-3 Kyber, via `pqcrypto-kyber`, which is unmaintained). ML-KEM needs an
  upstream PR (`MLKEM768` variant plus resolver), a vendored patch as a path dependency, or the
  hack of returning ML-KEM-768 from a custom resolver under the `Kyber1024` label (**rejected**:
  the protocol name hashed into the transcript would lie, and cross-implementation test vectors
  would be impossible). snow's KEM buffers are sized 4096 B (`MAXKEMPUBLEN`/`MAXKEMCTLEN`), so
  768 fits.
- The HFS spec is "revision 1, 2018, unofficial/unstable". Its security argument is simple
  (an extra `MixKey` after `ee`), and the same idea appears in PQNoise's hybrid analysis.

**(c) Rosenpass-style or PSQ: a separate PQ key exchange feeding a PSK.** Rosenpass (for
WireGuard) uses Classic McEliece static keys (≈ 0.5 MB public keys; they do not fit a 65 535
Noise message or a 61 440 frame) plus ephemeral Kyber, and refreshes the PSK every ~2 minutes
for long-lived tunnels. That model fits WireGuard and does **not** fit TCN's per-ssh-invocation
E2E sessions. Cryspen's `libcrux-psq` (X25519 + ML-KEM-768 or McEliece, two messages,
responder authenticated by KEM, initiator optionally by DH/Ed25519/ML-DSA) is the closest
ready-made "PQ PSK" component, but it is 0.0.x, unaudited and has an unstable API.
Composition is (a)/(a2) with a better-analysed front end. Not recommended as the main path;
worth watching.

**(d) Replace Noise with TLS 1.3 (rustls + X25519MLKEM768).** rustls ≥ 0.23.22 ships the
hybrid group with the `aws-lc-rs` provider (`prefer-post-quantum` sets its priority), and raw
public keys (RFC 7250) are possible.
- Pros: an IETF-standard hybrid; the only realistic **FIPS** path (`aws-lc-rs` `fips`).
- Cons: loses IK's **silent rejection** (the TLS server answers before the client
  authenticates, so the relay becomes visible to scanners and §7.3 "does not respond" is
  gone); adds a round trip of server flight before client auth; brings a much larger parser
  surface (TLS, RPK/X.509); brings a C TCB (aws-lc); and means rewriting the typestate,
  Phase 5 rotation, the Phase 6 cert-in-msg1 transport and E2E-in-`Data`. ML-DSA certificates
  in rustls are still experimental. **Not recommended.**

**(e) PQNoise / hybrid patterns (`clatter`).** `clatter` 2.3.0 implements PQNoise (`pqIK`:
`-> skem, e, s` / `<- ekem, skem`) and hybrid patterns, e.g. `noise_hybrid_ik`:

```
<- s
...
-> skem, e, es, s, ss
<- ekem, skem, e, ee, se
```

- Gives: KEM-based authentication of **both** static keys plus DH. Identity and payload are
  protected by the KEM from the first token. Forward secrecy comes from `ekem`. This is the
  right **end state**.
- Needs: static ML-KEM keys for every node (PQ-3), since it is not a quick win. `clatter` is
  unaudited, appears to have a single maintainer with low adoption, enables PQClean
  (`pqcrypto-mlkem`, unmaintained in RustSec) **by default** (so it must be used with
  `default-features = false`), and depends on the older `ml-kem` 0.2.x. Its license is
  unverified. No HFS.

### 3.3 Which layer first

| | E2E client ↔ agent | Outer peer ↔ relay |
| :- | :- | :- |
| Protects | SSH bytes from the relay **and** the network (A1 + A4) | Metadata from the network; wraps the E2E msg1 |
| Upgrade needed | Client + agent only | Relay + agents + clients |
| Order | **First** (agents accept v1+v2, then clients pin v2 per node) | Same release, enabled second |

Do both in PQ-1: it is the same code (`zt-crypto::noise` plus the envelope). With both layers
on HFS, a passive network recorder with a CRQC learns only the outer msg1 (identity and
certificate). Without the outer layer it also learns stream metadata and the E2E msg1.

### 3.4 Message sizes (bytes, ML-KEM-768: ek 1184, ct 1088, ss 32)

| Handshake | msg1 (P = payload) | msg1 max with v1 cert (P = 4 328) | msg1 max with v2 cert (P = 7 637, §4) | msg2 |
| :- | -: | -: | -: | -: |
| v1 IK (today) | 96 + P | 4 424 | — | 48 |
| PQ-1 IKhfs (+5 B envelope) | 1 285 + P | 5 613 | 8 922 | 1 152 |
| PQ-3 hybrid IK (PQNoise-style, approx.) | ≈ 3 557 + P | — | ≈ 11 194 | ≈ 2 256 (+1 184 if responder `e` also carries a KEM key; check the clatter layout) |
| Limit: `Data` payload / Noise message | 61 440 / 65 535 | ✓ | ✓ | ✓ |

All variants fit comfortably. The only constants to change are `NOISE_MSG1_OVERHEAD` (per
suite), `MAX_MSG1_LEN` in `agent.rs` and the const assertions in `limits.rs`. The 61 440
two-layer frame budget is untouched because KEM data lives only in handshakes, never in
transport frames. Flow control is untouched too (msg1 ≪ 256 KiB `INITIAL_WINDOW`).

### 3.5 CPU and latency (order of magnitude; PQ-0 must measure on x86_64 and aarch64 musl)

| Operation | Portable Rust (≈ 3 GHz) | SIMD (libcrux AVX2) |
| :- | -: | -: |
| X25519 DH | 40–60 µs | — |
| ML-KEM-768 keygen / encaps / decaps | 30–90 µs each | ≈ 10–30 µs each |
| Ed25519 verify | 30–60 µs | — |
| ML-DSA-65 verify | 60–150 µs | ≈ 30–60 µs |
| ML-DSA-65 sign (offline CA) | 0.2–1 ms | — |
| SLH-DSA-SHA2-128s verify / sign | ≈ 0.5–2 ms / 0.3–2 s | — |

*Unverified: these ranges come from published benchmarks of comparable implementations, not
from TCN measurements.*

- v1 IK today costs about 5 × 50 µs ≈ 250 µs per side. PQ-1 adds 1 keygen + 1 decaps
  (initiator) and 1 encaps (responder), roughly +40–80 % handshake CPU, **no extra RTT**,
  and +2.3 KB per handshake. That is negligible next to SSH's own KEX and the TCP/relay RTTs.
- Relay capacity: unauthenticated msg1 cost is unchanged in PQ-1 (see 3.2b). In PQ-3 the
  responder decapsulates `skem` before anything is authenticated: +50–100 µs per invalid msg1,
  times keys (current/previous), times accepted versions. That is bounded by the existing
  per-IP and per-/64 handshake limiter (§10).

### 3.6 Recommendation

- **PQ-1:** option (b), `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` on both channels, via an
  upstream snow PR, with a vendored, reviewed patch (path dependency, allowed by `cargo deny`)
  if upstream does not release in time. Fall back to (a2) if neither is acceptable.
- **PQ-3:** option (e), PQNoise-style hybrid IK.
- **KEM:** plain **ML-KEM-768** inside Noise, not X-Wing. Noise's chaining key already makes
  the hybrid combination with X25519, and both `ek` and `ct` are hashed into the transcript
  (`MixHash`), which covers the KEM-binding concerns X-Wing's combiner addresses. X-Wing
  (`x-wing` 0.1.0, draft-06) is the right primitive only for a standalone KEM outside Noise,
  e.g. option (a).
- **Level:** ML-KEM-1024 only if CNSA 2.0 compliance is required (+384 B per ek/ct).

---

## 4. PQ and hybrid signatures

### 4.1 What signs what in TCN

Only the **offline CA** signs (client certificates, PROTOCOL §15.2). Node keys **never** sign
(their X25519 form is used for Noise), and this is a stated security invariant ("no signing
oracle in the fleet"). The PQ authentication of relays, agents and clients therefore belongs
in the **KEM** handshake (PQ-3), not in signatures. Signatures are needed for:

1. client certificates (CA → client): PQ-2;
2. release artefacts: PQ-4;
3. nothing else.

### 4.2 Algorithms and sizes (bytes)

| Scheme | Category | Public key | Signature | Notes |
| :- | :-: | -: | -: | :- |
| Ed25519 (today) | classical | 32 | 64 | — |
| ML-DSA-44 | 2 | 1 312 | 2 420 | — |
| **ML-DSA-65** | 3 | 1 952 | 3 309 | matches ML-KEM-768 (cat. 3) |
| ML-DSA-87 | 5 | 2 592 | 4 627 | CNSA 2.0 |
| SLH-DSA-SHA2-128s | 1 | 32 | 7 856 | hash-based, most conservative, slow to sign |
| SLH-DSA-SHA2-128f | 1 | 32 | 17 088 | — |
| SLH-DSA-SHA2-192s | 3 | 48 | 16 224 | — |
| **Composite ML-DSA-65 + Ed25519** | 3 | 1 984 | 3 373 | IETF composite style; AND combiner |

The IETF `draft-ietf-lamps-pq-composite-sigs` is at revision -19 and is in the RFC Editor queue
(Proposed Standard, no RFC number yet). It includes ML-DSA + Ed25519 combinations, verification
succeeds only if **all** components verify, and labels and prefixes give non-separability. TCN
does not use X.509, so it should borrow the **semantics** (AND, domain separation,
non-separability) rather than the OIDs and DER.

### 4.3 Composite construction for TCN (proposal)

```
CTX2  = "TCN client certificate v2\0"
M'    = CTX2 || TBS                    (TBS includes version and sig_alg = 0x02 composite)
sig_E = Ed25519-Sign(ca_ed, M')                      64 B
sig_M = ML-DSA-65.Sign(ca_mldsa, M', ctx = "TCN-cert-v2")   3 309 B, hedged (FIPS 204 default)
signature = sig_M || sig_E
verify: ML-DSA verify(M', ctx) AND Ed25519 verify_strict(M'); both MUST pass, fixed order,
        result computed only after both (no short-circuit oracle needed: inputs are public)
```

- **Non-separability / stripping:** a v2 cert cannot be turned into a v1 cert. `sig_E` covers
  `CTX2` and `version = 0x02`, and the v1 verifier uses `CTX1`. The ML-DSA `ctx` string
  separates TCN from any other use of the key.
- **Malleability:** ML-DSA hedged signing is randomized, so different signatures over the same
  content are normal. TCN identity is already the `serial` (§15.2), so nothing changes. The
  verifier must reject non-canonical encodings. This is exactly the bug class of
  CVE-2026-24850 (RustCrypto `ml-dsa` accepted repeated hint indices) and of a hint-bounds bug
  reported in `libcrux-ml-dsa`. Make Wycheproof/ACVP vectors and a differential test between
  two implementations mandatory.
- **Keys:** the CA secret file v2 is `tcn-ca-secret-v2:<hex(ed25519_seed ‖ mldsa_seed ξ)>`
  (64 B of seeds; FIPS 204 keygen from the 32-byte seed). It has a new prefix, so v1 loaders
  reject it. The public key is `tcn-ca-pub-v2:` + hex(ed25519 ‖ mldsa_pk) (1 984 B → 3 968 hex
  characters). It is pinned in `[[authorities]]`.

### 4.4 Certificate format v2 (proposal, for PROTOCOL §15.1)

```
 off   size  field
 0      4    magic "TCNC"
 4      1    version       0x02
 5      1    sig_alg       0x02 = ML-DSA-65+Ed25519 composite
                           (reserved: 0x03 ML-DSA-87+Ed25519, 0x04 SLH-DSA-SHA2-128s+Ed25519)
 6     32    ca_fp         SHA-256("TCN CA fingerprint v2\0" || ca_pub_v2)   (replaces ca_key)
 38     1    subject_kind  0x01 = identity v1 (X25519 fp), 0x02 = identity v2 (hybrid fp, PQ-3)
 39    32    subject_fp    fingerprint of the subject's static key, of that kind
 71    16    serial
 87     8    not_before
 95     8    not_after
 103    1    name_len, name, scope, node_count, nodes   (unchanged rules)
 L-S    S    signature     S = 3 373 for sig_alg 0x02
```

- Length range: 3 480 ..= 7 638 bytes for `sig_alg = 0x02` (v1: 170 ..= 4 328). `MAX_CERT_LEN`
  becomes per-version (and per-`sig_alg`). Rule 1 still applies: length checked against the
  maximum for the declared `(version, sig_alg)` **before** reading fields.
- `ca_fp` instead of `ca_key` saves 1 952 B per certificate. Verification still uses only the
  **pinned** key, found by `ca_fp` byte for byte (the same principle as today).
- `subject_fp` is typed, so the same cert format survives PQ-3. The binding check (§15.4
  step 4) compares it, in constant time, with the fingerprint of the static key that the
  handshake authenticated, *of the same kind*. Step 4 still comes before the signature, so the
  DoS ordering is preserved.
- Rule 8 (canonical Ed25519 points) applies only to keys still present: the CA key is now
  pinned rather than embedded, so canonicity checks move to load time of `[[authorities]]`.
- Verification cost per msg1 with a cert: about 100–200 µs (Ed25519 + ML-DSA-65), within the
  §10 handshake limits. Order of checks: 0 handshake, 1 key denylist, 3 length/format,
  4 binding, 5 pinned CA by `ca_fp`, **6a ML-DSA, 6b Ed25519**, 7… unchanged.

### 4.5 Should the CA root use SLH-DSA?

TCN has a **single-tier** CA: the offline CA signs each short-lived client cert directly, and
every handshake verifies it. SLH-DSA-128s would mean 7.9 KB certificates (12.2 KB max), about
0.5–2 ms verification on **every** relay and agent handshake (DoS-exposed: anyone can present
a well-formed certificate bound to their own fresh key), and seconds of signing per issuance.

- **Recommendation:** composite ML-DSA-65 + Ed25519 for the client-cert CA. Reserve
  `sig_alg = 0x04` (SLH-DSA + Ed25519) in case lattice signatures are ever broken. Using
  SLH-DSA as a root over an ML-DSA *intermediate* would add about 10 KB and a second
  verification per handshake, plus intermediate rotation logic. TCN's CA is already offline
  and short-TTL, so that complexity is not worth it.
- **Use SLH-DSA where it fits:** the release-signing root (PQ-4) signs rarely, sizes do not
  matter, and the key is long-lived.

### 4.6 Fingerprints and pinning

- Fingerprint v1 stays as is. **Fingerprint v2** (PQ-3) is
  `SHA-256("TCN fingerprint v2\0" ‖ x25519 ‖ mlkem768_ek)`, displayed as `SHA256:` + hex as
  today.
- A hybrid peer matched by a **v1** whitelist entry is authenticated only classically: a CRQC
  that recovers the X25519 secret can pair it with its own ML-KEM key. So policy and
  `clients.toml` entries must carry the v2 public key to get PQ authentication. Log v1 matches
  of hybrid peers (`classical_identity_match`, WARN) and forbid them with
  `min_identity_version = 2`.
- The denylist `keys` must match on **both** fingerprints. Revoking a key revokes every identity
  sharing its X25519 component; this preserves the P/−P property of §15.8.

---

## 5. Rust crate maturity (verified 2026-11-09 unless marked)

| Crate | Version (date) | What | Audit | Verification / CT | `unsafe` | License vs `deny.toml` | musl | Verdict |
| :- | :- | :- | :- | :- | :- | :- | :- | :- |
| RustCrypto **`ml-kem`** | 0.3.4 (2026-10-31), MSRV 1.87 | FIPS 203, pure Rust | **Never independently audited** (README) | NIST vectors; no RustSec advisory found; KyberSlash-style CT *unverified* | *unverified* | Apache-2.0/MIT ✓ | trivial | Good **test oracle** / fallback |
| Cryspen **`libcrux-ml-kem`** | 0.0.11 (2026-10-07) | FIPS 203 | No independent audit | Portable + AVX2 formally verified with hax/F\* (correctness, panic freedom, secret independence, as claimed); NEON unverified; GHSA-2cgv-28vr-rv6j (aarch64 wrong results from an unverified intrinsic fallback, 0.0.3, fixed 0.0.4); Feb 2026 Symbolic Software found spec/proof errors in admitted modules (Rust code itself correct) and Cryspen disputed parts of it. OpenSSH's mlkem768 code is derived from libcrux (*my knowledge, unverified here*) | Yes, in SIMD intrinsics (outside TCN's `forbid`) | Apache-2.0 ✓ | ✓ | **Recommended primary**; pin version; consider portable-only on aarch64 |
| RustCrypto **`ml-dsa`** | 0.1.1 (2026-06-05), MSRV 1.85 | FIPS 204 | Never audited | **RUSTSEC-2025-0144 / CVE-2026-22705** (timing in `decompose`, fixed 0.1.0-rc.3); **CVE-2026-24850** (accepted repeated hint indices, fixed 0.1.0-rc.4) | *unverified* | Apache-2.0/MIT ✓ | ✓ | **Recommended** for verify (fleet) and sign (offline CA, where timing exposure is minimal), with mandatory vectors and an oracle |
| `libcrux-ml-dsa` | 0.0.11 (2026-10-07) | FIPS 204 | No audit | Partially verified (field arithmetic, NTT, serialization) | Yes | *license not shown on docs.rs page (unverified)* | ✓ | **Differential oracle** |
| RustCrypto **`slh-dsa`** | 0.2.0-rc.5 (2026-04-28); last stable 0.1.0 (2024) | FIPS 205 | Never audited | — | *unverified* | Apache-2.0/MIT ✓ | ✓ | For PQ-4 (release root) once 0.2 is stable |
| RustCrypto **`x-wing`** | 0.1.0 (2026-07-09) | X-Wing draft-06 (ML-KEM-768 + X25519) | Never audited | — | — | Apache-2.0/MIT ✓ | ✓ | Only if a standalone KEM is needed (option a) |
| **`aws-lc-rs`** / `aws-lc-sys` | 1.19.0 / 0.47.0 (2026-10-28) | C (AWS-LC) bindings | AWS-LC 3 static, **FIPS 140-3 cert #5314** (validated 2026-06-05, **ML-KEM approved**, ML-DSA not listed); `fips` feature binds AWS-LC-FIPS 4.x ("submitted to NIST") | C implementation, own CT practices | C TCB | Apache-2.0 OR ISC ✓; aws-lc-sys license text points to AWS-LC LICENSE (may need extra `allow` entries: *unverified*) | prebuilt bindings for x86_64 and aarch64 musl; needs a C compiler; FIPS needs CMake + Go | **Only for a FIPS track** (and then TLS, not Noise) |
| `oqs` (liboqs) | 0.11.0 wrapping liboqs 0.13.0 | C | No audit; liboqs itself says it is not for production | — | C TCB | MIT/Apache ✓ | CMake | **No** |
| `pqcrypto-*` (PQClean) | — | C | — | — | C | ✓ | — | **No**: RUSTSEC-2026-0161/0164 *unmaintained* (PQClean archived ≥ July 2026), so `cargo deny` fails |
| **`clatter`** | 2.3.0 (2026-08-30) | Noise + PQNoise + hybrid patterns | **No audit** ("has not received any formal audit") | Classical patterns checked against Cacophony/snow vectors | *unverified* | *unverified* | ✓ (no_std) | Candidate for PQ-3 **after an internal review**; `default-features = false` (default pulls `pqcrypto-mlkem`); depends on `ml-kem` 0.2.x |
| **`snow`** | 0.10.0 (in use) | Noise | — | `hfs` feature exists, but only `KemChoice::Kyber1024` via `pqcrypto-kyber` 0.8 (round-3 Kyber, unmaintained) | — | ✓ | ✓ | Needs an ML-KEM `KemChoice` (upstream PR or vendored patch) |
| **`rustls`** | 0.23.46 | TLS | — | X25519MLKEM768 via aws-lc-rs provider since 0.23.22; `prefer-post-quantum` sets priority (*whether it is default-on in 0.23.46 is unverified*); ML-DSA only experimental via `rustls-post-quantum` (`aws-lc-rs-unstable`) | — | ✓ | via aws-lc-rs | Not recommended (see 3.2d) |
| `libcrux-psq` | 0.0.9 | PQ PSK protocol | No audit stated | Cryspen; not stated as verified | — | Apache-2.0 (*unverified*) | ✓ | Watch |

Takeaways:

- **No PQ crate in Rust is independently audited.** The deciding factors are formal
  verification (libcrux ML-KEM), simplicity and review of TCN's own glue, differential testing
  between two independent implementations, Wycheproof/ACVP/NIST vectors in CI, and the existing
  `cargo-fuzz` targets extended to new parsers.
- Secret-dependent timing matters most for **static** KEM decapsulation on network-exposed
  responders (PQ-3). It matters less for HFS ephemerals (single use) and least for ML-DSA
  signing on an offline CA. Verification uses only public data.
- `#![forbid(unsafe_code)]` stays in TCN crates. Accept `unsafe` in libcrux's SIMD intrinsics
  (verified for AVX2, unverified for NEON), or enable portable-only on aarch64. Feature names
  must be checked.

---

## 6. Crypto agility and migration

### 6.1 Handshake versioning (new; the frame `version` byte stays 0x01)

Frames do not change: KEM data lives only in handshakes. The handshake gets an explicit,
authenticated envelope from v2 on:

```
msg1_v2 = "TCN" (54 43 4e) || hs_version (u8) || suite (u8) || noise_msg1
prologue_v2 = "TCN/2 outer" | "TCN/2 end-to-end"  ||  hs_version || suite
msg2 unchanged (no envelope: the initiator knows what it asked for)
confirm "TCN/1 ready" -> "TCN/2 ready"
suite 0x01 = Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s       (PQ-1)
suite 0x02 = hybrid IK, static ML-KEM-768 both sides               (PQ-3)
```

- The envelope is in the prologue, so changing `suite` or `version` breaks the handshake.
- v1 msg1 has no envelope (it starts with a random ephemeral key). Responder dispatch:
  1. Magic matches → parse as that version **only** (a v1 message that starts with the 5-byte
     magic by chance, probability 2⁻⁴⁰, fails once and the client retries with a new
     ephemeral).
  2. Otherwise, if `min_handshake_version ≤ 1`, run today's v1 `respond_any`.
  3. Otherwise drop silently (as today).
- Trial cost: at most (keys) × 1, because the version is explicit. The `respond_any` pattern
  stays.

### 6.2 Capabilities are pinned, never negotiated downwards

- **Initiator:** a per-peer `handshake = 1 | 2 | 3` next to each pinned key: `client.toml`
  `[[relays]]` and nodes, the agent's `--relay`/`[[relays]]` entries. From PQ-3 on, a v2
  public key format implies ≥ 3. There is **no automatic fallback**: a v2 failure is an error
  (with §13 failover to the *next relay* still allowed before `OpenAck`, which does not lower
  the version).
- **Responder:** `min_handshake_version` (CLI/config, default 1 in the PQ-1 release, 2 in the
  next). Audit `legacy_handshake_accepted` (WARN, with peer fingerprint), plus an hourly
  reminder `legacy_handshakes_still_accepted`, like `previous_key_still_accepted`.
  `keys_in_use` gains `handshake_versions`.
- **Downgrade analysis (A2):** an active attacker cannot turn a v2 msg1 into a valid v1 msg1
  (different protocol name and prologue mean different keys, and the initiator's static secret
  is required). The initiator never retries with v1. A responder with `min = 2` never accepts
  v1. The only way v1 survives is operator configuration, and the audit events make it
  visible.

### 6.3 Mixed fleet (PQ-1)

| Client | Relay | Agent | Client↔relay | Agent↔relay | E2E |
| :- | :- | :- | :- | :- | :- |
| old | old | old | v1 | v1 | v1 |
| new (pins v1) | new | old | v1 | v1 | v1 |
| new (pins E2E v2) | old | **new** | v1 | v1 | **v2** (E2E needs no relay upgrade) |
| new (pins relay v2) | **new** | old | **v2** | v1 | v1 |
| new | new | new (pins relay v2) | v2 | v2 | v2 |

HA (≤ 8 relays): the per-relay `handshake` pin lets relays be upgraded one at a time (restarts
interrupt nothing with HA, §13).

**Rollout order:**
1. Agents (accept v1+v2 E2E).
2. Clients pin E2E v2 per node.
3. Relays one by one (accept v1+v2).
4. Clients and agents pin relays v2.
5. Responders set `min = 2`.
6. The next major release removes v1.

### 6.4 Rollback

- PQ-1 binaries keep v1. Rolling back means first flipping initiator pins back to `1`, then
  resetting responder `min` to 1, then downgrading binaries if needed (the **reverse** of the
  rollout).
- A client that pins v2 towards a downgraded agent fails closed. On E2E it stops, because
  errors after `OpenAck` are final (§13). That is the intended behaviour, and the docs must
  explain it (OPERATIONS "rollback" runbook).
- PQ-2 certs: rollback means the CA re-issues v1 (possible while the v1 CA key is still pinned).
  Certs live ≤ `max_lifetime`, so the system converges within hours.

### 6.5 Interplay with Phase 5 rotation and Phase 6 certificates

- **PQ-1:** no keys change. Rotation is unaffected.
- **PQ-2 (certs):** the client sends **one** certificate on both channels (§15.3), so every relay
  **and** agent must accept v2 certs before the CA issues them. Old binaries reject `version
  0x02` (fail closed; the client moves to the next relay, then fails). Steps:
  1. Deploy binaries that accept v1+v2 certs everywhere.
  2. Verify via `authorities_in_use` (add `cert_versions`).
  3. Add the composite key to the authority entry: `public_keys = ["<v2 composite>", "<v1
     ed25519>"]`. The existing two-key rotation applies, and `ca_rotation_pending` warns until
     it is finished.
  4. Issue v2.
  5. After `max_lifetime` (default 8 h, ≤ 24 h) since the last v1 issuance, remove the Ed25519
     key.
  6. With no v1 CA key pinned, v1 certs are unacceptable, which is the downgrade protection
     against a CRQC forging Ed25519.
- `[[authorities]]` load checks extend to mixed key types: a CA key is never equal to a peer
  key, so compare both components; and a v2 composite key's Ed25519 part must not equal any v1
  CA key in another entry (otherwise "same CA in two entries" could be bypassed; finding
  0006-1/2 class).
- **PQ-3 (identities):** the ML-KEM key derives from the existing seed (D12), so **no new secret
  file** is needed. But fingerprints change from v1 to v2, so policies, `clients.toml`, pins,
  the denylist and cert `subject_fp` must all migrate. Reuse Phase 5: `public_keys = [v2, v1]`
  for agents, the relay keyring unchanged (the same seed serves v1 and v3 handshakes during
  migration), and `agent_rotation_pending`-style WARNs until v1 entries are gone. Certs:
  `subject_kind = 0x02` is issued once the client's peers all accept v3.
- **TTL:** Phase 6 short TTLs are an asset. Certificate-format changes converge in ≤ 24 h, so
  there is no long compatibility tail as in X.509 PKIs.

---

## 7. Phased plan

Each phase follows METHODOLOGY: RED spec, RED adversary, GREEN, REFACTOR, then an adversary
review recorded as `docs/adversary/00NN-pq-*.md`. Each phase updates PROTOCOL.md
(normative), OPERATIONS.md (runbook) and a plan file in the style of `docs/phase6-plan.md`.

### PQ-0: groundwork (no wire change)

- **Scope:**
  - A `HandshakeVersion`/`Suite` value object in `zt-domain` (closed enum, `TryFrom<u8>`).
  - Config fields `handshake` per pin and `min_handshake_version` (parsed and validated, only
    `1` accepted yet).
  - New audit event kinds.
  - A KEM provider trait in `zt-crypto`, so implementations can be swapped and differentially
    tested.
  - A test harness for NIST ACVP / Wycheproof vectors (ML-KEM, ML-DSA).
  - `criterion` baselines for v1 handshakes and cert verification on x86_64 and aarch64 musl.
  - `cargo deny` dry run with candidate crates.
  - An upstream snow PR for `KemChoice::MLKEM768`.
  - OPERATIONS: an SSH PQ KEX section (`KexAlgorithms`, OpenSSH version matrix, Paramiko caveat).
  - Optionally, the agent logs the local sshd banner version at startup (`ssh_server_version`)
    so non-PQ sshd is visible. It reads only from `127.0.0.1:22` before any client exists, so no
    client payload enters the logs.
- **Why first:** it makes the negotiation and observability changes reviewable on their own and
  gives measured perf budgets instead of the estimates in §3.5.
- **Catalogue:** Parsing: unknown `handshake` values and out-of-range `min`. State: `min` >
  supported. Side channels: new events contain fingerprints only.
- **Perf budget:** none (baseline only).

### PQ-1: hybrid forward secrecy (HNDL), both channels

- **Scope:**
  - Envelope + suite 0x01 (`IKhfs` + ML-KEM-768, libcrux).
  - `zt-crypto::noise` gains versioned `initiate`/`respond_any` (dispatch on the envelope; v1
    path unchanged).
  - `limits.rs` per-suite overheads and const assertions.
  - `agent.rs` `MAX_MSG1_LEN` per suite.
  - Validation of the received `e1` (FIPS 203 encapsulation-key modulus/type check) before
    encapsulation in `accept()`.
  - `TCN/2 ready`.
  - Pins with `handshake = 2`.
  - New fuzz targets: v2 msg1/msg2 responder and initiator, envelope parser.
- **Why:** it closes the urgent HNDL gap for SSH payload and most metadata with no key
  management.
- **Attack catalogue (adversary must cover):**

| Category | Rows |
| :- | :- |
| Parsing | msg1 lengths at 0/1/5 (envelope only)/1 284/1 285/max/max+1 per suite; unknown version/suite; envelope present with a v1 body; v1 body that starts with the magic; `e1` with coefficients ≥ q (modulus check) or of wrong length; msg2 with `ekem1` truncated or extended; non-empty msg2 payload |
| Resources | CPU per unauthenticated v2 msg1 (must equal v1 plus a bounded `ek` check; no encapsulation before `accept`); memory per pending handshake; trial cost with previous key × versions; a compromised relay looping E2E v2 msg1s at an agent (per-relay quota, finding 0005-1) |
| State | v2 msg1 to a v1-only responder (silent drop); v1 msg1 to a `min = 2` responder; replayed v2 msg1 (no `TCN/2 ready` means no sshd, as in 0002-3); `TCN/1 ready` sent on a v2 session; reload changing `min` during a handshake (keys and settings taken at accept) |
| Identity | same static key on v1 and v2: audit and whitelist identical; previous key × v2; relay key swap during the v2 rollout |
| Downgrade | an attacker strips or rewrites the envelope (must fail); a client pinned v2 receives a failure, so no v1 retry on the same or next relay; an agent pinned v2 for relay *i* does not fall back; `legacy_handshake_accepted` is always emitted for v1 |
| Side channels | ML-KEM decapsulation constant time (implicit rejection; libcrux claim plus a dudect-style smoke test); errors that differ between "bad envelope" and "bad Noise" (none, only metadata); logs never contain `ek`/`ct` |
| Malleability | `ek`/`ct` are fixed-length, so one encoding each; envelope canonical; flipping bits in `e1` must fail at msg2 (transcript hash) |

- **Perf budget (gate):**
  - Handshake CPU per side ≤ +200 µs p99 (x86_64) and ≤ +400 µs (aarch64) compared with the
    PQ-0 baseline.
  - No extra RTT.
  - msg1 ≤ 1 285 + P and msg2 = 1 152 bytes.
  - Relay unauthenticated-msg1 throughput within 5 % of baseline.
  - Release binary growth ≤ 400 KB per binary.
  - Bulk transport throughput unchanged.
- **Decisions:** D2, D3, D4, D5, D6, D7, D8.

### PQ-2: post-quantum certificates and CA

- **Scope:**
  - Cert v2 (§4.4), with v1 still accepted.
  - `zt-ca keygen --v2` (CA secret v2), `sign` produces v2, `inspect` handles both.
  - `[[authorities]]` accepts composite keys (hex), with mixed v1/v2 keys during rotation.
  - Per-version `MAX_CERT_LEN` and `MIN_CERT_LEN`; message 1 limits re-proved with const
    assertions.
  - Issuance log gains a `version` column.
  - Audit `cert_version` field.
  - Fuzz targets for the v2 decoder.
- **Why now:** a live CRQC forging the CA is the highest-impact authentication break, and CA
  migration is cheap thanks to short TTLs. It does not depend on PQ-3, because `subject_kind`
  makes the format future-proof.
- **Attack catalogue:**

| Category | Rows |
| :- | :- |
| Parsing | lengths min-1/min/max/max+1 **per (version, sig_alg)**; `sig_alg` reserved codes; `subject_kind` unknown; v2 header with a v1-length body; text prefix `tcn-client-cert-v2:` vs v1 confusion; CA key text v1/v2 confusion |
| Resources | CPU per presented v2 cert (binding before both signature checks; ML-DSA before or after Ed25519, measured); a compromised relay replaying v2 certs at an agent |
| State | rotation with mixed `public_keys = [v2, v1]`; removal of the v1 key closes v1-cert sessions (§12); expiry within a session unchanged |
| Identity | `ca_fp` that matches no pin; `ca_fp` collision attempts across entries; composite key whose Ed25519 half equals another entry's v1 key or a peer key (load-time rejection); `subject_kind` 0x01 cert presented in a v3 handshake and vice versa |
| Downgrade / stripping | remove `sig_M` and present as v1 (fails: CTX and version); replace `sig_E`; v1 cert under a v1 key still pinned (accepted only until the key is removed, then audited) |
| Side channels | errors reveal only `cert_check` codes; serial/name only after both signatures verify |
| Malleability | ML-DSA non-canonical signatures: repeated or out-of-order hint indices (CVE-2026-24850 regression), `z` out of range, trailing bytes; Ed25519 non-canonical `S`/`R` (`verify_strict`); two implementations must agree on every mutated vector |

- **Perf budget:** cert verify ≤ 250 µs p99 (x86_64); v2 cert ≤ 7 638 B; offline signing
  ≤ 50 ms.
- **Decisions:** D9, D10, D11.

### PQ-3: hybrid identities and hybrid IK (PQ authentication)

- **Scope:**
  - Identity v2: an ML-KEM-768 static key derived from the Ed25519 seed (D12), with key
    validation at load (`dk` hash check).
  - Public key format v2 and fingerprint v2; `keygen`/`pubkey` print both.
  - Policy, `clients.toml`, `client.toml` and `--relay-key` accept v2 keys.
  - Suite 0x02 hybrid IK (D15).
  - Denylist matches both fingerprints.
  - `min_identity_version`.
  - Certificates with `subject_kind = 0x02`.
- **Why:** it closes the remaining live-CRQC impersonation and the outer msg1 HNDL leak. It comes
  after PQ-2 because it is the most invasive operationally (every pin changes), and PQ-1 and
  PQ-2 already removed the urgent and the highest-impact items.
- **Attack catalogue:**

| Category | Rows |
| :- | :- |
| Parsing | v2 key text lengths (2 432 hex); invalid `ek` (modulus); `dk` hash mismatch at load; v2 msg1 with truncated `skem`; mixed v1 key in a v3 pin |
| Resources | responder decapsulation before authentication: cost × keys × versions under the rate limiter; agent per-relay quota with v3 msg1 floods |
| State | v1 → v3 identity migration with `public_keys = [v2, v1]`; previous key in v3; the same seed used concurrently in v1 and v3 sessions |
| Identity | **X25519 of the victim + attacker's ML-KEM key** matched by a v1 entry (must WARN, and be rejected with `min_identity_version = 2`); attacker reuses the victim's `ek` with their own X25519 (handshake fails); P/−P under v2 (different `ek`, same X25519: the denylist still matches); a CA key equal to either component of a node key |
| Downgrade | v3-capable peers forced to v2 or v1 (pins forbid); a v1 whitelist entry for a peer that has a v2 key |
| Side channels | static ML-KEM decapsulation CT (critical: long-term key, network-exposed); timing of trial across keys reveals only which public key matched |
| Malleability | fixed-length KEM objects; transcript covers `ek` and `ct` |

- **Perf budget:** handshake CPU per side ≤ +400 µs p99 versus baseline; msg1 ≤ 3.6 KB + P;
  msg2 ≤ 3.5 KB; unauthenticated-msg1 cost ≤ 2.5× baseline.
- **Decisions:** D12, D13, D14, D15.

### PQ-4: supply chain and SSH

- **Scope:**
  - An offline **SLH-DSA-SHA2-128s** (+ Ed25519 composite) release key signs `SHA256SUMS`, in
    addition to the Sigstore/SLSA attestation. A `zt-* verify-release` subcommand or a
    documented OpenSSL ≥ 3.5 command verifies it. The fingerprint is published out of band
    (README, `SECURITY.md`).
  - A separate key file prefix and context string (never the client-cert CA).
  - SSH: a documented KEX policy, plus an agent startup warning if sshd does not offer
    mlkem768x25519/sntrup761x25519 (PQ-0 observability).
- **Why last:** these attacks need a live CRQC at install time, and they are independent of the
  protocol, so this phase can run in parallel.
- **Catalogue:** Parsing of the signature file; Identity (wrong key, signature of another
  artefact); Malleability (SLH-DSA is deterministic or randomized; identity is the checksum
  file).
- **Perf:** irrelevant (offline).

### PQ-5: classical-only sunset

- Responders default to `min_handshake_version = 3` and `min_identity_version = 2`. The
  v1 handshake code, v1 certificates and v1 CA keys are removed in a major release after a
  deprecation window. Keep the hybrid: classical components stay inside every construction;
  only *classical-only* paths are removed.
- Catalogue: verify that each removed path is now rejected (Parsing/State rows reused as
  negative tests).

**As implemented (Phase 7, PQ-SUNSET; OPERATIONS §19).** The defaults do **not** change and no
code path is removed: the suite ids replaced the numeric minimum of this section (AP-7), and a
mixed fleet must keep working across upgrades. The sunset is the opt-in `pq_only` profile
(`[handshake] pq_only` in `relay.toml`, `--pq-only` on the agent, `pq_only` in
`client.toml`), which refuses at every load a suite other than the hybrid IK suite (`IKhfs`
included: its authentication is classical), a role missing from `require_hybrid_identity`, a v1
CA key and, on the client, a certificate that is not v2 and hybrid-bound. `check` lists the
classical paths a configuration still accepts, and the running relay and agent log the same
(`pq_only_profile`, `classical_paths_accepted`). Removing the v1 code is left to a later major
release, if ever.

The catalogue item above (Parsing/State rows reused as negative tests) was **not** done as
written, because no code path was removed: each row would test a path that still exists and is
still covered by its own phase's tests. What the profile adds is a load-time refusal, so its
negative tests are per setting instead. `crates/zt-net/tests/pq_sunset.rs` loads each file that
keeps one classical path through the binaries' loading code, checks that the profile refuses it
and that the same file loads without the profile, and checks a reload under the profile on the
wire (review 0014, A14-5, A14-6).

---

## 8. Decisions for the user

| # | Decision | Options | Recommended | Reasoning |
| :-: | :- | :- | :- | :- |
| D1 | End-state handshake | PQNoise-style hybrid IK (Noise) / TLS 1.3 + X25519MLKEM768 | **Hybrid IK on Noise** | Keeps silent rejection, IK 1-RTT, sans-IO typestate, cert in msg1, and no C TCB; TLS only for a FIPS mandate |
| D2 | PQ-1 construction | (b) IKhfs / (a) IKpsk2 + static-KEM PSK / (a2) ephemeral pre-round PSK / (e) jump straight to hybrid IK | **(b) IKhfs ML-KEM-768** | PQ forward secrecy, no new keys or pins, no RTT, no unauthenticated KEM work. (a) needs static keys and lacks PQ-FS; (a2) costs +1 RTT per channel; (e) delays HNDL protection behind PQ-3's key migration |
| D3 | How to get ML-KEM into snow | upstream PR / vendored patched snow (path dependency) / label hack / switch to clatter | **Upstream PR, vendored patch as fallback** | Smallest diff, same library; the label hack makes the transcript lie; clatter has no HFS |
| D4 | KEM primitive and level | ML-KEM-768 / ML-KEM-1024 / X-Wing | **ML-KEM-768** inside Noise | Noise already provides the hybrid combiner and transcript binding; 1024 only for CNSA 2.0 |
| D5 | ML-KEM implementation | libcrux-ml-kem / RustCrypto ml-kem / aws-lc-rs | **libcrux-ml-kem** (pinned), RustCrypto as test oracle | Formal verification of portable/AVX2 and an OpenSSH lineage (unverified); pure-Rust oracle catches divergences such as the aarch64 GHSA |
| D6 | FIPS | none / aws-lc-rs fips | **None** unless mandated | Noise 25519/ChaChaPoly/BLAKE2s is not approved anyway; FIPS means a TLS redesign and a C TCB |
| D7 | Migration style | hard cutover / negotiated (pinned initiator, responder `min`) | **Negotiated, never auto-downgrading** | HA fleets and outbound-only agents cannot flip at once; pins plus `min` plus audit events stop A2 |
| D8 | Layers in PQ-1 | E2E only / both | **Both in one release, E2E enabled first** | Same code; outer HFS also protects E2E msg1 and stream metadata from the network |
| D9 | Certificate signature | ML-DSA-44 / ML-DSA-65 / ML-DSA-87 / pure ML-DSA / composite ML-DSA-65+Ed25519 / SLH-DSA | **Composite ML-DSA-65 + Ed25519, AND** | Hedges ML-DSA immaturity (two 2026 CVEs) with Ed25519 and Ed25519 with ML-DSA; cat. 3 matches the KEM; ≤ 7.6 KB fits easily |
| D10 | SLH-DSA for the CA root | yes (direct) / yes (root over ML-DSA intermediate) / no, reserved codepoint | **No for client certs; yes for the release root (PQ-4)** | Per-handshake DoS cost and size; single-tier offline CA; SLH-DSA suits rare, long-lived signing |
| D11 | ML-DSA implementation | RustCrypto ml-dsa / libcrux-ml-dsa / aws-lc-rs | **RustCrypto ml-dsa ≥ 0.1.1** plus libcrux-ml-dsa differential tests and Wycheproof | Complete FIPS 204 API with `ctx`; both had hint-parsing bugs, so differential plus vectors is the real control; signing is offline |
| D12 | ML-KEM static key source | derived from the existing Ed25519 seed / new random seed in key file v2 | **Derived** (`SHAKE256("TCN ML-KEM-768 seed v1\0" ‖ seed)` → (d, z)) | No new secret file; key files, permissions and rotation unchanged; choose a random seed if FIPS key-generation provenance is ever required |
| D13 | v2 public key in configs | full hex in TOML (2 432 chars) / fingerprint plus sidecar key bundle / extra RTT to fetch the key | **Full hex in TOML** | IK needs the responder's `ek` before msg1; no TOFU, no extra RTT; tooling prints the line |
| D14 | PQ authentication of the initiator | KEM (hybrid IK `skem` both ways) / client ML-DSA signature over the transcript | **KEM** | Keeps "node keys never sign"; the analysed PQNoise construction; no signing oracle on clients |
| D15 | PQ-3 implementation | `clatter` (`noise_hybrid_ik`, after internal review, `default-features = false`) / own minimal implementation / snow extension (hfs + psk0 + static-KEM-in-prologue) | **Spike in PQ-3 RED; default to clatter-after-review**, with cross-checks against an independent reimplementation of the pattern in tests | Implements the PQNoise patterns directly; risk is maturity, mitigated by review, pinning, vectors and fuzzing; keep the snow path as a fallback |
| D16 | Deprecation of v1 | fixed date / after N releases / when audit events show zero legacy handshakes for 30 days | **Event-driven plus a fixed upper bound** | Measurable from the audit stream; avoids an indefinite tail |

---

## 9. Side findings (not PQ-specific)

1. **Double-counted tag in the message 1 size proof.** `NOISE_MSG1_OVERHEAD = 96` already
   includes the 16-byte payload tag (`e` 32 + encrypted `s` 48 + tag 16). PROTOCOL §15.3
   ("`96 + 4 328 + 16`") and the const assertions in `crates/zt-domain/src/limits.rs` add
   `NOISE_TAG_LEN` again. This is harmless (conservative), but `agent.rs` `MAX_MSG1_LEN = 96 +
   4 328` is the exact value, so the documents disagree with the code. Fix when the constants
   become per-suite in PQ-1.
2. **Handshake versioning does not exist.** PROTOCOL §3 says "the only evolution mechanism is the
   `version` byte", which is true for frames but not for handshakes (the v1 msg1 is
   indistinguishable random bytes). PQ-0/PQ-1 must add the envelope (§6.1) and update the
   specification's wording.

---

## 10. Sources and unverified claims

Sources (accessed 2026-11-09):

- RustCrypto `ml-kem` 0.3.4: https://docs.rs/crate/ml-kem/latest
- RustCrypto `ml-dsa` 0.1.1: https://docs.rs/crate/ml-dsa/latest
- RUSTSEC-2025-0144 (ml-dsa timing): https://rustsec.org/advisories/RUSTSEC-2025-0144
- CVE-2026-24850 (ml-dsa repeated hint indices): https://osv.dev/vulnerability/CVE-2026-24850
- RustCrypto `slh-dsa`: https://docs.rs/crate/slh-dsa/latest, https://docs.rs/crate/slh-dsa/0.2.0-rc.5
- RustCrypto `x-wing` 0.1.0: https://docs.rs/crate/x-wing/0.1.0
- `libcrux-ml-kem` 0.0.11: https://docs.rs/libcrux-ml-kem
- `libcrux-ml-dsa` 0.0.11: https://docs.rs/crate/libcrux-ml-dsa/latest
- Cryspen ML-KEM verification: https://cryspen.com/post/ml-kem-verification/
- GHSA-2cgv-28vr-rv6j (libcrux aarch64): https://advisories.gitlab.com/cargo/libcrux-ml-kem/GHSA-2cgv-28vr-rv6j/
- Symbolic Software on libcrux proofs: https://www.symbolic.software/blog/2026-02-12-cryspen-response
- Cryspen PSQ: https://cryspen.com/post/psq-announce/
- `aws-lc-rs` 1.19.0: https://docs.rs/crate/aws-lc-rs/latest ; `aws-lc-sys` 0.47.0: https://docs.rs/crate/aws-lc-sys/latest
- AWS-LC 3 FIPS cert #5314 (ML-KEM approved): https://sec-certs.org/fips/1e0b605fa2f516ae/ ; CMVP #5429: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5429 ; AWS blog: https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation
- PQClean archived, pqcrypto unmaintained: https://rustsec.org/advisories/RUSTSEC-2026-0164 , https://rustsec.org/advisories/RUSTSEC-2026-0161
- `oqs` 0.11.0: https://docs.rs/crate/oqs/latest/
- Project Eleven survey (July 2025): https://www.projecteleven.com/blog/the-state-of-post-quantum-cryptography-in-rust-the-belt-is-vacant
- `clatter`: https://docs.rs/crate/clatter/latest , https://github.com/NicsTr/clatter , patterns: https://docs.rs/clatter/latest/clatter/handshakepattern/fn.noise_hybrid_ik.html , https://docs.rs/clatter/latest/clatter/handshakepattern/fn.noise_pqik.html
- `snow` features (hfs, Kyber1024 only): https://docs.rs/crate/snow/latest/features , https://docs.rs/crate/snow/latest/source/src/params/mod.rs , https://docs.rs/crate/snow/latest/source/src/constants.rs
- Noise HFS extension: https://github.imc.re/noiseprotocol/noise_hfs_spec/blob/master/noise_hfs.md (mirror of github.com/noiseprotocol/noise_hfs_spec)
- PQNoise (Angel, Dowling, Hülsing, Schwabe, Weber, CCS 2022): https://eprint.iacr.org/2022/539
- rustls PQ defaults: https://docs.rs/crate/rustls/latest/source/src/manual/defaults.rs ; https://docs.rs/rustls-post-quantum
- Composite signatures draft: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
- OpenSSH 10.0 (mlkem768x25519-sha256 default): https://www.openssh.org/txt/release-10.0
- Rosenpass: https://bienkma.github.io/books/rosenpass-whitepaper.pdf (mirror of the whitepaper)

Unverified (check before relying on them):

- Benchmark ranges in §3.5 (to be measured in PQ-0).
- `unsafe` usage in RustCrypto `ml-kem`/`ml-dsa`; KyberSlash-style constant-time status of
  RustCrypto `ml-kem`; exact libcrux feature names for portable-only builds.
- OpenSSH's ML-KEM code being derived from libcrux.
- snow's `CryptoResolver::resolve_kem` hook and support for psk modifiers combined with `hfs`
  or `IKpsk0`; whether snow upstream already plans ML-KEM.
- clatter license, maintainer count, and whether the responder's `e` in `noise_hybrid_ik`
  carries a KEM key (affects msg2 size).
- Whether rustls 0.23.46 enables `prefer-post-quantum` by default; current stability of the
  ML-DSA API in aws-lc-rs.
- aws-lc-sys license expression against `deny.toml` (may need extra entries).
- Paramiko PQ KEX support; PQ KEX availability in RHEL 9/10 FIPS mode; SSH composite signature
  drafts (e.g. `draft-miller-sshm-mldsa65-ed25519-composite-sigs`) being deployed.
- `libcrux-ml-dsa` and `libcrux-psq` licenses.
