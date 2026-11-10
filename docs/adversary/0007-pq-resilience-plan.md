# Adversary review AP: post-quantum and resilience plans (pre-implementation)

**Surface:** two design analyses, not code:
`../analysis/pq.md` (hybrid Noise IKhfs X25519+ML-KEM-768, handshake version envelope, composite
ML-DSA-65+Ed25519 certificate v2, hybrid identities / fingerprint v2, crate choices, PQ-0 … PQ-5)
and `../analysis/resilience.md` (admission and refund, per-identity bucket, separate pools,
backoff and liveness, hedged failover, drain, supervision and watchdog, restart policy,
metrics, efficiency, R-1 … R-6). Every load-bearing claim was checked against `main` at
`dfb3b8b` (`crates/`, `bins/`, `packaging/systemd/`, `docs/PROTOCOL.md`, `docs/OPERATIONS.md`,
`docs/adversary/0001`–`0006`), against the sources of `snow 0.10.0` and `tokio-util 0.7.20`
fetched with `cargo fetch --locked` (the repository was not modified), and against crates.io,
RustSec/GHSA and openssh.org (2026-11-09).

**Reviewer:** an independent adversary agent. It did not write the plans and did not take
their reasoning on trust. The encrypted project instructions (`.claude/private/…`) were **not**
visible to it. Like the plans themselves, this review relies only on the public documents and
the code.

**Attacker model:**
- (a) a remote host with no credentials;
- (b) an on-path recorder that can **replay** captured handshake messages;
- (c) the holder of one valid or stolen identity;
- (d) one compromised relay;
- (e) a future CRQC, either passive (harvest-now-decrypt-later) or live;
- (f) operator error during a mixed-fleet rollout.

Severity uses the 0001–0006 scale: **high** blocks the plan as written, **medium** must change
before RED, and **low** / **info** are fixed in the phase that touches them.

## Findings

| # | Sev. | Surface |
| :-: | :-: | :- |
| AP-1 | **high** | R-1 refund on success, separate pools, per-identity bucket |
| AP-2 | medium | R-1 per-identity bucket against the Ansible use case |
| AP-3 | medium | D-12 aggregated pre-auth logging, PQ `legacy_handshake_accepted` |
| AP-4 | medium | R-3 watchdog heartbeat; the hub's `Tick` today |
| AP-5 | medium | PQ composite verification order, ML-DSA verifier exposure |
| AP-6 | medium | PQ-3 / cert v2: fingerprint v1/v2 confusion in denylist, pins and display |
| AP-7 | medium | PQ §6.1 envelope: `hs_version` vs `suite`, numeric `min` |
| AP-8 | medium | Phase ordering between the two plans |
| AP-9 | medium | PQ-2 claimed value without PQ-3 |
| AP-10 | medium | R-4 hedged failover under overload |
| AP-11 | low | PQ §6.1 plaintext magic: passive fingerprinting |
| AP-12 | low | PQ-3 hybrid IK: KEM authentication of the initiator only after msg2 |
| AP-13 | low | cert v2: algorithm/key binding, component-key reuse |
| AP-14 | low | D3 snow: upstream status, HFS code path, an alternative not considered |
| AP-15 | low | D15 clatter: facts and two Noise stacks in the TCB |
| AP-16 | low | R-1 per-source budget loosened while PQ makes handshakes costlier |
| AP-17 | low | R-3 restart policy contradicts "configuration errors fail the unit" |
| AP-18 | low | R-3 watchdog/`panic = "abort"` core dumps contain key material |
| AP-19 | low | PQ-4 `verify-release` is circular; composite release signature can be stripped by the verifier |
| AP-20 | low | R-1 `msg1_deadline` 3 s vs multi-segment PQ msg1 |
| AP-21 | low | R-3 drain: simultaneous relay restarts; D-10 HTTP listener |
| AP-22 | low | R-6 window auto-tuning before the global byte budget |
| AP-23 | info | IKhfs: exact security properties the plan must state |
| AP-24 | info | Factual errors and corrections |

---

### AP-1 (high): a replayed message 1 counts as "authenticated success". Refund, the pool move and per-identity charging can then be driven by an attacker with no keys

**Surface:** resilience §5.1 "Refund on authenticated success … once the policy has admitted the
peer *and* msg2 has been sent", "Separate pools … Handshake slots are released when msg1 is
done", "Per-identity bucket … keyed by fingerprint"; R1-A7.

**Attack hypothesis:** the attacker records one outer msg1 of any legitimate client or agent
(on path, or as a compromised relay for the E2E msg1). IK msg1 is replayable (PROTOCOL §7.3,
§15.3, finding 0002-3): the responder authenticates the claimed static key and runs the policy
on it, then sends msg2. Under the proposed rule, that is "success". So the attacker, from one
IP address and with no keys:
1. **Bypasses the per-source gate.** Every replay is refunded, so the per-IP budget never
   drops.
2. **Fills the authenticated pool.** The connection leaves the pre-auth pool when msg1 is done.
   In the relay core a *client* connection has no first-frame deadline: `register_timeout`
   applies only to `Role::Agent` (`zt-application/src/relay.rs:348–360`). The only limit is the
   90 s idle timeout (`zt-net/src/relay.rs` `serve`). With a per-identity budget of 64 + 10/s,
   one recorded identity holds about 964 slots for 90 s. Nine recorded identities exhaust a
   pool of 8 192.
3. **Drains the victim's per-identity bucket.** This is a targeted DoS: the real agent or client
   with that key is then refused.
4. **Costs the responder full work on every replay.** That means 4 DH, plus ML-KEM encapsulation
   in `accept()` in PQ-1, plus the certificate signatures in PQ-2. PROTOCOL §15.3 justifies the
   cost of a replay with "within the handshake limit (§10)". Refunding removes exactly that
   limit.

**Evidence:**
- `zt-net/src/relay.rs`: `admit` → `pending.establish` (msg2) → `HubEvent::Connected`, with
  nothing between msg2 and the core.
- `ratelimit.rs`: the gate is charged at `accept` (today it is never refunded, which is what
  keeps replays bounded now).
- The R1-A7 catalogue row tests a race with reload, not replay.

**Required change:**
- Define "authenticated success" as **key confirmation**: the first authentic transport frame
  from the initiator (`Register` for an agent, any frame for a client, `TCN/2 ready` E2E).
- Refund, the move to the authenticated pool and the per-identity charge all happen only then.
  Until then the connection stays in the pre-auth pool and counts against the source budget.
- Add a `first_frame_deadline` (≈ 5 s) for **clients** too, mirroring `register_timeout`.
- Add catalogue rows: `replayed_msg1_is_not_refunded`, `replayed_msg1_does_not_enter_the_authenticated_pool`,
  `replayed_msg1_cannot_drain_the_victims_identity_budget`.
- Keep PROTOCOL §15.3's cost argument true.

### AP-2 (medium): the per-identity bucket throttles the case R-1 is meant to fix

**Surface:** resilience §5.1 per-identity bucket (example: burst 64, 10/s); R1-A1; R-4 hedging.

**Attack hypothesis / failure:**
- An Ansible controller is **one** client identity: one `client.key`, and each `zt-client`
  process uses it. With `forks = 50` against 200 hosts it opens about 200 outer handshakes in a
  few seconds. A bucket of 64 + 10/s admits about 114 in 5 s, so the rest fail. R1-A1 ("200
  authenticated clients from one IPv4 address … all admitted") therefore contradicts the
  proposed default.
- Hedging (R-4) consumes the same identity's budget twice.
- The bucket defends against "a stolen key in a tight loop". That case is already bounded by
  the per-source gate, and with AP-1 by the failure budget too.

**Required change:**
- Make the per-identity control a **concurrency** limit on simultaneous pre-confirmation
  handshakes (for example 64), not a rate. Or make it configurable per policy entry, with a
  default sized for `forks × hosts`.
- Charge it only on key confirmation (AP-1).
- R1-A1 must use a single identity.

### AP-3 (medium): "per-event only once Noise has proven an identity" does not stop the log flood

**Surface:** D-12, G10, R1-A9; PQ §6.2 `legacy_handshake_accepted` (WARN per v1 handshake).

**Attack hypothesis:**
- "`peer` present" only means the initiator owns *some* static key, and anyone can generate a
  fresh key per connection. A scanner that speaks Noise then gets one
  `authentication_failed{peer=…}` WARN per connection, at the per-source rate, from any number
  of addresses. journald's 10 000 / 30 s limit then drops real audit events, exactly as in G10.
  Replayed msg1s (AP-1) also produce per-event lines that name a real victim.
- Separately, the PQ plan emits one WARN for **every** v1 handshake while v1 is still the
  majority. Ansible bursts become thousands of WARN lines.

**Required change:**
- Log per event only for identities that are **known** to the configuration (whitelisted, bound
  by a pinned-CA certificate, or in the denylist). Unknown keys go into the aggregated summary,
  counted with `distinct_keys` but not named.
- `legacy_handshake_accepted` is aggregated per peer per interval (first occurrence plus hourly
  counts).
- Test: `noise_speaking_scanner_with_fresh_keys_cannot_crowd_out_audit_events`.

### AP-4 (medium): the watchdog heartbeat "hub processed a `Tick` within 5 s" gives false positives on a busy relay, and `Tick` can already be starved today

**Surface:** resilience §5.4 watchdog, R3-C6; `zt-net/src/relay.rs` `hub`.

**Evidence:** the hub loop is `tokio::select! { biased; policy.changed(), events.recv(), tick.tick() }`.
With `biased`, the tick branch is selected only when both of the others are pending. Every data
frame of every connection goes through `events` (`HubEvent::Core(Input::Received)`). Under
sustained load (a reconnect herd plus bulk `copy`), `events` can stay ready, and then:
1. The proposed heartbeat fails although the hub is making progress. After 60 s systemd kills a
   healthy, overloaded relay. That cuts every session and causes a reconnect herd. An attacker
   who can cause overload can turn "slow" into "down", and with `StartLimitIntervalSec=0`
   (D-14) the relay ends up in a restart loop.
2. **Already today**, `Input::Tick` drives the agent `register_timeout` and the relay's 1 s
   certificate-expiry recheck (PROTOCOL §15.7). Under saturation both are delayed by an unbounded
   amount. This is unverified under real load: it needs a test.

**Required change:**
- The heartbeat is a **progress counter**: any input processed since the last kick. It is not
  "a `Tick` was processed".
- Make the tick non-starvable: check a deadline on every loop iteration, or put `tick` before
  `events` in the biased order.
- Add tests `tick_is_not_starved_by_a_saturated_event_queue` and
  `watchdog_does_not_fire_on_a_busy_but_progressing_hub`.

### AP-5 (medium): verify Ed25519 **before** ML-DSA, so that ML-DSA parser bugs are reachable only by insiders

**Surface:** PQ §4.4 check order "6a ML-DSA, 6b Ed25519"; D9, D11.

**Evidence (2026 advisories, verified):**
- `libcrux-ml-dsa` (the plan's oracle):
  - RUSTSEC-2026-0076: **a panic during verify** from malformed hints, network-reachable,
    CVSS 8.7.
  - RUSTSEC-2026-0077: wrong norm check, so it accepted invalid signatures.
  - RUSTSEC-2026-0125 / GHSA-fhvh-vw7h-9xf3: AVX2 `use_hint` (needs a malicious verification
    key).
  - RUSTSEC-2026-0126: AVX2 reduction.
- RustCrypto `ml-dsa`:
  - RUSTSEC-2025-0144 / CVE-2026-22705: timing.
  - CVE-2026-24850: repeated hint indices accepted (fixed 0.1.0-rc.4).
  - GHSA-h37v-hp6w-2pp8: `use_hint` off by two, which **rejects valid signatures** (fixed
    0.1.0-rc.5).
- The latest RustCrypto release is **0.1.2 (2026-10-31)**, not 0.1.1.

With `panic = "abort"`, a panic in a dependency's verifier is a remote crash of every relay and
agent. TCN's `clippy::panic`/`unwrap_used` lints do not apply to dependencies.

**Attack hypothesis:** with ML-DSA verified first, any host (a) can generate its own static
key, write a well-formed certificate bound to it (so step 4 passes), and put arbitrary bytes in
`sig_M`. The ML-DSA decoder is then reachable without credentials.

**Required change:**
- Order: binding (4) → pinned CA by `ca_fp` (5) → **Ed25519 `verify_strict` (6a)** → ML-DSA
  (6b), with both mandatory. Before a CRQC exists, only a holder of a valid CA-signed TBS for
  their **own** authenticated key (an insider) can reach the ML-DSA code, and Ed25519 is also
  the cheaper check.
- `zt-ca sign` verifies after signing with the **same verifier and exact version** the fleet
  uses. Pin with `=`, so that a GHSA-h37v-class divergence cannot make the fleet accept or
  reject a certificate differently.
- Require `ml-dsa ≥ 0.1.2`, not 0.1.1.
- Fuzz target `cert_v2_verify` with valid Ed25519 and mutated `sig_M`.

### AP-6 (medium): fingerprint v1/v2 confusion can let a revoked key back in during the migration

**Surface:** PQ §4.4 (`subject_key` replaced by a typed `subject_fp`), §4.6, §6.5, PQ-3
denylist "matches both fingerprints"; PROTOCOL §15.8; OPERATIONS §10.

**Attack hypothesis:**
- The initiator chooses the handshake version, and responders accept v1 while
  `min_handshake_version ≤ 1` (the whole of PQ-3's migration). A thief with a stolen seed
  connects with **v1**, which exposes only the X25519 key.
- Today the denylist stores **public keys** (`keys = [...]`, converted to the X25519
  fingerprint at load), so v2 keys would still allow the v1 fingerprint to be derived.
- But certificate v2 drops `subject_key`, and the issuance log records "fingerprint", which
  OPERATIONS §10.3 says "is needed to revoke". An operator revoking from a v2 certificate or
  from the log then has only a **v2 fingerprint** (`SHA-256(… ‖ x25519 ‖ ek)`). A v2 fingerprint
  cannot be mapped back to the X25519 identity, so the denylist entry does not match the
  thief's v1 handshake. The same happens in the other direction for a v2 entry in policy or
  audit queries.
- Both versions are displayed as `SHA256:<hex>`, so nothing distinguishes them in files, logs
  or `zt-ca inspect`.

**Required change:**
- The **revocation unit is the X25519-level (v1) fingerprint**, always computable from any
  handshake version.
- Certificate v2 with `subject_kind = 0x02` also carries (or `zt-ca` logs) the X25519
  fingerprint.
- The denylist accepts keys, or v1 fingerprints only. A v2-only entry is a load error.
- v2 fingerprints get a distinct display prefix (for example `SHA256v2:`). Loaders reject a v2
  fingerprint where v1 is expected and vice versa.
- Test: `a_key_revoked_by_its_v2_identity_cannot_connect_with_a_v1_handshake`.

### AP-7 (medium): two version fields and a numeric `min` create ambiguity in negotiation

**Surface:** PQ §6.1–6.2, PQ-5.

**Evidence:** the plan is internally inconsistent:
- The envelope has `hs_version` **and** `suite`, and both prologues are `"TCN/2 …"`.
- Suite 0x01 is PQ-1 and suite 0x02 is PQ-3.
- Pins are `handshake = 1 | 2 | 3`, and PQ-5 sets `min_handshake_version = 3`.

So it is not clear what `(hs_version = 2, suite = 0x02)` and `handshake = 3` mean, or which byte
the responder uses for dispatch. A numeric `min` also assumes the suites are totally ordered by
security. A future suite (ML-KEM-1024, or a suite that turns out to be broken) breaks that
ordering, and "min ≥ N" would then accept it.

The default changes "1 in the PQ-1 release, 2 in the next". Because of that, a binary upgrade
silently cuts off v1 initiators fleet-wide.

**Required change:**
- Use **one** identifier: `suite` (u8), carried in the envelope and mixed into the prologue
  (`"TCN/2 outer" ‖ suite`).
- Initiators pin exactly one suite per peer.
- Responders configure an explicit **accepted set**, per role (agents and clients separately:
  laptops form the long tail).
- No ordering comparisons.
- No default that changes between releases: the accepted set is explicit configuration, with
  an audit event at startup.

### AP-8 (medium): the phase ordering across the two plans delays the urgent HNDL fix, and is justified with inflated PQ costs

**Surface:** resilience §1 and §6 ("R-1 to R-3 should ship before PQ"), §4; PQ §7.

**Evidence:**
- **HNDL is the only threat that is already happening** (PQ §1). Every month spent on R-2 (a
  turmoil harness, size M–L) and R-3 is a month of recordable SSH traffic.
- The resilience plan's PQ numbers are wrong for PQ-1:
  - The *responder* **encapsulates** in IKhfs; it does not decapsulate (snow `Token::Ekem1`
    write path).
  - Agents send no certificate, so an agent reconnect is about 150 B today and about 2.4 KB
    with PQ-1, not "5–12 KB". A 4 000-agent herd is about 10 MB, not 20–50 MB.
  - Responder CPU grows by +15–45 % (one encapsulation on top of 4 X25519), not 2–4×.
- **PQ-1 on E2E needs only agent and client upgrades.** It needs no relay restarts, so drain
  and herd control are not prerequisites.
- Rolling relay restarts already work with HA (PROTOCOL §13: agents are active-active, and
  clients fail over before `OpenAck`). Drain only saves the sessions that are open at that
  moment.

**Required change:** a combined order:
1. PQ-0 ∥ R-1 (with AP-1/AP-2 fixed).
2. PQ-1 **E2E**.
3. R-2/R-3 ∥ PQ-1 outer, rolled out with HA rolling restarts.
4. R-4/R-5.
5. PQ-2 + PQ-3 as one authentication milestone (AP-9).
6. R-6.

Correct the PQ cost table in resilience §4.

### AP-9 (medium): PQ-2 alone does not stop a live CRQC from impersonating clients

**Surface:** PQ §1 item 4, §2.3 priority 3, §7 "PQ-2 … does not depend on PQ-3".

**Attack hypothesis:**
- A live CRQC does not need to forge the CA. It recovers a client's X25519 secret from the
  public key (which is in the policy, in the recorded outer msg1 and in the certificate). It
  then presents that client's **own** valid certificate. Certificates are not secret, and the
  CRQC decrypts them from recorded msg1s. A fresh one appears every day because of the short
  TTL.
- Until PQ-3, `subject_kind = 0x01` binds the certificate to a classical key. Relays and agents
  are impersonable in the same way.
- So PQ-2 prevents only **scope expansion** (minting new names or nodes). For an admin with
  `--all-nodes`, impersonating that admin is equivalent to forging the CA.

**Required change:**
- State plainly that PQ-2 gives **no** live-CRQC protection on its own.
- Plan PQ-2 and PQ-3 as one milestone that must be complete before a CRQC exists. PQ-2 can
  still be implemented first.
- Do not market PQ-2 as closing A3.

### AP-10 (medium): hedging doubles load exactly when relays are slow

**Surface:** resilience §5.3 / D-4 ("start relay i+1 … after a stagger of 2 s with no `OpenAck`").

**Evidence:** the agent answers `Open` with `OpenAck` **immediately**, before it contacts sshd
(`zt-net/src/agent.rs` `on_relay_frame`). sshd is contacted only after `TCN/1 ready`. So once
the outer handshake has completed, a missing `OpenAck` after 2 s means the relay (its hub or its
CPU) is overloaded. It does not mean the relay is dead. If every client hedges at that point,
handshakes double across the fleet during overload. That is a metastable failure: hedges add
load, which slows the relays, which causes more hedges. The relays also share the same
agents' per-relay stream slots.

**Required change:**
- Hedge only while relay *i* has **not** completed TCP connect plus the outer handshake within
  the stagger. That is the black-hole signal R-4 targets.
- Once relay *i* has completed the handshake, wait for `OpenAck` up to the per-step timeout and
  do not hedge.
- Add an overload catalogue row: `hedging_does_not_amplify_a_slow_but_alive_relay` (sim).

### AP-11 (low): a plaintext `"TCN"` magic makes TCN and its PQ status visible to passive observers

**Surface:** PQ §6.1.

**Evidence:**
- Today msg1 starts with a uniformly random X25519 `e`. The PQ plan argues against TLS because
  the relay must stay invisible (§3.2d).
- A fixed magic plus version and suite bytes lets any passive observer classify TCN flows and
  pick out the **still classical** ones, which are the best HNDL targets.
- It also enables cheap DPI blocking of v2. That is only a DoS, because pinned initiators do not
  fall back.

**Required change:** choose explicitly between:
- (a) dispatching without a magic, by trial: v2 first if `len ≥ 1 280`, else v1. The cost is
  bounded by keys × 2, and an unauthenticated v2 read does no KEM work.
- (b) keeping the magic and documenting the loss of indistinguishability.

The reviewer prefers (a).

### AP-12 (low): in PQ-3 the initiator's KEM authentication completes only after msg2

**Surface:** PQ D14/D15 (`-> skem, e, es, s, ss / <- ekem, skem, e, ee, se`).

**Attack hypothesis:**
- The responder proves the initiator's ML-KEM key only when the initiator's first transport
  message decrypts. Before msg2 it has only the classical `ss`.
- Against a live CRQC (which recovers the X25519 secret), the policy decision and the "silent
  rejection" before msg2 are therefore classical-strength. The relay sends msg2 to an attacker
  who claims a whitelisted identity, which makes it a membership oracle.
- `HubEvent::Connected` also happens before key confirmation.

**Required change:**
- Document this in PROTOCOL.
- Make key confirmation (AP-1) the point at which a v3 connection becomes `Connected` in the
  core and is charged against identity-keyed accounting.
- Add catalogue row: "CRQC-capable impostor passes the pre-msg2 check, fails at key
  confirmation, leaves no session and no identity-named success event".

### AP-13 (low): bind the certificate algorithm to the pinned key; forbid component-key reuse

**Surface:** PQ §4.3–4.4, §6.5.

**Hypothesis:**
- `ca_fp = SHA-256("TCN CA fingerprint v2\0" ‖ ca_pub_v2)` does not include the algorithm.
  `sig_alg` is read from the certificate, and 0x03/0x04 are reserved. A future verifier that
  takes the algorithm from the certificate rather than from the pinned key's type opens
  algorithm confusion.
- The plan forbids a composite whose Ed25519 half equals a v1 CA key "in **another** entry".
  It does not forbid that within the **same** entry during migration
  (`public_keys = [v2, v1]`). Reuse is not exploitable here, because CTX1 ≠ CTX2, but it goes
  against the composite draft's guidance and keeps v1 key material alive inside v2.

**Required change:**
- Include `sig_alg` in the `ca_fp` input.
- Require `cert.sig_alg == pinned_key.alg`; the algorithm always comes from the pinned key.
- At load, reject a composite Ed25519 component equal to **any** pinned Ed25519 CA key, peer key
  or own key (the 0006-1/2 class).

### AP-14 (low): snow: "upstream PR in time" is unrealistic, and an alternative is missing

**Surface:** D3.

**Evidence:**
- `snow` 0.10.0 is the latest release (**2025-07-19**, crates.io), about 16 months without a
  release. `KemChoice` is a closed enum with only `Kyber1024` (`params/mod.rs:128`), and
  `MAXKEMPUBLEN` / `MAXKEMCTLEN` are 4096. The plan's claims are correct.
- The HFS paths use `unwrap()` (`handshakestate.rs` `Token::Ekem1`: `self.kem.as_mut().unwrap()`,
  `self.kem_re.as_ref().unwrap()`). With valid patterns these do not look reachable, but this is
  the least-exercised code in the TCB and runs under `panic = "abort"`.
- Not considered by the plan: stock snow 0.10.0 exposes `get_handshake_hash()` and
  `TransportState::rekey_manually()`. A **post-handshake KEM ratchet** would work like this:
  - `ek` goes in the first transport message (for example `TCN/2 ready ‖ ek`) and `ct` in the
    reply.
  - Both sides switch to `k' = HKDF(h ‖ split, ss)`.
  - This gives PQ forward secrecy without forking snow. It is a homegrown construction, though,
    and on the outer channel it needs a framing change.

**Required change:**
- Treat a **vendored, minimal, reviewed snow patch** as the primary path. The upstream PR is
  opportunistic.
- Fuzz the HFS paths for panics.
- Evaluate the stock-snow ratchet in the PQ-0 spike as the fallback, instead of (a2) with its
  extra RTT.

### AP-15 (low): clatter facts; avoid two Noise stacks

**Surface:** §5 table, D15.

**Evidence (crates.io / docs.rs):** `clatter` 2.3.0 (2026-08-30):
- License **MIT** (allowed by `deny.toml`). The plan says "unverified".
- Default features include **both** `use-pqclean-ml-kem` (→ `pqcrypto-mlkem`, which RUSTSEC-2026-0161
  marks unmaintained, so `cargo deny` fails) and `use-rust-crypto-ml-kem` (→ `ml-kem` **0.2.1**,
  while the current line is 0.3.4).
- It brings its own `x25519-dalek` 2.0.1, `sha2` 0.10.9 (the workspace uses 0.11), `blake2`
  0.10.6 and `chacha20poly1305` 0.10.1.

Choosing it for PQ-3 alone means two Noise implementations and duplicate primitive versions in
the TCB until PQ-5.

**Required change:** the D15 spike decides between:
- (a) clatter for **all** suites, with libcrux plugged in through its KEM trait and
  `default-features = false`;
- (b) extending the same vendored snow.

It must not keep snow for v1/v2 and clatter for v3.

### AP-16 (low): the plan loosens the unauthenticated budget while PQ makes it costlier

**Surface:** resilience §5.1 "per-source unauthenticated burst 32 at 1/s".

**Evidence:**
- A refill of 1/s is three times today's 1 per 3 s (PROTOCOL §10). That contradicts D-1's
  "without loosening unauthenticated protection".
- PQ-2 adds a signature check per well-formed attacker certificate (cheaper with AP-5).
- PQ-3 adds a static decapsulation per unauthenticated msg1, times the number of keys.

**Required change:** keep the failure refill at 1 per 3 s, or derive it from PQ-0 measurements
with the cost-based gate. Raise only the burst, if the measurements justify it.

### AP-17 (low): the restart policy contradicts "configuration errors at startup still fail the unit"

**Surface:** D-14, §5.4.

**Evidence:** `Restart=always` with `StartLimitIntervalSec=0` restarts a configuration error
forever, every 2 s, or up to every 60 s with `RestartSteps`.

**Required change:** use a dedicated exit code for configuration errors (for example 78,
`EX_CONFIG`) and `RestartPreventExitStatus=78`, and test it.

### AP-18 (low): watchdog `SIGABRT` and `panic = "abort"` leave key material in core dumps

**Surface:** R-3 watchdog; `Cargo.toml` `panic = "abort"`; `packaging/systemd/*.service`.

**Evidence:**
- systemd's default `WatchdogSignal` is SIGABRT, and an abort produces a core. With
  systemd-coredump, the current static key, the previous key, and the session and transport
  keys of every open connection then land in `/var/lib/systemd/coredump`. That undermines the
  forward secrecy that rekey provides.
- The units do not set `LimitCORE`.

**Required change:** add `LimitCORE=0` to both units, and/or `prctl(PR_SET_DUMPABLE, 0)` at
startup (`rustix` `process` is already a dependency), and document it.

### AP-19 (low): PQ-4 `zt-* verify-release` is circular

**Surface:** PQ-4.

**Hypothesis:**
- A downloaded binary that verifies itself proves nothing.
- OpenSSL ≥ 3.5 can verify SLH-DSA and Ed25519 **separately**, but not a TCN-specific composite
  format. A user who checks only the Ed25519 half strips the AND.
- `slh-dsa` 0.2 is still a release candidate.

**Required change:**
- Publish two standard detached signatures, both required by the documented procedure.
- The **already-installed** binary, or OpenSSL, verifies the new release.
- Do the signing offline with OpenSSL, so that no `slh-dsa` crate enters the shipped binaries.

### AP-20 (low): `msg1_deadline` of 3 s conflicts with the plan's own "keep ≥ 5 s"

**Surface:** resilience §4 vs §5.1/§5.3.

**Evidence:** a PQ-3 msg1 with a v2 certificate is about 11 KB, which is 8 or more TCP segments.
One loss costs at least one RTO, and slow links add time on top.

**Required change:** set `msg1_deadline` ≥ 5 s, or derive it from the suite's maximum msg1.
Add a test with netem loss.

### AP-21 (low): drain and metrics details

**Surface:** D-6, D-10.

- **Drain.** Restarting all relays at once (for example Ansible `serial: 100%`) now closes every
  listener for up to `--drain-timeout`. The outage for new connections grows from about 2 s to
  60 s. With a single relay, drain also lengthens the outage. The runbook must require serial
  restarts, and `check` should warn.
- **Agent drain.** The agent's new `Reject NodeOffline` makes clients walk all N relays to the
  same draining agent. That is acceptable, but it must be documented.
- **Metrics.** The relay HTTP listener adds a listener and a parser. Load-balancer health
  probes assume an LB topology that the per-IP gate does not support without the PROXY
  protocol. The node_exporter **textfile** already chosen for the agent works for the relay
  too.

**Required change:** D-10 → textfile for both; the HTTP listener is optional and comes later.

### AP-22 (low): window auto-tuning raises typical per-stream memory 4× before the global byte budget exists

**Surface:** R-6 / G11.

**Required change:** ship the queue budget before auto-tuning, or in the same change.

### AP-23 (info): what IKhfs does and does not give (the plan must state all of it in PROTOCOL)

**It gives:**
- Confidentiality and forward secrecy of transport data against a **passive** CRQC (HNDL),
  including later theft of static keys (A5). This is secure if X25519 **or** ML-KEM holds.
- Both `ek` and `ct` are hashed into the transcript (snow `encrypt_and_mix_hash`).
- KEM parsers are reachable only after authentication: the responder encapsulates in
  `accept()`, and the initiator decapsulates only a `ct` that passed AEAD under `ee`/`es`.

**It does not give:**
- PQ authentication: a live CRQC impersonates either side or does a full MITM.
- PQ **identity hiding**: the outer msg1 `s` and the certificate payload are protected only by
  `es`/`ss`.
- Protection against KCI, msg1 replay, or length and timing metadata. The msg1 length reveals
  the certificate length, and so the name length and the number of nodes in scope. Padding the
  certificate payload to fixed buckets is cheap.
- On E2E, the relay (A4) still sees the E2E msg1 under classical protection.

HFS is "revision 1, unofficial". The PQNoise CCS'22 analysis covers PQ patterns, not IKhfs
itself.

### AP-24 (info): factual corrections

| Claim | Correction |
| :- | :- |
| `ml-dsa` 0.1.1 is latest | **0.1.2 (2026-10-31)** |
| ML-DSA "two 2026 CVEs", "a hint-bounds bug in libcrux-ml-dsa" | RustCrypto: 3 advisories (RUSTSEC-2025-0144 / CVE-2026-22705, CVE-2026-24850, GHSA-h37v-hp6w-2pp8). libcrux-ml-dsa: RUSTSEC-2026-0076 (panic in verify), -0077 (accepted invalid signatures), -0125, -0126 |
| ML-KEM-1024 "+384 B per ek/ct" | ek +384 (1 568), **ct +480** (1 568) |
| clatter license unverified | MIT; ml-kem 0.2.1; pqclean on by default |
| sntrup761x25519 in OpenSSH 8.x "available but not the default" | 8.5 release notes: **disabled by default** (not in the default list) until 9.0, so a modern client cannot negotiate PQ KEX with EL9's 8.7 without server configuration. The conclusion stands |
| OpenSSH ML-KEM "derived from libcrux" | Not stated in the 9.9/10.0 release notes; still unverified (not load-bearing) |
| v2 cert max 7 637 (§3.4) | 7 638 (§4.4 is right); msg1 max 8 923 |
| v1 msg1 with the magic by chance: "client retries with a new ephemeral" | E2E: an error after `OpenAck` is final (§13); outer: the next relay. Probability 2⁻⁴⁰, harmless |
| Resilience §4: "responder ML-KEM decaps", 5–12 KB per reconnect, CPU 2–4× | See AP-8 |

**Verified correct:**
- snow `hfs` / `Kyber1024` only, KEM buffers 4096, encapsulation in the msg2 write path.
- IKhfs sizes: msg1 = 1 280 + P (+5 envelope), msg2 = 1 152.
- Side finding 1 (the tag is double-counted in `limits.rs`, while `agent.rs` `MAX_MSG1_LEN` is
  exact).
- `LengthDelimitedCodec` reserves the declared length (`length_delimited.rs:559`).
- Gate defaults: charged at accept, never refunded; `RelayConfig::default()` with no flags.
- The agent rejects a `Ping` from the relay.
- `OpenAck` is sent before sshd is contacted.
- RUSTSEC-2026-0161 (pqcrypto-mlkem unmaintained); CVE-2026-24850 details.
- systemd versions: 253 notify-reload, 254 RestartSteps, RHEL 9 / Debian 12 = 252.
- journald defaults; `StartLimit*` defaults; OpenSSH 9.9 / 10.0 KEX facts.

## Verdict on each decision

**PQ plan**

| # | Verdict |
| :-: | :- |
| D1 hybrid IK on Noise | **agree** |
| D2 IKhfs ML-KEM-768 | **agree**, with AP-7, AP-11 and AP-23 written into the spec |
| D3 snow ML-KEM | **change**: vendored minimal patch as primary, upstream opportunistic, stock-snow ratchet spike as fallback (AP-14) |
| D4 ML-KEM-768 in Noise, no X-Wing | **agree** |
| D5 libcrux-ml-kem | **agree**: exact pin `=0.0.11`, portable-only on aarch64 until NEON is verified, RustCrypto `ml-kem` 0.3.x as oracle |
| D6 no FIPS | **agree** |
| D7 negotiated, never auto-downgrading | **agree in principle; change** to a single suite id with per-role accepted sets and no numeric `min` (AP-7) |
| D8 both layers | **change**: E2E ships first, as a release not gated on R-phases or relay restarts; outer follows (AP-8) |
| D9 composite ML-DSA-65+Ed25519 AND | **agree; change** the order to Ed25519 → ML-DSA, and bind the algorithm to the pinned key (AP-5, AP-13) |
| D10 SLH-DSA only for releases | **agree**; signing via OpenSSL offline (AP-19) |
| D11 RustCrypto ml-dsa | **change**: `≥ 0.1.2`, exact pin, verify-after-sign in `zt-ca` with the fleet verifier, Wycheproof + libcrux differential (AP-5) |
| D12 ML-KEM key derived from the seed | **agree** |
| D13 full hex keys in TOML | **agree**, with a distinct v2 fingerprint prefix (AP-6) |
| D14 KEM initiator authentication | **agree**; document AP-12 |
| D15 clatter for PQ-3 | **change**: one Noise stack for all suites (AP-15) |
| D16 event-driven deprecation | **agree** |
| PQ-2 before PQ-3 | **change**: one authentication milestone; PQ-2 alone is not claimed to stop A3 (AP-9) |
| Revocation unit | **change**: X25519-level fingerprint everywhere (AP-6) |

**Resilience plan**

| # | Verdict |
| :-: | :- |
| D-1 refund + per-identity + separate pools | **change**: success = key confirmation; client first-frame deadline; per-identity as a concurrency limit, charged after confirmation (AP-1, AP-2) |
| D-2 full jitter + spread | **agree** |
| D-3 keepalive 10 s / `TCP_USER_TIMEOUT` | **agree** ("dead" = no inbound frame at all, not only missing `Pong`s) |
| D-4 staggered hedge | **change**: hedge only while connect + outer handshake are incomplete (AP-10) |
| D-5 no client health memory | **agree** |
| D-6 SIGTERM drain | **agree**, plus serial-restart enforcement (AP-21) |
| D-7 internal-only watchdog | **agree; change** the heartbeat to a progress counter and make the tick non-starvable (AP-4) |
| D-8 ControlPersist guidance | **agree** |
| D-9 turmoil | **agree** |
| D-10 relay HTTP metrics | **change**: textfile for both (AP-21) |
| D-11 `check` in `ExecReload` | **agree** |
| D-12 aggregated pre-auth logs | **change**: aggregate unknown identities too; per-event only for known ones (AP-3) |
| D-13 byte budget | **agree**, shipped before window auto-tuning (AP-22) |
| D-14 restart policy | **change**: add `RestartPreventExitStatus` for configuration errors and `LimitCORE=0` (AP-17, AP-18) |
| Phase order "R-1…R-3 before PQ" | **change**: PQ-0 ∥ R-1 → PQ-1 E2E → R-2/R-3 ∥ PQ-1 outer → … (AP-8) |
| R-1 unauthenticated refill 1/s | **change**: keep 1 per 3 s unless measured (AP-16) |
| R-1 `msg1_deadline` 3 s | **change**: ≥ 5 s or derived from the suite (AP-20) |
