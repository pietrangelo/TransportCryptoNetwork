# TCN framing protocol, version 1

This document is the normative specification of the frame format. The reference code is
`crates/zt-domain` (types and invariants) and `crates/zt-proto` (encoding). In case of conflict,
the tests in `crates/zt-proto/tests` are the source of truth and this document must be corrected.

The words MUST, MUST NOT and MAY have the meaning given in RFC 2119.

## 1. Position in the stack

```
 zt-client ── Noise (client↔relay) ── zt-relay ── Noise (relay↔agent) ── zt-agent ── 127.0.0.1:22
     └──────────────── Noise end-to-end client↔agent, inside Data frames ─────────┘
```

- Each frame travels inside **one** Noise transport message (max 65 535 bytes, including the
  16-byte AEAD tag).
- The payload of `Data` frames is itself encrypted end-to-end between client and agent: the relay
  sees only opaque bytes (*blind relay*).
- Noise handshakes are not frames: they take place before framing begins (Phase 2).

## 2. Wire layout

All integers are **big-endian** and unsigned.

```
 offset  size field
 ------  ---  -----------------------------------------------
   0      1   version   MUST be 0x01
   1      1   kind      type code (§3)
   2      4   stream_id 0 = connection control, >0 = stream
   6      2   length    payload bytes that follow
   8      n   payload   n = length
```

The header is exactly `FRAME_HEADER_LEN = 8` bytes long.

## 3. Frame types

| Code | Type | stream_id | Payload length | Payload contents |
| :-: | :- | :-: | :-: | :- |
| `0x01` | `Register` | `= 0` | 1..=63 | `NodeId` (ASCII, §4.1) |
| `0x02` | `Open` | `> 0` | 1..=63 | destination `NodeId` |
| `0x03` | `OpenAck` | `> 0` | 0 | none |
| `0x04` | `Reject` | `> 0` | 1 | `RejectReason` (§4.3) |
| `0x10` | `Data` | `> 0` | 1..=61 440 | opaque E2E-encrypted bytes |
| `0x11` | `WindowUpdate` | `> 0` | 4 | `u32` credit, MUST be > 0 |
| `0x12` | `Close` | `> 0` | 1 | `CloseReason` (§4.4) |
| `0x20` | `Ping` | `= 0` | 8 | `u64` nonce |
| `0x21` | `Pong` | `= 0` | 8 | `u64` nonce of the `Ping` |

Any other code is an error. There are no reserved fields and no optional extensions: the only
evolution mechanism is the `version` byte.

## 4. Value invariants

### 4.1 `NodeId`
Restricted DNS label: length 1..=63, alphabet `[a-z0-9-]`, no leading or trailing `-`. No
uppercase (no case folding), no dots, no Unicode: this eliminates homographs, log injection
and comparison ambiguity.

### 4.2 Size limits
| Constant | Value | Rationale |
| :- | -: | :- |
| `MAX_PAYLOAD_LEN` | 61 440 (60 KiB) | a maximum payload wrapped in **two** layers (header + tag each) fits in one Noise message |
| `MAX_FRAME_LEN` | 61 448 | header + maximum payload |
| `MAX_NODE_ID_LEN` | 63 | RFC 1035 §2.3.4 |

The relations between limits are checked with `const` assertions: a build with inconsistent
limits does not compile.

### 4.3 `RejectReason`
`0x01` NotAuthorized, `0x02` UnknownNode, `0x03` NodeOffline, `0x04` RateLimited,
`0x05` ResourceExhausted.

### 4.4 `CloseReason`
`0x00` Normal, `0x01` Timeout, `0x02` ProtocolViolation, `0x03` Drained, `0x04` PeerGone,
`0x05` Unauthorized (the agent rejects the client's end-to-end identity).

## 5. Decoder rules

1. The decoder MUST NOT consume bytes until a frame is complete.
2. The header MUST be validated in full (version, type, stream scope, length range for the
   type) **as soon as 8 bytes are available**, before waiting for the payload. An
   out-of-range length is rejected without allocating anything.
3. The decoder MUST NOT reserve more than `MAX_FRAME_LEN` bytes for a frame.
4. Any violation is **fatal**: the decoder stays poisoned and the connection MUST be closed.
   There is no resynchronisation on a corrupted stream.
5. An EOF in the middle of a frame is an error, not a clean close.
6. The encoding is **canonical**: every accepted frame has a single byte representation
   (verified with property tests). There is no format malleability.
7. Error messages contain only metadata (codes, lengths, positions), never received bytes.

## 6. Reference vectors

```
Ping { nonce: 0x0102030405060708 }
01 20 00 00 00 00 00 08 01 02 03 04 05 06 07 08

Open { stream: 0x0a0b0c0d, target: "db1" }
01 02 0a 0b 0c 0d 00 03 64 62 31
```

## 7. Transport and handshake

### 7.1 Messages over TCP
Each Noise message is preceded by its length as a big-endian `u16` (maximum 65 535). After the
handshake each Noise message contains **exactly one** frame: excess bytes or an incomplete
frame are fatal violations.

### 7.2 Identity
Each node has a long-term Ed25519 key (hexadecimal file, permissions `0600`). For Noise its
X25519 form is used (Edwards → Montgomery map). The **fingerprint** is
`SHA-256("TCN fingerprint v1\0" || x25519_public)`, displayed as `SHA256:<hex>`.
Small-order public keys are rejected at load time.

### 7.3 Handshake
The suite pinned by the initiator (§7.5): `Noise_IK_25519_ChaChaPoly_BLAKE2s` (the classical
suite, the default) or `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` (the hybrid suite), on
either channel. Each channel and suite has its own prologue. The
payload of
message 2 MUST be empty (the initiator rejects a message 2 with a payload); the payload of
message 1 is either empty or contains a client certificate (§15.3), and a responder rejects a
payload that is neither empty nor a valid certificate.

| Channel | Initiator | Responder | Prologue |
| :- | :- | :- | :- |
| outer | agent or client | relay | classical: `TCN/1 outer`; hybrid: `TCN/2 outer` ‖ `0x01` |
| end-to-end | client | agent (inside `Data` frames) | classical: `TCN/1 end-to-end`; hybrid: `TCN/2 end-to-end` ‖ `0x01` |

The initiator pins the responder's key. The responder learns the initiator's identity from the
first message and, if it is not on its whitelist, **does not respond**: it closes without
sending the second message.

On the end-to-end channel the client's first transport message MUST have the confirmation of
its suite as its plaintext: `TCN/1 ready` for the classical suite, `TCN/2 ready` for the hybrid
one. The confirmation of the other suite, or any other plaintext, closes the stream
(`ProtocolViolation`) without contacting sshd. IK message 1 can be replayed by anyone who observes it (the relay): only after this
confirmation does the agent contact sshd and register the session.

### 7.4 Rekey
On both channels, after every **1024** authentic transport messages in one direction, sender
and receiver perform Noise's `Rekey()` on that direction's key. The rekey is implicit: no frame
on the wire, only the counter. This works because TCP delivers in order and any rejected
message closes the channel; a forged message does not increment the receiver's counter. Each
period has a key derived one-way from the previous one, so a copy of the process memory does
not decrypt recorded traffic from past periods. With the 30 s keepalive an idle channel changes
key every ~8.5 hours; an SSH session every ~16 MiB.

### 7.5 Handshake suites
A **suite** fixes the Noise protocol name, the prologues and the message sizes of a handshake.
Each suite has one identifier, its Noise protocol name, which is also its only spelling in
configuration: exact, with no case folding, trimming or aliases.

| Suite | Id | Message 1 | Message 2 | This release |
| :- | :- | -: | -: | :- |
| `Noise_IK_25519_ChaChaPoly_BLAKE2s` | `0x00` | 96 + payload | 48 | supported, the default |
| `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` | `0x01` | 1 296 + payload | 1 152 | supported on both channels (end to end since PQ-1, outer since Phase 3) |

Message 1 of the classical suite is `e` (32) + encrypted `s` (32 + 16) + the payload tag (16).
In IKhfs, `e1` (the 1 184-byte ML-KEM-768 encapsulation key) follows `es`, so it is encrypted
too (+ 16). Message 2 carries `ekem1` (1 088 + 16) between `ee` and `se`.

Rules:

- **No suite travels in the clear.** There is no envelope, magic or version byte in front of
  message 1. A responder finds the suite by trying, in turn, each suite it accepts whose
  message 1 can have the received length, with its current key and then its previous one
  (§14). A length outside every accepted suite's bounds is refused without running Noise, and
  with the same error as an invalid message (no oracle). The classical suite is byte for byte
  the handshake of earlier releases: v1 peers interoperate in both directions.
- **Domain separation.** The classical suite keeps the `TCN/1` prologues. From PQ-1 on, a new
  suite has its own prologue (`TCN/2 <channel>` followed by its id), so that a message of one
  suite is never valid as another.
- **The initiator pins one suite** per relay and per node (`suite`, OPERATIONS §5). It never
  falls back to another: if the responder does not accept that suite, it does not answer.
- **The responder accepts explicit sets, per role.** The relay has one set for agents and
  one for clients (`relay.toml`, OPERATIONS §4.1). The agent has one set for clients on the
  end-to-end channel (`--accept-client-suites`). The sets are not ordered and there is no
  "minimum suite". The default is the classical suite alone. It does not change between
  releases: a release that adds a suite does not accept it until it is configured. On the relay
  the role is known only after message 1. A peer whose suite is accepted for the other role
  gets no message 2 and produces `handshake_suite_rejected` (WARN).
- A suite that this build cannot run **on that channel** is a configuration error at startup,
  on every side. Every suite of this release runs on both channels.

#### 7.5.1 The hybrid suite on the end-to-end channel (PQ-1)

The end-to-end handshake is opaque `Data` payload for the relay, so the hybrid suite needs no
change on the relays: a relay of any earlier release forwards it. Its message 1 (at most
1 296 + 4 328 = 5 624 bytes) and message 2 (1 152 bytes) fit one `Data` frame
(`MAX_PAYLOAD_LEN`, checked with `const` assertions); the frame budget does not change.

Transcript, with the prologue `TCN/2 end-to-end` ‖ `0x01` and the protocol name above
(Noise §5 and the HFS extension, revision 1):

```text
<- s
...
-> e, es, e1, s, ss        e1: ML-KEM-768 encapsulation key (1 184), encrypted under es
<- e, ee, ekem1, se        ekem1: ML-KEM-768 ciphertext (1 088), encrypted; then MixKey(ss_kem)
```

The KEM is `libcrux-ml-kem` (FIPS 203), plugged into snow through its resolver; snow's own KEM
code is not used (docs/pq-snow.md, `vendor/snow/PATCHES.md`). A wrong ciphertext gives a
different shared secret (implicit rejection): message 2 then fails its AEAD tag like any other
corruption, with the same error and no oracle on which field was wrong.

The agent (responder) handles message 1 as follows:

1. A length above the largest message 1 of any suite this build runs end to end (5 624
   bytes) is refused before Noise runs, as a malformed certificate. The bound does not depend
   on the accepted set, so that a known client with a large certificate is still named in
   step 3 (review 0009, A9-5).
2. It tries the accepted suites whose message 1 can have that length.
3. Only if none succeeds, it tries the other suites it supports on this channel, to recognise
   a known client whose suite it does not accept. The result of this step is a value without
   `accept` (`noise::Responded::Unaccepted`, A9-3): that client gets no message 2. The agent
   records `handshake_suite_rejected` (WARN, with `peer`, `suite` and `confirmed = false`)
   and closes the stream with `Unauthorized`. An unknown key produces no per-suite line,
   whatever its suite. A message 1 valid for no suite is `handshake_failed`, or a malformed
   certificate if it is longer than any accepted message 1.
4. The confirmation of the suite (`TCN/2 ready`) must arrive before sshd is contacted.

`handshake_suite_rejected` is written before any proof that the client is live: message 1 can
be replayed (§7.3), and there is no message 2 to confirm. A compromised relay that recorded a
client's message 1 can produce it at will, so the agent rate-limits it per identity, like the
relay (§10.1), together with every `authentication_failed` line that names a peer.

Cost: steps 2 and 3 run on every agent whose accepted set is not every supported suite (the
default, classical-only agent included). An invalid message 1 costs one trial per key for
each suite whose length bounds fit, accepted or not: with both suites and two keys (during a
rotation), up to four trials, on any agent (the `both suites` row of docs/pq-snow.md §5 is the
two-trial case). The trials of step 3 are read-only: no KEM operation happens before
`accept`.

What IKhfs gives, and what it does not (AP-23):

- **Gives:** confidentiality of the end-to-end session against an adversary who records the
  traffic today and has a quantum computer later ("harvest now, decrypt later"), as long as
  ML-KEM-768 holds; if ML-KEM fails, X25519 alone, as in the classical suite.
- **Does not give post-quantum authentication.** Identities remain X25519 static keys: a
  quantum adversary *active during the handshake* can impersonate either side.
- **Does not hide identities post-quantumly.** The client's static key in message 1 is
  encrypted under `es` (X25519 only): a recorded handshake reveals it to a future quantum
  adversary, and with it which client reached which agent.
- **Does not change IK's properties:** no protection against key-compromise impersonation of
  the responder, message 1 replayable (hence the confirmation, §7.3).
- **Leaks lengths.** The suite is visible to anyone who sees the sizes of the `Data` frames
  (1 296 + payload vs 96 + payload).
- **The relay channel** runs the hybrid suite only where it is pinned and accepted (§7.5.2);
  otherwise the routing metadata and the client's identity towards the relay are X25519 only.
- **HFS is not a final standard.** The pattern follows the Noise HFS extension (revision 1),
  not an RFC; the protocol name binds the exact construction, and a different construction
  would get a new suite id.

Memory: the agent's and the client's ML-KEM decapsulation key and seed are wiped when dropped;
snow wipes its KEM output buffer. Not wiped in this release: snow's internal HKDF and DH
temporaries, and the copies libcrux makes of its by-value arguments.

#### 7.5.2 The hybrid suite on the outer channel (PQ-1, Phase 3)

The same construction as §7.5.1 on the hops client ↔ relay and agent ↔ relay, with the prologue
`TCN/2 outer` ‖ `0x01`. The prologue binds the channel: an outer hybrid message 1 is never valid
end to end and the reverse, so a relay cannot replay a client's end-to-end message 1 to another
relay as an outer one. The outer channel has no confirmation string: its key confirmation is
the first authentic transport frame (`Register`, `Open` or `Ping`, §10.1), which a replayed
message 1 can never produce. An end-to-end confirmation (`TCN/1 ready`, `TCN/2 ready`) never
decodes as a frame.

- **Relay (responder).** It accepts one set per role (`relay.toml`, OPERATIONS §4.1). It tries
  the union of the two sets on message 1 (the role is known only from the key), then checks
  the suite against the role's set: an agent whose suite is accepted only for clients, or the
  reverse, gets no message 2, and the relay writes `handshake_suite_rejected` (WARN,
  `confirmed = false`, rate-limited per identity, §10.1). An unknown key produces no per-suite
  line. Message 1 is buffered up to the largest legitimate message 1 of the union (5 624 bytes
  when the hybrid suite is accepted for either role); the first-frame cap of §10.1 applies only
  after message 2 has been written.
- **Initiators.** The agent pins one suite per relay (`--relay-suite`), the client one per
  relay (`suite` in `[[relays]]`, `relay_suite` for the single-relay form). Neither ever
  retries another suite. A client may still fail over to the next relay before `OpenAck`
  (§13), with that relay's own pin. Failover never lowers the pin **of a relay**, but with
  mixed pins (during the rollout of OPERATIONS §13) it can land on a relay pinned to the
  classical suite: an active attacker who resets the hybrid-pinned relays gets a classical
  hop for that session. `zt-client` warns when failover changes the suite, and
  `require_outer_suite` in `client.toml` makes any relay pinned to another suite a
  configuration error, so failover cannot leave the required suite (review 0010, A10-9).
- **Audit.** Every summary interval the relay writes `outer_suites_confirmed` with the number
  of key-confirmed handshakes per role and suite (`agents_classical`, `agents_hybrid`,
  `clients_classical`, `clients_hybrid`, absent when zero), without identities: this is the
  signal for the sunset of the classical suite (OPERATIONS §13), and replays never count. The
  agent writes `relay_registered` with the pinned `suite` for every relay session, once
  `Register` is sent: message 2 proved that the relay accepts the suite for agents, but the
  relay can still refuse the registration itself and close.
- **Cost.** About 1.2 KiB more in each direction per connection and the CPU of
  docs/pq-snow.md §5, once per connection; the transport is unchanged. The relay does no KEM
  work before the policy and suite decisions (encapsulation happens when message 2 is
  written).
- **Properties.** Those of §7.5.1 for the hop: hybrid forward secrecy of the routing metadata
  and of the client's certificate in later transport frames against a recording adversary; no
  post-quantum authentication and no post-quantum hiding of the static key or of the
  certificate in message 1 (both are encrypted under `es`, X25519 only).

## 8. Lifecycle

1. The agent connects, completes the handshake and sends `Register` within 10 s with the name
   that the policy associates with its key. A second agent with the same key replaces the first.
2. The client connects and sends `Open { stream, target }`. The relay replies `Reject
   NotAuthorized` both for nodes not granted and for nonexistent nodes (no oracle),
   `NodeOffline` or `ResourceExhausted`; otherwise it forwards `Open` to the agent with a stream
   id chosen by the relay (increasing, never reused).
3. The agent replies `OpenAck`. The client's first `Data` contains message 1 of the end-to-end
   handshake; the agent checks the client against its **own** list and, if it does not know
   it, closes with `Close Unauthorized`. After that, `Data` frames carry the encrypted SSH bytes.
4. A `Close` from one side is forwarded to the other. The loss of a connection closes all of its
   streams with `PeerGone`.
5. **Drain** (a graceful stop, OPERATIONS §14). A draining relay closes its listening socket at
   once (new connections are refused, so clients and agents move to another relay, §13),
   answers a new `Open` on a connection that is already open with `Reject NodeOffline` (the
   client moves on, §13), and keeps routing the open streams, under the policy in force and its reloads (a revocation
   still cuts a session). When the last stream ends, or at the drain deadline (60 s by
   default), it sends `Close Drained` on both sides of every stream still open and closes
   every connection. A draining agent answers every new `Open` with `Reject NodeOffline`, so
   the relay and the client treat the node as offline on that path; a stream it acknowledged
   before the drain and whose end-to-end handshake is not finished is waited for and then
   closed with `Close Drained` instead of becoming a session. It keeps its open sessions and
   drops its relay connections after the last one or at its deadline.

A peer that violates a rule (frame order, role, credit, rate) loses the connection. The
exception is frames **in flight** on a stream that is already closed (for example `Data` or
`Close` crossing a `Close`): they are silently discarded. A frame on a stream that was never
opened remains a violation. The stream ids that the relay assigns to agents are strictly
increasing; the agent rejects ids it has already seen.

## 9. Flow control

| Constant | Value |
| :- | -: |
| `INITIAL_WINDOW` | 256 KiB per direction per stream |
| `MAX_WINDOW` | 1 MiB |
| `MIN_CHARGE` | 512 bytes: a `Data` costs `max(len, 512)` |
| `MIN_WINDOW_UPDATE` | 512 bytes |

The receiver returns credit with `WindowUpdate` after delivering the data. The relay applies the
same rules: a `Data` beyond the credit, or a `WindowUpdate` below the minimum or that takes the
window beyond `MAX_WINDOW`, are violations. The memory the relay queues towards a peer is
therefore bounded by `streams × MAX_WINDOW`.

## 10. Default limits and timeouts

| Limit | Value |
| :- | -: |
| unconfirmed connections to the relay (pre-authentication pool) | 1 024 |
| unconfirmed connections at once per IPv4 address or IPv6 /64 / per IPv6 /48 | 50 / 100 |
| confirmed connections to the relay (established pool) | 8 192 |
| share of the established pool that only agents may use | 10 % (819) |
| confirmed connections per identity | 512 |
| unconfirmed handshakes per IPv4 address or IPv6 /64 prefix | burst of 64, then 1 every 3 s |
| refunds of that budget per identity | burst of 512, then 10 per second |
| new IPv6 /64 prefixes per /48 | burst of 64, then 1 per second |
| `Open` per client connection | burst of 64, then 10 per second |
| streams per client / per agent | 32 / 64 |
| `Ping` per connection | burst of 10, then 1 every 5 s |
| relay: complete message 1 / message 2 sent / first authentic frame | 5 s / 10 s / 5 s after message 2 |
| initiator handshake / idle / write | 10 s / 90 s / 30 s |
| relay idle per role: agents / clients (`relay.toml` `[liveness]`, 15–3600 s) | 90 s / 90 s |
| agent and client keepalive (`Ping`) | 10 s |
| agent: relay link dead after | 3 keepalive intervals with no inbound frame at all |
| TCP on every socket: `TCP_USER_TIMEOUT` / keepalive idle, interval, probes | 20 s / 10 s, 5 s, 3 |
| agent reconnect: first delay after a failure / cap / spread after a session that lived 10 s | full jitter over 1 s, doubling / 30 s / uniform over 10 s |
| `agent_flapping`: registration takeovers of one node | 3 in 60 s, reported once per window |
| drain deadline (`--drain-timeout`, 1–3600 s) | 60 s |

Liveness (resilience R-2). The agent sends a `Ping` every keepalive interval and declares the
relay link dead when **no frame at all** (not only no `Pong`) arrived for three intervals; it
then reconnects. Any inbound frame counts, so a busy link never pings itself to death. The
relay's idle timeout per role is the other side of the same check: it drops a silent agent and
its registration, so a client gets `NodeOffline` at once instead of an `Open` that is never
acknowledged. Its default stays at 90 s, three times the 30 s keepalive of agents before R-2,
until the whole fleet is upgraded (OPERATIONS §4.1). `TCP_USER_TIMEOUT` makes the kernel give
up on a peer that stops acknowledging within 20 s, whatever the application timers say. On a
client this also means that 20–25 s of path loss (Wi-Fi roaming, a tunnel) ends the
interactive session, where before R-2 the limit was the 90 s idle timeout.

The relay's admission limits are set in `relay.toml` (OPERATIONS §4.1). Every value is checked
at startup: none may be zero, none may be absurd, the message 1 deadline lies between 5 s
and the handshake deadline, the per-source refill is 3 s or slower, one identity may not hold
more than the established pool, a source may not hold more than its /48, and a /48 may not hold
more than half of the pre-authentication pool. The relay logs the limits in force at startup
(`admission_limits_in_use`).

### 10.1 Admission on the relay
A connection passes through two pools:

```text
accept ─(per-source token, pre-auth slot)─▶ unconfirmed ─first authentic frame─▶ established
   │ refused: dropped without a reply          │ token refunded, identity charged
   ▼                                           ▼ closed: slot freed, token stays spent
 counted in preauth_summary                  counted in preauth_summary
```

1. **At accept** the connection takes a slot in the pre-authentication pool and one token
   from the budget of its source (IPv4 address or IPv6 /64, plus the /48 bucket for new /64s).
   A source holds at most `max_pending_per_source` unconfirmed connections at once, and all the
   /64s of one IPv6 /48 together at most `max_pending_per_wide`. A full pool, a source at its
   cap or an empty budget drops the connection without a reply. The pool and the caps are
   checked first, so they do not spend the source's tokens.
2. **Message 1** must be complete within `msg1_deadline` (≥ 5 s), however slowly it trickles
   in. Its length prefix is checked on sight: over the largest legitimate message 1 of the
   accepted suites (4 424 bytes for the classical suite, 5 624 with the hybrid one, §15.3,
   §7.5.2), the connection is closed
   before any byte of the message is buffered. Until key confirmation (step 4) the limit is the
   largest legitimate first transport message: 87 bytes, the tag and a `Register` or `Open` with
   a 63-byte name. A longer prefix is refused on sight and counted as `oversized`. After key
   confirmation the limit is the usual Noise maximum (§7.1).
3. **Message 2** is sent if the policy (§15.4) and the suite (§7.5) accept the peer, within
   `handshake_timeout` from accept.
4. **Key confirmation.** Message 1 can be a recording (§7.3), so message 2 proves nothing about
   the initiator. Only the first authentic transport frame does (`Register` from an agent, `Open`
   or `Ping` from a client). It must arrive within `first_frame_deadline` after message 2. Only
   then does the connection reach the relay core, move to the established pool and count
   against its identity's concurrency limit. The source gets its token back if the identity
   still has refunds (`identity_refund_burst`, then one every `identity_refund_refill`).
   Clients may fill the established pool only up to `max_established` minus the agents' share
   (`agent_reserve_percent`); agents may use all of it. A confirmed identity that is refused
   here (its concurrency limit, or a full pool) gets `Reject RateLimited` in answer to its
   `Open`, and the relay writes an `admission_refused` line that names it.

Consequences:

- The per-source budget limits **unconfirmed** handshakes, and the refunds bound confirmed ones.
  A fleet controller that opens hundreds of sessions from one address (4 waves of
  `forks = 50`) is not throttled, because every confirmed session gives its token back. One
  identity that loops connect, handshake, first frame, close from one address gets 512
  handshakes at once, then 10 per second plus the source's 1 every 3 s. Replays and scanners
  never confirm, so they spend the budget for good.
- The pre-authentication pool is still global. With the defaults, one source holds at most 50 of
  its 1 024 slots and one /48 at most 100, so filling it takes at least 21 IPv4 addresses (or
  /64s in different /48s), or 11 IPv6 /48s, each holding its slots for the 5 s of
  `msg1_deadline` at a time. An operator who expects such an attacker raises `max_preauth` or
  lowers the caps (OPERATIONS §4.1).
- The /48 caps the slots its /64s hold at once, not the handshakes they start: in a burst one
  /48 can start up to `wide_burst` × `source_burst` (4 096) unconfirmed handshakes over time,
  at most 100 at once.
- Replays of a recorded message 1 never enter the established pool and never charge the
  victim's identity: they cannot lock the victim out.
- A stolen identity holds at most `max_per_identity` confirmed connections, however many
  addresses it has.
- Failures before confirmation never produce one log line per connection: they are
  aggregated (§15.11). An `authentication_failed` line is written only for a key the
  configuration knows (whitelisted or revoked), or for a certificate rejected after a pinned CA's
  signature was verified. Any other key is one that anyone could have made up.
- A recorded message 1 of a known identity can be replayed at will, for example one of a key
  revoked since or one whose certificate has expired since. So the line about a known identity
  (`authentication_failed`, `handshake_suite_rejected`, `admission_refused`) is written in full
  once per identity and `summary_interval` (on the agent, `authentication_failed` with a peer
  and `handshake_suite_rejected`, once per identity and 10 s, review 0009 A9-2). The repeats are counted in one
  `<event>_repeated{peer, …, count}` line per identity and interval. At most 256 identities are
  logged per interval; beyond them the events are only counted (`suppressed_identities` in
  `preauth_summary`).

## 11. The client as `ProxyCommand`

`zt-client connect <node>` opens a connection to the relay with a single stream to the node and
connects OpenSSH's stdin/stdout to the end-to-end channel.

- **Pinned keys, no TOFU.** The relay key and the agent key of each node come from
  `client.toml`. A node without a pinned key, an invalid name, a trust file that is not a
  regular file, is owned by another user or is writable by others (including via the
  directory), or a secret key readable by others make the client fail before any connection.
- **stdout is the SSH channel.** Only bytes decrypted from the end-to-end channel go there; logs
  and errors go to stderr. Each delivered message is written and flushed immediately (stdout is
  line-buffered and SSH does not send lines).
- **Closing.** EOF on stdin closes the stream (`Close Normal`); a close from the node side
  closes stdout and terminates the process even if stdin remains open. There is no half-close:
  SSH does not need it, because its channel EOF travels inside the SSH protocol.
- **Exit code.** 0 only for `Close Normal` or local EOF; 1 for any other outcome, including an
  error `Close` from the agent (for example sshd unreachable); 2 for invalid arguments.
- **No write timeout on stdout.** A suspended `ssh` stops reading: the window bounds the memory
  and the session resumes when ssh starts reading again.

## 12. Hot revocation

Relay and agent reload their trust files on `SIGHUP` (`systemctl reload`). The new
configuration also applies to what is already open:

| Change | Effect |
| :- | :- |
| key removed from the policy, or moved from client to agent (or vice versa) | connection closed; the peers of its sessions receive `Close PeerGone` |
| agent key associated with another node | connection closed (`access_revoked`). The agent keeps registering with its own `--node` and is rejected until it is reconfigured (`TCN_NODE`) and restarted: an agent's node is changed in both places (finding 0004-3) |
| client that loses access to a node | only the streams to that node are closed with `Close Unauthorized` on both sides |
| client removed from an agent's authorized clients | the agent closes its sessions with `Close Unauthorized`, without waiting for the relay |
| certificate revoked (serial number or key in the denylist), CA removed, certificate lifetime beyond its CA's new `max_lifetime` (§15) | like a key removed from the policy: connection closed by the relay, sessions closed with `Close Unauthorized` by the agent |
| a CA's `allow` narrowed (§15.5) | only the streams to nodes no longer granted are closed with `Close Unauthorized`, as for a client |

Every revocation produces the audit event `access_revoked`. A file that is invalid or has become
insecure changes nothing and produces `policy_reload_failed` (relay) or
`authorized_clients_reload_failed` (agent), at `ERROR` level.

## 13. Multiple relays (high availability)

Relays are independent: no shared state and no protocol between them. Each has its own key and
a copy of the same policy, which the operator distributes (for example with Ansible). Nothing
changes on the wire.

- **Agent**: has a list of relays (at most 8, each with its own pinned key) and maintains a
  session to **each** of them, in parallel and with independent backoffs. An unreachable or
  slow relay does not affect the sessions to the others. The backoff is sans-IO
  (`ReconnectPolicy`): after a failure the delay is uniform between 0 and an exponential bound
  (1 s, doubling, at most 30 s, "full jitter"); after a session that lived at least 10 s (a
  relay restart or drain) the first reconnect is uniform over the spread window
  (`--reconnect-spread`, 10 s by default), so a fleet comes back over the window and not in
  one wave. From then on the spread is also the floor of the failure bound
  (`max(spread, min(30 s, 1 s·2ⁿ⁻¹))`): a relay still down when the first retries arrive does
  not turn them into one-second retries that pile up when it returns (review 0010, A10-4).
  Without randomness (the system RNG fails) the delay is the bound, never zero.
- **Client**: has an ordered list of relays (at most 8) and tries them in the given order. It
  moves on to the next one **only** for errors that occur before the `OpenAck` and that say
  nothing about the right of access:

  | Error on relay *i* | The client |
  | :- | :- |
  | TCP refused, timeout, outer handshake failed (including wrong relay key), connection closed | tries the next relay |
  | `Reject NodeOffline`, `Reject RateLimited` | tries the next relay |
  | `Reject NotAuthorized`, `Reject UnknownNode` | stops: the policy has answered (fail closed) |
  | any error after the `OpenAck` (end-to-end handshake, `Close` from the agent, data) | stops |

  After the `OpenAck` the client has already talked to the agent: retrying on another relay
  would mask an impostor agent (wrong end-to-end key) or a revocation, and could duplicate a
  session that has already started. Differing policies across relays are a configuration
  error: the client does not "work around" them by looking for a more permissive relay.

  Note, however: a relay that **does not know** the client's key closes the outer channel
  during the handshake, and for the client this is indistinguishable from a broken relay, so it
  moves on to the next one. A key removed from the policy of only one relay remains valid on the
  others: revocation is complete only when all relays have reloaded the policy (or when the
  agents remove the key from their authorized clients, §12).

- **Timing**: attempts are sequential, each with its own timeouts (connection, handshake,
  `Open`). In the worst case, with *N* relays all unreachable by timeout, the client takes *N*
  times the duration of one attempt before giving up. It is advisable to put the closest and
  most reliable relays first; an OpenSSH `ConnectTimeout` shorter than the total interrupts the
  client before it has tried them all.

## 14. Key rotation

A responder (the relay on the outer channel, the agent on the end-to-end one) may have, in
addition to the current key, a **previous key**: it accepts a `msg1` encrypted to either one
(it tries the current one, then the previous one) and replies with the one that matches. As
initiator it always uses the current key. This way the peers' pins are updated gradually,
without a simultaneous change across the whole fleet.

| Rotation | Steps |
| :- | :- |
| relay key | 1. new key; 2. the relay loads it as current and keeps the old one as previous, in a single step: a restart with the new arguments (or a `SIGHUP`, if it is already running with `--previous-key` and the files have been arranged in a safe order, OPERATIONS §8); 3. the pins on agents and clients are replaced (never two entries for the same relay); 4. the previous key is removed (a restart without `--previous-key`) |
| an agent's key | 1. new key; 2. the relay policy lists both keys for the node (`public_keys`, at most 2) and is reloaded; 3. the agent restarts with the new key and the old one as previous: the outer session uses the new one, the end-to-end channel also accepts the old one; 4. the clients' pins are updated; 5. the old key is removed from the policy and the previous key from the agent |

Relay and agent declare in the audit log, at startup and on every reload, the fingerprints of
the keys they accept (`keys_in_use`), and as long as a previous key is accepted they repeat it
every hour (`previous_key_still_accepted`): a half-finished rotation does not remain invisible.
In the same way the relay reports, at startup, on every reload and every hour, the nodes that
still have two agent keys in the policy (`agent_rotation_pending`).

The relay rereads its own keys on **every** `SIGHUP`, even when the reload is meant for the
policy: the swap between current and previous key must therefore be a single step, never a
sequence of file moves under a relay started without `--previous-key`. A previous key equal to
the current one, or an invalid file, makes the reload fail and leaves the earlier keys in force.

Restarting an agent interrupts only the SSH sessions of that node. Restarting a relay, with
multiple relays, interrupts nothing new: agents and clients use the others.

**A compromised key is not rotated: it is revoked.** Keeping it as previous would leave whoever
holds it able to impersonate the responder towards anyone who still pins it. In that case the
key is changed without `--previous-key` and the pins are updated immediately (OPERATIONS §7 and §8).

## 15. Client certificates

With only the per-key whitelist (§12) every client key must be listed in the policy of every
relay and in the authorized clients of every agent, and revocation is always a change to those
files. With certificates an **offline CA** (an Ed25519 key that is never on a relay, agent or
client) signs short-lived certificates, from minutes to hours, that bind a client's Noise static
key to a name, a set of nodes and a validity window. Relays and agents pin only the CAs' public
keys (`[[authorities]]`, OPERATIONS §10) and accept any client that presents a valid
certificate. The per-key whitelist remains valid and takes precedence (§15.5).

The certificate does not replace Noise authentication: the proof of possession remains the IK
handshake on the client's static key. The certificate only says *what* that key may do, and it
is valid only together with it.

### 15.1 Format

Binary, big-endian, fixed-length or length-prefixed fields, in a fixed order. No optional
fields, no extensions: evolution goes through `version` (and through a new signature context
string, §15.2).

```
 offset    size field
 --------  ---  -------------------------------------------------------------
   0        4   magic        "TCNC" (54 43 4e 43)
   4        1   version      MUST be 0x01
   5        1   sig_alg      MUST be 0x01 (Ed25519, RFC 8032, pure variant)
   6       32   ca_key       Ed25519 public key of the signing CA
  38       32   subject_key  Ed25519 public key of the client (the same as in the config files)
  70       16   serial       serial number, 128 random bits, never all zeros
  86        8   not_before   u64, Unix seconds (UTC)
  94        8   not_after    u64, Unix seconds (UTC), exclusive
 102        1   name_len     1..=63
 103        n   name         client name, NodeId rules (§4.1)
 103+n      1   scope        0x00 = list of nodes, 0x01 = all nodes granted to the CA
 104+n      1   node_count   scope 0x00: 1..=64; scope 0x01: MUST be 0
 105+n      …   nodes        node_count times: len (u8, 1..=63) + NodeId
 L-64      64   signature    Ed25519 signature of bytes [0, L-64) (§15.2)
```

Decoder rules, all fatal (the certificate is rejected in full):

1. The total length `L` MUST be within `MIN_CERT_LEN..=MAX_CERT_LEN` (170..=4 328 bytes);
   an out-of-range certificate is rejected **before** any of its fields is read.
2. `magic`, `version` and `sig_alg` MUST have exactly the values given. There is no algorithm
   negotiation: another value is not "unknown but ignorable", it is an error.
3. `serial` MUST NOT be all zeros; `ca_key` and `subject_key` MUST NOT be equal (a CA does not
   certify itself as a client).
4. `not_before < not_after` and `not_after - not_before <= MAX_CERT_LIFETIME` (86 400 s, 24 hours).
   The limit applies to the format, independently of the CA; each CA has a tighter one
   (§15.6).
5. `name` and every node MUST be valid `NodeId`s (alphabet `[a-z0-9-]`, §4.1).
6. With `scope = 0x00` the nodes MUST be in **strictly increasing** byte order: no
   duplicates, only one possible order. An empty list is not allowed (a certificate that grants
   nothing is an issuer error).
7. After the last node exactly 64 bytes (the signature) MUST remain: no more, no fewer.
8. `ca_key` and `subject_key` MUST be **canonical** encodings of valid Ed25519 points (re-encoding
   the decompressed point gives back the same 32 bytes) and MUST NOT be of small order.
   `curve25519-dalek` decompression also accepts non-canonical encodings: the check is
   explicit. Rules 1–7 are purely syntactic (domain); rule 8 requires curve arithmetic and is
   applied in steps 4 and 6 of §15.4.

It follows that the encoding is **canonical**: every content has a single byte representation,
apart from the signature (§15.2). Errors report only metadata (field, position, length), never
certificate bytes.

In files the certificate is a single line of text: `tcn-client-cert-v1:` followed by the bytes
in hexadecimal, with an optional trailing newline. The prefix prevents a certificate from being
mistaken for a key (and vice versa): the key loaders do not accept it.

### 15.2 Signature

`signature = Ed25519-Sign(ca_secret, CTX || L[0..L-64])`, with
`CTX = "TCN client certificate v1\0"` (26 bytes). The context string provides domain
separation: a certificate signature is not valid for any other message, present or future,
signed with the same key. The signature covers `ca_key`: a certificate cannot be attributed to
another CA.

Verification MUST use the **strict** variant (`verify_strict` from `ed25519-dalek`: canonical
`S`, `R` and key not of small order) and the key **pinned** in the configuration, whose 32 bytes
MUST equal `ca_key`: verification is never done with the key written in the certificate
without having found it, byte for byte, among the pinned ones.

Ed25519 is deterministic, but a CA could produce two different signatures of the same content:
that is why a certificate's identity is its `serial`, not the hash of its bytes.

The CA secret key is a dedicated Ed25519 key. Its file has a different format from that of node
keys (`tcn-ca-secret-v1:<64 hex>`): relays, agents and clients do not load it, and `zt-ca` does
not sign with a node key file. Node keys never sign anything (Noise uses their X25519 form), so
there is no signing oracle in the fleet.

### 15.3 Transport

The certificate travels in the **payload of message 1** of Noise IK, on **both** channels:

| Channel | Who sends it | Who verifies it | Before |
| :- | :- | :- | :- |
| outer | client | relay | sending message 2 |
| end-to-end | client (inside the first `Data`) | agent | sending message 2 |

The client sends the same certificate on both channels; agent and relay each verify it with
their **own** pinned CAs, their own denylist and their own clock (defence in depth: a
compromised relay cannot produce or alter the certificate that reaches the agent).

Why in message 1 and not in a frame:

- **It is not in the clear.** In IK the payload of message 1 is encrypted and authenticated with
  the keys derived from `es` and `ss`, that is, towards the responder's pinned static key: a
  network observer cannot read it and cannot remove or replace it without the client's secret
  key. It has the same properties as the client's static key, which travels in the same
  message: anyone who in the future obtained the responder's secret key could read the recorded
  certificates, just as they can already read the identities. The certificate contains no
  secrets.
- **The decision stays before message 2.** An invalid certificate is equivalent to an unknown
  key: the responder does not respond (§7.3). No unauthorised peer completes a handshake or
  reaches the frame decoder, and there is no new "connected but not yet authorised" state in
  the relay core.
- **No change to framing.** The set of frames (§3) remains closed and unchanged; no new round
  trip.

A `Certificate` frame after the handshake was rejected: it would force the relay to complete
the handshake with anyone, would add a pre-authorisation state and timeout, and on the
end-to-end channel the agent would have to respond to unknown clients. The `Open` frame
(1..=63 bytes) cannot hold it.

Message 1 can be replayed (§7.3). A replayed message 1 with a valid certificate does not
complete the handshake (it needs the client's ephemeral key), costs the responder at most one
extra signature verification, within the per-source budget (§10.1), and produces no success event:
the events that name an accepted certificate (§15.11) are recorded only after an authentic
transport message from the client (`Open` on the outer channel, the suite's confirmation on the
end-to-end one, §7.3).

Compatibility: a relay or agent older than Phase 6 ignores the payload of message 1; a client
with a certificate and without an entry in its policy is therefore treated as an unknown key (no
response). A client without a certificate changes nothing. The frames' `version` byte and the
prologues remain unchanged.

Sizes: message 1 with the largest certificate is `96 + 4 328 = 4 424` bytes long, where the 96
bytes already include the payload's AEAD tag (§7.5). It fits both in a Noise message and in the
payload of a `Data` frame (verified with a `const` assertion), and it is the relay's
pre-authentication buffer cap for the classical suite (§10.1). Releases before PQ-0 counted the
tag twice (`96 + 4 328 + 16`); that bound was 16 bytes too loose and never refused a legitimate
message. Under the hybrid suite (end-to-end only) the bound is `1 296 + 4 328 = 5 624` bytes,
which also fits a `Data` frame. A
responder rejects a message 1 payload longer than `MAX_CERT_LEN` without interpreting it.

### 15.4 Verification: order of checks

Relay (outer channel) and agent (end-to-end channel) apply the same checks, in this order; the
first one that fails determines the reason recorded in the audit (§15.11). The order puts the
cheap checks first, along with those that do not depend on unsigned data, and ensures that an
event naming a serial number always concerns a certificate actually signed by a pinned CA.

| # | Check | Outcome on failure (`cert_check`) |
| :-: | :- | :- |
| 0 | valid Noise message 1 → client static key authenticated | `handshake_failed` (as today) |
| 1 | client key in the denylist (`keys`, §15.8) | `key_revoked`, even without a certificate |
| 2 | empty payload → no certificate: only the per-key whitelist decides (§15.5) | — |
| 3 | length within `MIN_CERT_LEN..=MAX_CERT_LEN`, then format §15.1 rules 1–7 | `malformed` |
| 4 | `subject_key` canonical and not weak; **fingerprint of `subject_key` equal to the fingerprint of the static key authenticated by Noise** (constant-time comparison) | `key_mismatch` |
| 5 | `ca_key` equal, byte for byte, to a key pinned in `[[authorities]]` | `unknown_authority` |
| 6 | strict signature (§15.2) with that pinned key | `bad_signature` |
| 7 | `serial` in the denylist (`serials`) | `serial_revoked` |
| 8 | `now >= not_before - SKEW` (§15.6) | `not_yet_valid` |
| 9 | `now < not_after` | `expired` |
| 10 | `not_after - not_before <= max_lifetime` of the CA that signed | `lifetime_exceeds_authority` |
| 11 | (relay only) the key has the agent role in the policy | `role_conflict` |
| 12 | (agent only) its own node is within the effective scope (§15.5) | `node_out_of_scope` |

Check 4 comes **before** the signature: a stolen certificate presented with another static key
does not cost even one signature verification, and the responder does not act as a
verification oracle for arbitrary certificates. The fingerprint (§7.2) is computed on the
X25519 form, the same one Noise authenticates: two Ed25519 keys `P` and `−P` have the same
X25519 form and therefore the same identity, in the certificate as in the policy.

Outcome of a failure:

- **relay**: no message 2, connection closed (like an unknown key, §7.3); event
  `authentication_failed`. The client cannot distinguish a rejected certificate from a broken
  relay and tries the next relay (§13): this is why `zt-client` checks its own certificate
  locally before connecting (§15.6).
- **agent**: no message 2, stream closed with `Close Unauthorized` (like an unknown client, §8
  item 3); event `authentication_failed`. The client stops (error after the `OpenAck`, §13).

The relay rechecks steps 1, 5 and 7–11 in the relay core with the policy and the clock at the
moment the connection arrives there (a reload between the handshake and registration is not
lost, as for keys, finding 0004-9).

### 15.5 Authorisation: whitelist and certificates

A key listed in the policy (relay) or in the authorized clients (agent) is authorised **by the
whitelist**, which takes precedence:

| The key… | Certificate presented | Result |
| :- | :- | :- |
| is in the `keys` denylist | any | rejected (step 1) |
| is a whitelist client | none | whitelist permissions (as today) |
| is a whitelist client | valid | whitelist permissions; the certificate is ignored after verification (no merging of permissions, no in-session expiry) |
| is a whitelist client | invalid | rejected: a presented certificate is always verified (fail closed) |
| is an agent (relay only) | present | rejected (`role_conflict`): a key has only one role |
| is not in the whitelist | none | rejected (as today) |
| is not in the whitelist | valid | certificate permissions (below) |

The precedence of the whitelist makes migration gradual: a client receives the certificate while
its entry is still in the files; when the entry is removed (and reloaded) its connection drops
once (§12) and reopens with the certificate. Removing the key from the whitelist is not enough
to revoke a client that also has a certificate: the denylist is used for that (§15.8).

The precedence also applies to open connections (finding 0006-4): if a reload adds to the
relay's whitelist the key of a client connected with a certificate, the connection switches to
the whitelist credential and its permissions, even if narrower; streams to nodes no longer
granted are closed with `Close Unauthorized` and `access_revoked`, as for any narrowing (§12),
and from that moment on the connection no longer expires with the certificate.

**Effective scope** of a certificate signed by CA `A`:

```
relay:  granted nodes = policy nodes ∩ scope(cert) ∩ allow(A)
agent:  accepts       ⇔ own node ∈ scope(cert) ∩ allow(A)
where scope(cert) = allow(A) if scope = 0x01, otherwise the certificate's list;
      allow(A)    = all nodes if the CA has allow = ["*"]
```

A CA is valid only for the nodes the operator assigns to it (`allow`): a certificate that lists
a node outside `allow(A)` does not grant it, even if the signature is valid. The CA that counts
is the one whose pinned key verified the signature, not the name written somewhere. An empty
effective scope does not reject the connection (like `allow = []` for a key): every `Open`
receives `Reject NotAuthorized`, which remains indistinguishable from "nonexistent node" (§8).

The certificate's **name** is a label for the audit logs: it does not enter into any decision.
It may coincide with the name of a whitelist client or with that of another certificate
without any consequence for access; this is why events always also report the key fingerprint,
the CA and the serial number.

### 15.6 Time

All times are Unix UTC seconds from the system clock (`SystemTime`); a clock before 1970 counts
as 0 (fail closed: no certificate is valid yet). A certificate is valid at instant `now` if

```
not_before - SKEW  <=  now  <  not_after          with SKEW = 120 s
```

- The tolerance applies **only to `not_before`**: it covers an offline CA whose clock is
  slightly ahead, issuing a certificate "in the future" for relays and agents. `not_after` is
  never extended: expiry is the security boundary, and a verifier that is behind already
  lengthens it by itself.
- `SKEW` is a protocol constant, not an option: fewer knobs, no tolerance of hours set for
  convenience.
- Maximum lifetime: `not_after - not_before` exceeds neither the CA's `max_lifetime` (60..=86 400 s,
  default 28 800 = 8 hours; OPERATIONS §10) nor `MAX_CERT_LIFETIME` (24 hours, format rule).
- All time arithmetic is checked (`checked_*`/`saturating_*`): `not_before` close to 0 or
  `not_after` close to `u64::MAX` do not cause overflow.
- `zt-client` checks its own certificate before connecting, with its own clock: it rejects a
  certificate that has already expired or that is not for its own key, and warns on stderr if it
  expires within 15 minutes or is not yet valid. This is only an aid for the user: decisions are
  made by relays and agents.

Accepted residual risk: whoever moves the clock of a relay **and** of an agent backwards (an
attack on NTP) makes expired certificates valid again. NTS is recommended (OPERATIONS §10); the
denylist remains effective in any case.

### 15.7 Expiry during the session

**A session authorised by a certificate ends when the certificate expires.** At the moment
`now >= not_after`:

- the **relay** sends `Close Unauthorized` on every stream of the client's connection, to both
  sides (client and agent), then closes the connection, and records `certificate_expired`. The
  check takes place on every tick of the relay core (1 s);
- the **agent** closes every end-to-end session authorised by that certificate with
  `Close Unauthorized` and records `certificate_expired`. The check rereads the system clock at
  least every 60 s and at the expected expiry, so a forward jump of the clock or a suspended VM
  do not extend the session by more than 60 s;
- `zt-client`, on receiving `Close Unauthorized` after its own certificate has expired, says so
  explicitly ("certificate expired: renew it") and exits with code 1.

Rationale:

1. **Short lifetime is the only automatic revocation.** If sessions survived expiry, whoever
   steals key and certificate would open a session at the last minute and keep it open for days
   (ControlPersist, idle tunnels with keepalive): "short" would be worth nothing precisely
   against the attacker.
2. **Consistency with hot revocation (§12)**, which already applies to open sessions: expiry is
   a revocation announced in advance.
3. **The denylist can be pruned.** Since no session survives `not_after`, a denylist entry can
   be removed after the certificate expires (§15.8); otherwise it would have to stay until every
   session opened with it had ended, which nobody knows.

The operational cost is known and documented (OPERATIONS §10): a playbook longer than the
certificate is interrupted, so one issues a certificate that covers its duration (within
`max_lifetime`) or renews it beforehand; with `ControlPersist` the SSH master uses the
certificate it was created with, and after a renewal it must be closed (`ssh -O exit`) to use
the new one.

Sessions authorised by the whitelist do not expire, even if the client presented a certificate
(§15.5).

### 15.8 Revocation

Between issuance and expiry a certificate is revoked with a **denylist**, a separate file
(`revoked.toml`, OPERATIONS §10) that relays and agents read with `--revocations` and reload on
`SIGHUP` together with the policy or the authorized clients, in a single step: if either of the
two files is invalid the reload fails in full and both previous ones remain
(`..._reload_failed`). The file is the same for the whole fleet, relays and agents: a single
artefact to distribute and compare (`sha256sum`).

| Entry | Effect |
| :- | :- |
| `serials` | that certificate is rejected (step 7) |
| `keys` | that key is rejected with **any** credential: all its certificates, from any CA, and its whitelist entry (step 1). This is the revocation of a person or a machine |

The denylist also applies to open connections and sessions, like any reload (§12). A key is
compared by fingerprint (X25519 form), so `P` and `−P` are the same entry.

With a pinned CA, `--revocations` is **mandatory** (even with an empty file): relays and agents
do not start, and a reload fails, if the configuration has `[[authorities]]` but no denylist.
This way the path for an urgent revocation already exists before it is needed.

A `serials` entry can be removed once the certificate has been expired for more than `SKEW`
(§15.7): `zt-ca` records every issuance with serial number and expiry (OPERATIONS §10). A `keys`
entry stays until the key has been replaced everywhere.

Emergency revocation of an entire CA: its key is removed from `[[authorities]]` and the
configuration is reloaded; all its certificates, including those in use, drop.

### 15.9 CA rotation

As for agent keys (§14), an `[[authorities]]` entry has one key (`public_key`) or, during a
rotation, two (`public_keys = ["<new>", "<old>"]`). The same `name`, `allow` and
`max_lifetime` apply to both.

1. The new CA is created (offline) and its key is added to the entry, on all relays and
   agents; the configuration is reloaded.
2. New certificates are issued with the new CA.
3. Once at least `max_lifetime` has passed since the last certificate signed by the old one, no
   certificate from the old one is valid any more: it is removed and the configuration is
   reloaded.

As long as an entry has two keys, relays and agents record `ca_rotation_pending` at startup, on
every reload and every hour. A **compromised CA** is not rotated: it is removed immediately
(§15.8, emergency revocation) and the certificates are reissued with a new CA.

Load constraints, all fatal: at most `MAX_AUTHORITIES` (16) entries; one or two keys per entry,
distinct; a CA key appears in only one entry; a CA key is never the key of a peer in the same
configuration (agent or whitelist client), nor the key of the process itself (relay or agent,
current or previous), nor, for an agent, the key of a pinned relay (`--relay-key`): otherwise a
compromised relay, with its own node seed turned into a CA file, would sign certificates that
the agent admits (finding 0006-1); CA names are mutually distinct `NodeId`s; keys are canonical
and not weak. The check applies at startup and on every reload, in both directions: a policy
reload rejects a CA equal to the relay keys in force, and a reload of the relay keys (§14)
rejects a key equal to a CA of the policy in force or of the policy on disk, so a CA and an
equal key written for the same `SIGHUP` do not get in together (`relay_keys_reload_failed`,
"authority key equals the relay key"; finding 0006-2).

### 15.10 Multiple relays

Nothing changes with respect to §13. All relays must have the same `[[authorities]]` and the
same denylist. A relay that does not pin the CA, or that has not yet reloaded a more permissive
denylist, closes the handshake without responding, and the client moves on to the next one as
for an unknown key. In the same way a revocation is complete on the relays only when all of
them have reloaded the denylist; the agents apply it on their own regardless, whichever relay
is used.

### 15.11 Audit

New events or events with new fields (OPERATIONS §6). A certificate never appears in the logs:
only serial number (hexadecimal), CA and client fingerprints, name and expiry.

| `event_kind` | Level | When, and added fields |
| :- | :- | :- |
| `authentication_failed` | WARN | a check from §15.4 fails: `reason` (`key_revoked` or `certificate`), `cert_check`; `ca`, `serial`, `cert_name` and `not_after` only after step 6 (signature verified), on relay and agent |
| `session_established` (relay), `e2e_session_started` (agent) | INFO | `credential` = `key` or `certificate`; for a certificate also `ca`, `serial`, `cert_name`, `not_after`. Recorded only after an authentic message from the client (§15.3) |
| `access_denied` | WARN | as today, with the same certificate fields |
| `access_revoked` | WARN | as today, with the same certificate fields |
| `certificate_expired` | INFO | (relay and agent) a session authorised by a certificate was closed at expiry: `peer`, `ca`, `serial` |
| `authorities_in_use` | INFO, WARN with two keys | at startup and on every reload, for each CA: `authority`, `fingerprints`, `max_lifetime` |
| `ca_rotation_pending` | WARN | at startup, on every reload and every hour, for each CA with two keys |
| `revocations_in_use` | INFO | at startup and on every reload: `serials`, `keys` (how many entries) |

From R-1 on (§10.1), the relay writes `authentication_failed` only for a key the configuration
knows, or for a certificate rejected after its signature was verified (from `serial_revoked`
on). Other failures before key confirmation are counted in `preauth_summary`. On the agent
every rejection keeps its own line: a flood there needs a compromised relay, and its streams
are bounded per relay.

Comparing the serial numbers seen in the audits with the `zt-ca` issuance register
(OPERATIONS §10) reveals a certificate that the CA did not issue, i.e. a compromised CA.

### 15.12 Limits

| Limit | Value | Rationale |
| :- | -: | :- |
| `MAX_CERT_LEN` | 4 328 bytes | 64 nodes of 63 bytes, 63-byte name; fits in a `Data` and in a message 1 |
| `MIN_CERT_LEN` | 170 bytes | the shortest certificate (`scope = 0x01`, 1-byte name) |
| `MAX_CERT_NODES` | 64 | beyond that, use `scope = 0x01` with a dedicated CA |
| `MAX_CERT_LIFETIME` | 86 400 s | "short" by construction |
| `max_lifetime` of a CA | 60..=86 400 s, default 28 800 | per CA |
| `SKEW` | 120 s | only on `not_before` |
| `MAX_AUTHORITIES` | 16 | per file |
| keys per CA | 1 or 2 | rotation |
| `serials` / `keys` in the denylist | 16 384 / 4 096 | hash table lookup; file within 1 MiB |
| expiry check | 1 s (relay), ≤ 60 s (agent) | §15.7 |

The cost of a message 1 with a certificate, for its receiver, is at most one extra signature
verification compared with today, and only after the binding check (step 4): it stays within
the per-source budget of unconfirmed handshakes (§10.1) on the relay and within the per-relay stream quota on the
agent. The relay core keeps, for each connection with a certificate, only the verified data (at
most 64 nodes), not the certificate bytes.

### 15.13 Reference vector

CA with Ed25519 seed `01 × 32`, client with seed `02 × 32` (seeds are the key file format,
§7.2), `serial = 01 02 … 10`, `not_before = 1 800 000 000`,
`not_after = 1 800 003 600`, name `alice`, nodes `db-01`, `web-01` (L = 187):

```
ca_key      8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
subject_key 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
client fingerprint SHA256:2f5eeec4374d5bc20b0db3d79cf1ebaee1b6834b48e41fe65e8d24f5b653228b

54 43 4e 43 01 01 8a 88 e3 dd 74 09 f1 95 fd 52
db 2d 3c ba 5d 72 ca 67 09 bf 1d 94 12 1b f3 74
88 01 b4 0f 6f 5c 81 39 77 0e a8 7d 17 5f 56 a3
54 66 c3 4c 7e cc cb 8d 8a 91 b4 ee 37 a2 5d f6
0f 5b 8f c9 b3 94 01 02 03 04 05 06 07 08 09 0a
0b 0c 0d 0e 0f 10 00 00 00 00 6b 49 d2 00 00 00
00 00 6b 49 e0 10 05 61 6c 69 63 65 00 02 05 64
62 2d 30 31 06 77 65 62 2d 30 31 65 9f a0 0c 94
7c 7c 51 3c 25 6d b9 67 3b a4 0a 89 5e e8 ad ba
9e 4d a9 7e 57 8f 67 43 f9 76 ac 53 01 b6 aa d1
20 3e 4a 03 a8 7d d2 cf fc a2 2d 96 41 26 ae 7d
5b 26 a9 d1 60 67 69 7e 5b 53 0f
```

The vector was computed outside the project; as for framing, if the test
`reference_vector_matches_the_protocol` contradicts it, this document must be corrected.

### 15.14 Attacks considered

| Attack | Defence |
| :- | :- |
| stolen certificate (from logs, from the relay, from a backup) presented with another static key | binding at step 4: the subject's fingerprint must be the one proven by Noise; no signature verification for unbound certificates |
| key and certificate stolen together | short lifetime, expiry also within the session (§15.7), `serials`/`keys` denylist |
| one department's CA signing for another department's nodes | effective scope ∩ the CA's `allow` (§15.5); the CA is identified by the pinned key that verifies the signature |
| same CA key in two entries with different scopes; CA key also used as a peer key | rejected at load time (§15.9) |
| algorithm, version or format confusion | single-valued `magic`, `version`, `sig_alg`; versioned signature context; distinct prefixes for certificate files and CA key files; node keys never sign |
| malleable certificates (two encodings of the same content, non-canonical keys, malleable signatures) | canonical encoding (§15.1), canonical and non-weak keys, `verify_strict`, identity = `serial` |
| huge certificate or one with many nodes to consume memory or CPU | `MAX_CERT_LEN` checked before parsing; `MAX_CERT_NODES`; bounded message 1 payload; signature verified after the cheap checks, within the handshake limits |
| extreme `not_before` / `not_after`, long lifetime, overflow | format rule 4, per-CA `max_lifetime`, checked arithmetic, tolerance only on `not_before` |
| keeping a session open beyond expiry | §15.7 |
| bypassing the denylist with another certificate for the same key, with `−P`, or with the whitelist entry | `keys` applies to every credential and compares fingerprints |
| invalid denylist during an emergency | the reload fails in full with an ERROR event; the agents apply it on their own; emergency revocation of the CA |
| certificate name equal to that of another client | names authorise nothing; audits always have fingerprint, CA and serial |
| removing the certificate to fall back on the whitelist (downgrade) | the payload is authenticated by Noise: removing it requires the client's secret key; whitelist precedence is the operator's choice, not the peer's |
| compromised relay forging or altering certificates towards the agent | the relay does not have the CA key; the end-to-end certificate is encrypted towards the agent; the agent verifies it by itself, including its own node being in scope |
| compromised relay replaying end-to-end message 1 | as today: without the suite's confirmation (`TCN/1 ready` or `TCN/2 ready`) no sshd and no registered session (finding 0002-3) |
| replayed message 1 to make a client appear in the audits | success events are recorded only after an authentic message (§15.3) |
| CA signing a certificate for an agent's key | `role_conflict` on the relay; the key cannot open streams |
| relay and agent clock moved backwards | accepted residual risk (§15.6); NTS recommended; denylist |

## 16. Out of scope

Hot reload of an agent's key (requires restarting that agent); shared or synchronised policy
across relays; rate limiting for IPv4 prefixes wider than a single address. For certificates:
certificates for agents and relays; an online CA or automatic certificate renewal; automatic
distribution of the denylist (CRL/OCSP); certificate constraints beyond nodes (source
addresses, SSH users, commands): these remain SSH's job.
