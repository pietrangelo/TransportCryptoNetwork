# Adversary review 0002: relay, agent and handshake (Phase 2)

**Surface:** `zt-application` (relay core, rate limiter), `zt-crypto` (identity, Noise IK),
`zt-net` (Noise channel over TCP, relay server, agent, client, configuration).
**Reviewer:** independent adversary agent, given the code and not the author's
conclusions. Every hypothesis was proven with an executed test, or refuted by
a test or by a line of code.
**Attacker:** (a) unauthenticated network; (b) authenticated but malicious peer (compromised agent,
stolen client key); (c) compromised relay.

## Findings open at review time, all fixed in this PR

| # | Attack hypothesis | Severity | Fix | Regression |
| :-: | :- | :-: | :- | :- |
| 1 | A client authorised by the relay but rejected by the agent opens a stream and closes it. The agent answered the `Close` with another `Close`, which the relay treated as a "close on unknown stream": it disconnected the agent and killed **all** the node's sessions. Deterministic. | high | The relay silently drops frames on already-closed streams (agent side: ids below `next_stream`; client side: last 256 closed ids). The agent no longer answers a `Close` with a `Close`. | `crossing_close_is_dropped_silently`, `open_close_by_a_rejected_client_does_not_kill_other_sessions` |
| 2 | Ordinary races between closes: the agent's `Data`, `WindowUpdate`, `Close` or `OpenAck` in flight after the client's `Close` brought the agent down, even with no attacker. | high | As #1. | `agent_frames_in_flight_after_client_close_are_dropped`, `late_open_ack_or_reject_after_client_close_is_dropped` |
| 3 | A compromised relay replays a captured first end-to-end IK message: the agent answered, opened a connection to sshd and logged "session started" for that client. Forgeable audits and sshd pre-auth slots consumed. | medium | As its first transport message the client sends a confirmation (`TCN/1 ready`) that only a party that completed the handshake can encrypt. The agent contacts sshd and logs the session only after verifying it. | `replayed_end_to_end_handshake_never_reaches_sshd` |
| 4 | `Open`/`Close` flood: free for the client, two frames each towards the agent. An agent on a slow link ended up with the hub queue full and got deregistered. | medium | `Open` token bucket per client connection (burst of 64, then 10/s), applied before any other check; the excess receives `Reject RateLimited`. | `open_floods_are_rate_limited` |
| 5 | 65 536 addresses from a single IPv6 /64 filled the handshake rate limiter's table, which then rejected every new address. | medium | Rate limiter key: address for IPv4 (including IPv4-mapped), /64 prefix for IPv6. | `every_address_of_an_ipv6_slash64_shares_one_key`, `ipv4_and_ipv4_mapped_addresses_are_keyed_per_address` |
| 6 | The agent closes while client `Data` is in flight: the relay disconnected the client. | low | As #1. | `client_frames_in_flight_after_agent_close_are_dropped` |

The fixes to #1, #2 and #6 do not loosen the rules: a frame on a stream that was **never** opened
is still a violation (`frames_on_never_opened_streams_are_still_violations`).

## Refuted hypotheses

| # | Attack hypothesis | Outcome |
| :-: | :- | :- |
| 7 | Replay the first message of an agent's outer handshake to take over its node. | **Mitigated.** The replayed connection never completes the handshake and, without `Register`, times out. |
| 8 | An agent registers under another node's name or writes into another agent's streams. | **Mitigated.** `agent_cannot_register_as_another_node`, `agent_cannot_inject_into_streams_it_does_not_own`. |
| 9 | Ed25519 keys P and −P have the same X25519 form and the same fingerprint. | **Mitigated.** The policy rejects the duplicate key (`a_key_has_exactly_one_role_and_a_node_one_agent`). |
| 10 | Make the relay queue unlimited data; `WindowUpdate` overflow or flood. | **Mitigated.** `data_beyond_the_window_kills_the_sender`, `tiny_or_overflowing_window_updates_are_violations`. |
| 11 | Flood of `Ping`, unsolicited `Pong`, frames before `Register`, `Register` from a client. | **Mitigated.** Tests of the same name in `relay_core.rs`. |
| 12 | Malformed frames, stream 0, invalid node names, log injection through names. | **Mitigated.** `decode_malicious.rs`, `[a-z0-9-]` alphabet of `NodeId`s. |
| 13 | A malicious relay sends the agent an `Open` for another node. | **Mitigated.** The agent answers `Reject NotAuthorized`. |

## Verified by the author after the review

| # | Hypothesis | Outcome |
| :-: | :- | :- |
| 14 | A malicious relay pushes data beyond the window into the queue of an agent stream (credit was only checked on leaving the queue). | **Fixed.** Agent and client enforce the credit **before** queuing (`relay_exceeding_stream_credit_gets_the_stream_closed`). |
| 15a | A malicious relay reuses a stream id, making a terminated task remove the new stream. | **Fixed.** The agent only accepts strictly increasing ids. |
| 15b | TOCTOU between the key permission check and the read. | **Fixed.** Permissions are checked on the already-opened file. |
| 15c | Timing side channels. | **Accepted.** Identity comparisons are made on fingerprints already authenticated by Noise; fingerprints use `subtle`. |

## Accepted residuals

- The handshake rate limiter remains *fail closed*: an attacker with 65 536 /64 prefixes
  (a whole /48) can still block **new** addresses for about a minute. Agents that are
  already connected are not affected. A threshold for a shorter prefix arrives with Phase 4.
- The relay sees metadata (who talks to whom, when, how many bytes): this is inherent to a relay.
