# Adversary review 0005: high availability and key rotation (Phase 5)

**Surface:** multiple relays per agent and client (`RelayEndpoint`, `MAX_RELAYS`, one session per
relay in the agent, client failover in `may_try_next_relay`), `Keyring` with current and
previous key (`respond_any`), relay key reload with `SIGHUP`, two keys per node
in the policy (`public_keys`, `add_agent_keys`), validation of `--relay`/`--relay-key`,
`[[relays]]` and `--previous-key`.
**Reviewer:** independent adversary agent, given the code and not the author's
conclusions. It worked on a copy of the repository; every hypothesis was
verified with a test that asserted the attackable behaviour.
**Attacker:** (a) remote host; (b) one compromised relay out of N, or a stolen client key;
(c) DNS hijacked towards an impostor; (d) operator error (partial policy rollout,
previous key forgotten in the systemd unit, same key twice).

## Findings open at review time, all fixed in this PR

| # | Attack hypothesis | Severity | Fix | Regression |
| :-: | :- | :-: | :- | :- |
| 1 | The agent's `max_streams` semaphore was shared across all relays. A compromised relay opened streams without ever sending `msg1` and held all the permits for a whole handshake timeout, renewing them continuously: the honest client going through a good relay received `Reject ResourceExhausted` (14 attempts out of 16 in 8 s), a final error. This contradicted PROTOCOL §13 ("a slow relay does not affect the sessions through the others"). | medium | Each session with a relay has its own stream quota (`ResourceExhausted` only towards that relay). The global limit permit is taken only after `CONFIRM`, i.e. after the client has completed the end-to-end handshake; if none is available, the stream is closed with `Close Drained`. A relay can only exhaust its own quota of unauthenticated streams. | `a_compromised_relay_cannot_starve_sessions_through_the_others`, `the_session_limit_holds_for_the_whole_agent` |
| 2 | A client key removed from relay A's policy but not from B's (partial rollout or `policy_reload_failed`): A closes the outer handshake, the client treats it as a failure and moves on to B, where the session succeeds with no signal at all. OPERATIONS §2 said that a misaligned policy "shows up as an access denied", which is true only for a narrowed permission (`NotAuthorized`). | low (docs) | Text fixed in PROTOCOL §13 and OPERATIONS §2, §7: revocation is complete only when all relays have reloaded the policy; how to verify it (`sha256sum` of the policy on all relays); the key removed from `clients.toml` on the agents remains the defence that does not depend on the relays. The client's behaviour is intended: a relay that does not recognise the key is indistinguishable from a failed relay, and with a stolen key the attacker would use their own client anyway. | `agent_revocation_cuts_the_session_even_if_the_relay_still_allows_it` (existing) |
| 3 | A forgotten previous key was visible nowhere: no log reported its presence or fingerprint, `relay_keys_reloaded` did not say which keys were in effect, and a `--previous-key` left in the systemd unit stayed accepted forever. PROTOCOL §14 said "without a restart", whereas OPERATIONS §8 requires one to add and one to remove `--previous-key`. | low | Relay and agent log `keys_in_use` (`role`, `current_fingerprint`, `previous_fingerprint`) at start-up and on every reload, at WARN level if there is a previous one; as long as there is, `previous_key_still_accepted` every hour. PROTOCOL §14 aligned with OPERATIONS §8; events documented in OPERATIONS §6. | `a_previous_key_is_announced_and_reminded_until_it_is_removed`, `a_single_key_is_announced_once_and_never_reminded`, `sighup_rotates_the_relay_key_without_a_restart`, `the_previous_key_cannot_be_the_current_key` |
| 4 | The duration of an invocation grows with the number of relays: with 8 silent relays the worst case is several minutes, and an address hijacked towards a black hole adds a timeout to every Ansible connection. | low | **Accepted and documented** (PROTOCOL §13): attempts are sequential and failover does not change security; the most reliable relays should be listed first. An overall deadline or parallel attempts remain in the backlog. **Closed by R-4 (A5-4):** a 20 s overall deadline (`connect_deadline_secs`), per-step timeouts of 3/5/10 s and a hedge of at most two attempts, only while connect and outer handshake are incomplete (PROTOCOL §13; resilience §5.3). | `a_black_holed_first_relay_costs_only_the_stagger`, `all_relays_down_ends_at_the_deadline` |

The regression test for finding 1 surfaced an older, intermittent defect (about
one time in three under load): when the task of an agent stream had already finished, a
client `Data` frame still in flight found the queue closed and the agent answered
`Close ProtocolViolation`, which could reach the client before the real `Close` (here `Drained`,
but it also applies to an unreachable sshd). Now a frame for a stream whose task has finished is
dropped like the other in-flight frames; `ProtocolViolation` remains only for a full queue, i.e. a
relay that does not respect the credit. Verified with eight complete consecutive runs of
`the_session_limit_holds_for_the_whole_agent` without errors.

## Refuted or accepted hypotheses

| # | Attack hypothesis | Outcome |
| :-: | :- | :- |
| 5 | Retry after `OpenAck`: duplicate sessions, impostor agent disguised behind another relay | **Mitigated.** `msg1` is sent only after `OpenAck`, and from then on every error is final. `an_impostor_agent_is_reported_and_never_retried_elsewhere`, `an_agent_refusal_is_final_and_never_retried_elsewhere`. |
| 6 | Retry after the agent has already received `msg1` | **Mitigated**: it cannot happen. A `Timeout("open")` leaves at most one stream on the agent waiting for `msg1`, which is closed when the connection with that relay drops. |
| 7 | DNS hijacked towards an impostor at the first address | **Mitigated.** Each relay has its own pinned key: moving on to the next one does not lower security. `the_client_falls_back_past_an_impostor_at_the_first_address`. |
| 8 | A compromised relay answers `NotAuthorized`, or sends `OpenAck` and then goes silent, defeating failover | **Accepted.** High availability covers failures, not a Byzantine relay; retrying after `OpenAck` is forbidden on purpose. |
| 9 | `may_try_next_relay` too permissive on `Protocol`, `Crypto`, `Decode` | **Accepted.** They happen before `OpenAck` and the next relay authenticates itself. On `ResourceExhausted` it is restrictive, in the safe direction. |
| 10 | `RateLimited` checked before authorisation: failover of a revoked client | **Accepted.** Each `zt-client` opens a new connection with a full bucket; it is not reached in practice. |
| 11 | Semaphore permits lost through a panic or the drop of the session with a relay | **Mitigated.** Permits are returned when the session drops; `panic = "abort"` in release and `Restart=always` in systemd. |
| 12 | Two relays that register the same agent exchange traffic | **Mitigated.** Streams are per session and ids per relay. `the_agent_serves_through_every_relay_of_its_list`. |
| 13 | Old and new agent keys registered at the same time | **Accepted.** The last registration wins, the previous one is drained. A ping-pong is possible only for whoever holds the old key, and a compromised key gets revoked (PROTOCOL §14). |
| 14 | Removing the old key from the policy must close the connection authenticated with it | **Mitigated.** The reload removes the role and closes the connection. |
| 15 | Sneak keys into `add_agent_keys` (three keys, duplicates, another peer's key) | **Mitigated.** `more_than_two_keys_or_none_are_refused`, `the_same_key_twice_is_refused`, `a_key_of_another_peer_cannot_be_smuggled_in_as_a_second_key`, `agent_key_lists_are_validated`. |
| 16 | Timing or oracle in `respond_any` | **Accepted.** Timing reveals only which public key worked; an invalid `msg1` costs 2 DH instead of 1, and flooding is already limited by the handshake gate. |
| 17 | Relay key reload in the middle of a handshake | **Mitigated.** Each connection takes the keys at accept. `sighup_rotates_the_relay_key_without_a_restart`. |
| 18 | Remove the previous key with a reload | **Accepted** and documented: with the file missing or equal to the current one the reload fails and the previous keys remain; a restart is needed. Observability is finding 3. |
| 19 | Operator errors: same key twice, misaligned `--relay` and `--relay-key`, repeated relays | **Mitigated.** `the_previous_key_cannot_be_the_current_key`, `a_relay_list_with_mismatched_or_repeated_entries_is_refused`, `a_keyring_loads_both_keys_and_refuses_the_same_key_twice`. |
| 20 | Client with both `relay` and `[[relays]]`, or `relay` without a key | **Mitigated.** `a_relay_list_must_be_unambiguous_and_bounded`. |
| 21 | A relay key equal to a node key | **Mitigated.** `no_relay_key_may_double_as_a_node_key`. |
| 22 | Secrets in logs | **Mitigated.** `Identity` prints as `<redacted>`; loading errors report only the path; the new events report only fingerprints. |
| 23 | Different policies across relays used to look for a more permissive relay with `NotAuthorized` | **Mitigated.** `a_policy_denial_is_final_and_never_retried_elsewhere`. For a key removed entirely see finding 2. |

## Second review (0005b, high effort)

A second independent review, carried out in greater depth before the merge, verified the
fixes of the first one and looked for what it had missed. It found a defect of medium
severity precisely in the fix for finding 1. All findings are fixed in this PR.

| # | Attack hypothesis | Severity | Fix | Regression |
| :-: | :- | :-: | :- | :- |
| 5b-1 | **The fix for finding 1 did not hold.** The per-relay quota counted slots, but a `Close` from the relay removed the slot immediately, while the stream's task was still alive. A compromised relay that loops `Open`, garbage `msg1` and `Close` never hit the quota: tasks and memory grew with the duration of the attack (`zt-agent` release, 600 000 streams: RSS from 4.8 MB to 219 MB in 26 s). The same happened in the "credit exceeded" branch. | medium | The slot lives as long as the task: a `Close` (or a credit violation) only detaches the queue towards the task, and the slot is removed by the `done` channel when the task has finished. Subsequent frames for that id are dropped. `done` cannot remove the slot of a newer stream: ids grow and a repeated id closes the session. | `a_relay_close_does_not_free_the_quota_before_the_stream_task_ends` |
| 5b-2 | A second agent key left in the policy (`public_keys = [new, old]`) was never reported: whoever holds the old key can still register as the node. | low | WARN event `agent_rotation_pending` (`node`, `fingerprints`) at start-up, on every reload and every hour, for every node with two keys. | `an_agent_rotation_left_in_the_policy_is_reported_until_it_is_completed`, `a_pending_agent_rotation_in_the_policy_is_reported`, `agent_keys_lists_both_keys_of_a_node_in_rotation` |
| 5b-3 | The same relay listed twice by the agent, once with the old key and once with the new one (for example `127.0.0.1:p` and `localhost:p`), passes validation. The two sessions override each other and bring down the SSH sessions. | low (operator) | OPERATIONS §8 and PROTOCOL §14: the pin is **replaced**, not supplemented with a second entry. Names are not resolved at start-up (addresses can change). | — |
| 5b-4 | A huge `--max-streams` made the agent panic at start-up (tokio's semaphore has a maximum). | low | `--max-streams` accepts 1..=4096 (`agent::MAX_STREAMS`). `agent::run` rejects out-of-range values without panicking. | `max_streams_out_of_range_is_refused_without_panic`, `an_out_of_range_max_streams_is_refused_without_panic` |
| 5b-5 | Every `SIGHUP` reloads both the policy and the relay keys. Following the runbook as it was written (first move the files, then add `--previous-key` and restart), a policy reload between the two steps activated the new key without the previous one. | low (docs) | OPERATIONS §8 runbook rewritten: the swap happens in a single step (a drop-in with the new `--key` and the old `--previous-key`, then a restart). In every intermediate state a reload either changes nothing or fails safely. PROTOCOL §14 and the systemd unit say the same. | — |

Refuted or accepted by the second review:
- the `done` channel removing the slot of a newer stream (refuted: ids are not reused);
- several colluding relays exhausting the global limit (refuted: the permit is taken after `CONFIRM`, which a relay cannot produce; k quotas of unconfirmed streams remain, each with a bounded window: accepted);
- dropping frames towards a finished task leaving the client hanging (refuted: every task exit sends `Close`, which precedes `done`);
- secrets in logs during rotation (refuted: fingerprints only);
- connections opened before a `SIGHUP` keep the old keyring (accepted).
