# Adversary review 0004: hardening (Phase 4)

**Surface:** hot revocation (`Revocable`, `Input::PolicyUpdated` in the relay core, revocation
in the agent's sessions, reload with `SIGHUP`), implicit Noise rekey, handshake limit per /48
prefix, JSON audit log, fuzzing targets, systemd units, release workflow and `cargo deny`.
**Reviewer:** independent adversary agent, given the code and not the author's
conclusions. Every hypothesis was verified with a test or a measurement on a copy
of the repository (strace for the syscall filter, `systemd-analyze` for the units).
**Attacker:** (a) remote host, even with a whole IPv6 /48; (b) compromised relay;
(c) operator error (invalid file, `reload` during start-up, key pasted into the wrong
file); (d) supply chain (GitHub actions, dependency build scripts).

## Findings open at review time, all fixed in this PR

| # | Attack hypothesis | Severity | Fix | Regression |
| :-: | :- | :-: | :- | :- |
| 1 | The /48 bucket was consumed on every handshake: a single host reconnecting twice a second (burst 64, 1/s) exhausted it and locked out all the other /64s of the same /48, i.e. the neighbours in a home /56 or a cloud VPC. | medium | The /48 bucket limits the appearance of **new** /64s: a /64 already in the table is throttled only by its own bucket. The limit against whoever controls a /48 remains (65 536 new /64s in one go → at most 64 admitted). | `one_busy_host_cannot_lock_out_its_slash48_neighbours`, `a_whole_slash48_cannot_lock_out_other_networks` |
| 2 | A `SIGHUP` arriving before the handler was installed killed the relay (40 out of 40 at 0 ms from start). With `Restart=on-failure` systemd did not restart it, because `SIGHUP` counts as a clean exit: a `systemctl reload` right after start shut the relay down. | low | The handler is installed before reading the key and trust files, so a signal during the read is not lost. The units are `Type=notify`: the service sends `READY=1` only once it already handles `SIGHUP`, and systemd does not run `reload` before that. The remaining window (before `main`, measured under 5 ms) is not reachable from `systemctl`. The relay now has `Restart=always`. | `ready_is_notified_only_once_sighup_is_handled` |
| 3 | PROTOCOL §12 said that an agent associated with another node reconnects with the new name. In reality the agent keeps declaring its own `--node` and is rejected in a loop. | low (docs) | §12 fixed: an agent's node is changed in the policy **and** in the agent's configuration (`TCN_NODE`). | — |
| 4 | The agent's session events had target `zt_audit` but no `event_kind`; the relay's events put the data in a `Debug` string (`fields.event`) that a SIEM has to parse. | low | Every event has `event_kind` and separate fields (`peer`, `node`, `session`, `stream`, `reason`, `rule`, `outcome`). New agent events `e2e_session_started` / `e2e_session_ended`. | `audit_events_are_json_with_a_stable_kind_and_no_secrets` |
| 5 | Workflow actions were referenced by mutable tags, even in the job that receives the OIDC token for attestation; the same job ran `cargo test` and `cargo build`, i.e. the build scripts of all dependencies; `cargo-fuzz` had no version. A moved tag or a compromised dependency could sign a fake binary with the project's provenance. | medium | Actions pinned to a commit. Compilation runs without permissions; a separate `attest` job, which compiles nothing, verifies the hashes and attests. `checkout` without persisted credentials. `cargo-fuzz` 0.13.2. | workflow review |
| 6 | Fuzzing did not reach important parts: `noise_responder` never got to the accepting branch; `transport_decrypt` did two key generations and a rekey per input; `config_parsers` claimed "no secrets in errors" without checking it; the relay core (and therefore `PolicyUpdated`) was not fuzzed; `fuzz/Cargo.lock` escaped `cargo deny`. | low | `noise_responder` modifies an authentic msg1 in half of the inputs and checks that an accepted message reveals only the true identity; `transport_decrypt` uses fixed identities and rekeys only if the input asks for it; `config_parsers` checks that errors do not report long hexadecimal sequences; new `relay_core` target (sequences of connections, frames, clock ticks and reloads: no sends to closed connections, no peer without a role connected after a reload); `cargo deny` on `fuzz/` too. The new `config_parsers` check immediately found a real defect: a private key pasted by mistake into a trust file ended up in the error message (`unknown field \`<64 hex>\``) and therefore in the journal. Now hexadecimal sequences of 32 characters or more are replaced by `<redacted>`. | `a_secret_pasted_into_a_trust_file_is_not_echoed_in_the_error`; 60–90 s per target without crashes |

Rekeying is not the weak point it seems: the 1024-message limit applies per direction and
counts only authentic messages. In a large transfer this means a rekey roughly every
16 MiB (PROTOCOL §7.4); in an interactive SSH session, one every 1024 messages, much sooner.

## Refuted or accepted hypotheses

| # | Attack hypothesis | Outcome |
| :-: | :- | :- |
| 7 | Desynchronise the rekey with forged or lost messages | **Mitigated.** A message that does not decrypt does not advance the counter; the transport is reliable and ordered (TCP), so there are no lost messages. `transport_decrypt`, `tests/rekey.rs`. |
| 8 | Forged message accepted after a rekey | **Mitigated.** `transport_decrypt` goes through the rekey. |
| 9 | Race between policy reload and new connections (a connection authenticated with the old policy reaches the core after the new one) | **Mitigated.** The relay hub reads the policy first (`biased`), and the core re-applies it to already registered connections; the agent checks the current value before every wait. `tests/revocation.rs`. |
| 10 | Incomplete revocation: a stream to a node no longer granted stays open | **Mitigated.** `Close Unauthorized` on both sides, one `access_revoked` per node; new `relay_core` target. |
| 11 | Invalid file on reload | **Accepted** as a design choice: the previous configuration remains, with an ERROR-level `..._reload_failed` in the audit. `an_invalid_policy_on_reload_keeps_the_previous_one`. |
| 12 | The `SystemCallFilter=@system-service ~@privileged` filter breaks tokio or rustix | **Refuted** with strace: all the syscalls used are in the set. |
| 13 | `PrivateUsers=yes` breaks the owner check on trust files | **Refuted.** The files are owned by root or `tcn`, both visible in the namespace. |
| 14 | Option injection from `EnvironmentFile` | **Refuted.** Each variable becomes a single argument and goes through clap's parser. |
| 15 | The `systemd-analyze security` score hides an exposure | **Refuted.** 1.2 "OK"; what remains open (IPv4/IPv6 network, Unix socket for systemd) is needed by the service. |
| 16 | Permissive `deny.toml` (wildcards, git, licences) | **Refuted.** Sources from crates.io only, wildcards forbidden; the only licence exception (NCSA for `libfuzzer-sys`) concerns only `fuzz/`. |
| 17 | The claims about rekeying (interval, cost) are wrong | **Refuted**, with the clarification given above (16 MiB applies only to large transfers). |
| 18 | Bypass the /48 limit with IPv4-mapped addresses (`::ffff:a.b.c.d`) | **Refuted.** Addresses are canonicalised before the keys are computed: an IPv4-mapped address is treated as IPv4. |
