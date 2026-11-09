# Adversary review 0003: `zt-client` as `ProxyCommand` (Phase 3)

**Surface:** `bins/zt-client` (CLI, configuration lookup, stdin/stdout wiring),
`zt-net::config` (client configuration, checks on trust files), `zt-net::client` and
`zt-net::stream` (pump towards the local process).
**Reviewer:** independent adversary agent, given the code and not the author's
conclusions. Every hypothesis was verified with a test executed on a copy of the
repository (OpenSSH 9.6p1, Ansible), or refuted by an existing test.
**Attacker:** (a) local user with another UID; (b) compromised relay; (c) malicious agent;
(d) whoever controls the host names that reach `%n`/`%h` (Ansible inventory, typed name).

Before the review, the specification tests had already found a defect: `zt-client`'s stdout
is line-buffered and the SSH bytes stayed in the buffer, stalling the session.
Now every delivered message is flushed immediately
(`delivered_bytes_are_flushed_to_a_buffered_local_writer`).

## Findings open at review time, all fixed in this PR

| # | Attack hypothesis | Severity | Fix | Regression |
| :-: | :- | :-: | :- | :- |
| 1 | The trust file check only looked at the file's `0o022` bits. Another UID that can write to the directory (`~/.config/tcn` with loose permissions, or a `TCN_CLIENT_CONFIG` in `/tmp`) puts its own `client.toml` in its place in `0644`, with the attacker's relay and node pins: full MITM of the TCN layer, with the victim's real key. Variants: a FIFO blocked every Ansible fork forever; other users' symlinks were followed. | medium | Like OpenSSH's `StrictModes`: regular file (opened with `O_NONBLOCK`), owned by the current user or root, containing directory owned by the user or by root and not writable by group or others. Applies to all trust files (client, relay policy, agent's authorised clients, known nodes) and to secret keys. A symlink is allowed only if the target file and its directory pass the checks. | `trust_files_owned_by_another_user_are_refused`, `non_regular_trust_and_key_files_are_refused_without_blocking`, `trust_files_in_a_directory_writable_by_others_are_refused` |
| 2 | A suspended `ssh` (`~^Z`, SIGSTOP) stops reading: after 30 s the local write timeout closed the session, which over direct TCP would have survived. The timeout protected nothing, because memory is already bounded by the window. | medium | The client writes to stdout without a timeout; the agent keeps the timeout towards sshd. | `a_stalled_local_reader_does_not_kill_the_session` |
| 3 | A `Close` with an error reason was treated as an orderly close: with sshd unreachable the client exited with 0 and no message; a `Close` injected by the relay made it exit with 0. Every `Closed` was described as a key error. | low | Only `Close Normal` is an orderly close; the others are errors (`exit 1`) with a message naming the node and the likely cause. A stream already closed by the peer is not closed again. | `unreachable_sshd_is_an_error_with_a_message` |
| 4 | ssh runs `sh -c "exec zt-client … %n"`: with an OpenSSH older than the CVE-2023-51385 fix, a host name with spaces (`web-01 --config /evil.toml`) became an option. | low | The node name is the last argument: everything that follows is collected and rejected; `--config` goes before `connect`. | `options_after_the_node_name_are_never_parsed` |

## Refuted or accepted hypotheses

| # | Attack hypothesis | Outcome |
| :-: | :- | :- |
| 5 | Shell metacharacters in `%n` | **Mitigated** by OpenSSH ≥ 9.6 (verified on 15 names); what gets through (`%`, `*`, trailing `.`, uppercase) is rejected by `NodeId` (`malformed_node_names_are_refused_without_touching_the_network`). |
| 6 | `--strip-suffix` widens the accepted names | **Mitigated.** `strip_suffix_does_not_widen_the_accepted_names` |
| 7 | Hijacked relay or DNS, impostor agent | **Mitigated.** `impostor_relay_is_detected_and_nothing_reaches_stdout`, `impostor_agent_is_detected_and_sshd_is_never_dialed` |
| 8 | Stdout pollution, secrets or payload in logs | **Mitigated.** `trace_logging_never_reaches_stdout_nor_leaks_the_secret` |
| 9 | The process stays alive and holds Ansible forks | **Mitigated.** `exits_when_the_node_closes_even_if_stdin_stays_open`; with `ControlPersist` expired no processes remain; the Ansible test uses `ControlMaster=auto` and `ControlPersist`. |
| 10 | Ansible concurrency and pipelining | **Mitigated.** `parallel_ssh_sessions`, `ansible_playbook_runs_through_tcn` |
| 11 | After EOF on stdin, incoming data is lost | **Accepted.** There is no half-close (PROTOCOL §11); ssh closes stdin only at the end of the session. |
| 12 | Relative `XDG_CONFIG_HOME`/`HOME`, empty or relative `TCN_CLIENT_CONFIG` | **Mitigated** (ignored) / **accepted** (relative: whoever controls the environment already controls the process). |
| 13 | `ssh WEB-01` matches `Host web-01` but node `WEB-01` does not exist | **Accepted**: fails closed; documented in OPERATIONS. |
