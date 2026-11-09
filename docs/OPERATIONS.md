# Deployment

This guide brings relay and agent into service and connects `zt-client` to OpenSSH and Ansible.

## 1. Keys

Each machine generates its own key; the secret never leaves the machine.

```bash
zt-relay keygen --out /etc/tcn/relay.key       # on the relay
zt-agent keygen --out /etc/tcn/agent.key       # on each target server
zt-client keygen --out ~/.config/tcn/client.key  # on the workstation / Ansible controller
```

Each command creates a new file with `0600` permissions (it never overwrites) and prints the public
key and the fingerprint. The public keys are the only information to distribute.
The binaries refuse to start if the key file is readable by group or others.

## 2. Relay policy

`/etc/tcn/policy.toml`:

```toml
[[agents]]
node = "web-01"                 # [a-z0-9-], 1..=63
public_key = "<agent public key>"

[[clients]]
name = "ansible"
public_key = "<client public key>"
allow = ["web-01"]              # ["*"] = all nodes in the policy; [] = none
```

A key has only one role, a node only one agent; unknown fields, weak keys and invalid names
make startup fail. During the rotation of an agent's key (§8) the entry
lists two keys: `public_keys = ["<new>", "<old>"]` instead of `public_key`.

With multiple relays (§8) each one has its own key but **the same policy**: distribute it to all of them
in the same step and verify that it is identical everywhere (for example by comparing
`sha256sum /etc/tcn/policy.toml` on all relays). A relay that denies access to a node
stops the client, but a relay that **does not know** the client's key closes the handshake as
if it were faulty, and the client moves on to the next one: a key removed from only one relay remains
valid on the others until you update them all (§7).

## 3. Authorized clients on the agent

`/etc/tcn/clients.toml` on the target server (same `[[clients]]` format, `allow` ignored).
This is defence in depth: even if the relay were compromised, the agent accepts only the
clients listed here.

## 4. Startup

```bash
zt-relay run --listen 0.0.0.0:7443 --key /etc/tcn/relay.key --policy /etc/tcn/policy.toml

zt-agent run --relay relay.example.org:7443 --relay-key <relay public key> \
    --node web-01 --key /etc/tcn/agent.key --authorized-clients /etc/tcn/clients.toml
```

The agent opens no ports: it connects outbound, reconnects on its own with exponential
backoff (full jitter, from 1 s up to 30 s) and forwards only to `127.0.0.1:22`
(`--ssh-target` to change it). After a session that lived (a relay restart or drain) the
first reconnect is spread over `--reconnect-spread` seconds (10 by default; 0 with a single
relay you want back at once), so the fleet does not come back in one wave. The agent pings
every 10 s and reconnects when nothing at all arrived from the relay for 30 s (PROTOCOL §10).

Both services have a `check` subcommand that takes the same options as `run`, loads and
validates every file `run` loads at startup (through the same code), prints `configuration OK`
and the SHA-256 of the trust and settings files, and listens on nothing. It is a pre-flight
before a **restart**. It exits 0; 78 (`EX_CONFIG`) when a file was read and is invalid; 1 when
a file is missing or unreadable. `run` exits the same way at startup: the units do not restart
on 78 (an operator must fix the file) and do restart on 1 (provisioning not finished yet, a
late mount), with their backoff. `SIGTERM` drains the service (§14); `--drain-timeout`
(default 60 s) bounds the drain.

**Reload.** `systemctl reload` runs `zt-relay reload --pid $MAINPID` (or `zt-agent
reload`): it sends `SIGHUP` to the running service and waits for the service's **own** verdict.
The service validates its files with the arguments it was started with (drop-ins included),
announces the reload to systemd (`RELOADING=1`, then `READY=1`) and publishes the outcome in
its runtime directory (`/run/zt-relay`, `/run/zt-agent`; `RuntimeDirectory=` in the units,
`--runtime-dir` outside systemd). `reload` then exits 0 when the files were applied, 78 when
the service rejected them and kept the previous ones (the reason is printed and is in the
journal as `..._reload_failed`), 1 when the service did not answer. `reload` takes no file
arguments, so a drop-in that changes `ExecStart=` (§8, §10.2) needs no change to
`ExecReload=` (review 0010, A10-1). The relay applies the policy even when its key files
cannot be reloaded; `reload` then prints a `warning:` line and exits 0 (§8).

With multiple relays, `--relay` and `--relay-key` are repeated in the same order, or separated with
commas (at most 8). The agent stays connected to all of them at the same time; `--max-streams`
applies to the agent as a whole, not per relay:

```bash
zt-agent run --relay r1.example.org:7443,r2.example.org:7443 \
    --relay-key <r1 key>,<r2 key> --node web-01 ...
```

Handshake suites (PROTOCOL §7.5) are named by their exact Noise protocol name. Without any
option every side uses the classical suite `Noise_IK_25519_ChaChaPoly_BLAKE2s`, which is the
handshake of every earlier release. This default never changes with an upgrade. The agent has
two options:

- `--relay-suite <name>`: the suite pinned towards the relays, one for all of them or one per
  `--relay` in the same order. The agent never falls back to another suite.
- `--accept-client-suites <name>[,<name>…]` (or the environment variable
  `TCN_ACCEPT_CLIENT_SUITES`, same syntax): the suites accepted from clients on the end-to-end
  channel. Without it, the classical suite alone.

The hybrid suite `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` (ML-KEM-768 + X25519) runs on
both channels. End to end (`--accept-client-suites`, a client's `[[nodes]] suite`) relays need
no upgrade, option or restart: follow §12. On the relay hops (`--relay-suite`, `relay.toml`, a
client's relay pins) the relays must accept it first: follow §13. The agent logs the suites in
force at startup (`handshake_suites_in_use`).

### 4.1 `relay.toml`: suites and admission limits

`zt-relay run --config /etc/tcn/relay.toml` sets the suites accepted per role and the
admission limits (PROTOCOL §10.1). Without the option, or with an empty file, the defaults
below apply. The file is read at startup only: `SIGHUP` does not reload it, so change it with a
restart. Unknown keys, a zero, absurd or inconsistent limit (PROTOCOL §10), or an
unknown suite stop the relay at startup. The relay logs the limits in force at startup
(`admission_limits_in_use`).

```toml
[handshake]
# Explicit sets, not ordered; there is no "minimum suite". Agents and clients are separate
# because laptops upgrade last. The hybrid suite (§13) is
# "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s".
agent_suites  = ["Noise_IK_25519_ChaChaPoly_BLAKE2s"]
client_suites = ["Noise_IK_25519_ChaChaPoly_BLAKE2s"]

[admission]
max_preauth = 1024               # handshakes that have not confirmed their key yet
max_pending_per_source = 50      # ...of which at once per IPv4 address or IPv6 /64
max_pending_per_wide = 100       # ...and per IPv6 /48 (at most max_preauth / 2)
max_established = 8192           # confirmed connections (agents and clients)
agent_reserve_percent = 10       # share of max_established only agents may use (at most 50)
max_per_identity = 512           # confirmed connections of one key (at most max_established)
source_burst = 64                # unconfirmed handshakes per IPv4 address or IPv6 /64...
source_refill_secs = 3           # ...then one more every 3 s (at least 3)
identity_refund_burst = 512      # confirmed handshakes per key that give their token back...
identity_refund_refill_ms = 100  # ...then one more every 100 ms
wide_burst = 64                  # new IPv6 /64s per /48...
wide_refill_secs = 1             # ...then one more every second
max_tracked_sources = 65536      # sources (and keys) the budgets track
max_tracked_wide = 16384         # IPv6 /48s the budget tracks
msg1_deadline_secs = 5           # accept -> complete message 1 (at least 5)
handshake_timeout_secs = 10      # accept -> message 2 sent (at most 300)
first_frame_deadline_secs = 5    # message 2 -> first authentic frame
summary_interval_secs = 10       # preauth_summary and per-identity line interval

[liveness]
agent_idle_secs = 90             # a silent agent connection is dropped after this (15..=3600)
client_idle_secs = 90            # same for client connections
```

`[liveness]` sets the relay's idle timeout per role (PROTOCOL §10). Agents of this release ping
every 10 s: the relay accepts 15 s or more (one keepalive plus slack), but use 30 s or more so a
lost keepalive or two does not cost a live agent its connection. Agents before R-2 ping every
30 s and need 90 s. Lower
`agent_idle_secs` (for example to 35) only once every agent is upgraded: a stale registration
then goes away in 35 s instead of 90 s, and clients get `NodeOffline` sooner after an agent's
host dies.

How to size it:

- A connection **gives its token back** once it confirms its key (its first authentic frame), so
  `source_burst` limits only handshakes that never complete: scanners, replays, broken
  clients. A controller behind one address (Ansible with `forks = 50`, a CI runner, a NAT) can
  open hundreds of sessions as long as at most `max_pending_per_source` (and `source_burst`)
  are in their handshake at the same time. Raise both if more connect at once. The relay
  refuses a refill under 3 s: it would make the relay easier to flood.
- One key gives back at most `identity_refund_burst` tokens at once, then 10 per second: a
  stolen key that loops connect, handshake, close from one address is throttled after that,
  while 4 waves of 50 forks are not.
- One address holds at most `max_pending_per_source` handshakes at once, and one IPv6 /48 at
  most `max_pending_per_wide`, so one source cannot fill `max_preauth`. Filling it takes
  `max_preauth / max_pending_per_source` sources (21 IPv4 addresses with the defaults) or
  `max_preauth / max_pending_per_wide` /48s (11). If you expect such an attacker, raise
  `max_preauth`; if all your clients are behind few addresses, keep the caps above their
  concurrency.
- `agent_reserve_percent` keeps part of `max_established` for agents: clients (for example
  many stolen client keys) cannot fill the pool and keep a dropped agent from registering again.
  Keep the reserve above the number of agents that connect to this relay.
- `max_per_identity` bounds what one stolen key can hold. Set it above the largest number of
  concurrent sessions that one legitimate key needs: for a controller, its forks, or more if
  it keeps `ControlMaster` connections open to many hosts.
- `max_preauth` is the room for handshakes in progress. When it is full, new connections are
  dropped (counted as `preauth_pool_full`) while established sessions keep working.
- Every client sends a frame right after its handshake. A client that stays silent for
  `first_frame_deadline_secs` is closed and counted as `unconfirmed`.

## 5. Client: `zt-client`

`~/.config/tcn/client.toml`:

```toml
# connect_deadline_secs = 8         # optional, top level: give up after this long (1-300)
relay = "relay.example.org:7443"
relay_key = "<relay public key>"
key = "client.key"                  # relative to this file, or absolute
# With multiple relays, instead of relay/relay_key (at most 8, tried in this order):
# [[relays]]
# address = "r1.example.org:7443"
# public_key = "<r1 key>"
# [[relays]]
# address = "r2.example.org:7443"
# public_key = "<r2 key>"

[[nodes]]
node = "web-01"
public_key = "<public key of the web-01 agent>"

[[nodes]]
node = "db-01"
public_key = "<public key of the db-01 agent>"
```

Each `[[relays]]` and `[[nodes]]` entry takes an optional `suite` (and the single-relay form
`relay_suite`): the handshake suite pinned towards that relay or that node (PROTOCOL §7.5,
exact Noise protocol name). Without it, the classical suite. The client never falls back to
another suite: a relay or agent that does not accept the pinned one does not answer. Both can
pin the hybrid suite: a node for the end-to-end channel (§12), a relay for the hop to it (§13).
The top-level `require_outer_suite = "<suite>"` makes every relay pinned to another suite a
configuration error, so failover can never land on a weaker hop (§13, step 4):

```toml
[[nodes]]
node = "web-01"
public_key = "<public key of the web-01 agent>"
suite = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s"
```

**Failover** (PROTOCOL §13, resilience R-4). The relays are tried in order. A relay that has
not completed TCP connect and the outer handshake after 2 s (plus up to 0.5 s of jitter) is
hedged: the next one starts in parallel, at most two at a time. A relay that has completed the
handshake but is slow to acknowledge the stream is **not** hedged (it is overloaded; hedging
would double its load): the client waits for the `OpenAck`, then moves on. That wait is the
time left before the deadline divided by the relays left (this one included), at least 2 s and
at most 4 s: with the defaults, up to three relays that handshake and then stall still leave a
healthy fourth one enough time. The other per-step timeouts are 3 s (connect) and 5 s
(handshake). The whole establishment ends at `connect_deadline_secs` (default 8 s), so that
with one failed relay of any kind the session is up within about 6 s: inside the 10 s
`ConnectTimeout` that Ansible gives `ssh` by default (see Ansible below).

When the client gives up for a reason that says nothing about the right of access (deadline,
relays unreachable, silent or dropping the connection, node offline or draining, rate limit),
`zt-client` exits with status **75** (`EX_TEMPFAIL`: try again later); a definitive answer
(policy refusal, failed handshake with a pinned key, protocol or configuration error) exits
with 1. Either way the reason is on stderr, for example

```text
zt-client: no relay completed the connection within 8 s (connect_deadline_secs in client.toml)
zt-client: timed out: handshake
```

and `ssh` exits with 255. A relay that drops an unknown client key looks the same as a relay
under admission pressure, so that case exits with 75 too; the stderr line names both. A
black-holed first relay costs about 2 s instead of the 35 s of the sequential failover before
R-4. The deadline covers establishment only, not the session.

A hedge that loses the race is closed politely, so that it costs the relay nothing it keeps:
one cancelled during its outer handshake completes it and confirms its key with a single
`Ping` (the relay gives back the admission token it took at accept, §4.1), one that already
sent `Open` sends `Close Normal` for it (the agent frees the stream at once). The relays still
see these connections: see §6.

As with OpenSSH's `StrictModes`, every trust file (this one, the relay policy, the agent's
authorized clients) must be a regular file, owned by the user running the binary or by
root, not writable by group or others, in a directory that follows the same rules; secret
keys must furthermore not be readable by group or others (`chmod 600`).

There is no trust-on-first-use: a node without an entry in `[[nodes]]` cannot be reached, and
`zt-client` rejects it before opening any connection. The path is chosen with
`--config`, `TCN_CLIENT_CONFIG`, `$XDG_CONFIG_HOME/tcn/client.toml`, in that order;
otherwise `~/.config/tcn/client.toml`.

### OpenSSH

```sshconfig
# ~/.ssh/config
Host *.tcn
    ProxyCommand zt-client connect --strip-suffix .tcn %h
    # optional: a single tunnel per host, reused by multiple sessions
    ControlMaster auto
    ControlPath ~/.ssh/cm-%C
    ControlPersist 60s
```

`ssh web-01.tcn` opens the stream to the node `web-01`. Without a suffix you can list the
hosts (`Host web-01 db-01`) and use `ProxyCommand zt-client connect %n`. The name must
already be a valid node name (`[a-z0-9-]`, 1..=63): `zt-client` does not normalise it.
`%n` preserves the capitals typed by the user (`ssh WEB-01` fails); `%h` is already
lowercase. `zt-client` options go before the node name
(`zt-client --config ~/tcn.toml connect %n`): no option is read after the name.

TCN does not replace SSH authentication: the server's host key and the user's key are
verified as always, end-to-end through the tunnel. `zt-client` writes only SSH bytes to stdout;
errors and logs (`RUST_LOG`, default `warn`) go to stderr, which `ssh` displays.

### Ansible

Ansible uses `ssh`, so the configuration above is all that is needed:

```ini
# inventory.ini
[web]
web-01.tcn
web-02.tcn
```

```ini
# ansible.cfg
[defaults]
# Passed to ssh as -o ConnectTimeout: keep it above connect_deadline_secs + 2 s (the
# default 10 s fits the default 8 s deadline).
timeout = 10

[ssh_connection]
pipelining = True
# ssh exits with 255 when zt-client fails (deadline, relay restart): Ansible retries the
# connection, with a growing pause between attempts.
retries = 3
ssh_args = -o ControlMaster=auto -o ControlPersist=300s -o ServerAliveInterval=15 -o ServerAliveCountMax=3
```

Each Ansible SSH connection starts its own `zt-client`, that is, one connection to the relay
with a single stream. The limit that matters is the agent's: `--max-streams` (default 16)
concurrent sessions per node, to be kept above the Ansible `forks` that can target the
same host. With `ControlPersist`, connections to the same host are reused.

Recommended settings with several relays (resilience R-4, D-8):

| Setting | Value | Why |
| :- | :- | :- |
| `retries` (`[ssh_connection]`) | 3 | a host whose `zt-client` gives up (status 255) is retried instead of failing the play as `UNREACHABLE` |
| `ServerAliveInterval` / `ServerAliveCountMax` | 15 / 3 | ssh notices a dead path within about 45 s, in line with the relay's idle timeouts (§4.1) |
| `ControlPersist` | 300s | one tunnel per host for the whole play; safe, because revocation and certificate expiry still close multiplexed sessions (PROTOCOL §12, §15.7) |
| `timeout` (`[defaults]`) | 10 (default), at least `connect_deadline_secs` + 2 | Ansible always passes it to `ssh` as `-o ConnectTimeout`, and OpenSSH applies it to the banner exchange through a `ProxyCommand`: a shorter one cuts `zt-client` off before its deadline. Raise it (or `ANSIBLE_TIMEOUT`) whenever you raise `connect_deadline_secs`; a `-o ConnectTimeout` in `ssh_args` works too, because `ssh_args` come before Ansible's own option and OpenSSH keeps the first one |
| `ConnectTimeout` (plain ssh) | unset, or at least `connect_deadline_secs` + 2 | the same, for `ssh` outside Ansible |

With hedging each `zt-client` has at most two outer handshakes **at once**; in total it may try
every relay of its list (at most 8), and with `retries = 3` up to four times that per host.
Hedges that lose do not spend the controller's admission budget at the relays: each confirms
its key before it closes (above), and the relay refunds the source token for that, up to the
identity's refund rate (§4.1). The budget therefore still counts only handshakes that never
complete: a relay that cannot finish its own handshake keeps the token, as it did before
hedging. Size `source_burst` for the `forks` of a controller behind one address, as before.

## 6. Logs and audit

Logs go to stderr, level set with `RUST_LOG` (default `info` for relay and agent, `warn` for
`zt-client`). Relay and agent accept `--log-format json`: one JSON line per event, with
`timestamp`, `level`, `target` and `fields`.

Security events have target `zt_audit` and a stable name in `fields.event_kind`:

| `event_kind` | Level | Meaning |
| :- | :- | :- |
| `agent_registered` | INFO | an agent registered for its node |
| `session_established` | INFO | the relay opened a client → node session |
| `connection_drained` | INFO | a session ended (with the reason) |
| `authentication_failed` | WARN | handshake failed, unknown key, wrong node name |
| `access_denied` | WARN | a client requested a node that the policy does not grant it |
| `protocol_violation` | WARN | a peer violated the protocol and was disconnected |
| `access_revoked` | WARN | a reload removed a peer's role or its access to a node |
| `e2e_session_started`, `e2e_session_ended` | INFO | (agent) session to sshd opened / closed, with `outcome` `closed`, `error` or `revoked`; `e2e_session_started` names the end-to-end `suite` |
| `policy_reloaded`, `authorized_clients_reloaded`, `relay_keys_reloaded` | INFO | reload succeeded |
| `policy_reload_failed`, `authorized_clients_reload_failed`, `relay_keys_reload_failed` | ERROR | reload failed: the previous configuration remains |
| `keys_in_use` | INFO, WARN with a previous key | (relay and agent) at startup and on every reload: `role`, `current_fingerprint`, `previous_fingerprint` (`none` if there is none) |
| `previous_key_still_accepted` | WARN | every hour, as long as a previous key is accepted: complete the rotation (§8) |
| `agent_rotation_pending` | WARN | (relay) at startup, on every reload and every hour, for each node with two agent keys in the policy: `node`, `fingerprints`; complete the rotation (§8) |
| `certificate_expired` | INFO | (relay and agent) a session authorized by a certificate was closed at its expiry: `peer`, `ca`, `serial` (§10) |
| `authorities_in_use` | INFO, WARN with two keys | (relay and agent) at startup and on every reload, for each pinned CA: `authority`, `fingerprints`, `max_lifetime` |
| `ca_rotation_pending` | WARN | (relay and agent) at startup, on every reload and every hour, for each CA with two keys: complete the rotation (§10.6) |
| `revocations_in_use` | INFO | (relay and agent) at startup and on every reload: how many `serials` and `keys` entries the denylist has |
| `handshake_suites_in_use` | INFO | (relay) at startup: `agent_suites`, `client_suites`, the accepted suites as comma-separated protocol names (§4.1) |
| `handshake_suites_in_use` | INFO | (agent) at startup: `role=agent`, `client_suites` (accepted end to end) and `relay_suites` (pinned towards the relays) |
| `handshake_suite_rejected` | WARN | (relay) a known peer completed message 1 with a suite not accepted for its role; (agent) a known client sent an end-to-end message 1 with a suite the agent does not accept: `peer`, `suite`, `confirmed = false`. It got no message 2. **Unconfirmed**: a replayed message 1 produces it too (see below) |
| `preauth_summary` | INFO | (relay) every 10 s, if anything failed before key confirmation: one count per reason, `distinct_sources`, `distinct_keys`, `saturated`, `suppressed_identities` (see below) |
| `admission_limits_in_use` | INFO | (relay) at startup: every admission limit in force (§4.1) |
| `admission_refused` | WARN | (relay) a peer that confirmed its key was refused by `max_per_identity` (`reason = identity_limit`) or a full established pool (`established_pool_full`): `peer`. Its `Open` got `Reject RateLimited` |
| `authentication_failed_repeated`, `handshake_suite_rejected_repeated`, `admission_refused_repeated` | WARN | (relay; agent: the first two) once per identity and interval: how many more times (`count`) the event was seen for `peer` after the line logged in full (see below) |
| `outer_suites_confirmed` | INFO | (relay) every summary interval, if any outer handshake confirmed its key: `agents_classical`, `agents_hybrid`, `clients_classical`, `clients_hybrid` (absent when zero). No identities; replays never count. The sunset signal of §13 |
| `relay_registered` | INFO | (agent) registered with a relay: `node`, `relay` (address), `suite` (the pinned outer suite) |
| `classical_identity_match` | WARN | (relay and agent) after key confirmation: a peer that proved a hybrid identity (hybrid IK suite) was admitted by an entry that checked only its X25519 key (a v1 key, a certificate v1, or a v2 certificate not bound to its hybrid identity): `peer`, `peer_v2`. Replace the entry with its `tcn-pub-v2:` key (§16) |
| `agent_flapping` | WARN | (relay) one node changed hands between agent connections 3 times within 60 s (two agents with the same key, or a reconnect loop): `node`, `peer`, `count`. Reported once per window; each registration still goes through |
| `configuration_loaded` | INFO | (relay and agent) at startup: `generation` (1) and `files`, the `path=sha256:<hex>` of each trust and settings file, computed from the bytes parsed. `policy_reloaded` and `authorized_clients_reloaded` carry the next `generation` (one per `SIGHUP` that applied something; on the relay `relay_keys_reloaded` shares it) and the `files` they applied: the policy (or authorized clients) and the denylist, never `relay.toml`, which only a restart reads |
| `relay_draining`, `relay_drained` | INFO | (relay) `SIGTERM` received: `timeout_secs`; drain over: `expired` (streams were still open at the deadline), `streams_closed` (closed with `Close Drained`) |
| `agent_draining`, `agent_drained` | INFO | (agent) `SIGTERM` received: `node`, `sessions`, `timeout_secs`; drain over: `expired`, `sessions` still open |
| `critical_task_failed` | ERROR | a background task the service relies on (reload, watchdog, key or CA watch) stopped: `task`, `how`. The service exits with 1 and systemd restarts it |
| `watchdog_stalled` | ERROR | the hub (agent: the runtime) made no progress for two watchdog checks in a row (two thirds of `WatchdogSec`): the watchdog is no longer kicked and systemd will restart the service if it does not resume. The relay's progress covers its hub, not the accept loop; the agent's is a heartbeat of its runtime, not of each relay loop |
| `clock_jumped` | WARN | the wall clock stepped against the monotonic clock by 5 s or more: `delta_secs`, `direction`. Backward steps make expired certificates valid again until corrected (§10.7). A VM suspend and resume shows up as a forward step |
| `clock_unsynchronised` | ERROR | at startup, or when the clock steps back below it, the wall clock is before this build: `now`, `floor`. **Every certificate is refused** until the clock passes the build date again (§10.7); key-pinned clients and agents still work, so the host stays reachable |
| `clock_synchronised` | WARN | the wall clock passed the build date again: certificates are checked again |
| `identity_events_suppressed` | WARN | (agent) once per 10 s interval, if events about more than 256 identities occurred: `count` of the events not logged per identity (the relay reports them as `suppressed_identities` in `preauth_summary`) |

The event data are separate fields: `peer` (fingerprint), `node`, `session` (hex),
`stream`, `reason`, `rule`, depending on the event. Never payloads or secrets.

With certificates (§10), `session_established`, `e2e_session_started`, `access_denied` and
`access_revoked` also have `credential` (`key` or `certificate`) and, for a certificate, `ca`
(fingerprint of the CA), `serial`, `cert_name`, `not_after` and `cert_version` (`1`, or `2`
for a post-quantum certificate, §10.8). `authentication_failed` has
`reason = certificate` (or `key_revoked`, or `identity_downgrade`: a peer pinned by its
`tcn-pub-v2:` key that did not prove that hybrid identity, §15) and `cert_check` with the check that failed (`malformed`,
`key_mismatch`, `unknown_authority`, `bad_signature`, `serial_revoked`, `not_yet_valid`,
`expired`, `lifetime_exceeds_authority`, `role_conflict`, `node_out_of_scope`; PROTOCOL §15.4).
After signature verification (from `serial_revoked` onwards) it also reports `ca`, `serial`,
`cert_name` and `not_after` of the rejected certificate; before that (`malformed` … `bad_signature`) never,
because those data are not signed by anyone.

Before key confirmation (PROTOCOL §10.1) the relay writes **no line per connection**: anyone
can make up keys, and one line per attempt would let a scanner bury the real events. A
connection refused or failed before it confirmed its key is only counted in
`preauth_summary`, which never names an identity or an address. Its fields, present only
when non-zero:

| Field | Counts |
| :- | :- |
| `rate_limited` | connections refused because their source used up its budget |
| `source_limit` | connections refused because their source (or its /48) had `max_pending_per_source` (`max_pending_per_wide`) handshakes in progress |
| `preauth_pool_full` | connections refused because `max_preauth` handshakes were in progress |
| `established_pool_full`, `identity_limit` | key confirmations refused by `max_established` or `max_per_identity` |
| `handshake_failed` | message 1 valid for no accepted suite and key |
| `timeout`, `aborted`, `oversized` | message 1 or message 2 too slow; the connection closed or failed before message 1 was complete or while message 2 was sent; message 1, or the first frame before key confirmation, announced longer than the largest legitimate one |
| `unknown_peer` | a valid message 1 from a key that the policy does not know |
| `unverified_certificate` | a certificate rejected before its signature was checked, from an unknown key |
| `unconfirmed` | message 2 sent, but no authentic frame followed (a replayed message 1, a silent client) |
| `distinct_sources`, `distinct_keys` | distinct IPv4 addresses or IPv6 /64s, and distinct unknown keys, at most 4 096 each; `saturated = true` when a limit was reached |
| `suppressed_identities` | events about known identities beyond the 256 logged per interval (see below) |

`authentication_failed` stays a line that names the peer for keys the configuration knows
(whitelisted or revoked) and for certificates rejected after a pinned CA's signature was
verified. A recorded message 1 can be replayed at will, though, so these lines (and
`handshake_suite_rejected`, `admission_refused`) are rate-limited per identity: the first
event of a `peer` in each 10 s interval is logged in full, the others are counted in one
`<event>_repeated` line with `peer`, the reason fields and `count`. At most 256 identities are
logged per interval; the events of further identities only add to `suppressed_identities`.

The agent applies the same rule (review 0009, A9-2) to its `authentication_failed` lines that
name a peer and to `handshake_suite_rejected`, with a 10 s interval, across all its relays: a
compromised relay can replay a recorded end-to-end message 1 as often as it likes.

How to read them:

- A rising `unconfirmed` count with few `distinct_sources` is the signature of someone replaying
  recorded handshakes. A rising `unknown_peer` with many `distinct_keys` is a scanner.
- Client hedging (§5) shows on the relays too, and is not an attack. A hedge that loses the
  race confirms its key and leaves, so it is not `unconfirmed`; but one cut off before its
  connect or handshake completed (the client gave up, or the relay was too slow to finish its
  own handshake) counts as `aborted` or `timeout`, a few per slow relay and controller. A
  hedge that had already sent `Open` may get as far as a `session_established` immediately
  followed by `connection_drained` on the losing relay, with no `e2e_session_started` at the
  agent: a session that never carried a byte, not a login. The client logs a WARN `relays
  disagree on the policy` when a losing relay refused the node that the winning one accepted:
  the policies of the relays differ (a reload that has not reached every relay, review 0005).
- A revoked key (`reason = key_revoked`) or an expired certificate (`cert_check = expired`)
  seen again and again, and especially in `authentication_failed_repeated`, is a **replay
  signal**: someone recorded the victim's message 1 and sends it back. It is not evidence that
  the victim is active or that its key is in use; a replay never gets past message 2.
- `admission_refused` names a real, authenticated peer. `identity_limit` for a fleet controller
  means `max_per_identity` is too low for its concurrency; for a key that should not be that
  busy, it is a stolen key.

```bash
journalctl -u zt-relay -o cat | jq 'select(.target == "zt_audit") | .fields'
```

## 7. Revoking a key

1. Remove the key from `/etc/tcn/policy.toml` on the relay and, for a client, from
   `/etc/tcn/clients.toml` on the agents (defence in depth: either one is enough).
2. `systemctl reload zt-relay` (and `zt-agent`). Ongoing sessions of the revoked key are
   closed immediately; the full table is in `docs/PROTOCOL.md` §12. With multiple relays, reload
   **all** the relays: `zt-client` moves on to the next relay when one does not recognise its
   key, so a relay that has not been updated keeps the revoked key valid. Removing the key
   from `clients.toml` on the agents blocks it anyway, whichever relay it uses.
3. `systemctl reload` fails when the service rejected the file, with its reason: the
   previous configuration is still in force (`..._reload_failed` in the journal). Fix the file
   and reload again. Check `access_revoked` in the audit log.

A client with a certificate (§10) is not revoked by removing it from the files: its key is not there.
The denylist is used instead (§10.5). Its `keys` take the v1 key, the `tcn-pub-v2:` key or the
`SHA256:` fingerprint, all the same entry (§15); never a `SHA256v2:` fingerprint, which is
refused at load time.

## 8. Multiple relays and key rotation

Multiple independent relays (same policy, different keys) remove the single point of failure:
the agents are connected to all of them, and `zt-client` moves on to the next relay if the first does not
respond or does not see the node. It does not move past a policy response or an
end-to-end error (PROTOCOL §13). With at least two relays, restarting one interrupts nothing.

**A relay's key** (two restarts; with at least two relays they interrupt nothing):

Every `SIGHUP` (`systemctl reload zt-relay`, even when it is only needed for the policy) rereads
**both** the policy **and** the keys, from the paths the relay was started with. So do not move
the key files under a relay started without `--previous-key`: any reload
between the move and the restart would activate the new key without the old one, and peers that
pin the old one would be rejected. The swap happens in a single step, at restart, in the
unit's arguments. A reload that finds a previous key equal to the current one, or a
missing or invalid file, fails (`relay_keys_reload_failed`) and keeps the previous keys:
in the intermediate states below this is always the case.

1. `zt-relay keygen --out /etc/tcn/relay.next.key` (then `chown tcn:tcn`, `0600`). The relay
   does not read it: nothing changes.
2. In a drop-in for the unit (`systemctl edit zt-relay`: an empty `ExecStart=` line, then
   the full `ExecStart=`) start the relay with
   `--key /etc/tcn/relay.next.key --previous-key /etc/tcn/relay.key`, then
   `systemctl restart zt-relay`. `keys_in_use` must report the new key as `current_fingerprint`
   and the old one as `previous_fingerprint`; from here on, reloads reread
   both.
3. Update `relay_key` (or `--relay-key`) on agents and clients, whenever convenient. **Replace**
   the pin: do not add a second entry for the same relay with the other key (for example
   `127.0.0.1:7443` with the old one and `localhost:7443` with the new one). The agent would open two
   sessions to the same relay, which override each other (the last registration wins) and
   drop the node's SSH sessions.
4. Remove the previous one: `cp -p /etc/tcn/relay.next.key /etc/tcn/relay.key` (a reload at
   this point fails, because the two keys are the same, and keeps the previous ones), remove
   the drop-in, `systemctl daemon-reload && systemctl restart zt-relay`, then delete
   `relay.next.key`. The `keys_in_use` event at startup must report `previous_fingerprint`
   `none`; until it does, `previous_key_still_accepted` reminds you every hour.

If a relay is already running with `--previous-key /etc/tcn/relay.prev.key`, the rotation can also be done
without a restart, but in this order: first `cp -p /etc/tcn/relay.key /etc/tcn/relay.prev.key`
(identical keys: a reload fails and keeps the previous ones), then
`mv /etc/tcn/relay.next.key /etc/tcn/relay.key` (a rename is atomic), then
`systemctl reload zt-relay` and check `relay_keys_reloaded` and `keys_in_use`. A key reload
that fails does not fail `systemctl reload` (the policy, the urgent part, is still applied):
`zt-relay reload` prints `warning: relay keys not reloaded …`, and the journal has
`relay_keys_reload_failed`. One `SIGHUP` is one configuration generation for both.

**An agent's key**:

1. `zt-agent keygen --out /etc/tcn/agent.key.new` on the node.
2. In the policy of **every** relay: `public_keys = ["<new>", "<old>"]` for the node, then
   `systemctl reload zt-relay`.
3. On the node: the old key becomes `--previous-key`, the new one `--key`; restart the agent
   (that node's SSH sessions are interrupted). Towards the relays it uses the new one; clients that
   pin the old one keep working.
4. Update the node's pin in the clients' `[[nodes]]`.
5. Remove the old one from the policy and `--previous-key` from the agent. As long as a node has two keys
   in the policy, the relay reports it with `agent_rotation_pending` at startup, on every reload and
   every hour: the old key can still register as that node.

A **compromised** key is not rotated: it is revoked (§7) without `--previous-key` and the
pins are updated immediately, because whoever has the old key could impersonate the relay or
the agent towards anyone still pinning it.

## 9. Installation with systemd

The releases (`.github/workflows/release.yml`) contain static binaries (musl) for x86_64 and
aarch64 with a provenance attestation: verify them before installing.

```bash
set -e
gh attestation verify tcn-v0.1.0-x86_64-unknown-linux-musl.tar.gz -R pietrangelo/TransportCryptoNetwork
# Both offline release signatures over SHA256SUMS, by the pinned keys, with OpenSSL >= 3.5
# (SECURITY.md). Use the tcn-release.sh you already trust (from the release you run, or from
# main): it refuses keys that are not pinned in it.
OPENSSL=openssl packaging/release/tcn-release.sh verify --tag v0.1.0 keys/ SHA256SUMS
grep ' tcn-v0.1.0-x86_64-unknown-linux-musl.tar.gz$' SHA256SUMS | sha256sum -c -
```

`SHA256SUMS` is signed twice, by an offline **SLH-DSA-SHA2-128s** key and an offline
**Ed25519** key (PQ-REL), with standard detached signatures that OpenSSL 3.5 or later verifies
on its own: the commands are in `SECURITY.md`. Never verify a release with the `zt-*` binary it
contains. The public keys are committed in `packaging/release/keys/`, but they are trusted only
through their **pinned fingerprints** (review 0013, A13-4): the same lines are built into
`tcn-release.sh`, in `packaging/release/release-keys.fingerprints` and in `SECURITY.md`, and
`verify` refuses any key that is not pinned. Take the fingerprints out of band **once** (from
`SECURITY.md` on `main`, or the release announcement), keep them, and verify later releases
against them (`verify --pins FILE`); keys and fingerprints that come from the same download
prove nothing. Upgrading an installed fleet: verify the new release on a machine you trust, with
OpenSSL, before copying the binaries out.

```bash
install -m 0755 zt-relay zt-agent zt-client /usr/local/bin/
install -m 0644 systemd/tcn.sysusers /usr/lib/sysusers.d/tcn.conf && systemd-sysusers
install -d -m 0755 -o root -g root /etc/tcn
zt-relay keygen --out /etc/tcn/relay.key && chown tcn:tcn /etc/tcn/relay.key   # or zt-agent / agent.key
install -m 0644 systemd/zt-relay.service /etc/systemd/system/   # or zt-agent.service
systemctl daemon-reload && systemctl enable --now zt-relay
```

The units run as user `tcn` without capabilities, with a read-only file system, a system call
filter and addresses restricted to IPv4/IPv6/Unix (`systemd-analyze security`: 1.2,
"OK"). The permissions required by the binaries are those of OpenSSH's `StrictModes`: key
`tcn:tcn 0600`, trust files and directories owned by root or by `tcn` and not writable by
others. For the agent, `/etc/tcn/agent.env` contains `TCN_RELAY`, `TCN_RELAY_KEY` and `TCN_NODE`;
if the relay's IP is fixed, enable `IPAddressDeny=any` / `IPAddressAllow=` in the unit.

A **new installation** should also accept both end-to-end suites, so that clients can move to
the hybrid one node by node without touching the agent again (§12):

```sh
# /etc/tcn/agent.env
TCN_ACCEPT_CLIENT_SUITES=Noise_IK_25519_ChaChaPoly_BLAKE2s,Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s
```

The built-in default stays the classical suite alone (PROTOCOL §7.5): an upgrade never changes
what an agent accepts unless this line is added.

The units are `Type=notify`: `systemctl start` returns when the service has loaded its key and
trust files and is already handling `SIGHUP`, so a `systemctl reload` right afterwards is safe. The
relay uses `Restart=always`, because an unexpected signal counts as a clean exit.

The lifecycle directives of the units (resilience R-3):

| Directive | Why |
| :- | :- |
| `After=time-sync.target` | certificates and revocations follow the wall clock (§10.7) |
| `ExecReload=… reload --pid $MAINPID`, `RuntimeDirectory=` | `SIGHUP` to the running service, which validates its own files with its own arguments; `systemctl reload` fails exactly when the service rejected them (and kept the previous ones) |
| `WatchdogSec=60s` | the relay's hub kicks the watchdog every 20 s, only while it processes events (its own 1 s tick counts); a stuck hub gets the relay restarted. At least 3 s: a shorter value is refused at startup (exit 78), because the 1 s tick could not show progress at every check. `watchdog_stalled` means two checks in a row without progress |
| `TimeoutStopSec=90s` | room for the drain (§14, 60 s by default) before `SIGKILL` |
| `RestartPreventExitStatus=78` | an invalid file is not restarted in a loop: fix it, then `systemctl restart`. A missing or unreadable file exits 1 and is retried |
| `StartLimitIntervalSec=0`, `RestartSteps=5`, `RestartMaxDelaySec=60s` | never give up restarting, but back off up to 60 s (systemd 254 and later; older versions ignore the last two) |
| `LimitCORE=0` | no core dumps of a process holding keys; the binaries also set `PR_SET_DUMPABLE` 0 |

`systemctl status` shows a `STATUS=` line: the relay's connections and streams every 10 s, or
`draining`.

## 10. Client certificates and offline CA

With many clients, or with access that must last only a few hours, instead of listing every key in
every policy and in every `clients.toml` you use an **offline CA**: relay and agent pin its
public key, and each client receives a short-lived certificate that binds its key to a name, to
a list of nodes and to an expiry (PROTOCOL §15). The per-key whitelist (§2, §3) keeps
working and takes precedence.

Rules to keep in mind:

- the CA's secret key **never** goes on a relay, an agent or an everyday
  workstation: whoever holds it can open sessions to all the nodes that the CA can grant;
- a certificate also expires **during** open sessions (PROTOCOL §15.7): issue it for the
  duration of the work, within the CA's `max_lifetime`;
- revocation before expiry goes through the denylist (§10.5), which must reach **all**
  the relays and **all** the agents.

### 10.1 Creating the CA (offline)

On a dedicated machine, without network, with an encrypted disk (or from an encrypted removable medium),
with the clock set correctly (the certificates take their time from here):

```bash
date -u                                       # check the UTC time before every signing session
zt-ca keygen --out /media/ca/ops-ca.key
# public_key  = "<CA public key>"
# fingerprint = SHA256:...
```

The file is new, `0600`, and has the format `tcn-ca-secret-v1:<hex>`, different from that of
node keys: relay, agent and client do not load it, and `zt-ca` does not sign with a
node key. Make an encrypted copy of it in a different location. The `zt-ca` binary is needed only on this
machine.

One CA per scope: for example `ops-ca` for administrators, `deploy-ca` for the Ansible
pipeline that touches only the application servers. The scope is decided by the relay and
agent configuration (`allow`, §10.2), not by the CA: a stolen CA grants no more than what it was assigned.

### 10.2 Pinning the CA on relay and agent

In the policy of **every** relay (`/etc/tcn/policy.toml`):

```toml
[[authorities]]
name = "ops-ca"                     # [a-z0-9-], 1..=63, distinct from the other CAs
public_key = "<CA public key>"
allow = ["web-01", "web-02"]        # nodes that this CA can grant; ["*"] = all
max_lifetime = 28800                # seconds, 60..=86400 (default 8 hours)
```

In the `clients.toml` of **every** agent that must accept the CA's clients, the same entry
(the agent checks that its own node is in `allow`; you can distribute the same block
everywhere).

The denylist, initially empty, is the **same file** on relay and agent
(`/etc/tcn/revoked.toml`, `root:root 0644` or `tcn`, the trust file rules of §5):

```toml
serials = []    # serial numbers of revoked certificates (32 hexadecimal characters)
keys = []       # revoked public keys, with any credential
```

Startup (or a drop-in for the systemd unit, `systemctl edit`):

```bash
zt-relay run ... --policy /etc/tcn/policy.toml --revocations /etc/tcn/revoked.toml
zt-agent run ... --authorized-clients /etc/tcn/clients.toml --revocations /etc/tcn/revoked.toml
```

With an `[[authorities]]` entry and without `--revocations` the process does not start (and a reload that
adds a CA fails): the denylist must exist before it is needed. A CA key cannot
also be the key of an agent or a client in the same file, nor that of the process
(current or previous), nor, in `clients.toml`, the key of a relay passed to the agent with
`--relay-key`: whoever controls a relay must not be able to sign certificates for the agents
(PROTOCOL §15.9). The error says "authority key equals the relay key" (or `agent`). The same
applies when rotating the relay's key with `SIGHUP`: a new key equal to a CA in the
policy is rejected with `relay_keys_reload_failed` and the previous keys remain. Each CA is a
key generated with `zt-ca keygen` and used only for signing.

Verification: `authorities_in_use` in the audit log of every relay and agent reports the name and fingerprint
of the CA; `revocations_in_use` the number of entries in the denylist. As for the policy, compare
`sha256sum /etc/tcn/policy.toml /etc/tcn/revoked.toml` on all relays, and `revoked.toml` on
all agents.

### 10.3 Issuing a certificate

1. The client generates its own key, if it does not already have one (`zt-client keygen`, §1), and sends
   the CA operator the **public key**, never the key file. The operator
   verifies the fingerprint with the requester over a different channel (by phone, or in a
   signed ticket): whoever substitutes the public key in transit obtains the certificate.
   Caution: the `zt-client` key file contains 64 hexadecimal characters, like a
   public key, and `zt-ca` cannot tell them apart. `--subject` is the `public_key` line printed by
   `zt-client keygen`, not the content of `client.key`. If the secret ends up in a
   certificate by mistake, `zt-client` rejects it ("secret key leaked into a certificate: regenerate the
   client key"): the secret is by now in the certificate and in the log, so the
   client key is regenerated, the certificate is revoked (§10.5) and a new one is issued.
2. On the CA machine:

   ```bash
   zt-ca sign --ca /media/ca/ops-ca.key --log /media/ca/issued.tsv \
       --subject <client public key> --name alice \
       --nodes web-01,web-02 --validity 8h --out alice.cert
   # serial      = 3f0c...       (32 hex)
   # subject     = SHA256:...    (client fingerprint)
   # not_before  = 2026-11-08T09:00:00Z
   # not_after   = 2026-11-08T17:00:00Z
   ```

   - `--nodes` (a list, at most 64) or `--all-nodes` (all the nodes in the CA's `allow`).
     Prefer the list.
   - `--validity` accepts `s`, `m`, `h` (for example `90m`), at most 24 hours and in any case not
     beyond the CA's `max_lifetime`, otherwise relay and agent reject it.
   - `--not-before <Unix seconds>` issues a certificate for a future window (scheduled
     maintenance); by default it starts from now.
   - `--log` is mandatory: `zt-ca` appends a line for each certificate (serial,
     fingerprint, name, start, expiry, scope, certificate version `v1`/`v2`, hybrid
     fingerprint or `-`). It is needed to revoke (§10.5) and to notice
     certificates that the CA did not issue (PROTOCOL §15.11). Keep it with the CA key,
     but in a separate file: `zt-ca` rejects a log that is the key file (same
     file, hard link or copy) or a symbolic link.
   - `zt-ca` never overwrites `--out` and rejects weak or invalid keys.
3. Deliver `alice.cert` to the client. It is not a secret (on its own it is useless without the
   client's key), but a certificate substituted in transit simply does not work.

### 10.4 Using the certificate on `zt-client`

**Before delivering a certificate, pin the CA on all the relays and all the agents** that the
client must reach (§10.2) and check `authorities_in_use` on each one. A presented
certificate is always verified, even from a client still in the whitelist (PROTOCOL §15.5): a
relay or an agent that does not know the CA rejects it (`unknown_authority`, fail closed) and the
client, admitted by key until then, stays locked out of that node until the CA is pinned or the
certificate is removed from `client.toml`.

Next to the key, for example `~/.config/tcn/client.cert`, and in `client.toml`:

```toml
key = "client.key"
certificate = "client.cert"         # relative to this file, or absolute
```

The certificate file follows the trust file rules (§5). `zt-client` reads it on every
invocation and, before connecting, checks that it is for its own key and has not expired
(according to the local clock): if not, it exits with a clear message instead of trying all
the relays. It warns on stderr when less than 15 minutes remain before expiry.

```bash
zt-client certificate     # name, nodes, CA, serial number, validity of the configured certificate
```

**Renewal**: repeat §10.3 and replace the file atomically
(`mv alice.cert.new ~/.config/tcn/client.cert`). New invocations use the new
certificate; open sessions remain bound to the one they started with and are closed at its
expiry. With `ControlPersist` the SSH master is one of these: after renewal close it
(`ssh -O exit web-01.tcn`) so as not to lose it in the middle of a job.

**Ansible**: a playbook that runs longer than the certificate is interrupted at expiry. Issue
the certificate for the expected duration (within `max_lifetime`) or renew it before launching.

If the client is also still in the whitelist (§2, §3), the whitelist applies and the certificate is only
verified: an invalid certificate still causes the client to be rejected. To switch entirely to
certificates, remove its entry from the policy and `clients.toml` and reload: its connection drops once
and reopens with the certificate.

### 10.5 Revocation before expiry

For a certificate (for example a lost laptop with key and certificate):

1. Find the serial number in the CA log (`issued.tsv`) or with
   `zt-ca inspect --cert alice.cert`, which also prints the line to paste.
2. Add it to `serials` in `/etc/tcn/revoked.toml`. To revoke **everything** a key
   can do (all its certificates, from any CA, and its whitelist entry, if any)
   add its public key to `keys` instead: this is the right choice when the
   key is compromised.
3. Distribute the file to **all** the relays and **all** the agents and reload
   (`systemctl reload zt-relay`, `systemctl reload zt-agent`). Ongoing sessions of the
   certificate are closed immediately (PROTOCOL §12).
4. A failed `systemctl reload` (and `policy_reload_failed` or
   `authorized_clients_reload_failed` in the journal) means that the **revocation is not in
   force** on that node (the previous configuration remains): fix the file and reload. Check
   `access_revoked` and `revocations_in_use` with the new number of entries.

Even with a relay that has not been updated, the updated agents block the certificate; conversely, an
agent that has not been updated is protected only by the relays. Update them all.

**Pruning**: a `serials` entry can be removed once the certificate has been expired for more than
a few minutes (expiry also closes the sessions, PROTOCOL §15.7); the date is in the CA
log. A `keys` entry stays until that key has been replaced everywhere.

**Emergency** (a CA to be stopped immediately, for example because the denylist is not enough or the
CA's key is exposed): remove the `[[authorities]]` entry (or just the key) from relay and agent and
reload. All the certificates of that CA drop, including in open sessions.

### 10.6 CA rotation

A scheduled rotation, without interruptions:

1. `zt-ca keygen --out /media/ca/ops-ca.next.key` on the CA machine.
2. On all relays and agents: `public_keys = ["<new>", "<old>"]` instead of
   `public_key` in the CA's entry, then reload. `authorities_in_use` shows the two
   fingerprints, `ca_rotation_pending` reminds you every hour.
3. From here on, sign only with the new key.
4. Once at least `max_lifetime` has passed since the last certificate signed with the old one (see
   the log), none of its certificates is valid any more: remove the old one (`public_key =
   "<new>"`) everywhere and reload. Archive or destroy the old key.

**Compromised CA**: it is not rotated. Immediately remove its key from relay and agent (§10.5,
emergency), create a new CA, pin it, reissue the necessary certificates. Then compare the serial
numbers in the audit logs (`session_established`, `e2e_session_started`) with the CA
log: a serial that does not appear in the log is a forged certificate.

### 10.7 Clocks

Relay and agent decide validity and expiry with their own system clock, with 2 minutes of
tolerance only on the start of validity. Keep them synchronised, preferably with NTS
(`chrony` with `nts`): whoever moves the clock of a relay and an agent backwards makes
expired certificates valid again. A clock before the build date of the binaries (an RTC that
lost its time, NTP not reached yet) is treated as unknown: relay and agent refuse every
certificate until it passes the build date (`clock_unsynchronised`, then `clock_synchronised`),
so a certificate that expired before the build cannot become valid again. Key-pinned peers
are not affected. `After=time-sync.target` waits for synchronisation only when
`systemd-time-wait-sync.service` is enabled. The CA machine, being offline, must be set by hand before
every signing session; `zt-ca sign` prints the dates in UTC precisely so that you can check them.

### 10.8 Certificates v2: the post-quantum CA

A v1 CA is an Ed25519 key: a future quantum computer could recover it from the public key
pinned everywhere and sign certificates for any client. A **v2 CA** is a composite key,
Ed25519 **and** ML-DSA-65, and its certificates are valid only when both signatures verify
(PROTOCOL §15.14). Nothing changes for clients: the same `client.toml`, the same key, a
different certificate file.

**Creating a v2 CA** (on the offline machine, as in §10.1):

```bash
zt-ca keygen --v2 --out /media/ca/ops-ca.v2.key
# public_key  = "tcn-ca-pub-v2:<3 968 hex>"
# fingerprint = SHA256:...        (its Ed25519 half: the name in the audit logs)
# ca_fp       = TCNCA2:...        (the fingerprint that certificates v2 carry)
```

The secret file is `tcn-ca-secret-v2:<128 hex>` (both seeds), `0600`; back it up as the v1 one.
The public key is long (about 4 KB of text): copy it from the `zt-ca` output, never retype
it. `zt-ca sign --ca <v2 key>` issues certificates v2 (`tcn-client-cert-v2:` files, about
3.5–7.7 KB), with the same options as §10.3; every certificate is verified after signing with
the fleet's own verifier before it is written. With a v2 CA, `--subject` is the client's
`tcn-pub-v2:` key (`zt-client pubkey`, §15) and the certificate is **bound to its hybrid
identity**; a 64-hex subject is refused unless `--classical-subject` is given, which issues a
classical-kind certificate (bound to the X25519 key only, refused where
`require_hybrid_identity` covers clients, §15). `sign` prints `subject_kind` and the log's
hybrid column is `-` for such a certificate (review 0012, A12-1). `zt-ca inspect --cert alice.cert` prints
`version = 2` and `ca_fp`; with `--ca-key <tcn-ca-pub-v2:…>` it also verifies both
signatures.

**Rollout** (the rotation of §10.6, with the v2 key as "new"):

1. Upgrade **all** relays and agents to a release that knows certificates v2 (PQ-AUTH) and
   check that they run it. An older relay or agent refuses `tcn-ca-pub-v2:` keys at load
   time, so the next step fails loudly there instead of locking clients out.
2. `zt-ca keygen --v2` as above.
3. On all relays and agents, pin both keys in the CA's entry and reload:

   ```toml
   [[authorities]]
   name = "ops-ca"
   public_keys = ["tcn-ca-pub-v2:<…>", "<v1 key>"]
   allow = ["web-01", "web-02"]
   ```

   `authorities_in_use` shows both fingerprints and `ca_rotation_pending` reminds you every
   hour. v1 and v2 certificates are both accepted.
4. Sign only with the v2 key from here on. `session_established` and `e2e_session_started`
   carry `cert_version`: count the `cert_version = 1` sessions to see who still uses a v1
   certificate.
5. Once `max_lifetime` has passed since the last v1 certificate (see the CA log, column
   `v1`), pin only the v2 key (`public_key = "tcn-ca-pub-v2:<…>"`) and reload. From then on
   a v1 certificate is refused with `unknown_authority`. Archive or destroy the v1 key.

There is no automatic downgrade: a relay or agent accepts a v1 certificate only while a v1
key is pinned in that CA's entry. The two keys of an entry must be different CAs: a v2 key
built on the same Ed25519 key as the v1 one is a load error.

**Rollback**: until step 5 nothing is lost: sign v1 certificates again with the v1 key,
still pinned. After step 5, pin the v1 key again next to the v2 one (step 3) and reload; v2
certificates already issued stay valid.

**Sizes and cost**: a message 1 with a v2 certificate is about 3.6–7.8 KB under the classical
suite, 8.9 KB at most under the HFS suite (IKhfs) and 11.2 KB at most under the hybrid IK suite
(§15), within the relay's pre-authentication cap, which follows the largest certificate and the
accepted suites. Verifying a v2 certificate costs one Ed25519 and one ML-DSA-65
verification, only after the cheap checks (binding, pinned CA).

## 11. SSH key exchange: post-quantum today

TCN's handshakes can be post-quantum (hybrid): end to end since PQ-1 (§12), on the relay hops
since Phase 3 (§13); all authentication stays classical (PROTOCOL §7.5.1, §7.5.2). The SSH session
that runs inside the tunnel can be protected **now**: it is end-to-end between `ssh` and `sshd`,
and a recorded tunnel (harvest now, decrypt later) still has the SSH key exchange inside it.
OpenSSH supports two hybrid key exchanges:

| Algorithm | OpenSSH | Notes |
| :- | :- | :- |
| `mlkem768x25519-sha256` | 9.9 and later (default from 10.0) | ML-KEM-768 + X25519; preferred |
| `sntrup761x25519-sha512@openssh.com` | 8.5 and later (default from 9.0 to 9.9) | Streamlined NTRU Prime + X25519; the alias `sntrup761x25519-sha512` exists from 9.9 |

OpenSSH refuses a `KexAlgorithms` line that names an algorithm it does not know: `ssh` stops with
`Bad SSH2 KexAlgorithms` and `sshd -t` refuses the file. So the line depends on the version
of the OpenSSH that reads it (the client's for `~/.ssh/config`, the server's for
`/etc/ssh/sshd_config`), not on the peer's (review 0008, finding A8-9):

| OpenSSH that reads the file | `KexAlgorithms` | Examples |
| :- | :- | :- |
| 9.9 and later | `mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com` | Debian 13, Ubuntu 25.04, Fedora 42 |
| 8.5 to 9.8 | `sntrup761x25519-sha512@openssh.com` | Ubuntu 22.04 (8.9), Ubuntu 24.04 (9.6), EL9 (8.7), Debian 12 (9.2) |
| before 8.5 | no hybrid exists: upgrade OpenSSH | EL8 (8.0), Ubuntu 20.04 (8.2) |

Check what a build supports, and build the line from the intersection, with:

```sh
ssh -V
ssh -Q kex | grep -E '^(mlkem768x25519-sha256|sntrup761x25519-sha512(@openssh\.com)?)$' | paste -sd, -
```

For example, on a 9.9 or later client and server:

```sshconfig
# ~/.ssh/config
Host *.tcn
    KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com
```

```sshconfig
# /etc/ssh/sshd_config (then: sshd -t && systemctl reload sshd)
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com
```

and on an 8.5 to 9.8 client or server, `KexAlgorithms sntrup761x25519-sha512@openssh.com`. Names the peer does not
support are harmless: the two sides negotiate the first algorithm both know. With only hybrids
listed, a peer that supports none of them fails to connect (`no matching key exchange method
found`) instead of silently falling back to a classical exchange; to allow that fallback for
some hosts, append `curve25519-sha256` in a `Host` block for them only. Check what was
negotiated with `ssh -v web-01.tcn 2>&1 | grep 'kex: algorithm'`. This protects the confidentiality of
the SSH session. Authentication (host keys and user keys) stays classical, as it does in TCN
until a later release.

## 12. Hybrid end-to-end suite: rollout and rollback

The hybrid suite `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` protects the client ↔ agent
channel against "harvest now, decrypt later" (PROTOCOL §7.5.1, including what it does not
protect). It is negotiated by no one: each client pins it per node, each agent accepts an
explicit set. Relays are not involved and keep running unchanged.

Rollout, in this order:

1. **Agents.** Upgrade `zt-agent` and accept both suites (`TCN_ACCEPT_CLIENT_SUITES` in
   `agent.env`, §9, or `--accept-client-suites`), then restart it. Check the startup line
   `handshake_suites_in_use` with `role=agent`: `client_suites` names both. Existing clients
   keep working with the classical suite.
2. **Clients, node by node.** Upgrade `zt-client` and add
   `suite = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s"` to the `[[nodes]]` entries whose
   agents completed step 1. Check `e2e_session_started` on the agent: its `suite` is the hybrid
   one. A client pinned to the hybrid suite towards an agent that does not accept it **fails
   closed** (no session, no fallback); the agent logs `handshake_suite_rejected` if it is
   already an upgraded agent, and an older agent ignores it as an invalid handshake
   (`handshake_failed`). `zt-client` then says that the agent may not accept the pinned
   suite. Distribute configurations with a hybrid pin only to upgraded clients: a `zt-client`
   older than PQ-1 refuses the whole configuration (unknown suite), so **every** node becomes
   unreachable for it, not only the pinned one.
3. **Later (PQ-SUNSET), optional.** Once every client of an agent pins the hybrid suite (no
   `e2e_session_started` with the classical suite for a period you choose), accept only the
   hybrid one on that agent. Classical clients then fail with `handshake_suite_rejected`.

**Which signal to act on.** Base the sunset and rollback decisions on `e2e_session_started`
(written after the client's confirmation, so it proves a live client and names its suite)
and on your client inventory, **never on `handshake_suite_rejected` alone**. That line is
written before any proof of liveness (`confirmed = false`): a compromised relay that recorded
a classical message 1 before the sunset can replay it to produce "client X is still classical"
on any agent, for any client it ever recorded, to push you into re-accepting the classical
suite. A rejection that repeats identically, especially as `handshake_suite_rejected_repeated`
with a large `count`, from a client that otherwise shows `e2e_session_started` with the hybrid
suite, is a replay signal. Confirm with the client's owner before rolling back.

Rollback is the reverse order:

1. Accept both suites again on the agents that accept only the hybrid one (step 3).
2. Remove `suite` from the clients' `[[nodes]]` entries (back to the classical suite).
3. Only then, if needed, remove the hybrid suite from the agents or downgrade them. Doing this
   before step 2 cuts off the clients that still pin the hybrid suite. An agent older than
   PQ-1 ignores `TCN_ACCEPT_CLIENT_SUITES` and silently runs classical-only.
4. Downgrade `zt-client` only after its configuration has no `suite` pin left (see step 2 of
   the rollout).

Cost: the hybrid handshake adds about 1.2 KiB to each end-to-end message and roughly 0.1–0.2 ms
of CPU per side (docs/pq-snow.md §5). The relay sees larger `Data` frames during the handshake
and nothing else.

## 13. Hybrid suite on the relay hops: rollout and rollback

The same hybrid suite also protects the hops client ↔ relay and agent ↔ relay (PROTOCOL
§7.5.2): the routing metadata (who reaches which node, when) and the certificates in later
frames stop being "harvest now, decrypt later" material. Unlike §12 this involves the relays,
so every step that changes a relay is a **rolling restart** (§14): one relay at a time, the
next one only after the previous one is back and its agents have re-registered.

Rollout, in this order (pq.md §6.3):

1. **Upgrade every binary** (relays with a rolling restart, agents, clients) without changing
   any pin or set. Nothing changes on the wire.
2. **Relays, one by one: accept both suites for both roles** in `relay.toml` (§4.1), then
   restart that relay (`relay.toml` is read at startup only). Check `handshake_suites_in_use`:
   both sets name both suites. With HA (§8) clients and agents use the other relays while one
   drains and restarts.
3. **Agents: pin the hybrid suite per relay** (`--relay-suite`, one name for all relays or one
   per `--relay`) only towards relays that completed step 2, then restart the agent (with
   `--no-block` if you do it through TCN, §14). Check `relay_registered` with the hybrid
   `suite` for each relay. An agent pinned to the hybrid suite towards a relay that does not
   accept it for agents **fails closed** for that relay: it keeps retrying with the same suite
   (no fallback), the relay writes `handshake_suite_rejected` for it, and the other relays keep
   serving the node.
4. **Clients: pin the hybrid suite per relay** (`suite` in `[[relays]]`, or `relay_suite`).
   A client pinned to the hybrid suite at a relay that does not accept it moves on to the next
   relay with that relay's own pin, and fails if none accepts it. Distribute such a
   configuration only to upgraded clients: an older `zt-client` refuses it as a whole.

   While pins are mixed, failover can land on a classical hop: an active attacker who resets
   the connections to the hybrid-pinned relays makes the client complete on a classical one
   (no single pin is lowered, but that session's outer hop is classical). With hedging
   (§5) the attacker does not even need a reset: delaying the hybrid relay's handshake past
   the 2 s stagger is enough, and a hybrid handshake that is simply slower on that path has
   the same effect (review 0011, A11-7). Keep this window short, list the hybrid-pinned
   relays first, and watch `clients_classical` fall in `outer_suites_confirmed`.
   `zt-client` warns `failover to a relay pinned to another outer suite` on stderr when it
   happens (Ansible hides stderr unless the connection fails: run `-vvv` on a sample). Once every
   relay a client uses accepts the hybrid suite, add
   `require_outer_suite = "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s"` to its
   `client.toml`: a relay pinned to any other suite is then a configuration error, so failover
   can never land on a weaker hop (review 0010, A10-9). This is an explicit set of one suite,
   like the relays' accepted sets (there is still no "minimum suite" ordering).
5. **Sunset, per role (optional, PQ-SUNSET).** When `outer_suites_confirmed` shows no
   `agents_classical` (or `clients_classical`) for a period you choose on every relay, remove
   the classical suite from that role's set, relay by relay. Agents usually get there first;
   laptops last.

As in §12, act on `outer_suites_confirmed` (written only after key confirmation, so a replay
never counts) and on your inventory, never on `handshake_suite_rejected` alone (it is
unconfirmed and replayable).

Rollback is the reverse order: put the classical suite back into the relays' sets (step 5,
rolling restart), remove the clients' and then the agents' hybrid pins (steps 4 and 3), and only
then remove the hybrid suite from the relays (step 2). Removing it from a relay first cuts off
every peer that pins it towards that relay.

## 14. Restarts, drain and upgrades

`systemctl stop` and `systemctl restart` send `SIGTERM`, which **drains** the service instead of
cutting it (PROTOCOL §8):

- **Relay**: the port closes at once, so new connections are refused and clients and agents go
  to the other relays (§8); a new stream on a connection that is already open gets
  `Reject NodeOffline`, so the client moves on too. Open sessions continue, and the policy and its reloads still apply
  to them, until the last one ends or `--drain-timeout` (60 s) passes; then the remaining ones
  get `Close Drained` and the relay exits 0. `relay_draining` and `relay_drained` mark the two
  ends.
- **Agent**: new sessions get `Reject NodeOffline` on every relay (the node is offline during
  its own drain; the client tries its next relay and then gives up); a stream that was
  accepted just before the drain and is still in its end-to-end handshake is counted, and gets
  `Close Drained` instead of a session. Open ones continue up to
  `--drain-timeout`, then the agent exits 0. `agent_draining` and `agent_drained` mark the two
  ends.

**Serial restarts.** Restart relays **one at a time** and wait for the restarted one to be back
(`systemctl is-active`, and `agent_registered` lines from your agents) before the next: while one
relay drains, the others carry the fleet. With Ansible, `serial: 1` on the relay play. Agents of
different nodes can be restarted in parallel; two agents of the same node do not exist.

**Over TCN itself.** Restarting an agent through an SSH session that goes through that same
agent ends your own session at the end of the drain. Use `systemctl --no-block restart zt-agent`
so the command returns before the drain starts, and reconnect afterwards; with Ansible, run the
restart as an `async` task with `poll: 0`. The same applies to a relay restarted from a session
that goes through it, if it is the only relay.

**Drain length.** Keep `--drain-timeout` below `TimeoutStopSec` (90 s in the units) minus a few
seconds. Long-lived sessions (an interactive shell, a long `scp`) are cut at the deadline with
`Close Drained`; a shorter drain makes restarts faster, a longer one cuts fewer sessions.

**Configuration errors.** A restart with an invalid file exits 78 and is not retried
(`RestartPreventExitStatus=78`); run `zt-relay check` / `zt-agent check` with the unit's options
(the ones of its drop-ins too) before restarting. A missing or unreadable file exits 1 and is
retried with the backoff. `systemctl reload` needs no pre-flight: the running service checks
its own files and the reload fails if it rejects them.

## 15. Hybrid identities (PQ-AUTH)

Every key file already holds a hybrid identity: the static ML-KEM-768 key is derived from the
same secret (PROTOCOL §7.5.3). There is no new file and nothing to back up. `keygen` (relay,
agent, client) prints both forms:

```text
public_key     = "<64 hex>"
fingerprint    = SHA256:<64 hex>
public_key_v2  = "tcn-pub-v2:<2 432 hex>"
fingerprint_v2 = SHA256v2:<64 hex>
pin_v2         = "tcn-pin-v2:<64 hex>:<64 hex>"
```

For an existing key file, `zt-relay pubkey --key <file>` (and `zt-agent pubkey`, `zt-client
pubkey`) prints the same five lines and leaves the file as it is: the v2 forms are a function
of the secret, so they are obtained where the key lives. Copy them from the output (the v2 key
is about 2.4 KB of text), never retype them. Scripts that parse this output: the `pin_v2` line
is new in the release after review 0012, and the alignment of the `=` changed with PQ-AUTH
(`public_key     =`, five spaces).

`pin_v2` is the **compact responder pin** (review 0012, A12-2): the Ed25519 key and the
fingerprint v2, 139 characters. A relay or an agent never needs a peer's ML-KEM key from its
files (message 1 carries it), so the relay policy and `clients.toml` take the compact pin as
well as the full key, with the same effect. An initiator needs the full key: `client.toml` and
`--relay-key` refuse the pin. With full keys a policy entry is about 2.5 KB, with pins about
230 bytes; trust files are capped at 8 MiB and 32 768 entries (about 3 300 entries with full
keys, so use pins for large fleets).

Where the v2 key goes:

| File or option | v2 key accepted | Effect |
| :- | :- | :- |
| relay `policy.toml`, `[[agents]]` and `[[clients]]` `public_key(s)` | yes, or the `tcn-pin-v2:` pin | the entry is keyed by the v1 fingerprint, as before, and **pins** the hybrid identity: only a hybrid IK handshake that proves it is admitted (`identity_downgrade` otherwise) |
| agent `clients.toml` `[[clients]]` | yes, or the pin | the same, on the end-to-end channel |
| `revoked.toml` `keys` | yes, or the pin (also v1 keys and `SHA256:` fingerprints) | revokes the X25519-level identity, for every suite; `SHA256v2:` is a load error |
| `client.toml` `relay_key`, `[[relays]] public_key`, `[[nodes]] public_key` | yes (never the pin) | required for the hybrid IK `suite`; accepted with any suite |
| `zt-agent --relay-key` | yes (never the pin) | the same, with `--relay-suite` |
| `zt-ca sign --subject` | yes, with a v2 CA (the default there) | a certificate v2 bound to the hybrid identity (`subject_v2`, log column 8); a v1 CA refuses it; a 64-hex subject with a v2 CA needs `--classical-subject` |

**Requiring hybrid identities** (review 0012, A12-1). A pin protects one entry; a
certificate-only client has no entry, and a v1 entry is still admitted with a stolen X25519
key. The top-level setting

```toml
require_hybrid_identity = ["agents", "clients"]   # relay policy.toml
require_hybrid_identity = ["clients"]             # agent clients.toml
```

closes that for whole roles: a peer of a listed role is admitted only over the hybrid IK suite,
with exactly the fingerprint v2 of its v2 pin or of its hybrid-bound certificate. Anything
else (a classical or IKhfs handshake, a v1 or classical-kind certificate, another ML-KEM key) is
`authentication_failed reason = identity_downgrade`, logged per identity. A v1 entry of a listed
role is a load error that names the entry, so `zt-relay check` and `zt-agent check` are the
completion check of Phase 5 (§16). The list is explicit (no "all"), each role once; it is
reloaded with the file, and a reload that adds it closes the sessions that no longer satisfy
it.

A v1 and a v2 entry of the same key in one file are the same identity: a duplicate, refused. An
agent in rotation (§8) may list one v2 and one v1 key. Rules for the suite: a pin of
`Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s` with a v1 key is a configuration
error; there is no fallback to another suite.

Audit: `session_established` and `e2e_session_started` carry `peer_v2` for a hybrid IK session;
`classical_identity_match` (WARN) names hybrid peers still matched by v1 entries; denylist and
roles are reported by the v1 fingerprint, as before.

Cost (docs/pq-snow.md §5, §6): about 3.5 KB more in message 1 and 1.1 KB more in message 2 than
the classical suite, and on each side one more encapsulation and one more decapsulation than
IKhfs. The responder decapsulates `ct1` before Noise runs, and only if it accepts the suite: an
invalid message 1 of hybrid IK length costs one decapsulation and one X25519 multiplication per
key (two keys during a rotation), plus one multiplication per key shared by the classical and
IKhfs suites if they are accepted too. With all three suites accepted that is about 1.3 times
the classical responder of the release before PQ-AUTH with the same keys, and about 2.4–2.8
times the classical responder of this release: drop the suites a role no longer needs
(Phase 6 of §16) once the counters allow it.

## 16. PQ-AUTH migration runbook

The goal: post-quantum certificates (§10.8), then hybrid IK on every hop and end to end, with
every peer pinned by its v2 key. Each phase can stop and roll back on its own. Act on
confirmed signals only (`outer_suites_confirmed`, `session_established`,
`e2e_session_started`, `classical_identity_match`), never on `handshake_suite_rejected` alone.

**Phase 0, upgrade.** Upgrade every relay (rolling, §14), agent and client to the PQ-AUTH
release without changing any file. Nothing changes on the wire. Check `zt-relay check` and
`zt-agent check` with the unit's options.

**Phase 1, CA v2.** Follow §10.8: create the v2 CA, pin both keys everywhere, sign only v2
certificates, then drop the v1 key after `max_lifetime`. Watch `cert_version` in the audit.

**Phase 2, collect the v2 identities.** Run `keygen` for new nodes, and for each existing node
or client have its owner run `pubkey --key <its key file>` (§15). Keep them in your
inventory next to the v1 keys (and the `pin_v2` lines for the responders' files); nothing is
deployed yet. For certificate clients, re-issue the certificate with `--subject tcn-pub-v2:…`
(a hybrid-bound certificate); it is accepted only over the hybrid IK suite, so distribute it to
a client only together with its Phase 4 pins. `zt-client` refuses, before any connection, a
hybrid-bound certificate whose node pin is not on the hybrid IK suite (or whose relays none
are), and warns about the relays that are not; it also refuses a certificate bound to another
fingerprint v2 than its own key's.

**Phase 3, responders accept the suite.**

1. Relays, one by one: add the hybrid IK suite to both role sets in `relay.toml` (keep the
   others), rolling restart (§13 step 2). Check `handshake_suites_in_use`.
2. Agents: add it to `--accept-client-suites`, restart with `--no-block` (§14).
3. Publish the relays' and agents' v2 keys to the clients (`relay_key`, `[[nodes]]`).

**Phase 4, initiators flip the suite** (as §13 steps 3–4 and §12):

1. Agents: `--relay-key` with the relays' `tcn-pub-v2:` keys and
   `--relay-suite Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s`, relay by relay.
   Check `relay_registered` with that `suite`.
2. Clients: the v2 keys and `suite` in `[[relays]]` and `[[nodes]]`; once every relay a client
   uses accepts it, `require_outer_suite` with that name.
3. Watch `outer_suites_confirmed` and `e2e_session_started suite=…` for the remaining classical
   handshakes, and `classical_identity_match` for hybrid peers still matched by v1 entries.

**Phase 5, pin the identities.** Replace v1 keys with `tcn-pin-v2:` pins (or `tcn-pub-v2:`
keys) in the relay policy and in `clients.toml`, per peer, **only after** that peer runs the
hybrid IK suite on that hop (Phase 4): from then on that peer is refused over any other suite
(`identity_downgrade`). Reload (no restart). `classical_identity_match` for that peer stops. The
denylist needs no change: its entries keep matching every form. Phase 5 ends with
`require_hybrid_identity` (§15): add `["agents"]` once every agent is pinned, `["clients"]`
once every client is pinned or holds a hybrid-bound certificate, in the relay policy, and
`["clients"]` in each agent's `clients.toml`. `zt-relay check` / `zt-agent check` refuse the
file while an entry of a listed role is still v1, and name it. Until this step the guarantee
of PROTOCOL §7.5.3 holds per pinned peer only; with it, for the whole role.

**Phase 6, sunset (recommended).** When the counters show no classical or IKhfs handshake for a
role, remove those suites from that role's set on the relays and from `--accept-client-suites`,
as §13 step 5. Besides closing the classical paths, it brings the cost of an invalid message 1
back to that of one suite (§15).

**Rollback**, in reverse order, each step a reload or a rolling restart:

1. Phase 6: put the classical suite back in the sets first.
2. Phase 5: remove `require_hybrid_identity` first (a v1 entry is a load error while it lists
   the role), then replace the v2 entries with the v1 keys and reload; peers can then use any
   accepted suite again. A peer revoked in between stays revoked (the denylist is v1-keyed).
3. Phase 4: remove the clients' and then the agents' hybrid IK pins (and `require_outer_suite`).
   A hybrid-bound certificate stops working over the classical suite (`key_mismatch`): re-issue
   it with the 64-hex subject, or keep the whitelist entry.
4. Phase 3: only then remove the suite from the agents' and the relays' sets; removing it first
   cuts off every peer that pins it.
5. Phase 1: as §10.8 rollback.

Mixed states are safe but weaker: during Phase 4 a client may fail over to a relay pinned to an
older suite (§13); `require_outer_suite` closes that window. During Phase 5 a v1-pinned peer,
or a certificate-only client with a classical-kind certificate, with a stolen X25519 key is
still admitted (over a classical handshake, or over the hybrid IK suite with the attacker's own
ML-KEM key); that is the reason to complete Phase 5 with `require_hybrid_identity`.

## 17. Metrics and `status`

The relay and the agent write their counters to a **file** in the Prometheus text format, for
node_exporter's [textfile collector](https://github.com/prometheus/node_exporter#textfile-collector).
Nothing listens for metrics: the agent still has no listening socket at all, the relay only its
own port (review 0007, AP-21). There is no HTTP endpoint, no `/healthz`: a load balancer in front
of relays is not a supported topology (the per-source admission budget would see one address).

| Option | Default | Meaning |
| :- | :- | :- |
| `--metrics-file PATH` | `metrics.prom` in the runtime directory (`/run/zt-relay`, `/run/zt-agent`) | where the file is written |
| `--metrics-interval SECONDS` | 15 (1 to 3600) | how often it is rewritten |

The file is replaced atomically (a hidden temporary file in the same directory, then `rename`),
so node_exporter never reads half a file; it is always mode 0644 and a symlink planted at its
path is replaced, never followed. A write that fails (directory missing, disk full) is logged
once as `metrics_write_failed` and retried every interval; the service keeps running. The last
write happens at the end of the drain.

**Wiring node_exporter.** The runtime directory is 0700 (it also holds the reload state), so
node_exporter cannot read the default path. Give the service a directory it may write and
node_exporter may read, in a drop-in (`systemctl edit zt-relay`):

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/zt-relay --log-format json run --listen 0.0.0.0:7443 \
    --key /etc/tcn/relay.key --policy /etc/tcn/policy.toml \
    --metrics-file /var/lib/node_exporter/textfile/zt-relay.prom
ReadWritePaths=/var/lib/node_exporter/textfile
```

The directory must be writable by `tcn` because of the rename. Make it **sticky**
(`root:tcn 1775`), or give TCN a directory of its own and point node_exporter's
`--collector.textfile.directory` at both: in a shared directory without the sticky bit, `tcn`
could rename over or delete the other collectors' files, so a compromised relay could forge or
hide host metrics (review 0013, A13-8). node_exporter reads only `*.prom` files, and the
temporary name never ends in `.prom`. Use a different file name for each service on the host
(`zt-relay.prom`, `zt-agent.prom`). Every process series carries a `role` label, so the files
of a relay, an agent and a client on one host never export the same series (A13-3).

**`status`.** `zt-relay status` and `zt-agent status` print the file's age and every value
(`--metrics-file`, default the runtime directory): exit 0 if fresh, 1 if missing or invalid,
2 if stale (older than three intervals: the process stopped writing, or is wedged). Run it as
root or as `tcn`. It does not trust the file (A13-8): anything but a regular file (a FIFO, a
device) is invalid and never blocks it; a write time more than 60 seconds in the future is
invalid (a forged file, or a dead process after a backward clock step); the interval the file
claims is capped at 3600 seconds; only printable ASCII is printed (control characters and
format characters such as bidi overrides become `?`).

**What is in it.** Only roles, suites, reasons and relay indices are labels; there is never a
fingerprint, a client or node name, a certificate field or an address, so the file reveals no
inventory and its size is fixed (about 150 lines). Per-identity detail stays in the audit log
(§6).

| Metric | Type | Meaning |
| :- | :- | :- |
| `tcn_build_info{role,version}` | gauge | always 1 |
| `tcn_config_generation{role}` | gauge | generation in force (`configuration_loaded`, reloads) |
| `tcn_reloads_total{role,result}` | counter | `applied`, `rejected` |
| `tcn_watchdog_progress_total{role}` | counter | the hub's (relay) or the heartbeat's (agent) progress; flat = wedged |
| `tcn_draining{role}` | gauge | 1 during a drain |
| `tcn_process_start_time_seconds{role}` | gauge | start time |
| `tcn_metrics_last_write_timestamp_seconds{role}`, `tcn_metrics_interval_seconds{role}` | gauge | freshness (the client file has the first one, `role="client"`) |
| `tcn_relay_preauth_failures_total{reason}` | counter | the `preauth_summary` reasons (§6), before key confirmation |
| `tcn_relay_admission_refusals_total{reason}` | counter | confirmed identities refused (`established_pool_full`, `identity_limit`) |
| `tcn_relay_handshakes_total{role,suite}` | counter | confirmed outer handshakes: the sunset signal of §13 |
| `tcn_relay_auth_failures_total{reason}` | counter | known identities refused (`key_revoked`, `certificate`, `identity_downgrade`, `suite_rejected`, ...) |
| `tcn_relay_connections{role}` | gauge | confirmed connections |
| `tcn_relay_agents_registered`, `tcn_relay_streams` | gauge | registered nodes, open streams |
| `tcn_relay_open_rejects_total{reason}`, `tcn_relay_stream_closes_total{reason}` | counter | `Reject` and `Close` reasons |
| `tcn_relay_forwarded_bytes_total` | counter | `Data` bytes forwarded |
| `tcn_relay_queue_bytes`, `tcn_relay_queue_budget_bytes` | gauge | outbound queue and its budget (§18) |
| `tcn_relay_queue_shed_total`, `tcn_relay_queue_overflow_total` | counter | connections shed by the budget (the identity holding the most, §18); peers breaking the credit |
| `tcn_agent_relay_up{relay}` | gauge | 1 while registered with relay *n* (`--relay` order, 0-based) |
| `tcn_agent_relay_registrations_total{relay}`, `tcn_agent_relay_session_failures_total{relay}` | counter | registrations; sessions ended by an error (reconnects) |
| `tcn_agent_relay_consecutive_failures{relay}` | gauge | failures since the last registration |
| `tcn_agent_sessions` | gauge | sessions bridged to sshd |
| `tcn_agent_handshakes_total{suite}` | counter | end-to-end handshakes confirmed |
| `tcn_agent_auth_failures_total{reason}` | counter | end-to-end refusals (`unconfirmed`: a replayed message 1) |
| `tcn_agent_ssh_connect_failures_total` | counter | sshd unreachable |
| `tcn_agent_session_bytes_total{direction}` | counter | `to_ssh`, `from_ssh` |
| `tcn_agent_buffer_bytes`, `tcn_agent_buffer_budget_bytes` | gauge | receive windows and their budget (§18) |
| `tcn_agent_buffer_refusals_total` | counter | authenticated sessions refused because no initial window was left (§18) |
| `tcn_agent_window_grows_total`, `tcn_agent_window_growth_refusals_total` | counter | windows grown; growths refused at the budget's last quarter (benign) |

**Client.** `metrics_file = "zt-client.prom"` in `client.toml` (relative to it) makes
`zt-client connect` write the outcome of its session when it ends:
`tcn_client_last_session_outcome{outcome}`, `_relay_index` (-1: none), `_attempts`,
`_failover` (1 if not the first relay), `_bytes{direction}`. Concurrent clients overwrite one
another: the file describes the last session, which is enough for a cron-driven health probe
(`ssh -o BatchMode=yes node true`), not for fleet statistics. Like the services' files it is
mode 0644 whatever the umask, so other local users can read the last session's timing and byte
counts: put it in a directory only its owner can enter if that matters.

**Dashboards.** One row per relay: `rate(tcn_relay_handshakes_total[5m])` by role and suite
(stacked; the classical share is the §13 sunset signal), `tcn_relay_connections`,
`tcn_relay_agents_registered`, `tcn_relay_streams`, `rate(tcn_relay_forwarded_bytes_total[5m])`,
`rate(tcn_relay_preauth_failures_total[5m])` by reason, `tcn_relay_queue_bytes` against
`tcn_relay_queue_budget_bytes`. Fleet view: `sum by (instance) (tcn_agent_relay_up)` (how many
relays each agent reaches), `tcn_agent_sessions`, `rate(tcn_agent_auth_failures_total[5m])` by
reason.

**Alerts** (starting points; tune the thresholds to the fleet):

```yaml
groups:
  - name: tcn
    rules:
      - alert: TcnMetricsStale            # the process stopped writing: dead or wedged
        expr: time() - tcn_metrics_last_write_timestamp_seconds{role!="client"} > on (instance, role) 3 * tcn_metrics_interval_seconds
        for: 2m
      - alert: TcnWatchdogStalled         # progress flat while the file is still written
        expr: rate(tcn_watchdog_progress_total[5m]) == 0
        for: 5m
      - alert: TcnAgentNoRelay            # an agent registered with no relay at all
        expr: sum by (instance) (tcn_agent_relay_up) == 0
        for: 5m
      - alert: TcnAgentRelayDown          # one relay link down (relay restart, network)
        expr: tcn_agent_relay_consecutive_failures >= 5
        for: 10m
      - alert: TcnReloadRejected          # a reload kept the previous policy: revocation not in force
        expr: increase(tcn_reloads_total{result="rejected"}[15m]) > 0
      - alert: TcnRelayAgentsDropped      # nodes lost by a relay
        expr: tcn_relay_agents_registered < 0.9 * max_over_time(tcn_relay_agents_registered[1h])
        for: 10m
      - alert: TcnPreauthFlood            # scanning or a misconfigured client fleet
        expr: sum by (instance) (rate(tcn_relay_preauth_failures_total[5m])) > 50
        for: 10m
      - alert: TcnQueueBudgetShedding     # slow readers disconnected by the byte budget (§18)
        expr: increase(tcn_relay_queue_shed_total[15m]) > 0
      - alert: TcnAgentBufferExhausted    # sessions refused: the agent's byte budget is full (§18)
        expr: increase(tcn_agent_buffer_refusals_total[15m]) > 0
      - alert: TcnKnownIdentityRefused    # revoked keys or certificates still trying
        expr: increase(tcn_relay_auth_failures_total{reason=~"key_revoked|certificate|identity_downgrade"}[15m]) > 0
      - alert: TcnDraining                # a drain that lasts more than the drain timeout
        expr: tcn_draining == 1
        for: 5m
```

## 18. Memory: byte budgets, window tuning, soak

Buffered stream data is bounded by a **global byte budget** on the relay and on the agent: past
it there is backpressure or a disconnection, never an out-of-memory (resilience R-6, review
0007 AP-22 and D-13). `MemoryHigh=`/`MemoryMax=` in the unit stay the last resort.

| Process | Option | Default | Past the budget |
| :- | :- | :- | :- |
| relay | `run --queue-budget-mib N` (16–65536) | a quarter of the memory (the cgroup limit included), from 128 MiB to 1 GiB | the **identity** (peer fingerprint) holding the most of the budget loses its largest connection at once, even in the middle of a write; ties go to the newest connection. An identity over its share (a quarter of the budget, never less than one connection's full credit) is shed even within the budget |
| agent | `run --buffer-budget-mib N` (16–65536) | the same rule | an authenticated session whose initial window (256 KiB) does not fit is closed (`Close Drained`); a window does not grow |

**Relay.** Every frame queued towards a peer is counted until it is written, per connection and
per authenticated identity. Shedding is **fair per identity** (review 0013, A13-1): one client
key that spreads its backlog over many connections (up to `max_per_identity`) is shed as one
identity, so it can no longer get an honest slow-link download shed in its place. The rules:

1. no identity may hold more than its share: a quarter of the budget, never less than one
   connection's full credit (its streams × 1 MiB); past it, that identity loses its largest
   connection, even while the budget as a whole has room;
2. past the budget, the identity with the largest excess loses its largest connection. An
   agent's **normal credit** (`max_streams_per_agent × 1 MiB`, 64 MiB by default) is not
   counted as excess: an agent within its credit is shed only when agents alone hold more than
   the budget (the last resort, so the budget still holds).

A shed connection is audited (`queue_budget_exceeded`, WARN) with `conn`, `peer` (the
fingerprint), `role` (`agent` or `client`), `cause` (`identity_cap` or `budget`), `backlog`,
`identity_backlog`, `budget` and `identity_cap`, and counted in `tcn_relay_queue_shed_total`.
Its streams end as when the peer disconnects: the other side sees `Close PeerGone`, not
`Drained` (resilience.md §5.6 said `Drained`; `PeerGone` is what the relay core already sends for
a lost connection, and it is the truth). A healthy reader holds at most one window (1 MiB at
most) per stream in the queue. The default minimum (128 MiB) is two agents' full credit; a
smaller `--queue-budget-mib`, below `2 × max_streams_per_agent × 1 MiB`, is reported at startup
(`queue_budget_below_agent_credit`, WARN). Reads and writes of a connection stay in one task, so
a client that stops reading cannot make the relay queue more than its credit either (a
regression test guards it).

**Agent.** Each session reserves its receive window from the budget once its client is
authenticated (key confirmation) and gives it back when it ends. Before that, a stream is
bounded only by the per-relay quota (`--max-streams`, its initial window each), as before R-6:
a compromised relay that opens streams and never sends message 1 cannot exhaust the budget that
the other relays' streams share (review 0013, A13-2). A window **grows** (doubling, up to the protocol's `MAX_WINDOW`, 1 MiB) when
the agent delivered a whole window to sshd while waiting for data, that is when the window and
not sshd limits a transfer over a long or fat path; `tcn_agent_window_grows_total` counts it.
Growth stops at three quarters of the budget: the last quarter is kept for the initial windows
of new streams, so one bulk transfer cannot lock other clients out. A refused growth is counted
in `tcn_agent_window_growth_refusals_total` (benign) and the transfer simply goes on with its
current window; `tcn_agent_buffer_refusals_total` counts only sessions refused for want of an
initial window (A13-11).
The client tunes its own window the same way, within a budget of its own. No wire change: old
peers keep working, and the relay and every peer still refuse a window beyond 1 MiB.

**Sizing.** The budget is a ceiling on memory that *may* be buffered; it is only used while a
reader is slower than its sender. Watch `tcn_relay_queue_bytes` against
`tcn_relay_queue_budget_bytes` and `tcn_agent_buffer_bytes` against
`tcn_agent_buffer_budget_bytes` (§17). Sheds or refusals on a host with free memory mean the
budget is too small for its traffic; on a host short of memory they are the budget doing its job.

**The agent's runtime** has two worker threads (it serves few streams); the relay uses one per
core.

**Soak.** A nightly workflow (`.github/workflows/soak.yml`, also started by hand) runs the relay,
an agent and an echo server on localhost for 30 minutes: clients open sessions in a loop, the
relay is restarted every minute and its policy reloaded every 10 seconds. File descriptors,
resident memory and live tasks are sampled every 5 seconds; the run fails if any of them grows
under load (least-squares trend after a warm-up quarter: more than 8 descriptors, 16 tasks or
24 MiB) or has not come back after the load stops. One more client loop moves 4 MiB per
session, so receive windows grow inside the budgets; once the load stops, the budgets and the
gauges must be back to zero (`tcn_agent_buffer_bytes`, `tcn_agent_sessions`,
`tcn_relay_queue_bytes`, `tcn_relay_streams`, client connections): a leaked reservation costs no
memory, only the counters show it (review 0013, A13-7). Shedding is not exercised by the soak
(localhost TCP buffers absorb a slow reader's backlog); `budget_attacks.rs` and
`adversary_0013.rs` cover it. The samples are kept as the `soak-samples`
artifact (CSV). A 15-second version runs in every CI build, and a test injects a leak to prove
the gate fails. To run it by hand:

```sh
TCN_SOAK_SECS=600 TCN_SOAK_REPORT=/tmp/soak.csv \
  cargo test --release -p zt-net --test soak -- --ignored --nocapture soak_long
```
