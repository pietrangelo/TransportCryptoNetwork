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
backoff (1 s → 60 s, with jitter) and forwards only to `127.0.0.1:22`
(`--ssh-target` to change it).

With multiple relays, `--relay` and `--relay-key` are repeated in the same order, or separated with
commas (at most 8). The agent stays connected to all of them at the same time; `--max-streams`
applies to the agent as a whole, not per relay:

```bash
zt-agent run --relay r1.example.org:7443,r2.example.org:7443 \
    --relay-key <r1 key>,<r2 key> --node web-01 ...
```

## 5. Client: `zt-client`

`~/.config/tcn/client.toml`:

```toml
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
[ssh_connection]
pipelining = True
```

Each Ansible SSH connection starts its own `zt-client`, that is, one connection to the relay
with a single stream. The limit that matters is the agent's: `--max-streams` (default 16)
concurrent sessions per node, to be kept above the Ansible `forks` that can target the
same host. With `ControlPersist`, connections to the same host are reused.

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
| `e2e_session_started`, `e2e_session_ended` | INFO | (agent) session to sshd opened / closed, with `outcome` `closed`, `error` or `revoked` |
| `policy_reloaded`, `authorized_clients_reloaded`, `relay_keys_reloaded` | INFO | reload succeeded |
| `policy_reload_failed`, `authorized_clients_reload_failed`, `relay_keys_reload_failed` | ERROR | reload failed: the previous configuration remains |
| `keys_in_use` | INFO, WARN with a previous key | (relay and agent) at startup and on every reload: `role`, `current_fingerprint`, `previous_fingerprint` (`none` if there is none) |
| `previous_key_still_accepted` | WARN | every hour, as long as a previous key is accepted: complete the rotation (§8) |
| `agent_rotation_pending` | WARN | (relay) at startup, on every reload and every hour, for each node with two agent keys in the policy: `node`, `fingerprints`; complete the rotation (§8) |
| `certificate_expired` | INFO | (relay and agent) a session authorized by a certificate was closed at its expiry: `peer`, `ca`, `serial` (§10) |
| `authorities_in_use` | INFO, WARN with two keys | (relay and agent) at startup and on every reload, for each pinned CA: `authority`, `fingerprints`, `max_lifetime` |
| `ca_rotation_pending` | WARN | (relay and agent) at startup, on every reload and every hour, for each CA with two keys: complete the rotation (§10.6) |
| `revocations_in_use` | INFO | (relay and agent) at startup and on every reload: how many `serials` and `keys` entries the denylist has |

The event data are separate fields: `peer` (fingerprint), `node`, `session` (hex),
`stream`, `reason`, `rule`, depending on the event. Never payloads or secrets.

With certificates (§10), `session_established`, `e2e_session_started`, `access_denied` and
`access_revoked` also have `credential` (`key` or `certificate`) and, for a certificate, `ca`
(fingerprint of the CA), `serial`, `cert_name` and `not_after`. `authentication_failed` has
`reason = certificate` (or `key_revoked`) and `cert_check` with the check that failed (`malformed`,
`key_mismatch`, `unknown_authority`, `bad_signature`, `serial_revoked`, `not_yet_valid`,
`expired`, `lifetime_exceeds_authority`, `role_conflict`, `node_out_of_scope`; PROTOCOL §15.4).
After signature verification (from `serial_revoked` onwards) it also reports `ca`, `serial`,
`cert_name` and `not_after` of the rejected certificate; before that (`malformed` … `bad_signature`) never,
because those data are not signed by anyone.

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
3. Check `access_revoked` in the audit log. If you find `..._reload_failed`, the file is not
   valid: the previous configuration is still in force.

A client with a certificate (§10) is not revoked by removing it from the files: its key is not there.
The denylist is used instead (§10.5).

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
`systemctl reload zt-relay` and check `relay_keys_reloaded` and `keys_in_use`.

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
gh attestation verify tcn-v0.1.0-x86_64-unknown-linux-musl.tar.gz -R pietrangelo/TransportCryptoNetwork
sha256sum -c SHA256SUMS --ignore-missing
```

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

The units are `Type=notify`: `systemctl start` returns when the service has loaded its key and
trust files and is already handling `SIGHUP`, so a `systemctl reload` right afterwards is safe. The
relay uses `Restart=always`, because an unexpected signal counts as a clean exit.

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
     fingerprint, name, start, expiry, scope). It is needed to revoke (§10.5) and to notice
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
4. Check `access_revoked` and `revocations_in_use` with the new number of entries. A
   `policy_reload_failed` or `authorized_clients_reload_failed` means that the **revocation is not
   in force** on that node (the previous configuration remains): fix the file and reload.

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
expired certificates valid again. The CA machine, being offline, must be set by hand before
every signing session; `zt-ca sign` prints the dates in UTC precisely so that you can check them.
