# TCN: Transport Crypto Network

**Zero Trust** remote access for SSH and Ansible, without a VPN and without listening ports on the target
servers. Written in Rust, without `unsafe`, with post-quantum key agreement and authentication.

<p align="center">
  <img src="docs/assets/architecture.svg" alt="TCN architecture: zt-client and zt-agent both connect outbound to one or more zt-relay instances; an end-to-end Noise channel carries SSH to 127.0.0.1:22 on the target, opaque to the relay" width="100%">
</p>

> **Status:** the post-quantum and resilience roadmap is complete (`docs/pq-resilience-plan.md`):
> hybrid X25519 + ML-KEM-768 handshakes on every channel, post-quantum authentication with
> certificates v2 signed by a composite ML-DSA-65 + Ed25519 offline CA, failover across up to 8
> relays with an overall deadline, drain and liveness, file-based metrics and SLH-DSA + Ed25519
> signed releases. The built-in defaults stay classical so mixed fleets keep working; the opt-in
> `pq_only` profile retires the classical paths (OPERATIONS §19).

## How it works

| Component | Where it runs | What it does |
| :- | :- | :- |
| `zt-client` | admin workstation, Ansible controller | `ProxyCommand` for OpenSSH: bridges stdio to an outbound connection to a relay, then opens an end-to-end channel to the target's agent |
| `zt-relay` | public host, semi-trusted | the only listening port in the system; authenticates both sides, applies the policy whitelist and admission limits, routes streams by `NodeId`; never sees the SSH payload (*blind relay*) |
| `zt-agent` | each target server | zero listening ports; keeps an outbound session to **every** relay and forwards authorised streams to `127.0.0.1:22` |
| `zt-ca` | offline machine | signs short-lived client certificates that bind a key to a name, a list of nodes and an expiry |

**Three layers of encryption.** Each hop (client ↔ relay, relay ↔ agent) is a Noise IK channel
that the relay terminates to read frame headers and route. Inside the `Data` frames runs a second,
end-to-end Noise channel between client and agent, opaque to the relay. Inside that runs the SSH
session itself, with its own key exchange (`mlkem768x25519` on OpenSSH ≥ 10, OPERATIONS §11).

**Handshake suites.** Each peer pins exactly one suite and never falls back; responders accept
explicit sets per role, and no suite identifier travels in the clear (PROTOCOL §7.5).

| Id | Suite | Gives |
| :-: | :- | :- |
| `0x00` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | classical, the compatible default |
| `0x01` | `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` | hybrid forward secrecy against harvest-now-decrypt-later |
| `0x02` | `Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s` | plus post-quantum mutual authentication (ML-KEM static keys derived from each node's seed) |

**Identity and access.** Every node has one Ed25519 seed (its X25519 form for Noise, an ML-KEM-768
key derived from it for the hybrid IK suite). Keys are pinned by fingerprint; the relay policy and
the agent's `clients.toml` are whitelists, reloaded with `SIGHUP` and enforced on live sessions.
Client certificates v2 carry a composite ML-DSA-65 + Ed25519 signature (both must verify) from a
CA that relays and agents pin; a session closes when its certificate expires.

**Resilience.** Agents reconnect with full jitter and detect dead peers by liveness; clients try
their relays in order, only before `OpenAck`, within an 8 s overall deadline with a limited hedge.
`SIGTERM` drains instead of cutting, and admission separates unauthenticated handshakes from
confirmed identities so a flood cannot starve legitimate users. Every I/O has a timeout and every
queue is bounded.

**Operations.** Metrics are written to a Prometheus textfile for node_exporter (no metrics port
anywhere); security events go to the `zt_audit` JSON log, never secrets or payload. Releases are
static musl binaries with a SLSA attestation and two offline signatures over `SHA256SUMS`
(SLH-DSA-SHA2-128s and Ed25519), both required.

## Layout

| Path | Role |
| :- | :- |
| `crates/zt-domain` | pure domain core: value objects, frames, suites, certificates, policy, events, errors |
| `crates/zt-application` | sans-IO use cases: relay core, admission, rate limiting, failover, reconnect, liveness, lifecycle |
| `crates/zt-proto` | sans-IO wire format + `tokio-util` adapter (feature `codec`) |
| `crates/zt-crypto` | identities, sans-IO Noise IK / IKhfs / hybrid IK with typestate, ML-KEM-768, ML-DSA-65, certificates |
| `crates/zt-net` | tokio adapters: Noise channel, relay server, agent, client library, configuration, metrics, drain |
| `bins/zt-relay` | public meeting point (`run`, `check`, `status`, `reload`) |
| `bins/zt-agent` | agent on the target servers, outbound connections only (`run`, `check`, `status`, `reload`) |
| `bins/zt-client` | `ProxyCommand` for OpenSSH (`connect`) |
| `bins/zt-ca` | offline CA: key, signing and inspection of client certificates |
| `vendor/snow` | vendored `snow` with the minimal patch for the hybrid suites (`docs/pq-snow.md`) |
| `docs/PROTOCOL.md` | specification of framing, handshake suites, lifecycle, flow control and certificates |
| `docs/OPERATIONS.md` | keys, policy, startup, OpenSSH and Ansible, rollouts, metrics, the `pq_only` profile |
| `docs/METHODOLOGY.md` | hexagonal DDD, Adversarial TDD, coding rules |
| `docs/pq-resilience-plan.md` | post-quantum and resilience roadmap, with `docs/analysis/` |
| `docs/adversary/` | record of the adversary reviews |
| `fuzz/` | `cargo-fuzz` targets (nightly) |
| `packaging/systemd/` | systemd units and service user |
| `packaging/release/` | offline release signing and verification, pinned key fingerprints |

## Development

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
PROPTEST_CASES=100000 cargo test -p zt-proto --test framing_props   # deeper fuzzing
cargo test -p zt-client --test openssh -- --ignored   # requires sshd, ssh, scp and ansible-playbook
```

## Usage

```sshconfig
# ~/.ssh/config
Host *.tcn
    ProxyCommand zt-client connect --strip-suffix .tcn %h
```

```bash
ssh web-01.tcn
ansible-playbook -i inventory.ini site.yml   # inventory with web-01.tcn, db-01.tcn, ...
```

The relay and the pinned keys are in `~/.config/tcn/client.toml` (see `docs/OPERATIONS.md`).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). All code comments and documentation are written in
English.

## Security

To report a vulnerability, use GitHub's private reporting: see
[`SECURITY.md`](SECURITY.md). The defences of the repository and of the release process are in
[`docs/REPOSITORY_SECURITY.md`](docs/REPOSITORY_SECURITY.md).

## License

Apache-2.0
