# TCN: Transport Crypto Network

**Zero Trust** remote access for SSH and Ansible, without a VPN and without listening ports on the target
servers. Written in Rust, without `unsafe`.

```
admin / Ansible                         public relay                         target server
┌─────────────┐   outbound    ┌─────────────────────────┐   outbound   ┌──────────────────┐
│ ssh         │──────────────▶│ zt-relay                │◀─────────────│ zt-agent         │
│  └ zt-client│  Noise        │ authenticates, routes,  │  Noise       │  └▶ 127.0.0.1:22 │
│   (stdio)   │               │ never reads the payload │              │ 0 open ports     │
└─────────────┘               └─────────────────────────┘              └──────────────────┘
       └──────────────── end-to-end tunnel client ↔ agent ──────────────────────┘
```

> **Status:** Phase 6 (short-lived client certificates from an offline CA). `zt-ca` signs certificates
> that bind a client's key to a name, to a list of nodes and to an expiry; relay and
> agent pin the CA, verify the certificates in the handshake, close sessions at
> expiry and apply a reloadable denylist (PROTOCOL §15, OPERATIONS §10). The features
> of the previous phases remain: multiple relays with failover, key rotation, live revocation, channel
> rekeying, JSON audit log, continuous fuzzing, signed static binaries and hardened systemd units.
> See `docs/OPERATIONS.md`.

## Layout

| Path | Role |
| :- | :- |
| `crates/zt-domain` | pure domain core: value objects, frames, events, errors |
| `crates/zt-application` | sans-IO use cases: relay core, rate limiting |
| `crates/zt-proto` | sans-IO wire format + `tokio-util` adapter (feature `codec`) |
| `crates/zt-crypto` | Ed25519 identities, sans-IO Noise IK handshake with typestate |
| `crates/zt-net` | tokio adapters: Noise channel, relay server, agent, client library, configuration |
| `bins/zt-relay` | public meeting point |
| `bins/zt-agent` | agent on the target servers, outbound connections only |
| `bins/zt-client` | `ProxyCommand` for OpenSSH |
| `bins/zt-ca` | offline CA: key, signing and inspection of client certificates |
| `docs/PROTOCOL.md` | specification of framing, handshake, lifecycle and flow control |
| `docs/OPERATIONS.md` | keys, policy, starting relay and agent, OpenSSH and Ansible |
| `docs/METHODOLOGY.md` | hexagonal DDD, Adversarial TDD, coding rules |
| `docs/adversary/` | record of the adversary reviews |
| `fuzz/` | `cargo-fuzz` targets (nightly) |
| `packaging/systemd/` | systemd units and service user |

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
