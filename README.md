# TCN: Transport Crypto Network

Accesso remoto **Zero Trust** per SSH e Ansible, senza VPN e senza porte in ascolto sui server
target. Scritto in Rust, senza `unsafe`.

```
admin / Ansible                        relay pubblico                     server target
┌─────────────┐   outbound    ┌──────────────────────┐   outbound   ┌──────────────────┐
│ ssh         │──────────────▶│ zt-relay             │◀─────────────│ zt-agent         │
│  └ zt-client│  Noise        │ autentica, instrada, │  Noise       │  └▶ 127.0.0.1:22 │
│   (stdio)   │               │ non legge il payload │              │ 0 porte aperte   │
└─────────────┘               └──────────────────────┘              └──────────────────┘
       └──────────────── tunnel end-to-end client ↔ agent ───────────────────┘
```

> **Stato:** Fase 2 (handshake Noise, relay e agent). Relay e agent sono funzionanti; il
> collegamento di `zt-client` a OpenSSH arriva nella Fase 3. Vedi `docs/OPERATIONS.md`.

## Struttura

| Percorso | Ruolo |
| :- | :- |
| `crates/zt-domain` | domain core puro: value object, frame, eventi, errori |
| `crates/zt-application` | casi d'uso sans-IO: relay core, rate limiting |
| `crates/zt-proto` | wire format sans-IO + adapter `tokio-util` (feature `codec`) |
| `crates/zt-crypto` | identità Ed25519, handshake Noise IK sans-IO con typestate |
| `crates/zt-net` | adapter tokio: canale Noise, server relay, agent, libreria client, configurazione |
| `bins/zt-relay` | punto d'incontro pubblico |
| `bins/zt-agent` | agent sui server target, solo connessioni in uscita |
| `bins/zt-client` | `ProxyCommand` per OpenSSH |
| `docs/PROTOCOL.md` | specifica di framing, handshake, ciclo di vita e controllo di flusso |
| `docs/OPERATIONS.md` | chiavi, policy, avvio di relay e agent |
| `docs/METHODOLOGY.md` | DDD esagonale, Adversarial TDD, regole di codice |
| `docs/adversary/` | registro delle adversary review |

## Sviluppo

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
PROPTEST_CASES=100000 cargo test -p zt-proto --test framing_props   # fuzzing più profondo
```

## Uso previsto (Fase 2)

```sshconfig
Host *.fleet
    ProxyCommand zt-client --relay relay.example.org:7443 %n
```

## Licenza

Apache-2.0
