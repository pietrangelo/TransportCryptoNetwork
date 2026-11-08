# Fuzzing di TCN

Target di [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) sulle superfici
che leggono input non fidato. Richiedono nightly; il crate è escluso dal workspace.

| Target | Superficie | Proprietà verificate |
| :- | :- | :- |
| `frame_decoder` | decoder dei frame, byte arbitrari a pezzi arbitrari | nessun panic; codifica canonica (un frame accettato si ricodifica negli stessi byte); nessun byte consumato senza frame; decoder avvelenato dopo un errore |
| `noise_responder` | primo messaggio IK da rete non autenticata, canale esterno ed end-to-end; metà degli input sono un msg1 autentico modificato, anche con payload (certificato) | nessun panic; un msg1 accettato rivela solo l'identità vera dell'iniziatore; il msg1 intatto è accettato; il payload restituito è quello inviato; un payload oltre `MAX_CERT_LEN` non è mai accettato |
| `transport_decrypt` | messaggi di trasporto falsi intercalati ad autentici, anche oltre un rekey | nessun falso accettato; un falso non desincronizza il canale |
| `config_parsers` | policy e client autorizzati (con `[[authorities]]`), nodi noti, configurazione del client, denylist `revoked.toml`, file del certificato | nessun panic; un errore non riporta sequenze esadecimali lunghe del file (chiavi incollate per sbaglio) |
| `relay_core` | sequenze di connessioni (anche con claims di certificato), frame, disconnessioni, scatti dell'orologio monotono e di quello Unix (che avanza e salta), ricariche della policy con CA e denylist | nessun panic; nessun invio a una connessione chiusa; dopo una ricarica nessun peer senza ruolo resta connesso; nessuna connessione con certificato sopravvive oltre `not_after`, a una serie o chiave revocata o alla CA tolta |
| `cert_decoder` | decoder dei certificati client (PROTOCOL §15.1), byte arbitrari | nessun panic; un certificato accettato si ricodifica identico (`encode_tbs` + firma); nessun errore riporta byte dell'input |
| `cert_verify` | `verify_certificate` con trust e peer fissi; metà degli input sono un certificato autentico modificato | nessun panic; un input accettato è byte per byte il certificato autentico, e i claims sono i suoi; mai accettato per un altro peer |

```bash
cargo +nightly install cargo-fuzz --version 0.13.2 --locked
cd fuzz
cargo +nightly fuzz run frame_decoder -- -max_total_time=600
```

La CI esegue ogni target per 60 secondi a ogni pull request (job `fuzz`). Un crash va
trasformato in un test di regressione nel crate interessato prima della correzione, come
richiede l'Adversarial TDD (`docs/METHODOLOGY.md`). Le dipendenze di `fuzz/Cargo.lock` passano
anche da `cargo deny` (job `deny`).
