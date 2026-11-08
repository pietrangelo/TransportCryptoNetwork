# Fuzzing di TCN

Target di [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) sulle superfici
che leggono input non fidato. Richiedono nightly; il crate è escluso dal workspace.

| Target | Superficie | Proprietà verificate |
| :- | :- | :- |
| `frame_decoder` | decoder dei frame, byte arbitrari a pezzi arbitrari | nessun panic; codifica canonica (un frame accettato si ricodifica negli stessi byte); nessun byte consumato senza frame; decoder avvelenato dopo un errore |
| `noise_responder` | primo messaggio IK da rete non autenticata, canale esterno ed end-to-end | nessun panic, nessuna allocazione sproporzionata |
| `transport_decrypt` | messaggi di trasporto falsi intercalati ad autentici, anche oltre un rekey | nessun falso accettato; un falso non desincronizza il canale |
| `config_parsers` | policy, client autorizzati, nodi noti, configurazione del client | nessun panic |

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run frame_decoder -- -max_total_time=600
```

La CI esegue ogni target per 60 secondi a ogni pull request (job `fuzz`). Un crash va
trasformato in un test di regressione nel crate interessato prima della correzione, come
richiede l'Adversarial TDD (`docs/METHODOLOGY.md`).
