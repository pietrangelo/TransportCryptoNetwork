# Metodologia di sviluppo

TCN è un componente di sicurezza esposto in rete: ogni riga di codice è scritta assumendo che
dall'altra parte del socket ci sia un attaccante. La metodologia unisce tre pratiche.

## 1. Architettura: DDD esagonale

| Crate | Strato | Regola |
| :- | :- | :- |
| `zt-domain` | Domain core | puro: niente async, niente I/O, niente orologio, niente casualità |
| `zt-application` | Application layer | casi d'uso sans-IO (relay core); tempo e casualità entrano come parametri o porte |
| `zt-proto` | Adapter (wire format) | sans-IO; l'integrazione con tokio è dietro la feature `codec` |
| `zt-crypto` | Adapter (crittografia) | sans-IO; handshake con typestate |
| `zt-net` | Adapter (rete, file) | tokio; ogni I/O ha un timeout, ogni coda è limitata |
| `zt-relay`, `zt-agent`, `zt-client` | Composition root | CLI e wiring |

**Invalid states are unrepresentable**: i value object si costruiscono solo tramite
`TryFrom`/factory che validano; un `Frame` esistente è valido per costruzione, quindi
l'encoder è infallibile e il decoder è l'unico punto in cui si rifiuta input.

## 2. Ciclo di sviluppo: Adversarial TDD

Ogni funzionalità segue cinque passi. I primi due producono test che falliscono, e devono
essere committati **prima** dell'implementazione (la cronologia git lo dimostra).

```
 1. RED (specifica)   test del comportamento atteso
 2. RED (avversario)  test d'attacco: input che l'attaccante userebbe
 3. GREEN             implementazione minima che li fa passare tutti
 4. REFACTOR          pulizia a test verdi
 5. ADVERSARY REVIEW  revisione indipendente che prova a rompere il codice;
                      ogni finding diventa un test di regressione o un item di backlog
```

### L'adversary pattern

Il ruolo dell'avversario è separato da quello dell'implementatore: chi scrive i test d'attacco
o la revisione non deve partire dalle assunzioni di chi ha scritto il codice.

**Passo 2: catalogo d'attacco.** Per ogni superficie che accetta input esterno, l'avversario
compila una tabella e scrive almeno un test per riga:

| Categoria | Domande guida |
| :- | :- |
| Parsing | lunghezze ai bordi (0, 1, max, max+1, `u16::MAX`), tipi sconosciuti, versioni, campi incoerenti tra loro |
| Risorse | posso far allocare, bufferizzare o tenere vivo più di quanto invio? posso tenere aperto senza inviare? |
| Stato | posso inviare un messaggio nello stato sbagliato, due volte, o dopo la chiusura? |
| Identità | posso dichiararmi qualcun altro, riusare una sessione, confondere due nomi simili? |
| Canali laterali | tempi di confronto, messaggi d'errore, log: rivelano qualcosa? |
| Malleabilità | lo stesso messaggio ha più codifiche valide? |

**Passo 5: adversary review.** A test verdi, una revisione indipendente (una persona diversa o
un agente separato a cui si fornisce il codice, non le conclusioni dell'autore) cerca di
violare le garanzie dichiarate. L'esito si registra in `docs/adversary/NNNN-<area>.md` con:
superficie, ipotesi d'attacco, esito (*mitigato da test X*, *accettato con motivazione*,
*aperto → backlog*). Un finding aperto blocca il merge se è di gravità alta.

**Fuzzing continuo.** I test di proprietà (`proptest`) sono la versione automatica
dell'avversario: generano input arbitrari e input strutturati che superano i primi filtri.
`cargo-fuzz` (in `fuzz/`) copre decoder, handshake, trasporto e parser di configurazione; la
CI lo esegue a ogni pull request. Un crash diventa prima un test di regressione, poi una
correzione.

## 3. Regole di codice

- `#![forbid(unsafe_code)]` in ogni crate e `unsafe_code = "forbid"` a livello di workspace.
- Vietati in produzione: `unwrap`, `expect`, `panic!`, `todo!`, indicizzazione con `[]`,
  aritmetica che può andare in overflow, cast con troncamento (lint clippy a livello `deny`).
  I test li riabilitano localmente.
- Release: `panic = "abort"`, `overflow-checks = true`, LTO fat, un solo codegen unit, simboli
  rimossi.
- Segreti: niente `Clone`, `ZeroizeOnDrop`, `Debug` redatto, confronti con `subtle`.
- Log: solo metadati. Nessun payload, nessun segreto, nessun byte ricevuto in un messaggio
  d'errore. Tutti i log su stderr (stdout di `zt-client` è il canale SSH).

## 4. Definition of done

- [ ] test di specifica e d'attacco committati prima dell'implementazione
- [ ] `cargo test --workspace --all-features` verde
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` pulito
- [ ] `cargo fmt --check` pulito
- [ ] adversary review registrata in `docs/adversary/`
- [ ] `cargo deny check` pulito (advisories, licenze, sorgenti)
- [ ] documentazione del protocollo aggiornata se il formato cambia
