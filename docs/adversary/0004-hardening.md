# Adversary review 0004: hardening (Fase 4)

**Superficie:** revoca a caldo (`Revocable`, `Input::PolicyUpdated` nel core del relay, revoca
nelle sessioni dell'agent, ricarica con `SIGHUP`), rekey implicito di Noise, limite degli
handshake per prefisso /48, audit log JSON, target di fuzzing, unità systemd, workflow di
release e `cargo deny`.
**Revisore:** agente avversario indipendente, a cui è stato dato il codice e non le
conclusioni dell'autore. Ogni ipotesi è stata verificata con un test o una misura su una copia
del repository (strace per il filtro delle syscall, `systemd-analyze` per le unità).
**Attaccante:** (a) host remoto, anche con un intero /48 IPv6; (b) relay compromesso;
(c) operatore che sbaglia (file non valido, `reload` durante l'avvio, chiave incollata nel file
sbagliato); (d) supply chain (action di GitHub, build script delle dipendenze).

## Finding aperti al momento della review, tutti corretti in questa PR

| # | Ipotesi d'attacco | Gravità | Correzione | Regressione |
| :-: | :- | :-: | :- | :- |
| 1 | Il bucket per /48 si consumava a ogni handshake: un solo host che si riconnette 2 volte al secondo (burst 64, 1/s) lo esauriva e bloccava tutti gli altri /64 dello stesso /48, cioè i vicini di un /56 domestico o di una VPC cloud. | media | Il bucket /48 limita la comparsa di /64 **nuovi**: un /64 già nella tabella è frenato solo dal proprio bucket. Il limite contro chi controlla un /48 resta (65 536 /64 nuovi in un colpo → al massimo 64 ammessi). | `one_busy_host_cannot_lock_out_its_slash48_neighbours`, `a_whole_slash48_cannot_lock_out_other_networks` |
| 2 | Un `SIGHUP` arrivato prima dell'installazione del gestore uccideva il relay (40 su 40 a 0 ms dall'avvio). Con `Restart=on-failure` systemd non lo riavviava, perché `SIGHUP` conta come uscita pulita: un `systemctl reload` subito dopo lo start spegneva il relay. | bassa | Il gestore si installa prima di leggere chiave e file di trust, così un segnale durante la lettura non va perso. Le unità sono `Type=notify`: il servizio invia `READY=1` solo quando gestisce già `SIGHUP`, e systemd non esegue `reload` prima. La finestra che resta (prima di `main`, misurata sotto i 5 ms) non è raggiungibile da `systemctl`. Il relay ora ha `Restart=always`. | `ready_is_notified_only_once_sighup_is_handled` |
| 3 | PROTOCOL §12 diceva che un agent associato a un altro nodo si riconnette con il nome nuovo. In realtà l'agent continua a dichiarare il proprio `--node` e viene rifiutato in ciclo. | bassa (docs) | §12 corretto: il nodo di un agent si cambia nella policy **e** nella configurazione dell'agent (`TCN_NODE`). | — |
| 4 | Gli eventi di sessione dell'agent avevano target `zt_audit` ma nessun `event_kind`; gli eventi del relay mettevano i dati in una stringa `Debug` (`fields.event`) che un SIEM deve analizzare. | bassa | Ogni evento ha `event_kind` e campi separati (`peer`, `node`, `session`, `stream`, `reason`, `rule`, `outcome`). Nuovi eventi dell'agent `e2e_session_started` / `e2e_session_ended`. | `audit_events_are_json_with_a_stable_kind_and_no_secrets` |
| 5 | Le action dei workflow erano riferite con tag mobili, anche nel job che riceve il token OIDC per l'attestazione; nello stesso job giravano `cargo test` e `cargo build`, cioè i build script di tutte le dipendenze; `cargo-fuzz` non aveva versione. Un tag spostato o una dipendenza compromessa potevano firmare un binario falso con la provenienza del progetto. | media | Action fissate a un commit. La compilazione gira senza permessi; un job `attest` separato, che non compila nulla, verifica gli hash e attesta. `checkout` senza credenziali persistenti. `cargo-fuzz` 0.13.2. | revisione del workflow |
| 6 | Il fuzzing non raggiungeva parti importanti: `noise_responder` non arrivava mai al ramo che accetta; `transport_decrypt` faceva due generazioni di chiavi e un rekey per input; `config_parsers` dichiarava «nessun segreto negli errori» senza verificarlo; il core del relay (e quindi `PolicyUpdated`) non era fuzzato; `fuzz/Cargo.lock` sfuggiva a `cargo deny`. | bassa | `noise_responder` modifica un msg1 autentico in metà degli input e verifica che un messaggio accettato riveli solo l'identità vera; `transport_decrypt` usa identità fisse e fa il rekey solo se l'input lo chiede; `config_parsers` verifica che gli errori non riportino sequenze esadecimali lunghe; nuovo target `relay_core` (sequenze di connessioni, frame, scatti dell'orologio e ricariche: nessun invio a connessioni chiuse, nessun peer senza ruolo connesso dopo una ricarica); `cargo deny` anche su `fuzz/`. Il nuovo controllo di `config_parsers` ha trovato subito un difetto vero: una chiave privata incollata per errore in un file di trust finiva nel messaggio d'errore (`unknown field \`<64 hex>\``) e quindi nel journal. Ora le sequenze esadecimali di 32 caratteri o più sono sostituite da `<redacted>`. | `a_secret_pasted_into_a_trust_file_is_not_echoed_in_the_error`; 60–90 s per target senza crash |

Il rekey non è il punto debole che sembra: il limite di 1024 messaggi vale per direzione e
conta solo i messaggi autentici. In un trasferimento grosso significa un rekey circa ogni
16 MiB (PROTOCOL §7.4); in una sessione SSH interattiva, uno ogni 1024 messaggi, molto prima.

## Ipotesi smentite o accettate

| # | Ipotesi d'attacco | Esito |
| :-: | :- | :- |
| 7 | Desincronizzare il rekey con messaggi falsi o persi | **Mitigato.** Un messaggio che non si decifra non fa avanzare il contatore; il trasporto è affidabile e ordinato (TCP), quindi non ci sono messaggi persi. `transport_decrypt`, `tests/rekey.rs`. |
| 8 | Messaggio forgiato accettato dopo un rekey | **Mitigato.** `transport_decrypt` attraversa il rekey. |
| 9 | Race fra ricarica della policy e nuove connessioni (una connessione autenticata con la policy vecchia arriva al core dopo quella nuova) | **Mitigato.** L'hub del relay legge la policy per prima (`biased`), e il core la riapplica alle connessioni già registrate; l'agent controlla il valore attuale prima di ogni attesa. `tests/revocation.rs`. |
| 10 | Revoca incompleta: uno stream verso un nodo non più concesso resta aperto | **Mitigato.** `Close Unauthorized` a entrambi i lati, un `access_revoked` per nodo; nuovo target `relay_core`. |
| 11 | File non valido alla ricarica | **Accettato** come scelta: resta la configurazione precedente, con `..._reload_failed` di livello ERROR nell'audit. `an_invalid_policy_on_reload_keeps_the_previous_one`. |
| 12 | Il filtro `SystemCallFilter=@system-service ~@privileged` rompe tokio o rustix | **Smentito** con strace: tutte le syscall usate sono nel set. |
| 13 | `PrivateUsers=yes` rompe il controllo sul proprietario dei file di trust | **Smentito.** I file sono di root o di `tcn`, entrambi visibili nel namespace. |
| 14 | Iniezione di opzioni da `EnvironmentFile` | **Smentito.** Ogni variabile diventa un solo argomento e passa dal parser di clap. |
| 15 | Il punteggio di `systemd-analyze security` nasconde un'esposizione | **Smentito.** 1.2 «OK»; ciò che resta aperto (rete IPv4/IPv6, socket Unix per systemd) serve al servizio. |
| 16 | `deny.toml` permissivo (wildcard, git, licenze) | **Smentito.** Sorgenti solo da crates.io, wildcard vietati; l'unica eccezione di licenza (NCSA per `libfuzzer-sys`) riguarda solo `fuzz/`. |
| 17 | Le dichiarazioni sul rekey (intervallo, costo) sono sbagliate | **Smentito**, con la precisazione riportata sopra (16 MiB vale solo per i trasferimenti grossi). |
| 18 | Aggirare il limite /48 con indirizzi IPv4-mapped (`::ffff:a.b.c.d`) | **Smentito.** Gli indirizzi sono canonicalizzati prima del calcolo delle chiavi: un IPv4-mapped è trattato come IPv4. |
