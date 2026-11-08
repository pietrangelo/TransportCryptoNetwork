# Adversary review 0005: alta disponibilità e rotazione delle chiavi (Fase 5)

**Superficie:** più relay per agent e client (`RelayEndpoint`, `MAX_RELAYS`, una sessione per
relay nell'agent, failover del client in `may_try_next_relay`), `Keyring` con chiave corrente e
precedente (`respond_any`), ricarica della chiave del relay con `SIGHUP`, due chiavi per nodo
nella policy (`public_keys`, `add_agent_keys`), validazione di `--relay`/`--relay-key`,
`[[relays]]` e `--previous-key`.
**Revisore:** agente avversario indipendente, a cui è stato dato il codice e non le
conclusioni dell'autore. Ha lavorato su una copia del repository; ogni ipotesi è stata
verificata con un test che asseriva il comportamento attaccabile.
**Attaccante:** (a) host remoto; (b) un relay compromesso fra N, o una chiave client rubata;
(c) DNS dirottato verso un impostore; (d) operatore che sbaglia (rollout parziale della
policy, chiave precedente dimenticata nell'unità systemd, stessa chiave due volte).

## Finding aperti al momento della review, tutti corretti in questa PR

| # | Ipotesi d'attacco | Gravità | Correzione | Regressione |
| :-: | :- | :-: | :- | :- |
| 1 | Il semaforo `max_streams` dell'agent era unico per tutti i relay. Un relay compromesso apriva stream senza mai mandare `msg1` e teneva occupati tutti i permessi per un intero timeout di handshake, rinnovandoli di continuo: il client onesto che passava da un relay buono riceveva `Reject ResourceExhausted` (14 tentativi su 16 in 8 s), un errore definitivo. Contraddiceva PROTOCOL §13 («un relay lento non tocca le sessioni verso gli altri»). | media | Ogni sessione con un relay ha la propria quota di stream (`ResourceExhausted` solo verso quel relay). Il permesso del limite globale si prende solo dopo `CONFIRM`, cioè dopo che il client ha completato l'handshake end-to-end; se non ce n'è, lo stream si chiude con `Close Drained`. Un relay può esaurire solo la propria quota di stream non autenticati. | `a_compromised_relay_cannot_starve_sessions_through_the_others`, `the_session_limit_holds_for_the_whole_agent` |
| 2 | Una chiave client tolta dalla policy del relay A, ma non da B (rollout parziale o `policy_reload_failed`): A chiude l'handshake esterno, il client lo tratta come un guasto e passa a B, dove la sessione riesce senza alcun segnale. OPERATIONS §2 diceva che una policy disallineata «si vede come un accesso negato», vero solo per un permesso ristretto (`NotAuthorized`). | bassa (docs) | Testo corretto in PROTOCOL §13 e OPERATIONS §2, §7: la revoca è completa solo quando tutti i relay hanno ricaricato la policy; come verificarlo (`sha256sum` della policy su tutti i relay); la chiave tolta da `clients.toml` sugli agent resta la difesa che non dipende dai relay. Il comportamento del client è voluto: un relay che non riconosce la chiave non è distinguibile da un relay guasto, e con una chiave rubata l'attaccante userebbe comunque un client suo. | `agent_revocation_cuts_the_session_even_if_the_relay_still_allows_it` (esistente) |
| 3 | Una chiave precedente dimenticata non si vedeva da nessuna parte: nessun log ne riportava la presenza o la fingerprint, `relay_keys_reloaded` non diceva quali chiavi fossero in vigore, e una `--previous-key` rimasta nell'unità systemd restava accettata per sempre. PROTOCOL §14 diceva «senza riavvio», mentre OPERATIONS §8 ne richiede uno per aggiungere e uno per togliere `--previous-key`. | bassa | Relay e agent registrano `keys_in_use` (`role`, `current_fingerprint`, `previous_fingerprint`) all'avvio e a ogni ricarica, a livello WARN se c'è una precedente; finché c'è, ogni ora `previous_key_still_accepted`. PROTOCOL §14 allineato a OPERATIONS §8; eventi documentati in OPERATIONS §6. | `a_previous_key_is_announced_and_reminded_until_it_is_removed`, `a_single_key_is_announced_once_and_never_reminded`, `sighup_rotates_the_relay_key_without_a_restart`, `the_previous_key_cannot_be_the_current_key` |
| 4 | Il tempo di un'invocazione cresce con il numero di relay: con 8 relay muti il caso peggiore è di alcuni minuti, e un indirizzo dirottato verso un buco nero aggiunge un timeout a ogni connessione di Ansible. | bassa | **Accettato e documentato** (PROTOCOL §13): i tentativi sono in sequenza e il failover non cambia la sicurezza; si consiglia di mettere per primi i relay più affidabili. Una scadenza complessiva o tentativi in parallelo restano in backlog. | — |

La regressione del finding 1 ha fatto emergere un difetto più vecchio, intermittente (circa
una volta su tre sotto carico): quando il task di uno stream dell'agent era già finito, un
frame `Data` del client ancora in volo trovava la coda chiusa e l'agent rispondeva
`Close ProtocolViolation`, che poteva arrivare al client prima del `Close` vero (qui `Drained`,
ma vale anche per sshd irraggiungibile). Ora un frame per uno stream il cui task è finito si
scarta come gli altri frame in volo; `ProtocolViolation` resta solo per una coda piena, cioè un
relay che non rispetta il credito. Verificato con otto esecuzioni complete di fila senza errori
di `the_session_limit_holds_for_the_whole_agent`.

## Ipotesi smentite o accettate

| # | Ipotesi d'attacco | Esito |
| :-: | :- | :- |
| 5 | Retry dopo `OpenAck`: sessioni duplicate, agent impostore mascherato da un altro relay | **Mitigato.** `msg1` parte solo dopo `OpenAck`, e da lì ogni errore è definitivo. `an_impostor_agent_is_reported_and_never_retried_elsewhere`, `an_agent_refusal_is_final_and_never_retried_elsewhere`. |
| 6 | Retry dopo che l'agent ha già ricevuto `msg1` | **Mitigato**: non può succedere. Un `Timeout("open")` lascia sull'agent al più uno stream in attesa di `msg1`, che si chiude quando cade la connessione con quel relay. |
| 7 | DNS dirottato verso un impostore al primo indirizzo | **Mitigato.** Ogni relay ha la propria chiave pinnata: passare al successivo non abbassa la sicurezza. `the_client_falls_back_past_an_impostor_at_the_first_address`. |
| 8 | Un relay compromesso risponde `NotAuthorized`, o manda `OpenAck` e poi tace, annullando il failover | **Accettato.** L'alta disponibilità copre i guasti, non un relay bizantino; il retry dopo `OpenAck` è vietato apposta. |
| 9 | `may_try_next_relay` troppo permissivo su `Protocol`, `Crypto`, `Decode` | **Accettato.** Avvengono prima di `OpenAck` e il relay successivo si autentica da sé. Su `ResourceExhausted` è restrittivo, nella direzione sicura. |
| 10 | `RateLimited` controllato prima dell'autorizzazione: failover di un client revocato | **Accettato.** Ogni `zt-client` apre una connessione nuova con il bucket pieno; non si raggiunge in pratica. |
| 11 | Permessi del semaforo persi per un panic o per la caduta della sessione con un relay | **Mitigato.** I permessi tornano quando la sessione cade; `panic = "abort"` in release e `Restart=always` in systemd. |
| 12 | Due relay che registrano lo stesso agent si scambiano traffico | **Mitigato.** Gli stream sono per sessione e gli id per relay. `the_agent_serves_through_every_relay_of_its_list`. |
| 13 | Chiave vecchia e nuova dell'agent registrate insieme | **Accettato.** Vale l'ultima registrazione, la precedente viene drenata. Un ping-pong è possibile solo a chi ha la chiave vecchia, e una chiave compromessa si revoca (PROTOCOL §14). |
| 14 | Togliere la chiave vecchia dalla policy deve chiudere la connessione autenticata con essa | **Mitigato.** La ricarica toglie il ruolo e chiude la connessione. |
| 15 | Infilare chiavi in `add_agent_keys` (tre chiavi, duplicati, chiave di un altro peer) | **Mitigato.** `more_than_two_keys_or_none_are_refused`, `the_same_key_twice_is_refused`, `a_key_of_another_peer_cannot_be_smuggled_in_as_a_second_key`, `agent_key_lists_are_validated`. |
| 16 | Tempi o oracolo in `respond_any` | **Accettato.** Il tempo rivela solo quale chiave pubblica ha funzionato; un `msg1` non valido costa 2 DH invece di 1, e il flood è già limitato dal gate degli handshake. |
| 17 | Ricarica delle chiavi del relay a metà handshake | **Mitigato.** Ogni connessione prende le chiavi all'accept. `sighup_rotates_the_relay_key_without_a_restart`. |
| 18 | Togliere la chiave precedente con una ricarica | **Accettato** e documentato: con il file mancante o uguale alla corrente la ricarica fallisce e restano le chiavi di prima; serve un riavvio. L'osservabilità è il finding 3. |
| 19 | Errori dell'operatore: stessa chiave due volte, `--relay` e `--relay-key` disallineati, relay ripetuti | **Mitigato.** `the_previous_key_cannot_be_the_current_key`, `a_relay_list_with_mismatched_or_repeated_entries_is_refused`, `a_keyring_loads_both_keys_and_refuses_the_same_key_twice`. |
| 20 | Client con `relay` e `[[relays]]` insieme, o `relay` senza chiave | **Mitigato.** `a_relay_list_must_be_unambiguous_and_bounded`. |
| 21 | Chiave di un relay uguale a quella di un nodo | **Mitigato.** `no_relay_key_may_double_as_a_node_key`. |
| 22 | Segreti nei log | **Mitigato.** `Identity` si stampa come `<redacted>`; gli errori di caricamento riportano solo il percorso; i nuovi eventi riportano solo fingerprint. |
| 23 | Policy diverse fra relay usate per cercare un relay più permissivo con `NotAuthorized` | **Mitigato.** `a_policy_denial_is_final_and_never_retried_elsewhere`. Per la chiave rimossa del tutto vedi il finding 2. |
