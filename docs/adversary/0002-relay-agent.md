# Adversary review 0002: relay, agent e handshake (Fase 2)

**Superficie:** `zt-application` (relay core, rate limiter), `zt-crypto` (identità, Noise IK),
`zt-net` (canale Noise su TCP, server relay, agent, client, configurazione).
**Revisore:** agente avversario indipendente, a cui è stato dato il codice e non le
conclusioni dell'autore. Ogni ipotesi è stata dimostrata con un test eseguito, o smentita da
un test o da una riga di codice.
**Attaccante:** (a) rete non autenticata; (b) peer autenticato ma malevolo (agent compromesso,
chiave client rubata); (c) relay compromesso.

## Finding aperti al momento della review, tutti corretti in questa PR

| # | Ipotesi d'attacco | Gravità | Correzione | Regressione |
| :-: | :- | :-: | :- | :- |
| 1 | Un client autorizzato dal relay ma rifiutato dall'agent apre uno stream e lo chiude. L'agent rispondeva al `Close` con un altro `Close`, che il relay trattava come «close su stream sconosciuto»: disconnetteva l'agent e uccideva **tutte** le sessioni del nodo. Deterministico. | alta | Il relay scarta in silenzio i frame su stream già chiusi (lato agent: id sotto `next_stream`; lato client: ultimi 256 id chiusi). L'agent non risponde più a un `Close` con un `Close`. | `crossing_close_is_dropped_silently`, `open_close_by_a_rejected_client_does_not_kill_other_sessions` |
| 2 | Corse normali tra chiusure: `Data`, `WindowUpdate`, `Close` o `OpenAck` dell'agent in volo dopo il `Close` del client facevano cadere l'agent, anche senza attaccante. | alta | Come #1. | `agent_frames_in_flight_after_client_close_are_dropped`, `late_open_ack_or_reject_after_client_close_is_dropped` |
| 3 | Un relay compromesso rigioca il primo messaggio IK end-to-end catturato: l'agent rispondeva, apriva una connessione a sshd e registrava «sessione iniziata» per quel client. Audit falsificabili e slot pre-auth di sshd consumati. | media | Il client invia come primo messaggio di trasporto una conferma (`TCN/1 ready`) che solo chi ha completato l'handshake sa cifrare. L'agent contatta sshd e registra la sessione solo dopo averla verificata. | `replayed_end_to_end_handshake_never_reaches_sshd` |
| 4 | Flood di `Open`/`Close`: gratis per il client, due frame ciascuno verso l'agent. Un agent su un link lento finiva con la coda dell'hub piena e veniva deregistrato. | media | Token bucket di `Open` per connessione client (64 a raffica, poi 10/s), applicato prima di ogni altro controllo; l'eccesso riceve `Reject RateLimited`. | `open_floods_are_rate_limited` |
| 5 | 65 536 indirizzi di un solo /64 IPv6 riempivano la tabella del rate limiter degli handshake, che poi rifiutava ogni indirizzo nuovo. | media | Chiave del rate limiter: indirizzo per IPv4 (anche IPv4-mapped), prefisso /64 per IPv6. | `every_address_of_an_ipv6_slash64_shares_one_key`, `ipv4_and_ipv4_mapped_addresses_are_keyed_per_address` |
| 6 | L'agent chiude mentre `Data` del client è in volo: il relay disconnetteva il client. | bassa | Come #1. | `client_frames_in_flight_after_agent_close_are_dropped` |

Le correzioni a #1, #2 e #6 non allentano le regole: un frame su uno stream **mai** aperto resta
una violazione (`frames_on_never_opened_streams_are_still_violations`).

## Ipotesi smentite

| # | Ipotesi d'attacco | Esito |
| :-: | :- | :- |
| 7 | Rigiocare il primo messaggio dell'handshake esterno di un agent per prendersi il suo nodo. | **Mitigato.** La connessione rigiocata non completa mai l'handshake e, senza `Register`, scade per timeout. |
| 8 | Un agent si registra con il nome di un altro nodo o scrive negli stream di un altro agent. | **Mitigato.** `agent_cannot_register_as_another_node`, `agent_cannot_inject_into_streams_it_does_not_own`. |
| 9 | Le chiavi Ed25519 P e −P hanno la stessa forma X25519 e la stessa fingerprint. | **Mitigato.** La policy rifiuta la chiave duplicata (`a_key_has_exactly_one_role_and_a_node_one_agent`). |
| 10 | Far accodare al relay dati illimitati; overflow o flood di `WindowUpdate`. | **Mitigato.** `data_beyond_the_window_kills_the_sender`, `tiny_or_overflowing_window_updates_are_violations`. |
| 11 | Flood di `Ping`, `Pong` non richiesti, frame prima di `Register`, `Register` da un client. | **Mitigato.** Test omonimi in `relay_core.rs`. |
| 12 | Frame malformati, stream 0, nomi di nodo non validi, log injection tramite nomi. | **Mitigato.** `decode_malicious.rs`, alfabeto `[a-z0-9-]` dei `NodeId`. |
| 13 | Un relay malevolo invia all'agent un `Open` per un altro nodo. | **Mitigato.** L'agent risponde `Reject NotAuthorized`. |

## Verificati dall'autore dopo la review

| # | Ipotesi | Esito |
| :-: | :- | :- |
| 14 | Un relay malevolo spinge dati oltre la finestra nella coda di uno stream dell'agent (il credito veniva verificato solo all'uscita dalla coda). | **Corretto.** Agent e client applicano il credito **prima** di accodare (`relay_exceeding_stream_credit_gets_the_stream_closed`). |
| 15a | Un relay malevolo riusa uno stream id, facendo rimuovere a un task terminato lo stream nuovo. | **Corretto.** L'agent accetta solo id strettamente crescenti. |
| 15b | TOCTOU tra controllo dei permessi della chiave e lettura. | **Corretto.** I permessi si controllano sul file già aperto. |
| 15c | Canali laterali di tempo. | **Accettato.** I confronti di identità avvengono su fingerprint già autenticate da Noise; le fingerprint usano `subtle`. |

## Residui accettati

- Il rate limiter degli handshake resta *fail closed*: un attaccante con 65 536 prefissi /64
  (un intero /48) può ancora bloccare per circa un minuto gli indirizzi **nuovi**. Gli agent
  già connessi non sono toccati. Una soglia per prefisso più corto arriva con la Fase 4.
- Il relay vede i metadati (chi parla con chi, quando, quanti byte): è inerente a un relay.
