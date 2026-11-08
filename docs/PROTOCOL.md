# Protocollo di framing TCN, versione 1

Questo documento è la specifica normativa del formato dei frame. Il codice di riferimento è
`crates/zt-domain` (tipi e invarianti) e `crates/zt-proto` (codifica). In caso di conflitto,
i test in `crates/zt-proto/tests` sono la fonte di verità e questo documento va corretto.

Le parole DEVE, NON DEVE e PUÒ hanno il significato di RFC 2119.

## 1. Posizione nello stack

```
 zt-client ── Noise (client↔relay) ── zt-relay ── Noise (relay↔agent) ── zt-agent ── 127.0.0.1:22
     └──────────────── Noise end-to-end client↔agent, dentro i frame Data ────────┘
```

- Ogni frame viaggia dentro **un** messaggio di trasporto Noise (max 65 535 byte, tag AEAD
  di 16 byte incluso).
- Il payload dei frame `Data` è a sua volta cifrato end-to-end tra client e agent: il relay
  vede solo byte opachi (*blind relay*).
- Gli handshake Noise non sono frame: avvengono prima che il framing inizi (Fase 2).

## 2. Layout sul filo

Tutti gli interi sono **big-endian** e senza segno.

```
 offset  dim  campo
 ------  ---  -----------------------------------------------
   0      1   version   DEVE valere 0x01
   1      1   kind      codice del tipo (§3)
   2      4   stream_id 0 = controllo connessione, >0 = stream
   6      2   length    byte di payload che seguono
   8      n   payload   n = length
```

L'header è lungo esattamente `FRAME_HEADER_LEN = 8` byte.

## 3. Tipi di frame

| Codice | Tipo | stream_id | Lunghezza payload | Contenuto del payload |
| :-: | :- | :-: | :-: | :- |
| `0x01` | `Register` | `= 0` | 1..=63 | `NodeId` (ASCII, §4.1) |
| `0x02` | `Open` | `> 0` | 1..=63 | `NodeId` di destinazione |
| `0x03` | `OpenAck` | `> 0` | 0 | nessuno |
| `0x04` | `Reject` | `> 0` | 1 | `RejectReason` (§4.3) |
| `0x10` | `Data` | `> 0` | 1..=61 440 | byte opachi cifrati E2E |
| `0x11` | `WindowUpdate` | `> 0` | 4 | `u32` credito, DEVE essere > 0 |
| `0x12` | `Close` | `> 0` | 1 | `CloseReason` (§4.4) |
| `0x20` | `Ping` | `= 0` | 8 | `u64` nonce |
| `0x21` | `Pong` | `= 0` | 8 | `u64` nonce del `Ping` |

Qualsiasi altro codice è un errore. Non esistono campi riservati né estensioni opzionali:
l'unico meccanismo di evoluzione è il byte `version`.

## 4. Invarianti dei valori

### 4.1 `NodeId`
Etichetta DNS ristretta: lunghezza 1..=63, alfabeto `[a-z0-9-]`, nessun `-` iniziale o
finale. Niente maiuscole (nessun case folding), niente punti, niente Unicode: elimina
omografie, injection nei log e ambiguità di confronto.

### 4.2 Limiti di dimensione
| Costante | Valore | Motivazione |
| :- | -: | :- |
| `MAX_PAYLOAD_LEN` | 61 440 (60 KiB) | un payload massimo incapsulato in **due** strati (header + tag ciascuno) sta in un messaggio Noise |
| `MAX_FRAME_LEN` | 61 448 | header + payload massimo |
| `MAX_NODE_ID_LEN` | 63 | RFC 1035 §2.3.4 |

Le relazioni tra limiti sono verificate con `const` assertion: un build con limiti incoerenti
non compila.

### 4.3 `RejectReason`
`0x01` NotAuthorized, `0x02` UnknownNode, `0x03` NodeOffline, `0x04` RateLimited,
`0x05` ResourceExhausted.

### 4.4 `CloseReason`
`0x00` Normal, `0x01` Timeout, `0x02` ProtocolViolation, `0x03` Drained, `0x04` PeerGone,
`0x05` Unauthorized (l'agent rifiuta l'identità end-to-end del client).

## 5. Regole del decoder

1. Il decoder NON DEVE consumare byte finché un frame non è completo.
2. L'header DEVE essere validato per intero (versione, tipo, ambito dello stream, intervallo
   di lunghezza del tipo) **appena sono disponibili 8 byte**, prima di attendere il payload.
   Una lunghezza fuori intervallo è rifiutata senza allocare nulla.
3. Il decoder NON DEVE riservare più di `MAX_FRAME_LEN` byte per un frame.
4. Qualsiasi violazione è **fatale**: il decoder resta avvelenato e la connessione DEVE
   essere chiusa. Non c'è risincronizzazione su un flusso corrotto.
5. Un EOF a metà frame è un errore, non una chiusura pulita.
6. La codifica è **canonica**: ogni frame accettato ha un'unica rappresentazione in byte
   (verificato con test di proprietà). Non c'è malleabilità del formato.
7. I messaggi d'errore contengono solo metadati (codici, lunghezze, posizioni), mai byte
   ricevuti.

## 6. Vettori di riferimento

```
Ping { nonce: 0x0102030405060708 }
01 20 00 00 00 00 00 08 01 02 03 04 05 06 07 08

Open { stream: 0x0a0b0c0d, target: "db1" }
01 02 0a 0b 0c 0d 00 03 64 62 31
```

## 7. Trasporto e handshake

### 7.1 Messaggi su TCP
Ogni messaggio Noise è preceduto dalla sua lunghezza come `u16` big-endian (massimo 65 535).
Dopo l'handshake ogni messaggio Noise contiene **esattamente un** frame: byte in eccesso o un
frame incompleto sono violazioni fatali.

### 7.2 Identità
Ogni nodo ha una chiave Ed25519 a lungo termine (file esadecimale, permessi `0600`). Per Noise
si usa la sua forma X25519 (mappa Edwards → Montgomery). La **fingerprint** è
`SHA-256("TCN fingerprint v1\0" || x25519_public)`, mostrata come `SHA256:<hex>`.
Chiavi pubbliche di ordine piccolo sono rifiutate al caricamento.

### 7.3 Handshake
`Noise_IK_25519_ChaChaPoly_BLAKE2s`, payload vuoti, con prologue diverso per canale:

| Canale | Initiator | Responder | Prologue |
| :- | :- | :- | :- |
| esterno | agent o client | relay | `TCN/1 outer` |
| end-to-end | client | agent (dentro frame `Data`) | `TCN/1 end-to-end` |

L'initiator pinna la chiave del responder. Il responder impara l'identità dell'initiator dal
primo messaggio e, se non è nella sua whitelist, **non risponde**: chiude senza inviare il
secondo messaggio.

Sul canale end-to-end il primo messaggio di trasporto del client DEVE avere come plaintext
`TCN/1 ready`. Il messaggio 1 di IK è rigiocabile da chi lo osserva (il relay): solo dopo
questa conferma l'agent contatta sshd e registra la sessione.

## 8. Ciclo di vita

1. L'agent si connette, completa l'handshake e invia `Register` entro 10 s con il nome che la
   policy associa alla sua chiave. Un secondo agent con la stessa chiave sostituisce il primo.
2. Il client si connette e invia `Open { stream, target }`. Il relay risponde `Reject
   NotAuthorized` sia per nodi non concessi sia per nodi inesistenti (nessun oracolo),
   `NodeOffline` o `ResourceExhausted`; altrimenti inoltra `Open` all'agent con uno stream id
   scelto dal relay (crescente, mai riusato).
3. L'agent risponde `OpenAck`. Il primo `Data` del client contiene il messaggio 1
   dell'handshake end-to-end; l'agent verifica il client contro il **proprio** elenco e, se
   non lo conosce, chiude con `Close Unauthorized`. Poi i `Data` portano i byte SSH cifrati.
4. `Close` da una parte viene inoltrato all'altra. La caduta di una connessione chiude con
   `PeerGone` tutti i suoi stream.

Un peer che viola una regola (ordine dei frame, ruolo, credito, rate) perde la connessione.
Fanno eccezione i frame **in volo** su uno stream già chiuso (per esempio `Data` o `Close`
che incrociano un `Close`): vengono scartati in silenzio. Un frame su uno stream mai aperto
resta una violazione. Gli stream id che il relay assegna agli agent sono strettamente
crescenti; l'agent rifiuta id già visti.

## 9. Controllo di flusso

| Costante | Valore |
| :- | -: |
| `INITIAL_WINDOW` | 256 KiB per direzione per stream |
| `MAX_WINDOW` | 1 MiB |
| `MIN_CHARGE` | 512 byte: un `Data` costa `max(len, 512)` |
| `MIN_WINDOW_UPDATE` | 512 byte |

Chi riceve restituisce credito con `WindowUpdate` dopo aver consegnato i dati. Il relay
applica le stesse regole: un `Data` oltre il credito, un `WindowUpdate` sotto il minimo o che
porta la finestra oltre `MAX_WINDOW` sono violazioni. La memoria che il relay accoda verso un
peer è quindi limitata a `stream × MAX_WINDOW`.

## 10. Limiti e timeout di default

| Limite | Valore |
| :- | -: |
| connessioni contemporanee al relay | 4 096 |
| handshake per IPv4 o per prefisso /64 IPv6 | 20 a raffica, poi 1 ogni 3 s |
| `Open` per connessione client | 64 a raffica, poi 10 al secondo |
| stream per client / per agent | 32 / 64 |
| `Ping` per connessione | 10 a raffica, poi 1 ogni 5 s |
| handshake / inattività / scrittura | 10 s / 90 s / 30 s |
| keepalive di agent e client | 30 s |

## 11. Il client come `ProxyCommand`

`zt-client connect <nodo>` apre una connessione al relay con un solo stream verso il nodo e
collega stdin/stdout di OpenSSH al canale end-to-end.

- **Chiavi pinnate, niente TOFU.** Chiave del relay e chiave dell'agent di ogni nodo vengono da
  `client.toml`. Un nodo senza chiave pinnata, un nome non valido, un file di trust non
  regolare, di un altro utente o scrivibile da altri (anche tramite la directory), o una chiave
  segreta leggibile da altri fanno fallire il client prima di qualsiasi connessione.
- **stdout è il canale SSH.** Ci finiscono solo byte decifrati dal canale end-to-end; log ed
  errori vanno su stderr. Ogni messaggio consegnato viene scritto e svuotato subito (stdout è
  bufferizzato a righe e SSH non manda righe).
- **Chiusura.** EOF su stdin chiude lo stream (`Close Normal`); la chiusura dal lato del nodo
  chiude stdout e termina il processo anche se stdin resta aperto. Non c'è half-close: SSH non
  ne ha bisogno, perché il suo EOF di canale viaggia dentro il protocollo SSH.
- **Codice d'uscita.** 0 solo per `Close Normal` o EOF locale; 1 per ogni altro esito,
  compresa una `Close` d'errore dell'agent (per esempio sshd irraggiungibile); 2 per argomenti
  non validi.
- **Nessun timeout di scrittura su stdout.** Un `ssh` sospeso smette di leggere: la finestra
  limita la memoria e la sessione riprende quando ssh torna a leggere.

## 12. Fuori dall'ambito della Fase 3

Rekey dei canali di lunga durata, revoca a caldo delle chiavi, `cargo-fuzz` e pacchetti
(Fase 4).
