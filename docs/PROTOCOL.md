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
`Noise_IK_25519_ChaChaPoly_BLAKE2s`, con prologue diverso per canale. Il payload del
messaggio 2 DEVE essere vuoto (l'initiator rifiuta un messaggio 2 con payload); il payload del
messaggio 1 è vuoto oppure contiene un certificato client (§15.3), e un responder rifiuta un
payload che non sia né vuoto né un certificato valido.

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

### 7.4 Rekey
Su entrambi i canali, dopo ogni **1024** messaggi di trasporto autentici in una direzione,
mittente e destinatario eseguono `Rekey()` di Noise sulla chiave di quella direzione. Il rekey
è implicito: nessun frame sul filo, solo il contatore. Funziona perché TCP consegna in ordine
e qualsiasi messaggio rifiutato chiude il canale; un messaggio falso non incrementa il
contatore del destinatario. Ogni periodo ha una chiave derivata a senso unico dalla
precedente, quindi una copia della memoria del processo non decifra il traffico registrato dei
periodi passati. Con il keepalive di 30 s un canale inattivo cambia chiave ogni ~8,5 ore; una
sessione SSH ogni ~16 MiB.

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

## 12. Revoca a caldo

Relay e agent ricaricano i propri file di trust con `SIGHUP` (`systemctl reload`). La nuova
configurazione si applica anche a ciò che è già aperto:

| Cambiamento | Effetto |
| :- | :- |
| chiave tolta dalla policy, o passata da client ad agent (o viceversa) | connessione chiusa; i peer delle sue sessioni ricevono `Close PeerGone` |
| chiave di agent associata a un altro nodo | connessione chiusa (`access_revoked`). L'agent continua a registrarsi con il proprio `--node` e viene rifiutato finché non lo si riconfigura (`TCN_NODE`) e riavvia: il nodo di un agent si cambia in entrambi i posti (finding 0004-3) |
| client che perde l'accesso a un nodo | solo gli stream verso quel nodo si chiudono con `Close Unauthorized` da entrambi i lati |
| client tolto dai client autorizzati di un agent | l'agent chiude le sue sessioni con `Close Unauthorized`, senza aspettare il relay |
| certificato revocato (numero di serie o chiave nella denylist), CA tolta, durata del certificato oltre il nuovo `max_lifetime` della sua CA (§15) | come una chiave tolta dalla policy: connessione chiusa dal relay, sessioni chiuse con `Close Unauthorized` dall'agent |
| `allow` di una CA ristretto (§15.5) | solo gli stream verso i nodi non più concessi si chiudono con `Close Unauthorized`, come per un client |

Ogni revoca produce l'evento di audit `access_revoked`. Un file non valido o diventato
insicuro non cambia nulla e produce `policy_reload_failed` (relay) o
`authorized_clients_reload_failed` (agent), a livello `ERROR`.

## 13. Più relay (alta disponibilità)

I relay sono indipendenti: nessuno stato condiviso e nessun protocollo fra di loro. Ognuno ha
la propria chiave e una copia della stessa policy, che l'operatore distribuisce (per esempio
con Ansible). Nulla cambia sul filo.

- **Agent**: ha un elenco di relay (al massimo 8, ciascuno con la propria chiave pinnata) e
  mantiene una sessione verso **ognuno**, in parallelo e con backoff indipendenti. Un relay
  irraggiungibile o lento non tocca le sessioni verso gli altri.
- **Client**: ha un elenco ordinato di relay (al massimo 8) e li prova nell'ordine dato.
  Passa al successivo **solo** per errori che si verificano prima dell'`OpenAck` e che non
  dicono nulla sul diritto d'accesso:

  | Errore sul relay *i* | Il client |
  | :- | :- |
  | TCP rifiutato, timeout, handshake esterno fallito (anche chiave del relay sbagliata), connessione chiusa | prova il relay successivo |
  | `Reject NodeOffline`, `Reject RateLimited` | prova il relay successivo |
  | `Reject NotAuthorized`, `Reject UnknownNode` | si ferma: la policy ha risposto (fail closed) |
  | qualsiasi errore dopo l'`OpenAck` (handshake end-to-end, `Close` dell'agent, dati) | si ferma |

  Dopo l'`OpenAck` il client ha già parlato con l'agent: ripetere su un altro relay
  mascherebbe un agent impostore (chiave end-to-end sbagliata) o una revoca, e potrebbe
  duplicare una sessione già iniziata. Policy diverse fra i relay sono un errore di
  configurazione: il client non le «aggira» cercando un relay più permissivo.

  Attenzione però: un relay che **non conosce** la chiave del client chiude il canale esterno
  durante l'handshake, e per il client questo è indistinguibile da un relay guasto, quindi
  passa al successivo. Una chiave tolta dalla policy di un solo relay resta valida sugli altri:
  la revoca è completa solo quando tutti i relay hanno ricaricato la policy (o quando gli
  agent tolgono la chiave dai loro client autorizzati, §12).

- **Tempi**: i tentativi sono in sequenza, ognuno con i propri timeout (connessione,
  handshake, `Open`). Nel caso peggiore, con *N* relay tutti irraggiungibili per timeout, il
  client impiega *N* volte il tempo di un tentativo prima di arrendersi. Conviene mettere per
  primi i relay più vicini e affidabili; un `ConnectTimeout` di OpenSSH più corto del totale
  interrompe il client prima che li abbia provati tutti.

## 14. Rotazione delle chiavi

Un responder (il relay sul canale esterno, l'agent su quello end-to-end) può avere, oltre alla
chiave corrente, una **chiave precedente**: accetta un `msg1` cifrato verso l'una o l'altra
(prova la corrente, poi la precedente) e risponde con quella che corrisponde. Come initiator
usa sempre la chiave corrente. Così i pin dei peer si aggiornano un po' alla volta, senza un
cambio contemporaneo in tutta la flotta.

| Rotazione | Passi |
| :- | :- |
| chiave del relay | 1. nuova chiave; 2. il relay la carica come corrente e tiene la vecchia come precedente, in un solo passo: un riavvio con i nuovi argomenti (o un `SIGHUP`, se è già avviato con `--previous-key` e i file sono stati sistemati in un ordine sicuro, OPERATIONS §8); 3. si sostituiscono i pin su agent e client (mai due voci per lo stesso relay); 4. si toglie la precedente (un riavvio senza `--previous-key`) |
| chiave di un agent | 1. nuova chiave; 2. la policy del relay elenca entrambe le chiavi per il nodo (`public_keys`, al massimo 2) e si ricarica; 3. l'agent si riavvia con la nuova chiave e la vecchia come precedente: la sessione esterna usa la nuova, il canale end-to-end accetta anche la vecchia; 4. si aggiornano i pin dei client; 5. si tolgono la vecchia chiave dalla policy e la precedente dall'agent |

Relay e agent dichiarano nell'audit log, all'avvio e a ogni ricarica, le fingerprint delle
chiavi che accettano (`keys_in_use`), e finché una precedente è accettata lo ricordano ogni ora
(`previous_key_still_accepted`): una rotazione lasciata a metà non resta invisibile. Allo
stesso modo il relay segnala, all'avvio, a ogni ricarica e ogni ora, i nodi che hanno ancora
due chiavi di agent nella policy (`agent_rotation_pending`).

Il relay rilegge le proprie chiavi a **ogni** `SIGHUP`, anche quando la ricarica serve per la
policy: lo scambio tra chiave corrente e precedente deve quindi essere un unico passo, mai una
sequenza di spostamenti di file sotto un relay avviato senza `--previous-key`. Una precedente
uguale alla corrente, o un file non valido, fa fallire la ricarica e lascia in vigore le chiavi
di prima.

Il riavvio di un agent interrompe solo le sessioni SSH di quel nodo. Il riavvio di un relay,
con più relay, non interrompe nulla di nuovo: agent e client usano gli altri.

**Una chiave compromessa non si ruota: si revoca.** Tenerla come precedente lascerebbe a chi
la possiede la possibilità di impersonare il responder verso chi la pinna ancora. In quel
caso si cambia la chiave senza `--previous-key` e si aggiornano subito i pin (OPERATIONS §7 e §8).

## 15. Certificati client

Con la sola whitelist per chiave (§12) ogni chiave di client va elencata nella policy di ogni
relay e nei client autorizzati di ogni agent, e la revoca è sempre un cambio di quei file. Con
i certificati una **CA offline** (una chiave Ed25519 che non sta mai su relay, agent o client)
firma certificati brevi, da minuti a ore, che legano la chiave statica Noise di un client a un
nome, a un insieme di nodi e a una finestra di validità. Relay e agent pinnano solo le chiavi
pubbliche delle CA (`[[authorities]]`, OPERATIONS §10) e accettano ogni client che presenta un
certificato valido. La whitelist per chiave resta valida e ha la precedenza (§15.5).

Il certificato non sostituisce l'autenticazione Noise: la prova di possesso resta l'handshake
IK sulla chiave statica del client. Il certificato dice soltanto *che cosa* quella chiave può
fare, e vale solo insieme a essa.

### 15.1 Formato

Binario, big-endian, campi a lunghezza fissa o preceduti dalla lunghezza, in ordine fisso.
Nessun campo opzionale, nessuna estensione: l'evoluzione passa da `version` (e da una nuova
stringa di contesto della firma, §15.2).

```
 offset    dim  campo
 --------  ---  -------------------------------------------------------------
   0        4   magic        "TCNC" (54 43 4e 43)
   4        1   version      DEVE valere 0x01
   5        1   sig_alg      DEVE valere 0x01 (Ed25519, RFC 8032, variante pura)
   6       32   ca_key       chiave pubblica Ed25519 della CA che firma
  38       32   subject_key  chiave pubblica Ed25519 del client (la stessa dei file di config)
  70       16   serial       numero di serie, 128 bit casuali, mai tutti zero
  86        8   not_before   u64, secondi Unix (UTC)
  94        8   not_after    u64, secondi Unix (UTC), escluso
 102        1   name_len     1..=63
 103        n   name         nome del client, regole di NodeId (§4.1)
 103+n      1   scope        0x00 = elenco di nodi, 0x01 = tutti i nodi concessi alla CA
 104+n      1   node_count   scope 0x00: 1..=64; scope 0x01: DEVE valere 0
 105+n      …   nodes        node_count volte: len (u8, 1..=63) + NodeId
 L-64      64   signature    firma Ed25519 dei byte [0, L-64) (§15.2)
```

Regole del decoder, tutte fatali (il certificato è rifiutato per intero):

1. La lunghezza totale `L` DEVE stare in `MIN_CERT_LEN..=MAX_CERT_LEN` (170..=4 328 byte);
   un certificato fuori intervallo è rifiutato **prima** di leggerne qualsiasi campo.
2. `magic`, `version` e `sig_alg` DEVONO avere esattamente i valori indicati. Non esiste
   negoziazione dell'algoritmo: un altro valore non è «sconosciuto ma ignorabile», è un errore.
3. `serial` NON DEVE essere tutto a zero; `ca_key` e `subject_key` NON DEVONO coincidere (una CA
   non certifica sé stessa come client).
4. `not_before < not_after` e `not_after - not_before <= MAX_CERT_LIFETIME` (86 400 s, 24 ore).
   Il limite vale per il formato, indipendentemente dalla CA; ogni CA ne ha uno più stretto
   (§15.6).
5. `name` e ogni nodo DEVONO essere `NodeId` validi (alfabeto `[a-z0-9-]`, §4.1).
6. Con `scope = 0x00` i nodi DEVONO essere in ordine **strettamente crescente** di byte: niente
   duplicati, un solo ordine possibile. Un elenco vuoto non è ammesso (un certificato che non
   concede nulla è un errore dell'emittente).
7. Dopo l'ultimo nodo DEVONO restare esattamente 64 byte (la firma): né di più né di meno.
8. `ca_key` e `subject_key` DEVONO essere codifiche **canonicali** di punti Ed25519 validi (la
   ricodifica del punto decompresso restituisce gli stessi 32 byte) e NON DEVONO essere di
   ordine piccolo. La decompressione di `curve25519-dalek` accetta anche codifiche non
   canonicali: il controllo è esplicito. Le regole 1–7 sono puramente sintattiche (dominio);
   la regola 8 richiede l'aritmetica della curva e si applica ai passi 4 e 6 di §15.4.

Ne segue che la codifica è **canonica**: ogni contenuto ha una sola rappresentazione in byte, a
parte la firma (§15.2). Gli errori riportano solo metadati (campo, posizione, lunghezza), mai
byte del certificato.

Nei file il certificato è una sola riga di testo: `tcn-client-cert-v1:` seguito dai byte in
esadecimale, con un a capo finale facoltativo. Il prefisso impedisce di scambiare un
certificato per una chiave (e viceversa): i caricatori delle chiavi non lo accettano.

### 15.2 Firma

`signature = Ed25519-Sign(ca_secret, CTX || L[0..L-64])`, con
`CTX = "TCN client certificate v1\0"` (26 byte). La stringa di contesto separa il dominio:
una firma di certificato non è valida per nessun altro messaggio, presente o futuro, firmato
con la stessa chiave. La firma copre `ca_key`: un certificato non si può attribuire a un'altra
CA.

La verifica DEVE usare la variante **stretta** (`verify_strict` di `ed25519-dalek`: `S`
canonico, `R` e chiave non di ordine piccolo) e la chiave **pinnata** nella configurazione, i
cui 32 byte DEVONO coincidere con `ca_key`: non si verifica mai con la chiave scritta nel
certificato senza averla trovata, byte per byte, fra quelle pinnate.

Ed25519 è deterministico, ma una CA potrebbe produrre due firme diverse dello stesso contenuto:
per questo l'identità di un certificato è il suo `serial`, non l'hash dei suoi byte.

La chiave segreta della CA è una chiave Ed25519 dedicata. Il suo file ha un formato diverso da
quello delle chiavi di nodo (`tcn-ca-secret-v1:<64 hex>`): relay, agent e client non lo
caricano, e `zt-ca` non firma con un file di chiave di nodo. Le chiavi di nodo non firmano mai
nulla (Noise usa la loro forma X25519), quindi non esiste un oracolo di firma nella flotta.

### 15.3 Trasporto

Il certificato viaggia nel **payload del messaggio 1** di Noise IK, su **entrambi** i canali:

| Canale | Chi lo invia | Chi lo verifica | Prima di |
| :- | :- | :- | :- |
| esterno | client | relay | inviare il messaggio 2 |
| end-to-end | client (dentro il primo `Data`) | agent | inviare il messaggio 2 |

Il client invia lo stesso certificato sui due canali; agent e relay lo verificano ciascuno con
le **proprie** CA pinnate, la propria denylist e il proprio orologio (difesa in profondità: un
relay compromesso non sa produrre né alterare il certificato che arriva all'agent).

Perché nel messaggio 1 e non in un frame:

- **Non è in chiaro.** In IK il payload del messaggio 1 è cifrato e autenticato con le chiavi
  derivate da `es` e `ss`, cioè verso la chiave statica pinnata del responder: un osservatore
  di rete non lo legge e non lo può togliere né sostituire senza la chiave segreta del client.
  Ha le stesse proprietà della chiave statica del client, che viaggia nello stesso messaggio:
  chi in futuro ottenesse la chiave segreta del responder potrebbe leggere i certificati
  registrati, come può già leggere le identità. Il certificato non contiene segreti.
- **La decisione resta prima del messaggio 2.** Un certificato non valido equivale a una
  chiave sconosciuta: il responder non risponde (§7.3). Nessun peer non autorizzato completa un
  handshake o raggiunge il decoder dei frame, e non c'è un nuovo stato «connesso ma non ancora
  autorizzato» nel relay core.
- **Nessun cambio al framing.** L'insieme dei frame (§3) resta chiuso e invariato; nessun
  nuovo round trip.

Un frame `Certificate` dopo l'handshake è stato scartato: obbligherebbe il relay a completare
l'handshake con chiunque, aggiungerebbe uno stato e un timeout pre-autorizzazione, e sul canale
end-to-end l'agent dovrebbe rispondere a client sconosciuti. Il frame `Open` (1..=63 byte) non
può contenerlo.

Il messaggio 1 si può rigiocare (§7.3). Un messaggio 1 rigiocato con un certificato valido non
completa l'handshake (serve la chiave effimera del client), costa al responder al più una
verifica di firma in più, entro il limite degli handshake (§10), e non produce alcun evento di
successo: gli eventi che nominano un certificato accettato (§15.11) si registrano solo dopo un
messaggio di trasporto autentico del client (`Open` sul canale esterno, `TCN/1 ready` su quello
end-to-end).

Compatibilità: un relay o un agent precedente alla Fase 6 ignora il payload del messaggio 1;
un client con certificato e senza voce nella sua policy viene quindi trattato come chiave
sconosciuta (nessuna risposta). Un client senza certificato non cambia nulla. Il byte
`version` dei frame e i prologue restano invariati.

Dimensioni: il messaggio 1 con il certificato più grande è lungo `96 + 4 328 + 16` byte e sta
sia in un messaggio Noise sia nel payload di un frame `Data` (verificato con `const`
assertion). Un responder rifiuta un payload del messaggio 1 più lungo di `MAX_CERT_LEN` senza
interpretarlo.

### 15.4 Verifica: ordine dei controlli

Relay (canale esterno) e agent (canale end-to-end) applicano gli stessi controlli, in
quest'ordine; il primo che fallisce decide il motivo registrato nell'audit (§15.11). L'ordine
mette prima i controlli economici e quelli che non dipendono da dati non firmati, e fa sì che un
evento che nomina un numero di serie riguardi sempre un certificato davvero firmato da una CA
pinnata.

| # | Controllo | Esito se fallisce (`cert_check`) |
| :-: | :- | :- |
| 0 | messaggio 1 Noise valido → chiave statica del client autenticata | `handshake_failed` (come oggi) |
| 1 | chiave del client nella denylist (`keys`, §15.8) | `key_revoked`, anche senza certificato |
| 2 | payload vuoto → nessun certificato: solo la whitelist per chiave decide (§15.5) | — |
| 3 | lunghezza in `MIN_CERT_LEN..=MAX_CERT_LEN`, poi formato §15.1 regole 1–7 | `malformed` |
| 4 | `subject_key` canonica e non debole; **fingerprint di `subject_key` uguale alla fingerprint della chiave statica autenticata da Noise** (confronto a tempo costante) | `key_mismatch` |
| 5 | `ca_key` uguale, byte per byte, a una chiave pinnata in `[[authorities]]` | `unknown_authority` |
| 6 | firma stretta (§15.2) con quella chiave pinnata | `bad_signature` |
| 7 | `serial` nella denylist (`serials`) | `serial_revoked` |
| 8 | `now >= not_before - SKEW` (§15.6) | `not_yet_valid` |
| 9 | `now < not_after` | `expired` |
| 10 | `not_after - not_before <= max_lifetime` della CA che ha firmato | `lifetime_exceeds_authority` |
| 11 | (solo relay) la chiave ha il ruolo di agent nella policy | `role_conflict` |
| 12 | (solo agent) il proprio nodo è nell'ambito effettivo (§15.5) | `node_out_of_scope` |

Il controllo 4 viene **prima** della firma: un certificato rubato e presentato con un'altra
chiave statica non costa nemmeno una verifica di firma, e il responder non fa da oracolo di
verifica per certificati arbitrari. La fingerprint (§7.2) è calcolata sulla forma X25519, la
stessa che Noise autentica: due chiavi Ed25519 `P` e `−P` hanno la stessa forma X25519 e quindi
la stessa identità, nel certificato come nella policy.

Esito di un fallimento:

- **relay**: nessun messaggio 2, connessione chiusa (come una chiave sconosciuta, §7.3);
  evento `authentication_failed`. Il client non distingue un certificato rifiutato da un relay
  guasto e prova il relay successivo (§13): per questo `zt-client` controlla localmente il
  proprio certificato prima di connettersi (§15.6).
- **agent**: nessun messaggio 2, stream chiuso con `Close Unauthorized` (come un client
  sconosciuto, §8 punto 3); evento `authentication_failed`. Il client si ferma (errore dopo
  l'`OpenAck`, §13).

Il relay ricontrolla i passi 1, 5 e 7–11 nel relay core con la policy e l'orologio del momento in
cui la connessione vi arriva (una ricarica fra l'handshake e la registrazione non si perde,
come per le chiavi, finding 0004-9).

### 15.5 Autorizzazione: whitelist e certificati

Una chiave elencata nella policy (relay) o nei client autorizzati (agent) è autorizzata **dalla
whitelist**, che ha la precedenza:

| La chiave… | Certificato presentato | Risultato |
| :- | :- | :- |
| è nella denylist `keys` | qualsiasi | rifiutata (passo 1) |
| è un client della whitelist | nessuno | permessi della whitelist (come oggi) |
| è un client della whitelist | valido | permessi della whitelist; il certificato è ignorato dopo la verifica (nessuna unione dei permessi, nessuna scadenza in sessione) |
| è un client della whitelist | non valido | rifiutata: un certificato presentato si verifica sempre (fail closed) |
| è un agent (solo relay) | presente | rifiutata (`role_conflict`): una chiave ha un solo ruolo |
| non è nella whitelist | nessuno | rifiutata (come oggi) |
| non è nella whitelist | valido | permessi del certificato (sotto) |

La precedenza della whitelist rende la migrazione graduale: un client riceve il certificato
mentre la sua voce è ancora nei file; quando la voce viene tolta (e ricaricata) la sua
connessione cade una volta (§12) e si riapre con il certificato. Togliere la chiave dalla
whitelist non basta per revocare un client che ha anche un certificato: si usa la denylist
(§15.8).

**Ambito effettivo** di un certificato firmato dalla CA `A`:

```
relay:  nodi concessi = nodi della policy ∩ ambito(cert) ∩ allow(A)
agent:  accetta       ⇔ proprio nodo ∈ ambito(cert) ∩ allow(A)
dove ambito(cert) = allow(A) se scope = 0x01, altrimenti l'elenco del certificato;
     allow(A)     = tutti i nodi se la CA ha allow = ["*"]
```

Una CA vale solo per i nodi che l'operatore le assegna (`allow`): un certificato che elenca
un nodo fuori da `allow(A)` non lo concede, anche se la firma è valida. La CA che conta è
quella la cui chiave pinnata ha verificato la firma, non il nome scritto da qualche parte.
Un ambito effettivo vuoto non rifiuta la connessione (come `allow = []` per una chiave): ogni
`Open` riceve `Reject NotAuthorized`, che resta indistinguibile da «nodo inesistente» (§8).

Il **nome** del certificato è un'etichetta per gli audit log: non entra in nessuna decisione.
Può coincidere con il nome di un client della whitelist o con quello di un altro certificato
senza conseguenze sull'accesso; per questo gli eventi riportano sempre anche la fingerprint
della chiave, la CA e il numero di serie.

### 15.6 Tempo

Tutti i tempi sono secondi Unix UTC dell'orologio di sistema (`SystemTime`); un orologio prima
del 1970 vale 0 (fail closed: nessun certificato è ancora valido). Un certificato è valido
all'istante `now` se

```
not_before - SKEW  <=  now  <  not_after          con SKEW = 120 s
```

- La tolleranza vale **solo per `not_before`**: copre una CA offline con l'orologio un po'
  avanti, che emette un certificato «nel futuro» per relay e agent. `not_after` non è mai
  esteso: la scadenza è il confine di sicurezza, e un verificatore in ritardo la allunga già da
  sé.
- `SKEW` è una costante del protocollo, non un'opzione: meno manopole, nessuna tolleranza di
  ore impostata per comodità.
- Durata massima: `not_after - not_before` non supera `max_lifetime` della CA (60..=86 400 s,
  default 28 800 = 8 ore; OPERATIONS §10) né `MAX_CERT_LIFETIME` (24 ore, regola del formato).
- Ogni aritmetica sui tempi è controllata (`checked_*`/`saturating_*`): `not_before` vicino a 0
  o `not_after` vicino a `u64::MAX` non provocano overflow.
- `zt-client` controlla il proprio certificato prima di connettersi, con il proprio orologio:
  rifiuta un certificato già scaduto o che non è per la propria chiave, e avvisa su stderr se
  scade entro 15 minuti o non è ancora valido. È solo un aiuto per l'utente: le decisioni le
  prendono relay e agent.

Residuo accettato: chi sposta all'indietro l'orologio di un relay **e** di un agent (attacco a
NTP) rende di nuovo validi certificati scaduti. Si raccomanda NTS (OPERATIONS §10); la denylist
resta efficace in ogni caso.

### 15.7 Scadenza durante la sessione

**Una sessione autorizzata da un certificato finisce quando il certificato scade.** Al momento
`now >= not_after`:

- il **relay** invia `Close Unauthorized` su ogni stream della connessione del client, a
  entrambi i lati (client e agent), poi chiude la connessione, e registra
  `certificate_expired`. Il controllo avviene a ogni scatto del relay core (1 s);
- l'**agent** chiude ogni sessione end-to-end autorizzata da quel certificato con
  `Close Unauthorized` e registra `certificate_expired`. Il controllo rilegge l'orologio di
  sistema almeno ogni 60 s e allo scadere previsto, quindi un salto in avanti dell'orologio o
  una VM sospesa non allungano la sessione di più di 60 s;
- `zt-client`, ricevendo `Close Unauthorized` dopo la scadenza del proprio certificato, lo dice
  esplicitamente («certificate expired: renew it») e termina con codice 1.

Motivazione:

1. **La durata breve è l'unica revoca automatica.** Se le sessioni sopravvivessero alla
   scadenza, chi ruba chiave e certificato aprirebbe una sessione all'ultimo minuto e la terrebbe
   aperta per giorni (ControlPersist, tunnel inattivi con keepalive): «breve» non varrebbe nulla
   proprio contro l'attaccante.
2. **Coerenza con la revoca a caldo (§12)**, che si applica già alle sessioni aperte: la
   scadenza è una revoca annunciata in anticipo.
3. **La denylist si può potare.** Poiché nessuna sessione sopravvive a `not_after`, una voce
   della denylist si può togliere dopo la scadenza del certificato (§15.8); altrimenti dovrebbe
   restare finché ogni sessione aperta con esso non fosse finita, cosa che nessuno sa.

Il costo operativo è noto e documentato (OPERATIONS §10): un playbook più lungo del certificato
viene interrotto, quindi si emette un certificato che ne copra la durata (entro `max_lifetime`)
o lo si rinnova prima; con `ControlPersist` il master SSH usa il certificato con cui è nato, e
dopo un rinnovo va chiuso (`ssh -O exit`) per usare quello nuovo.

Le sessioni autorizzate dalla whitelist non scadono, anche se il client ha presentato un
certificato (§15.5).

### 15.8 Revoca

Fra l'emissione e la scadenza un certificato si revoca con una **denylist**, un file separato
(`revoked.toml`, OPERATIONS §10) che relay e agent leggono con `--revocations` e ricaricano con
`SIGHUP` insieme alla policy o ai client autorizzati, in un solo passo: se uno dei due file non
è valido la ricarica fallisce per intero e restano entrambi i precedenti (`..._reload_failed`).
Il file è lo stesso per tutta la flotta, relay e agent: un solo artefatto da distribuire e da
confrontare (`sha256sum`).

| Voce | Effetto |
| :- | :- |
| `serials` | quel certificato è rifiutato (passo 7) |
| `keys` | quella chiave è rifiutata con **qualsiasi** credenziale: tutti i suoi certificati, di qualsiasi CA, e la sua voce nella whitelist (passo 1). È la revoca di una persona o di una macchina |

La denylist si applica anche alle connessioni e sessioni aperte, come ogni ricarica (§12).
Una chiave è confrontata per fingerprint (forma X25519), quindi `P` e `−P` sono la stessa voce.

Con una CA pinnata, `--revocations` è **obbligatorio** (anche con un file vuoto): relay e agent
non partono, e una ricarica fallisce, se la configurazione ha `[[authorities]]` ma nessuna
denylist. Così il percorso per una revoca urgente esiste già prima che serva.

Una voce di `serials` si può togliere quando il certificato è scaduto da più di `SKEW` (§15.7):
`zt-ca` registra ogni emissione con numero di serie e scadenza (OPERATIONS §10). Una voce di
`keys` resta finché la chiave non è sostituita ovunque.

Revoca d'emergenza di un'intera CA: si toglie la sua chiave da `[[authorities]]` e si ricarica;
tutti i suoi certificati, anche in uso, cadono.

### 15.9 Rotazione delle CA

Come per le chiavi di agent (§14), una voce `[[authorities]]` ha una chiave
(`public_key`) o, durante una rotazione, due (`public_keys = ["<nuova>", "<vecchia>"]`). Lo
stesso `name`, `allow` e `max_lifetime` valgono per entrambe.

1. Si crea la nuova CA (offline) e si aggiunge la sua chiave alla voce, su tutti i relay e gli
   agent; si ricarica.
2. Si emettono i certificati nuovi con la nuova CA.
3. Quando è passato almeno `max_lifetime` dall'ultimo certificato firmato dalla vecchia, nessun
   certificato della vecchia è più valido: la si toglie e si ricarica.

Finché una voce ha due chiavi, relay e agent registrano `ca_rotation_pending` all'avvio, a ogni
ricarica e ogni ora. Una **CA compromessa** non si ruota: si toglie subito (§15.8, revoca
d'emergenza) e si riemettono i certificati con una CA nuova.

Vincoli di caricamento, tutti fatali: al massimo `MAX_AUTHORITIES` (16) voci; una o due chiavi
per voce, distinte; una chiave di CA compare in una sola voce; una chiave di CA non è mai la
chiave di un peer della stessa configurazione (agent o client della whitelist), né la chiave
del processo stesso (relay o agent, corrente o precedente), né per un agent la chiave di un
relay pinnato (`--relay-key`): un relay compromesso, con il proprio seme di nodo trasformato in
file di CA, firmerebbe altrimenti certificati che l'agent ammette (finding 0006-1); i nomi delle
CA sono `NodeId` distinti fra loro; chiavi canonicali e non deboli. Il controllo vale all'avvio
e a ogni ricarica, nei due versi: una ricarica della policy rifiuta una CA uguale alle chiavi del
relay in vigore, e una ricarica delle chiavi del relay (§14) rifiuta una chiave uguale a una CA
della policy in vigore (`relay_keys_reload_failed`, «authority key equals the relay key»;
finding 0006-2).

### 15.10 Più relay

Nulla cambia rispetto a §13. Tutti i relay devono avere le stesse `[[authorities]]` e la stessa
denylist. Un relay che non pinna la CA, o che non ha ancora ricaricato una denylist più
permissiva, chiude l'handshake senza rispondere, e il client passa al successivo come per una
chiave sconosciuta. Allo stesso modo una revoca è completa sui relay solo quando tutti hanno
ricaricato la denylist; gli agent la applicano comunque per conto proprio, qualunque relay sia
usato.

### 15.11 Audit

Eventi nuovi o con campi nuovi (OPERATIONS §6). Un certificato non compare mai nei log: solo
numero di serie (esadecimale), fingerprint della CA e del client, nome e scadenza.

| `event_kind` | Livello | Quando, e campi aggiunti |
| :- | :- | :- |
| `authentication_failed` | WARN | un controllo del §15.4 fallisce: `reason` (`key_revoked` o `certificate`), `cert_check`; `ca`, `serial`, `cert_name` e `not_after` solo dopo il passo 6 (firma verificata), su relay e agent |
| `session_established` (relay), `e2e_session_started` (agent) | INFO | `credential` = `key` o `certificate`; per un certificato anche `ca`, `serial`, `cert_name`, `not_after`. Si registrano solo dopo un messaggio autentico del client (§15.3) |
| `access_denied` | WARN | come oggi, con gli stessi campi del certificato |
| `access_revoked` | WARN | come oggi, con gli stessi campi del certificato |
| `certificate_expired` | INFO | (relay e agent) una sessione autorizzata da un certificato è stata chiusa alla scadenza: `peer`, `ca`, `serial` |
| `authorities_in_use` | INFO, WARN con due chiavi | all'avvio e a ogni ricarica, per ogni CA: `authority`, `fingerprints`, `max_lifetime` |
| `ca_rotation_pending` | WARN | all'avvio, a ogni ricarica e ogni ora, per ogni CA con due chiavi |
| `revocations_in_use` | INFO | all'avvio e a ogni ricarica: `serials`, `keys` (quante voci) |

Confrontare i numeri di serie visti negli audit con il registro delle emissioni di `zt-ca`
(OPERATIONS §10) rivela un certificato che la CA non ha emesso, cioè una CA compromessa.

### 15.12 Limiti

| Limite | Valore | Motivazione |
| :- | -: | :- |
| `MAX_CERT_LEN` | 4 328 byte | 64 nodi da 63 byte, nome da 63 byte; sta in un `Data` e in un messaggio 1 |
| `MIN_CERT_LEN` | 170 byte | il certificato più corto (`scope = 0x01`, nome di 1 byte) |
| `MAX_CERT_NODES` | 64 | oltre si usa `scope = 0x01` con una CA dedicata |
| `MAX_CERT_LIFETIME` | 86 400 s | «breve» per costruzione |
| `max_lifetime` di una CA | 60..=86 400 s, default 28 800 | per CA |
| `SKEW` | 120 s | solo su `not_before` |
| `MAX_AUTHORITIES` | 16 | per file |
| chiavi per CA | 1 o 2 | rotazione |
| `serials` / `keys` nella denylist | 16 384 / 4 096 | lookup in tabella hash; file entro 1 MiB |
| controllo della scadenza | 1 s (relay), ≤ 60 s (agent) | §15.7 |

Il costo di un messaggio 1 con certificato, per chi lo riceve, è al più una verifica di firma
in più rispetto a oggi, e solo dopo il controllo di binding (passo 4): resta entro il limite
degli handshake per indirizzo (§10) sul relay e entro la quota di stream per relay sull'agent.
Il relay core tiene per ogni connessione con certificato solo i dati verificati (al più 64
nodi), non i byte del certificato.

### 15.13 Vettore di riferimento

CA con seme Ed25519 `01 × 32`, client con seme `02 × 32` (i semi sono il formato dei file di
chiave, §7.2), `serial = 01 02 … 10`, `not_before = 1 800 000 000`,
`not_after = 1 800 003 600`, nome `alice`, nodi `db-01`, `web-01` (L = 187):

```
ca_key      8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
subject_key 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
fingerprint del client SHA256:2f5eeec4374d5bc20b0db3d79cf1ebaee1b6834b48e41fe65e8d24f5b653228b

54 43 4e 43 01 01 8a 88 e3 dd 74 09 f1 95 fd 52
db 2d 3c ba 5d 72 ca 67 09 bf 1d 94 12 1b f3 74
88 01 b4 0f 6f 5c 81 39 77 0e a8 7d 17 5f 56 a3
54 66 c3 4c 7e cc cb 8d 8a 91 b4 ee 37 a2 5d f6
0f 5b 8f c9 b3 94 01 02 03 04 05 06 07 08 09 0a
0b 0c 0d 0e 0f 10 00 00 00 00 6b 49 d2 00 00 00
00 00 6b 49 e0 10 05 61 6c 69 63 65 00 02 05 64
62 2d 30 31 06 77 65 62 2d 30 31 65 9f a0 0c 94
7c 7c 51 3c 25 6d b9 67 3b a4 0a 89 5e e8 ad ba
9e 4d a9 7e 57 8f 67 43 f9 76 ac 53 01 b6 aa d1
20 3e 4a 03 a8 7d d2 cf fc a2 2d 96 41 26 ae 7d
5b 26 a9 d1 60 67 69 7e 5b 53 0f
```

Il vettore è stato calcolato fuori dal progetto; come per il framing, se il test
`reference_vector_matches_the_protocol` lo smentisce, va corretto questo documento.

### 15.14 Attacchi considerati

| Attacco | Difesa |
| :- | :- |
| certificato rubato (dai log, dal relay, da un backup) presentato con un'altra chiave statica | binding al passo 4: la fingerprint del soggetto deve essere quella provata da Noise; nessuna verifica di firma per certificati non legati |
| chiave e certificato rubati insieme | durata breve, scadenza anche in sessione (§15.7), denylist `serials`/`keys` |
| CA di un reparto che firma per nodi di un altro | ambito effettivo ∩ `allow` della CA (§15.5); la CA si identifica dalla chiave pinnata che verifica la firma |
| stessa chiave di CA in due voci con ambiti diversi; chiave di CA usata anche come chiave di peer | rifiutati al caricamento (§15.9) |
| confusione di algoritmo, versione o formato | `magic`, `version`, `sig_alg` a valore unico; contesto di firma con versione; prefissi distinti per file di certificato e di chiave della CA; le chiavi di nodo non firmano mai |
| certificati malleabili (due codifiche dello stesso contenuto, chiavi non canonicali, firme malleabili) | codifica canonica (§15.1), chiavi canonicali e non deboli, `verify_strict`, identità = `serial` |
| certificato enorme o con molti nodi per consumare memoria o CPU | `MAX_CERT_LEN` controllato prima del parsing; `MAX_CERT_NODES`; payload del messaggio 1 limitato; firma verificata dopo i controlli economici, entro i limiti degli handshake |
| `not_before` / `not_after` estremi, durata lunga, overflow | regole 4 del formato, `max_lifetime` per CA, aritmetica controllata, tolleranza solo su `not_before` |
| tenere aperta una sessione oltre la scadenza | §15.7 |
| aggirare la denylist con un altro certificato della stessa chiave, con `−P`, o con la voce della whitelist | `keys` vale per ogni credenziale e confronta fingerprint |
| denylist non valida durante un'emergenza | la ricarica fallisce per intero con un evento ERROR; gli agent la applicano per conto proprio; revoca d'emergenza della CA |
| nome del certificato uguale a quello di un altro client | i nomi non autorizzano nulla; gli audit hanno sempre fingerprint, CA e serie |
| togliere il certificato per ricadere sulla whitelist (downgrade) | il payload è autenticato da Noise: toglierlo richiede la chiave segreta del client; la precedenza della whitelist è una scelta dell'operatore, non del peer |
| relay compromesso che forgia o altera certificati verso l'agent | il relay non ha la chiave della CA; il certificato end-to-end è cifrato verso l'agent; l'agent verifica da sé, compreso il proprio nodo nell'ambito |
| relay compromesso che rigioca il messaggio 1 end-to-end | come oggi: senza `TCN/1 ready` niente sshd e niente sessione registrata (finding 0002-3) |
| messaggio 1 rigiocato per far comparire un client negli audit | gli eventi di successo si registrano solo dopo un messaggio autentico (§15.3) |
| CA che firma un certificato per la chiave di un agent | `role_conflict` sul relay; la chiave non può aprire stream |
| orologio di relay e agent spostato all'indietro | residuo accettato (§15.6); NTS raccomandato; denylist |

## 16. Fuori dall'ambito

Ricarica a caldo della chiave di un agent (richiede il riavvio di quell'agent); policy
condivisa o sincronizzata fra relay; rate limiting per prefissi IPv4 più ampi di un
indirizzo. Per i certificati: certificati per agent e relay; una CA online o il rinnovo
automatico dei certificati; distribuzione automatica della denylist (CRL/OCSP); vincoli sul
certificato oltre ai nodi (indirizzi di origine, utenti SSH, comandi): restano compito di SSH.
