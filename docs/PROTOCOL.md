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
`0x00` Normal, `0x01` Timeout, `0x02` ProtocolViolation, `0x03` Drained, `0x04` PeerGone.

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

## 7. Fuori dall'ambito della Fase 1

Handshake Noise e legame tra chiave statica e `NodeId`, controllo di flusso a credito,
rate limiting, timeout e keepalive: sono responsabilità degli use case e degli adapter di
rete (Fase 2). Il framing garantisce solo che ogni frame ricevuto sia ben formato.
