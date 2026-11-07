# Adversary review 0001: framing (Fase 1)

**Superficie:** `zt_proto::FrameDecoder::decode`, l'unico punto in cui byte non fidati
diventano tipi di dominio.
**Attaccante:** peer autenticato a livello Noise ma malevolo (agent compromesso, client
rubato), oppure relay compromesso che riscrive i frame.

| # | Ipotesi d'attacco | Esito |
| :-: | :- | :- |
| 1 | Dichiarare `length = 0xFFFF` per far bufferizzare 64 KiB per connessione | **Mitigato.** Rifiutato dal solo header, prima di attendere il payload (`rejects_oversized_length_from_the_header_alone`, proprietà `oversized_lengths_rejected_before_buffering`). |
| 2 | Versione o tipo sconosciuti per raggiungere percorsi non testati | **Mitigato.** Insieme chiuso, errore fatale (`rejects_unsupported_versions`, `rejects_unknown_kinds`, tutti i 247 codici non definiti). |
| 3 | Frame `Data` sullo stream 0 o `Ping` su uno stream per confondere il demultiplexer | **Mitigato.** Ambito dello stream validato nell'header (`rejects_stream_frames_on_the_control_stream`, `rejects_control_frames_on_a_data_stream`). |
| 4 | Dopo un errore, continuare a inviare sperando in una risincronizzazione | **Mitigato.** Decoder avvelenato (`decoder_is_poisoned_after_the_first_error`). |
| 5 | Codifiche alternative dello stesso frame per eludere filtri o firme future | **Mitigato.** Codifica canonica verificata su byte arbitrari e strutturati (`arbitrary_bytes_never_panic_and_accepted_frames_are_canonical`, `structured_fuzz_never_panics`). |
| 6 | `NodeId` con maiuscole, Unicode, NUL, newline per omografie, log injection o path traversal | **Mitigato.** Alfabeto `[a-z0-9-]` (`rejects_invalid_node_ids`, test di dominio). |
| 7 | Errori che riflettono i byte inviati nei log del relay | **Mitigato.** Errori solo con metadati (`errors_never_echo_attacker_bytes`). |
| 8 | Panic su input fuzzato (overflow, indicizzazione) per abbattere il processo | **Mitigato.** Lint `deny` su indicizzazione e aritmetica, ~10 000 casi proptest per run, `panic = "abort"` in release limita l'effetto a un processo. |
| 9 | Troncare la connessione a metà frame per lasciare stato parziale | **Mitigato.** EOF a metà frame è `DecodeError::Io` (`truncated_stream_is_an_error_not_a_silent_eof`). |
| 10 | Inviare tanti `Data` da 1 byte: ogni `Bytes` restituito condivide il buffer di lettura e può tenerne viva l'allocazione mentre attende in coda | **Aperto → Fase 2.** I canali bounded vanno dimensionati in **byte**, non in numero di frame, oppure i payload piccoli vanno copiati prima di metterli in coda. |
| 11 | Flood di `Ping`, `Pong` non richiesti, `WindowUpdate` che porta il credito oltre `u32::MAX` | **Aperto → Fase 2.** Il framing li accetta perché ben formati; rate limit, `Pong` solo in risposta e somma del credito con `checked_add` spettano agli use case. |
| 12 | Slowloris: inviare l'header e poi un byte al minuto | **Aperto → Fase 2.** Timeout per frame e per inattività nell'adapter di rete (`tokio::time::timeout`). |

**Verdetto:** il decoder rispetta le garanzie della specifica. I finding 10–12 sono requisiti
di input per la Fase 2 e vanno coperti da test d'attacco prima dell'implementazione.
