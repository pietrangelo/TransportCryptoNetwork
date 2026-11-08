# Adversary review 0003: `zt-client` come `ProxyCommand` (Fase 3)

**Superficie:** `bins/zt-client` (CLI, ricerca della configurazione, wiring di stdin/stdout),
`zt-net::config` (configurazione del client, controlli sui file di trust), `zt-net::client` e
`zt-net::stream` (pump verso il processo locale).
**Revisore:** agente avversario indipendente, a cui è stato dato il codice e non le
conclusioni dell'autore. Ogni ipotesi è stata verificata con un test eseguito su una copia del
repository (OpenSSH 9.6p1, Ansible), o smentita da un test esistente.
**Attaccante:** (a) utente locale con un altro UID; (b) relay compromesso; (c) agent malevolo;
(d) chi controlla i nomi host che arrivano a `%n`/`%h` (inventario Ansible, nome digitato).

Prima della review, i test di specifica avevano già trovato un difetto: lo stdout di
`zt-client` è bufferizzato a righe e i byte SSH restavano nel buffer, bloccando la sessione.
Ora ogni messaggio consegnato viene svuotato subito
(`delivered_bytes_are_flushed_to_a_buffered_local_writer`).

## Finding aperti al momento della review, tutti corretti in questa PR

| # | Ipotesi d'attacco | Gravità | Correzione | Regressione |
| :-: | :- | :-: | :- | :- |
| 1 | Il controllo sui file di trust guardava solo i bit `0o022` del file. Un altro UID che può scrivere nella directory (`~/.config/tcn` con permessi larghi, o un `TCN_CLIENT_CONFIG` in `/tmp`) mette al suo posto un `client.toml` suo in `0644`, con relay e pin dei nodi dell'attaccante: MITM completo del livello TCN, con la chiave vera della vittima. Varianti: un FIFO bloccava per sempre ogni fork di Ansible; i symlink di altri venivano seguiti. | media | Come `StrictModes` di OpenSSH: file regolare (aperto con `O_NONBLOCK`), proprietario l'utente corrente o root, directory che lo contiene di proprietà dell'utente o di root e non scrivibile da gruppo o altri. Vale per tutti i file di trust (client, policy del relay, client autorizzati dell'agent, nodi noti) e per le chiavi segrete. Un symlink è ammesso solo se il file di destinazione e la sua directory superano i controlli. | `trust_files_owned_by_another_user_are_refused`, `non_regular_trust_and_key_files_are_refused_without_blocking`, `trust_files_in_a_directory_writable_by_others_are_refused` |
| 2 | Un `ssh` sospeso (`~^Z`, SIGSTOP) smette di leggere: dopo 30 s il timeout di scrittura locale chiudeva la sessione, che su TCP diretto sarebbe sopravvissuta. Il timeout non proteggeva nulla, perché la memoria è già limitata dalla finestra. | media | Il client scrive su stdout senza timeout; l'agent mantiene il timeout verso sshd. | `a_stalled_local_reader_does_not_kill_the_session` |
| 3 | Una `Close` con motivo d'errore era trattata come chiusura ordinata: con sshd irraggiungibile il client usciva con 0 e senza messaggi; un `Close` iniettato dal relay faceva uscire con 0. Ogni `Closed` veniva descritto come errore di chiavi. | bassa | Solo `Close Normal` è una chiusura ordinata; le altre sono errori (`exit 1`) con un messaggio che nomina il nodo e la causa probabile. Lo stream già chiuso dal peer non viene richiuso. | `unreachable_sshd_is_an_error_with_a_message` |
| 4 | ssh esegue `sh -c "exec zt-client … %n"`: con un OpenSSH precedente al fix di CVE-2023-51385 un nome host con spazi (`web-01 --config /evil.toml`) diventava un'opzione. | bassa | Il nome del nodo è l'ultimo argomento: tutto ciò che segue viene raccolto e rifiutato; `--config` va prima di `connect`. | `options_after_the_node_name_are_never_parsed` |

## Ipotesi smentite o accettate

| # | Ipotesi d'attacco | Esito |
| :-: | :- | :- |
| 5 | Metacaratteri di shell in `%n` | **Mitigato** da OpenSSH ≥ 9.6 (verificato su 15 nomi); ciò che passa (`%`, `*`, `.` finale, maiuscole) è rifiutato da `NodeId` (`malformed_node_names_are_refused_without_touching_the_network`). |
| 6 | `--strip-suffix` allarga i nomi accettati | **Mitigato.** `strip_suffix_does_not_widen_the_accepted_names` |
| 7 | Relay o DNS dirottati, agent impostore | **Mitigato.** `impostor_relay_is_detected_and_nothing_reaches_stdout`, `impostor_agent_is_detected_and_sshd_is_never_dialed` |
| 8 | Inquinamento di stdout, segreti o payload nei log | **Mitigato.** `trace_logging_never_reaches_stdout_nor_leaks_the_secret` |
| 9 | Il processo resta vivo e trattiene i fork di Ansible | **Mitigato.** `exits_when_the_node_closes_even_if_stdin_stays_open`; con `ControlPersist` scaduto non restano processi; il test Ansible usa `ControlMaster=auto` e `ControlPersist`. |
| 10 | Concorrenza di Ansible e pipelining | **Mitigato.** `parallel_ssh_sessions`, `ansible_playbook_runs_through_tcn` |
| 11 | Dopo l'EOF su stdin si perdono i dati in arrivo | **Accettato.** Non c'è half-close (PROTOCOL §11); ssh chiude stdin solo a fine sessione. |
| 12 | `XDG_CONFIG_HOME`/`HOME` relativi, `TCN_CLIENT_CONFIG` vuoto o relativo | **Mitigato** (ignorati) / **accettato** (relativo: chi controlla l'ambiente controlla già il processo). |
| 13 | `ssh WEB-01` corrisponde a `Host web-01` ma il nodo `WEB-01` non esiste | **Accettato**: fallisce in modo chiuso; documentato in OPERATIONS. |
