# Messa in esercizio

Questa guida porta in funzione relay e agent e collega `zt-client` a OpenSSH e Ansible.

## 1. Chiavi

Ogni macchina genera la propria chiave; il segreto non lascia mai la macchina.

```bash
zt-relay keygen --out /etc/tcn/relay.key       # sul relay
zt-agent keygen --out /etc/tcn/agent.key       # su ogni server target
zt-client keygen --out ~/.config/tcn/client.key  # sulla workstation / controller Ansible
```

Ogni comando crea un file nuovo con permessi `0600` (non sovrascrive mai) e stampa la chiave
pubblica e la fingerprint. Le chiavi pubbliche sono le uniche informazioni da distribuire.
I binari rifiutano di avviarsi se il file della chiave è leggibile da gruppo o altri.

## 2. Policy del relay

`/etc/tcn/policy.toml`:

```toml
[[agents]]
node = "web-01"                 # [a-z0-9-], 1..=63
public_key = "<chiave pubblica dell'agent>"

[[clients]]
name = "ansible"
public_key = "<chiave pubblica del client>"
allow = ["web-01"]              # ["*"] = tutti i nodi della policy; [] = nessuno
```

Una chiave ha un solo ruolo, un nodo un solo agent; campi sconosciuti, chiavi deboli e nomi
non validi fanno fallire l'avvio. Durante la rotazione della chiave di un agent (§8) la voce
elenca due chiavi: `public_keys = ["<nuova>", "<vecchia>"]` al posto di `public_key`.

Con più relay (§8) ognuno ha la propria chiave ma **la stessa policy**: distribuiscila a tutti
nello stesso passaggio e verifica che sia identica ovunque (per esempio confrontando
`sha256sum /etc/tcn/policy.toml` su tutti i relay). Un relay che nega l'accesso a un nodo
ferma il client, ma un relay che **non conosce** la chiave del client chiude l'handshake come
se fosse guasto, e il client passa al successivo: una chiave tolta da un solo relay resta
valida sugli altri finché non li aggiorni tutti (§7).

## 3. Client autorizzati sull'agent

`/etc/tcn/clients.toml` sul server target (stesso formato `[[clients]]`, `allow` ignorato).
È la difesa in profondità: anche se il relay venisse compromesso, l'agent accetta solo i
client elencati qui.

## 4. Avvio

```bash
zt-relay run --listen 0.0.0.0:7443 --key /etc/tcn/relay.key --policy /etc/tcn/policy.toml

zt-agent run --relay relay.example.org:7443 --relay-key <chiave pubblica del relay> \
    --node web-01 --key /etc/tcn/agent.key --authorized-clients /etc/tcn/clients.toml
```

L'agent non apre porte: si connette in uscita, si riconnette da solo con backoff
esponenziale (1 s → 60 s, con jitter) e inoltra solo a `127.0.0.1:22`
(`--ssh-target` per cambiarlo).

Con più relay si ripetono `--relay` e `--relay-key` nello stesso ordine, o si separano con
virgole (al massimo 8). L'agent resta connesso a tutti contemporaneamente; `--max-streams`
vale per l'agent intero, non per relay:

```bash
zt-agent run --relay r1.example.org:7443,r2.example.org:7443 \
    --relay-key <chiave di r1>,<chiave di r2> --node web-01 ...
```

## 5. Client: `zt-client`

`~/.config/tcn/client.toml`:

```toml
relay = "relay.example.org:7443"
relay_key = "<chiave pubblica del relay>"
key = "client.key"                  # relativo a questo file, oppure assoluto
# Con più relay, al posto di relay/relay_key (al massimo 8, provati in quest'ordine):
# [[relays]]
# address = "r1.example.org:7443"
# public_key = "<chiave di r1>"
# [[relays]]
# address = "r2.example.org:7443"
# public_key = "<chiave di r2>"

[[nodes]]
node = "web-01"
public_key = "<chiave pubblica dell'agent di web-01>"

[[nodes]]
node = "db-01"
public_key = "<chiave pubblica dell'agent di db-01>"
```

Come per `StrictModes` di OpenSSH, ogni file di trust (questo, la policy del relay, i client
autorizzati dell'agent) deve essere un file regolare, dell'utente che esegue il binario o di
root, non scrivibile da gruppo o altri, in una directory con le stesse regole; le chiavi
segrete inoltre non devono essere leggibili da gruppo o altri (`chmod 600`).

Non c'è trust-on-first-use: un nodo senza voce in `[[nodes]]` non si raggiunge, e
`zt-client` lo rifiuta prima di aprire qualsiasi connessione. Il percorso si sceglie con
`--config`, `TCN_CLIENT_CONFIG`, `$XDG_CONFIG_HOME/tcn/client.toml`, in quest'ordine;
altrimenti `~/.config/tcn/client.toml`.

### OpenSSH

```sshconfig
# ~/.ssh/config
Host *.tcn
    ProxyCommand zt-client connect --strip-suffix .tcn %h
    # opzionale: un solo tunnel per host, riusato da più sessioni
    ControlMaster auto
    ControlPath ~/.ssh/cm-%C
    ControlPersist 60s
```

`ssh web-01.tcn` apre lo stream verso il nodo `web-01`. Senza suffisso si può elencare gli
host (`Host web-01 db-01`) e usare `ProxyCommand zt-client connect %n`. Il nome deve essere
già un nome di nodo valido (`[a-z0-9-]`, 1..=63): `zt-client` non lo normalizza.
`%n` conserva le maiuscole scritte dall'utente (`ssh WEB-01` fallisce); `%h` è già in
minuscolo. Le opzioni di `zt-client` vanno prima del nome del nodo
(`zt-client --config ~/tcn.toml connect %n`): dopo il nome non si legge nessuna opzione.

TCN non sostituisce l'autenticazione SSH: l'host key del server e la chiave dell'utente si
verificano come sempre, end-to-end attraverso il tunnel. `zt-client` scrive su stdout solo i
byte SSH; errori e log (`RUST_LOG`, default `warn`) vanno su stderr, che `ssh` mostra.

### Ansible

Ansible usa `ssh`, quindi basta la configurazione sopra:

```ini
# inventory.ini
[web]
web-01.tcn
web-02.tcn
```

```ini
# ansible.cfg
[ssh_connection]
pipelining = True
```

Ogni connessione SSH di Ansible avvia un proprio `zt-client`, cioè una connessione al relay
con un solo stream. Il limite che conta è quello dell'agent: `--max-streams` (default 16)
sessioni contemporanee per nodo, da tenere sopra i `forks` di Ansible che possono puntare allo
stesso host. Con `ControlPersist` le connessioni verso lo stesso host si riusano.

## 6. Log e audit

Log su stderr, livello con `RUST_LOG` (default `info` per relay e agent, `warn` per
`zt-client`). Relay e agent accettano `--log-format json`: una riga JSON per evento, con
`timestamp`, `level`, `target` e `fields`.

Gli eventi di sicurezza hanno target `zt_audit` e un nome stabile in `fields.event_kind`:

| `event_kind` | Livello | Significato |
| :- | :- | :- |
| `agent_registered` | INFO | un agent si è registrato per il suo nodo |
| `session_established` | INFO | il relay ha aperto una sessione client → nodo |
| `connection_drained` | INFO | una sessione è terminata (con il motivo) |
| `authentication_failed` | WARN | handshake fallito, chiave sconosciuta, nome di nodo sbagliato |
| `access_denied` | WARN | un client ha chiesto un nodo che la policy non gli concede |
| `protocol_violation` | WARN | un peer ha violato il protocollo ed è stato disconnesso |
| `access_revoked` | WARN | una ricarica ha tolto a un peer il ruolo o l'accesso a un nodo |
| `e2e_session_started`, `e2e_session_ended` | INFO | (agent) sessione verso sshd aperta / chiusa, con `outcome` `closed`, `error` o `revoked` |
| `policy_reloaded`, `authorized_clients_reloaded`, `relay_keys_reloaded` | INFO | ricarica riuscita |
| `policy_reload_failed`, `authorized_clients_reload_failed`, `relay_keys_reload_failed` | ERROR | ricarica fallita: resta la configurazione precedente |
| `keys_in_use` | INFO, WARN con una chiave precedente | (relay e agent) all'avvio e a ogni ricarica: `role`, `current_fingerprint`, `previous_fingerprint` (`none` se non c'è) |
| `previous_key_still_accepted` | WARN | ogni ora, finché una chiave precedente è accettata: completa la rotazione (§8) |
| `agent_rotation_pending` | WARN | (relay) all'avvio, a ogni ricarica e ogni ora, per ogni nodo con due chiavi di agent nella policy: `node`, `fingerprints`; completa la rotazione (§8) |
| `certificate_expired` | INFO | (relay e agent) una sessione autorizzata da un certificato è stata chiusa alla sua scadenza: `peer`, `ca`, `serial` (§10) |
| `authorities_in_use` | INFO, WARN con due chiavi | (relay e agent) all'avvio e a ogni ricarica, per ogni CA pinnata: `authority`, `fingerprints`, `max_lifetime` |
| `ca_rotation_pending` | WARN | (relay e agent) all'avvio, a ogni ricarica e ogni ora, per ogni CA con due chiavi: completa la rotazione (§10.6) |
| `revocations_in_use` | INFO | (relay e agent) all'avvio e a ogni ricarica: quante voci `serials` e `keys` ha la denylist |

I dati dell'evento sono campi separati: `peer` (fingerprint), `node`, `session` (hex),
`stream`, `reason`, `rule`, secondo l'evento. Mai payload o segreti.

Con i certificati (§10) `session_established`, `e2e_session_started`, `access_denied` e
`access_revoked` hanno anche `credential` (`key` o `certificate`) e, per un certificato, `ca`
(fingerprint della CA), `serial`, `cert_name` e `not_after`. `authentication_failed` ha
`reason = certificate` (o `key_revoked`) e `cert_check` con il controllo fallito (`malformed`,
`key_mismatch`, `unknown_authority`, `bad_signature`, `serial_revoked`, `not_yet_valid`,
`expired`, `lifetime_exceeds_authority`, `role_conflict`, `node_out_of_scope`; PROTOCOL §15.4).
Dopo la verifica della firma (da `serial_revoked` in poi) riporta anche `ca`, `serial`,
`cert_name` e `not_after` del certificato rifiutato; prima (`malformed` … `bad_signature`) mai,
perché quei dati non sono firmati da nessuno.

```bash
journalctl -u zt-relay -o cat | jq 'select(.target == "zt_audit") | .fields'
```

## 7. Revoca di una chiave

1. Togli la chiave da `/etc/tcn/policy.toml` sul relay e, per un client, da
   `/etc/tcn/clients.toml` sugli agent (difesa in profondità: basta uno dei due).
2. `systemctl reload zt-relay` (e `zt-agent`). Le sessioni in corso della chiave revocata si
   chiudono subito; la tabella completa è in `docs/PROTOCOL.md` §12. Con più relay, ricarica
   **tutti** i relay: `zt-client` passa al relay successivo quando uno non riconosce la sua
   chiave, quindi un relay non aggiornato tiene valida la chiave revocata. Togliere la chiave
   da `clients.toml` sugli agent la blocca comunque, qualunque relay usi.
3. Controlla `access_revoked` nell'audit log. Se trovi `..._reload_failed`, il file non è
   valido: la configurazione precedente è ancora in vigore.

Un client con un certificato (§10) non si revoca togliendolo dai file: la sua chiave non c'è.
Si usa la denylist (§10.5).

## 8. Più relay e rotazione delle chiavi

Più relay indipendenti (stessa policy, chiavi diverse) tolgono il single point of failure:
gli agent sono connessi a tutti, e `zt-client` passa al relay successivo se il primo non
risponde o non vede il nodo. Non passa oltre una risposta della policy né un errore
end-to-end (PROTOCOL §13). Con almeno due relay, il riavvio di uno non interrompe nulla.

**Chiave di un relay** (due riavvii; con almeno due relay non interrompono nulla):

Ogni `SIGHUP` (`systemctl reload zt-relay`, anche quando serve solo per la policy) rilegge
**sia** la policy **sia** le chiavi, dai percorsi con cui il relay è stato avviato. Non spostare
quindi i file delle chiavi sotto un relay avviato senza `--previous-key`: una ricarica qualsiasi
tra lo spostamento e il riavvio attiverebbe la chiave nuova senza la vecchia, e i peer che
pinnano la vecchia verrebbero rifiutati. Lo scambio avviene in un solo passo, al riavvio, negli
argomenti dell'unità. Una ricarica che trova una chiave precedente uguale alla corrente, o un
file mancante o non valido, fallisce (`relay_keys_reload_failed`) e lascia le chiavi di prima:
negli stati intermedi qui sotto è sempre così.

1. `zt-relay keygen --out /etc/tcn/relay.next.key` (poi `chown tcn:tcn`, `0600`). Il relay
   non lo legge: nulla cambia.
2. In un drop-in dell'unità (`systemctl edit zt-relay`: una riga `ExecStart=` vuota, poi
   l'`ExecStart=` completo) avvia il relay con
   `--key /etc/tcn/relay.next.key --previous-key /etc/tcn/relay.key`, poi
   `systemctl restart zt-relay`. `keys_in_use` deve riportare come `current_fingerprint` la
   chiave nuova e come `previous_fingerprint` la vecchia; da qui le ricariche rileggono
   entrambe.
3. Aggiorna `relay_key` (o `--relay-key`) su agent e client, quando conviene. **Sostituisci**
   il pin: non aggiungere una seconda voce per lo stesso relay con l'altra chiave (per esempio
   `127.0.0.1:7443` con la vecchia e `localhost:7443` con la nuova). L'agent aprirebbe due
   sessioni verso lo stesso relay, che si scavalcano a vicenda (vale l'ultima registrazione) e
   fanno cadere le sessioni SSH del nodo.
4. Togli la precedente: `cp -p /etc/tcn/relay.next.key /etc/tcn/relay.key` (una ricarica in
   questo momento fallisce, perché le due chiavi coincidono, e lascia quelle di prima), togli
   il drop-in, `systemctl daemon-reload && systemctl restart zt-relay`, poi cancella
   `relay.next.key`. L'evento `keys_in_use` all'avvio deve riportare `previous_fingerprint`
   `none`; finché non è così, `previous_key_still_accepted` lo ricorda ogni ora.

Se un relay gira già con `--previous-key /etc/tcn/relay.prev.key`, la rotazione si fa anche
senza riavvio, ma in quest'ordine: prima `cp -p /etc/tcn/relay.key /etc/tcn/relay.prev.key`
(chiavi uguali: una ricarica fallisce e lascia quelle di prima), poi
`mv /etc/tcn/relay.next.key /etc/tcn/relay.key` (una rinomina è atomica), poi
`systemctl reload zt-relay` e controlla `relay_keys_reloaded` e `keys_in_use`.

**Chiave di un agent**:

1. `zt-agent keygen --out /etc/tcn/agent.key.new` sul nodo.
2. Nella policy di **ogni** relay: `public_keys = ["<nuova>", "<vecchia>"]` per il nodo, poi
   `systemctl reload zt-relay`.
3. Sul nodo: la vecchia chiave diventa `--previous-key`, la nuova `--key`; riavvia l'agent
   (si interrompono le sessioni SSH di quel nodo). Verso i relay usa la nuova; i client che
   pinnano la vecchia continuano a funzionare.
4. Aggiorna il pin del nodo in `[[nodes]]` dei client.
5. Togli la vecchia dalla policy e `--previous-key` dall'agent. Finché un nodo ha due chiavi
   nella policy, il relay lo segnala con `agent_rotation_pending` all'avvio, a ogni ricarica e
   ogni ora: la chiave vecchia può ancora registrarsi come quel nodo.

Una chiave **compromessa** non si ruota: si revoca (§7) senza `--previous-key` e si
aggiornano subito i pin, perché chi ha la chiave vecchia potrebbe impersonare il relay o
l'agent verso chi la pinna ancora.

## 9. Installazione con systemd

Le release (`.github/workflows/release.yml`) contengono binari statici (musl) per x86_64 e
aarch64 con attestazione di provenienza: verificali prima dell'installazione.

```bash
gh attestation verify tcn-v0.1.0-x86_64-unknown-linux-musl.tar.gz -R pietrangelo/TransportCryptoNetwork
sha256sum -c SHA256SUMS --ignore-missing
```

```bash
install -m 0755 zt-relay zt-agent zt-client /usr/local/bin/
install -m 0644 systemd/tcn.sysusers /usr/lib/sysusers.d/tcn.conf && systemd-sysusers
install -d -m 0755 -o root -g root /etc/tcn
zt-relay keygen --out /etc/tcn/relay.key && chown tcn:tcn /etc/tcn/relay.key   # o zt-agent / agent.key
install -m 0644 systemd/zt-relay.service /etc/systemd/system/   # o zt-agent.service
systemctl daemon-reload && systemctl enable --now zt-relay
```

Le unit girano come utente `tcn` senza capability, con file system in sola lettura, filtro
delle system call e indirizzi limitati a IPv4/IPv6/Unix (`systemd-analyze security`: 1.2,
«OK»). I permessi richiesti dai binari sono quelli di `StrictModes` di OpenSSH: chiave
`tcn:tcn 0600`, file di trust e directory di proprietà di root o di `tcn` e non scrivibili da
altri. Per l'agent, `/etc/tcn/agent.env` contiene `TCN_RELAY`, `TCN_RELAY_KEY` e `TCN_NODE`;
se l'IP del relay è fisso, attiva `IPAddressDeny=any` / `IPAddressAllow=` nella unit.

Le unit sono `Type=notify`: `systemctl start` ritorna quando il servizio ha caricato chiave e
file di trust e gestisce già `SIGHUP`, quindi un `systemctl reload` subito dopo è sicuro. Il
relay usa `Restart=always`, perché un segnale inatteso conta come uscita pulita.

## 10. Certificati client e CA offline

Con molti client, o con accessi che devono durare poche ore, invece di elencare ogni chiave in
ogni policy e in ogni `clients.toml` si usa una **CA offline**: relay e agent pinnano la sua
chiave pubblica, e ogni client riceve un certificato breve che lega la sua chiave a un nome, a
un elenco di nodi e a una scadenza (PROTOCOL §15). La whitelist per chiave (§2, §3) continua a
funzionare e ha la precedenza.

Regole da tenere a mente:

- la chiave segreta della CA non va **mai** su un relay, un agent o una workstation di uso
  quotidiano: chi la possiede apre sessioni verso tutti i nodi che la CA può concedere;
- un certificato scade anche **durante** le sessioni aperte (PROTOCOL §15.7): emettilo per la
  durata del lavoro, entro il `max_lifetime` della CA;
- la revoca prima della scadenza passa dalla denylist (§10.5), che deve arrivare a **tutti**
  i relay e a **tutti** gli agent.

### 10.1 Creare la CA (offline)

Su una macchina dedicata, senza rete, con disco cifrato (o da un supporto rimovibile cifrato),
con l'orologio impostato correttamente (i certificati prendono l'ora da qui):

```bash
date -u                                       # controlla l'ora UTC prima di ogni sessione di firma
zt-ca keygen --out /media/ca/ops-ca.key
# public_key  = "<chiave pubblica della CA>"
# fingerprint = SHA256:...
```

Il file è nuovo, `0600`, e ha il formato `tcn-ca-secret-v1:<hex>`, diverso da quello delle
chiavi di nodo: relay, agent e client non lo caricano, e `zt-ca` non firma con una chiave di
nodo. Fanne una copia cifrata in un luogo diverso. Il binario `zt-ca` serve solo su questa
macchina.

Una CA per ambito: per esempio `ops-ca` per gli amministratori, `deploy-ca` per la pipeline di
Ansible che tocca solo i server applicativi. L'ambito lo decide la configurazione di relay e
agent (`allow`, §10.2), non la CA: una CA rubata non concede più di quanto le è stato assegnato.

### 10.2 Pinnare la CA su relay e agent

Nella policy di **ogni** relay (`/etc/tcn/policy.toml`):

```toml
[[authorities]]
name = "ops-ca"                     # [a-z0-9-], 1..=63, distinto dalle altre CA
public_key = "<chiave pubblica della CA>"
allow = ["web-01", "web-02"]        # nodi che questa CA può concedere; ["*"] = tutti
max_lifetime = 28800                # secondi, 60..=86400 (default 8 ore)
```

Negli `clients.toml` di **ogni** agent che deve accettare i client della CA, la stessa voce
(l'agent controlla che il proprio nodo sia in `allow`; puoi distribuire lo stesso blocco
ovunque).

La denylist, inizialmente vuota, è lo **stesso file** su relay e agent
(`/etc/tcn/revoked.toml`, `root:root 0644` o `tcn`, regole di §5 sui file di trust):

```toml
serials = []    # numeri di serie dei certificati revocati (32 caratteri esadecimali)
keys = []       # chiavi pubbliche revocate, con qualsiasi credenziale
```

Avvio (o drop-in dell'unità systemd, `systemctl edit`):

```bash
zt-relay run ... --policy /etc/tcn/policy.toml --revocations /etc/tcn/revoked.toml
zt-agent run ... --authorized-clients /etc/tcn/clients.toml --revocations /etc/tcn/revoked.toml
```

Con una `[[authorities]]` e senza `--revocations` il processo non parte (e una ricarica che
aggiunge una CA fallisce): la denylist deve esistere prima che serva. Una chiave di CA non può
essere anche la chiave di un agent o di un client nello stesso file, né quella del processo
(corrente o precedente), né, in `clients.toml`, la chiave di un relay passata all'agent con
`--relay-key`: chi controlla un relay non deve poter firmare certificati per gli agent
(PROTOCOL §15.9). L'errore dice «authority key equals the relay key» (o `agent`). Lo stesso
vale alla rotazione della chiave del relay con `SIGHUP`: una chiave nuova uguale a una CA della
policy è rifiutata con `relay_keys_reload_failed` e restano le chiavi precedenti. Ogni CA è una
chiave generata con `zt-ca keygen` e usata solo per firmare.

Verifica: `authorities_in_use` nell'audit log di ogni relay e agent riporta nome e fingerprint
della CA; `revocations_in_use` il numero di voci della denylist. Come per la policy, confronta
`sha256sum /etc/tcn/policy.toml /etc/tcn/revoked.toml` su tutti i relay, e `revoked.toml` su
tutti gli agent.

### 10.3 Emettere un certificato

1. Il client genera la propria chiave, se non l'ha già (`zt-client keygen`, §1), e manda
   all'operatore della CA la **chiave pubblica**, mai il file della chiave. L'operatore
   verifica la fingerprint con il richiedente su un canale diverso (per telefono, o in un
   ticket firmato): chi sostituisce la chiave pubblica in transito ottiene il certificato.
2. Sulla macchina della CA:

   ```bash
   zt-ca sign --ca /media/ca/ops-ca.key --log /media/ca/issued.tsv \
       --subject <chiave pubblica del client> --name alice \
       --nodes web-01,web-02 --validity 8h --out alice.cert
   # serial      = 3f0c...       (32 hex)
   # subject     = SHA256:...    (fingerprint del client)
   # not_before  = 2026-11-08T09:00:00Z
   # not_after   = 2026-11-08T17:00:00Z
   ```

   - `--nodes` (elenco, al massimo 64) oppure `--all-nodes` (tutti i nodi in `allow` della
     CA). Preferisci l'elenco.
   - `--validity` accetta `s`, `m`, `h` (per esempio `90m`), al massimo 24 ore e comunque non
     oltre il `max_lifetime` della CA, altrimenti relay e agent lo rifiutano.
   - `--not-before <secondi Unix>` emette un certificato per una finestra futura (manutenzione
     programmata); di default parte da adesso.
   - `--log` è obbligatorio: `zt-ca` aggiunge una riga per ogni certificato (serie,
     fingerprint, nome, inizio, scadenza, ambito). Serve per revocare (§10.5) e per accorgersi di
     certificati che la CA non ha emesso (PROTOCOL §15.11). Conservalo con la chiave della CA.
   - `zt-ca` non sovrascrive mai `--out` e rifiuta chiavi deboli o non valide.
3. Consegna `alice.cert` al client. Non è un segreto (da solo non serve a nulla senza la chiave
   del client), ma un certificato sostituito in transito semplicemente non funziona.

### 10.4 Usare il certificato su `zt-client`

Accanto alla chiave, per esempio `~/.config/tcn/client.cert`, e in `client.toml`:

```toml
key = "client.key"
certificate = "client.cert"         # relativo a questo file, oppure assoluto
```

Il file del certificato segue le regole dei file di trust (§5). `zt-client` lo legge a ogni
invocazione e, prima di connettersi, controlla che sia per la propria chiave e non sia scaduto
(secondo l'orologio locale): in quel caso esce con un messaggio chiaro invece di provare tutti
i relay. Avvisa su stderr quando mancano meno di 15 minuti alla scadenza.

```bash
zt-client certificate     # nome, nodi, CA, numero di serie, validità del certificato configurato
```

**Rinnovo**: si ripete §10.3 e si sostituisce il file in modo atomico
(`mv alice.cert.new ~/.config/tcn/client.cert`). Le nuove invocazioni usano il certificato
nuovo; le sessioni aperte restano legate a quello con cui sono nate e si chiudono alla sua
scadenza. Con `ControlPersist` il master SSH è una di queste: dopo il rinnovo chiudilo
(`ssh -O exit web-01.tcn`) per non perderlo a metà di un lavoro.

**Ansible**: un playbook che dura più del certificato viene interrotto alla scadenza. Emetti
il certificato per la durata prevista (entro `max_lifetime`) o rinnovalo prima del lancio.

Se il client è ancora anche nella whitelist (§2, §3), vale la whitelist e il certificato è solo
verificato: un certificato non valido fa comunque rifiutare il client. Per passare del tutto ai
certificati togli la sua voce da policy e `clients.toml` e ricarica: la sua connessione cade una
volta e si riapre con il certificato.

### 10.5 Revoca prima della scadenza

Per un certificato (per esempio un portatile perso con chiave e certificato):

1. Trova il numero di serie nel registro della CA (`issued.tsv`) o con
   `zt-ca inspect --cert alice.cert`, che stampa anche la riga da incollare.
2. Aggiungilo a `serials` in `/etc/tcn/revoked.toml`. Per revocare **tutto** ciò che una chiave
   può fare (tutti i suoi certificati, di qualsiasi CA, e la sua eventuale voce nella
   whitelist) aggiungi invece la sua chiave pubblica a `keys`: è la scelta giusta quando la
   chiave è compromessa.
3. Distribuisci il file a **tutti** i relay e a **tutti** gli agent e ricarica
   (`systemctl reload zt-relay`, `systemctl reload zt-agent`). Le sessioni in corso del
   certificato si chiudono subito (PROTOCOL §12).
4. Controlla `access_revoked` e `revocations_in_use` con il nuovo numero di voci. Un
   `policy_reload_failed` o `authorized_clients_reload_failed` vuol dire che la **revoca non è
   in vigore** su quel nodo (resta la configurazione precedente): correggi il file e ricarica.

Anche con un relay non aggiornato, gli agent aggiornati bloccano il certificato; viceversa un
agent non aggiornato è protetto solo dai relay. Aggiornali tutti.

**Potatura**: una voce di `serials` si può togliere quando il certificato è scaduto da più di
qualche minuto (la scadenza chiude anche le sessioni, PROTOCOL §15.7); la data è nel registro
della CA. Una voce di `keys` resta finché quella chiave non è sostituita ovunque.

**Emergenza** (una CA da fermare subito, per esempio perché la denylist non basta o la chiave
della CA è esposta): togli la voce `[[authorities]]` (o la sola chiave) da relay e agent e
ricarica. Tutti i certificati di quella CA cadono, anche nelle sessioni aperte.

### 10.6 Rotazione della CA

Una rotazione programmata, senza interruzioni:

1. `zt-ca keygen --out /media/ca/ops-ca.next.key` sulla macchina della CA.
2. Su tutti i relay e gli agent: `public_keys = ["<nuova>", "<vecchia>"]` al posto di
   `public_key` nella voce della CA, poi ricarica. `authorities_in_use` mostra le due
   fingerprint, `ca_rotation_pending` lo ricorda ogni ora.
3. Da qui firma solo con la nuova chiave.
4. Quando è passato almeno `max_lifetime` dall'ultimo certificato firmato con la vecchia (vedi
   il registro), nessun suo certificato è più valido: togli la vecchia (`public_key =
   "<nuova>"`) ovunque e ricarica. Archivia o distruggi la chiave vecchia.

**CA compromessa**: non si ruota. Togli subito la sua chiave da relay e agent (§10.5,
emergenza), crea una CA nuova, pinnala, riemetti i certificati necessari. Poi confronta i numeri
di serie negli audit log (`session_established`, `e2e_session_started`) con il registro della
CA: una serie che non compare nel registro è un certificato forgiato.

### 10.7 Orologi

Relay e agent decidono validità e scadenza con il proprio orologio di sistema, con 2 minuti di
tolleranza solo sull'inizio della validità. Tienili sincronizzati, preferibilmente con NTS
(`chrony` con `nts`): chi sposta all'indietro l'orologio di un relay e di un agent rende di
nuovo validi certificati scaduti. La macchina della CA, offline, va regolata a mano prima di
ogni sessione di firma; `zt-ca sign` stampa le date in UTC proprio per controllarle.
