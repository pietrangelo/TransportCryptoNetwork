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
nello stesso passaggio. Il client non aggira un relay che lo rifiuta cercandone uno più
permissivo, quindi una policy disallineata si vede come un accesso negato.

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
| `policy_reloaded`, `authorized_clients_reloaded` | INFO | ricarica riuscita |
| `policy_reload_failed`, `authorized_clients_reload_failed` | ERROR | ricarica fallita: resta la configurazione precedente |

I dati dell'evento sono campi separati: `peer` (fingerprint), `node`, `session` (hex),
`stream`, `reason`, `rule`, secondo l'evento. Mai payload o segreti.

```bash
journalctl -u zt-relay -o cat | jq 'select(.target == "zt_audit") | .fields'
```

## 7. Revoca di una chiave

1. Togli la chiave da `/etc/tcn/policy.toml` sul relay e, per un client, da
   `/etc/tcn/clients.toml` sugli agent (difesa in profondità: basta uno dei due).
2. `systemctl reload zt-relay` (e `zt-agent`). Le sessioni in corso della chiave revocata si
   chiudono subito; la tabella completa è in `docs/PROTOCOL.md` §12.
3. Controlla `access_revoked` nell'audit log. Se trovi `..._reload_failed`, il file non è
   valido: la configurazione precedente è ancora in vigore.

## 8. Più relay e rotazione delle chiavi

Più relay indipendenti (stessa policy, chiavi diverse) tolgono il single point of failure:
gli agent sono connessi a tutti, e `zt-client` passa al relay successivo se il primo non
risponde o non vede il nodo. Non passa oltre una risposta della policy né un errore
end-to-end (PROTOCOL §13). Con almeno due relay, il riavvio di uno non interrompe nulla.

**Chiave di un relay** (senza riavvio):

1. `zt-relay keygen --out /etc/tcn/relay.key.new`, poi sposta la chiave attuale in
   `/etc/tcn/relay.prev.key` e la nuova in `/etc/tcn/relay.key` (entrambe `tcn:tcn 0600`).
2. Se il relay non ha ancora `--previous-key /etc/tcn/relay.prev.key`, aggiungilo
   all'unità (un riavvio, la prima volta). Poi `systemctl reload zt-relay`: dall'evento
   `relay_keys_reloaded` vale la chiave nuova e la vecchia resta accettata.
3. Aggiorna `relay_key` (o `--relay-key`) su agent e client, quando conviene.
4. Togli la precedente: un file non valido alla ricarica lascia le chiavi di prima
   (`relay_keys_reload_failed`), quindi la si toglie riavviando senza `--previous-key`.

**Chiave di un agent**:

1. `zt-agent keygen --out /etc/tcn/agent.key.new` sul nodo.
2. Nella policy di **ogni** relay: `public_keys = ["<nuova>", "<vecchia>"]` per il nodo, poi
   `systemctl reload zt-relay`.
3. Sul nodo: la vecchia chiave diventa `--previous-key`, la nuova `--key`; riavvia l'agent
   (si interrompono le sessioni SSH di quel nodo). Verso i relay usa la nuova; i client che
   pinnano la vecchia continuano a funzionare.
4. Aggiorna il pin del nodo in `[[nodes]]` dei client.
5. Togli la vecchia dalla policy e `--previous-key` dall'agent.

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
