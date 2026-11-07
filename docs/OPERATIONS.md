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
non validi fanno fallire l'avvio.

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

## 5. Client: `zt-client`

`~/.config/tcn/client.toml` (permessi `0600` o `0644`, mai scrivibile da gruppo o altri):

```toml
relay = "relay.example.org:7443"
relay_key = "<chiave pubblica del relay>"
key = "client.key"                  # relativo a questo file, oppure assoluto

[[nodes]]
node = "web-01"
public_key = "<chiave pubblica dell'agent di web-01>"

[[nodes]]
node = "db-01"
public_key = "<chiave pubblica dell'agent di db-01>"
```

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

Log strutturati su stderr; livello con `RUST_LOG` (default `info` per relay e agent, `warn`
per `zt-client`). Gli eventi di sicurezza
hanno target `zt_audit`: registrazioni, sessioni aperte e chiuse, accessi negati,
autenticazioni fallite, violazioni di protocollo. Contengono fingerprint, nomi di nodo e
session id, mai payload o segreti.

```bash
RUST_LOG=zt_audit=info,warn zt-relay run ...
```
