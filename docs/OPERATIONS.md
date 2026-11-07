# Messa in esercizio (Fase 2)

Questa guida porta in funzione relay e agent. Il collegamento di `zt-client` a OpenSSH arriva
nella Fase 3.

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

## 5. Log e audit

Log strutturati su stderr; livello con `RUST_LOG` (default `info`). Gli eventi di sicurezza
hanno target `zt_audit`: registrazioni, sessioni aperte e chiuse, accessi negati,
autenticazioni fallite, violazioni di protocollo. Contengono fingerprint, nomi di nodo e
session id, mai payload o segreti.

```bash
RUST_LOG=zt_audit=info,warn zt-relay run ...
```
