# Politica di sicurezza

TCN è un sistema di accesso remoto: una vulnerabilità può aprire SSH su un'intera flotta di
server. Le segnalazioni sono benvenute e vengono trattate con priorità.

> **English:** please report vulnerabilities privately through GitHub's
> [private vulnerability reporting](https://github.com/pietrangelo/TransportCryptoNetwork/security/advisories/new).
> Do not open a public issue. Reports in English or Italian are both fine.

## Come segnalare

Usa la **segnalazione privata di GitHub**:
[Security → Report a vulnerability](https://github.com/pietrangelo/TransportCryptoNetwork/security/advisories/new).

**Non** aprire una issue pubblica, una PR o una discussione per un problema di sicurezza.

Una buona segnalazione contiene:

- la versione (tag o commit) e il binario coinvolto (`zt-agent`, `zt-relay`, `zt-client`);
- il modello d'attacco: chi è l'attaccante (rete, relay compromesso, client autorizzato,
  utente locale) e che cosa ottiene;
- i passi per riprodurre o un proof of concept minimale;
- l'impatto stimato.

Non includere chiavi private, token o dati reali di produzione.

## Che cosa aspettarsi

| Fase | Tempo indicativo |
| --- | --- |
| Conferma di ricezione | entro 3 giorni lavorativi |
| Prima valutazione (validità, gravità) | entro 10 giorni lavorativi |
| Correzione dei problemi critici | il prima possibile, di norma entro 30 giorni |

La correzione viene pubblicata con un GitHub Security Advisory (con CVE quando serve), e chi
ha segnalato viene citato, se lo desidera. Chiediamo di non divulgare il problema finché la
correzione non è disponibile o finché non sono passati 90 giorni dalla segnalazione.

## Versioni supportate

Il progetto è prima della 1.0: viene corretta solo l'ultima release e il ramo `main`.

## Ambito

Rientrano nell'ambito, fra l'altro:

- bypass dell'autenticazione mutua o delle policy di autorizzazione del relay e dell'agent;
- un relay che riesce a leggere, alterare o reindirizzare il traffico end-to-end;
- crash, panic, esaurimento di memoria o CPU provocati da input remoto;
- segreti o payload SSH che finiscono nei log;
- debolezze del processo di rilascio (binari, attestazioni SLSA, workflow GitHub Actions).

Il modello di minaccia e le difese sono descritti in `docs/PROTOCOL.md` e nelle review in
`docs/adversary/`.

## Verificare un binario rilasciato

Ogni archivio di release ha un'attestazione di provenienza SLSA firmata da GitHub Actions:

```bash
sha256sum -c SHA256SUMS
gh attestation verify tcn-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz \
  --repo pietrangelo/TransportCryptoNetwork
```
