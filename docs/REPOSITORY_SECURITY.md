# Sicurezza del repository GitHub

Il codice di TCN finisce come root-of-trust sui server di una flotta: chi riesce a far entrare
un commit in `main`, o a pubblicare un binario a nome del progetto, ottiene SSH ovunque. Questo
documento descrive le difese del repository, quelle già nel codice e quelle che vanno attivate
dalle impostazioni di GitHub (solo il proprietario può farlo).

## Modello di minaccia

| Minaccia | Difesa |
| --- | --- |
| Push diretto o force-push su `main`, anche da un token rubato | ruleset `main`: niente push diretti, niente force-push né cancellazione, solo PR |
| PR che passa senza test o fuzzing | check obbligatori, ramo aggiornato prima del merge |
| Commit con autore falsificato | commit firmati obbligatori su `main`, *vigilant mode* sull'account |
| Dipendenza compromessa (crates.io) | `cargo-deny`, `Cargo.lock` con `--locked`, Dependabot con *cooldown* di 7 giorni, CODEOWNERS su `Cargo.lock` |
| Action compromessa o tag di un'action spostato | action fissate a un commit SHA, zizmor in CI, Dependabot per gli aggiornamenti, whitelist delle action ammesse |
| Script injection nei workflow | nessuna espressione `${{ }}` dentro `run:`, verificato da zizmor |
| Token di CI usato per scrivere sul repository | `permissions: contents: read` come default, credenziali di checkout non persistite |
| Release da codice non revisionato | il tag deve puntare a un commit su `main` (`verify-tag`), solo l'admin crea tag `v*` |
| Tag di release spostato dopo la pubblicazione | ruleset `release-tags-immutable`, release immutabili |
| Firma o pubblicazione non autorizzata | job `attest` e `release` nell'environment protetto `release`, con approvazione manuale |
| Segreti nel repository | secret scanning e push protection; la configurazione di Claude è cifrata con `cc` (`cc check` in CI) |
| Vulnerabilità divulgata in pubblico | `SECURITY.md` e segnalazione privata di GitHub |

## Già nel repository

- `.github/workflows/*`: permessi minimi, action fissate a SHA, `persist-credentials: false`,
  timeout su ogni job, `concurrency`, input della matrice passati via `env`.
- `ci.yml` → job `zizmor`: analisi statica dei workflow, fallisce su ogni finding.
- `release.yml`: `verify-tag` (tag su `main`, nome semver), `attest` e `release`
  nell'environment `release`.
- `.github/dependabot.yml`: Cargo (`/` e `/fuzz`) e GitHub Actions, settimanale, cooldown 7 giorni.
- `.github/CODEOWNERS`, `SECURITY.md`.
- `.github/rulesets/*.json`: le regole di branch e tag, pronte da importare.

## Da attivare nelle impostazioni (proprietario)

L'ordine conta: il ruleset `main` richiede check con i nomi introdotti da questa modifica, quindi
va attivato **dopo** il merge della PR che li aggiunge.

### 1. Account

1. [Autenticazione a due fattori](https://github.com/settings/security) con passkey o chiave
   hardware, se non è già attiva.
2. [Chiave di firma](https://github.com/settings/keys): aggiungi una chiave SSH come
   *Signing key* (o GPG) e configura git in locale:
   `git config --global gpg.format ssh`,
   `git config --global user.signingkey ~/.ssh/id_ed25519.pub`,
   `git config --global commit.gpgsign true`, `git config --global tag.gpgsign true`.
3. Nella stessa pagina attiva **Flag unsigned commits as unverified** (*vigilant mode*).

### 2. Settings → General

- *Pull Requests*: lascia solo **Allow squash merging**; togli merge commit e rebase.
  Attiva **Always suggest updating pull request branches** e
  **Automatically delete head branches**.
- *Features*: disattiva **Wikis** e **Projects** se non li usi (meno superficie da sorvegliare).
- *Releases*: attiva **Enable release immutability**, così asset e tag di una release
  pubblicata non si possono più cambiare.

### 3. Settings → Rules → Rulesets

Per ogni file, **New ruleset → Import a ruleset** e scegli il JSON:

1. `.github/rulesets/release-tags-immutable.json`: nessuno, nemmeno l'admin, può spostare
   o cancellare un tag `v*`.
2. `.github/rulesets/release-tags-create.json`: solo l'admin crea tag `v*`.
3. `.github/rulesets/main.json` (**dopo il merge**): PR obbligatoria con merge squash,
   conversazioni risolte, check obbligatori con ramo aggiornato, storia lineare, commit
   firmati, niente force-push né cancellazione. Nessun bypass, nemmeno per l'admin.

In alternativa, da un terminale con `gh` autenticato come proprietario:

```bash
for f in release-tags-immutable release-tags-create main; do
  gh api -X POST repos/pietrangelo/TransportCryptoNetwork/rulesets \
    --input ".github/rulesets/$f.json"
done
```

Nota: con un solo maintainer le approvazioni richieste sono 0, perché GitHub non lascia
approvare le proprie PR. Le altre regole valgono comunque: niente arriva su `main` senza PR e
CI verde. Quando entra un secondo maintainer, porta `required_approving_review_count` a 1 e
`require_code_owner_review` a `true`.

### 4. Settings → Environments → New environment `release`

- **Required reviewers**: `pietrangelo`.
- **Deployment branches and tags** → *Selected branches and tags* → aggiungi la regola di
  tipo *Tag* con il pattern `v*`.
- Non servono segreti: la firma usa il token OIDC di GitHub (Sigstore). Se in futuro ne
  servisse uno (per esempio per un registry), va messo qui e non fra i segreti del repository.

### 5. Settings → Actions → General

- *Actions permissions*: **Allow pietrangelo, and select non-pietrangelo, actions and
  reusable workflows**, con **Allow actions created by GitHub** e questa lista:
  `dtolnay/rust-toolchain@*, Swatinem/rust-cache@*, EmbarkStudios/cargo-deny-action@*,
  zizmorcore/zizmor-action@*`.
- Attiva **Require actions to be pinned to a full-length commit SHA**.
- *Fork pull request workflows*: **Require approval for all external contributors**.
- *Workflow permissions*: **Read repository contents and packages permissions** e
  **disattiva** *Allow GitHub Actions to create and approve pull requests*.

### 6. Settings → Advanced Security (Code security)

- **Private vulnerability reporting**: Enable (oggi è spento; `SECURITY.md` ci rimanda).
- **Dependency graph**, **Dependabot alerts**, **Dependabot security updates**: Enable.
- **Secret Protection** / **Secret scanning** e **Push protection**: Enable.
- **Code scanning → CodeQL analysis → Set up → Default**: linguaggi Rust e GitHub Actions.

## Verifica

Dopo aver applicato tutto:

- un `git push origin HEAD:main` deve essere rifiutato;
- un `git push --delete origin vX.Y.Z` deve essere rifiutato;
- una PR con un check rosso non deve avere il pulsante di merge attivo;
- la run di `release` su un nuovo tag deve fermarsi su *Waiting for review* prima di `attest`.
