# Fase 6: certificati client brevi da una CA offline (piano di implementazione)

Piano per gli agenti di test e di implementazione. La specifica normativa è
`docs/PROTOCOL.md` §15 (formato, trasporto, ordine dei controlli, scadenza, revoca, rotazione);
il runbook è `docs/OPERATIONS.md` §10. In caso di dubbio vale la specifica; se un test la
smentisce si corregge la specifica, non il test (come per il framing).

Il piano segue l'Adversarial TDD (`docs/METHODOLOGY.md`): per ogni passo i test **RED** di
specifica e d'attacco si committano **prima** del codice, poi GREEN, REFACTOR, e alla fine
l'adversary review `docs/adversary/0006-client-certs.md`.

## 1. Decisioni in breve

| Tema | Decisione | Dove |
| :- | :- | :- |
| Formato | binario canonico, layout fisso, `TCNC` v1, Ed25519, 170..=4 328 byte, ≤ 64 nodi | PROTOCOL §15.1 |
| Firma | Ed25519 pura su `"TCN client certificate v1\0" ‖ TBS`, `verify_strict`, chiave pinnata uguale byte per byte | §15.2 |
| Trasporto | payload del messaggio 1 Noise IK, su canale esterno **e** end-to-end; messaggio 2 sempre vuoto; nessun frame nuovo | §15.3 |
| Binding | fingerprint di `subject_key` = fingerprint della chiave statica Noise, **prima** della firma | §15.4 |
| Precedenza | la whitelist per chiave vince; certificato presentato sempre verificato; nessuna unione di permessi | §15.5 |
| Ambito | `nodi della policy ∩ ambito(cert) ∩ allow(CA)`; l'agent controlla il proprio nodo | §15.5 |
| Tempo | `not_before − 120 s ≤ now < not_after`; durata ≤ `max_lifetime` della CA ≤ 24 h | §15.6 |
| Scadenza in sessione | la sessione si chiude (`Close Unauthorized`, `certificate_expired`) | §15.7 |
| Revoca | file `revoked.toml` comune a relay e agent (`serials`, `keys`), ricaricato insieme alla policy; obbligatorio con una CA | §15.8 |
| Rotazione CA | 1 o 2 chiavi per `[[authorities]]`, `ca_rotation_pending` | §15.9 |

## 2. Dipendenze

Nessun crate nuovo: `cargo deny` resta invariato (`deny.toml` non cambia).

| Esigenza | Scelta | Motivo |
| :- | :- | :- |
| firma e verifica Ed25519 | `ed25519-dalek` 3.0.0, già in `zt-crypto` | `SigningKey::try_sign`, `VerifyingKey::verify_strict`, `is_weak`, `to_edwards().compress()` per la canonicità; feature `zeroize` già attiva |
| casualità del numero di serie | `getrandom` 0.4.3, già usato | |
| testo dei file | `hex` 0.4.3, già usato | niente `base64`: un crate in meno, e le regole di redazione esistenti (`redact_hex`) coprono già il contenuto |
| durate CLI (`8h`) | parser di 10 righe in `zt-ca` | niente `humantime`; accetta solo `<n>s`, `<n>m`, `<n>h` |
| registro delle emissioni | riga TSV scritta a mano | niente `serde_json` in produzione; tutti i campi hanno alfabeti ristretti |

`zt-domain` resta senza crittografia: decodifica, invarianti e decisioni pure (tempo passato
come parametro). La firma, la canonicità dei punti e il binding stanno in `zt-crypto`.

## 3. Tipi e funzioni

Le firme sono indicative nei dettagli (nomi dei campi privati, `&`/`Arc`), vincolanti nella
sostanza: chi le cambia aggiorna questo file.

### 3.1 `zt-domain`

`src/limits.rs` (con `const` assertion: `NOISE_MSG1_OVERHEAD + MAX_CERT_LEN + NOISE_TAG_LEN`
≤ `MAX_PAYLOAD_LEN` e ≤ `NOISE_MAX_MESSAGE_LEN`; `MIN_CERT_LEN ≤ MAX_CERT_LEN`):

```rust
pub const MAX_CERT_LEN: usize = 4_328;
pub const MIN_CERT_LEN: usize = 170;
pub const MAX_CERT_NODES: usize = 64;
pub const MAX_CERT_LIFETIME_SECS: u64 = 86_400;
pub const CERT_CLOCK_SKEW_SECS: u64 = 120;
pub const MIN_AUTHORITY_LIFETIME_SECS: u64 = 60;
pub const DEFAULT_AUTHORITY_LIFETIME_SECS: u64 = 28_800;
pub const MAX_AUTHORITIES: usize = 16;
pub const MAX_AUTHORITY_KEYS: usize = 2;
pub const MAX_REVOKED_SERIALS: usize = 16_384;
pub const MAX_REVOKED_KEYS: usize = 4_096;
pub const NOISE_MSG1_OVERHEAD: usize = 96; // e (32) + s cifrata (32 + 16) + tag del payload (16)
```

`src/cert.rs` (nuovo):

```rust
pub const CERT_MAGIC: [u8; 4] = *b"TCNC";
pub const CERT_VERSION: u8 = 0x01;
pub const CERT_SIG_ED25519: u8 = 0x01;
pub const CERT_SIGNATURE_LEN: usize = 64;
pub const CERT_SIGNATURE_CONTEXT: &[u8] = b"TCN client certificate v1\0";

pub struct UnixTime(u64);                    // Copy, Ord; from_secs, as_secs, checked/saturating ops
pub struct CertSerial([u8; 16]);             // Copy, Eq, Hash; TryFrom<[u8;16]> rifiuta lo zero; Display hex
pub struct CertKey([u8; 32]);                // 32 byte Ed25519 non ancora validati come punto (lo fa zt-crypto)
pub enum CertScope { All, Only(BTreeSet<NodeId>) } // Only: 1..=MAX_CERT_NODES

pub struct CertBody { /* campi privati */ }
impl CertBody {
    pub fn new(ca_key: CertKey, subject_key: CertKey, serial: CertSerial,
               not_before: UnixTime, not_after: UnixTime,
               name: NodeId, scope: CertScope) -> Result<Self, CertFormatError>;
    pub fn encode_tbs(&self) -> Vec<u8>;     // infallibile: un CertBody esistente è valido
    // getter: ca_key(), subject_key(), serial(), not_before(), not_after(), name(), scope(), lifetime_secs()
}

pub struct ParsedCert<'a> { pub body: CertBody, pub tbs: &'a [u8], pub signature: &'a [u8; 64] }
pub fn decode_certificate(bytes: &[u8]) -> Result<ParsedCert<'_>, CertFormatError>;

#[non_exhaustive] pub enum CertFormatError { /* solo metadati: Length{len}, Magic, Version(u8),
    Algorithm(u8), SerialZero, Validity, Lifetime{secs}, Name(DomainError), Scope(u8),
    NodeCount(u8), NodeOrder{index}, Truncated{at}, Trailing{extra} */ }

#[derive(Clone, Copy)] #[non_exhaustive]
pub enum CertRejection { Malformed, KeyMismatch, UnknownAuthority, BadSignature,
    SerialRevoked, NotYetValid, Expired, LifetimeExceedsAuthority, RoleConflict, NodeOutOfScope }
impl CertRejection { pub const fn as_str(self) -> &'static str; } // valori di `cert_check`

/// Solo i dati di un certificato la cui firma è già stata verificata (zt-crypto).
pub struct CertClaims { /* ca: Fingerprint, ca_key: CertKey, subject: Fingerprint, serial,
                          name, scope, not_before, not_after */ }
impl CertClaims {
    pub fn from_verified(body: CertBody, ca: Fingerprint, subject: Fingerprint) -> Self;
    pub fn reference(&self) -> CertRef;
}
#[derive(Clone)] pub struct CertRef { pub ca: Fingerprint, pub serial: CertSerial,
                                      pub name: NodeId, pub not_after: UnixTime }
```

`src/trust.rs` (nuovo):

```rust
pub struct TrustedCaKey { pub key: CertKey, pub fingerprint: Fingerprint }
pub struct Authority { /* name, keys: Vec<TrustedCaKey> (1..=2), allowed: AllowedNodes, max_lifetime_secs */ }
pub struct Revocations { /* serials: HashSet<CertSerial>, keys: HashSet<Fingerprint> */ }
impl Revocations {
    pub fn new(serials: impl IntoIterator<Item = CertSerial>,
               keys: impl IntoIterator<Item = Fingerprint>) -> Result<Self, DomainError>; // limiti
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool;
    pub fn is_serial_revoked(&self, serial: &CertSerial) -> bool;
    pub fn counts(&self) -> (usize, usize);
}
pub struct CertTrust { /* authorities, indice CertKey → authority, revocations: Option<Revocations> */ }
impl CertTrust {
    pub fn add_authority(&mut self, name: NodeId, keys: &[TrustedCaKey],
                         allowed: AllowedNodes, max_lifetime_secs: u64) -> Result<(), DomainError>;
    pub fn set_revocations(&mut self, revocations: Revocations);
    pub fn is_empty(&self) -> bool;                       // nessuna CA
    pub fn needs_revocations(&self) -> bool;              // CA presenti e denylist assente
    pub fn authority_for_key(&self, key: &CertKey) -> Option<&Authority>;
    pub fn ca_fingerprints(&self) -> impl Iterator<Item = Fingerprint> + '_;
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool;
    /// Passi 5 e 7–10 di PROTOCOL §15.4, nell'ordine.
    pub fn check(&self, claims: &CertClaims, now: UnixTime) -> Result<&Authority, CertRejection>;
    pub fn rotations_pending(&self) -> impl Iterator<Item = (&NodeId, &[TrustedCaKey])>;
}
impl Authority { pub fn permits(&self, claims: &CertClaims, node: &NodeId) -> bool; /* ambito(cert) ∩ allow */ }
```

`src/policy.rs` (estensione di `AccessPolicy`, relay):

```rust
pub enum ClientCredential { Key, Certificate(Arc<CertClaims>) }
pub enum Admission<'a> { Agent { node: &'a NodeId }, Client { credential: ClientCredential } }
impl AccessPolicy {
    pub fn set_cert_trust(&mut self, trust: CertTrust) -> Result<(), DomainError>; // chiavi di CA ≠ chiavi di peer
    pub fn cert_trust(&self) -> &CertTrust;
    /// Passi 1, 2, 5, 7–11 di PROTOCOL §15.4 e la tabella di §15.5.
    pub fn admit(&self, peer: &Fingerprint, cert: Option<&Arc<CertClaims>>, now: UnixTime)
        -> Result<Admission<'_>, AuthFailureReason>;
    /// `may_open` generalizzato: nodi della policy ∩ ambito effettivo.
    pub fn may_open_with(&self, peer: &Fingerprint, credential: &ClientCredential,
                         target: &NodeId, now: UnixTime) -> bool;
}
```

`add_agent`, `add_agent_keys`, `add_client` controllano anche le fingerprint delle CA già
presenti (ordine d'inserimento irrilevante). `may_open` resta per i client della whitelist.

`src/clients.rs` (nuovo, lato agent; sostituisce `HashSet<Fingerprint>`):

```rust
pub struct AuthorizedClients { /* keys: HashSet<Fingerprint>, trust: CertTrust */ }
impl AuthorizedClients {
    pub fn new() -> Self;
    pub fn add_client(&mut self, key: Fingerprint) -> Result<(), DomainError>;
    pub fn set_cert_trust(&mut self, trust: CertTrust) -> Result<(), DomainError>;
    pub fn cert_trust(&self) -> &CertTrust;
    pub fn contains_key(&self, key: &Fingerprint) -> bool;
    /// Passi 1, 2, 5, 7–10 e 12 di PROTOCOL §15.4.
    pub fn admit(&self, peer: &Fingerprint, cert: Option<&Arc<CertClaims>>, node: &NodeId,
                 now: UnixTime) -> Result<ClientCredential, AuthFailureReason>;
    /// Per la revoca a caldo e la scadenza: la credenziale vale ancora?
    pub fn still_admits(&self, peer: &Fingerprint, credential: &ClientCredential,
                        node: &NodeId, now: UnixTime) -> bool;
}
```

`src/events.rs`:

- `AuthFailureReason::KeyRevoked`, `AuthFailureReason::Certificate(CertRejection)`;
- `DomainEvent::SessionEstablished` e `DomainEvent::AccessRevoked` e `DomainEvent::AccessDenied`
  ricevono `certificate: Option<CertRef>`;
- nuovo `DomainEvent::CertificateExpired { peer: Fingerprint, certificate: CertRef }`,
  `kind() == "certificate_expired"`, `is_security_alert() == false`.

`src/error.rs`: `DomainError::{AuthorityKeys(NodeId), DuplicateAuthority(NodeId),
AuthorityLifetime { secs }, TooManyAuthorities, TooManyRevocations { what }}`; i conflitti di
chiave riusano `DuplicatePeer`.

### 3.2 `zt-crypto`

`src/noise.rs`:

```rust
pub const MAX_HANDSHAKE_PAYLOAD_LEN: usize = zt_domain::limits::MAX_CERT_LEN;
pub fn initiate_with_payload(local: &Identity, remote: &PublicKey, channel: Channel,
                             payload: &[u8]) -> Result<(Vec<u8>, AwaitingResponse), CryptoError>;
// `initiate` = `initiate_with_payload(.., &[])`. Oltre il massimo: CryptoError::MessageTooLarge.
impl AuthorizationPending { pub fn payload(&self) -> &[u8]; }
// `respond`/`respond_any`: payload oltre MAX_HANDSHAKE_PAYLOAD_LEN → CryptoError::Handshake
// (nessun oracolo), conservato in un Vec dimensionato sul payload.
// `AwaitingResponse::complete`: payload del messaggio 2 non vuoto → CryptoError::Handshake.
```

`src/identity.rs`: `PublicKey::from_canonical_bytes(&[u8; 32]) -> Result<PublicKey, CryptoError>`
(punto valido, ricodifica identica, non debole), `PublicKey::to_bytes() -> [u8; 32]`.

`src/cert.rs` (nuovo):

```rust
/// Chiave segreta di una CA. Niente Clone, azzerata al drop, Debug redatto.
pub struct CaSigningKey { /* SigningKey */ }
impl CaSigningKey {
    pub const FILE_PREFIX: &'static str = "tcn-ca-secret-v1:";
    pub fn generate() -> Result<Self, CryptoError>;
    pub fn from_secret_text(text: &str) -> Result<Self, CryptoError>;  // richiede il prefisso
    pub fn to_secret_text(&self) -> Zeroizing<String>;
    pub fn public_key(&self) -> PublicKey;
}
pub const CERT_FILE_PREFIX: &str = "tcn-client-cert-v1:";
pub fn trusted_ca_key(key: &PublicKey) -> TrustedCaKey;
pub fn cert_key(key: &PublicKey) -> CertKey;
/// Firma `body`; errore se `body.ca_key()` non è la chiave pubblica di `ca`.
pub fn sign_certificate(ca: &CaSigningKey, body: &CertBody) -> Result<Vec<u8>, CryptoError>;
/// Passi 3–6 di PROTOCOL §15.4, nell'ordine; il resto lo decide il dominio.
pub fn verify_certificate(bytes: &[u8], peer: &Fingerprint, trust: &CertTrust)
    -> Result<CertClaims, CertRejection>;
pub fn encode_certificate_text(bytes: &[u8]) -> String;
pub fn decode_certificate_text(text: &str) -> Result<Vec<u8>, CertFormatError>;
```

### 3.3 `zt-application` (relay core)

```rust
pub struct Now { pub instant: Instant, pub unix: UnixTime }
impl<S: SessionIds> RelayCore<S> { pub fn handle(&mut self, input: Input, now: Now) -> Vec<Output>; }
pub enum Input {
    Connected { conn: ConnId, peer: Fingerprint, certificate: Option<Arc<CertClaims>> },
    // Received, Disconnected, Tick, PolicyUpdated invariati
}
```

- `Role::Client { credential: ClientCredential }`; `on_connected` usa `policy.admit`.
- `on_open` usa `may_open_with(.., now.unix)`; `AccessDenied` e `SessionEstablished` portano
  `certificate`.
- `on_tick`: per ogni connessione con `ClientCredential::Certificate` e `now.unix >= not_after`:
  `Close Unauthorized` su ogni stream a entrambi i lati, `ConnectionDrained Unauthorized` per
  sessione, `CertificateExpired`, teardown, `Output::Close`.
- `on_policy`: per i client, `still admitted` con la credenziale salvata (CA ancora pinnata
  per chiave, denylist, durata, ruolo); altrimenti `AccessRevoked { target: None, certificate }`
  e chiusura; restringimento dell'ambito stream per stream come oggi.

Effetto sui test esistenti: `Input::Connected` riceve `certificate: None`, `handle` riceve
`Now`; gli helper `Harness` di `relay_core.rs` e `revocation.rs` e il target `relay_core` si
adattano in un solo punto.

### 3.4 `zt-net`

- `lib.rs`: `pub fn unix_now() -> UnixTime` (`SystemTime`, prima del 1970 → 0).
- `channel.rs`: `connect_with_payload(io, local, remote, channel, payload, timeouts)`
  (`connect` delega con `&[]`); `Pending::payload(&self) -> &[u8]`.
- `config.rs`:
  - `PolicyFile` + `authorities: Vec<AuthorityEntry>` (`name`, `public_key` | `public_keys`,
    `allow`, `max_lifetime: Option<u64>`; `deny_unknown_fields`); stesso blocco in
    `clients.toml`;
  - `RevocationsFile { serials: Vec<String>, keys: Vec<String> }`;
  - `ClientFile` + `certificate: Option<String>`; `ClientSettings` + `certificate: Option<PathBuf>`;
  - `pub fn parse_revocations(origin, text) -> Result<Revocations, ConfigError>`;
  - `pub fn load_relay_policy(policy: &Path, revocations: Option<&Path>) -> Result<AccessPolicy, ConfigError>`
    (`load_policy` resta e rifiuta una policy con CA: `ConfigError::RevocationsRequired`);
  - `pub fn parse_authorized_clients(origin, text) -> Result<AuthorizedClients, ConfigError>` (tipo nuovo);
  - `pub fn load_authorized_clients(path: &Path, revocations: Option<&Path>) -> Result<AuthorizedClients, ConfigError>`;
  - `pub struct CertificateFile { pub bytes: Arc<[u8]>, pub body: CertBody }`,
    `pub fn parse_certificate_file(origin, text)`, `pub fn load_certificate(path)` (regole dei
    file di trust, file ≤ 16 KiB);
  - `pub fn create_ca_key(path) -> Result<CaSigningKey, ConfigError>` (nuovo, `0600`, mai
    sovrascritto), `pub fn load_ca_key(path)` (regole delle chiavi segrete);
  - `ConfigError::{RevocationsRequired(String), Certificate { path, source: CertFormatError }}`.
- `relay.rs`: in `Connection::serve`, dopo `accept` e prima di `establish`: denylist della
  chiave, `verify_certificate` se il payload non è vuoto, `policy.admit(.., unix_now())`;
  rifiuto → audit e chiusura senza messaggio 2. `HubEvent::Connected` porta il certificato.
  L'hub costruisce `Now` a ogni input. `audit()` scrive i campi di PROTOCOL §15.11
  (`credential`, `ca`, `serial`, `cert_name`, `not_after`, `cert_check`).
- `client.rs`: `ClientConfig` + `certificate: Option<Arc<[u8]>>`; il certificato va nel
  messaggio 1 esterno (`connect_with_payload`) e in quello end-to-end
  (`initiate_with_payload`). Il failover non cambia.
- `agent.rs`: `AgentConfig.authorized_clients: Revocable<AuthorizedClients>`; `StreamTask`
  verifica il payload e chiama `admit(.., &config.node, unix_now())` prima di `accept`; rifiuto
  → `authentication_failed` e `Close Unauthorized`. `bridge` chiude con `Close Unauthorized`
  quando `still_admits` diventa falso: si risveglia a ogni cambio di `authorized` e a
  `min(not_after, adesso + 60 s)` (poi rilegge l'orologio, PROTOCOL §15.7); alla scadenza
  `certificate_expired`, altrimenti `access_revoked`. `e2e_session_started` porta i campi del
  certificato.
- `keys.rs`: `announce_authorities(role, &CertTrust)` (`authorities_in_use`,
  `revocations_in_use`), `watch_authorities(role, Revocable<T>, every)` con
  `ca_rotation_pending` ogni ora finché una CA ha due chiavi (generico su `T` con un accessor
  `fn cert_trust(&T) -> &CertTrust`).

### 3.5 Binari

- **`bins/zt-ca`** (nuovo membro del workspace; dipende da `zt-domain`, `zt-crypto`, `zt-net`
  per i controlli sui file, `clap`, `getrandom`; nessun runtime tokio avviato):
  - `zt-ca keygen --out <file>`;
  - `zt-ca sign --ca <file> --log <file> --subject <hex> --name <nome>
    (--nodes a,b,… | --all-nodes) --validity <n{s,m,h}> [--not-before <unix>] --out <file>`;
    stampa serie, fingerprint del soggetto, date UTC; `--out` con `create_new`; `--log` in
    append, `0600`, una riga TSV `serial  subject_fp  name  not_before  not_after  scope`
    scritta e sincronizzata **prima** di creare `--out`;
  - `zt-ca inspect --cert <file> [--ca-key <hex>]`: campi, verifica della firma se c'è
    `--ca-key`, riga `serials = ["…"]` per la denylist.
  - Aggiunto a `cargo build -p` nel workflow di rilascio.
- **`zt-relay run`**: `--revocations <file>` (facoltativo, obbligatorio con CA); la ricarica
  con `SIGHUP` rilegge policy **e** denylist insieme; rifiuta all'avvio e alla ricarica una CA
  uguale alla chiave corrente o precedente del relay.
- **`zt-agent run`**: `--revocations <file>`, stesse regole; rifiuta una CA uguale alla propria
  chiave.
- **`zt-client`**: `certificate` in `client.toml`; prima della rete controlla formato, binding
  alla propria chiave e scadenza (errore, codice 1) e avvisa su stderr entro 15 minuti dalla
  scadenza o se non è ancora valido; nuovo comando `zt-client certificate`; `describe()` con
  certificato: `Closed` → «certificate not accepted by the relay (expired, revoked, CA not
  pinned) or relay restart», `Close Unauthorized` dopo `not_after` → «certificate expired:
  renew it».
- `packaging/systemd`: unità invariate (`--revocations` si aggiunge con un drop-in, OPERATIONS
  §10.2), per non rompere gli aggiornamenti senza CA.

## 4. Passi

Ogni passo è piccolo e si chiude con `cargo test`, `clippy -D warnings` e `fmt` verdi. I test
RED di un passo si committano prima del suo codice (un commit «RED» per passo basta).

| # | Passo | Crate | Dipende da |
| :-: | :- | :- | :- |
| 1 | limiti, `UnixTime`, `CertSerial`, `CertKey`, `CertScope`, `CertBody`, `decode_certificate`, `encode_tbs`, `CertFormatError` | `zt-domain` | — |
| 2 | `CertTrust`, `Authority`, `Revocations`, `CertClaims`, `CertRejection`, `AccessPolicy::admit`/`may_open_with`, `AuthorizedClients`, eventi | `zt-domain` | 1 |
| 3 | `CaSigningKey`, `sign_certificate`, `verify_certificate`, `PublicKey::from_canonical_bytes`, testo dei file | `zt-crypto` | 1, 2 |
| 4 | payload del messaggio 1, messaggio 2 vuoto | `zt-crypto` | — |
| 5 | parser e caricatori: `[[authorities]]`, `revoked.toml`, `certificate`, chiavi di CA | `zt-net::config` | 2, 3 |
| 6 | relay core: `Now`, credenziali, scadenza, rivalutazione alla ricarica | `zt-application` | 2 |
| 7 | rete: relay (verifica prima del messaggio 2), client (payload), agent (verifica, scadenza, revoca) | `zt-net` | 3–6 |
| 8 | osservabilità: `authorities_in_use`, `revocations_in_use`, `ca_rotation_pending` | `zt-net::keys` | 5 |
| 9 | `zt-ca`; opzioni di `zt-relay`/`zt-agent`; `zt-client` | `bins/*` | 5, 7 |
| 10 | target di fuzzing | `fuzz/` | 1–7 |
| 11 | README (stato), adversary review 0006 | `docs/` | tutto |

## 5. Test RED

Ogni riga è un test da scrivere **prima** del codice. «S» = specifica, «A» = attacco.

### Passo 1: formato (`crates/zt-domain/tests/cert_format.rs`, `cert_props.rs`)

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `reference_vector_layout_decodes` | i byte di PROTOCOL §15.13 danno esattamente i campi attesi e il TBS di 123 byte |
| S | `a_certificate_body_round_trips_canonically` | `encode_tbs` + firma fittizia → `decode` → stesso corpo, stessi byte |
| S | `smallest_and_largest_certificates_are_accepted` | 170 byte (`scope` tutti, nome di 1 byte) e 4 328 byte (64 nodi da 63) |
| S | `scope_all_carries_no_nodes` | `0x01` con `node_count = 0` |
| S | `limits_are_consistent` | le `const` di §15.12 e le relazioni con `MAX_PAYLOAD_LEN` |
| A | `lengths_outside_the_bounds_are_rejected_before_parsing` | 0, 1, 169, 4 329, 65 535 byte: errore `Length` senza leggere i campi |
| A | `every_other_magic_version_and_algorithm_is_rejected` | tutti i 255 valori alternativi di `version` e `sig_alg`, magic alterato |
| A | `a_zero_serial_is_rejected` | serie tutta a zero |
| A | `empty_or_inverted_validity_is_rejected` | `not_before == not_after`, `not_before > not_after` |
| A | `a_lifetime_over_24_hours_is_rejected` | 86 401 s no, 86 400 s sì |
| A | `extreme_times_never_overflow` | `not_before = 0`, `not_after = u64::MAX` e viceversa: errore, nessun panic |
| A | `invalid_names_and_node_ids_are_rejected` | maiuscole, NUL, `\n`, `-` ai bordi, Unicode, 0 e 64 byte, `name_len` 0 |
| A | `unsorted_or_duplicate_nodes_are_rejected` | ordine decrescente, duplicati: una sola codifica per ogni insieme |
| A | `an_empty_list_or_nodes_with_scope_all_are_rejected` | `scope 0x00` con 0 nodi; `scope 0x01` con nodi |
| A | `unknown_scope_codes_are_rejected` | `scope` 0x02..=0xff |
| A | `more_than_64_nodes_are_rejected` | `node_count` 65 e 255 |
| A | `length_fields_past_the_end_are_rejected` | `name_len`/`len` di nodo oltre il buffer: `Truncated`, nessun panic |
| A | `missing_or_extra_signature_bytes_are_rejected` | 63 o 65 byte dopo l'ultimo nodo |
| A | `errors_never_echo_certificate_bytes` | il `Display` degli errori non contiene nome, nodi o chiavi del certificato |
| A | `arbitrary_bytes_never_panic_and_accepted_certificates_are_canonical` (proptest) | byte arbitrari e strutturati: un certificato accettato si ricodifica identico |

### Passo 2: fiducia e autorizzazione (`crates/zt-domain/tests/cert_trust.rs`)

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `a_valid_certificate_grants_its_nodes_within_the_authority` | ambito effettivo = cert ∩ `allow` ∩ nodi della policy |
| S | `scope_all_means_the_authority_allow_list` | `scope 0x01` con `allow = [a]` concede solo `a` |
| S | `authority_allow_all_means_every_policy_node` | `allow = ["*"]` non inventa nodi inesistenti |
| S | `validity_has_skew_only_on_not_before` | `nb−120` sì, `nb−121` no; `na−1` sì, `na` no |
| S | `whitelisted_keys_keep_their_grant_and_the_certificate_adds_nothing` | voce `allow=[a]` + cert `[b]` → solo `a`, credenziale `Key` |
| S | `agent_side_accepts_only_its_own_node_in_scope` | `AuthorizedClients::admit` con il proprio nodo dentro e fuori |
| S | `an_empty_effective_scope_admits_but_grants_nothing` | ammesso, ogni `may_open_with` falso |
| S | `rotations_pending_lists_authorities_with_two_keys` | per `ca_rotation_pending` |
| A | `a_certificate_cannot_grant_nodes_of_another_authority` | CA `web` firma `db-01`: negato |
| A | `an_unpinned_authority_is_rejected` | `UnknownAuthority`, anche dopo una ricarica che toglie la CA |
| A | `a_lifetime_over_the_authority_max_is_rejected` | durata 8 h + 1 s con `max_lifetime` 8 h |
| A | `a_revoked_serial_is_rejected` | `SerialRevoked` |
| A | `a_revoked_key_is_rejected_with_any_credential` | chiave in `keys`: rifiutata con certificato, con voce di whitelist, e come agent |
| A | `a_whitelisted_key_with_an_invalid_certificate_is_rejected` | fail closed anche con la voce presente |
| A | `an_agent_key_presenting_a_certificate_is_a_role_conflict` | `RoleConflict` |
| A | `authority_keys_cannot_double_as_peer_keys_in_any_order` | CA poi agent/client e viceversa: `DuplicatePeer` |
| A | `a_ca_key_cannot_appear_in_two_authorities` | stessa chiave, due nomi con ambiti diversi |
| A | `authority_entries_are_validated` | 0 o 3 chiavi, chiavi ripetute, nomi ripetuti, 17 CA, `max_lifetime` 59 e 86 401 |
| A | `revocation_lists_are_bounded` | 16 385 serie, 4 097 chiavi |
| A | `certificate_names_never_affect_authorization` | nome uguale a un client della whitelist, a un nodo, a una CA |
| A | `authorities_without_revocations_are_flagged` | `needs_revocations()` |

### Passo 3: firma e verifica (`crates/zt-crypto/tests/cert.rs`)

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `reference_vector_matches_the_protocol` | dai semi `01×32` e `02×32` gli stessi 187 byte e la stessa fingerprint di §15.13 |
| S | `sign_then_verify_yields_the_claims` | claims = corpo, CA e soggetto come fingerprint |
| S | `ca_secret_files_have_their_own_format` | `to_secret_text`/`from_secret_text`; il prefisso è obbligatorio |
| S | `certificate_text_round_trips` | `tcn-client-cert-v1:` + hex, a capo facoltativo |
| A | `a_certificate_with_another_static_key_fails_before_the_signature` | `KeyMismatch` anche con firma rotta (prova che la firma non è valutata) |
| A | `any_single_bit_flip_invalidates_the_certificate` | ogni bit di ogni byte del vettore: mai `Ok` |
| A | `a_signature_without_the_context_string_is_rejected` | firma del solo TBS |
| A | `non_canonical_or_small_order_keys_are_rejected` | `subject_key` e `ca_key` con `y ≥ p`, punti di ordine piccolo, identità |
| A | `a_malleated_signature_is_rejected` | `S + ℓ`, `R` di ordine piccolo (`verify_strict`) |
| A | `the_ca_key_must_match_a_pin_byte_for_byte` | pin `P`, certificato con `ca_key = −P` firmato con `−s`: `UnknownAuthority` |
| A | `a_ca_key_equal_to_the_subject_is_rejected` | autocertificazione |
| A | `sign_refuses_a_body_naming_another_ca` | `sign_certificate` con `ca_key` diversa |
| A | `node_and_ca_key_files_are_not_interchangeable` | `Identity::from_secret_hex` rifiuta il file della CA; `CaSigningKey::from_secret_text` rifiuta una chiave di nodo |
| A | `ca_signing_key_debug_is_redacted` | nessun byte del segreto nel `Debug` |

### Passo 4: payload dell'handshake (`crates/zt-crypto/tests/handshake.rs`)

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `msg1_payload_reaches_the_responder_intact` | entrambi i canali, anche con `respond_any` sulla chiave precedente |
| S | `initiate_without_payload_is_unchanged` | `payload()` vuoto |
| A | `an_oversized_msg1_payload_is_refused_on_both_sides` | initiator `MessageTooLarge`; responder `Handshake` |
| A | `a_non_empty_msg2_payload_is_refused_by_the_initiator` | responder modificato che scrive un payload |

### Passo 5: configurazione (`crates/zt-net/tests/cert_config.rs`)

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `authorities_parse_with_one_or_two_keys` | `public_key` o `public_keys`, mai entrambi né nessuno |
| S | `max_lifetime_defaults_to_eight_hours` | |
| S | `revocations_parse_serials_and_keys` | |
| S | `the_same_authorities_block_works_for_relay_and_agent` | stesso testo in policy e in `clients.toml` |
| S | `client_settings_resolve_the_certificate_next_to_the_file` | percorso relativo al file |
| S | `ca_key_files_are_created_private_and_never_overwritten` | `0600`, `create_new` |
| A | `authorities_require_a_revocation_list` | `load_relay_policy(.., None)` e `load_authorized_clients(.., None)` con CA: `RevocationsRequired` |
| A | `authority_typos_and_bad_values_are_refused` | campo sconosciuto, nodo non valido in `allow`, `max_lifetime` fuori intervallo, chiave debole o non canonicale (le chiavi di CA si leggono con `PublicKey::from_canonical_bytes`, così il confronto byte per byte del passo 5 implica la canonicità) |
| A | `revocation_files_reject_bad_entries` | 31/33 hex, non hex, serie zero, chiave debole, campo sconosciuto, oltre i limiti |
| A | `certificate_files_reject_other_formats` | chiave di nodo, segreto di CA, due righe, spazi, prefisso sbagliato |
| A | `certificate_and_revocation_files_follow_trust_file_rules` | scrivibili da altri, di un altro utente, FIFO senza blocco, directory insicura |
| A | `a_ca_secret_pasted_into_a_trust_file_is_not_echoed` | estende il finding 0004-6 |
| A | `an_invalid_revocation_file_fails_the_whole_load` | policy valida + denylist rotta: errore, nessuna policy parziale |

### Passo 6: relay core (`crates/zt-application/tests/relay_certs.rs`)

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `a_certified_client_opens_streams_within_its_effective_scope` | `Open` concesso / `Reject NotAuthorized` |
| S | `session_established_carries_the_certificate_reference` | `certificate: Some(CertRef)` |
| S | `a_certified_connection_closes_at_not_after` | `Tick` con `unix ≥ not_after`: `Close Unauthorized` a client e agent, `ConnectionDrained`, `CertificateExpired`, `Output::Close` |
| S | `a_whitelisted_client_never_expires` | credenziale `Key`, nessuna chiusura |
| A | `expiry_follows_wall_time_not_monotonic_time` | `instant` fermo, `unix` che avanza: chiuso |
| A | `a_certificate_already_expired_when_it_reaches_the_core_is_refused` | `Connected` con claims scaduti |
| A | `a_connection_racing_a_reload_that_removes_its_authority_is_refused` | `Connected` dopo `PolicyUpdated` senza la CA |
| A | `revoking_a_serial_on_reload_cuts_the_connection` | `AccessRevoked` con `certificate`, peer chiusi |
| A | `revoking_a_key_on_reload_cuts_static_and_certified_clients` | |
| A | `removing_the_authority_cuts_all_its_connections` | |
| A | `narrowing_the_authority_allow_closes_only_the_lost_streams` | come `relay_grant_narrowing…` |
| A | `shrinking_max_lifetime_below_the_certificate_cuts_it` | |
| A | `a_certificate_for_an_agent_key_is_refused_in_the_core` | `RoleConflict` |

### Passo 7: rete (`crates/zt-net/tests/certs.rs`, `adversary_certs.rs`)

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `a_certified_client_reaches_its_node_through_relay_and_agent` | eco end-to-end con solo la CA pinnata |
| S | `a_whitelisted_client_without_certificate_still_works` | nessuna regressione |
| S | `a_certified_client_falls_back_past_a_relay_without_the_authority` | silenzio sul primo relay, successo sul secondo |
| S | `the_session_ends_when_the_certificate_expires` | certificato di pochi secondi: `Close Unauthorized` al client, `certificate_expired` |
| S | `agent_revocation_of_a_serial_cuts_the_session_even_if_the_relay_still_allows_it` | solo l'agent ha la denylist nuova |
| A | `a_stolen_certificate_with_another_key_never_gets_msg2` | nessun messaggio 2, `cert_check=key_mismatch` |
| A | `garbage_or_oversized_msg1_payloads_get_no_msg2` | relay e agent; il relay sopravvive |
| A | `a_compromised_relay_cannot_open_a_node_outside_the_certificate_scope` | relay finto apre il nodo: `Close Unauthorized`, sshd mai contattato (tripwire) |
| A | `a_compromised_relay_cannot_substitute_a_certificate_toward_the_agent` | msg1 end-to-end del relay con certificato di una CA sua: rifiutato, sshd mai contattato |
| A | `the_agent_rejects_an_authority_it_does_not_pin_even_if_the_relay_does` | difesa in profondità |
| A | `replaying_a_certified_msg1_logs_no_session` | messaggio 1 esterno rigiocato: nessun `session_established` né evento con quella serie |
| A | `expired_and_not_yet_valid_certificates_are_refused_on_relay_and_agent` | oltre la tolleranza |
| A | `a_relay_without_revocations_for_its_authorities_does_not_start` | con `RelayServer`/`agent::run` costruiti dai caricatori |

### Passo 8: osservabilità (`crates/zt-net/tests/keys.rs`)

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `authorities_and_revocations_are_announced` | `authorities_in_use`, `revocations_in_use` con i conteggi |
| S | `a_ca_rotation_is_reported_until_it_is_completed` | `ca_rotation_pending` all'avvio, a ogni ricarica, ogni intervallo |
| A | `announcements_never_contain_certificate_bytes_or_secrets` | solo fingerprint e conteggi |

### Passo 9: binari

`bins/zt-ca/tests/cli.rs`:

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `keygen_creates_a_private_ca_key_and_prints_its_public_key` | `0600`, prefisso, chiave e fingerprint su stdout |
| S | `sign_writes_a_certificate_that_inspect_verifies` | `inspect --ca-key` conferma firma e campi |
| S | `sign_appends_one_line_per_certificate_to_the_log` | due firme → due righe TSV |
| S | `inspect_prints_the_denylist_line` | `serials = ["…"]` |
| A | `sign_never_overwrites_and_refuses_bad_subjects` | `--out` esistente; chiave debole, non hex, non canonicale |
| A | `sign_refuses_bad_durations` | `0s`, `25h`, `1d`, `-1h`, `1h30m`, vuoto, overflow |
| A | `sign_refuses_a_node_key_as_ca` | file di chiave di nodo |
| A | `sign_requires_exactly_one_of_nodes_and_all_nodes` | nessuno o entrambi; 65 nodi; nodo non valido |
| A | `a_failed_log_write_creates_no_certificate` | log non scrivibile: nessun `--out` |
| A | `errors_never_print_secret_material` | |

`bins/zt-client/tests/cli.rs` e `attack.rs`:

| Tipo | Test | Intento |
| :-: | :- | :- |
| S | `certificate_subcommand_prints_status` | nome, nodi, CA, serie, validità |
| S | `a_certificate_expiring_soon_warns_on_stderr_only` | stdout vuoto |
| A | `an_expired_certificate_fails_before_any_connection` | listener tripwire senza connessioni |
| A | `a_certificate_for_another_key_fails_before_any_connection` | |
| A | `an_insecure_certificate_file_is_refused` | regole dei file di trust |

`bins/zt-relay/tests/operations.rs` e `bins/zt-agent/tests/cli.rs`:

| Tipo | Test | Intento |
| :-: | :- | :- |
| A | `authorities_without_revocations_refuse_to_start` | relay e agent |
| A | `a_ca_key_equal_to_the_process_key_refuses_to_start` | relay (anche `--previous-key`) e agent |
| S | `sighup_reloads_revocations_and_cuts_a_revoked_certificate` | relay |
| A | `a_bad_revocation_file_on_reload_keeps_both_previous_files` | `policy_reload_failed`, la policy nuova non entra |

### Passo 10: fuzzing (`fuzz/fuzz_targets/`)

| Target | Superficie | Proprietà |
| :- | :- | :- |
| `cert_decoder` (nuovo) | `decode_certificate` su byte arbitrari | nessun panic; un certificato accettato si ricodifica identico (`encode_tbs` + firma); nessun errore riporta byte dell'input |
| `cert_verify` (nuovo) | `verify_certificate` con trust e chiave fissi; metà degli input sono il vettore di §15.13 modificato | nessun panic; un input accettato è byte per byte il certificato autentico, e i claims sono i suoi |
| `noise_responder` (esteso) | messaggio 1 con payload | il payload restituito è quello inviato; un payload oltre il massimo non è mai accettato |
| `config_parsers` (esteso) | `[[authorities]]`, `parse_revocations`, `parse_certificate_file` | nessun panic; nessuna sequenza esadecimale lunga negli errori |
| `relay_core` (esteso) | connessioni con claims, `Now` con `unix` che avanza e salta, ricariche con CA e denylist | nessuna connessione con certificato sopravvive oltre `not_after`, a una serie o chiave revocata, o alla CA tolta |

`fuzz/README.md` elenca i target nuovi; la CI li esegue come gli altri.

## 6. Catalogo d'attacco per l'avversario

Per il passo 2 di ogni superficie (e per la review 0006), le domande della metodologia
applicate ai certificati; ogni riga ha almeno un test qui sopra.

| Categoria | Domande |
| :- | :- |
| Parsing | lunghezze 169/170/4 328/4 329; `node_count` e `name_len` ai bordi; codici di `scope`, `version`, `sig_alg`; testo del file con prefissi e spazi |
| Risorse | quanta CPU costa un messaggio 1 con certificato, e prima di quale controllo? memoria per connessione nel relay core? un relay compromesso che manda msg1 con certificati in ciclo all'agent? |
| Stato | certificato scaduto fra handshake e core; ricarica in mezzo; scadenza durante un `Open`; sessione aperta con la whitelist e poi voce tolta |
| Identità | certificato con un'altra chiave; `P` e `−P`; CA uguale a un peer; due CA con la stessa chiave; agent con certificato; nomi uguali |
| Canali laterali | il relay rivela perché ha rifiutato? i log contengono il certificato? gli errori dei parser riportano serie o chiavi? |
| Malleabilità | due codifiche dello stesso contenuto; chiavi non canonicali; firme malleabili; esadecimale maiuscolo nei file |

## 7. Scelte su cui l'implementazione non deve tornare senza aggiornare la specifica

1. Il certificato nel messaggio 1, non in un frame (PROTOCOL §15.3).
2. Binding prima della firma; chiave di CA pinnata uguale byte per byte (§15.2, §15.4).
3. La whitelist ha la precedenza, ma un certificato presentato si verifica sempre (§15.5).
4. Tolleranza solo su `not_before`, costante di 120 s (§15.6).
5. La scadenza chiude le sessioni aperte (§15.7).
6. Denylist in un file separato, comune a relay e agent, ricaricato atomicamente con la policy,
   obbligatorio con una CA (§15.8).
7. Nessun codice di `RejectReason` o `CloseReason` nuovo: `Close Unauthorized` per scadenza e
   revoca, silenzio sul relay per un certificato non valido.
