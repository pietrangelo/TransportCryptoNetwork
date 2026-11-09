# Phase 6: short-lived client certificates from an offline CA (implementation plan)

Plan for the test and implementation agents. The normative specification is
`docs/PROTOCOL.md` §15 (format, transport, order of checks, expiry, revocation, rotation);
the runbook is `docs/OPERATIONS.md` §10. When in doubt the specification prevails; if a test
contradicts it, the specification is corrected, not the test (as for the framing).

The plan follows Adversarial TDD (`docs/METHODOLOGY.md`): for each step the **RED**
specification and attack tests are committed **before** the code, then GREEN, REFACTOR, and finally
the adversary review `docs/adversary/0006-client-certs.md`.

## 1. Decisions in brief

| Topic | Decision | Where |
| :- | :- | :- |
| Format | canonical binary, fixed layout, `TCNC` v1, Ed25519, 170..=4 328 bytes, ≤ 64 nodes | PROTOCOL §15.1 |
| Signature | pure Ed25519 over `"TCN client certificate v1\0" ‖ TBS`, `verify_strict`, pinned key equal byte for byte | §15.2 |
| Transport | payload of Noise IK message 1, on the outer channel **and** end-to-end; message 2 always empty; no new frame | §15.3 |
| Binding | fingerprint of `subject_key` = fingerprint of the Noise static key, **before** the signature | §15.4 |
| Precedence | the per-key whitelist wins; a presented certificate is always verified; no union of permissions | §15.5 |
| Scope | `policy nodes ∩ scope(cert) ∩ allow(CA)`; the agent checks its own node | §15.5 |
| Time | `not_before − 120 s ≤ now < not_after`; lifetime ≤ the CA's `max_lifetime` ≤ 24 h | §15.6 |
| In-session expiry | the session is closed (`Close Unauthorized`, `certificate_expired`) | §15.7 |
| Revocation | `revoked.toml` file shared by relay and agent (`serials`, `keys`), reloaded together with the policy; mandatory with a CA | §15.8 |
| CA rotation | 1 or 2 keys per `[[authorities]]`, `ca_rotation_pending` | §15.9 |

## 2. Dependencies

No new crates: `cargo deny` stays unchanged (`deny.toml` does not change).

| Need | Choice | Reason |
| :- | :- | :- |
| Ed25519 signing and verification | `ed25519-dalek` 3.0.0, already in `zt-crypto` | `SigningKey::try_sign`, `VerifyingKey::verify_strict`, `is_weak`, `to_edwards().compress()` for canonicity; `zeroize` feature already enabled |
| serial number randomness | `getrandom` 0.4.3, already used | |
| file text | `hex` 0.4.3, already used | no `base64`: one crate fewer, and the existing redaction rules (`redact_hex`) already cover the content |
| CLI durations (`8h`) | 10-line parser in `zt-ca` | no `humantime`; accepts only `<n>s`, `<n>m`, `<n>h` |
| issuance log | hand-written TSV line | no `serde_json` in production; all fields have restricted alphabets |

`zt-domain` stays free of cryptography: decoding, invariants and pure decisions (time passed
as a parameter). Signing, point canonicity and binding live in `zt-crypto`.

## 3. Types and functions

The signatures are indicative in the details (names of private fields, `&`/`Arc`), binding in
substance: whoever changes them updates this file.

### 3.1 `zt-domain`

`src/limits.rs` (with `const` assertions: `NOISE_MSG1_OVERHEAD + MAX_CERT_LEN + NOISE_TAG_LEN`
≤ `MAX_PAYLOAD_LEN` and ≤ `NOISE_MAX_MESSAGE_LEN`; `MIN_CERT_LEN ≤ MAX_CERT_LEN`):

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
pub const NOISE_MSG1_OVERHEAD: usize = 96; // e (32) + encrypted s (32 + 16) + payload tag (16)
```

`src/cert.rs` (new):

```rust
pub const CERT_MAGIC: [u8; 4] = *b"TCNC";
pub const CERT_VERSION: u8 = 0x01;
pub const CERT_SIG_ED25519: u8 = 0x01;
pub const CERT_SIGNATURE_LEN: usize = 64;
pub const CERT_SIGNATURE_CONTEXT: &[u8] = b"TCN client certificate v1\0";

pub struct UnixTime(u64);                    // Copy, Ord; from_secs, as_secs, checked/saturating ops
pub struct CertSerial([u8; 16]);             // Copy, Eq, Hash; TryFrom<[u8;16]> rejects zero; Display hex
pub struct CertKey([u8; 32]);                // 32 Ed25519 bytes not yet validated as a point (zt-crypto does that)
pub enum CertScope { All, Only(BTreeSet<NodeId>) } // Only: 1..=MAX_CERT_NODES

pub struct CertBody { /* private fields */ }
impl CertBody {
    pub fn new(ca_key: CertKey, subject_key: CertKey, serial: CertSerial,
               not_before: UnixTime, not_after: UnixTime,
               name: NodeId, scope: CertScope) -> Result<Self, CertFormatError>;
    pub fn encode_tbs(&self) -> Vec<u8>;     // infallible: an existing CertBody is valid
    // getters: ca_key(), subject_key(), serial(), not_before(), not_after(), name(), scope(), lifetime_secs()
}

pub struct ParsedCert<'a> { pub body: CertBody, pub tbs: &'a [u8], pub signature: &'a [u8; 64] }
pub fn decode_certificate(bytes: &[u8]) -> Result<ParsedCert<'_>, CertFormatError>;

#[non_exhaustive] pub enum CertFormatError { /* metadata only: Length{len}, Magic, Version(u8),
    Algorithm(u8), SerialZero, Validity, Lifetime{secs}, Name(DomainError), Scope(u8),
    NodeCount(u8), NodeOrder{index}, Truncated{at}, Trailing{extra} */ }

#[derive(Clone, Copy)] #[non_exhaustive]
pub enum CertRejection { Malformed, KeyMismatch, UnknownAuthority, BadSignature,
    SerialRevoked, NotYetValid, Expired, LifetimeExceedsAuthority, RoleConflict, NodeOutOfScope }
impl CertRejection { pub const fn as_str(self) -> &'static str; } // values of `cert_check`

/// Only the data of a certificate whose signature has already been verified (zt-crypto).
pub struct CertClaims { /* ca: Fingerprint, ca_key: CertKey, subject: Fingerprint, serial,
                          name, scope, not_before, not_after */ }
impl CertClaims {
    pub fn from_verified(body: CertBody, ca: Fingerprint, subject: Fingerprint) -> Self;
    pub fn reference(&self) -> CertRef;
}
#[derive(Clone)] pub struct CertRef { pub ca: Fingerprint, pub serial: CertSerial,
                                      pub name: NodeId, pub not_after: UnixTime }
```

`src/trust.rs` (new):

```rust
pub struct TrustedCaKey { pub key: CertKey, pub fingerprint: Fingerprint }
pub struct Authority { /* name, keys: Vec<TrustedCaKey> (1..=2), allowed: AllowedNodes, max_lifetime_secs */ }
pub struct Revocations { /* serials: HashSet<CertSerial>, keys: HashSet<Fingerprint> */ }
impl Revocations {
    pub fn new(serials: impl IntoIterator<Item = CertSerial>,
               keys: impl IntoIterator<Item = Fingerprint>) -> Result<Self, DomainError>; // limits
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool;
    pub fn is_serial_revoked(&self, serial: &CertSerial) -> bool;
    pub fn counts(&self) -> (usize, usize);
}
pub struct CertTrust { /* authorities, index CertKey → authority, revocations: Option<Revocations> */ }
impl CertTrust {
    pub fn add_authority(&mut self, name: NodeId, keys: &[TrustedCaKey],
                         allowed: AllowedNodes, max_lifetime_secs: u64) -> Result<(), DomainError>;
    pub fn set_revocations(&mut self, revocations: Revocations);
    pub fn is_empty(&self) -> bool;                       // no CA
    pub fn needs_revocations(&self) -> bool;              // CAs present and denylist missing
    pub fn authority_for_key(&self, key: &CertKey) -> Option<&Authority>;
    pub fn ca_fingerprints(&self) -> impl Iterator<Item = Fingerprint> + '_;
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool;
    /// Steps 5 and 7–10 of PROTOCOL §15.4, in order.
    pub fn check(&self, claims: &CertClaims, now: UnixTime) -> Result<&Authority, CertRejection>;
    pub fn rotations_pending(&self) -> impl Iterator<Item = (&NodeId, &[TrustedCaKey])>;
}
impl Authority { pub fn permits(&self, claims: &CertClaims, node: &NodeId) -> bool; /* scope(cert) ∩ allow */ }
```

`src/policy.rs` (extension of `AccessPolicy`, relay):

```rust
pub enum ClientCredential { Key, Certificate(Arc<CertClaims>) }
pub enum Admission<'a> { Agent { node: &'a NodeId }, Client { credential: ClientCredential } }
impl AccessPolicy {
    pub fn set_cert_trust(&mut self, trust: CertTrust) -> Result<(), DomainError>; // CA keys ≠ peer keys
    pub fn cert_trust(&self) -> &CertTrust;
    /// Steps 1, 2, 5, 7–11 of PROTOCOL §15.4 and the table in §15.5.
    pub fn admit(&self, peer: &Fingerprint, cert: Option<&Arc<CertClaims>>, now: UnixTime)
        -> Result<Admission<'_>, AuthFailureReason>;
    /// Generalised `may_open`: policy nodes ∩ effective scope.
    pub fn may_open_with(&self, peer: &Fingerprint, credential: &ClientCredential,
                         target: &NodeId, now: UnixTime) -> bool;
}
```

`add_agent`, `add_agent_keys`, `add_client` also check the fingerprints of the CAs already
present (insertion order irrelevant). `may_open` stays for whitelist clients.

`src/clients.rs` (new, agent side; replaces `HashSet<Fingerprint>`):

```rust
pub struct AuthorizedClients { /* keys: HashSet<Fingerprint>, trust: CertTrust */ }
impl AuthorizedClients {
    pub fn new() -> Self;
    pub fn add_client(&mut self, key: Fingerprint) -> Result<(), DomainError>;
    pub fn set_cert_trust(&mut self, trust: CertTrust) -> Result<(), DomainError>;
    pub fn cert_trust(&self) -> &CertTrust;
    pub fn contains_key(&self, key: &Fingerprint) -> bool;
    /// Steps 1, 2, 5, 7–10 and 12 of PROTOCOL §15.4.
    pub fn admit(&self, peer: &Fingerprint, cert: Option<&Arc<CertClaims>>, node: &NodeId,
                 now: UnixTime) -> Result<ClientCredential, AuthFailureReason>;
    /// For hot revocation and expiry: is the credential still valid?
    pub fn still_admits(&self, peer: &Fingerprint, credential: &ClientCredential,
                        node: &NodeId, now: UnixTime) -> bool;
}
```

`src/events.rs`:

- `AuthFailureReason::KeyRevoked`, `AuthFailureReason::Certificate(CertRejection)`;
- `DomainEvent::SessionEstablished` and `DomainEvent::AccessRevoked` and `DomainEvent::AccessDenied`
  receive `certificate: Option<CertRef>`;
- new `DomainEvent::CertificateExpired { peer: Fingerprint, certificate: CertRef }`,
  `kind() == "certificate_expired"`, `is_security_alert() == false`.

`src/error.rs`: `DomainError::{AuthorityKeys(NodeId), DuplicateAuthority(NodeId),
AuthorityLifetime { secs }, TooManyAuthorities, TooManyRevocations { what }}`; key
conflicts reuse `DuplicatePeer`.

### 3.2 `zt-crypto`

`src/noise.rs`:

```rust
pub const MAX_HANDSHAKE_PAYLOAD_LEN: usize = zt_domain::limits::MAX_CERT_LEN;
pub fn initiate_with_payload(local: &Identity, remote: &PublicKey, channel: Channel,
                             payload: &[u8]) -> Result<(Vec<u8>, AwaitingResponse), CryptoError>;
// `initiate` = `initiate_with_payload(.., &[])`. Beyond the maximum: CryptoError::MessageTooLarge.
impl AuthorizationPending { pub fn payload(&self) -> &[u8]; }
// `respond`/`respond_any`: payload beyond MAX_HANDSHAKE_PAYLOAD_LEN → CryptoError::Handshake
// (no oracle), kept in a Vec sized to the payload.
// `AwaitingResponse::complete`: non-empty message 2 payload → CryptoError::Handshake.
```

`src/identity.rs`: `PublicKey::from_canonical_bytes(&[u8; 32]) -> Result<PublicKey, CryptoError>`
(valid point, identical re-encoding, not weak), `PublicKey::to_bytes() -> [u8; 32]`.

`src/cert.rs` (new):

```rust
/// Secret key of a CA. No Clone, zeroed on drop, redacted Debug.
pub struct CaSigningKey { /* SigningKey */ }
impl CaSigningKey {
    pub const FILE_PREFIX: &'static str = "tcn-ca-secret-v1:";
    pub fn generate() -> Result<Self, CryptoError>;
    pub fn from_secret_text(text: &str) -> Result<Self, CryptoError>;  // requires the prefix
    pub fn to_secret_text(&self) -> Zeroizing<String>;
    pub fn public_key(&self) -> PublicKey;
}
pub const CERT_FILE_PREFIX: &str = "tcn-client-cert-v1:";
pub fn trusted_ca_key(key: &PublicKey) -> TrustedCaKey;
pub fn cert_key(key: &PublicKey) -> CertKey;
/// Signs `body`; error if `body.ca_key()` is not the public key of `ca`.
pub fn sign_certificate(ca: &CaSigningKey, body: &CertBody) -> Result<Vec<u8>, CryptoError>;
/// Steps 3–6 of PROTOCOL §15.4, in order; the rest is decided by the domain.
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
    // Received, Disconnected, Tick, PolicyUpdated unchanged
}
```

- `Role::Client { credential: ClientCredential }`; `on_connected` uses `policy.admit`.
- `on_open` uses `may_open_with(.., now.unix)`; `AccessDenied` and `SessionEstablished` carry
  `certificate`.
- `on_tick`: for every connection with `ClientCredential::Certificate` and `now.unix >= not_after`:
  `Close Unauthorized` on every stream on both sides, `ConnectionDrained Unauthorized` per
  session, `CertificateExpired`, teardown, `Output::Close`.
- `on_policy`: for clients, `still admitted` with the saved credential (CA still pinned
  by key, denylist, lifetime, role); otherwise `AccessRevoked { target: None, certificate }`
  and close; scope narrowing stream by stream as today.

Effect on existing tests: `Input::Connected` receives `certificate: None`, `handle` receives
`Now`; the `Harness` helpers in `relay_core.rs` and `revocation.rs` and the `relay_core` target
are adapted in a single place.

### 3.4 `zt-net`

- `lib.rs`: `pub fn unix_now() -> UnixTime` (`SystemTime`, before 1970 → 0).
- `channel.rs`: `connect_with_payload(io, local, remote, channel, payload, timeouts)`
  (`connect` delegates with `&[]`); `Pending::payload(&self) -> &[u8]`.
- `config.rs`:
  - `PolicyFile` + `authorities: Vec<AuthorityEntry>` (`name`, `public_key` | `public_keys`,
    `allow`, `max_lifetime: Option<u64>`; `deny_unknown_fields`); same block in
    `clients.toml`;
  - `RevocationsFile { serials: Vec<String>, keys: Vec<String> }`;
  - `ClientFile` + `certificate: Option<String>`; `ClientSettings` + `certificate: Option<PathBuf>`;
  - `pub fn parse_revocations(origin, text) -> Result<Revocations, ConfigError>`;
  - `pub fn load_relay_policy(policy: &Path, revocations: Option<&Path>) -> Result<AccessPolicy, ConfigError>`
    (`load_policy` stays and rejects a policy with a CA: `ConfigError::RevocationsRequired`);
  - `pub fn parse_authorized_clients(origin, text) -> Result<AuthorizedClients, ConfigError>` (new type);
  - `pub fn load_authorized_clients(path: &Path, revocations: Option<&Path>) -> Result<AuthorizedClients, ConfigError>`;
  - `pub struct CertificateFile { pub bytes: Arc<[u8]>, pub body: CertBody }`,
    `pub fn parse_certificate_file(origin, text)`, `pub fn load_certificate(path)` (trust
    file rules, file ≤ 16 KiB);
  - `pub fn create_ca_key(path) -> Result<CaSigningKey, ConfigError>` (new, `0600`, never
    overwritten), `pub fn load_ca_key(path)` (secret key rules);
  - `ConfigError::{RevocationsRequired(String), Certificate { path, source: CertFormatError }}`.
- `relay.rs`: in `Connection::serve`, after `accept` and before `establish`: key
  denylist, `verify_certificate` if the payload is not empty, `policy.admit(.., unix_now())`;
  rejection → audit and close without message 2. `HubEvent::Connected` carries the certificate.
  The hub builds `Now` on every input. `audit()` writes the fields of PROTOCOL §15.11
  (`credential`, `ca`, `serial`, `cert_name`, `not_after`, `cert_check`).
- `client.rs`: `ClientConfig` + `certificate: Option<Arc<[u8]>>`; the certificate goes into the
  outer message 1 (`connect_with_payload`) and into the end-to-end one
  (`initiate_with_payload`). Failover does not change.
- `agent.rs`: `AgentConfig.authorized_clients: Revocable<AuthorizedClients>`; `StreamTask`
  verifies the payload and calls `admit(.., &config.node, unix_now())` before `accept`; rejection
  → `authentication_failed` and `Close Unauthorized`. `bridge` closes with `Close Unauthorized`
  when `still_admits` becomes false: it wakes up on every change of `authorized` and at
  `min(not_after, now + 60 s)` (then re-reads the clock, PROTOCOL §15.7); at expiry
  `certificate_expired`, otherwise `access_revoked`. `e2e_session_started` carries the
  certificate fields.
- `keys.rs`: `announce_authorities(role, &CertTrust)` (`authorities_in_use`,
  `revocations_in_use`), `watch_authorities(role, Revocable<T>, every)` with
  `ca_rotation_pending` every hour as long as a CA has two keys (generic over `T` with an accessor
  `fn cert_trust(&T) -> &CertTrust`).

### 3.5 Binaries

- **`bins/zt-ca`** (new workspace member; depends on `zt-domain`, `zt-crypto`, `zt-net`
  for the file checks, `clap`, `getrandom`; no tokio runtime started):
  - `zt-ca keygen --out <file>`;
  - `zt-ca sign --ca <file> --log <file> --subject <hex> --name <name>
    (--nodes a,b,… | --all-nodes) --validity <n{s,m,h}> [--not-before <unix>] --out <file>`;
    prints serial, subject fingerprint, UTC dates; `--out` with `create_new`; `--log` in
    append mode, `0600`, one TSV line `serial  subject_fp  name  not_before  not_after  scope`
    written and synced **before** creating `--out`;
  - `zt-ca inspect --cert <file> [--ca-key <hex>]`: fields, signature verification if
    `--ca-key` is given, a `serials = ["…"]` line for the denylist.
  - Added to `cargo build -p` in the release workflow.
- **`zt-relay run`**: `--revocations <file>` (optional, mandatory with a CA); reloading
  with `SIGHUP` re-reads policy **and** denylist together; rejects at start-up and on reload a CA
  equal to the relay's current or previous key.
- **`zt-agent run`**: `--revocations <file>`, same rules; rejects a CA equal to its own
  key.
- **`zt-client`**: `certificate` in `client.toml`; before touching the network it checks format,
  binding to its own key and expiry (error, exit code 1) and warns on stderr within 15 minutes of
  expiry or if it is not yet valid; new `zt-client certificate` command; `describe()` with a
  certificate: `Closed` → "certificate not accepted by the relay (expired, revoked, CA not
  pinned) or relay restart", `Close Unauthorized` after `not_after` → "certificate expired:
  renew it".
- `packaging/systemd`: units unchanged (`--revocations` is added with a drop-in, OPERATIONS
  §10.2), so as not to break upgrades without a CA.

## 4. Steps

Each step is small and closes with `cargo test`, `clippy -D warnings` and `fmt` green. The RED
tests of a step are committed before its code (one "RED" commit per step is enough).

| # | Step | Crate | Depends on |
| :-: | :- | :- | :- |
| 1 | limits, `UnixTime`, `CertSerial`, `CertKey`, `CertScope`, `CertBody`, `decode_certificate`, `encode_tbs`, `CertFormatError` | `zt-domain` | — |
| 2 | `CertTrust`, `Authority`, `Revocations`, `CertClaims`, `CertRejection`, `AccessPolicy::admit`/`may_open_with`, `AuthorizedClients`, events | `zt-domain` | 1 |
| 3 | `CaSigningKey`, `sign_certificate`, `verify_certificate`, `PublicKey::from_canonical_bytes`, file text | `zt-crypto` | 1, 2 |
| 4 | message 1 payload, empty message 2 | `zt-crypto` | — |
| 5 | parsers and loaders: `[[authorities]]`, `revoked.toml`, `certificate`, CA keys | `zt-net::config` | 2, 3 |
| 6 | relay core: `Now`, credentials, expiry, re-evaluation on reload | `zt-application` | 2 |
| 7 | network: relay (verification before message 2), client (payload), agent (verification, expiry, revocation) | `zt-net` | 3–6 |
| 8 | observability: `authorities_in_use`, `revocations_in_use`, `ca_rotation_pending` | `zt-net::keys` | 5 |
| 9 | `zt-ca`; `zt-relay`/`zt-agent` options; `zt-client` | `bins/*` | 5, 7 |
| 10 | fuzzing targets | `fuzz/` | 1–7 |
| 11 | README (status), adversary review 0006 | `docs/` | everything |

## 5. RED tests

Each row is a test to write **before** the code. "S" = specification, "A" = attack.

### Step 1: format (`crates/zt-domain/tests/cert_format.rs`, `cert_props.rs`)

| Type | Test | Intent |
| :-: | :- | :- |
| S | `reference_vector_layout_decodes` | the bytes of PROTOCOL §15.13 give exactly the expected fields and the 123-byte TBS |
| S | `a_certificate_body_round_trips_canonically` | `encode_tbs` + dummy signature → `decode` → same body, same bytes |
| S | `smallest_and_largest_certificates_are_accepted` | 170 bytes (`scope` all, 1-byte name) and 4 328 bytes (64 nodes of 63) |
| S | `scope_all_carries_no_nodes` | `0x01` with `node_count = 0` |
| S | `limits_are_consistent` | the `const`s of §15.12 and their relations with `MAX_PAYLOAD_LEN` |
| A | `lengths_outside_the_bounds_are_rejected_before_parsing` | 0, 1, 169, 4 329, 65 535 bytes: `Length` error without reading the fields |
| A | `every_other_magic_version_and_algorithm_is_rejected` | all 255 alternative values of `version` and `sig_alg`, altered magic |
| A | `a_zero_serial_is_rejected` | all-zero serial |
| A | `empty_or_inverted_validity_is_rejected` | `not_before == not_after`, `not_before > not_after` |
| A | `a_lifetime_over_24_hours_is_rejected` | 86 401 s no, 86 400 s yes |
| A | `extreme_times_never_overflow` | `not_before = 0`, `not_after = u64::MAX` and vice versa: error, no panic |
| A | `invalid_names_and_node_ids_are_rejected` | uppercase, NUL, `\n`, `-` at the edges, Unicode, 0 and 64 bytes, `name_len` 0 |
| A | `unsorted_or_duplicate_nodes_are_rejected` | descending order, duplicates: a single encoding for every set |
| A | `an_empty_list_or_nodes_with_scope_all_are_rejected` | `scope 0x00` with 0 nodes; `scope 0x01` with nodes |
| A | `unknown_scope_codes_are_rejected` | `scope` 0x02..=0xff |
| A | `more_than_64_nodes_are_rejected` | `node_count` 65 and 255 |
| A | `length_fields_past_the_end_are_rejected` | node `name_len`/`len` beyond the buffer: `Truncated`, no panic |
| A | `missing_or_extra_signature_bytes_are_rejected` | 63 or 65 bytes after the last node |
| A | `errors_never_echo_certificate_bytes` | the errors' `Display` does not contain the certificate's name, nodes or keys |
| A | `arbitrary_bytes_never_panic_and_accepted_certificates_are_canonical` (proptest) | arbitrary and structured bytes: an accepted certificate re-encodes identically |

### Step 2: trust and authorisation (`crates/zt-domain/tests/cert_trust.rs`)

| Type | Test | Intent |
| :-: | :- | :- |
| S | `a_valid_certificate_grants_its_nodes_within_the_authority` | effective scope = cert ∩ `allow` ∩ policy nodes |
| S | `scope_all_means_the_authority_allow_list` | `scope 0x01` with `allow = [a]` grants only `a` |
| S | `authority_allow_all_means_every_policy_node` | `allow = ["*"]` does not invent non-existent nodes |
| S | `validity_has_skew_only_on_not_before` | `nb−120` yes, `nb−121` no; `na−1` yes, `na` no |
| S | `whitelisted_keys_keep_their_grant_and_the_certificate_adds_nothing` | entry `allow=[a]` + cert `[b]` → only `a`, credential `Key` |
| S | `agent_side_accepts_only_its_own_node_in_scope` | `AuthorizedClients::admit` with its own node inside and outside |
| S | `an_empty_effective_scope_admits_but_grants_nothing` | admitted, every `may_open_with` false |
| S | `rotations_pending_lists_authorities_with_two_keys` | for `ca_rotation_pending` |
| A | `a_certificate_cannot_grant_nodes_of_another_authority` | CA `web` signs `db-01`: denied |
| A | `an_unpinned_authority_is_rejected` | `UnknownAuthority`, also after a reload that removes the CA |
| A | `a_lifetime_over_the_authority_max_is_rejected` | lifetime 8 h + 1 s with `max_lifetime` 8 h |
| A | `a_revoked_serial_is_rejected` | `SerialRevoked` |
| A | `a_revoked_key_is_rejected_with_any_credential` | key in `keys`: rejected with a certificate, with a whitelist entry, and as an agent |
| A | `a_whitelisted_key_with_an_invalid_certificate_is_rejected` | fail closed even with the entry present |
| A | `an_agent_key_presenting_a_certificate_is_a_role_conflict` | `RoleConflict` |
| A | `authority_keys_cannot_double_as_peer_keys_in_any_order` | CA then agent/client and vice versa: `DuplicatePeer` |
| A | `a_ca_key_cannot_appear_in_two_authorities` | same key, two names with different scopes |
| A | `authority_entries_are_validated` | 0 or 3 keys, repeated keys, repeated names, 17 CAs, `max_lifetime` 59 and 86 401 |
| A | `revocation_lists_are_bounded` | 16 385 serials, 4 097 keys |
| A | `certificate_names_never_affect_authorization` | name equal to a whitelist client, to a node, to a CA |
| A | `authorities_without_revocations_are_flagged` | `needs_revocations()` |

### Step 3: signing and verification (`crates/zt-crypto/tests/cert.rs`)

| Type | Test | Intent |
| :-: | :- | :- |
| S | `reference_vector_matches_the_protocol` | from seeds `01×32` and `02×32` the same 187 bytes and the same fingerprint as §15.13 |
| S | `sign_then_verify_yields_the_claims` | claims = body, CA and subject as fingerprints |
| S | `ca_secret_files_have_their_own_format` | `to_secret_text`/`from_secret_text`; the prefix is mandatory |
| S | `certificate_text_round_trips` | `tcn-client-cert-v1:` + hex, optional trailing newline |
| A | `a_certificate_with_another_static_key_fails_before_the_signature` | `KeyMismatch` even with a broken signature (proves the signature is not evaluated) |
| A | `any_single_bit_flip_invalidates_the_certificate` | every bit of every byte of the vector: never `Ok` |
| A | `a_signature_without_the_context_string_is_rejected` | signature of the TBS alone |
| A | `non_canonical_or_small_order_keys_are_rejected` | `subject_key` and `ca_key` with `y ≥ p`, small-order points, identity |
| A | `a_malleated_signature_is_rejected` | `S + ℓ`, small-order `R` (`verify_strict`) |
| A | `the_ca_key_must_match_a_pin_byte_for_byte` | pin `P`, certificate with `ca_key = −P` signed with `−s`: `UnknownAuthority` |
| A | `a_ca_key_equal_to_the_subject_is_rejected` | self-certification |
| A | `sign_refuses_a_body_naming_another_ca` | `sign_certificate` with a different `ca_key` |
| A | `node_and_ca_key_files_are_not_interchangeable` | `Identity::from_secret_hex` rejects the CA file; `CaSigningKey::from_secret_text` rejects a node key |
| A | `ca_signing_key_debug_is_redacted` | no byte of the secret in `Debug` |

### Step 4: handshake payload (`crates/zt-crypto/tests/handshake.rs`)

| Type | Test | Intent |
| :-: | :- | :- |
| S | `msg1_payload_reaches_the_responder_intact` | both channels, also with `respond_any` on the previous key |
| S | `initiate_without_payload_is_unchanged` | empty `payload()` |
| A | `an_oversized_msg1_payload_is_refused_on_both_sides` | initiator `MessageTooLarge`; responder `Handshake` |
| A | `a_non_empty_msg2_payload_is_refused_by_the_initiator` | modified responder that writes a payload |

### Step 5: configuration (`crates/zt-net/tests/cert_config.rs`)

| Type | Test | Intent |
| :-: | :- | :- |
| S | `authorities_parse_with_one_or_two_keys` | `public_key` or `public_keys`, never both nor neither |
| S | `max_lifetime_defaults_to_eight_hours` | |
| S | `revocations_parse_serials_and_keys` | |
| S | `the_same_authorities_block_works_for_relay_and_agent` | same text in the policy and in `clients.toml` |
| S | `client_settings_resolve_the_certificate_next_to_the_file` | path relative to the file |
| S | `ca_key_files_are_created_private_and_never_overwritten` | `0600`, `create_new` |
| A | `authorities_require_a_revocation_list` | `load_relay_policy(.., None)` and `load_authorized_clients(.., None)` with a CA: `RevocationsRequired` |
| A | `authority_typos_and_bad_values_are_refused` | unknown field, invalid node in `allow`, `max_lifetime` out of range, weak or non-canonical key (CA keys are read with `PublicKey::from_canonical_bytes`, so the byte-for-byte comparison in step 5 implies canonicity) |
| A | `revocation_files_reject_bad_entries` | 31/33 hex, non-hex, zero serial, weak key, unknown field, beyond the limits |
| A | `certificate_files_reject_other_formats` | node key, CA secret, two lines, spaces, wrong prefix |
| A | `certificate_and_revocation_files_follow_trust_file_rules` | writable by others, owned by another user, FIFO without blocking, insecure directory |
| A | `a_ca_secret_pasted_into_a_trust_file_is_not_echoed` | extends finding 0004-6 |
| A | `an_invalid_revocation_file_fails_the_whole_load` | valid policy + broken denylist: error, no partial policy |

### Step 6: relay core (`crates/zt-application/tests/relay_certs.rs`)

| Type | Test | Intent |
| :-: | :- | :- |
| S | `a_certified_client_opens_streams_within_its_effective_scope` | `Open` granted / `Reject NotAuthorized` |
| S | `session_established_carries_the_certificate_reference` | `certificate: Some(CertRef)` |
| S | `a_certified_connection_closes_at_not_after` | `Tick` with `unix ≥ not_after`: `Close Unauthorized` to client and agent, `ConnectionDrained`, `CertificateExpired`, `Output::Close` |
| S | `a_whitelisted_client_never_expires` | `Key` credential, no close |
| A | `expiry_follows_wall_time_not_monotonic_time` | `instant` frozen, `unix` advancing: closed |
| A | `a_certificate_already_expired_when_it_reaches_the_core_is_refused` | `Connected` with expired claims |
| A | `a_connection_racing_a_reload_that_removes_its_authority_is_refused` | `Connected` after `PolicyUpdated` without the CA |
| A | `revoking_a_serial_on_reload_cuts_the_connection` | `AccessRevoked` with `certificate`, peers closed |
| A | `revoking_a_key_on_reload_cuts_static_and_certified_clients` | |
| A | `removing_the_authority_cuts_all_its_connections` | |
| A | `narrowing_the_authority_allow_closes_only_the_lost_streams` | like `relay_grant_narrowing…` |
| A | `shrinking_max_lifetime_below_the_certificate_cuts_it` | |
| A | `a_certificate_for_an_agent_key_is_refused_in_the_core` | `RoleConflict` |

### Step 7: network (`crates/zt-net/tests/certs.rs`, `adversary_certs.rs`)

| Type | Test | Intent |
| :-: | :- | :- |
| S | `a_certified_client_reaches_its_node_through_relay_and_agent` | end-to-end echo with only the CA pinned |
| S | `a_whitelisted_client_without_certificate_still_works` | no regression |
| S | `a_certified_client_falls_back_past_a_relay_without_the_authority` | silence on the first relay, success on the second |
| S | `the_session_ends_when_the_certificate_expires` | certificate valid for a few seconds: `Close Unauthorized` to the client, `certificate_expired` |
| S | `agent_revocation_of_a_serial_cuts_the_session_even_if_the_relay_still_allows_it` | only the agent has the new denylist |
| A | `a_stolen_certificate_with_another_key_never_gets_msg2` | no message 2, `cert_check=key_mismatch` |
| A | `garbage_or_oversized_msg1_payloads_get_no_msg2` | relay and agent; the relay survives |
| A | `a_compromised_relay_cannot_open_a_node_outside_the_certificate_scope` | fake relay opens the node: `Close Unauthorized`, sshd never contacted (tripwire) |
| A | `a_compromised_relay_cannot_substitute_a_certificate_toward_the_agent` | the relay's end-to-end msg1 with a certificate from its own CA: rejected, sshd never contacted |
| A | `the_agent_rejects_an_authority_it_does_not_pin_even_if_the_relay_does` | defence in depth |
| A | `replaying_a_certified_msg1_logs_no_session` | replayed outer message 1: no `session_established` nor any event with that serial |
| A | `expired_and_not_yet_valid_certificates_are_refused_on_relay_and_agent` | beyond the tolerance |
| A | `a_relay_without_revocations_for_its_authorities_does_not_start` | with `RelayServer`/`agent::run` built from the loaders |

### Step 8: observability (`crates/zt-net/tests/keys.rs`)

| Type | Test | Intent |
| :-: | :- | :- |
| S | `authorities_and_revocations_are_announced` | `authorities_in_use`, `revocations_in_use` with the counts |
| S | `a_ca_rotation_is_reported_until_it_is_completed` | `ca_rotation_pending` at start-up, on every reload, every interval |
| A | `announcements_never_contain_certificate_bytes_or_secrets` | only fingerprints and counts |

### Step 9: binaries

`bins/zt-ca/tests/cli.rs`:

| Type | Test | Intent |
| :-: | :- | :- |
| S | `keygen_creates_a_private_ca_key_and_prints_its_public_key` | `0600`, prefix, key and fingerprint on stdout |
| S | `sign_writes_a_certificate_that_inspect_verifies` | `inspect --ca-key` confirms signature and fields |
| S | `sign_appends_one_line_per_certificate_to_the_log` | two signatures → two TSV lines |
| S | `inspect_prints_the_denylist_line` | `serials = ["…"]` |
| A | `sign_never_overwrites_and_refuses_bad_subjects` | existing `--out`; weak, non-hex, non-canonical key |
| A | `sign_refuses_bad_durations` | `0s`, `25h`, `1d`, `-1h`, `1h30m`, empty, overflow |
| A | `sign_refuses_a_node_key_as_ca` | node key file |
| A | `sign_requires_exactly_one_of_nodes_and_all_nodes` | neither or both; 65 nodes; invalid node |
| A | `a_failed_log_write_creates_no_certificate` | non-writable log: no `--out` |
| A | `errors_never_print_secret_material` | |

`bins/zt-client/tests/cli.rs` and `attack.rs`:

| Type | Test | Intent |
| :-: | :- | :- |
| S | `certificate_subcommand_prints_status` | name, nodes, CA, serial, validity |
| S | `a_certificate_expiring_soon_warns_on_stderr_only` | empty stdout |
| A | `an_expired_certificate_fails_before_any_connection` | tripwire listener with no connections |
| A | `a_certificate_for_another_key_fails_before_any_connection` | |
| A | `an_insecure_certificate_file_is_refused` | trust file rules |

`bins/zt-relay/tests/operations.rs` and `bins/zt-agent/tests/cli.rs`:

| Type | Test | Intent |
| :-: | :- | :- |
| A | `authorities_without_revocations_refuse_to_start` | relay and agent |
| A | `a_ca_key_equal_to_the_process_key_refuses_to_start` | relay (including `--previous-key`) and agent |
| S | `sighup_reloads_revocations_and_cuts_a_revoked_certificate` | relay |
| A | `a_bad_revocation_file_on_reload_keeps_both_previous_files` | `policy_reload_failed`, the new policy does not get in |

### Step 10: fuzzing (`fuzz/fuzz_targets/`)

| Target | Surface | Property |
| :- | :- | :- |
| `cert_decoder` (new) | `decode_certificate` on arbitrary bytes | no panic; an accepted certificate re-encodes identically (`encode_tbs` + signature); no error reports input bytes |
| `cert_verify` (new) | `verify_certificate` with fixed trust and key; half of the inputs are the §15.13 vector modified | no panic; an accepted input is byte for byte the authentic certificate, and the claims are its own |
| `noise_responder` (extended) | message 1 with payload | the returned payload is the one sent; a payload beyond the maximum is never accepted |
| `config_parsers` (extended) | `[[authorities]]`, `parse_revocations`, `parse_certificate_file` | no panic; no long hexadecimal sequence in errors |
| `relay_core` (extended) | connections with claims, `Now` with `unix` advancing and jumping, reloads with CA and denylist | no connection with a certificate survives past `not_after`, a revoked serial or key, or the removal of the CA |

`fuzz/README.md` lists the new targets; CI runs them like the others.

## 6. Attack catalogue for the adversary

For step 2 of every surface (and for review 0006), the methodology's questions
applied to certificates; every row has at least one test above.

| Category | Questions |
| :- | :- |
| Parsing | lengths 169/170/4 328/4 329; `node_count` and `name_len` at the edges; `scope`, `version`, `sig_alg` codes; file text with prefixes and spaces |
| Resources | how much CPU does a message 1 with a certificate cost, and before which check? memory per connection in the relay core? a compromised relay that sends the agent msg1s with certificates in a loop? |
| State | certificate expired between handshake and core; reload in between; expiry during an `Open`; session opened with the whitelist and then the entry removed |
| Identity | certificate with another key; `P` and `−P`; CA equal to a peer; two CAs with the same key; agent with a certificate; equal names |
| Side channels | does the relay reveal why it rejected? do logs contain the certificate? do parser errors report serials or keys? |
| Malleability | two encodings of the same content; non-canonical keys; malleable signatures; uppercase hexadecimal in files |

## 7. Choices the implementation must not revisit without updating the specification

1. The certificate in message 1, not in a frame (PROTOCOL §15.3).
2. Binding before the signature; pinned CA key equal byte for byte (§15.2, §15.4).
3. The whitelist takes precedence, but a presented certificate is always verified (§15.5).
4. Tolerance only on `not_before`, a constant of 120 s (§15.6).
5. Expiry closes open sessions (§15.7).
6. Denylist in a separate file, shared by relay and agent, reloaded atomically with the policy,
   mandatory with a CA (§15.8).
7. No new `RejectReason` or `CloseReason` code: `Close Unauthorized` for expiry and
   revocation, silence on the relay for an invalid certificate.
