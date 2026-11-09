# GitHub repository security

TCN's code ends up as the root of trust on a fleet's servers: anyone who manages to get a commit
into `main`, or to publish a binary in the project's name, gets SSH everywhere. This document
describes the repository's defences, those already in the code and those that must be enabled
in the GitHub settings (only the owner can do that).

## Threat model

| Threat | Defence |
| --- | --- |
| Direct push or force-push to `main`, even from a stolen token | `main` ruleset: no direct pushes, no force-push or deletion, PRs only |
| PR that gets through without tests or fuzzing | required checks, branch up to date before merge |
| Commit with a forged author | signed commits required on `main`, *vigilant mode* on the account |
| Compromised dependency (crates.io) | `cargo-deny`, `Cargo.lock` with `--locked`, Dependabot with a 7-day *cooldown*, CODEOWNERS on `Cargo.lock` |
| Compromised action or moved action tag | actions pinned to a commit SHA, zizmor in CI, Dependabot for updates, allow-list of permitted actions |
| Script injection in workflows | no `${{ }}` expressions inside `run:`, checked by zizmor |
| CI token used to write to the repository | `permissions: contents: read` as default, checkout credentials not persisted |
| Release from unreviewed code | the tag must point to a commit on `main` (`verify-tag`), only the admin creates `v*` tags |
| Release tag moved after publication | `release-tags-immutable` ruleset, immutable releases |
| Unauthorised signing or publication | `attest` and `release` jobs in the protected `release` environment, with manual approval |
| Secrets in the repository | secret scanning and push protection; the Claude configuration is encrypted with `cc` (`cc check` in CI) |
| Vulnerability disclosed in public | `SECURITY.md` and GitHub private reporting |

## Already in the repository

- `.github/workflows/*`: minimal permissions, actions pinned to SHA, `persist-credentials: false`,
  timeout on every job, `concurrency`, matrix inputs passed via `env`.
- `ci.yml` → `zizmor` job: static analysis of the workflows, fails on any finding.
- `release.yml`: `verify-tag` (tag on `main`, semver name), `attest` and `release`
  in the `release` environment; the release stays a draft.
- `release-publish.yml` (by hand, `release` environment): publishes a draft only once
  `SHA256SUMS` carries both offline release signatures, verified with a pinned OpenSSL 3.5.
- `soak.yml`: nightly 30-minute soak with the leak gate (R-6), read-only.
- `.github/dependabot.yml`: Cargo (`/` and `/fuzz`) and GitHub Actions, weekly, 7-day cooldown.
- `.github/CODEOWNERS`, `SECURITY.md`.
- `.github/rulesets/*.json`: the branch and tag rules, ready to import.

## To enable in the settings (owner)

Order matters: the `main` ruleset requires checks with the names introduced by this change, so
it must be enabled **after** the PR that adds them is merged.

### 1. Account

1. [Two-factor authentication](https://github.com/settings/security) with a passkey or hardware
   key, if not already enabled.
2. [Signing key](https://github.com/settings/keys): add an SSH key as a
   *Signing key* (or GPG) and configure git locally:
   `git config --global gpg.format ssh`,
   `git config --global user.signingkey ~/.ssh/id_ed25519.pub`,
   `git config --global commit.gpgsign true`, `git config --global tag.gpgsign true`.
3. On the same page enable **Flag unsigned commits as unverified** (*vigilant mode*).

### 2. Settings → General

- *Pull Requests*: leave only **Allow squash merging**; remove merge commits and rebase.
  Enable **Always suggest updating pull request branches** and
  **Automatically delete head branches**.
- *Features*: disable **Wikis** and **Projects** if you don't use them (less surface to watch).
- *Releases*: enable **Enable release immutability**, so that the assets and tag of a published
  release can no longer be changed.

### 3. Settings → Rules → Rulesets

For each file, **New ruleset → Import a ruleset** and choose the JSON:

1. `.github/rulesets/release-tags-immutable.json`: nobody, not even the admin, can move
   or delete a `v*` tag.
2. `.github/rulesets/release-tags-create.json`: only the admin creates `v*` tags.
3. `.github/rulesets/main.json` (**after the merge**): PR required with squash merge,
   conversations resolved, required checks with branch up to date, linear history, signed
   commits, no force-push or deletion. No bypass, not even for the admin.

Alternatively, from a terminal with `gh` authenticated as the owner:

```bash
for f in release-tags-immutable release-tags-create main; do
  gh api -X POST repos/pietrangelo/TransportCryptoNetwork/rulesets \
    --input ".github/rulesets/$f.json"
done
```

Note: with a single maintainer the required approvals are 0, because GitHub does not let you
approve your own PRs. The other rules still apply: nothing reaches `main` without a PR and green
CI. When a second maintainer joins, set `required_approving_review_count` to 1 and
`require_code_owner_review` to `true`.

### 4. Settings → Environments → New environment `release`

- **Required reviewers**: `pietrangelo`.
- **Deployment branches and tags** → *Selected branches and tags* → add a rule of
  type *Tag* with the pattern `v*`.
- No secrets are needed: signing uses GitHub's OIDC token (Sigstore). If one is ever needed
  in the future (for example for a registry), it goes here and not among the repository secrets.

### 5. Settings → Actions → General

- *Actions permissions*: **Allow pietrangelo, and select non-pietrangelo, actions and
  reusable workflows**, with **Allow actions created by GitHub** and this list:
  `dtolnay/rust-toolchain@*, Swatinem/rust-cache@*, EmbarkStudios/cargo-deny-action@*,
  zizmorcore/zizmor-action@*`.
- Enable **Require actions to be pinned to a full-length commit SHA**.
- *Fork pull request workflows*: **Require approval for all external contributors**.
- *Workflow permissions*: **Read repository contents and packages permissions** and
  **disable** *Allow GitHub Actions to create and approve pull requests*.

### 6. Settings → Advanced Security (Code security)

- **Private vulnerability reporting**: Enable (currently off; `SECURITY.md` points to it).
- **Dependency graph**, **Dependabot alerts**, **Dependabot security updates**: Enable.
- **Secret Protection** / **Secret scanning** and **Push protection**: Enable.
- **Code scanning → CodeQL analysis → Set up → Default**: Rust and GitHub Actions languages.

## Release signing keys (PQ-REL, maintainer)

`SHA256SUMS` of every release is signed offline by two keys, SLH-DSA-SHA2-128s and Ed25519,
with `packaging/release/tcn-release.sh` and OpenSSL 3.5 or later. The private keys never
reach GitHub, CI or any networked machine; CI only verifies (`release-publish.yml`).

Once, on an offline machine with OpenSSL >= 3.5:

```bash
packaging/release/tcn-release.sh keygen /media/offline/tcn-release   # private keys 0600
packaging/release/tcn-release.sh fingerprint /media/offline/tcn-release
```

Commit `release-slhdsa.pub.pem` and `release-ed25519.pub.pem` to `packaging/release/keys/`
and **pin** the two fingerprint lines in the same reviewed PR to `main` (review 0013, A13-4),
in three places that the release tests check against each other:

- `PINNED_FINGERPRINTS` in `packaging/release/tcn-release.sh` (what `verify` trusts);
- `packaging/release/release-keys.fingerprints`;
- the "Pinned release keys" block of `SECURITY.md`.

Publish them out of band too (for example a signed announcement). Back up the private keys
offline, in two places, encrypted:
`openssl pkey -in release-ed25519.key.pem -aes-256-cbc -out release-ed25519.key.enc.pem`
(the same for the SLH-DSA key); `keygen` writes them unencrypted because they live on an
offline machine. Until the keys are pinned, `verify` and `release-publish.yml` refuse every
release (fail closed).

For each release, after `release.yml` made the draft:

1. Download `SHA256SUMS` from the draft (`gh release download vX.Y.Z --pattern SHA256SUMS`),
   check it lists exactly the expected archives and that their attestations verify.
2. Carry it to the offline machine and sign:
   `packaging/release/tcn-release.sh sign /media/offline/tcn-release SHA256SUMS`. The tool
   refuses a malformed `SHA256SUMS` (A13-5) and a private key readable by others, and verifies
   what it signed.
3. Bring back `SHA256SUMS.slhdsa.sig` and `SHA256SUMS.ed25519.sig` and upload them to the
   draft: `gh release upload vX.Y.Z SHA256SUMS.slhdsa.sig SHA256SUMS.ed25519.sig`.
4. Run **release-publish** from the tag: Actions → release-publish → *Run workflow* → *Use
   workflow from* → *Tags* → `vX.Y.Z` (A13-6: the tag is the ref of the run, there is no
   input, and the `release` environment admits only `v*` tags, so a run from `main` is
   refused). A job with a read-only token builds a pinned OpenSSL 3.5 with the script of the
   default branch. Then, in the `release` environment, after approval, the publishing job checks
   that the tag's commit is on `main`, verifies both signatures with `tcn-release.sh` **and its
   pins from the default branch** against the keys committed at the tag (`--tag vX.Y.Z`),
   checks every archive against `SHA256SUMS`, checks that the draft holds exactly those files,
   downloads them again and compares them byte for byte, and only then publishes the draft.
   The write token is set only on the steps that call `gh`.

A lost or compromised release key: commit the new public key and pin its fingerprint in the
three places (reviewed PR to `main`), publish the new fingerprint with the reason, and sign
every later release with the new pair. For a planned rotation, keep the old pin next to the new
one until the last release signed by the old pair is out of support, and sign the announcement
of the new fingerprints with the old pair (`openssl pkeyutl -sign` with each old key over the
announcement), so that users who pinned the old keys can follow. A compromised key's pin is
removed at once. Releases signed by an old key stay verifiable with `verify --pins` and the old
lines.

## Verification

After applying everything:

- a `git push origin HEAD:main` must be rejected;
- a `git push --delete origin vX.Y.Z` must be rejected;
- a PR with a red check must not have the merge button enabled;
- the `release` run on a new tag must stop at *Waiting for review* before `attest`.
