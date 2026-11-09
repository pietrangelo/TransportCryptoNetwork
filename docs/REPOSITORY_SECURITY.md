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
  in the `release` environment.
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

## Verification

After applying everything:

- a `git push origin HEAD:main` must be rejected;
- a `git push --delete origin vX.Y.Z` must be rejected;
- a PR with a red check must not have the merge button enabled;
- the `release` run on a new tag must stop at *Waiting for review* before `attest`.
