# AGENTS.md — Countersign

The map for agents working in this repo. It points to where things are; the
details live in `docs/` and the files below. This project follows the value-al
AI Development Protocol at autonomy level **L2** (owner override, 2026-11-08): low- and medium-risk PRs
merge through the merge bot once CI and the reviewer pass; high-risk PRs and
protected paths need the owner's `human-approved`.

**This repo is public.** The protocol lets agents run only in private repos.
Until the owner decides (see `docs/tech-debt.md`), no agent runs here
unattended; these notes are for sessions the owner starts himself.

## What this is

A small, dependency-free .NET library (`netstandard2.0` + `net8.0`) for
payment/PSP integrations: `RequestSigner` signs outbound requests,
`WebhookVerifier` verifies inbound webhooks. HMAC, RSA and ECDSA schemes,
canonical forms over raw bytes, constant-time compare, replay tolerance.
Published on NuGet as `Countersign`; used as the webhook boundary of
[Remit](https://github.com/value-al/Remit). Scope: `README.md`, `CONTRIBUTING.md`.

## Where things are

| Need | Look in |
|---|---|
| What it does, usage, design notes | `README.md` |
| Scope, contribution rules | `CONTRIBUTING.md` |
| Threat model, disclosure policy | `SECURITY.md` |
| How the library fits together | `ARCHITECTURE.md` |
| Why a technical choice was made | `docs/adr/` |
| Specs being built / done | `docs/specs/active/`, `docs/specs/done/` |
| Code rules | `docs/golden-principles.md` |
| Known debt and protocol gaps | `docs/tech-debt.md` |
| Release history | `CHANGELOG.md` |
| Commands, environments, high-risk paths | `project.yml` |

## Layout

- `src/Countersign/` — the library. Public types in the `Countersign`
  namespace; helpers in `Countersign.Internal` (`Mac`, `Hex`, `Payload`,
  `SignatureEncoder`, `EcdsaSignature`), all internal.
- `tests/Countersign.Tests/` — xUnit, on `net8.0` and `net48` (Windows):
  known-answer vectors (RFC 4231), scheme interop, tolerance, and the public
  API snapshot `PublicApi.approved.txt`.
- `tests/Countersign.ArchitectureTests/` — NetArchTest rules for the layers
  in `ARCHITECTURE.md`; each failure says how to fix it.
- `Directory.Build.props` — warnings as errors, nullable, deterministic builds.
- `.github/workflows/` — `ci.yml` (build, tests, scan), `release.yml`
  (NuGet on a `v*` tag), `merge-bot.yml`.

## Commands

```bash
dotnet restore
dotnet build -c Release                                     # warnings are errors
dotnet test -c Release                                      # unit + architecture
dotnet test tests/Countersign.ArchitectureTests -c Release  # architecture only
dotnet tool restore && dotnet stryker --since:main          # mutation testing, local only
```

`net48` tests run only on Windows; on Linux use `-f net8.0`.

## How to work here

- One issue per session. Change only what the issue says; anything else
  becomes a new issue.
- Branch `<issue-number>-<short-name>`, PR body `Closes #<n>`. Never push to
  `main`, never merge, never push a tag (a `v*` tag publishes to NuGet).
- Tests from the acceptance criteria first, then the code. Crypto changes
  need known-answer vectors where a standard publishes them.
- Never modify, delete or rename existing tests; add new ones.
- Never wait for an answer: decide, and write `Decision made: <what and why>`
  in the PR. Never add labels yourself.
- After 3 failed attempts, stop and write a failure summary in the issue.
- A structural change updates `ARCHITECTURE.md` and the architecture tests;
  a decision that is expensive to reverse gets an ADR.
- Every change to `src/Countersign/` is High tier (`needs_human` in
  `project.yml`): the owner reviews the diff.
- Never use `--no-verify`, `--force`, hard resets or `git clean`, and never
  print secrets. Test keys are generated in the test, never committed.

## Library rules (short; details in `docs/golden-principles.md`)

- No runtime dependencies. Build-time tools only with `PrivateAssets="all"`.
- Outbound (`RequestSigner`) and inbound (`WebhookVerifier`) stay separate types.
- Sign and verify the exact bytes; canonical forms work on `byte[]`.
- Schemes turn bytes into signatures; the verifier alone decides validity.
- Fixed-time compare only, through `Internal.Mac.FixedTimeEquals`.
- Public API changes are deliberate: update `PublicApi.approved.txt`,
  `CHANGELOG.md` under `## [Unreleased]`, and follow semantic versioning.
- Every public member has XML docs (the build fails otherwise).

## Owner

value-al's own open-source library, Light level; Aldiger approves. Outside
contributors follow `CONTRIBUTING.md`; security reports go through GitHub's
private advisories (`SECURITY.md`), never a public issue.
No AI attribution in commits, PRs, issues or code comments.
