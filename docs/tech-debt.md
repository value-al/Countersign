# Tech debt — Countersign

Known debt and gaps against the value-al AI Development Protocol. Agents keep
this current: add a line when you find debt, remove it when it's paid.

## Open protocol question

| Question | Why it matters | Until then |
|---|---|---|

## Code

| Item | Why it matters | Fix |
|---|---|---|
| `WebhookVerifier.Verify` takes `messageTimestamp` separately from `SignatureContext.Timestamp`, and nothing checks they agree | A caller could put one timestamp in the signed message and check tolerance against another, which defeats replay protection. The README examples pass the same header to both | Document it prominently; consider (in a major version) deriving the tolerance check from the signed timestamp |
| `SECURITY.md` still says "pre-1.0" and lists only HMAC-SHA256/512 | 1.0.0 shipped with SHA-384/SHA-1, RSA and ECDSA; the threat model is out of date | Update the supported-versions and "helps with" sections (High tier: `SECURITY.md` is in `needs_human`) |
| Mutation score 66 % for the whole library (Stryker.NET, 2026-11-08): 39 survived, 56 not covered | Survivors in signing code are untested behaviour; uncovered mutants include the `netstandard2.0` compare (tests run on `net8.0`) and DER edge cases in `Internal/EcdsaSignature.cs` | Add tests for the survivors, starting with `EcdsaSignature` and `CheckTimestamp` boundaries; run Stryker against `net48` too |
| CI installs .NET SDK 8.0.x, but `Countersign.slnx` needs SDK 9.0.200 or later; it works only because the runner image has a newer SDK. No `global.json` | A runner image change can break CI or change the compiler | Add a `global.json` pinning the SDK and install that version in CI |
| GitHub Actions pinned to tags (`@v4`, `@v2`, `@v7`), not commit SHAs (Semgrep warnings in `ci.yml`, `release.yml`, `merge-bot.yml`) | In a public repo with a NuGet release secret, a moved tag could run changed code | Pin each action to its commit SHA |
| `.github/dependabot.yml` has no `cooldown` (Semgrep warning) | Freshly published packages get proposed at once | Add `cooldown: default-days: 7` to both ecosystems |
| Seven Dependabot PRs open (#1, #4, #8, #12–#15), some three months old | Each touches `.github/**` or a `.csproj`, so each needs `human-approved`; stale bumps pile up | Review and merge or close them; group updates in `dependabot.yml` |
| No `.githooks` pre-push hook | Failures are caught in CI instead of before the push | Add `.githooks/pre-push` and `.githooks/checks` as in the Playbook, running build, unit and architecture tests |

## Protocol gaps

| Gap | Needed for | Plan |
|---|---|---|
| Hosting contract (Coolify), staging, production deploy: **not applicable: library** | — | The "environment" is the NuGet package, released by the owner with a `v*` tag. A prerelease tag (`-alpha`, `-rc`) plays the role of staging |
| Commit SHA endpoint: **not applicable: library** | Deploy workflow | SourceLink already stamps the commit into the package; nothing to expose |
| The `dotnet` stack profile assumes an app (PostgreSQL, Coolify, Playwright E2E, one-command run); there is no library variant | Moving beyond L0 ("an app on a stack without a profile stays at L0") | Add a library variant to the profile: build, unit, architecture, mutation, public API snapshot, pack |
| No holdout scenarios | QA agent | For a library, scenarios would be consumer programs (sign with a provider's documented example, verify a captured webhook) run by the QA runner |
| No mutation gate | L2 gate | Baseline recorded in `project.yml`; set `mutation_score_changed_code` before L2 |
| No machine account fork, reviewer bot or taskrunner | Agents building unattended | Comes with the protocol platform |
