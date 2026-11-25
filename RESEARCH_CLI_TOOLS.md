# CI/CD Pipeline Security Scanners — Research Report for the New Python CLI

**Research date:** 25 Nov 2026.
**Method:** each tool's actual GitHub repo / README / docs / source was read
(via search, then reading the returned pages), plus official docs (docs.zizmor.sh,
checkov.io policy index, docs.github.com, jenkins.io, PyPI pages).
Four research batches were run in parallel by subagents and all four of
their full reports are incorporated here, together with first-hand
verification by the parent agent (zizmor audits page, Scorecard reports,
Checkov policy index, GHAST/PipeGuard searches, CredScan and Jenkins linter
docs were all opened and read directly). Where a claim comes only from a
subagent's report it is marked [subagent]; where it comes from earlier
project context it is marked [prior context].

> **⚠️ NAME WARNING — read first:** the planned name **"PipeGuard" is taken
> twice over in the exact same niche** (see §13). The user has already chosen
> the replacement name **PipeSentry** (0 GitHub results, fully free, chosen
> 19:35 PKT). This file keeps the `pipeguard/` working directory name it was
> tasked with, but the tool it designs for is **PipeSentry**.

## Contents

1. [zizmor](#1-zizmor--zizmorcorezizmor)
2. [OpenSSF Scorecard](#2-openssf-scorecard--ossfscorecard)
3. [Poutine](#3-poutine--boostsecurityiopoutine)
4. [Gato (+ Trajan / Gato-X)](#4-gato--praetorian-incgato)
5. [actionlint](#5-actionlint--rhysdactionlint)
6. [StepSecurity secure-repo (ex secure-workflows) + harden-runner; pinact is a separate tool](#6-stepsecurity-secure-repo-ex-secure-workflows--harden-runner-pinact-is-a-separate-tool)
7. [Checkov — GitHub Actions checks](#7-checkov--github-actions-checks--bridgecrewioCheckov)
8. [GHAST — four tools, one name](#8-ghast--four-tools-one-name)
9. [Credential scanners: CredScan, Gitleaks, TruffleHog, detect-secrets](#9-credential-scanners-credscan-gitleaks-trufflehog-detect-secrets)
10. [Jenkinsfile security linters](#10-jenkinsfile-security-linters)
11. [Octoscan (bonus)](#11-octoscan-bonus--synacktivoctoscan)
12. [GitHub's own starter-workflows / hardening guidance](#12-githubs-own-starter-workflows--hardening-guidance)
13. [Name collisions: "PipeGuard"](#13-name-collisions-pipeguard)
14. [Comparison matrix](#14-comparison-matrix)
15. [Synthesis: what every tool checks, what nobody checks, what PipeSentry should do](#15-synthesis)

---

## 1. zizmor — `zizmorcore/zizmor`

**One line:** the reference static analysis tool for GitHub Actions — the one
every other tool is compared against. Rust, MIT, created 2024-08-19,
**7,158 stars**, 97 releases, not archived. Also audits Dependabot and
pre-commit configs, not just workflows.

Current version seen in docs: **v1.33.1** (new audit `dangerous-checkout`
in v1.33.0; experimental workflow-lockfile support in v1.32.0).
**42 audits** counted on `docs.zizmor.sh/audits/` — each audit page lists
Type (Workflow / Action / Dependabot / pre-commit), version introduced,
works-offline ✅/❌, auto-fix ✅/⚠️/❌, configurable ✅/❌.

### 1.1 What it scans
- GitHub Actions workflow YAML (`.github/workflows/*.yml`), composite
  `action.yml`s, Dependabot config, pre-commit config.
- Inputs: individual files, local directories (`zizmor .`), **remote repos by
  slug** (`zizmor example/example`, `example/example@v1`, `example/example@<sha>`),
  or **stdin** (`cat workflow.yml | zizmor -`). Mixed inputs in one run.
- **No Jenkinsfile support.** No GitLab.
- Needs a GitHub token (`--gh-token`, `GH_TOKEN`) only for the **online audits**
  (`impostor-commit`, `known-vulnerable-actions`, `ref-confusion`, `typosquat-uses`);
  everything else works fully offline (`--offline`, `--no-online-audits`).

### 1.2 Exact audit names (from docs.zizmor.sh/audits/, read directly)
Each audit has severity + confidence, a docs page, and most have a working
offline mode. The security-relevant ones:

| Audit | What it catches |
|---|---|
| `template-injection` | `${{ ... }}` (e.g. `github.event.issue.title`) expanded inside `run:` → shell injection. The single biggest advisory bucket: 27 of 49 `ecosystem:actions` GHSA advisories (PyCon US 2026 study) |
| `dangerous-triggers` | `pull_request_target` / `workflow_run` + checkout of PR code — the pwn-request pattern |
| `excessive-permissions` | No `permissions:` block, or `write-all`, or broader scopes than the job needs. Fires when a workflow has no `permissions:` block at all (token inherits the repo default). ~102k PyPI repos hit |
| `unpinned-uses` | `uses:` not pinned by full 40-char SHA. **Since v1.20.0 the default is hash-pin on *all* actions**, including `actions/*` (previously first-party actions could be ref-pinned). Configurable policies in `zizmor.yml`: `hash-pin` / `ref-pin` / `any` per repo pattern, e.g. `actions/checkout: hash-pin`, `actions/*: ref-pin` |
| `artipacked` | `actions/checkout` persisting the git credential on disk (`.git/config` pre-v6, `$RUNNER_TEMP` in v6+); artifact upload of the credential. Fix: `persist-credentials: false` |
| `cache-poisoning` | Cache reads in release workflows; cache writes via privileged triggers / `cache-mode: write`. Aware of GitHub's `cache-mode` (v1.31.0+) |
| `impostor-commit` | A pinned SHA that does not belong to the claimed action repo (online) |
| `typosquat-uses` | Lookalike action names (online) |
| `known-vulnerable-actions` | A `uses:` ref with a published GitHub Security Advisory (online) |
| `ref-confusion` | Confusable git refs (online) |
| `archived-uses` | `uses:` pointing at an archived repo |
| `bot-conditions` | Spoofable bot checks like `github.actor == 'dependabot[bot]'` (should be `github.event.pull_request.user.login`) |
| `unredacted-secrets` | Secrets used as structured values, e.g. `${{ fromJSON(secrets.MY_SECRET).password }}` — the field is **not** redacted in logs |
| `unsound-condition` | `if:` with a fenced `${{ false }}` + trailing YAML newline → always true |
| `unsound-contains` | `contains('refs/heads/main refs/heads/develop', github.ref)` — substring bypass |
| `use-trusted-publishing` | Release workflows not using OIDC trusted publishing |
| `adhoc-packages` | `npm install <pkg>` / `gem install` / `bundle add` in `run:` — packages installed outside a locked manifest |
| `anonymous-definition` | Workflow/action with no `name:` (`--pedantic` only) |
| `dangerous-checkout` | `actions/checkout` with `allow-unsafe-pr-checkout: true` (checkout v7+ blocks fork-PR checkout on those triggers by default) — new in v1.33.0 |
| `secrets-inherit` | `secrets: inherit` on reusable-workflow calls |
| `overprovisioned-secrets` | Whole-context exposure, e.g. `SECRETS: ${{ toJSON(secrets) }}` — pass individual named secrets instead |
| `secrets-outside-env` | Secrets used outside a GitHub Environment (auditor persona only; `GITHUB_TOKEN` never flagged) |
| `hardcoded-container-credentials` | Docker registry username/password hardcoded in the workflow |
| `insecure-commands` | Re-enabling deprecated `::set-env`/`::add-path` via `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` |
| `github-env` / `github-app` | Untrusted data written to `$GITHUB_ENV`/`$GITHUB_PATH`; GitHub App token interpolated directly into shell instead of via `env:` |
| `self-hosted-runner` | PR-triggered jobs on self-hosted runners (pedantic) |
| `unpinned-images` | Container image not pinned to a tag ≠ `latest` (pedantic: not `@sha256:`) |
| `unpinned-tools` | Tool setup actions with `latest`/unset version (e.g. `aquasecurity/setup-trivy`, `1password/load-secrets-action`) |
| `stale-action-refs` | SHA pin whose `# vX.Y.Z` comment no longer matches any release (pedantic) |
| `ref-version-mismatch` | Stale/missing version comment on a pin |

Also counted on the audits page (not security-core, listed for completeness):
`concurrency-limits`, `dependabot-cooldown`, `dependabot-execution`,
`forbidden-uses` (opt-in), `insecure-url-scheme`, `misfeature`,
`obfuscation`, `self-repository`, `superfluous-actions`,
`undocumented-permissions` (pedantic — every explicit permission needs an
explanatory comment; `contents: read` exempt), `unsound-ternary`.

Also: `excessive-permissions` + `template-injection` together are the classic
"somebody else gets a release out of your repository" combination.
`dangerous-triggers` remediation: replace `pull_request_target` →
`pull_request`, `workflow_run` → `workflow_call`; "**Never** run
PR-controlled code in the context of a `pull_request_target`-triggered
workflow" (it also flags `issue_comment` since v1.31.0). With
`--persona=pedantic|auditor`, `template-injection` flags **all** expansions
in code contexts, even likely-safe ones; its auto-fix is unsafe. The
`template-injection` fix is to pass via `env:` and use shell expansion
`${ISSUE_TITLE}`, *not* `${{ env.ISSUE_TITLE }}`. `excessive-permissions`
remediation: `permissions: {}` at workflow level, then grant only needed
job-level permissions.

### 1.3 File + line numbers — YES, annotated source
Plain output is cargo-style annotated source with **1-based** line numbers;
`--format=json-v1` uses 0-based `row`; SARIF uses 1-based. Example JSON
finding (from docs):
```json
{
  "ident": "template-injection",
  "desc": "code injection via temp..."
}
```

### 1.4 Interface
CLI-args only — **no interactive menu**. Config file `zizmor.yml`
(discovered per input in order `.github/zizmor.yml` → `.github/zizmor.yaml`
→ `zizmor.yml` → `zizmor.yaml`; remote inputs look in the repo root;
`--no-config` skips it; JSON Schema published, also on SchemaStore).
Settings: `rules.<id>.disable: true`,
`rules.<id>.ignore: [ci.yml:100, tests.yml, pypi.yml:12:10]`,
`rules.<id>.config: {...}`, `rules.<id>.remap.severity: high` (v1.25.0+).
Inline suppression is `# zizmor: ignore[rule-name]` on the line (1-based
`filename.yml[:line[:column]]` coordinates; composite-action findings can
only be ignored inline, not via `zizmor.yml`). Personas: `regular`
(default, high-signal), `pedantic` (adds code smells, e.g.
`anonymous-definition`, `self-hosted-runner`, `stale-action-refs`,
`undocumented-permissions`), `auditor` (everything, incl.
`secrets-outside-env`). Also: `--collect=<all|default|workflows|actions|
dependabot|pre-commit>` (indirect collection; explicitly named files are
always audited), experimental `--lsp` (language-server mode for IDEs),
`--completions <bash|elvish|fish|nushell|powershell|zsh>`. Key flags:
```
zizmor .
zizmor --format=json . | jq .[0]
zizmor --format=sarif . > results.sarif
zizmor --format=github .            # PR annotations
zizmor --fix=all                    # safe + unsafe auto-fixes (pinning, persist-credentials, ...)
zizmor --offline --no-online-audits .
zizmor --strict-collection .        # fail if any collected file fails to parse
zizmor --collect=all .              # ignore .gitignore
```
Exit codes are CI-gateable: `0` no findings, `1` error, `2` arg-parse failure,
`3` no inputs collected (v1.21.0+), `11/12/13/14` findings whose worst severity
is informational/low/medium/high; suppressed by `--no-exit-codes`,
`--format=sarif`, or a fully successful `--fix`. Also ships as a GitHub
Action (`zizmorcore/zizmor-action`, online audits on by default because the
job already has a token), a pre-commit hook, and a Docker image
(`ghcr.io/zizmorcore/zizmor`).

### 1.5 Pinning model
Full 40-char SHA required by default (`unpinned-uses`, hash-pin policy for
all actions). The docs recommend keeping a `# vX.Y.Z` comment so humans and
Dependabot can read the version; zizmor's `--fix` rewrites tags to SHAs.
Remediation docs point at pinact, gha-update and frizbee as third-party
pinning tools.

### 1.6 Install model
Rust binary from GitHub Releases, **or `pip install zizmor`** (the Python
package bundles the binary — `uvx "zizmor@<version>"` is the documented CI
pattern), Homebrew, Docker. No Go, no Java.

### 1.7 Limitations
- GitHub Actions only — no Jenkins, GitLab, or generic YAML.
- Cannot see repo-level settings (workflow-permissions default, environment
  protection rules, branch protection) — YAML-only view.
- Online audits need a token and network; offline mode silently skips them
  (4 audits: `impostor-commit`, `known-vulnerable-actions`, `ref-confusion`,
  `stale-action-refs` — `--fix` cannot fix those four either).
- YAML anchors were historically buggy (crashes / wrong-location findings on
  aliased steps, e.g. issue #1770); a Trail of Bits 2026 hardening pass
  (41,253-workflow corpus, 15 PRs) brought anchor support to "full
  coverage", but anchors remain a documented edge.
- `template-injection` has a reported high false-positive rate in the wild;
  `pedantic`/`auditor` personas are intentionally noisy.
- Workflow lockfiles: experimental since v1.32.0, with documented
  limitations.
- No built-in score/grade; findings are per-audit severities, not a 0–100
  score (contrast Scorecard, §2).

---

## 2. OpenSSF Scorecard — `ossf/scorecard`

**One line:** repo-level security posture scoring, not a workflow linter. Go,
Apache-2.0, run by the OpenSSF. Latest version seen: **v5.6.0**.

### 2.1 What it scans
- A whole **repository** (local or remote, any host it can clone), not just
  workflow files: branch protection, code review, releases, dependencies,
  workflow tokens, etc. **No Jenkinsfile.**
- 19 checks in the default set (README table) incl. experimental `Webhooks`
  (Critical, needs a maintainer PAT with `admin:repo_hook`), each scored
  **0–10**, combined into a risk-weighted aggregate (Critical ×10, High
  ×7.5, Medium ×5, Low ×2.5). Checks are heuristics — the project warns of
  false positives and negatives. `docs/checks.md` additionally documents
  **`SBOM`** (Medium). Secondary guides variously say "18 default checks"
  vs "20 checks" — the discrepancy is `Webhooks` (experimental, not
  default) and `SBOM` (documented, absent from the README table); treat the
  count as version-dependent.

### 2.2 The Actions-relevant checks (exact names)
| Check | Risk | What it looks for |
|---|---|---|
| `Dangerous-Workflow` | Critical | Dangerous patterns in GitHub Actions workflows — the `pull_request_target` + checkout-PR-code anti-pattern, plus script injection with untrusted context variables (e.g. `github.event.issue.title`) and "logging github context and secrets". "no dangerous workflow patterns detected" = 10. **Binary-ish at repo level** (10 if clean, 0 if any dangerous workflow), not per-finding severity like zizmor — and it only counts trigger **+ explicit PR checkout**, so zizmor's `dangerous-triggers` is stricter here. No equivalent of zizmor's `unredacted-secrets` / `overprovisioned-secrets` / `artipacked`. |
| `Token-Permissions` | High | Least privilege on `GITHUB_TOKEN`. Highest score when each workflow sets read-only `permissions:` at top level; warns per file, e.g. `Warn: jobLevel 'contents' permission set to 'write': .github/workflows/main.yml:21`, `Warn: no topLevel permission defined: .github/workflows/lint.yml:1`. One point is reduced if all jobs have permissions defined but top-level permissions are not defined. **Limitation, stated in the docs:** "The check cannot detect if the 'read-only' GitHub permission setting is enabled, as there is no API available." |
| `Pinned-Dependencies` | Medium | Dependencies pinned to **hashes** in build files. Counts pinned vs unpinned separately for GitHub-owned and third-party actions, e.g. `Warn: third-party GitHubAction not pinned by hash: .github/workflows/main.yml:70`, `Info: 4 out of 4 GitHub-owned GitHubAction dependencies pinned`. Also flags `downloadThenRun` (curl \| sh) unpinned. Remediation links point to StepSecurity's secure-workflows app: `https://app.stepsecurity.io/secureworkflow/<owner>/<repo>/<file>/<branch>?enable=pin`. **More lenient than zizmor:** a `uses:` ref to a tag is also treated as pinned when that tag is backed by a published **immutable release**, and Go modules count as pinned with a full semantic version. Scoring is **proportional, not binary** (e.g. `8 / 10` when some deps are unpinned). |
| `Binary-Artifacts` | High | Generated binaries committed to the repo |
| `Code-Review` | High | Human review before merge |
| `SAST` | Medium | A SAST tool run on all commits |
| `Security-Policy` | Medium | Published `SECURITY.md` |

Other checks (not Actions-specific): Branch-Protection, Vulnerabilities
(OSV), Maintained, Licence, Fuzzing, Packaging, Signed-Releases, CII-Best-Practices.

### 2.3 File + line numbers — YES, in details
Each check's `Details` list gives `file:line`, e.g.
`.github/workflows/main.yml:70`. Scores are per-check, not per-finding —
there is no per-finding severity beyond the check's risk level.

### 2.4 Interface
CLI-args only — **no interactive menu**. No config file for checks (checks
are fixed; only repo selection and token are inputs):
```
scorecard --repo=github.com/<owner>/<repo>
scorecard --local=. --format=json
```
Output: human text, **JSON**, **SARIF** (via the Scorecard GitHub Action,
`ossf/scorecard-action` v2.4.x, `results_format` `json` | `sarif` | `intoto`,
which uploads to code scanning; `publish_results` controls public posting).
SARIF is only produced by the Action, not the CLI (`--format` on the CLI is
only `default`/`json`). Web viewer: `scorecard.dev/viewer/?uri=github.com/<owner>/<repo>`.
There is **no general config file** to disable/tune checks — the only
repo-side file is the experimental **Maintainer Annotations** file
(`scorecard.yml` / `.scorecard.yml` / `.github/scorecard.yml`), with
`exemptions:` per check (`binary-artifacts`, `dangerous-workflow`, …) and
annotations (`test-data`, `remediated`, `not-applicable`, `not-supported`,
`not-detected`); annotations suppress SARIF alerts in the Action but do not
change the numeric score. Also available as an MCP server (`scorecard mcp`,
over stdio, reads the REST API, no scan). **Windows is not supported**
("Currently, Scorecard supports OSX and Linux…"). It scores a *remote repo*
(`--repo=…`), not a directory of YAML you hand it — there is no local-file
mode, no `--fix`, no menu. Weekly public scans omit 3 checks (`CI-Tests`,
`Contributors`, `Dependency-Update-Tool`).

### 2.5 Pinning model
Hash-pinned counts as pinned; a tag or version range does not. It counts
GitHub-owned and third-party actions separately, and also covers Dockerfiles
and `curl | sh` installers. It does **not** rewrite or fix pins — it links
out to StepSecurity to do that.

### 2.6 Install model
Prebuilt Go binary from GitHub Releases, Docker, or the GitHub Action.
Needs a token for private repos / higher API rate limits. No pip.

### 2.7 Limitations
- Posture scoring, not a linter: it will not tell you *which line* has a
  `${{ }}` injection, and it has no template-injection check at all.
- Needs repo/API access for several checks; local-only runs lose checks.
- No Jenkins, no auto-fix, no baseline mode (scores move as the repo changes).

---

## 3. Poutine — `boostsecurityio/poutine`

**One line:** defensive static supply-chain scanner for **build pipelines**,
written in Go by BoostSecurity.io. Apache-2.0, created 2024-04-09, ~540
stars, latest seen v1.1.6 (May 2026), active. [subagent]

### 3.1 What it scans
- **GitHub Actions** workflows + composite `action.yml`s, **GitLab CI,
  Azure DevOps, and Tekton (Pipelines-as-Code)** — the only tool here that
  is multi-platform. **No Jenkins/Jenkinsfile support.**
- Scope: a local checkout, a single remote repo, or an **entire org**
  (`analyze_org` scans all repos in parallel via shallow, sparse checkout
  of YAML only). Also builds an **inventory/SBOM of build-time dependencies**
  (actions, GitLab imports, Docker images as PURLs) and checks them against
  **OSV for known CVEs**.
- Needs only a **read-only token** (`GH_TOKEN`) for remote/org scans; local
  scans need no token.

### 3.2 Commands / interface
CLI-args only — **no interactive menu**. Subcommands:
```
poutine analyze_local .
poutine analyze_repo org/repo --token "$GH_TOKEN"
poutine analyze_org org --token "$GH_TOKEN"
poutine analyze_org my-org/project --token "$GL_TOKEN" --scm gitlab --scm-base-url https://gitlab.example.com
```
Key flags: `--format` (pretty/json/sarif), `--token`, `--scm`
(github/gitlab), `--scm-base-url`, `--threads` (default 2), `--config`,
`--skip <rule>` (repeatable), `--ignore-forks`, `--verbose`,
`--fail-on-violation` (exit code **10**), `--disable-version-check`.

### 3.3 Exact rule names (13 built-in rules)
| Rule ID | Rule name | What it catches |
|---|---|---|
| `injection` | Injection with Arbitrary External Contributor Input | `${{ }}` interpolation of attacker-controlled input in `run:` — the script-injection check |
| `untrusted_checkout_exec` | Arbitrary Code Execution from Untrusted Code Changes | **Signature rule.** Knows which build tools execute code from the working tree (`npm install`, `make`, `pip`, … — catalogued in BoostSecurity's Living Off The Pipeline project) and flags them when they run on a checkout of PR code in a privileged workflow (`pull_request_target`, `workflow_run`, etc.). The pwn-request pattern, modelled as untrusted-checkout + privileged execution, not a literal trigger string match |
| `pr_runs_on_self_hosted` | Pull Request Runs on Self-Hosted GitHub Actions Runner | PR-triggered jobs on `self-hosted` runners |
| `default_permissions_on_risky_events` | Default permissions used on risky events | Missing/overly broad `permissions:` on risky triggers. Known false positive: fires on a job with `permissions: {}` (empty = none to GitHub) |
| `job_all_secrets` | Workflow job exposes all secrets | `secrets: inherit` / all-secrets exposure to a job |
| `unverified_script_exec` | Unverified Script Execution | `curl \| bash`-style remote script execution |
| `unpinnable_action` | Unpinnable CI component used | See §3.6 — **not** a plain "unpinned" rule |
| `github_action_from_unverified_creator_used` | Github Action from Unverified Creator used | Severity `note`; action owner is not a GitHub Verified Creator |
| `known_vulnerability_in_build_component` | Build Component with a Known Vulnerability used | OSV CVE lookup on actions/build deps |
| `known_vulnerability_in_build_platform` | Build Platform with a Known Vulnerability used | Same for the platform itself |
| `debug_enabled` | CI Runner Debug Enabled | `ACTIONS_STEP_DEBUG` / runner debug |
| `if_always_true` | If condition always evaluates to true | Dead/tautological `if:` |
| `confused_deputy_auto_merge` | (auto-merge confused deputy) | Dangerous auto-merge configurations |

**Coverage gaps vs. the requested checklist:** no rule literally named for
`pull_request_target` alone (folded into `untrusted_checkout_exec` /
`default_permissions_on_risky_events`); **no dedicated secrets-in-logs /
secret-exfiltration rule** (closest is `job_all_secrets`); **no
`workflow_dispatch`-abuse rule**; no Jenkins.

### 3.4 File + line numbers — YES
Findings carry `path` + `line` (+ `job`, `step`). Example summary output
(real run, via blog.kammel.dev):
```
Summary of findings:
| RULE ID                   | RULE NAME                        | FAILURES | STATUS |
| github_action_from_unverified_creator_used | Github Action from Unverified Creator used | 3 | Failed |
| untrusted_checkout_exec   | Arbitrary Code Execution from Untrusted Code Changes | 0 | Passed |
```
Each finding links to its rule doc page, e.g.
`https://boostsecurityio.github.io/poutine/rules/github_action_from_unverified_creator_used`.

### 3.5 Output formats / config
- `--format pretty` (default, human table), `json`, `sarif` (uploadable via
  `github/codeql-action/upload-sarif`, `sarif_file: results.sarif`). No HTML.
- **Config file:** `.poutine.yml` (or `.github/poutine.yml`, auto-discovered;
  `--config` overrides). Supports `skip:` entries filtered by `job` / `level`
  (note/warning/error) / `path` / `rule` / `purl` / `osv_id`; and `include:`
  paths for **custom Rego rules** (`package rules.<name>`, `*.rego`,
  evaluated by an embedded OPA engine). **No inline ignore comments** —
  `# poutine:ignore <rule>` in a workflow is inert; suppression is only via
  `.poutine.yml` / `--skip`.
- Extras: pre-commit hook, own GitHub Action
  (`boostsecurityio/poutine-action`), MCP integration. Telemetry note: a
  once-per-24h version check sends version + anonymous instance ID (disable
  via `--disable-version-check` / `POUTINE_DISABLE_VERSION_CHECK=1`).

### 3.6 How it checks pinning
**Important nuance: Poutine has no plain "action not pinned to SHA" rule**
(unlike zizmor/GHAST). Pinning is handled two indirect ways:
- `unpinnable_action` — flags components where **pinning does not guarantee
  immutability**, typically composite actions whose own steps use `@v3` tags,
  or Docker actions using `:tag` instead of `@sha256:…` digests. Docs: *"if a
  component … depends on other components, which can be compromised, pinning
  it does not effectively mitigate the risks"*, and *"Pinning is NOT a silver
  bullet."* Remediation: replace with a pinnable alternative, fork/vendor it,
  or ask the maintainer.
- `known_vulnerability_in_build_component` — resolves the pinned version and
  checks OSV, so a pinned-but-vulnerable action still fires.
- So: a workflow using `actions/checkout@v4` (tag, no SHA) is **not** flagged
  by Poutine as "unpinned" — that gap is why guides pair it with
  zizmor/pinact.

### 3.7 Install model
Prebuilt Go binary from GitHub Releases, Homebrew (`brew install poutine` /
`brew install boostsecurityio/tap/poutine`), Docker
(`docker run -e GH_TOKEN ghcr.io/boostsecurityio/poutine:latest`), GitHub
Action, pre-commit, or build from source (Go 1.26+ per current README).
No pip.

### 3.8 Limitations
- Not a generic workflow linter: no "unpinned action" rule, no
  `pull_request_target`-only rule, no secrets-in-logs rule, no Jenkins.
- Org scans need a token and API access; findings are static (no
  exploitation/proof).
- `default_permissions_on_risky_events` false positive on `permissions: {}`.

---

## 4. Gato — `praetorian-inc/gato`

**One line:** an **offensive enumeration + exploitation tool** for GitHub
Actions, **not a static linter**. Python, Apache-2.0, created 2023-01-06.
[subagent]

> **⚠️ Status: the repo is now deprecated and ARCHIVED** — "No further
> updates, bug fixes, or security patches will be made". Praetorian directs
> users to its successor **Trajan** (`praetorian-inc/trajan`, merges Gato +
> GitLab's Glato). The actively maintained fork is **Gato-X**
> (`AdnaneKhan/gato-x`, `pip install gato-x`, Python 3.10+, adds TOCTOU
> detection, cross-repo/reusable-workflow analysis, deployment-environment
> secrets; claims 35–40k repos in 1–2 h with one PAT).

### 4.1 What it scans
- **GitHub Actions only** (no Jenkins, GitLab, etc.). Targets: a single repo,
  an org, or a list of repos/orgs from a file. Works against **public and
  private repos** via a GitHub **classic PAT** (`GH_TOKEN`) or a GitHub App
  installation token (min `Actions:read` + `Contents:read` for enumeration).
- Two data sources, deliberately combined: **static workflow-file analysis**
  (sparse clone + parse `.github/workflows/*.yml`) **and workflow run-log
  analysis** (parses run logs to discover self-hosted runner names —
  including non-ephemeral runners, v1.6+).
- Also enumerates **what a compromised classic PAT can do** (PAT privilege
  enumeration — blast radius of a stolen token) and, in v1.7, scans
  **workflow artifacts for secrets**.

### 4.2 Subcommands (no rule IDs, no severity levels — it finds exploitable paths)
```
gato search -h | gato enum -h | gato attack -h        # also: gato s / e / a
```
- **`gato search`** — finds candidate repos at scale via the GitHub Code
  Search API and/or **SourceGraph** (`--sourcegraph`/`-sg`, e.g.
  `gato search --sourcegraph --output-text public_repos.txt`, or a raw query
  like `'count:75000 /(issue_comment|pull_request_target|issues:)/ file:.github/workflows/ lang:yaml'`). Output: text file of repos.
- **`gato enum` / `gato enumerate`** — the scanner. Examples:
  `gato enumerate --target octocat`,
  `gato e --enum_wf_artifacts --include_all_artifact_secrets --skip_sh_runner_enum -O testorgs.txt -oJ testorgoutput.json`.
  Detects: **Pwn Requests** (`pull_request_target` + checkout of PR code
  with secrets/permissions), **Actions/script injection** (`${{ }}`
  interpolation of untrusted event data into `run:`), and **self-hosted
  runners** (from `runs-on: self-hosted` in YAML and from run logs). Flags:
  `--enum_wf_artifacts`, `--include_all_artifact_secrets`,
  `--skip_sh_runner_enum`, `-R/--repositories`, `-O` (orgs file),
  `-oJ/--output-json`.
- **`gato attack`** — the exploitation module (requires authorization).
  Examples: `gato attack --target octocat/gato-demo-repo --secrets`
  (creates a workflow that **exfiltrates all secrets accessible to the
  run**); **Runner-on-Runner (RoR)** takeover — installs a second
  self-hosted runner on the compromised host registered to the attacker's
  org, giving persistent interactive access. Other attack features:
  **Automated Command Execution via Fork PR Creation**, **Automated Command
  Execution via Workflow Creation**. On success RoR drops to an
  **interactive shell prompt on the runner**. Real-world proof: used against
  PyTorch (self-hosted runner, root via `sudo -l`) — StepSecurity write-up.
- **v1.7 Actions Artifacts Secrets Scanner:** downloads workflow artifacts
  (max 50/repo, 1 per name, skips files >2.68 GB, max 10 files >536 MB),
  recursively extracts, scans with **NoseyParker** (must be installed on
  `$PATH`); default exclusions suppress common false positives
  (`--include_all_artifact_secrets` overrides). Praetorian used it to find
  critical secret leaks in prominent OSS projects.

### 4.3 File + line numbers — effectively NO
Findings are reported **per repository / workflow / runner**, not per
file:line. No SARIF, no rule ID, no severity — output is console text plus
optional **JSON** (`-oJ`) "intended for further machine analysis". Gato-X's
own docs warn it is "tuned to avoid false negatives" and "will have a higher
false positive rate than SAST tools like CodeQL" — the operator triages.

### 4.4 Interface / config / output
- CLI-args only, **no interactive menu** (except the post-exploitation
  interactive shell on a pwned runner), **no config file**, **no SARIF/HTML**.
  Proxy support: SOCKS5 + HTTPS.
- Token via `GH_TOKEN` env var or interactive prompt.

### 4.5 Pinning
**No pinning check at all.** Gato does not care whether actions are pinned;
it cares whether a workflow is *exploitable* (pwn request / injection /
runner takeover). Pinning hygiene is out of scope.

### 4.6 Install model
Clone + `pip install .` in a venv; binary is `gato` / `praetorian-gato`.
**macOS/Linux only, Python 3.7+; requires `git` ≥ 2.27 on PATH, and `sed`
for the fork-PR attack module.** No PyPI package for original Gato (Gato-X
is `pip install gato-x`). No Docker image, no GitHub Action.

### 4.7 Limitations (state clearly)
- **Offensive/enumeration tool, not a static linter:** no rules, severities,
  SARIF, or line numbers; cannot be dropped into CI as a pass/fail gate the
  way Poutine/GHAST can. `search`/`enum` are safe on public repos; `attack`
  mutates the target (creates PRs/workflows, exfiltrates secrets) and
  **requires written authorization**.
- **Archived/deprecated** — use Trajan or Gato-X instead; no Windows support.
- No checks for overly broad `permissions:`, unpinned actions,
  `workflow_dispatch` abuse, or secrets-in-logs as static findings (secrets
  work is *active exfiltration* or artifact scanning, not log-pattern
  detection). Artifact secret scanning has many false positives by the
  authors' own admission.
- Needs a live token + network/API access; cannot scan a local checkout
  offline.

---

## 5. actionlint — `rhysd/actionlint`

**One line:** the **correctness linter** for GitHub Actions workflow files —
syntax, expressions, action inputs — with security checks bolted on. Go, MIT,
by rhysd. Latest release seen v1.7.12.

### 5.1 What it scans
- GitHub Actions workflow YAML (`.github/workflows/*.yml` / `*.yaml`) and
  composite actions under `.github/actions/`. Auto-discovers files from the
  repo root — it takes **no file arguments** by design
  (`actionlint` or `actionlint .github/workflows/ci.yml`).
- **No Jenkinsfile.** No GitLab.

### 5.2 Checks (~40, each with an example in the docs)
~37 checks. Rule "kinds" appear in brackets at the end of each finding:
`syntax-check`, `expression`, `shellcheck`, `pyflakes`, `job-needs`,
`matrix`, `events`, `runner-label`, `action`, `workflow-call`,
`credentials`, `env-var`, `permissions`, `shell-name`, `id`, plus `cron`,
`glob`, `needs`, `if`, `job`, `env`, `deprecated-commands` and more.
**Script injection is reported under the `[expression]` kind, not a
dedicated security kind.**
- **Script injection by untrusted inputs** — the strongest security check
  here. It keeps a hardcoded list of untrusted properties and flags them
  when used directly in `run:` or in `actions/github-script`'s `script:`
  input: `github.event.issue.title/body`, `github.event.pull_request.title/body`,
  `github.event.comment.body`, `github.event.review.body`,
  `github.event.review_comment.body`, `github.event.pages.*.page_name`,
  `github.event.commits.*.message`, `github.event.head_commit.message`,
  `github.event.head_commit.author.email/name`,
  `github.event.commits.*.author.email/name`,
  `github.event.pull_request.head.ref`, `github.event.pull_request.head.label`,
  `github.event.pull_request.head.repo.default_branch`, `github.head_ref`.
  It also follows object filters (`toJSON(github.event.*.body)`) and exempts
  boolean functions `contains()`/`startswith()`/`endswith()`. Real output:
  ```
  test.yaml:10:24: "github.event.pull_request.title" is potentially untrusted. avoid using it directly in inline scripts. instead, pass it through an environment variable. see https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks for more details [expression]
  ```
  The suggested fix is passing the value via `env:`.
- **Expression type checks:** knows the type of every context
  (`github.repository` is a string, so
  `github.repository.permissions.admin` is an error).
- **Action inputs:** built-in dataset covers 100+ popular actions — missing
  required input or misspelled input (`node_version` vs `node-version`) is
  reported; also flags action versions whose Node.js runtime GitHub no longer
  supports (e.g. `actions/checkout@v3`).
- **Runner labels:** knows GitHub-hosted labels (incl. recent `macos-26-intel`,
  `ubuntu-slim`) and generic self-hosted labels; resolves
  `runs-on: ${{ matrix.os }}`; reports conflicting combinations.
- **Deprecated commands:** `set-output`, `save-state`, `set-env`, `add-path`
  (deprecated Oct 2022 in favour of `$GITHUB_OUTPUT` / `$GITHUB_STATE`).
- **Permissions `[permissions]`:** validates only that scopes and levels are
  *valid* — e.g. `permissions: write` → `"write" is invalid for permission
  for all the scopes. available values are "read-all", "write-all" or {}`;
  unknown scope `check` → lists all valid scopes (`actions`,
  `artifact-metadata`, `attestations`, `checks`, `contents`, `deployments`,
  `discussions`, `id-token`, `issues`, `models`, `packages`, `pages`,
  `pull-requests`, `repository-projects`, `security-events`, `statuses`);
  `models: write` → only `read`/`none` allowed. **It does NOT flag overly
  broad permissions** — `write-all` is perfectly valid to it.
- **Credentials `[credentials]`:** only for `container:` / `services:`
  `password:` written literally instead of via secrets: `"password" section
  in "container" section should be specified via secrets. do not put password
  value directly [credentials]`.
- **shellcheck + pyflakes:** runs shellcheck on the shell inside every `run:`
  block (SC2086 unquoted var, SC2129 redirects, SC2046 command substitution)
  and pyflakes on Python scripts. Idiomatic Actions patterns like
  `>> "$GITHUB_ENV"` trip generic shellcheck rules, so repos silence that
  class in config.
- **What it does NOT check:** no `pull_request_target` / pwn-request rule, no
  permissions analysis, no pinning rule, no self-hosted-runner security rule.
  It is a correctness tool first; zizmor is its security complement
  (WordPress's published standard runs **both**: actionlint for correctness,
  zizmor for security).

### 5.3 File + line numbers — YES, with columns
Output format:
```
<file>:<line>:<col>: <message> [<rule>]
```
`-oneline` prints one line per error. `# actionlint-ignore` inline comments
suppress specific rules; shellcheck rules can be suppressed with
`# shellcheck disable=...`.

### 5.4 Interface
CLI-args only — **no interactive menu**. Bare `actionlint` auto-discovers
workflows; `actionlint path/to/workflow.yaml ...`; `cat file | actionlint -`
reads stdin. Flags (from `docs/usage.md`): `-ignore '<regex>'` (repeatable,
RE2, matched against message), `-shellcheck=` / `-pyflakes=` (paths; empty
string disables), `-format '<Go template>'`, `-color`, `-oneline`,
`-verbose`, `-version`, `-config-file`, `-init-config`. Exit codes: `0`
clean, `1` problems found, `2` bad option, `3` fatal error. Config file
(optional): `.github/actionlint.yaml` or `.github/actionlint.yml`
(generate with `actionlint -init-config`). Only three settings:
`self-hosted-runner.labels` (glob patterns allowed), `config-variables`
(strict `vars.*` checking; `null` disables), `paths: <glob>: ignore:
[regexes]`. Also usable as a Go library, via Docker (image bundles
shellcheck + pyflakes), pre-commit hook, reviewdog
(`reviewdog/action-actionlint`), Problem Matchers
(`.github/actionlint-matcher.json`), super-linter, and a WASM online
playground at `rhysd.github.io/actionlint/`.

### 5.5 Pinning model
No pinning rule of its own. It *knows* action versions (flags unsupported
Node runtimes) but does not require SHAs. Pinning is left to zizmor/pinact.

### 5.6 Install model
Single Go binary: `go install github.com/rhysd/actionlint/cmd/actionlint@latest`,
Homebrew, Chocolatey (`choco install actionlint`), Scoop, Winget, mise
(`"github:rhysd/actionlint" = "v1.7.7"`), Docker. No pip.

### 5.7 Limitations
- Correctness, not security: no permissions, no pwn-request, no pinning.
- Shellcheck false positives on idiomatic Actions shell (`$GITHUB_ENV` etc.)
  need config silencing.
- No native JSON/SARIF/JUnit flags — instead `-format` takes a Go template,
  and the docs give examples for JSON (`actionlint -format '{{json .}}'`),
  JSON Lines, Markdown, GitHub `::error` annotations, and SARIF (template
  linked from test data, not inlined in the docs). Error objects expose
  `Message`, `Snippet`, `Kind`, `Filepath`, `Line`, `Column`, `EndColumn`.
- No auto-fix, no severity levels (all findings are errors), no score.
- shellcheck/pyflakes must be installed separately (except in the Docker
  image); disabling them makes it much faster.
- The popular-action dataset is compiled into the binary, so actions
  released after your version aren't covered.
- Type checking is stricter than the GitHub runtime, so it can report things
  GitHub would accept.

---

## 6. StepSecurity secure-repo (ex secure-workflows) + harden-runner; pinact is a separate tool

**One line:** StepSecurity is a **hardener/fixer**, not a scanner — it
rewrites workflows to be safe and pins actions for you. The repo is
`step-security/secure-workflows`.

### 6.1 What it is

**Important naming correction:** the project was originally
`step-security/secure-workflows` and is now **`step-security/secure-repo`**
(same code/catalog; the old README survives in forks). The hosted app is
`app.stepsecurity.io/securerepo`. It is **not a scanner/linter at all — it
is an auto-remediator**: it takes a workflow YAML in and returns a
*rewritten* workflow YAML (or opens a PR with the fix). There are no check
IDs, no findings list, no severities, no line numbers.

- **secure-repo** — the "Catalog of Fixes" (README, 8 items):
  1. **Automatically set minimum `GITHUB_TOKEN` permissions** — the
     signature feature. It looks up each action used in the workflow in a
     **knowledge base** (`knowledge-base/actions/<owner>/<repo>/action-security.yml`),
     sums the permissions, and writes least-privilege `permissions:` at
     workflow level (`contents: read` by default) and job level with
     `# reason` comments. Example KB entry for `peter-evans/close-issue`:
     ```yaml
     github-token:
       action-input:
         input: token
         is-default: true
       permissions:
         issues: write
         issues-reason: to close issues
     ```
     KB entries also support `environment-variable-name` (token via env
     var), conditional scopes (`<scope>-if: ${{ ... }}`), and a "token not
     used" case. Action owners contribute their own `action-security.yml`.
     The Go API surface confirms this:
     `remediation/workflow/metadata.GetActionKnowledgeBase(action)`,
     `remediation/workflow/permissions.AddJobLevelPermissions` /
     `AddWorkflowLevelPermissions`, and a `SecureWorkflowReponse` struct
     with fields `PinnedActions`, `AddedHardenRunner`, `AddedPermissions`,
     `MissingActions`, `JobErrors`, `AlreadyHasPermissions`.
  2. **Add Harden-Runner to each job** — inserts `step-security/harden-runner`
     as the first step of every job.
  3. **Pin Actions to a full-length commit SHA** — resolves each mutable
     tag/branch via the GitHub API to its commit SHA and rewrites `uses:`;
     the version is kept readable in a `# v4` comment in the PR examples.
     Docker images likewise pinned to digests.
  4. **Pin image tags to digests in Dockerfiles** — e.g. `rust:latest` →
     `rust:latest@sha256:02a53e...` via Docker registry APIs.
  5. **Add/update Dependabot config** — adds missing ecosystems (incl.
     `github-actions`) to `dependabot.yml`, so pinned SHAs keep getting
     bumped.
  6. **Add CodeQL workflow** (from `workflow-templates/`, language
     placeholder replaced per repo).
  7. **Add dependency-review workflow.**
  8. **Add OpenSSF Scorecard workflow.**
  Scorecard's `Pinned-Dependencies` remediation links point exactly here —
  that is how most people meet it.
- **`step-security/harden-runner`** — a GitHub Action (not a scanner) that
  installs a runtime security agent on the runner, "like an EDR for CI
  runners": monitors network/file/process activity, detects compromised
  dependencies and DNS exfiltration/cryptomining, and enforces network
  egress. Inputs: `egress-policy: audit` (log only — start here) or `block`
  (deny everything not in `allowed-endpoints`, a `host:port` list, e.g.
  `registry.npmjs.org:443`), plus `disable-sudo`,
  `disable-file-monitoring`. Community tier is free for public repos on
  GitHub-hosted runners; it secures "over 25 million workflow runs every
  week" per its README, and is credited with catching the
  tj-actions/changed-files (CVE-2025-30066), Trivy, and axios compromises.
  Secure-repo adds it in audit mode by default.
- **⚠️ Correction: `pinact` is NOT StepSecurity.** `pinact` is a separate
  tool by suzuki-shunsuke (`github.com/suzuki-shunsuke/pinact`), not a
  StepSecurity project. It is a Go CLI that *rewrites* workflow files to pin
  actions/reusable workflows to full SHAs (`pinact run`, verify-only
  `pinact run --verify`, `--min-age 7` cooldown refusing pins younger than
  N days, config `.pinact.yaml` incl. global config at
  `~/.config/pinact/pinact.yaml`, SARIF output, PR review comments via
  `pinact run -review`, GitHub Enterprise Server support with optional
  fallback to github.com). It pins without changing the underlying SHA
  except for safe semver updates. It is the natural companion to
  secure-repo (which does one-off pinning) for *ongoing* pin enforcement,
  but it is a different author, repo, and install:
  ```
  pinact run                    # rewrite every tag pin to SHA + trailing comment, in place
  pinact run --check            # print the diff, exit 1 while any uses: is unpinned (CI gate)
  pinact run --verify           # resolve each comment's tag; rewrite comments whose tag moved
  ```
  Example output:
  ```
  .github/workflows/ci.yml:7
  -       - uses: actions/checkout@v7.0.1
  +       - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  ```
  Install: Homebrew/Scoop, or `go install github.com/suzuki-shunsuke/pinact/v4/cmd/pinact@latest`.

### 6.2 What it scans / checks
- It does not "scan" with findings — it **fixes**: SHA-pinning (full
  40-char SHA + `# vX.Y.Z` comment; the comment is what Dependabot,
  `pinact run --verify` and zizmor read to know which release the SHA is
  supposed to match), permissions tightening, Harden Runner insertion.
- **pull_request_target + checkout / pwn-request:** **not detected, not
  fixed.** Nothing in the catalog analyses triggers or checkout
  configuration.
- **Script injection / secrets in logs:** **not detected.** No `${{ }}`
  analysis at all.
- **Overly broad permissions:** **this is its core strength** — it actively
  *rewrites* permissions to the KB-computed minimum rather than merely
  flagging them.
- **Unpinned actions:** **its other core strength** — auto-pins to full
  40-char SHAs (and Docker digests).
- The fix it cannot do: rewriting a `run:` block that interpolates untrusted
  input — that needs a human (or zizmor + a model, per the DevToCash agent
  write-up).

### 6.3 Pinning model
Full 40-char commit SHA, version in trailing comment only. SHA resolution:
`git ls-remote https://github.com/<owner>/<action> refs/tags/vX.Y.Z`.
A SHA pin nobody updates rots — Dependabot reads the `# vX.Y.Z` comment and
opens PRs bumping SHA + comment together.

### 6.4 Interface / install
- secure-repo: **no CLI menu, no interactive menu.** Three ways to use it:
  (a) hosted web app at `app.stepsecurity.io/securerepo` — paste repo, log
  in with GitHub (no app install / no write access needed), click "Create
  pull request"; (b) the original paste-YAML web flow at
  `app.stepsecurity.io` (paste workflow → "Secure Workflows" → paste fixed
  YAML back); (c) self-hosted — deploy `cloudformation/ecr.yml` +
  `cloudformation/resources.yml` in your AWS account; the repo itself is a
  Go program/API (`secure-repo` command on pkg.go.dev). There is **no
  per-repo config file**; the knowledge base *is* the configuration, and it
  lives in the repo. Selection of which fixes to apply is via the web UI,
  not flags.
- pinact: Go binary CLI, args only, no menu, config file `.pinact.yaml`
  (incl. global `~/.config/pinact/pinact.yaml`), SARIF output, PR review
  comments via `pinact run -review`, GitHub Enterprise Server support.
- harden-runner: GitHub Action (`step-security/harden-runner@<sha> # vX.Y.Z`,
  `with: { egress-policy: audit }`).

### 6.5 Limitations (for PipeSentry's design)
- A fixer, not an auditor: no finding list, no severities, no file:line
  report, no score. It cannot tell you *what* is wrong with a workflow you
  did not ask it to rewrite; it can't gate CI on "no new issues."
- Permission minimisation is only as good as KB coverage — unknown actions
  land in `MissingActions` and get no permissions (the KB depends on action
  owners contributing `action-security.yml`).
- Fixes nothing about triggers (`pull_request_target`), script injection,
  secrets handling, or cache poisoning.
- Hosted flow requires GitHub login and (for the PR flow) public repos;
  self-hosting means running AWS infrastructure.
- Harden-runner egress `block` mode needs a measured allowlist (run `audit`
  first for a release cycle or two); jobs that legitimately hit arbitrary
  URLs can't use `block`. Historically Ubuntu-focused; current README lists
  Linux, Windows, and macOS runners.
- Pinning trusts whatever SHA GitHub returns for a tag at conversion time;
  drift is only caught by later `--verify` runs.

---

## 7. Checkov — GitHub Actions checks — `bridgecrewio/checkov`

**One line:** the giant Python IaC scanner (1000+ checks, 20+ frameworks);
its GitHub Actions framework is small — **7 job checks + 1 graph check** —
and weaker than the dedicated Actions tools. Version seen in sources: 3.4.0
(28 Oct 2026); ~9,122 stars; Apache-2.0.

### 7.1 What it scans
- GitHub Actions workflow YAML (plus Terraform, CloudFormation, K8s, Helm,
  Dockerfiles, GitLab CI, etc. — the GHA framework is one of many).
- Command: `checkov -d . --framework github_actions` or
  `checkov --file .github/workflows/deploy.yml --framework github_actions`.

### 7.2 Exact GHA checks (from the checkov.io auto-generated policy index — authoritative)
| Check ID | Policy | File in repo |
|---|---|---|
| `CKV_GHA_1` | Ensure `ACTIONS_ALLOW_UNSECURE_COMMANDS` isn't true on environment variables | `AllowUnsecureCommandsOnJob.py` | Fails if `env.ACTIONS_ALLOW_UNSECURE_COMMANDS` is truthy at job or step level (`supported_entities=('jobs','jobs.*.steps[]')`) |
| `CKV_GHA_2` | Ensure run commands are not vulnerable to shell injection | `ShellInjection.py` | For each step with `run:`, regex-searches the raw `run:` string against a `bad_inputs` list of untrusted `github.event…` patterns (`for term in bad_inputs: if re.search(term, run): FAILED`). Pure text regex, not expression parsing |
| `CKV_GHA_3` | Suspicious use of curl with secrets | `SuspectCurlInScript.py` | Fails if any single line of `run:` contains **both** `curl` and `secret` (case-sensitive substring match) |
| `CKV_GHA_4` | Suspicious use of netcat with IP address | `ReverseShellNetcat.py` | Regex `(nc\|netcat) (\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})` (dots unescaped) against `run:` |
| `CKV_GHA_5` | Found artifact build without evidence of cosign sign execution in pipeline | `CosignArtifacts.py` | Job-level: if any step is a known build action/command (lists in `checkov/github_actions/common/build_actions.py` / `artifact_build.py`), fails unless a later step's `run:` contains `cosign sign` |
| `CKV_GHA_6` | Found artifact build without evidence of cosign sbom attestation in pipeline | `CosignSBOM.py` | Same build detection; passes only if a step's `run:` contains both `cosign` and `sbom` |
| `CKV_GHA_7` | The build output cannot be affected by user parameters other than the build entry point and the top-level source location. GitHub Actions `workflow_dispatch` inputs MUST be empty. | `EmptyWorkflowDispatch.py` | Entity `on`: fails if `workflow_dispatch.inputs` is a non-empty dict; passes for a bare `workflow_dispatch` trigger |
| `CKV2_GHA_1` | Ensure top-level permissions are not set to `write-all` | `graph_checks/ReadOnlyTopLevelPermissions.yaml` | Graph (YAML-policy) check on the top-level `permissions:` block |

A pinning check was explicitly requested in issue #7057 ("Github Actions
should check for RevisionHash", Mar 2025, citing the tj-actions
CVE-2025-30066 attack) as a *proposed* `CKV_GHA_XX: "Ensure Github Action
sources use a commit hash"` — i.e. it does not exist yet.

> **⚠️ Numbering trap:** secondary write-ups renumber these checks
> differently (one popular skill doc lists `CKV_GHA_1` = shell injection,
> `CKV_GHA_2` = pinned SHA, `CKV_GHA_3` = workflow_run, `CKV_GHA_4` =
> self-hosted runners). **The checkov.io index above is authoritative.**
> Consequences for PipeSentry: **Checkov's GHA framework has NO dedicated
> `pull_request_target` check and NO unpinned-action check** — the "pin to
> SHA" and "no pull_request_target" claims in blog posts are wrong for the
> current check set. Its shell-injection check (`CKV_GHA_2`) is a regex list
> of untrusted `github.event` fields inside `run:`.

### 7.3 File + line numbers — YES
Example real output:
```
Check: CKV_GHA_2: "Ensure run commands are not vulnerable to shell injection"
	PASSED for resource: jobs(build)
	File: /.github/workflows/tests.yml:20-53
```
Findings carry the **file path** and the failing job/step resource. Precise
line numbers are available in structured output (JSON `file_line_range` /
SARIF locations); the default CLI view is file + check + resource oriented,
**not** actionlint-style `file:line:col` with a snippet. (This is a genuine
weak spot vs actionlint for locating a finding in a big workflow.)

### 7.4 Interface
CLI-args only — **no interactive menu**. `checkov -d .` (auto-detects
frameworks), `checkov -f file`, `checkov -d . --framework github_actions
--compact`, `checkov --list`, `checkov --check CKV_GHA_2` /
`--skip-check CKV_GHA_1,CKV_GHA_3` (wildcards allowed), `--soft-fail` /
`--soft-fail-on`, `--compact`, `--quiet`, `--create-baseline` /
`--baseline .checkov.baseline` (fail only on new findings),
`--external-checks-dir` for custom Python/YAML checks. Config file:
`.checkov.yaml` / `.checkov.yml` (or `--config-file`), with keys like
`framework:`, `skip-check:`, `skip-path:`, `compact:`, `output:`,
`soft-fail-on:`. Suppression: inline `# checkov:skip=CKV_GHA_2:reason`
comment, `--skip-check`, or a `.checkov.baseline` file. Custom checks can
be written in Python (subclass `BaseGithubActionsCheck`, as the built-ins
do) or as YAML graph policies (like CKV2_GHA_1). Also ships as the
`bridgecrewio/checkov-action@v12` GitHub Action (`directory:`,
`framework:`, `output_format:`, `output_file_path:`, `soft_fail:` inputs)
and a pre-commit hook. Exit code is non-zero on any failure unless
`--soft-fail`.

### 7.5 Output formats
`cli`, `json`, `sarif`, `junitxml`, `csv`, `cyclonedx`, `spdx`,
`gitlab_sast`, `github_failed_only`. The **secrets framework** (separate)
uses `bc-detect-secrets` (Bridgecrew's fork of Yelp's detect-secrets) with
regex, keyword and entropy detectors.

### 7.6 Pinning model
None in the GHA framework — no rule requires a SHA. (Pinning lives in
Checkov's SCA/package world, not in workflow checks.)

### 7.7 Install model
Python: `pip install checkov` / `pipx install checkov` / `brew install checkov`;
Docker image `bridgecrew/checkov:latest`; pre-commit
(`bridgecrewio/checkov` repo); GitHub Action
`bridgecrewio/checkov-action@v12`. No binary. Severities, SCA
(`sca_package`/`sca_image`) and Prisma Cloud enforcement rules need a
`--bc-api-key`. (Note: several guides flag that the official action runs
`ghcr.io/bridgecrewio/checkov` by version tag rather than digest.) A separate
`github_configuration` framework (CKV_GITHUB_*) calls the GitHub REST/GraphQL
APIs with `GITHUB_TOKEN` for org settings/branch protection — that is *not*
part of the GHA workflow checks.

### 7.8 Limitations
- GHA coverage is thin and idiosyncratic: cosign signing/SBOM attestation
  checks (CKV_GHA_5/6) are supply-chain checks most repos fail; no
  pwn-request, no pinning, no self-hosted-runner, no permissions-beyond-
  write-all check.
- The 1000+ check count is across all frameworks — the Actions slice is 8.

---

## 8. GHAST — four tools, one name

> **⚠️ GHAST identity warning first:** there is **no findable
> `H4K3R-01/ghast` repo** — searches for that owner return nothing.
> "GHAST" is a collision of at least **four different tools** sharing the
> name. The canonical one matching the classic description ("GitHub Actions
> Security Testing tool", `check_for_*` checks, PyPI `ghast-scanner`) is
> **`bin3xish477/ghast`** — that is what §8.1 covers in depth. The other
> three are noted in §8.8 so the builder can pick the right one.
> [subagent]

### 8.1 GHAST — `bin3xish477/ghast` (the canonical one)

**One line:** a small, simple **defensive static analyzer** for GitHub
Actions YAML — the original "GHAST" (PyPI `ghast-scanner`). Python, MIT,
created 2023-07-20, only **20 stars / 125 commits / 13 releases, last
release 1.8.8 on 2023-08-13 — effectively unmaintained for ~3 years**. The
author later shipped the same checks under the renamed project **asa /
actions-security-analyzer** (`bin3xish477/asa`, PyPI
`actions-security-analyzer`).

#### 8.1.1 What it scans
- **GitHub Actions workflow YAML files only** — a single
  `--file action.yml` or a directory `-d directory-with-actions/`. No
  org/API scanning, no token needed, no Jenkins, no GitLab. Also ships an
  `actions/` directory of intentionally vulnerable example workflows for
  testing.
- Additionally runs **4 auxiliary repo-hygiene checks** (see §8.1.2).

#### 8.1.2 Exact check names (13 + 4 auxiliary)
Levels are only **FAIL** or **WARN** (no Critical/High/Medium scale):

| # | Check | Level | What it does |
|---|---|---|---|
| 1 | `check_for_3p_actions_without_hash` | FAIL | 3rd-party action referenced by a version tag such as `v1.1` instead of a **commit SHA hash** |
| 2 | `check_for_allow_unsecure_commands` | FAIL | `ACTIONS_ALLOW_UNSECURE_COMMANDS` env var (enables dangerous `set-env`/`add-path` → injection/credential theft) |
| 3 | `check_for_cache_action` / `check_for_cache_action_usage` | WARN | Any use of `actions/cache` (cache poisoning / sensitive-data disclosure) |
| 4 | `check_for_dangerous_write_permissions` | FAIL | Write `contents:` scope, or `write-all` (complete write access to all scopes) |
| 5 | `check_for_inline_script` | WARN | Inline `run:` script instead of a proper Action (injection-prone; recommends passing context values as action inputs) |
| 6 | `check_for_pull_request_target` | FAIL | **Any use of the `pull_request_target` trigger** — "allows workflow executions to run in the context of the repository that defines the workflow … potentially allowing a threat actor to gain access to [its] sensitive secrets!" (Flags the trigger itself; does not model checkout/execution like Poutine's `untrusted_checkout_exec`) |
| 7 | `check_for_script_injection` | FAIL | **Direct `${{ ... }}` interpolation of a GitHub Context variable controllable by an untrusted actor into an inline script** → command execution in the shell; recommends env-var passing |
| 8 | `check_for_self_hosted_runners` | WARN | Any `self-hosted` runner usage (persistence / on-prem access if compromised) |
| 9 | `check_for_aws_configure_credentials_non_oidc` | WARN | `aws-actions/configure-aws-credentials` with non-OIDC (long-lived) credentials |
| 10 | `check_for_create_or_approve_pull_request` | WARN | Actions that create/approve PRs (malicious code merged without controls) |
| 11 | `check_for_remote_script` | WARN | A URL inside an inline script (remote-script inclusion, i.e. `curl \| bash` pattern) |
| 12 | `check_for_upload_download_artifact_action` | WARN | `actions/upload-artifact` / `download-artifact` use (poisoned-artifact / compromised-binary risk; recommends integrity checks) |
| 13 | `check_for_non_github_managed_actions` | WARN | Any non-GitHub-managed (3rd-party) action — review-the-supply-chain reminder |
| A1–A4 | `check_for_missing_codeowners_file`, `check_for_missing_security_md_file`, `check_for_missing_gitignore_file`, `check_for_missing_dockerignore_file` | — | Missing `CODEOWNERS` / `SECURITY.md` / `.gitignore` / `.dockerignore` |

**Coverage vs. checklist:** pwn-request is covered only as the blunt
`check_for_pull_request_target` trigger flag; **no `actions/checkout` +
pwn-request combination modelling**; **no secrets-in-logs / exfiltration
check**; **no `workflow_dispatch` check**; permissions covered only as
dangerous-write (`contents: write-all`), not least-privilege in general.

#### 8.1.3 File + line numbers — NOT documented
The README shows **no example finding output at all** (only an asciinema
demo link) and no flag for locations. Findings are printed per file with
check name + FAIL/WARN; file:line granularity could not be verified from
the README/docs — treat as **not established** (contrast: Poutine and
seanwevans/Ghast both show explicit `file:line`).

#### 8.1.4 Interface / config / output
- CLI-args only, **no interactive menu, no auto-fix, no config file**:
```
ghast --file action.yml
ghast -d directory-with-actions/ --verbose
ghast --file action.yml --ignore-warnings
ghast --list-checks
ghast -i check_for_inline_script --no-summary
```
- **Output: console text only** (+ a pass/fail summary; `--no-summary`
  suppresses it). **No JSON, SARIF, or HTML output documented.**
- Usable as a native GitHub Action:
  `uses: bin3xish477/ghast@<40-char SHA>` with inputs `dir`, `verbose`,
  `no-summary`, `ignore-checks` (space-separated check names). Example in
  README pins checkout at
  `actions/checkout@96f53100ba2a5449eb71d2e6604bbcd94b9449b5 # v3.5.3`.

#### 8.1.5 Pinning
`check_for_3p_actions_without_hash` (FAIL): flags any 3rd-party action
referenced by a version number (e.g. `v1.1`) instead of a commit SHA hash —
the rationale being supply-chain compromise of the action's repo. The README
does not state whether it validates a full 40-char SHA vs. a short hash;
the check name and text say "commit SHA hash" only. No branch-ref or
tag-age analysis.

#### 8.1.6 Install model
`pip install ghast-scanner` (PyPI, last 1.8.8, Aug 2023; requires
`$HOME/.local/bin` on PATH) or
`git clone https://github.com/bin3xish477/ghast.git && python3 -m pip install .`.
No Docker, no binary release, no Homebrew.

#### 8.1.7 Limitations
- **Stale:** no release since Aug 2023; tiny community (20 stars);
  superseded by the author's own `asa` rename.
- Crude, pattern-based checks: `pull_request_target` and `actions/cache`
  are flagged on sight (high false-positive rate for legitimate uses); no
  taint tracking, no cross-workflow reasoning (`workflow_run` chains,
  reusable workflows), no severity ranking beyond FAIL/WARN, no SARIF/JSON,
  no line numbers verified, no auto-fix, no config file (only
  `--ignore-warnings` / `-i` / action-input `ignore-checks`).

### 8.8 The other "Ghast"s (for disambiguation)
- **`seanwevans/Ghast`** (created 2025-05-08, MIT, 3 stars, actively
  developed): the most capable of the name-sharers. Subcommands `scan` /
  `fix` / `report` / `rules` / `config` / `baseline`; 12 rules with real
  severities (`poisoned_pipeline_execution` CRITICAL,
  `command_injection`/`environment_injection`/`token_security`/`permissions`
  HIGH, `action_pinning` MEDIUM, `timeout`/`shell_specification`/
  `workflow_name` LOW, …); **file:line in output** (e.g.
  `File: .github/workflows/ci.yml:15`, `:18`); outputs **text, JSON, SARIF,
  HTML**; **auto-fix + `--interactive` fix review**; YAML config `ghast.yml`
  (rule IDs as keys, `severity_thresholds`, `auto_fix`); inline
  `# ghast: ignore[action_pinning]` suppressions + `ghast baseline` JSON
  burndown files; scans `.github/workflows/*.yml` **and composite
  `action.yml`s**; `pip install ghast`; GitHub Action
  `seanwevans/ghast@v1`; pre-commit hooks (`ghast`, `ghast-strict`). Its
  `action_pinning` rule flags `actions/checkout@v3` as "not pinned to a
  specific commit SHA" and its `command_injection` rule tracks a documented
  list of untrusted contexts (`github.event.issue.title/body`,
  `comment.body`, `pull_request.title/body/head.ref`,
  `head_commit.message`, `workflow_run.head_branch`, `github.head_ref`,
  `inputs.*`, …) while deliberately **not** flagging the recommended
  env-var mitigation. If the builder wants "GHAST with remediation + SARIF
  + line numbers", **this** is the one — but note its tiny adoption
  (3 stars, 1 release).
- **`citizen204/ghast`**: taint-analysis scanner tracing attacker-controlled
  data (issue title, comment body, branch name) to execution sinks;
  `ghast hunt` batch mode; MIT; author self-reports 12 scanner bugs found
  by sweeping ~1,800 workflow files (dev.to write-up).
- **Academic GHAST** (Benedetti, Verderame, Merlo, SCORED '22,
  arXiv:2208.03837): prototype with SSC Builder → WF Extractor → WF
  SecAnalyzer modules, Neo4j graph model, applied to 50 OSS projects
  (24,905 issues reported). Not a maintained CLI.

---

## 9. Credential scanners: CredScan, Gitleaks, TruffleHog, detect-secrets

These are **secret scanners**, not pipeline scanners — they find the
*credentials themselves*, not the workflow patterns that leak them. A
pipeline tool needs them as a complement (or as a check of its own).

### 9.1 CredScan (Microsoft) — proprietary, Azure DevOps + GitHub-side monitoring, no public CLI
- **Not a public standalone CLI.** CredScan exists in three forms:
  1. **Server-side GitHub monitoring run by Microsoft itself** — "CredScan
     monitors all incoming commits on GitHub and checks for specific Azure
     tenant secrets such as Azure subscription management certificates and
     Azure SQL connection strings." No opt-in; on detection the Azure
     subscription owner is emailed by Microsoft's Cyber Defense Operation
     Center (CDOC) with commit, subscription, asset, secret type and fix
     guidance.
  2. **Azure DevOps build task** — part of the Microsoft Security Code
     Analysis extension. Task ID
     `securedevelopmentteam.vss-secure-development-tools.build-task-credscan.CredScan@2/@3`.
     Add "Run Credential Scanner" to a build definition (classic editor or
     YAML); it runs on every pipeline run.
  3. **VS Code Analyzer** — CredScan Code Analyzer in the Microsoft DevLabs
     Visual Studio extension, for inline detection while coding.
- What it scans: source code and configuration files in the scanned folder
  (`Scan Folder` input); the GitHub-side service scans incoming commits.
  Focus is Azure/Microsoft secrets (certificates, SQL connection strings,
  storage keys) plus generic credentials.
- How it detects: a set of **content searchers defined in `buildsearchers.xml`**
  — "an array of XML serialized objects that represent a ContentSearcher
  object" — i.e. pattern/regex-style searchers, user-extensible with a custom
  searchers file (`Searchers File Type` input). **No entropy or live
  verification is documented anywhere.**
- File + line numbers: yes — output records **file, row number, and a hash of
  the credential** (the secret value itself is deliberately *not* stored, "to
  avoid the credential leak from build output"). Suppressions are a JSON file
  keyed by that hash (the hash is generated from a portion of the matching
  value or file content — any source revision can change the hash and disable
  the suppression).
- Output formats: **TSV / CSV / SARIF / PREfast** (task option `Output
  Format`). Other task options: `Tool Major Version` (V1/V2, V2 recommended),
  `Tool Version` (Latest), `Suppressions File`, `Verbose Output`, `Batch Size`
  (concurrent threads, default 20), `Match Timeout`, `File Scan Read Buffer
  Size` (default 524,288), `Maximum File Scan Read Bytes` (default
  104,857,600).
- Install model / gating: Azure DevOps only; requires the Microsoft Security
  Code Analysis extension installed in the organisation. **The CredScan task
  itself does not fail the build** — a separate **Post Analysis** task reads
  all tools' outputs and fails the build, and **PublishSecurityAnalysisLogs**
  publishes the logs as build artifacts.
- Usage is a pipeline task, not a command:
  ```yaml
  - task: CredScan@3
    inputs:
      outputFormat: 'sarif'
      scanFolder: '$(Build.SourcesDirectory)'
      suppressionsFile: '.config/credScanSuppressions.json'
  ```
  or via MSDO: `tools: 'eslint,trivy,credscan,terrascan'` with
  `break: true` to fail the pipeline on Critical/High findings.
- **Licensing is the blocker:** the MSCA extension is restricted to
  customers with a premium license; it is not open source and cannot be run
  on a local checkout.
- Verdict for PipeSentry: cite it as the enterprise reference, but do not
  try to copy it — the open-source equivalents below are the model.

### 9.2 Gitleaks — `gitleaks/gitleaks` (Go, ~150–170+ rules)
- Detects hardcoded secrets with **regex rules + per-rule keyword prefilter
  (Aho-Corasick) + optional per-rule Shannon-entropy floor**, scanning the
  working tree **and git history** (so a secret committed last year is still
  found even if it was deleted). Rule shape in `.gitleaks.toml`: `id`,
  `regex`, `secretGroup`, `entropy = 3.5`, `keywords = ["token"]`. The default
  ruleset is generated from Go definitions in
  `cmd/generate/config/rules/*.go`, each validated against true/false
  positives. **No live verification** (no API calls to check if a key is
  live). It is file-type agnostic — it scans Jenkinsfiles and
  `.github/workflows/*.yml` like any other text file; there are **no
  pipeline-specific rules** (no "unpinned action" or "permissions" rule).
- Commands (v8.19+): `gitleaks git`, `gitleaks dir`, `gitleaks stdin` (older
  `detect`/`protect` deprecated in v8.19.0):
  ```
  gitleaks detect --redact --report-format sarif
  gitleaks protect --staged            # pre-commit hook, staged changes only
  gitleaks detect --source . --exit-code 1
  ```
- File + line numbers: yes, precisely. A finding prints `RuleID`, `Entropy`,
  `File`, `Line`, `Commit`, `Author`, `Email`, `Date`, and `Fingerprint`
  (`<commit>:<file>:<rule>:<line>`, e.g.
  `cd52267…:cmd/generate/config/rules/sidekiq.go:sidekiq-secret:23`). JSON
  reports add `StartLine`/`EndLine`/`StartColumn`/`EndColumn`.
- Config file `.gitleaks.toml` (allowlist, custom rules, `redact`).
  Output: `--report-format json | csv | junit | sarif` (default `json`),
  `--report-path`, `--report-template` (Go template), `--redact` (secrets
  redacted in v8+, `--redact=20` for partial). Exit codes: `0` clean, `1`
  leaks found, `2` execution error. `--baseline-path` ignores findings
  already in a baseline report; `--enable-rule` selects rules;
  `gitleaks:allow` comments and `.gitleaksignore` (fingerprints) suppress.
  GitHub Action available. Install: Go binary, Homebrew, Docker
  (`zricethezav/gitleaks`, `ghcr.io/gitleaks/gitleaks`), `go install`,
  pre-commit hook. **CLI only, no menu.**
- Maintenance caveat (secondary sources, not verified against the primary
  repo): the original creator Zach Rice has said Gitleaks is "feature
  complete… Future releases will be security patches only" and is building a
  successor, **Betterleaks** (Aikido Security); one research note says he "no
  longer controls the repo". Latest verified release cited was v8.30.1
  (2026-03-21). Treat as a flag to re-check before depending on it long-term.
- Verdict: the practical open-source CredScan replacement; a PipeSentry
  "secrets in workflow files" check should behave like Gitleaks' rule set
  (regex + entropy + allowlist) rather than a single hardcoded pattern.

### 9.3 TruffleHog — `trufflesecurity/trufflehog` (Go, ~888–895 detectors, "over 800 secret types")
- The differentiator is **live verification**: four stages — **Discovery,
  Classification, Validation, Analysis**. Detectors are per-provider
  regex/keyword patterns; then **live verification**: for each classified
  secret it logs in to the provider API (e.g. AWS detector calls
  `sts:GetCallerIdentity`; GitHub token calls the GitHub API) and reports
  `verified` / `unverified` / `unknown`. Private keys are verified against
  GitHub users/TLS certificates via "Driftwood". For ~20 common types,
  `trufflehog analyze` makes many calls to learn scope/permissions of a live
  key. Custom detectors via `config.yaml` (`detectors:` with `keywords`,
  `regex` named capture groups, optional `verify:` endpoint with
  `successRanges`/`rotatedRanges`).
  ```
  trufflehog git file://. --only-verified --json
  trufflehog filesystem --json
  trufflehog git https://github.com/<org>/<repo> --only-verified
  ```
- What it scans: far more than git — subcommands per source: `git` (full
  history, all branches), `github` (repos/orgs/issues/PRs/gists), `gitlab`,
  `filesystem`, `s3`, `gcs`, `docker`, `circleci`, `postman`,
  `elasticsearch`, `jenkins`, and more. **Jenkins source = build logs only**
  (`trufflehog jenkins --url https://jenkins.example.com --username admin
  --password admin`; docs: "The Jenkins integration scans Jenkins build logs
  for credentials… Job artifacts are not scanned"). It does **not**
  parse/analyse a Jenkinsfile.
- Output: `--json`, `--sarif` (native to GitHub code scanning — findings
  surface inline on PR diffs and in the Security tab),
  `--results=verified|unknown|unverified` (older flag `--only-verified`).
  JSON output includes file/commit/line context for git/filesystem sources
  (less line-precise than Gitleaks for non-git sources; the Jenkins source
  reports the build log). GitHub Action and pre-commit hook available.
  Install: `brew install trufflehog` / `brew install
  trufflesecurity/trufflehog/trufflehog`, Docker
  (`trufflesecurity/trufflehog:latest`), release binaries (checksums signed
  with cosign), `go install`, install script `scripts/install.sh`. **CLI
  only, no menu.** Enterprise product exists for continuous monitoring.
- Verdict: verification is the gold standard for a secrets check, but it
  needs network access and is out of scope for a static YAML scanner —
  PipeSentry should report "looks like a secret" (Gitleaks-style) and let
  TruffleHog verify.

### 9.4 detect-secrets — Yelp's `detect-secrets` (Python, pip)
- Plugin-based secret detector with a **baseline file**:
  ```
  detect-secrets scan --baseline .secrets.baseline
  detect-secrets audit .secrets.baseline
  ```
  Findings already in the baseline are suppressed, so only *new* secrets
  fail the build — this is the **baseline-mode pattern** PipeSentry's PDF
  asks for (stretch: baseline mode, only new findings). Checkov's secrets
  framework is a fork of it (`bc-detect-secrets`).
- How it detects: three strategies — **(1) regex** plugins for structured
  secrets (AWS, Azure, GitHub, Slack, Stripe…), **(2) Shannon entropy**
  (`Base64HighEntropyString`, default limit 4.5; `HexHighEntropyString`,
  default 3.0), **(3) keyword** detector for variable names like
  `password =` / `secret_key =`. **27 built-in plugins.** **No live
  verification** in the core tool.
- File + line numbers: yes — the JSON baseline (`.secrets.baseline`)
  records `filename`, `line_number`, `type`, and the hashed secret per
  finding; `detect-secrets audit .secrets.baseline` is an interactive
  true/false-positive labeller.
- Install: `pip install detect-secrets` / `brew install detect-secrets`;
  pre-commit config `repo: https://github.com/Yelp/detect-secrets`,
  `rev: v1.5.0`, `hooks: [{id: detect-secrets, args: ['--baseline',
  '.secrets.baseline']}]`; also `detect-secrets-hook --baseline
  .secrets.baseline` and a server-side scanner (`detect-secrets-server`
  repo). **CLI + pre-commit hook, no menu.**

### 9.5 git-secrets (AWS Labs, shell, Apache-2.0)
- Repo: `https://github.com/awslabs/git-secrets`. AWS-centric by design.
- What it scans: commits, commit messages, `--no-ff` merges (via git
  hooks) and files/history on demand.
- How it detects: **regex only** — user-registered patterns
  (`git secrets --add '<regex>'`, `--add-provider`, `--register-aws` adds
  common AWS patterns and ensures keys in `~/.aws/credentials` are never
  committed). No entropy, no verification, no generic-secret detection
  unless you add the pattern yourself.
- File + line numbers: no structured report — `--scan` writes the **matched
  text to stdout** and exits non-zero; `--scan-history` scans all revisions.
  No JSON/SARIF/line-numbered report format.
- Install: `brew install git-secrets`, `make install` (PREFIX/MANPREFIX),
  Windows `install.ps1` (to `%USERPROFILE%/.git-secrets`). **Critical
  gotcha:** installing the binary does nothing until you run
  `git secrets --install` **in every repo** (or into
  `~/.git-templates/git-secrets` + `git config --global init.templateDir`).
  **CLI/git-subcommand only, no menu.**

### 9.6 GitHub's own secret scanning (context, not a CLI)
GitHub native secret scanning (partner patterns — AWS, Azure, GitHub tokens,
Slack, Stripe, hundreds of providers — plus generic non-provider patterns:
private keys, `http_basic/bearer_authentication_header`,
`mongodb/mysql/postgres_connection_string`, and a `password` pattern in
beta) with **push protection** (blocks the push) and **validity checks**
(currently only for GitHub tokens; Team/Enterprise + GitHub Secret
Protection). Custom patterns can be defined per repo/org/enterprise. This
is a server-side service, not a tool a new CLI would re-implement — but it
is the baseline users already get for free on public repos.

**Gap for a new tool:** none of these understands pipeline *semantics* —
none flags "secret echoed in `run:`", "unpinned action", "over-broad
`permissions:`", or "Jenkins `sh` with GString interpolation". They only
find secret-shaped strings.

---

## 10. Jenkinsfile security linters

**Headline finding: there is no established, dedicated open-source Jenkinsfile
*security* scanner.** The Jenkins ecosystem has syntax linters and generic
Groovy analysis, but nothing comparable to zizmor for Jenkins. This is the
single biggest gap PipeSentry can fill — and the PDF's stretch item
(Jenkinsfile scanning) is exactly this. Evidence for "thin": the official
Jenkins page **"Pipeline Development Tools"**
(`jenkins.io/doc/book/pipeline/development/`) lists exactly: Command-line
Pipeline Linter, Pipeline Graph View, Replay, IDE integrations (Eclipse, VS
Code, Neovim, Atom, Sublime), pre-commit hook `jenkinsfilelint`, Pipeline
Unit Testing Framework. **Zero security checks, zero mention of
credentials/secrets.** The only tools that do check Jenkinsfile security
rules are a recent multi-provider scanner (`pipeline-check`, §10.9) and two
commercial/skill products (§10.10).

### 10.1 Jenkins' own declarative linter — syntax only, needs a live controller
Jenkins ships a built-in **declarative pipeline linter**. It validates
syntax, nothing else:
```
ssh -p $JENKINS_PORT $JENKINS_HOST declarative-linter < Jenkinsfile
curl -X POST --user "$JENKINS_AUTH" -F "jenkinsfile=<Jenkinsfile" "$JENKINS_URL/pipeline-model-converter/validate"
# Jenkinsfile successfully validated.
#   — or —
# Errors encountered validating Jenkinsfile:
# WorkflowScript: 2: Not a valid section definition:
```
- It catches compile-time errors only (missing `agent`, `Undefined section`,
  `Expected a step`); it does **not** catch run-time errors
  (`MissingPropertyException`, unknown step) and has **no security checks**
  at all. It requires a live Jenkins controller (SSH or HTTP + API token +
  CSRF crumb). The VS Code extension "Jenkins Pipeline Linter Connector"
  just posts to this same endpoint.
- Verdict: useful as a *syntax pre-check* in a pipeline tool, useless as a
  security scanner.

### 10.2 jenkinsfile-runner — executes pipelines locally, not a scanner
`jenkinsci/jenkinsfile-runner` (Java, "Incubating project", version
`1.0-beta-33-SNAPSHOT`) packages the Jenkins Pipeline engine as a CLI/Docker
image to **execute** a Jenkinsfile without a persistent controller
(`jenkinsfile-runner -w <war> -p <plugins> -f <Jenkinsfile>`, or
`jenkinsfile-runner run -w … -p … -f …`; Docker `jenkins/jenkinsfile-runner`).
Exit code = build result. Use cases: FaaS, local pipeline testing,
shared-library integration tests. It is a **runtime**, not a linter: it
proves the pipeline *runs*, not that it is safe. No findings, no severities,
no SARIF.

### 10.3 CodeNarc — generic Groovy static analysis
`CodeNarc` (Groovy) runs rule sets over Groovy code, including Jenkinsfile
Groovy (scripted pipelines, `vars/*.groovy` shared-library code). Rules are
generic code-quality rules (naming, complexity, unused variables) — **no
Jenkins-security-specific rules** (no credential handling, no `sh` GString
interpolation, no `agent any` on controller). It is a linter you would have
to *teach* Jenkins security, not one that knows it. (CodeNarc does have
generic security-ish rules, e.g. around `System.exit`/`printStackTrace`, but
no Jenkinsfile-credential rule names were found in the material read — do
not assume they exist.)

### 10.4 npm-groovy-lint / jenkinsfile-validator — thin wrappers
- **npm-groovy-lint** (`nvuillam/npm-groovy-lint`, npm package; based on
  **CodeNarc**): generic Groovy code quality — **not Jenkins security**.
  Presets in v19: `recommended` (149 rules: "likely mistakes only — bugs,
  dead code, security and concurrency hazards, misused APIs"), `advanced`
  (344), `all` (390 CodeNarc rules), `format` (40), plus framework add-ons
  `grails`, `tests`, `jenkinsfile` / `recommended-jenkinsfile`
  ("`-c jenkinsfile` alone is a full lint, not only the Jenkinsfile-specific
  rules"). The Jenkinsfile preset is about Groovy/Jenkinsfile *style and
  correctness*, and no rule in the material read targets plaintext
  credentials, `sh` interpolation, `agent any`, `input` without submitter,
  or `evaluate()`/`load`.
- File + line: yes — CodeNarc violations carry file/line/column; output via
  `-o/--output`: **txt, json, sarif, html, xml**. `--failon
  error|warning|info|none` (exit 1), `--fix`/`--format` auto-fix, `--parse`
  (compile check, default true), `--rulesets` for custom CodeNarc RuleSets,
  `--codenarcargs` passthrough. Default files: `**/*.groovy, **/Jenkinsfile,
  **/*.gradle`.
- Install: npm (`npm install -g npm-groovy-lint` / npx), needs Java 17–25
  (it launches a microservice to avoid JVM reload, auto-kills after 1h idle;
  `--noserver` disables). Also in VS Code Groovy Lint extension,
  Mega-Linter, Docker image. **CLI, no menu.**
- **jenkinsfile-validator** (Claude Code skill / shell+grep scripts):
  hardcoded-secret patterns + syntax checks, `--strict` exit 1,
  `--assume-declarative` / `--assume-scripted`. Small, ad-hoc, no rule IDs,
  no SARIF, no maintained repo to cite as a standard.

### 10.5 ci-sentinel — the closest thing to a real Jenkins security scanner
`ci-sentinel` (Baneado98, via Glama MCP server + pay-per-call HTTP API)
covers **7 CI systems including Jenkins**, with a taint model, **SARIF
output with codeFlows**, file:line locations, and auto-remediation diffs.
For Jenkins it claims taint from `params.*` / `env.CHANGE_*` / `ghprb*` /
SCM data into `sh`/`bat`/`powershell` (through `environment{}`),
credential-leak (`credentials()`/`withCredentials` printed or baked into a
GString), Groovy `evaluate()`/`load` RCE, missing `input()` approval gate,
unsafe `agent any`, plus shared-library cross-file taint. It is the only
tool found that treats Jenkinsfile security as a first-class problem — but
it is a **paid API / MCP service**, not a local open-source CLI (not an open
CLI repo that could be verified), so it cannot be bundled or run offline.

### 10.6 jenkinsfilelint — the official pre-commit wrapper (syntax only)
- **Repo:** `jenkinsci/jenkinsfilelint` (accepted into the `jenkinsci` org;
  blog 2026-06-08, `jenkins.io/blog/2026/06/08/jenkinsfilelint-pre-commit/`;
  v1.4.0 in the Jenkins docs example, v1.6.1 released 2026-11-18; small
  project — ~12 stars, ~66 commits).
- **What it checks:** Groovy syntax + Declarative structure:
  required/allowed sections, `stages`, `agent`, `environment`, `options`,
  `triggers`, `parameters`, `when`, `post`, `matrix`. Three modes:
  **offline** (bundled native engine, no Jenkins/Docker/JVM — "checks Groovy
  syntax and the Declarative structure"), **remote** (POSTs to your Jenkins
  `/pipeline-model-converter/validate`), **local** (spins up a Jenkins in
  Docker, image `ghcr.io/jenkinsci/jenkinsfilelint-server:latest`).
- **Interface:** CLI + pre-commit hook. `pip install jenkinsfilelint`;
  `jenkinsfilelint Jenkinsfile`, `jenkinsfilelint --local Jenkinsfile`,
  `jenkinsfilelint --offline Jenkinsfile`; pre-commit
  `repo: https://github.com/jenkinsci/jenkinsfilelint`,
  `id: jenkinsfilelint` / `jenkinsfilelint-offline`; env `JENKINS_URL`,
  `JENKINS_USER`, `JENKINS_TOKEN`. No menu, no JSON/SARIF output documented,
  **no security rules**.
- Older/alternative wrappers (same idea, not security):
  `eastwd/jenkins-lint` (Go, `jenkins-lint -f ./test/Jenkinsfile`,
  `.jlint.toml`, calls Jenkins API), `aissa-laribi/jklint` (PyPI `jklint`,
  wraps `java -jar jenkins-cli.jar … declarative-linter`, "Masked
  credentials" is listed as a feature of its setup, not a scan rule).

### 10.7 Script Security plugin — runtime sandbox, not a static scanner
- **Plugin:** `plugins.jenkins.io/script-security` — "supports two related
  systems: script approval, and Groovy sandboxing."
- **What it does:** at **runtime**, every method call / object construction /
  field access in sandboxed Groovy is checked against a whitelist; an
  unapproved call kills the script with `RejectedAccessException: Scripts
  not permitted to use staticMethod …` (e.g. `String.execute()`,
  `Jenkins.getInstance`, `new java.io.File`). Admins approve exact signatures
  under **Manage Jenkins → In-process Script Approval**
  (`/manage/scriptApproval/`). Non-sandboxed scripts need whole-script
  approval.
- **What it does not do:** no static scan of a Jenkinsfile, no file+line
  report, no CLI, no checks for hardcoded secrets or `sh` interpolation, no
  output format. It is a Jenkins plugin (UI), and it is the reason
  `evaluate()`/`load`-style RCE is *mitigated at runtime* but not *detected
  statically*.

### 10.8 warnings-ng — a results *consumer*, not a scanner
- **Plugin:** `warnings-ng` (CloudBees docs: plugin ID `warnings-ng`, min
  Jenkins 2.555.3). "Collects compiler warnings or issues reported by static
  analysis tools and visualizes the results" — built-in parsers for compilers
  and tools (spotbugs, pmd, checkstyle, eslint…), plus a generic **SARIF**
  parser: `recordIssues enabledForFailure: true, tools: [sarif(pattern:
  '*.sarif.json')]` with quality gates (`threshold`, `type:
  'TOTAL_HIGH'/'TOTAL_ERROR'`). It displays findings with source annotations,
  trends and gates — but **defines no Jenkinsfile rules itself**. Any new
  Jenkinsfile scanner should emit SARIF precisely so warnings-ng (and GitHub
  code scanning) can display it.

### 10.9 pipeline-check — the nearest real Jenkinsfile security scanner
- **Repo:** `dmartinochoa/pipeline-check`, PyPI `pipeline-check`, Python
  ≥3.10/3.11 — **the closest thing to a dedicated Jenkinsfile security
  scanner found**, but multi-provider, not Jenkins-only: "550+ checks across
  18 providers" (other pages say 1200+ checks / 36 providers — counts vary by
  version), **Jenkins: 32 checks `JF-001`–`JF-032`** on `Jenkinsfile`
  (Declarative/Scripted), GitHub Actions: 39 checks `GHA-001`–`039`; maps
  findings to OWASP Top 10 CI/CD, SLSA, NIST SSDF, PCI DSS, SOC 2; scores
  A–D; 111 autofixers; taint engine + attack chains (MITRE ATT&CK).
- CLI: `pip install pipeline-check`, `pipeline_check` (auto-detect),
  `--jenkinsfile-path`, `-o json`, PR review comments via composite action
  `dmartinochoa/pipeline-check/.github/actions/pipeline-check-pr@v1`
  (findings on precise lines). No menu. PyPI 1.16.0 (also 0.5.0).

### 10.10 Jenkinsfile Safety Check (Getly, $5 paid skill)
- Python 3.9+ stdlib-only scanner, rules **J01–J18**: J01 credential in
  `sh`/`bat`/`powershell` via double-quoted Groovy string; J02
  password/token/key written in the pipeline; J03 PR title/branch/author
  interpolated into shell; J13 `curl -k`/`wget --no-check-certificate`; J14
  downloads piped into shell; J17 `input` without submitter; J18 free-text
  build parameters interpolated into shell. Returns BLOCK/REVIEW/NOT FLAGGED
  with file, line, reason, fix. Agent skill, not a public repo.

**Verdict for §10:** a Jenkinsfile security scanner with named rules,
file+line output and a CLI is a genuine gap in the *open, Jenkins-official*
ecosystem. The reusable rule inventory already exists in prose (Credentials
Binding docs, J01–J18, JF-001–032, ci-sentinel's Jenkins table) — a new tool
would be codifying documented practice, not inventing it.

### 10.11 The Jenkins risks a scanner must cover (synthesised from the above + Jenkins docs)
| Risk | Why it matters | What to flag |
|---|---|---|
| Plaintext credentials in `environment {}` | Secrets committed in the Jenkinsfile, visible to anyone with repo read | `environment { PASSWORD = '...' }`, `withCredentials` misused, `credentials('id')` in a `sh` double-quoted string |
| Secrets interpolated into double-quoted `sh` GStrings | Groovy expands the secret into the shell command line, defeating Jenkins' log masking; the secret lands in the build log and process list | `sh "curl -u user:${PASSWORD} ..."` → fix is single-quoted `sh '...'` with the credential passed via env |
| Groovy `evaluate()` / `load` | Remote code execution from a string / file | `evaluate(...)`, `load '...'` on untrusted content |
| Missing `input()` approval gates | Production deploys with no human approval | `stage('Deploy')` with no `input` step |
| Unsafe `agent any` | Job runs on the controller, which can read `JENKINS_HOME` (credentials, secrets) | `agent any` on a job that should be `agent { label '...' }` |
| `@Library` imports on mutable refs | Shared library pulled from a branch/tag that can move | `@Library('my-lib@main')` instead of a pinned commit |
| Shared-library (`vars/*.groovy`) cross-file taint | The vulnerability lives in the library, not the Jenkinsfile | Taint from library steps into `sh` |
| `build` step without `wait: false` / `propagate` | Downstream job failure hidden | `build job: '...', propagate: false` in a deploy |
| `docker` / `podTemplate` with privileged containers | Same class as RBACLens WL-001, inside Jenkins | `privileged: true`, `hostPath` in pod templates |
| Parameter injection | Free-text string parameter interpolated into shell executes attacker-controlled commands | `sh("echo ${params.STATEMENT}")` with `hello; ls /` as the parameter value |
| Masking is best-effort | Jenkins masks secrets as `****` in logs, but mangled/encoded/split secrets defeat it; `set +x` / `@echo off` recommended; anyone who can configure a job is assumed trusted with credentials in scope | — |
| Credentials Binding anti-pattern (quotes) | Single quotes, not double quotes: `sh 'curl -H "Authorization: Bearer $TOKEN" …'` (shell expands the env var) vs the insecure `sh """ … $TOKEN … """` — "the secret is interpolated by Groovy and so (for example) typical operating system process listings will accidentally disclose it". Jenkins logs at runtime: `Warning: A secret was passed to "sh" using Groovy String interpolation, which is insecure. Affected argument(s) used the following variable(s): [TOKEN] See https://jenkins.io/redirect/groovy-string-interpolation` | `sh "curl … ${TOKEN}"` |

---

## 11. Octoscan (bonus) — `synacktiv/octoscan`

Found during research; worth recording because it is the only other tool
that **builds on actionlint's Linter** and adds security rules.

- Go, GPL-3.0, v0.1.6. **17 rules** incl. `dangerous-checkout`,
  `dangerous-action`, `dangerous-write` (`$GITHUB_OUTPUT`/`$GITHUB_ENV`),
  `expression-injection`, `runner-label`, `repo-jacking`,
  `unsecure-commands`, `bot-check`, `known-vulnerability`,
  `dangerous-artefact`, `credentials`, `shellcheck`, `local-action`,
  `oidc-action` (+ debug rules).
- ```
  octoscan scan
  octoscan dl --org <org>            # download workflows for offline scanning
  octoscan --list-rules
  octoscan --disable-rules <rule> --filter-triggers <trigger> --config-file <file>
  ```
- Output: **SARIF + JSON**. GitHub Action; Docker
  `ghcr.io/synacktiv/octoscan`. CLI-args-only, no menu.
- Limitations: small community, no pinning rule of its own, no Jenkins,
  no score.

---

## 12. GitHub's own starter-workflows / hardening guidance

GitHub's own documentation (docs.github.com, "Security hardening for
GitHub Actions") is the **authoritative baseline** every tool above
implements. Key rules PipeSentry should encode:

- **Pin third-party actions to a full 40-char SHA** (plus a version comment
  for readability). This is the single most-repeated rule in the docs.
- **Least-privilege `permissions:`** — top-level read-only (or `{}`) by
  default; new repos have had read-only tokens by default since
  2023-02-02. Set permissions per-job, never `write-all`.
- **Secrets:** never store sensitive values as plaintext in workflow files
  — use secrets (org/repo/environment level). Mask non-secret sensitive data
  with `::add-mask::VALUE`. **Never use structured data as a secret** — a
  JSON/XML/YAML blob defeats log redaction (redaction relies on exact-match);
  create individual secrets per value. **Register all secrets used within
  workflows** — if a secret is used to generate another value (e.g. private
  key → signed JWT), register the derived value (and any Base64/URL-encoded
  transform) as a secret too, or it won't be redacted. Least privilege: "Any
  user with write access to your repository has read access to all secrets"
  — use minimally-scoped credentials; set the default `GITHUB_TOKEN`
  permission to **read-only for repository contents** and raise per job.
  Audit how secrets are handled (check actions don't send them to unintended
  hosts or print them); review logs after valid *and* invalid inputs;
  **delete the log and rotate the secret** if an unredacted secret reaches a
  log. Rotate periodically; remove unneeded secrets; use **required reviewers
  for environment secrets**. **CODEOWNERS:** put `.github/workflows` under
  CODEOWNERS so workflow changes need a designated reviewer.
- **Never interpolate `${{ }}` into `run:`** — treat everything in the
  `github` context as untrusted input (PR titles, branch names, issue
  bodies…). Preferred fix 1 — JS action: pass the context value as an
  *argument* (`with: title: ${{ github.event.pull_request.title }}` to a
  JavaScript action) — it never becomes shell script. Preferred fix 2 — env
  var: assign to an intermediate environment variable and reference the
  variable (e.g. `env: { TITLE: ${{ github.event.issue.title } } }` then
  `echo "$TITLE"`). The docs show the attack string `a"; ls
  $GITHUB_WORKSPACE` failing harmlessly this way. Double-quote shell
  variables to avoid word-splitting. This is the fix every tool recommends
  for template-injection.
- **`pull_request_target` / `workflow_run` are privileged triggers** — they
  run in the base-repo context with secrets and share the main branch's
  cache. **Avoid `pull_request_target` if not necessary**; for privilege
  separation `workflow_run` is the better trigger; use them only when the
  workflow actually needs the privileged context. Never check out or execute
  fork code in them (pwn requests, GHSA-fgv8-vgyp-7mq3); `workflow_run`
  workflows must treat artifacts from other workflows as untrusted data.
  CodeQL can scan and detect vulnerable workflows (enable default setup);
  OpenSSF **Scorecards** checks script injection, token permissions and
  pinned actions. `actions/checkout` v7 **refuses fork-PR checkout by
  default** (v2–v6 since 2026-07-20, opt back in with
  `allow-unsafe-pr-checkout: true`); `pull_request_target` on public repos is
  **blocked by default from 2026-12-02**.
- **Actions cache is read-only for low-trust triggers** since 2026-06-26
  (`cache-mode` controls it).
- **Pinning third-party actions (and reusable workflows):** strongest (new)
  is **workflow dependency lockfiles** — record the exact commit for every
  action including transitive deps, verify source-repo identity at runtime;
  "supersedes SHA pinning for repositories that adopt it". Otherwise: **pin
  to a full-length commit SHA**, verified as coming from the action's own
  repository, not a fork (a bad actor would need a SHA-1 collision for a
  valid Git object). Keep the version in a trailing comment, e.g.
  `uses: actions/checkout@<40-char-sha> # v4.1.1`. Tag only if you trust the
  creator — the "Verified creator" badge is a useful signal, but a tag can be
  moved or deleted if the repo is compromised. Always **audit the action's
  source code** (secrets not sent to unintended hosts, not logged). Same rules
  apply to reusable workflows. **Keep actions updated with Dependabot**
  (version updates + security updates; it updates SHA pins and their
  comments). Note: Dependabot only creates alerts for vulnerable actions
  using semantic versioning, **not** for SHA-pinned ones; it ignores
  locally-referenced actions (`./.github/actions/…`) and `docker://`
  container actions.
- **Workflow dependency lockfiles are GA** (Oct 28, 2026): `gh actions-lock`
  writes `.github/workflows/actions.lock`; reusable workflows are not covered.
- **Use OIDC (trusted publishing) instead of long-lived credentials** for
  cloud deploys (custom claims unavailable for AWS).
- **Self-hosted runners:** GitHub-hosted runners are ephemeral/clean VMs;
  self-hosted runners "should almost never be used for public repositories"
  (any PR author can compromise them and reach secrets/`GITHUB_TOKEN`); use
  runner groups, JIT (ephemeral, one-job) runners, and minimise sensitive
  data on the host (SSH keys, cloud metadata access).
- **Dependency graph / Advisory Database / dependency review:**
  `.github/workflows` files are parsed as manifests
  (`jobs[*].steps[*].uses`, `jobs.<id>.uses`); advisories surface in the
  graph; use dependency review on PRs and the `dependency-review-action` to
  block vulnerable additions.
- **Audit log:** monitor e.g. `org.update_actions_secret`; do not allow
  workflows to create/approve PRs without oversight.
- **Starter workflows are not safe by default:** GitHub Security Lab found
  template-injection cases in GitHub's own starter workflows — a new tool
  should not assume a workflow is safe because it came from a template.
  (GitHub's "starter workflows" themselves are templates — e.g. the CodeQL
  analysis workflow — which the docs say to use "instead of starting from
  scratch"; the security *rules* are the hardening guide above.)

### 12.1 Reference incidents (why these checks exist)
- **tj-actions/changed-files, Mar 2025** — a compromised action version
  (23,000+ repos) leaked secrets from CI runs; the attack was caught by
  pinning/SHA verification advocates and is the case study behind
  alex-jung's PipeGuard (§13).
- **Trivy supply-chain compromise, Mar 2026** (CVE-2026-33634) — 76 of 77
  tags force-pushed; another pinning failure.

---

## 13. Name collisions: "PipeGuard"

**"PipeGuard" is taken in the exact same niche — twice (three times if you
count a fork). The name cannot be used.**

| Project | Language / location | What it does | Collision severity |
|---|---|---|---|
| **alex-jung/pipeguard-cli** | Python, GitHub + PyPI `pipeguard-cli` 0.1.0 (2026-03-12), 0.1.2 (2026-03-14), Apache-2.0, Python 3.11+ | "Catch GitHub Actions security issues before they reach your runners" — a **pre-commit scanner with the same CLI shape as the planned tool**. Rules: `sha-pinning`, `sha-pinning-reusable`, `cve-<id>` (offline CVE DB — CVE-2025-30066 `tj-actions/changed-files`, CVE-2025-30154 `reviewdog/action-setup`, CVE-2023-49291 `tj-actions/branch-names`), `supply-chain` (unverified publisher), `secrets-leak` (`echo ${{ secrets.… }}`), `secrets-leak-debug` (`set -x`), `permissions-missing`, `permissions-write-all`, `permissions-excessive`, `permissions-id-token-unused`, `permissions-invalid`, `pull-request-target`, `pull-request-target-pwn`, `actionlint` (syntax), `action-inventory` (info). `pipeguard scan [PATH]`, `--format json|sarif`, exit 0 clean / 1 errors-or-warnings, pre-commit hook, fully offline. Launched by a 2026-03-13 dev.to post: "I built a static analyzer that would have caught the tj-actions supply-chain attack" — repo link in that post is `github.com/alex-jung/pipeguard-cli`. Also listed in a 2026-02-26 news digest as "PipeGuard v0.1.0 — an open-source CI/CD pipeline security scanner." | **BLOCKER — same name, same domain, same CLI** |
| **`pipeguard-scanner-cli`** | Python, TestPyPI 1.0.0 (2026-05-16), MIT, "Copyright (c) 2026 Liem Tran" | Broader Python CLI (Typer + Rich + PyYAML): `pipeguard scan .` / `scan <path>` / `scan <git-url> --ref main`; categories `--category cicd|docker|iac|repo|secrets|vuln`; `--fail-on high`, `--ignore RULE_ID`, `--config pipeguard.yml`, `--output report.md|.json|.sarif`, `--docker-image` via Trivy/Grype. Rules include `GH_ACTION_UNPINNED_ACTION`, `GH_ACTION_PULL_REQUEST_TARGET_CHECKOUT_HEAD` (Critical), `GH_ACTION_SECRET_IN_PULL_REQUEST`, `GH_ACTION_CURL_BASH`, `DOCKER_SECRET_ENV` (Critical), `SECRET_AWS_ACCESS_KEY`, `SECRET_PRIVATE_KEY`, `SECRET_GITHUB_TOKEN`, `K8S_PRIVILEGED_CONTAINER`, `K8S_HOST_PATH_VOLUME`, `REPO_ENV_FILE_COMMITTED` (Critical), `VULN_PYTHON_PACKAGE_VULNERABLE`. Sample output shows file+line, e.g. `GH_ACTION_JOB_WRITE_PERMISSION cicd .github/workflows/release-tag.yml 24`. **No GitHub repo URL was found** in any search — TestPyPI only, install documented as `pip install -e .` from the project directory. | **BLOCKER — same name, same CLI name `pipeguard`, broader scanner** |
| **karlhillx/pipeguard** | Go, created 2026-03-18, 0 stars, 4 commits, public, main branch | Policy-as-code validator for **Bitbucket Pipelines** YAML. Rules (MVP v1): `require-step`, `forbid-image-tag` (e.g. `latest`), `require-manual-trigger` (for `deployment: production`), `allow-pipe-list`. `./pipeguard --config bitbucket-pipelines.yml --format text|json`; severities ERROR/WARNING/INFO; example: `[ERROR] (forbid-image-tag) Forbidden image tag 'latest' … node:latest`. Author site `karlhill.com/work/developer-tooling` describes it identically. | Medium — same name, adjacent CI domain |
| **tazi06/pipeguard** | Go (forked by dinzz005) | CI/CD pipeline guard — listed on CodeTriage with 3 issues; `dinzz005/pipeguard` is a public Go fork "Forked from tazi06/pipeguard". It could **not** be verified whether `karlhillx/pipeguard` is a rename/re-upload of `tazi06/pipeguard` or a separate reimplementation — the karlhillx repo is marked "Fork: No", created 2026-03-18 with 4 commits. Either way it is another `pipeguard` repo in the same space. | Medium — same name, same domain |
| **Steeve-Crypto/pipeguard** | Rust | CI/CD scanner, same domain | Medium — same name, same domain [prior context, not re-verified in this pass] |
| **SOFTSWISS "Pipeguard"** | Internal corporate platform, not open source | "Custom-built CI/CD security platform" — SAST, SCA, container and secrets scanning, IaC scanning, SBOM, policy-as-code, Risk Context Score; 200+ production repos, 2,000+ scans/day, >90% of criticals fixed in SLA; won Global Tech Award 2026 (CyberTech). No GitHub repo found. | Medium — CI/CD security platform (proprietary); brand/trademark collision |
| `pipelineguard-ai` | PyPI `pipelineguard-ai` | Different name but same niche (AI pipeline guard) | Low — similar name, different exact name |
| `pipguard` | PyPI `pipguard` (`shenxianpeng/pipguard`), 0.1.0 (2026-03-25) → 0.4.3 (2026-10-22) | Python supply-chain tool: AST-scans packages *before* `pip install`, blocks the March 2026 litellm `.pth` attack, CRITICAL/HIGH → exit 1, `pipguard install …`, GitHub Action `shenxianpeng/pipguard@v0.3.0`. **Not** a pipeline-file scanner, but one letter from PipeGuard and in the same CI/CD-security conversation. | Low — different name and domain |

Near-misses (different spelling, confusable): `AnantDhavale/pip-guardian`
(PyPI `pip-guardian`, same litellm-era pre-install gate);
`jern2004/pipeline-guard` (Azure-hosted incident-tracker demo API;
different name, not a scanner). Unrelated uses of the word (pollute search
but not collisions): `PipeGuard` class inside
`AbrahamPaulJ/facefusion-mobile` (an internal lock guarding a native video
pipeline); **PipeGuard · Research Lab** (`pipeguard-ai.vercel.app`) —
CNN–LSTM gas-pipeline leak-detection research prototype; physical pipelines,
unrelated; `pi-guard` / `pi-guards` / `pi-path-guard` — AI-agent session
guards, unrelated.

**Decision (user, 19:35 PKT): rename to PipeSentry** — 0 GitHub results,
fully free. The other candidate names the user already rejected are also
taken: CIGuard, FlowGuard, WorkflowGuard, ActionLens, BuildGuard.
**PipeSentry is the name to build under.** Author: only "CyberBoy50",
no real names (same rule as RBACLens).

---

## 14. Comparison matrix

| Capability | zizmor | Scorecard | Poutine | Gato | actionlint | StepSecurity | Checkov GHA | GHAST bin3xish477 | GHAST seanwevans | Octoscan |
|---|---|---|---|---|---|---|---|---|---|---|
| Scans | GH Actions (+ Dependabot, pre-commit) | Whole repo | GH Actions + GitLab + Azure + Tekton | GH Actions (API + run logs) | GH Actions YAML | GH Actions (fixer) | GH Actions (+ 20 frameworks) | GH Actions YAML | GH Actions YAML + composite | GH Actions YAML |
| Jenkinsfile | No | No | No | No | No | No | No | No | No | No |
| `pull_request_target` + checkout pwn-request | `dangerous-triggers` | `Dangerous-Workflow` (Critical) | `untrusted_checkout_exec` (modelled) | **Core** (enum + exploit) | No | No | No | Blunt flag `check_for_pull_request_target` (FAIL) | `poisoned_pipeline_execution` (CRITICAL) | `dangerous-checkout` |
| Unpinned actions | `unpinned-uses` (hash-pin default) | `Pinned-Dependencies` (Medium) | **No direct rule** (`unpinnable_action` only) | No | No | **Fixes it** (pinact) | No | `check_for_3p_actions_without_hash` (FAIL) | `action_pinning` (MEDIUM) | No |
| Secrets in logs / exfiltration | `unredacted-secrets` (fromJSON) | No | Only `job_all_secrets` | **Active exfiltration** (`attack --secrets`); artifact scan | `[credentials]` (hard-coded tokens) | No | No | No | `token_security` (HIGH) | `credentials` |
| `${{ }}` script injection | `template-injection` | No | `injection` | Enum | Expression check (untrusted props) | No | `CKV_GHA_2` | `check_for_script_injection` (FAIL) | `command_injection` (HIGH) | `expression-injection` |
| Overly broad permissions | `excessive-permissions` | `Token-Permissions` (High) | `default_permissions_on_risky_events` | PAT privilege enum (not workflow) | No | Fixes (tightens) | `CKV2_GHA_1` (write-all only) | `check_for_dangerous_write_permissions` (FAIL) | `permissions` (HIGH) | `dangerous-write` |
| Self-hosted runner abuse | (via `dangerous-triggers` context) | No | `pr_runs_on_self_hosted` | **Core** (enum + RoR takeover) | Runner-label correctness only | No | No | `check_for_self_hosted_runners` (WARN) | — | `runner-label` |
| Cache poisoning | `cache-poisoning` | No | No | No | No | No | No | `check_for_cache_action_usage` (WARN) | — | — |
| `workflow_dispatch` abuse | No | No | No | No | No | No | `CKV_GHA_7` (inputs must be empty) | No | — | — |
| `ACTIONS_ALLOW_UNSECURE_COMMANDS` | — | No | No | No | Deprecated-commands check | No | `CKV_GHA_1` | `check_for_allow_unsecure_commands` (FAIL) | — | `unsecure-commands` |
| Known-vulnerable actions (CVE) | `known-vulnerable-actions` (online) | `Vulnerabilities` (OSV, repo-level) | `known_vulnerability_in_build_component` (OSV) | No | No (flags unsupported Node runtime) | No | No | No | — | `known-vulnerability` |
| Exact check names | 42 audits, named | 19 checks, named (incl. experimental `Webhooks`) | 13 Rego rule IDs | Subcommands, no rules | ~37 rules, `[category]` | Fixer, no checks | 8 checks (CKV_GHA_1–7, CKV2_GHA_1) | 13 `check_for_*` + 4 aux | 12 rules, severities | 17 rules |
| File + line numbers | **Yes** (annotated source; 1-based plain/SARIF, 0-based json-v1) | **Yes** (file:line in details) | **Yes** (path + line, job, step) | No (per-repo/workflow) | **Yes** (`file:line:col`) | N/A (rewrites files) | **Yes** (file:line ranges) | Not documented | **Yes** (file:line) | **Yes** (via actionlint) |
| Interface | CLI only; `zizmor.yml` config | CLI only; no config | CLI only; `.poutine.yml` + Rego | CLI only; no config | CLI only; `.actionlint.yaml` | Web app + GH Action / CLI (pinact) | CLI only; `.checkov.yml` | CLI only; no config | CLI only; `ghast.yml` | CLI only; config file |
| Interactive menu | **No** | **No** | **No** | **No** | **No** | **No** | **No** | **No** | **No** (but `--interactive` fix review) | **No** |
| Output formats | plain / json / json-v1 / **sarif** / github | text / **json** (SARIF only via the Action) | pretty / **json** / **sarif** | console / **json** (`-oJ`) | plain text; JSON/SARIF via `-format` Go template | N/A (rewritten files) | cli / **json** / **sarif** / junitxml / csv / cyclonedx / spdx | console text only | text / **json** / **sarif** / **html** | **sarif** / **json** |
| Auto-fix | **Yes** (`--fix`, `--fix=all`) | No | No | No (attack ≠ fix) | No | **Yes** (its whole purpose) | No | No | **Yes** (`fix`, `--interactive`) | No |
| Baseline mode | No | No | No (skip rules in config) | No | No (ignore list) | No | `.checkov.baseline` | No | **`ghast baseline`** (JSON burndown) | No |
| Score / grade | No (per-audit severity) | **0–10 per check, weighted aggregate** | No (pass/fail per rule) | No | No | No | No (pass/fail per check) | FAIL/WARN only | Severities only | No |
| Pinning model | Full 40-char SHA (hash-pin default) | Hash-pinned counts; tag does not | Transitive / "unpinnable" | N/A | None | Full SHA + `# vX.Y.Z` comment | None | Tag → commit SHA | Tag → commit SHA | None |
| Install | Rust binary / **pip** / brew / Docker | Go binary / Docker / GH Action | Go binary / brew / Docker / GH Action | Clone + pip (macOS/Linux) | Go binary / brew / choco / scoop | GH Action / web app / Go binary (pinact) | **pip** | **pip** (`ghast-scanner`) | **pip** (`ghast`) | Go binary / Docker / GH Action |
| Status | Active, 7,158★ | Active (OpenSSF) | Active, ~540★ | **Archived** → Trajan / Gato-X | Active | Active | Active | **Stale since Aug 2023** | Active, 3★ | Active, small |

*Also covered in text but not in the matrix (different category): CredScan
(proprietary Azure DevOps task, SARIF), Gitleaks (Go, SARIF, git history),
TruffleHog (Go, JSON, live verification), detect-secrets (Python, baseline
file), git-secrets (AWS Labs, regex only, no structured report), GitHub
secret scanning (server-side service, push protection), Jenkins' own
declarative linter (syntax only, needs a live controller), jenkinsfilelint
(official pre-commit wrapper, three modes, syntax only), jenkinsfile-runner
(runtime, not a scanner), CodeNarc / npm-groovy-lint (generic Groovy),
Script Security plugin (runtime sandbox, not a scanner), warnings-ng
(results consumer — emit SARIF so it can display findings), pipeline-check
(nearest real Jenkinsfile security scanner: JF-001–JF-032, GHA-001–039,
scores A–D, 111 autofixers), ci-sentinel (paid API/MCP, SARIF with
codeFlows), Jenkinsfile Safety Check (paid skill, J01–J18).*

---

## 15. Synthesis

### 15.1 Which checks appear in most tools (the must-have core)
1. **Unpinned actions** — zizmor, Scorecard, GHAST (both), StepSecurity/pinact
   (fixer). The single most-consensus check: full 40-char SHA.
2. **Overly broad permissions** — zizmor, Scorecard, Poutine, Checkov,
   GHAST, Octoscan. Least privilege is universal; the trigger is usually
   `write-all` or a missing `permissions:` block.
3. **`${{ }}` script injection** — zizmor, Poutine, actionlint, Checkov,
   GHAST, Octoscan. Every serious tool has it; the fix is always "pass via
   `env:`".
4. **`pull_request_target` / pwn-request** — zizmor, Scorecard, Poutine,
   Gato, GHAST, Octoscan. The *modelling* differs: blunt trigger flag
   (GHAST), trigger + checkout (zizmor/Scorecard), trigger + checkout +
   privileged execution (Poutine), live exploitation (Gato).
5. **Self-hosted runner risk** — Poutine, Gato, GHAST, Octoscan.
6. **`ACTIONS_ALLOW_UNSECURE_COMMANDS` / deprecated commands** — Checkov,
   GHAST, actionlint, Octoscan.
7. **Secrets handling** — the weakest consensus: only `unredacted-secrets`
   (zizmor), `job_all_secrets` (Poutine), `[credentials]` (actionlint),
   `token_security` (seanwevans/Ghast). **No tool has a dedicated
   "secret echoed to logs" static check** — the PDF's requirement is
   genuinely under-served.

### 15.2 Gaps — what nobody (or almost nobody) does
| Gap | Evidence | PipeSentry opportunity |
|---|---|---|
| **Jenkinsfile + Actions in ONE tool** | Every tool in §1–§11 is Actions-only (or Jenkins-syntax-only). The only exception is `pipeline-check` (§10.9) — a multi-provider Python CLI with 32 Jenkins checks (JF-001–JF-032) and 39 Actions checks, scores A–D, 111 autofixers — but it has no menu, and it is not Jenkins-official. No *open, Jenkins-official* tool scans both. | **Core differentiator — the PDF's stretch item.** One scanner, two parsers. |
| **Beginner-friendly interactive menu** | **Zero tools have one.** All are CLI-args-only. Closest: seanwevans/Ghast `--interactive` fix review (reviews fixes one by one) and Gato's post-exploitation shell. | **Core differentiator — same menu pattern as SSTIProbe/RBACLens** (numbered menu, `[?]` prompts, config block). This alone makes PipeSentry the easiest tool to demo to an instructor. |
| **Baseline mode (only new findings)** | Only seanwevans/Ghast (`ghast baseline` JSON burndown) and Checkov (`.checkov.baseline`) and detect-secrets (baseline file) have it. None of the big three (zizmor/Scorecard/Poutine) do. | **PDF stretch item** — implement `.pipesentry-baseline.json`. |
| **Secrets echoed to logs (static)** | No tool flags `echo $SECRET` / `echo ${{ secrets.X }}` in `run:` blocks as a first-class check. Gato does it by *exploiting*; the rest ignore it. | **PDF core requirement** — a dedicated check with the exact `run:` line. |
| **Taint tracking across steps/jobs** | Only citizen204/ghast (taint) and ci-sentinel (paid) attempt it. zizmor/Poutine/GHAST are per-step pattern matchers. | Stretch: track a secret/untrusted value from `env:`/`inputs` into a `run:` sink. |
| **Score / grade (0–100 + letter)** | Only Scorecard (0–10 per check, weighted) and Polaris-style tools in the K8s world do this. No Actions scanner gives a single 0–100 score + grade. | Reuse RBACLens' scoring model (Critical −25, High −10, Medium −5, Low −2, clamp 0–100, grades A–F) — instant familiarity for the instructor. |
| **Offline CVE data for actions** | Poutine needs OSV (online); zizmor's `known-vulnerable-actions` needs a token. Only alex-jung's PipeGuard ships an offline CVE DB. | Ship a small bundled known-vulnerable list (tj-actions, etc.) — offline by default. |
| **Auto-fix** | Only zizmor `--fix`, pinact, StepSecurity, seanwevans/Ghast. | Stretch: `--fix` that rewrites tags to SHAs (pinact-style) — but keep it optional and explicit. |
| **Docker-action digest pinning** | Poutine's `unpinnable_action` touches it; nobody else checks `@sha256:` digests on Docker actions. | Check `uses: docker://image:tag` → require `@sha256:`. |
| **`workflow_run` / reusable-workflow chains** | Only Gato-X (cross-repo/reusable analysis) and Poutine's `untrusted_checkout_exec` model them. | Check `workflow_run` triggers + `workflow_call` inputs for the same pwn-request pattern. |

### 15.3 Menu check — verified
**No tool in this report has an interactive numbered menu.** Every one is
CLI-args-only (or a web app / GitHub Action). The only interactive elements
anywhere are seanwevans/Ghast's `--interactive` fix review and Gato's
post-exploitation shell. PipeSentry's menu (SSTIProbe/RBACLens pattern) is a
genuine, demonstrable difference — and it matches how the instructor will
actually run the tool in a demo.

### 15.4 What PipeSentry should copy
- **zizmor's audit list** as the reference check set — especially
  `template-injection`, `dangerous-triggers`, `excessive-permissions`,
  `unpinned-uses`, `artipacked`, `cache-poisoning`, `unredacted-secrets`.
- **GHAST (bin3xish477) check IDs** as the naming model — `check_for_*`
  names are readable in a report; seanwevans/Ghast's severity scale
  (CRITICAL/HIGH/MEDIUM/LOW) is the right scale to use.
- **Poutine's modelling** of pwn-request as *trigger + checkout + privileged
  execution*, not a blunt trigger flag (GHAST's false-positive problem).
- **Scorecard's file:line details** and its `Pinned-Dependencies`
  remediation style (link a fix, don't just complain).
- **Checkov's CKV IDs** as an example of stable, citable check IDs —
  PipeSentry should give every rule a stable ID (e.g. `PS-001` …) and a
  `--list-checks` flag, like GHAST's.
- **detect-secrets / seanwevans baseline** as the baseline-mode pattern.
- **Gitleaks' regex + entropy + allowlist** as the secrets-check pattern.
- **actionlint's `file:line:col` output** as the report format model, and
  its `-format` Go-template pattern if a JSON/SARIF export is needed without
  a native flag — but prefer native JSON/SARIF like zizmor/Poutine.
- **warnings-ng's SARIF consumption** — emit SARIF so Jenkins' warnings-ng
  plugin (and GitHub code scanning) can display findings with source
  annotations, trends and quality gates.
- **The documented Jenkins rule inventories** — Credentials Binding docs,
  J01–J18 (Jenkinsfile Safety Check), JF-001–JF-032 (pipeline-check),
  ci-sentinel's Jenkins table — as the Jenkins rule set; PipeSentry codifies
  documented practice, it does not invent it.
- **RBACLens' scoring + report format** (score 0–100 + grade A–F, text +
  JSON reports, `file, line, severity, fix`) — the PDF asks for exactly
  "file, line, severity, fix" in the report.

### 15.5 What PipeSentry should NOT copy
- **Gato's offensive model** — no exploitation, no `attack` subcommand, no
  token needed, no live API access. Detection only (same rule as SSTIProbe).
- **GHAST (bin3xish477) bluntness** — flagging `pull_request_target` or
  `actions/cache` on sight produces false positives that cost marks in a
  demo. Model the *combination* (trigger + checkout + secrets/permissions).
- **Checkov's thin GHA framework** — 8 checks, cosign checks most repos fail.
  Do not treat Checkov's check IDs as the standard; the checkov.io index is
  authoritative and its GHA set is weak.
- **CredScan's licensing model** — proprietary, premium, Azure-only. Do not
  depend on any paid service.
- **Poutine's telemetry** — a once-per-24h version check phoning home is
  unnecessary in a student tool.
- **zizmor's online-audit dependency** — PipeSentry must work fully offline
  on a local folder (like RBACLens does on a folder of YAML).

### 15.6 Proposed PipeSentry rule set (from the PDF + this research)
Map the PDF's requirements to rule IDs, using the gaps above:

| ID | Severity | Check (PDF requirement in brackets) |
|---|---|---|
| PS-001 | High | `pull_request_target` + `actions/checkout` of PR code (pwn-request) [PDF: flag pull_request_target + checkout — high] |
| PS-002 | High | `${{ github.event... }}` / untrusted context interpolated into `run:` (script injection) [PDF: detect `${{ github.event... }}` in run blocks] |
| PS-003 | Medium | Third-party action not pinned to full 40-char SHA [PDF: check pinning to full commit SHA] |
| PS-004 | High | Secret echoed to logs (`echo ${{ secrets.X }}`, `echo $SECRET`, `printenv` in `run:`) [PDF: secrets echoed to logs] |
| PS-005 | High | Overly broad permissions (`write-all`, `contents: write` at top level, no `permissions:` block on risky trigger) [PDF: overly broad permissions] |
| PS-006 | Medium | `ACTIONS_ALLOW_UNSECURE_COMMANDS` / deprecated `set-output`/`save-state` |
| PS-007 | Medium | `actions/cache` on a privileged trigger (cache poisoning) |
| PS-008 | Medium | `curl \| sh` / remote script execution in `run:` |
| PS-009 | High | `secrets: inherit` / all-secrets exposure to a reusable workflow job |
| PS-010 | Medium | Self-hosted runner on a PR-triggered job |
| PS-011 | Low | Workflow/action with no `name:`; job with no `timeout-minutes` |
| PS-012 | Medium | Docker action not pinned by `@sha256:` digest |
| PS-013 | High | Jenkinsfile: plaintext credential in `environment {}` [stretch] |
| PS-014 | High | Jenkinsfile: secret interpolated into double-quoted `sh` GString [stretch] |
| PS-015 | Critical | Jenkinsfile: `evaluate()` / `load` on untrusted content [stretch] |
| PS-016 | Medium | Jenkinsfile: `agent any` on a job that handles secrets / deploys [stretch] |
| PS-017 | Medium | Jenkinsfile: `@Library` on a mutable ref (branch/tag, not SHA) [stretch] |
| PS-018 | Medium | Jenkinsfile: deploy stage with no `input()` approval gate [stretch] |

Report format (per PDF): **file, line, severity, fix** — plus the rule ID,
the matched evidence line, and a score 0–100 + grade A–F (RBACLens model).
Stretch: **JSON report** and **baseline mode** (only new findings).

### 15.7 Interface decision (from the research)
- **Menu by default** (like SSTIProbe/RBACLens): [1] Scan a folder
  [2] Quick scan bad [3] Quick scan clean [4] List all checks
  [5] Show pinning inventory [6] Run step tests [7] Doctor [0] Exit.
  Red/Orange theme (user chose 19:37 PKT), author only "CyberBoy50".
- **CLI flags** mirroring the ecosystem: path positional, `-o/--output`,
  `--json`, `--min-severity`, `--fail-on`, `--check`, `--skip-check`,
  `--list-checks`, `--baseline`, `-q/--quiet`, `--batch`, `--version`,
  `--no-color` — same flag vocabulary as zizmor/Poutine/Checkov/GHAST so
  the tool feels familiar to anyone who has used them.
- **Zero online dependency**: PyYAML only (like RBACLens), works on a local
  folder, no token, no API calls, no telemetry.

---

## Sources

- zizmor repo + docs: `github.com/zizmorcore/zizmor`, `docs.zizmor.sh/audits/`,
  `docs.zizmor.sh/quickstart/`, `docs.zizmor.sh/configuration/`
- OpenSSF Scorecard: `github.com/ossf/scorecard`, `scorecard.dev`,
  scorecard-action README
- Poutine: `github.com/boostsecurityio/poutine`,
  `boostsecurityio.github.io/poutine/rules/*`, blog.kammel.dev write-up
- Gato: `github.com/praetorian-inc/gato`, Trajan
  (`praetorian-inc/trajan`), Gato-X (`AdnaneKhan/gato-x`)
- actionlint: `github.com/rhysd/actionlint`, `rhysd.github.io/actionlint/`
  (playground), WordPress standard (actionlint + zizmor)
- StepSecurity: `github.com/step-security/secure-workflows`,
  `github.com/step-security/harden-runner`,
  `app.stepsecurity.io/secureworkflow/...`, pinact
  (`github.com/suzuki-shunsuke/pinact`)
- Checkov: `github.com/bridgecrewio/checkov`, checkov.io policy index
  (GHA framework), `checkov --list`
- GHAST: `github.com/bin3xish477/ghast` (PyPI `ghast-scanner`),
  `github.com/seanwevans/Ghast` (PyPI `ghast`),
  `github.com/citizen204/ghast`, Benedetti et al. SCORED '22
  (arXiv:2208.03837)
- CredScan: Microsoft Learn "Customize Microsoft Security Code Analysis
  tasks", gregorsuttie.com CredScan walkthrough, ecanarys.com implementation
  guide, grizzlypeaksoftware.com Azure Pipelines scanning guide
- Gitleaks: `github.com/gitleaks/gitleaks`; TruffleHog:
  `github.com/trufflesecurity/trufflehog`; detect-secrets:
  `github.com/Yelp/detect-secrets`
- Jenkins: `alpha.docs.jenkins.io/user-docs/2.504.x/pipeline/development.html`
  (declarative linter), `docs.cloudbees.com` pipeline dev tools,
  `github.com/jenkinsci/jenkinsfile-runner`, CodeNarc, npm-groovy-lint,
  jenkinsfile-validator, ci-sentinel
- Octoscan: `github.com/synacktiv/octoscan`
- GitHub docs: "Security hardening for GitHub Actions"
  (docs.github.com), `actions/checkout` v7 release notes,
  `gh actions-lock` (GA Oct 28, 2026), GHSA-fgv8-vgyp-7mq3
- PipeGuard collisions: `github.com/alex-jung/pipeguard-cli`
  (PyPI `pipeguard-cli`), `github.com/karlhillx/pipeguard`,
  `github.com/tazi06/pipeguard` [prior context],
  `github.com/Steeve-Crypto/pipeguard` [prior context],
  PyPI `pipelineguard-ai`, PyPI `pipguard`
- Incidents: tj-actions/changed-files (Mar 2025), Trivy
  (CVE-2026-33634, Mar 2026), PyTorch self-hosted runner (Gato, StepSecurity
  write-up)

*End of report.*
