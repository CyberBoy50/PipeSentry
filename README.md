# PipeSentry — CI/CD Pipeline Security Scanner

A Python command-line tool that audits CI/CD pipeline files and finds the
misconfigurations attackers love — secrets printed to logs, unpinned
third-party actions, dangerous triggers and script injection through
event data. Pipelines run with powerful credentials, and a flaw in the
pipeline file is a flaw in the build itself.

**Author:** CyberBoy50

**Current version:** 1.4

## Legal — authorized use only

DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical, authorized security testing only. You are using it on your own responsibility. The authors are not responsible for how you use it, or for anything that happens because of your use. Only test systems, code, and data you own or have explicit written permission to test — testing anything else may be illegal (for example, PECA 2016 in Pakistan).

The same disclaimer is printed in the tool's banner and written into every report it generates (text and JSON). Version 1.3 adds this explicit disclaimer only; no detection logic, rule, finding, score or behaviour changed. Version 1.4 closes the remaining limits (Jenkinsfile Groovy parsing, Docker Hub digest verification, API cache, repository settings checks, expanded typosquat list) — the disclaimer is unchanged and verbatim.

## What it scans

Two input kinds, in one tool, one report format:

1. **GitHub Actions workflow YAML** — triggers, jobs, steps, `permissions:`,
   environment blocks, `uses:` pins, `run:` blocks.
2. **Jenkinsfiles** — parsed as Groovy (brace-matched stages and steps,
   so findings name their stage as well as their line), then checked for
   plaintext credentials, unguarded shell steps, `input` steps without
   a timeout.

It works **offline on files** — no live cluster, no credentials, no
network. Point it at your own pipeline files (or a folder you exported),
never at a repository you do not own. With `--verify-online` (v1.1) it
also checks pinned SHAs against GitHub (PG-020) and docker digests
against Docker Hub (PG-022) — the only features that need internet,
and their responses are cached locally so repeat runs cost no requests.
With `--repo owner/repo` (v1.4) it also checks repository settings —
branch protection, Actions permissions and the OIDC subject claim
(PG-023/024/025) — which needs a `GITHUB_TOKEN`.

## Quick start

```bash
git clone https://github.com/CyberBoy50/PipeSentry.git
cd PipeSentry
python run.py setup        # creates a venv, installs PyYAML + colorama
python run.py scan test_workflows/bad     # 39 findings, score 0/100 (F)
python run.py scan test_workflows/clean   # 0 findings, score 100/100 (A)
python run.py test         # 157 step-test checks — all should pass
```

Or run the tool directly (needs PyYAML installed):

```bash
pip install pyyaml colorama
python pipesentry.py                  # numbered menu (SSTIProbe style)
python pipesentry.py path/to/pipelines
```

Windows: double-click `run.bat`. Linux / macOS: `./run.sh`.

## The checks (25 rules)

| Rule | Severity | Check |
|------|----------|-------|
| PG-001 | Critical | `pull_request_target` checks out PR head code (pwn request) |
| PG-002 | High | `pull_request_target` without checkout |
| PG-003 | High | `workflow_run` executes a downloaded artifact |
| PG-004 | Critical | Script injection via `${{ }}` in `run:` |
| PG-005 | High | Unpinned third-party action |
| PG-006 | Medium | Unpinned first-party action (`actions/*`, `github/*`) |
| PG-007 | Medium/High | Secret echoed to logs (`echo $SECRET`, `printenv`, `set -x`) |
| PG-008 | High | `permissions: write-all` |
| PG-009 | High/Medium | Workflow-level write permission |
| PG-010 | Medium | No `permissions:` block at all |
| PG-011 | Medium | `id-token: write` outside a deploy job |
| PG-012 | High | `ACTIONS_ALLOW_UNSECURE_COMMANDS=true` |
| PG-013 | Low | Checkout persists credentials + artifact upload |
| PG-014 | High | Self-hosted runner with an untrusted trigger |
| PG-015 | Critical/High | Hardcoded credential in a Jenkinsfile |
| PG-016 | High | Unguarded `sh` step in a Jenkinsfile |
| PG-017 | Low | Jenkins `input` step without a timeout |
| PG-018 | High | `secrets: inherit` exposes all secrets |
| PG-019 | Medium | Remote script execution (`curl \| sh`) |
| PG-020 | High | Pinned SHA does not match its tag, or does not exist upstream (`--verify-online` only) |
| PG-021 | High | Action name is a typosquat of a well-known action (e.g. `actions/checkou` vs `actions/checkout`) |
| PG-022 | High | Docker image digest does not match Docker Hub (`--verify-online` only) |
| PG-023 | High/Medium | Default branch has no (or weak) branch protection (`--repo` only) |
| PG-024 | High/Medium | Repository Actions permissions are too broad (`--repo` only) |
| PG-025 | Medium | OIDC subject claim is overly broad (`--repo` only) |

Severity details: PG-001 drops to High for a plain checkout with no
`ref:` (the safety then depends on the checkout version); PG-004 drops
to High when the workflow cannot be triggered by a fork; PG-007 is High
for `printenv` / `set -x` and Medium for a plain echo; PG-015 is
Critical for private keys and AWS keys, High for passwords and tokens.

## Score and exit codes

Score starts at 100 and subtracts points per finding — Critical −25,
High −10, Medium −5, Low −2 — clamped to 0–100, graded A (≥90), B (≥80),
C (≥70), D (≥60), F (<60). The score always reflects **all** findings,
even when `--min-severity` hides some from display.

Exit codes: **0** clean, **1** findings, **2** any Critical (or a
`--fail-on` hit). Use it as a CI gate:

```bash
pipesentry path/to/.github/workflows --fail-on high
```

## Flags

```
pipesentry <path> [-o report.txt] [--json report.json]
    [--min-severity {critical,high,medium,low}]
    [--fail-on {critical,high,medium,low,none}]
    [--check PG-001,PG-004] [--skip-check PG-013]
    [--baseline FILE] [--baseline-write FILE]
    [--verify-online] [--repo OWNER/REPO]
    [--cache-file FILE] [--no-cache]
    [--strict] [-q] [--batch] [-i|--interactive|--menu]
    [--structure] [--list-checks] [--version] [--no-color]
```

- `--strict` — escalates first-party unpinned actions (PG-006) to High.
- `--verify-online` — verify pinned SHAs against GitHub (PG-020): does
  the SHA match its `# vX.Y.Z` comment, and does the SHA exist upstream
  at all? Also verifies `docker://` digests and tags against Docker Hub
  (PG-022), and confirms typosquat suspicions against the GitHub API
  (PG-021 evidence gains a "confirmed online" note when the used action
  does not exist upstream but the well-known one does). Needs internet;
  unauthenticated GitHub API calls are limited to 60/hour — set
  `GITHUB_TOKEN` (classic token, no scopes needed) for 5,000/hour, and
  repeat runs reuse the local API cache (`~/.cache/pipesentry/api_cache.json`,
  24 h) so they cost no requests. If the API is unreachable or
  rate-limited, the scan keeps its other findings and notes the skip.
- `--repo OWNER/REPO` — check repository settings online (PG-023 branch
  protection, PG-024 Actions permissions, PG-025 OIDC subject claim).
  Opt-in and token-gated: without a `GITHUB_TOKEN` it reports
  "not checked — needs a token" instead of failing. Can be combined
  with a file/folder scan, or run on its own
  (`pipesentry --repo owner/repo`).
- `--cache-file FILE` / `--no-cache` — use a different API cache file,
  or disable the cache.
- `--structure` — print the parsed structure (triggers, jobs, steps;
  Jenkinsfile stages and steps) without running any checks.
- `--list-checks` — list all 25 rules with severities.

## Baseline mode (for legacy repos)

A legacy repo has hundreds of findings on day one. Baseline mode answers
one question: **what is NEW since the last approved scan?** Only new
findings fail the gate.

```bash
pipesentry . --baseline-write .pipesentry-baseline.json   # first run: record
pipesentry . --baseline .pipesentry-baseline.json         # later: only new
```

Findings are identified by file + rule + the object they are about —
**never by line number**, because lines shift on every edit. A baseline
never stores secret values (only a hash of the evidence), so it is safe
to commit. With `--baseline` the report shows both scores: overall and
new-findings-only, and the exit code is computed from the new findings.

## The menu

Run `pipesentry` with no arguments (or `python run.py scan` with no
path) to open the numbered menu — same shape as SSTIProbe / RBACLens,
but in the Red/Orange theme:

```
[1] Scan a folder of pipelines
[2] Quick scan: test workflows (bad — planted flaws)
[3] Quick scan: test workflows (clean — should pass)
[4] Show parsed structure of a folder
[5] List all checks
[6] Run step tests
[7] Check setup (doctor)
[8] Scan with online SHA verification (--verify-online)
[9] Check repository settings online (--repo, needs token)
[0] Exit
```

Demo order for a presentation: **7** (doctor) → **5** (checks) →
**2** (bad scan, 0/100) → **3** (clean scan, 100/100).

## Files

```
pipesentry.py          # the tool: parsing, checks, scoring, reports, menu
run.py                 # launcher: setup / scan / test / doctor / checks
run.bat / run.sh       # one-click launch (Windows / Linux-macOS)
test_pipesentry.py     # 12 step tests (157 checks, incl. online PG-020/PG-022, typosquat PG-021, Jenkins parser, API cache, --repo)
requirements.txt       # pyyaml>=6.0, colorama>=0.4.6
test_workflows/bad/    # vulnerable workflows + Jenkinsfile (planted flaws)
test_workflows/clean/  # hardened mirror (must scan clean)
test_jenkins/bad/      # vulnerable Jenkinsfile
test_jenkins/clean/    # clean Jenkinsfile
report_bad.txt / .json # sample reports from the bad folder
report_clean.txt / .json
README.md  DEMO.md  STEP_BY_STEP_GUIDE.md
RESEARCH_CLI_TOOLS.md  RESEARCH_IMPLEMENTATION.md
```

## How it works inside

1. **Parse** — a custom PyYAML loader (`LineLoader`) stamps every
   mapping, list and string scalar with its 1-based source line, so
   every finding reports the exact line it is on. It also fixes the
   YAML 1.1 gotcha where `on:` parses as boolean `True`, and rejects
   duplicate keys (a second `permissions:` block must not silently
   hide the first).
2. **Trigger analysis** — `on:` is normalised from every form it can
   take (scalar, list, mapping), then checked against the checkout
   steps: `pull_request_target` + a checkout of PR head code is the
   pwn-request pattern.
3. **Injection analysis** — every `${{ }}` in a `run:` block is
   checked against a tiered list of attacker-controlled expressions
   (PR titles, issue bodies, branch names). `env:` values are never
   scanned — passing a value through `env:` is the fix, not a finding.
4. **Secret analysis** — per step, the tool collects which env vars
   hold secrets (step `env:` + job `env:` + workflow `env:`), then
   scans the step's `run:` for prints of those names.
5. **Typosquat analysis (v1.2, PG-021; expanded v1.4)** — every remote
   `uses:` name is compared with a curated list of 150+ well-known
   actions (`difflib.SequenceMatcher`); a name that is close but not
   exact (ratio ≥ 0.85, e.g. `actions/checkou` vs `actions/checkout`) is
   flagged, while exact matches and unrelated custom actions are not.
   With `--verify-online` the suspicion is confirmed against the GitHub
   API: the used action must not exist upstream while the well-known
   one does.
6. **Jenkinsfile analysis (v1.4)** — the Jenkinsfile is parsed as
   Groovy: brace matching (ignoring braces inside strings and comments)
   recovers the real stage/step structure, so findings name their stage
   as well as their line, and an `input` step is only flagged when it
   is not wrapped in a `timeout { }` block. `--structure` prints the
   parsed stages and steps.
7. **Docker Hub verification (v1.4, PG-022)** — with `--verify-online`,
   a `docker://image@sha256:<digest>` pin is checked against the
   image's tags on Docker Hub (the digest must be one the image
   actually has), and a `docker://image:tag` pin is checked to exist.
8. **Repository settings (v1.4, PG-023/024/025)** — with `--repo
   owner/repo` and a `GITHUB_TOKEN`, the GitHub API is asked for the
   default branch's protection, the Actions permissions (allowed
   actions, default workflow permissions, can-approve) and the OIDC
   subject claim customisation. Without a token nothing is checked.
9. **API cache (v1.4)** — GitHub and Docker Hub responses are cached
   locally (`~/.cache/pipesentry/api_cache.json`, 24 h; 404s for 1 h),
   so repeat runs cost no requests. On a rate limit or network failure
   a stale cached answer is used instead of failing the scan.
10. **Report** — text (file, line, severity, evidence, fix) and JSON,
    with a score, a grade and a defensive lesson.

## Limits (stated honestly)

Version 1.4 closes every limit the v1.3 report listed — there are no
known remaining shortcomings:

- **Typosquat list** — the curated list grew from 44 to 150+ well-known
  actions across the ecosystem, and with `--verify-online` a suspicion
  is confirmed against the GitHub API (the used action must not exist
  upstream while the well-known one does).
- **Jenkinsfile parsing** — Jenkinsfiles are now parsed as Groovy
  (brace-matched stages/steps), not scanned as raw text; findings name
  their stage, and `input`-without-`timeout` is decided by block
  structure, not a line window. Control-flow analysis (following
  `if`/`when` branches) is still out of scope — a finding means the
  pattern is present, not that it always executes.
- **Docker digests** — `docker://` digests and tags are verified
  against Docker Hub with `--verify-online` (PG-022). Images on other
  registries (`ghcr.io`, `gcr.io`, …) are out of scope for that check
  and are skipped, not flagged.
- **GitHub API rate limit** — responses are cached locally for 24 h
  (404s for 1 h), so repeat runs cost no requests; `GITHUB_TOKEN`
  still raises the limit from 60/hour to 5,000/hour, and a stale
  cached answer is used when the API is rate-limited or unreachable.
- **Repository settings** — `--repo owner/repo` (token-gated, opt-in)
  checks branch protection, Actions permissions and the OIDC subject
  claim (PG-023/024/025). It reads settings only; it never changes
  anything, and it only works on repositories the token can see.
- Composite actions (`action.yml`) are scanned with the same rules as
  workflows when they appear in the folder.
- This tool finds flaws; it does not exploit anything. Only scan
  pipeline files you own or have written permission to scan.

## Research

Before building, 14+ existing tools were read (zizmor, OpenSSF
Scorecard, Poutine, Gato, actionlint, StepSecurity secure-repo, pinact,
Checkov, GHAST, Gitleaks, TruffleHog, detect-secrets, pipeline-check
and others). The full comparison is in `RESEARCH_CLI_TOOLS.md` and the
implementation notes (line numbers, pinning rules, baseline design) in
`RESEARCH_IMPLEMENTATION.md`. None of them has an interactive menu, and
no Python tool combines GitHub Actions + Jenkinsfile scanning with
baseline mode — that is what PipeSentry adds.

## Cross-platform

| OS | Command |
|----|---------|
| Linux / macOS | `python3 run.py setup` then `python3 run.py scan <folder>` |
| Windows | `python run.py setup` then `python run.py scan <folder>` (or double-click `run.bat`) |

`run.py` picks the right venv Python for the OS automatically.

License: MIT — see LICENSE
