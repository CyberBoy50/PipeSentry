# PipeSentry — CI/CD Pipeline Security Scanner

A Python command-line tool that audits CI/CD pipeline files and finds the
misconfigurations attackers love — secrets printed to logs, unpinned
third-party actions, dangerous triggers and script injection through
event data. Pipelines run with powerful credentials, and a flaw in the
pipeline file is a flaw in the build itself.

**Author:** CyberBoy50

## What it scans

Two input kinds, in one tool, one report format:

1. **GitHub Actions workflow YAML** — triggers, jobs, steps, `permissions:`,
   environment blocks, `uses:` pins, `run:` blocks.
2. **Jenkinsfiles** — scanned as text (plaintext credentials, unguarded
   shell steps, `input` steps without a timeout).

It works **offline on files** — no live cluster, no credentials, no
network. Point it at your own pipeline files (or a folder you exported),
never at a repository you do not own. With `--verify-online` (v1.1) it
also checks pinned SHAs against GitHub (PG-020) — the only feature that
needs internet.

## Quick start

```bash
git clone https://github.com/CyberBoy50/PipeSentry.git
cd PipeSentry
python run.py setup        # creates a venv, installs PyYAML + colorama
python run.py scan test_workflows/bad     # 39 findings, score 0/100 (F)
python run.py scan test_workflows/clean   # 0 findings, score 100/100 (A)
python run.py test         # 72 step tests — all should pass
```

Or run the tool directly (needs PyYAML installed):

```bash
pip install pyyaml colorama
python pipesentry.py                  # numbered menu (SSTIProbe style)
python pipesentry.py path/to/pipelines
```

Windows: double-click `run.bat`. Linux / macOS: `./run.sh`.

## The checks (21 rules)

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
    [--strict] [-q] [--batch] [-i|--interactive|--menu]
    [--structure] [--list-checks] [--version] [--no-color]
```

- `--strict` — escalates first-party unpinned actions (PG-006) to High.
- `--verify-online` — verify pinned SHAs against GitHub (PG-020): does
  the SHA match its `# vX.Y.Z` comment, and does the SHA exist upstream
  at all? Needs internet; unauthenticated GitHub API calls are limited
  to 60/hour — set `GITHUB_TOKEN` (classic token, no scopes needed) for
  5,000/hour. If the API is unreachable or rate-limited, the scan keeps
  its other findings and notes the skip.
- `--structure` — print the parsed structure (triggers, jobs, steps)
  without running any checks.
- `--list-checks` — list all 21 rules with severities.

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
[0] Exit
```

Demo order for a presentation: **7** (doctor) → **5** (checks) →
**2** (bad scan, 0/100) → **3** (clean scan, 100/100).

## Files

```
pipesentry.py          # the tool: parsing, checks, scoring, reports, menu
run.py                 # launcher: setup / scan / test / doctor / checks
run.bat / run.sh       # one-click launch (Windows / Linux-macOS)
test_pipesentry.py     # 9 step tests (90 checks, incl. online PG-020 and typosquat PG-021)
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
5. **Typosquat analysis (v1.2, PG-021)** — every remote `uses:` name is
   compared with a curated list of 44 well-known actions
   (`difflib.SequenceMatcher`); a name that is close but not exact
   (ratio ≥ 0.85, e.g. `actions/checkou` vs `actions/checkout`) is
   flagged, while exact matches and unrelated custom actions are not.
6. **Jenkinsfile analysis** — line-oriented regex scanning, including
   a small state machine for multi-line `sh """..."""` blocks.
7. **Report** — text (file, line, severity, evidence, fix) and JSON,
   with a score, a grade and a defensive lesson.

## Limits (stated honestly)

- The scanner is offline by default: `--verify-online` (v1.1, PG-020)
  checks a pinned SHA against its `# vX.Y.Z` tag and against the
  upstream commit list. Typosquats are checked offline (v1.2, PG-021)
  against a curated list of 44 well-known actions — an attacker can
  still typosquat an action that is not on that list. Online checks
  are also limited to 60 GitHub API requests/hour without a token
  (`GITHUB_TOKEN` raises it to 5,000/hour).
- A Jenkinsfile is scanned as text, not parsed as Groovy, so it cannot
  follow control flow; Jenkinsfile findings are phrased as "pattern
  found on line N".
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
