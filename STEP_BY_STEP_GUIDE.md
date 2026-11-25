# PipeSentry — Step-by-Step Guide

Build plan from the project document, one step at a time. Every step
was tested before moving to the next; the tests live in
`test_pipesentry.py` (run them with `python run.py test`).

## Step 1 — Parse one workflow

**What:** load one GitHub Actions workflow YAML and print its triggers,
jobs and steps — with the line number of every `uses:` value.

**How:** a custom PyYAML loader (`LineLoader` in `pipesentry.py`) stamps
every mapping, list and string scalar with its 1-based source line.
It also fixes the YAML 1.1 gotcha where `on:` parses as boolean `True`,
and rejects duplicate keys (a second `permissions:` block must not
silently hide the first).

**Test:** `test_pipesentry.py` Step 1 — triggers parsed, 4 steps found,
`uses:` line exact, duplicate key raises `ValueError`, a non-workflow
YAML file is skipped with a note.

**Try it:** `python pipesentry.py --structure test_workflows/bad`

## Step 2 — Trigger check

**What:** flag `pull_request_target` combined with a checkout step as
high severity, and `workflow_run` jobs that download and execute an
artifact.

**How:** `on:` is normalised from every form it can take (scalar, flow
list, block list, mapping). Then every job's steps are walked for
`actions/checkout`. PG-001 is Critical when the checkout's `ref:` points
at the PR head, when `allow-unsafe-pr-checkout: true` is set, or when a
`run:` block `git clone`s the PR in the same job; it is High for a plain
checkout with no `ref:`. No checkout at all under
`pull_request_target` is PG-002 (High). A `workflow_run` job with a
`download-artifact` step and a `run:` step in the same job is PG-003
(High).

**Test:** Step 2 — PG-001 Critical on the `ref:` line, PG-002 on
`notify.yml`, PG-003 on `artifacts.yml`, nothing on the clean workflow.

## Step 3 — Pinning check

**What:** check every third-party action reference — pinned to a full
commit SHA, or flagged as unpinned.

**How:** `parse_uses()` splits `owner/repo[/path]@ref [# comment]` into
parts. Only a full 40-hex SHA (or 64-hex SHA-256) counts as pinned.
Third-party unpinned is PG-005 (High); first-party (`actions/*`,
`github/*`) unpinned is PG-006 (Medium, High with `--strict`).
`docker://image:tag` needs a `@sha256:` digest; local `./` actions are
never flagged; a short SHA is not a pin.

**Test:** Step 3 — SHA pinned, `v4` unpinned, 7-char SHA unpinned,
clean workflow has no pinning findings.

## Step 4 — Secret-echo check

**What:** detect secrets referenced in `run:` blocks in ways that print
them to logs.

**How:** for each step, collect the secret-bearing env vars visible to
it (step `env:` + job `env:` + workflow `env:`, where the value contains
`secrets.`), then scan the step's `run:` text: direct `echo ${{
secrets.X }}` (Medium), echo of a secret var (Medium), `printenv` / `env`
(High), `set -x` (High), `echo $VAR | base64` (High — encoded forms
bypass GitHub's log masking). GitHub masks registered secrets, but
substrings and encoded forms are not masked.

**Test:** Step 4 — 6 PG-007 findings in bad `ci.yml` (Medium and High),
none in the clean workflow, `curl | sh` is PG-019.

## Step 5 — Script-injection check

**What:** detect event data interpolated into `run:` blocks.

**How:** every `${{ }}` in a `run:` value is checked against a tiered
list of attacker-controlled expressions — PR titles and bodies, issue
and comment bodies, commit messages, branch names, workflow inputs.
Wrappers like `format()` and `fromJSON()` do not sanitise, so the
check looks inside them, at every argument. `env:` values are never
scanned (passing a value through `env:` is the fix), and neither are
`if:` conditions. Safe values (`github.sha`, `secrets.*`, `vars.*`)
are never flagged.

**Test:** Step 5 — PG-004 Critical on the PR title in `run:`, nothing
when the same value comes through `env:`, nothing for `github.sha`.

## Step 6 — Permissions check + report

**What:** flag overly broad permissions, and save the report to a file
with file name, line number, severity and fix advice for every finding.

**How:** `permissions: write-all` is PG-008 (High); a workflow-level
write scope is PG-009 (High for `contents`, Medium for others); no
`permissions:` block at all is PG-010 (Medium); `id-token: write`
outside a deploy job is PG-011 (Medium). A job-level block replaces the
workflow-level block entirely. `security-events: write` is whitelisted
for the job that uploads SARIF. The report builder writes a text report
(and JSON with `--json`) with file, line, severity, evidence and fix
per finding, plus score, grade and a defensive lesson.

**Test:** Step 6 — PG-008/009/010/011 all fire in the right places, the
report file contains file, line, severity and fix, the JSON report has
the same findings structured.

## Step 7 — Full run on the test folder

**What:** run the tool on the whole test folder and verify every
planted flaw is found, with the right severity and the right line.

**How:** `python run.py scan test_workflows/bad` and
`python run.py scan test_workflows/clean`, plus the Jenkinsfile folders
and baseline mode (`--baseline-write` / `--baseline`).

**Test:** Step 7 — bad folder: all 19 rules fire, 38 findings
(5 critical, 19 high, 12 medium, 2 low), score 0/100 grade F, exit
code 2; clean folder: 0 findings, score 100/100 grade A, exit code 0;
bad Jenkinsfile: PG-015 ×5, PG-016 ×3, PG-017 ×1; clean Jenkinsfile: 0;
baseline: same folder again reports 0 new findings, a clean baseline
makes all 38 findings new, and the baseline file stores no secret
values.

## After the build

1. `python run.py test` — 72 checks, all pass.
2. `python run.py scan test_workflows/bad` — see the 38 findings.
3. `python run.py scan test_workflows/clean` — see the clean pass.
4. Point it at your own pipeline folder: `python run.py scan <folder>`.
5. Use `--fail-on high` as a CI gate, and `--baseline-write` /
   `--baseline` for a legacy repo.
