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

**Test:** Step 7 — bad folder: all 20 offline rules fire, 39 findings
(5 critical, 20 high, 12 medium, 2 low), score 0/100 grade F, exit
code 2; clean folder: 0 findings, score 100/100 grade A, exit code 0;
bad Jenkinsfile: PG-015 ×5, PG-016 ×3, PG-017 ×1; clean Jenkinsfile: 0;
baseline: same folder again reports 0 new findings, a clean baseline
makes all 39 findings new, and the baseline file stores no secret
values.

## Step 8 — Online SHA verification (v1.1, PG-020, PDF ke baad ka upgrade)

**What:** a pinned SHA is only safe if it is the SHA the tag actually
points at — and if it exists upstream at all. `--verify-online` (menu
option 8) asks the GitHub API for each pinned action: the tag's commit
SHA (annotated tags resolved one hop) and whether the pinned commit
exists. Mismatch or missing SHA → PG-020 (High). The clean fixture
uses real SHAs (actions/checkout v4.2.1 and tj-actions/changed-files
v45, taken from the API), so it still scores 100/100; the bad fixture
has one bogus pin (`tj-actions/changed-files@0000… # v45`), so the
online bad scan is 39 findings in v1.1 (41 in v1.2 — the typo pin in
`ci.yml` also fires PG-020, because `actions/checkou` does not exist
upstream at all — and 42 in v1.4, with the bogus docker digest firing
PG-022 against Docker Hub).

**How:** `pipesentry.py <folder> --verify-online`. Only stdlib urllib —
no new dependency. Unauthenticated limit is 60 requests/hour; set
`GITHUB_TOKEN` for 5,000/hour. Responses are cached locally for 24 h
(v1.4, `~/.cache/pipesentry/api_cache.json`), so repeat runs cost no
requests; on a rate limit or network failure a stale cached answer is
used instead of failing the scan. If the API is unreachable or
rate-limited, the scan keeps its other findings and notes the skip.
`PIPE_SENTRY_GITHUB_API` overrides the API base URL (for tests).

**Test:** Step 8 — the tag lookups resolve to the real SHAs, a bogus
SHA does not exist upstream, the clean folder verifies with 0 findings,
the bad folder fires PG-020 twice and PG-022 once (42 findings in
v1.4). The step tests run the full online flow against a local fake
GitHub API server, so they pass even when the real API is rate-limited.

## Step 9 — Typosquat check (v1.2, PG-021, PDF ke baad ka upgrade)

**What:** an action name that is one typo away from a famous one is a
supply-chain trap — attackers publish look-alike actions
(`actions/checkou`, `tj-actions/changed-file`) and wait for a tired
developer to copy the wrong name. PG-021 (High) compares every remote
`uses:` name with a curated list of 150+ well-known actions
(`actions/checkout`, `actions/setup-node`, `docker/build-push-action`,
`tj-actions/changed-files`, `github/codeql-action/analyze`, and more)
using `difflib.SequenceMatcher`: a name that scores 0.85 or higher
against a known action, but is not an exact match, is flagged. Exact
matches never flag, and unrelated custom actions (`my-org/my-action`,
ratio 0.58) never flag either. Local `./` actions and `docker://`
are skipped — they are not GitHub action names.

**How:** `check_typosquat()` in `pipesentry.py`, wired into
`check_workflow()` like every other rule — so it appears in text and
JSON reports, `--list-checks`, scoring (High, −10) and the menu checks
list. Only stdlib `difflib` — no new dependency. The bad fixture has
one typo step (`actions/checkou@eef61447… # v4.2.1`, pinned with the
real checkout SHA on purpose, so offline it fires PG-021 only).

**Test:** Step 9 — exact known action does not flag, a close typo
flags once with the right line and both names in the evidence, an
unrelated custom action does not flag, a below-threshold name
(`actions/foobar`, ratio 0.69) does not flag, the bad folder fires
PG-021 once, the clean folder fires none. v1.4: the list has 150+
entries, typos of newly listed actions flag, and with
`--verify-online` the evidence gains a "confirmed online" note when
the used action does not exist upstream but the well-known one does.

## Step 10 — Jenkinsfile Groovy parser (v1.4)

**What:** a Jenkinsfile is parsed as Groovy, not scanned as raw text —
so findings point at real pipeline structure instead of raw text lines.

**How:** `parse_jenkinsfile()` in `pipesentry.py` walks the file with
brace matching: `pipeline {`, `stages {`, `stage('Build') {`,
`steps {`, `timeout(...) {`, `withCredentials(...) {`. Braces inside
string literals and `//` comments do not count, triple-quoted
`sh """..."""` blocks do not disturb the depth, and stage names are
read from the raw line (they sit inside quotes). The parse returns
stages (name, line, end line, steps) and steps (kind, line, stage,
whether the step sits inside a `timeout` block). PG-015/PG-016
findings now name their stage (`stage=Build:line=12`); PG-017
(`input` without a timeout) is decided by block structure — is the
`input` step inside a `timeout { }` block — instead of the old ±5-line
text window, which false-positived on the correct pattern (timeout
*wraps* input from above). `--structure` prints the parsed stages and
steps. An unbalanced file is reported as a note, not a crash.

**Test:** Step 10 — bad Jenkinsfile parses to stages Build and
Approve, Build holds 6 steps, the `input` step is not inside a
timeout (clean file: it is), findings name their stage, braces inside
strings do not break parsing, unbalanced braces are reported.

## Step 11 — Docker Hub digest check + API cache (v1.4)

**What:** `docker://` digests are verified online (PG-022), and API
responses are cached locally so repeat runs do not burn the rate limit.

**How:** `check_docker_online()` collects every `docker://` action
from `check_pinning()` (tag pins and digest pins alike) and asks the
Docker Hub tag API: a `sha256:` digest must be one of the digests the
image actually has, and a tag must exist. A missing digest or tag is
PG-022 (High). Images on other registries (`ghcr.io`, …) are skipped,
not flagged. The bad fixture has a bogus digest pin
(`docker://alpine@sha256:0000…`), so the online bad scan is 42
findings. The API cache (`~/.cache/pipesentry/api_cache.json`,
override with `PIPE_SENTRY_CACHE_FILE`, disable with `--no-cache`)
stores GitHub and Docker Hub responses for 24 h (404s for 1 h); on a
rate limit or network failure a stale cached answer is used instead of
failing the scan. `PIPE_SENTRY_DOCKER_HUB_API` overrides the Hub base
URL (for tests).

**Test:** Step 11 — the first online scan hits both APIs, the second
identical scan makes zero requests and finds the same 42 findings,
the cache file is written, a real digest passes, a bogus digest and a
missing tag each fire PG-022 once, `--no-cache` disables the cache.

## Step 12 — Repository settings check (v1.4, `--repo`)

**What:** an optional online `--repo owner/repo` mode checks the
repository settings a file scan cannot see: branch protection,
Actions permissions and the OIDC subject claim (PG-023/024/025).

**How:** `check_repo()` in `pipesentry.py`, using the GitHub API with
a token. PG-023 (High): the default branch has no branch protection;
(Medium) protection exists but requires neither a PR review nor status
checks. PG-024 (High): the repo allows all third-party actions, or the
default workflow permissions are write; (Medium) workflows can approve
PR reviews. PG-025 (Medium): a custom OIDC subject claim with no
`:ref:` or `:environment:` qualifier. The mode is opt-in and
token-gated: without `GITHUB_TOKEN` it reports "not checked — needs a
token" instead of failing, and it only reads settings — it never
changes anything. It runs on its own (`pipesentry --repo owner/repo`,
menu option 9) or combined with a file/folder scan, sharing the same
report, score and exit code.

**Test:** Step 12 — no token means no findings and a "needs a token"
note (exit 0); a wide-open repo fires PG-023 once, PG-024 three times
and PG-025 once (5 findings, score 60, exit 1); a locked-down repo is
clean; a repo the token cannot see is a note, not a crash; combined
mode adds the repo findings to a clean file scan.

## After the build

1. `python run.py test` — 157 checks, all pass.
2. `python run.py scan test_workflows/bad` — see the 39 findings.
3. `python run.py scan test_workflows/clean` — see the clean pass.
4. Point it at your own pipeline folder: `python run.py scan <folder>`.
5. Use `--fail-on high` as a CI gate, and `--baseline-write` /
   `--baseline` for a legacy repo.
