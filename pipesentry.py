#!/usr/bin/env python3
"""
PipeSentry — CI/CD Pipeline Security Scanner
=============================================
A command-line tool, written in Python, that reads CI/CD pipeline files
and finds the misconfigurations attackers love — secrets printed to logs,
unpinned third-party actions, dangerous triggers and script injection
through event data. Pipelines run with powerful credentials, and a flaw
in the pipeline file is a flaw in the build itself.

Two input kinds:
  1. GitHub Actions workflow YAML — triggers, jobs, steps, permissions,
     environment blocks, uses: pins, run: blocks.
  2. Jenkinsfiles — scanned as text (plaintext credentials, unguarded
     shell steps, input steps without a timeout).

It works on FILES ONLY — no live cluster, no credentials, no network.
Point it at your own pipeline files (or a folder you exported), never
at a repository you do not own.

Version: 1.0
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime

VERSION = "1.0"
AUTHOR = "CyberBoy50"

try:
    import yaml
    from yaml.loader import SafeLoader
except ImportError:  # pragma: no cover
    yaml = None
    SafeLoader = object

try:
    import colorama
    colorama.init()
except Exception:  # pragma: no cover
    pass


# ---------------------------------------------------------------- YAML lines
# Approach B from RESEARCH_IMPLEMENTATION.md §1: a custom SafeLoader that
# stamps every mapping / sequence / string scalar with its 1-based source
# line. Verified pattern (Apache Beam's SafeLineLoader, same idea).
# Two gotchas fixed here (both caught by runtime tests in the research):
#  * a plain list cannot take attributes, so sequences need a TaggedList
#    subclass, wrapped in construct_yaml_seq (NOT construct_sequence —
#    the stock construct_yaml_seq discards that return value);
#  * the override must be RE-REGISTERED with add_constructor, because
#    SafeLoader bound the stock function at class creation.
# Plus duplicate-key rejection (RBACLens StrictLoader pattern): a second
# `permissions:` block must not silently hide the first.
if yaml is not None:

    class LineLoader(SafeLoader):
        """SafeLoader that stamps every mapping / sequence / string scalar
        with its 1-based source line."""

        class TaggedString(str):
            """A str that also carries ._line_. Compares equal to plain
            str, so all existing string checks keep working."""
            pass

        class TaggedList(list):
            """A list that also carries .__line__."""
            pass

        def construct_scalar(self, node):
            value = super().construct_scalar(node)
            if isinstance(value, str):
                value = self.TaggedString(value)
                value._line_ = node.start_mark.line + 1
                # Block scalars (|, >) start content on the NEXT line;
                # the match_line() helper below needs this flag.
                value._block_ = node.style in ("|", ">")
            return value

        def construct_mapping(self, node, deep=False):
            # flatten_mapping resolves merge keys (<<: *base) first,
            # so anchors keep working; then build the dict by hand so
            # a repeated key is an error, not a silent overwrite.
            self.flatten_mapping(node)
            mapping = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in mapping:
                    raise ValueError("Duplicate key: %r" % (key,))
                mapping[key] = self.construct_object(value_node, deep=deep)
            mapping["__line__"] = node.start_mark.line + 1
            return mapping

        def construct_yaml_seq(self, node):
            # Generator, mirroring the stock implementation exactly
            # except the yielded object is a TaggedList.
            data = self.TaggedList()
            yield data
            data.extend(self.construct_sequence(node))
            data.__line__ = node.start_mark.line + 1

    # Re-register the sequence constructor: without this line the
    # override above is dead code.
    LineLoader.add_constructor(
        "tag:yaml.org,2002:seq", LineLoader.construct_yaml_seq)

else:  # pragma: no cover
    LineLoader = None


def load_workflow(text):
    """Load one workflow YAML file, with line numbers attached.
    Fixes the YAML 1.1 gotcha: `on:` parses as boolean True."""
    if yaml is None:
        raise ValueError("PyYAML is not installed. Run: python run.py setup")
    data = yaml.load(text, Loader=LineLoader)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("Workflow top level must be a mapping, not %s"
                         % type(data).__name__)
    if True in data:  # YAML 1.1 parsed "on:" as True
        data["on"] = data.pop(True)
    return data


def match_line(value, match_start):
    """1-based file line of a regex match inside a YAML scalar value.
    A block scalar (|, >) starts its content on the line AFTER the key."""
    line = value._line_ + value[:match_start].count("\n")
    if getattr(value, "_block_", False):
        line += 1
    return line


def scalar_line(value, default=None):
    """Line of a tagged scalar, or default when it carries none."""
    return getattr(value, "_line_", default)


def mapping_line(mapping, default=None):
    """Line of a mapping (its first key), or default."""
    if isinstance(mapping, dict):
        return mapping.get("__line__", default)
    return default


def items(d):
    """Mapping items, skipping the injected __line__ key."""
    return ((k, v) for k, v in (d or {}).items() if k != "__line__")


# ---------------------------------------------------------------- colours
# TraceRecon style, like SSTIProbe / RBACLens: one class, short names.
# PipeSentry theme is RED / ORANGE (user's choice): the accent colour
# for separators, headers and menu brackets is red, highlights are
# yellow-orange. Severity colours stay the same everywhere.
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[1;31m"
    GRN = "\033[1;32m"
    YEL = "\033[1;33m"
    BLU = "\033[1;34m"
    MAG = "\033[1;35m"
    CYN = "\033[1;36m"
    WHT = "\033[1;37m"
    # Old names, kept working.
    GREEN = GRN
    YELLOW = YEL
    BLUE = BLU
    CYAN = CYN
    BOLD = BLD
    RESET = RST

    @classmethod
    def disable(cls):
        for attr in ("RST", "BLD", "DIM", "RED", "GRN", "YEL", "BLU", "MAG",
                     "CYN", "WHT", "GREEN", "YELLOW", "BLUE", "CYAN",
                     "BOLD", "RESET"):
            setattr(cls, attr, "")


RED = C.RED
GREEN = C.GRN
YELLOW = C.YEL
CYAN = C.CYN
BOLD = C.BLD
RESET = C.RST
ACCENT = C.RED      # PipeSentry theme: red separators / brackets
ACCENT2 = C.YEL     # PipeSentry theme: orange highlights


def clear():
    """Clear the screen — GhostTrack / TraceRecon pattern.
    Windows: cls, macOS/Linux: clear."""
    os.system("cls" if os.name == "nt" else "clear")


def sep(color=ACCENT, char="─", width=58):
    """A rule line, TraceRecon style: sep(C.RED, '─') / sep(C.RED, '═')."""
    print(f"{color}{char * width}{C.RST}")


def header(title, color=ACCENT):
    """A titled section header with rule lines above and below."""
    sep(color)
    print(f"{color} {title}{C.RST}")
    sep(color)


def ok(msg):
    """[+] success line: ' [+] message' — white brackets, green plus."""
    print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")


def warn(msg):
    """[!] warning line, yellow."""
    print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")


def err(msg):
    """[x] error line, red."""
    print(f" {C.WHT}[{C.RED}x{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")


def info(label, value=None, label_color=C.WHT, val_color=C.GRN):
    """One aligned field — TraceRecon style:
    ' Target                : value' (label 22 chars, white; value green).
    Called with one argument it prints a plain [*] line, like before."""
    if value is None:
        print(f"{C.CYN}[*]{C.RST} {label}")
        return
    print(f" {label_color}{label:<22}{C.RST}: {val_color}{value}{C.RST}")


BANNER = r"""
 ____  _            ____             _
|  _ \(_)_ __   ___/ ___|  ___ _ __ | |_ _ __ _   _
| |_) | | '_ \ / _ \___ \ / _ \ '_ \| __| '__| | | |
|  __/| | |_) |  __/___) |  __/ | | | |_| |  | |_| |
|_|   |_| .__/ \___|____/ \___|_| |_|\__|_|   \__, |
        |_|                                   |___/
"""


def banner():
    print()
    print(f"{C.BOLD}{C.RED}{BANNER}{C.RST}", end="")
    print(f"{C.YEL}  PipeSentry — CI/CD Pipeline Security Scanner{C.RESET}")
    print(f"{C.DIM}  Version {VERSION}  |  Author: {AUTHOR}{C.RESET}")
    print(
        f"{C.YEL}  [!] LEGAL DISCLAIMER: Only scan pipeline files you own or have{C.RESET}"
    )
    print(
        f"{C.YEL}      written permission to scan — your own repos or lab.{C.RESET}"
    )
    # TraceRecon-style box under the banner, like SSTIProbe / RBACLens.
    print(f"{C.RED}")
    print("┌" + "─" * 50 + "┐")
    print("│" + ("PipeSentry v" + VERSION + " — files only, no network").center(50) + "│")
    print("│" + "For authorized use only".center(50) + "│")
    print("└" + "─" * 50 + "┘")
    print(f"{C.RST}", end="")
    print()


# ---------------------------------------------------------------- severities
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_POINTS = {"critical": -25, "high": -10, "medium": -5, "low": -2}

# Rule catalogue: id -> (title, severity, fix)
# PG-001..PG-017 from RESEARCH_IMPLEMENTATION.md §9; PG-018/PG-019 from
# RESEARCH_CLI_TOOLS.md §15.6 (PS-009, PS-008).
RULES = {
    "PG-001": ("pull_request_target checks out PR head code", "critical",
               "Split the workflow: untrusted code under pull_request, "
               "privileged work under workflow_run — never check out "
               "fork code in a pull_request_target job."),
    "PG-002": ("pull_request_target without checkout", "high",
               "Prefer pull_request unless you need secrets; keep the job "
               "free of PR-controlled data."),
    "PG-003": ("workflow_run executes a downloaded artifact", "high",
               "Download one bounded artifact, validate it against a "
               "schema, never execute it directly."),
    "PG-004": ("Script injection via ${{ }} in run:", "critical",
               "Move the value to env: and reference \"$VAR\" in the "
               "script — never interpolate event data into run:."),
    "PG-005": ("Unpinned third-party action", "high",
               "Pin to the full 40-char commit SHA, keep the version as "
               "a # vX.Y.Z comment. (tj-actions, CVE-2025-30066: attackers "
               "rewrote version tags and 23,000+ repos ran malicious code.)"),
    "PG-006": ("Unpinned first-party action", "medium",
               "Pin to the full 40-char commit SHA."),
    "PG-007": ("Secret echoed to logs", "medium",
               "Do not print secrets; remove the echo. If a value must be "
               "inspected, use ::add-mask:: before any command that might "
               "print it."),
    "PG-008": ("permissions: write-all", "high",
               "Replace with contents: read; grant writes per job."),
    "PG-009": ("Workflow-level write permission", "high",
               "Move the write scope to the job that needs it."),
    "PG-010": ("No permissions: block", "medium",
               "Declare permissions: {contents: read} explicitly; do not "
               "depend on the repo default."),
    "PG-011": ("id-token: write outside deploy job", "medium",
               "Restrict id-token: write to the deploy job."),
    "PG-012": ("Unsecure workflow commands enabled", "high",
               "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS."),
    "PG-013": ("Checkout persists credentials + artifact upload", "low",
               "Set persist-credentials: false on the checkout step."),
    "PG-014": ("Self-hosted runner with untrusted trigger", "high",
               "Use GitHub-hosted runners for PR-triggered jobs."),
    "PG-015": ("Hardcoded credential in Jenkinsfile", "critical",
               "Move it to the Jenkins credentials store and reference it "
               "by credentialsId."),
    "PG-016": ("Unguarded sh step in Jenkinsfile", "high",
               "Use single-quoted sh strings; pass values via env."),
    "PG-017": ("Jenkins input step without timeout", "low",
               "Add timeout: time: 30, unit: 'MINUTES'."),
    "PG-018": ("secrets: inherit exposes all secrets", "high",
               "Pass only the secrets the called workflow needs, by name — "
               "never secrets: inherit."),
    "PG-019": ("Remote script execution (curl | sh)", "medium",
               "Download the script, verify its hash, then run the local "
               "copy — never pipe a remote URL straight into a shell."),
}

FIRST_PARTY = {"actions", "github"}   # GitHub-authored actions

TRIGGERS_PRIVILEGED = {"pull_request_target", "workflow_run"}
TRIGGERS_UNTRUSTED = {"pull_request_target", "workflow_run",
                      "issue_comment", "pull_request_review"}

WRITE_SCOPES = {"contents", "issues", "pull-requests", "packages",
                "deployments", "statuses", "actions", "checks",
                "security-events", "pages", "discussions",
                "repository-projects", "id-token", "copilot-requests",
                "attestations"}

# --- pinning ---------------------------------------------------------------
SHA_RE = re.compile(r"^[0-9a-f]{40}$")          # full SHA-1, lowercase hex
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")       # future-proof: SHA-256 repos
USES_RE = re.compile(
    r"^(?P<owner>[^/\s]+)/(?P<repo>[^/\s@]+)"
    r"(?P<path>/[^@\s]*)?@(?P<ref>[^\s#]+)"
    r"\s*(?:#\s*(?P<comment>.*))?$")
DOCKER_USES_RE = re.compile(
    r"^docker://(?P<image>[^@\s]+)(?:@(?P<ref>[^\s#]+))?"
    r"\s*(?:#\s*(?P<comment>.*))?$")

# --- script injection (§5) -------------------------------------------------
EXPR_RE = re.compile(r"\$\{\{\s*(.+?)\s*\}\}", re.DOTALL)
WRAPPER_RE = re.compile(
    r"^(?:format|join|fromJSON|toJSON|contains|startsWith|"
    r"endsWith|hashFiles)\s*\((.*)\)$", re.DOTALL)
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
DANGEROUS_EXACT = {
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.commits",
    "github.head_ref",
    "github.event.inputs",
    "inputs",
    "github.event.workflow_run.head_branch",
}

# --- secret echo (§4) ------------------------------------------------------
SECRET_NAME_RE = re.compile(
    r"(SECRET|TOKEN|PASSWOR?D|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|"
    r"CREDENTIAL|AWS_SECRET|CLIENT_SECRET|AUTH)", re.IGNORECASE)
ECHO_EXPR_RE = re.compile(
    r"\becho\b[^\n;|&]*\$\{\{\s*secrets\.[A-Za-z0-9_.-]+\s*\}\}")
PRINTENV_RE = re.compile(r"(?m)^\s*(printenv|env)\s*(?:[|;&\n]|$)")
SETX_RE = re.compile(r"(?m)^\s*set\s+(-[^ \n]*x|--xtrace)\b")
def encoded_echo_re(var_names):
    """echo $VAR | base64 — an encoded form bypasses GitHub's log
    masking. Built from the step's own secret-bearing variable names,
    not a hardcoded list (a var called MY_TOKEN would otherwise slip
    through, because it does not start with SECRET/TOKEN/PASSWORD)."""
    names = "|".join(re.escape(n) for n in var_names)
    return re.compile(
        r"\becho\b[^\n]*\$(\{)?(" + names + r")\}?\b"
        r"[^\n]*\|\s*(base64|xxd|od|rev|tr|sed|awk)\b", re.IGNORECASE)
CURL_AUTH_RE = re.compile(
    r"curl[^\n]*(-u\s+|--user\s+)[^\s]+:[^\s]+")
CURL_PIPE_RE = re.compile(
    r"\bcurl\b[^\n|]*\|\s*(ba)?sh\b")

# --- Jenkinsfile (§7) ------------------------------------------------------
JENKINS_PATTERNS = [
    ("PG-015", "critical",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "Private key in Jenkinsfile — anyone with repo read access has it"),
    ("PG-015", "critical",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS access key ID in Jenkinsfile"),
    ("PG-015", "high",
     re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\b"
                r"\s*[:=]\s*['\"][^'\"]{3,}['\"]"),
     "Hardcoded credential value in Jenkinsfile — move it to the "
     "Jenkins credentials store and reference it by credentialsId"),
    ("PG-015", "high",
     re.compile(r"(?i)\benv\.[A-Z_][A-Z0-9_]*\s*=\s*['\"][^'\"]{3,}['\"]"),
     "Secret assigned to env in plaintext — visible in source control "
     "and in build logs"),
    ("PG-015", "high",
     re.compile(r"curl[^\n]*(-u\s+|--user\s+)[^\s]+:[^\s]+"),
     "Credentials in a curl -u user:pass argument — visible in the "
     "console log and in the process list"),
    ("PG-015", "high",
     re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}"),
     "Hardcoded Basic-auth header in Jenkinsfile"),
    ("PG-015", "medium",
     re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"][^'\"]+['\"]"),
     "AWS secret access key in Jenkinsfile"),
]
WITHCREDS_RE = re.compile(r"\bwithCredentials\s*\(")
DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock")
# A double-quoted Groovy string interpolates ${...} before the shell
# sees it; a single-quoted one does not.
# Real Jenkinsfiles call sh WITH or WITHOUT parens: sh "..." and
# sh("...") are both common — the paren is optional in every pattern.
SH_DQ_INTERP_RE = re.compile(r"""\bsh\s*(?:\(\s*)?"(?:[^"\\]|\\.)*\$\{[^}]+\}""")


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings):
    score = 100 + sum(SEVERITY_POINTS[f["severity"]] for f in findings)
    return max(0, min(100, score))


def summary_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


# ---------------------------------------------------------------- findings
def make_finding(file, line, rule, severity, obj, evidence, key_obj=None):
    """One finding. `key_obj` is the stable anchor for baseline mode;
    when omitted the object string is used (never the line number —
    lines shift on every edit)."""
    title, _sev, fix = RULES[rule]
    key = "|".join([file, rule, key_obj if key_obj is not None else obj])
    norm = " ".join(evidence.lower().split())
    evidence_hash = hashlib.sha256(norm.encode()).hexdigest()[:12]
    return {
        "file": file, "line": line, "rule": rule, "severity": severity,
        "title": title, "object": obj, "evidence": evidence, "fix": fix,
        "key": key, "evidence_hash": evidence_hash,
    }


def finding_to_json(f):
    return {
        "file": f["file"], "line": f["line"], "rule": f["rule"],
        "severity": f["severity"], "title": f["title"],
        "object": f["object"], "evidence": f["evidence"],
        "fix": f["fix"],
    }


# ---------------------------------------------------------------- baseline
BASELINE_VERSION = 1


def load_baseline(path):
    """Returns (by_key, by_hash). Fails loudly on a missing, corrupt or
    unknown-version baseline — never silently scan as if there were none."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("version") != BASELINE_VERSION:
        raise ValueError("Unsupported baseline version: %s"
                         % data.get("version"))
    by_key = {f["key"]: f for f in data.get("findings", [])}
    by_hash = {(f["file"], f["rule"], f["evidence_hash"]): f
               for f in data.get("findings", [])}
    return by_key, by_hash


def split_new_vs_known(findings, by_key, by_hash):
    """Split findings into (new, known) against a loaded baseline."""
    new, known = [], []
    for f in findings:
        if f["key"] in by_key:
            known.append(f)
        elif (f["file"], f["rule"], f["evidence_hash"]) in by_hash:
            known.append(f)
        else:
            new.append(f)
    return new, known


def save_baseline(path, findings, repo=".", generated_at=None):
    """Write a baseline JSON. Never stores secret values — only the
    evidence hash. `line` is stored for display only."""
    data = {
        "tool": "PipeSentry",
        "version": BASELINE_VERSION,
        "generated_at": generated_at or datetime.now().strftime(
            "%Y-%m-%dT%H:%M:%S"),
        "repo": repo,
        "findings": [
            {
                "key": f["key"], "file": f["file"], "rule": f["rule"],
                "severity": f["severity"],
                "object": f["key"].split("|", 2)[2],
                "line": f["line"], "evidence_hash": f["evidence_hash"],
                "title": f["title"],
            }
            for f in findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return len(findings)


# ---------------------------------------------------------------- parsing
def normalise_triggers(data):
    """Return {event_name: config_or_None} for every trigger, whatever
    form 'on:' was written in (scalar, flow list, block list, mapping)."""
    on = data.get("on", {}) or {}
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {event: None for event in on}
    if isinstance(on, dict):
        return {k: v for k, v in items(on)}
    return {}


def trigger_line(data):
    """Line of the `on:` block (or the workflow top line as fallback)."""
    on = data.get("on")
    if isinstance(on, dict):
        return mapping_line(on, mapping_line(data))
    if isinstance(on, (list, str)):
        return scalar_line(on, mapping_line(data))
    return mapping_line(data)


def iter_jobs(data):
    """Yield (job_id, job_dict, job_line) for every job."""
    for job_id, job in items(data.get("jobs") or {}):
        if isinstance(job, dict):
            yield job_id, job, mapping_line(job)


def iter_steps(data):
    """Yield (job_id, step_index, step_dict, step_line) for every step
    in every job."""
    for job_id, job, _line in iter_jobs(data):
        for i, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict):
                yield job_id, i, step, mapping_line(step)


def find_checkouts(data):
    """All (job_id, step_index, step, step_line) with uses: actions/checkout."""
    out = []
    for job_id, i, step, line in iter_steps(data):
        uses = step.get("uses") or ""
        if isinstance(uses, str) and uses.split("@")[0].strip() == "actions/checkout":
            out.append((job_id, i, step, line))
    return out


def parse_uses(uses):
    """Split 'owner/repo[/path]@ref [# comment]' into parts.
    Returns dict or None if the value is not a remote action."""
    if not isinstance(uses, str):
        return None
    uses = uses.strip()
    if uses.startswith("./"):
        return {"kind": "local", "raw": uses}
    if uses.startswith("docker://"):
        m = DOCKER_USES_RE.match(uses)
        if not m:
            return {"kind": "malformed", "raw": uses}
        d = m.groupdict()
        d["kind"] = "docker"
        return d
    m = USES_RE.match(uses)
    if not m:
        return {"kind": "malformed", "raw": uses}
    d = m.groupdict()
    d["kind"] = "remote"
    return d


def pin_status(ref):
    """'pinned' only for a full 40-hex SHA (or 64-hex SHA-256)."""
    if ref and (SHA_RE.match(ref) or SHA256_RE.match(ref)):
        return "pinned"
    return "unpinned"


def is_first_party(owner):
    return owner in FIRST_PARTY


# ---------------------------------------------------------------- checks
def check_triggers(data, file):
    """PG-001 / PG-002 / PG-003 — trigger + checkout analysis."""
    findings = []
    triggers = normalise_triggers(data)
    tline = trigger_line(data)
    if "pull_request_target" in triggers:
        checkouts = find_checkouts(data)
        if not checkouts:
            findings.append(make_finding(
                file, tline, "PG-002", "high",
                "trigger=pull_request_target",
                "Workflow runs on pull_request_target with secrets, but "
                "checks out nothing — any run: step touching "
                "github.event.* data is still exposed",
                key_obj="trigger=pull_request_target"))
        for job_id, _i, step, _line in checkouts:
            uses = step.get("uses") or ""
            uline = scalar_line(uses, mapping_line(step))
            with_block = step.get("with") or {}
            allow_unsafe = False
            ref = None
            for k, v in items(with_block):
                if k == "allow-unsafe-pr-checkout" and v is True:
                    allow_unsafe = True
                if k == "ref":
                    ref = v
            obj = "job=%s:step=checkout" % job_id
            if allow_unsafe:
                findings.append(make_finding(
                    file, uline, "PG-001", "critical", obj,
                    "actions/checkout with allow-unsafe-pr-checkout: true "
                    "in a pull_request_target workflow — fork code runs "
                    "with secrets",
                    key_obj="trigger=pull_request_target:job=%s" % job_id))
            elif isinstance(ref, str) and any(
                    s in ref for s in ("head.sha", "head.ref", "merge",
                                      "github.event.pull_request")):
                findings.append(make_finding(
                    file, scalar_line(ref, uline), "PG-001", "critical", obj,
                    "actions/checkout ref=%s checks out PR head code in a "
                    "pull_request_target workflow" % ref,
                    key_obj="trigger=pull_request_target:job=%s" % job_id))
            else:
                # Plain checkout, no ref: since checkout v7 (and the
                # backports) the action refuses fork-PR checkouts, so
                # this is High, not Critical — but only when the
                # checkout version actually has the defence.
                parsed = parse_uses(uses)
                pinned = parsed and pin_status(parsed.get("ref", "")) == "pinned"
                findings.append(make_finding(
                    file, uline, "PG-001", "high", obj,
                    "actions/checkout with no ref: in a "
                    "pull_request_target workflow (checkout %s) — the "
                    "safety of this depends on the checkout version"
                    % ("pinned" if pinned else "unpinned"),
                    key_obj="trigger=pull_request_target:job=%s" % job_id))
        # run:-block git clone / git checkout of the PR in the same job.
        for job_id, _i, step, _line in iter_steps(data):
            run = step.get("run") or ""
            if not isinstance(run, str):
                continue
            m = re.search(r"\bgit\s+(clone|checkout)\b[^\n]*"
                          r"(head\.sha|head\.ref|merge|pull/)", run)
            if m:
                findings.append(make_finding(
                    file, match_line(run, m.start()), "PG-001", "critical",
                    "job=%s:step=git-clone" % job_id,
                    "run: block clones/checks out PR code (%s) inside a "
                    "pull_request_target workflow" % m.group(0).strip(),
                    key_obj="trigger=pull_request_target:job=%s" % job_id))
    if "workflow_run" in triggers:
        for job_id, job, jline in iter_jobs(data):
            steps = job.get("steps") or []
            dl = None
            has_run = False
            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                u = step.get("uses") or ""
                if isinstance(u, str) and u.split("@")[0].strip() == "actions/download-artifact":
                    dl = (i, step)
                if isinstance(step.get("run"), str) and step.get("run").strip():
                    has_run = True
            if dl is not None and has_run:
                _i, dstep = dl
                du = dstep.get("uses") or ""
                findings.append(make_finding(
                    file, scalar_line(du, jline), "PG-003", "high",
                    "job=%s" % job_id,
                    "workflow_run job downloads an artifact and runs code "
                    "in the same job — a poisoned artifact from the "
                    "untrusted run executes here",
                    key_obj="trigger=workflow_run:job=%s" % job_id))
    return findings


def expr_is_dangerous(inner):
    """inner = text inside ${{ }}. Returns (tier, matched) or None.
    Wrappers like format()/fromJSON() do NOT sanitise, so look inside
    them — and check EVERY comma-separated argument, because in
    format('x {0}', github.event.pull_request.title) the dangerous
    value is the SECOND argument, not the first."""
    inner = inner.strip()
    m = WRAPPER_RE.match(inner)
    if m:
        inner = m.group(1)
    parts = [p.strip().strip("'\"") for p in inner.split(",")]
    for first in parts:
        if first in DANGEROUS_EXACT:
            return ("critical", first)
        for bad in DANGEROUS_PREFIXES:
            if first == bad or first.startswith(bad):
                return ("critical", first)
        if first.startswith("github.ref_name"):
            return ("high", first)
    return None


def check_injection(data, file, triggers):
    """PG-004 — dangerous ${{ }} in run: (and with: script: for
    actions/github-script). Never scans env: or if: values."""
    findings = []
    untrusted = bool(set(triggers) & TRIGGERS_UNTRUSTED)
    for job_id, i, step, sline in iter_steps(data):
        run = step.get("run")
        if isinstance(run, str):
            for m in EXPR_RE.finditer(run):
                hit = expr_is_dangerous(m.group(1))
                if hit:
                    tier, expr = hit
                    sev = "critical" if (tier == "critical" and untrusted) else "high"
                    obj = "job=%s:step=%d:expr=%s" % (job_id, i, expr)
                    findings.append(make_finding(
                        file, match_line(run, m.start()), "PG-004", sev,
                        obj,
                        "Untrusted expression ${{ %s }} interpolated in "
                        "run: — it becomes shell code" % expr,
                        key_obj=obj))
        uses = step.get("uses") or ""
        if isinstance(uses, str) and uses.split("@")[0].strip() == "actions/github-script":
            script = (step.get("with") or {}).get("script")
            if isinstance(script, str):
                for m in EXPR_RE.finditer(script):
                    hit = expr_is_dangerous(m.group(1))
                    if hit:
                        tier, expr = hit
                        sev = "critical" if (tier == "critical" and untrusted) else "high"
                        obj = "job=%s:step=%d:expr=%s" % (job_id, i, expr)
                        findings.append(make_finding(
                            file, match_line(script, m.start()), "PG-004", sev,
                            obj,
                            "Untrusted expression ${{ %s }} inside a "
                            "github-script step — it becomes JS code" % expr,
                            key_obj=obj))
    return findings


def secret_vars_visible(step, job_env, workflow_env):
    """Names of env vars whose value contains a secrets.* expression,
    visible to this step (step env wins over job env over workflow)."""
    visible = {}
    for env in (workflow_env, job_env, step.get("env") or {}):
        for name, value in items(env):
            if isinstance(value, str) and "secrets." in value:
                visible[name] = value
    return visible


def echo_var_re(var_names):
    names = "|".join(re.escape(n) for n in var_names)
    return re.compile(r"\becho\b[^\n;|&]*\$(\{)?(" + names + r")\}?\b")


def check_secret_echo(data, file):
    """PG-007 — secrets printed to logs from run: blocks."""
    findings = []
    workflow_env = data.get("env") or {}
    for job_id, job, _jline in iter_jobs(data):
        job_env = job.get("env") or {}
        for i, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            run = step.get("run")
            if not isinstance(run, str):
                continue
            visible = secret_vars_visible(step, job_env, workflow_env)
            obj_base = "job=%s:step=%d" % (job_id, i)
            m = ECHO_EXPR_RE.search(run)
            if m:
                findings.append(make_finding(
                    file, match_line(run, m.start()), "PG-007", "medium",
                    obj_base + ":expr",
                    "Secret interpolated directly in run: (%s) — GitHub "
                    "masks registered secrets, but substrings and encoded "
                    "forms are not masked" % m.group(0).strip()[:80],
                    key_obj=obj_base + ":expr"))
            if visible:
                ev = echo_var_re(visible)
                m = ev.search(run)
                if m:
                    findings.append(make_finding(
                        file, match_line(run, m.start()), "PG-007", "medium",
                        obj_base + ":var=" + ",".join(sorted(visible)),
                        "Secret-bearing variable echoed to logs: %s"
                        % ", ".join(sorted(visible)),
                        key_obj=obj_base + ":var=" + ",".join(sorted(visible))))
                m = encoded_echo_re(visible).search(run)
                if m:
                    findings.append(make_finding(
                        file, match_line(run, m.start()), "PG-007", "high",
                        obj_base + ":encoded",
                        "Secret piped through an encoder (%s) — encoded "
                        "forms bypass GitHub's log masking"
                        % m.group(0).strip()[:80],
                        key_obj=obj_base + ":encoded"))
                m = PRINTENV_RE.search(run)
                if m:
                    findings.append(make_finding(
                        file, match_line(run, m.start()), "PG-007", "high",
                        obj_base + ":printenv",
                        "printenv/env dumps the whole environment including "
                        "secrets",
                        key_obj=obj_base + ":printenv"))
                m = SETX_RE.search(run)
                if m:
                    findings.append(make_finding(
                        file, match_line(run, m.start()), "PG-007", "high",
                        obj_base + ":set-x",
                        "set -x prints every command with variables "
                        "expanded — secrets leak into the log",
                        key_obj=obj_base + ":set-x"))
                m = CURL_AUTH_RE.search(run)
                if m and any(v in run for v in visible):
                    findings.append(make_finding(
                        file, match_line(run, m.start()), "PG-007", "medium",
                        obj_base + ":curl-auth",
                        "Secret used as curl -u user:pass — credentials "
                        "appear in logs and the process list",
                        key_obj=obj_base + ":curl-auth"))
            m = CURL_PIPE_RE.search(run)
            if m:
                findings.append(make_finding(
                    file, match_line(run, m.start()), "PG-019", "medium",
                    obj_base + ":curl-pipe",
                    "Remote script piped straight into a shell (%s) — "
                    "download it, verify its hash, then run the local copy"
                    % m.group(0).strip()[:80],
                    key_obj=obj_base + ":curl-pipe"))
    return findings


def check_pinning(data, file, strict=False):
    """PG-005 / PG-006 — every uses: pinned to a full commit SHA?"""
    findings = []

    def check_one(uses, line, obj):
        parsed = parse_uses(uses)
        if parsed is None or parsed["kind"] in ("local", "malformed"):
            return
        if parsed["kind"] == "docker":
            ref = parsed.get("ref") or ""
            if SHA256_RE.match(ref.lstrip("sha256:")) and ref.startswith("sha256:"):
                return
            findings.append(make_finding(
                file, line, "PG-005", "high", obj,
                "Docker action %s is not pinned by digest — use "
                "docker://image@sha256:<digest>" % uses.strip(),
                key_obj=obj))
            return
        ref = parsed.get("ref") or ""
        if pin_status(ref) == "pinned":
            return
        owner = parsed.get("owner") or ""
        action = "%s/%s" % (owner, parsed.get("repo") or "")
        if is_first_party(owner):
            sev = "high" if strict else "medium"
            findings.append(make_finding(
                file, line, "PG-006", sev, obj,
                "First-party action %s@%s is not pinned — tags move; pin "
                "to the full 40-char commit SHA" % (action, ref or "(no ref)"),
                key_obj=obj))
        else:
            findings.append(make_finding(
                file, line, "PG-005", "high", obj,
                "Third-party action %s@%s is not pinned — pin to the full "
                "40-char commit SHA (see CVE-2025-30066)" % (action, ref or "(no ref)"),
                key_obj=obj))

    for job_id, i, step, sline in iter_steps(data):
        uses = step.get("uses")
        if isinstance(uses, str) and uses.strip():
            check_one(uses, scalar_line(uses, sline),
                      "job=%s:step=%d:action=%s"
                      % (job_id, i, uses.split("@")[0].strip()))
    for job_id, job, jline in iter_jobs(data):
        uses = job.get("uses")
        if isinstance(uses, str) and uses.strip():
            check_one(uses, scalar_line(uses, jline),
                      "job=%s:action=%s" % (job_id, uses.split("@")[0].strip()))
    return findings


def check_permissions(data, file):
    """PG-008 / PG-009 / PG-010 / PG-011 — permissions blocks."""
    findings = []
    wf_perms = data.get("permissions")
    if wf_perms is None:
        findings.append(make_finding(
            file, mapping_line(data), "PG-010", "medium",
            "workflow",
            "No permissions: block — the token scope depends on the repo "
            "default (often read+write on older repos)",
            key_obj="scope=none"))
    elif isinstance(wf_perms, str):
        if wf_perms.strip() == "write-all":
            findings.append(make_finding(
                file, scalar_line(wf_perms, mapping_line(data)), "PG-008", "high",
                "workflow",
                "permissions: write-all — every scope is writable",
                key_obj="scope=write-all"))
    elif isinstance(wf_perms, dict):
        for scope, level in items(wf_perms):
            if level != "write":
                continue
            sev = "high" if scope == "contents" else "medium"
            line = scalar_line(level, mapping_line(wf_perms))
            findings.append(make_finding(
                file, line, "PG-009", sev,
                "workflow:scope=%s" % scope,
                "Workflow-level %s: write — every job gets this write "
                "scope; move it to the one job that needs it" % scope,
                key_obj="scope=%s" % scope))
    for job_id, job, jline in iter_jobs(data):
        jp = job.get("permissions")
        if isinstance(jp, str) and jp.strip() == "write-all":
            findings.append(make_finding(
                file, scalar_line(jp, jline), "PG-008", "high",
                "job=%s" % job_id,
                "Job %s: permissions: write-all" % job_id,
                key_obj="job=%s:scope=write-all" % job_id))
        elif isinstance(jp, dict):
            uses_sarif = any(
                isinstance(s, dict) and isinstance(s.get("uses"), str)
                and "upload-sarif" in s.get("uses")
                for s in (job.get("steps") or []))
            for scope, level in items(jp):
                if level != "write":
                    continue
                if scope == "id-token" and "deploy" not in job_id.lower():
                    findings.append(make_finding(
                        file, scalar_line(level, mapping_line(jp)), "PG-011", "medium",
                        "job=%s:scope=id-token" % job_id,
                        "Job %s: id-token: write mints OIDC tokens — "
                        "restrict it to the deploy job" % job_id,
                        key_obj="job=%s:scope=id-token" % job_id))
                elif scope == "security-events" and uses_sarif:
                    continue  # legitimate: the SARIF upload job needs it
    return findings


def check_misc_workflow(data, file, triggers):
    """PG-012 / PG-013 / PG-014 / PG-018 — the remaining workflow checks."""
    findings = []
    # PG-012: ACTIONS_ALLOW_UNSECURE_COMMANDS=true in any env: block.
    def scan_env(env, obj, fallback_line):
        for k, v in items(env):
            if k == "ACTIONS_ALLOW_UNSECURE_COMMANDS" and (
                    v is True or (isinstance(v, str) and v.strip().lower() == "true")):
                findings.append(make_finding(
                    file, scalar_line(v, fallback_line), "PG-012", "high",
                    obj,
                    "ACTIONS_ALLOW_UNSECURE_COMMANDS=true re-enables the "
                    "deprecated set-output / save-state commands — an "
                    "injection primitive",
                    key_obj=obj))
    scan_env(data.get("env") or {}, "workflow", mapping_line(data))
    for job_id, job, jline in iter_jobs(data):
        scan_env(job.get("env") or {}, "job=%s" % job_id, jline)
        for i, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict):
                scan_env(step.get("env") or {},
                         "job=%s:step=%d" % (job_id, i), mapping_line(step))
    # PG-013: checkout persists credentials + upload-artifact in same job.
    for job_id, job, jline in iter_jobs(data):
        steps = job.get("steps") or []
        checkout = None
        uploads = False
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            u = step.get("uses") or ""
            if isinstance(u, str) and u.split("@")[0].strip() == "actions/checkout":
                with_block = step.get("with") or {}
                pc = with_block.get("persist-credentials")
                if pc is True or (isinstance(pc, str) and pc.strip().lower() == "true"):
                    checkout = (i, step)
            if isinstance(u, str) and u.split("@")[0].strip() == "actions/upload-artifact":
                uploads = True
        if checkout is not None and uploads:
            _i, cstep = checkout
            cu = cstep.get("uses") or ""
            findings.append(make_finding(
                file, scalar_line(cu, jline), "PG-013", "low",
                "job=%s" % job_id,
                "Job %s: checkout persists the GITHUB_TOKEN and the job "
                "uploads an artifact — the token can end up in the "
                "artifact" % job_id,
                key_obj="job=%s" % job_id))
    # PG-014: self-hosted runner + untrusted trigger.
    if set(triggers) & TRIGGERS_UNTRUSTED:
        for job_id, job, jline in iter_jobs(data):
            runs_on = job.get("runs-on")
            vals = []
            if isinstance(runs_on, str):
                vals = [runs_on]
            elif isinstance(runs_on, list):
                vals = [v for v in runs_on if isinstance(v, str)]
            if any("self-hosted" in v for v in vals):
                findings.append(make_finding(
                    file, jline, "PG-014", "high",
                    "job=%s" % job_id,
                    "Job %s runs on a self-hosted runner under an "
                    "untrusted trigger (%s) — a compromised step owns the "
                    "host" % (job_id, ", ".join(sorted(set(triggers) & TRIGGERS_UNTRUSTED))),
                    key_obj="job=%s" % job_id))
    # PG-018: reusable workflow call with secrets: inherit.
    for job_id, job, jline in iter_jobs(data):
        uses = job.get("uses")
        secrets = job.get("secrets")
        if isinstance(uses, str) and isinstance(secrets, str) \
                and secrets.strip() == "inherit":
            findings.append(make_finding(
                file, scalar_line(secrets, jline), "PG-018", "high",
                "job=%s" % job_id,
                "Job %s calls %s with secrets: inherit — every secret "
                "goes to the called workflow; pass only the ones it needs"
                % (job_id, uses.split("@")[0].strip()),
                key_obj="job=%s" % job_id))
    return findings


# ---------------------------------------------------------------- Jenkinsfile
def check_jenkins_credentials(lines, file):
    """PG-015 — hardcoded credentials, line by line."""
    text = "\n".join(lines)
    has_withcreds = bool(WITHCREDS_RE.search(text))
    findings = []
    for i, line in enumerate(lines, start=1):
        for rule, sev, rx, msg in JENKINS_PATTERNS:
            if rx.search(line):
                findings.append(make_finding(
                    file, i, rule, sev, "line=%d" % i, msg,
                    key_obj="pattern=%s" % rx.pattern[:40]))
        if (not has_withcreds
                and re.search(r"\$[A-Z_][A-Z0-9_]*", line)
                and SECRET_NAME_RE.search(line)):
            findings.append(make_finding(
                file, i, "PG-015", "medium",
                "line=%d" % i,
                "Secret-like variable used with no withCredentials block "
                "in this Jenkinsfile — where does its value come from?",
                key_obj="pattern=no-withcredentials"))
    return findings


def check_jenkins_shell(lines, file):
    """PG-016 / PG-017 — unguarded sh steps and input without timeout.
    A small state machine tracks multi-line sh \"\"\"...\"\"\" blocks:
    ${...} inside a double-quoted block is Groovy interpolation (the
    Jenkins equivalent of GitHub's ${{ }} injection); inside a
    single-quoted block it is not."""
    findings = []
    in_dq_block = False
    in_sq_block = False
    for i, line in enumerate(lines, start=1):
        if in_dq_block:
            if '"""' in line:
                in_dq_block = False
            m = re.search(r"\$\{[^}]+\}", line)
            if m:
                findings.append(make_finding(
                    file, i, "PG-016", "high", "line=%d" % i,
                    "Groovy ${...} interpolated inside a multi-line "
                    "double-quoted sh block — use single quotes and pass "
                    "values via env",
                    key_obj="pattern=sh-dq-block"))
            continue
        if in_sq_block:
            if "'''" in line:
                in_sq_block = False
            continue
        if re.search(r"""\bsh\s*(?:\(\s*)?\"\"\"""", line):
            in_dq_block = True
            m = re.search(r"\$\{[^}]+\}", line)
            if m:
                findings.append(make_finding(
                    file, i, "PG-016", "high", "line=%d" % i,
                    "Groovy ${...} interpolated inside a double-quoted "
                    "sh block — use single quotes and pass values via env",
                    key_obj="pattern=sh-dq-block"))
            continue
        if re.search(r"""\bsh\s*(?:\(\s*)?'''""", line):
            in_sq_block = True
            continue
        if SH_DQ_INTERP_RE.search(line):
            findings.append(make_finding(
                file, i, "PG-016", "high", "line=%d" % i,
                "Groovy ${...} interpolated inside a double-quoted sh "
                "string — use single quotes and pass values via env",
                key_obj="pattern=sh-dq-interp"))
        if DOCKER_SOCK_RE.search(line) and "sh" in line:
            findings.append(make_finding(
                file, i, "PG-016", "high", "line=%d" % i,
                "Docker socket mounted into a build step — the step is "
                "root on the host",
                key_obj="pattern=docker-sock"))
    # input without timeout: look for 'input' with no 'timeout' within
    # ~5 lines either side — timeout usually WRAPS input (above it), so
    # a forward-only window false-positives on the correct pattern.
    # Heuristic — say so in the report.
    text = "\n".join(lines)
    split = text.split("\n")
    for m in re.finditer(r"(?m)^\s*input\b.*$", text):
        start = text[:m.start()].count("\n")
        block = "\n".join(split[max(0, start - 5):start + 6])
        if "timeout" not in block:
            findings.append(make_finding(
                file, start + 1, "PG-017", "low", "line=%d" % (start + 1),
                "input step without a timeout — a build can hang forever "
                "waiting for approval",
                key_obj="pattern=input-no-timeout"))
    return findings


# ---------------------------------------------------------------- orchestrate
def check_workflow(data, file, strict=False):
    """Run every workflow check over one parsed workflow."""
    triggers = normalise_triggers(data)
    findings = []
    findings += check_triggers(data, file)
    findings += check_injection(data, file, triggers)
    findings += check_secret_echo(data, file)
    findings += check_pinning(data, file, strict=strict)
    findings += check_permissions(data, file)
    findings += check_misc_workflow(data, file, triggers)
    return findings


def is_jenkinsfile(path):
    base = os.path.basename(path)
    return base == "Jenkinsfile" or base.startswith("Jenkinsfile.")


def collect_files(path):
    """Walk a file or folder and collect pipeline files, sorted."""
    found = []
    if os.path.isfile(path):
        return [path]
    if not os.path.isdir(path):
        raise ValueError("No such file or folder: %s" % path)
    for root, dirs, files in os.walk(path):
        # Skip tooling dirs, but DO walk .github (workflows live there).
        dirs[:] = [d for d in dirs
                   if d not in ("venv", "__pycache__", ".git")]
        for name in sorted(files):
            full = os.path.join(root, name)
            if is_jenkinsfile(full):
                found.append(full)
            elif name.endswith((".yml", ".yaml")):
                found.append(full)
    return sorted(found)


def scan_one_file(path, display, strict=False):
    """Scan one file. Returns (findings, errors, stats)."""
    findings, errors = [], []
    stats = {"workflows": 0, "jenkinsfiles": 0, "jobs": 0, "steps": 0}
    if is_jenkinsfile(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            return [], ["Cannot read %s: %s" % (display, exc)], stats
        stats["jenkinsfiles"] = 1
        findings += check_jenkins_credentials(lines, display)
        findings += check_jenkins_shell(lines, display)
        return findings, errors, stats
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return [], ["Cannot read %s: %s" % (display, exc)], stats
    try:
        data = load_workflow(text)
    except (ValueError, Exception) as exc:  # noqa: BLE001 - YAML errors vary
        return [], ["Cannot parse %s: %s" % (display, exc)], stats
    if not data.get("on") and not data.get("jobs"):
        return [], ["Not a workflow, skipped: %s "
                    "(no 'on:' trigger and no jobs)" % display], stats
    if not data.get("on"):
        errors.append("No 'on:' trigger in %s — the workflow never runs"
                      % display)
    stats["workflows"] = 1
    jobs = data.get("jobs") or {}
    stats["jobs"] = sum(1 for k in jobs if k != "__line__")
    stats["steps"] = sum(
        len(job.get("steps") or [])
        for _k, job in items(jobs) if isinstance(job, dict))
    findings += check_workflow(data, display, strict=strict)
    return findings, errors, stats


def list_checks():
    print()
    print(f"{C.BOLD}PipeSentry checks ({len(RULES)} rules){C.RESET}")
    sep()
    for rule in sorted(RULES):
        title, severity, _fix = RULES[rule]
        col = {"critical": C.RED, "high": C.YELLOW,
               "medium": C.CYAN, "low": C.DIM}[severity]
        print("  %-10s %s%-9s%s %s" % (
            rule, col, severity.upper(), C.RESET, title))
    print()
    print("Use --check PG-001,PG-004 to run only some rules,")
    print("or --skip-check PG-013 to skip some.")
    print()


def print_summary(stats, findings, score, grade, quiet=False):
    counts = summary_counts(findings)
    print()
    print(f"{C.BOLD}PipeSentry — scan complete{C.RESET}")
    sep()
    print("Files: %d  (workflows %d, Jenkinsfiles %d, jobs %d, steps %d)"
          % (stats["files"], stats["workflows"], stats["jenkinsfiles"],
             stats["jobs"], stats["steps"]))
    colour = C.GREEN if score >= 90 else C.YELLOW if score >= 70 else C.RED
    print("Score: %s%d/100 (grade %s)%s" % (colour, score, grade, C.RESET))
    print("Findings: %d  (critical %d, high %d, medium %d, low %d)" % (
        len(findings), counts["critical"], counts["high"],
        counts["medium"], counts["low"]))
    if quiet:
        return
    for f in findings:
        col = {"critical": C.RED, "high": C.YELLOW,
               "medium": C.CYAN, "low": C.DIM}[f["severity"]]
        print("%s[%s]%s %s — %s" % (
            col, f["severity"].upper(), C.RESET, f["rule"], f["title"]))
        print("     %s:%s" % (f["file"], f["line"]))
        print("     %s" % f["object"])
        print("     Evidence: %s" % f["evidence"])
    print()


def build_text_report(path, stats, findings, score, grade, errors):
    lines = []
    lines.append("=" * 64)
    lines.append("PipeSentry Report — CI/CD Pipeline Security Scan")
    lines.append("=" * 64)
    lines.append("Date: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("Tool: PipeSentry %s (author: %s)" % (VERSION, AUTHOR))
    lines.append("Scanned: %s" % path)
    lines.append("")
    lines.append("Files: %d (workflows %d, Jenkinsfiles %d, jobs %d, "
                 "steps %d)" % (stats["files"], stats["workflows"],
                                stats["jenkinsfiles"], stats["jobs"],
                                stats["steps"]))
    lines.append("Score: %d/100 (grade %s)" % (score, grade))
    counts = summary_counts(findings)
    lines.append("Findings: %d (critical %d, high %d, medium %d, low %d)"
                 % (len(findings), counts["critical"], counts["high"],
                    counts["medium"], counts["low"]))
    lines.append("")
    if not findings:
        lines.append("No findings. The scanned pipelines look clean.")
        lines.append("")
    for f in findings:
        lines.append("-" * 64)
        lines.append("[%s] %s — %s" % (
            f["severity"].upper(), f["rule"], f["title"]))
        lines.append("File: %s (line %s)" % (f["file"], f["line"]))
        lines.append("Object: %s" % f["object"])
        lines.append("Evidence: %s" % f["evidence"])
        lines.append("Fix: %s" % f["fix"])
        lines.append("")
    for e in errors:
        lines.append("Note: %s" % e)
    lines.append("-" * 64)
    lines.append("Defensive lesson — pin actions to commit hashes.")
    lines.append("A tag like @v4 is a mutable pointer: whoever controls "
                 "the action repo can move it, and every pipeline that "
                 "uses it runs the new code. A full 40-char commit SHA "
                 "cannot be moved. Pin every third-party action to its "
                 "SHA and keep the version as a # vX.Y.Z comment, so "
                 "Dependabot can still open update PRs. In March 2025 "
                 "the tj-actions/changed-files tags were rewritten to "
                 "malicious code (CVE-2025-30066) and 23,000+ repos ran "
                 "it — every one of them would have been safe on a SHA pin.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(path, stats, findings, score, grade, errors):
    return {
        "tool": "PipeSentry",
        "version": VERSION,
        "author": AUTHOR,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanned_path": path,
        "files": stats["files"],
        "workflows": stats["workflows"],
        "jenkinsfiles": stats["jenkinsfiles"],
        "jobs": stats["jobs"],
        "steps": stats["steps"],
        "score": score,
        "grade": grade,
        "findings": [finding_to_json(f) for f in findings],
        "notes": errors,
    }


def scan_path(path, args):
    """Run a full scan. Returns (exit_code, findings, score, grade)."""
    if yaml is None:
        err("PyYAML is not installed. Run: python run.py setup")
        err("  or: pip install pyyaml")
        return 2, [], 0, "F"
    try:
        files = collect_files(path)
    except ValueError as exc:
        err(str(exc))
        return 2, [], 0, "F"
    if not files:
        warn("No pipeline files found in %s" % path)
        return 0, [], 100, "A"
    # Gobuster-style config block, like SSTIProbe / RBACLens.
    if not args.quiet:
        header("SCAN")
        info("Target", path)
        info("Files", "%d pipeline files" % len(files))
        info("Output", args.output)
        info("JSON report", args.json or "—")
        info("Min severity", args.min_severity or "all")
        checks = args.check or "all %d" % len(RULES)
        if args.skip_check:
            checks += " (skip %s)" % args.skip_check
        info("Checks", checks)
        info("Fail on", args.fail_on or "critical (default)")
        if getattr(args, "baseline", None):
            info("Baseline", args.baseline)
        if getattr(args, "baseline_write", None):
            info("Baseline write", args.baseline_write)
        sep()
    findings, errors = [], []
    stats = {"files": len(files), "workflows": 0, "jenkinsfiles": 0,
             "jobs": 0, "steps": 0}
    base = path if os.path.isdir(path) else os.path.dirname(
        os.path.abspath(path)) or "."
    for full in files:
        display = os.path.relpath(full, base)
        f, e, s = scan_one_file(full, display, strict=args.strict)
        findings.extend(f)
        errors.extend(e)
        for k in stats:
            if k != "files":
                stats[k] += s[k]
    findings.sort(key=lambda f: (f["file"], f["line"],
                                 SEVERITY_ORDER[f["severity"]]))
    score = score_findings(findings)
    grade = grade_for(score)

    # Baseline mode: --baseline-write records everything and exits 0;
    # --baseline reports only NEW findings (exit code from new only).
    shown = findings
    new_score, new_grade = score, grade
    if getattr(args, "baseline_write", None):
        n = save_baseline(args.baseline_write, findings, repo=path)
        print_summary(stats, findings, score, grade, quiet=args.quiet)
        ok("Baseline saved: %s (%d findings)" % (args.baseline_write, n))
        report = build_text_report(path, stats, findings, score, grade, errors)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        ok("Report saved: %s" % args.output)
        return 0, findings, score, grade
    if getattr(args, "baseline", None):
        try:
            by_key, by_hash = load_baseline(args.baseline)
        except (OSError, ValueError, KeyError) as exc:
            err("Baseline failed: %s" % exc)
            return 1, findings, score, grade
        total_baseline = len(by_key)
        shown, known = split_new_vs_known(findings, by_key, by_hash)
        fixed = total_baseline - len(known)
        new_score = score_findings(shown)
        new_grade = grade_for(new_score)
        if not args.quiet:
            print("%d known findings suppressed by baseline "
                  "(%d fixed since baseline)" % (len(known), fixed))

    # Filters: --min-severity / --check / --skip-check hide findings
    # from the display/report; the score always reflects every finding.
    if args.min_severity:
        level = SEVERITY_ORDER[args.min_severity]
        shown = [f for f in shown
                 if SEVERITY_ORDER[f["severity"]] <= level]
    if args.check:
        wanted = set(args.check.split(","))
        shown = [f for f in shown if f["rule"] in wanted]
    if args.skip_check:
        skipped = set(args.skip_check.split(","))
        shown = [f for f in shown if f["rule"] not in skipped]

    print_summary(stats, shown, new_score if getattr(args, "baseline", None)
                  else score, new_grade if getattr(args, "baseline", None)
                  else grade, quiet=args.quiet)

    report = build_text_report(path, stats, shown,
                               new_score if getattr(args, "baseline", None)
                               else score,
                               new_grade if getattr(args, "baseline", None)
                               else grade, errors)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    ok("Report saved: %s" % args.output)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(build_json_report(path, stats, shown,
                                        new_score if getattr(args, "baseline", None)
                                        else score,
                                        new_grade if getattr(args, "baseline", None)
                                        else grade, errors),
                      fh, indent=2)
        ok("JSON report saved: %s" % args.json)
    for e in errors:
        warn("Note: %s" % e)

    # Exit code: 0 clean, 1 findings, 2 any critical (or --fail-on hit).
    # --fail-on none disables the gate entirely (findings -> exit 1).
    # With --baseline, computed from the NEW findings only.
    gate = shown if getattr(args, "baseline", None) else findings
    if not gate:
        return 0, findings, score, grade
    if args.fail_on == "none":
        return 1, findings, score, grade
    if args.fail_on:
        level = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] <= level for f in gate):
            return 2, findings, score, grade
        return 0, findings, score, grade
    if summary_counts(gate)["critical"]:
        return 2, findings, score, grade
    return 1, findings, score, grade


# ---------------------------------------------------------------- menu
# Same menu shape as SSTIProbe / RBACLens (GhostTrack / TraceRecon):
# clear screen, banner, numbered options between '═' rule lines, then
# asks "[ ? ] Select option : ". After each option: "Press enter to
# continue" and loop back; Ctrl+C prints "[ ! ] Exit". Only the theme
# differs: red/orange accents instead of green.
MENU_OPTIONS = [
    (1, "Scan a folder of pipelines", "scan"),
    (2, "Quick scan: test workflows (bad — planted flaws)", "bad"),
    (3, "Quick scan: test workflows (clean — should pass)", "clean"),
    (4, "Show parsed structure of a folder", "structure"),
    (5, "List all checks", "checks"),
    (6, "Run step tests", "test"),
    (7, "Check setup (doctor)", "doctor"),
    (0, "Exit", None),
]


def ask(prompt, default=""):
    """Ask one [?] question; Enter on its own takes the default."""
    shown = f"{default}" if default else ""
    try:
        value = input(f"{C.CYN}[?]{C.RESET} {prompt} [{shown}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise
    return value or default


def menu_scan(args, default_path, default_output):
    path = ask("ENTER FOLDER OR FILE", default_path)
    if not path:
        path = default_path
    out = ask("ENTER REPORT FILE", default_output)
    args.output = out or default_output
    return scan_path(path, args)


def show_structure(path):
    """Menu option 4: parse every pipeline file and show its structure
    — triggers, jobs and steps — without running any checks."""
    try:
        files = collect_files(path)
    except ValueError as exc:
        err(str(exc))
        return
    if not files:
        warn("No pipeline files found in %s" % path)
        return
    header("PARSED STRUCTURE")
    for full in files:
        display = full
        if is_jenkinsfile(full):
            try:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    n = len(fh.read().splitlines())
            except OSError:
                n = 0
            info("Jenkinsfile", "%s (%d lines)" % (display, n))
            continue
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                data = load_workflow(fh.read())
        except (ValueError, Exception) as exc:  # noqa: BLE001
            err("Cannot parse %s: %s" % (display, exc))
            continue
        triggers = normalise_triggers(data)
        jobs = data.get("jobs") or {}
        print(f" {C.BOLD}{display}{C.RESET}")
        info("Triggers", ", ".join(sorted(triggers)) or "(none)")
        for job_id, job, _line in iter_jobs(data):
            steps = job.get("steps") or []
            print("   Job %s: %d step(s), runs-on %s"
                  % (job_id, len(steps), job.get("runs-on") or "?"))
    sep()


def doctor():
    """Menu option 7: is the setup ready? (SSTIProbe's menu option 5
    checks the lab is reachable; PipeSentry checks its own setup.)"""
    header("SETUP CHECK")
    ok("Python %s" % sys.version.split()[0])
    if yaml is not None:
        ok("PyYAML %s" % yaml.__version__)
    else:
        warn("PyYAML is NOT installed — run: python run.py setup")
    base = os.path.dirname(os.path.abspath(__file__))
    for label, rel in (("test workflows (bad)", "test_workflows/bad"),
                       ("test workflows (clean)", "test_workflows/clean"),
                       ("test Jenkinsfile (bad)", "test_jenkins/bad"),
                       ("test Jenkinsfile (clean)", "test_jenkins/clean")):
        full = os.path.join(base, rel)
        if os.path.isdir(full):
            ok("Test %s: %s" % (label, full))
        else:
            warn("Test %s missing: %s" % (label, full))
    if yaml is None:
        warn("Doctor: something is missing (see [!] lines above).")
        return 1
    ok("Doctor: all good. Run option 2 to scan the bad workflows.")
    return 0


def show_menu():
    """Clear screen, banner, then the numbered menu."""
    clear()
    banner()
    sep(ACCENT, "═")
    for num, label, _key in MENU_OPTIONS:
        print(f" {ACCENT}[{C.WHT}{num:>2}{ACCENT}]{C.RST} {C.WHT}{label}{C.RST}")
    sep(ACCENT, "═")


def menu(args):
    base = os.path.dirname(os.path.abspath(__file__))
    bad = os.path.join(base, "test_workflows", "bad")
    clean = os.path.join(base, "test_workflows", "clean")
    while True:
        show_menu()
        try:
            choice = input(f"{C.WHT}\n [ ? ] {ACCENT}Select option{C.WHT} : {ACCENT2}").strip()
            print(C.RST, end="")
            if choice == "0":
                print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
                return 0
            if choice == "1":
                code, _f, _s, _g = menu_scan(args, ".", "pipesentry_report.txt")
                print("Exit code: %d" % code)
            elif choice == "2":
                args.output = "report_bad.txt"
                code, _f, _s, _g = scan_path(bad, args)
                print("Exit code: %d" % code)
            elif choice == "3":
                args.output = "report_clean.txt"
                code, _f, _s, _g = scan_path(clean, args)
                print("Exit code: %d" % code)
            elif choice == "4":
                path = ask("ENTER FOLDER OR FILE", bad)
                show_structure(path or bad)
            elif choice == "5":
                list_checks()
            elif choice == "6":
                import test_pipesentry
                test_pipesentry.run_all_tests()
            elif choice == "7":
                doctor()
            else:
                err("Please input a number from the menu (0-7).")
                time.sleep(1)
                continue
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
            return 0
        # GhostTrack pattern: pause, then loop back to the menu.
        try:
            input(f"\n{C.WHT}[ {ACCENT2}+ {C.WHT}] {ACCENT2}Press enter to continue{C.RST}")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    return 0


# ---------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(
        prog="pipesentry",
        description="PipeSentry — CI/CD Pipeline Security Scanner "
                    "(files only, no network).")
    p.add_argument("path", nargs="?", default=None,
                   help="pipeline file or folder to audit")
    p.add_argument("-o", "--output", default="pipesentry_report.txt",
                   help="text report file (default: pipesentry_report.txt)")
    p.add_argument("--json", default=None, metavar="FILE",
                   help="also write a JSON report to FILE")
    p.add_argument("--min-severity", default=None,
                   choices=["critical", "high", "medium", "low"],
                   help="show only findings at or above this severity")
    p.add_argument("--fail-on", default=None,
                   choices=["critical", "high", "medium", "low", "none"],
                   help="exit 2 if any finding at or above this severity")
    p.add_argument("--check", default=None, metavar="RULES",
                   help="run only these rules, e.g. PG-001,PG-004")
    p.add_argument("--skip-check", default=None, metavar="RULES",
                   help="skip these rules, e.g. PG-013")
    p.add_argument("--baseline", default=None, metavar="FILE",
                   help="report only findings NOT in the baseline FILE")
    p.add_argument("--baseline-write", default=None, metavar="FILE",
                   help="write all findings to baseline FILE and exit 0")
    p.add_argument("--strict", action="store_true",
                   help="escalate first-party unpinned actions (PG-006) to High")
    p.add_argument("--structure", action="store_true",
                   help="print the parsed structure and exit")
    p.add_argument("--list-checks", action="store_true",
                   help="list all checks and exit")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only the summary, score and report path")
    p.add_argument("--batch", action="store_true",
                   help="never ask, use defaults (for scripts)")
    p.add_argument("-i", "--interactive", "--menu", action="store_true",
                   help="open the numbered menu")
    p.add_argument("--version", action="store_true",
                   help="print the version and exit")
    p.add_argument("--no-color", action="store_true",
                   help="plain output without colours")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color:
        C.disable()
    if args.version:
        print("PipeSentry %s" % VERSION)
        return 0
    if args.list_checks:
        list_checks()
        return 0
    if args.structure:
        if not args.path:
            err("Give a pipeline file or folder for --structure.")
            return 2
        show_structure(args.path)
        return 0
    if args.interactive or args.path is None:
        return menu(args)
    code, _findings, _score, _grade = scan_path(args.path, args)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!]{C.RESET} Exit")
        sys.exit(130)
