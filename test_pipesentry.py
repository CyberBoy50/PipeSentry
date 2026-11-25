#!/usr/bin/env python3
"""Step tests for PipeSentry — mirrors the PDF's 7-step build plan.

Step 1: parse one workflow (triggers / jobs / steps, line numbers).
Step 2: trigger check (pull_request_target, workflow_run).
Step 3: pinning check (SHA vs tag vs branch vs docker://).
Step 4: secret-echo check (echo, printenv, set -x, encoded).
Step 5: script-injection check (dangerous ${{ }} in run:).
Step 6: permissions check + report (file, line, severity, fix).
Step 7: full run on the test folders + Jenkinsfile + baseline mode.
Step 8: online SHA verification (v1.1, PG-020) — needs internet to
api.github.com; skips cleanly when offline.

Usage: python test_pipesentry.py   (or: python run.py test)
"""
import json
import os
import sys
import tempfile
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pipesentry as ps

BAD_DIR = os.path.join(HERE, "test_workflows", "bad")
CLEAN_DIR = os.path.join(HERE, "test_workflows", "clean")
JENKINS_BAD = os.path.join(HERE, "test_jenkins", "bad")
JENKINS_CLEAN = os.path.join(HERE, "test_jenkins", "clean")

PASSED = 0
FAILED = 0
FAILURES = []


def check(name, cond):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print("  [PASS] %s" % name)
    else:
        FAILED += 1
        FAILURES.append(name)
        print("  [FAIL] %s" % name)


def find_line(path, needle):
    """1-based line of the first line containing needle, or None."""
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            if needle in line:
                return i
    return None


def rules_of(findings):
    return {f["rule"] for f in findings}


def of_rule(findings, rule):
    return [f for f in findings if f["rule"] == rule]


def load(path):
    with open(path, encoding="utf-8") as fh:
        return ps.load_workflow(fh.read())


def scan(folder, **kw):
    args = SimpleNamespace(
        quiet=True,
        output=os.path.join(tempfile.gettempdir(), "ps_test_report.txt"),
        json=None, min_severity=None, check=None, skip_check=None,
        fail_on=None, baseline=None, baseline_write=None, strict=False)
    args.__dict__.update(kw)
    return ps.scan_path(folder, args)


def step1():
    print("\nStep 1 — parse one workflow")
    data = load(os.path.join(CLEAN_DIR, "ci.yml"))
    check("on: stays the string 'on' (YAML 1.1 boolean fix)",
          "on" in data and True not in data)
    triggers = ps.normalise_triggers(data)
    check("triggers parsed: pull_request", "pull_request" in triggers)
    jobs = list(ps.iter_jobs(data))
    check("one job parsed", len(jobs) == 1 and jobs[0][0] == "build")
    steps = list(ps.iter_steps(data))
    check("four steps parsed", len(steps) == 4)
    check("uses: line is exact",
          ps.scalar_line(steps[0][2].get("uses")) ==
          find_line(os.path.join(CLEAN_DIR, "ci.yml"), "uses: actions/checkout@"))
    bad = load(os.path.join(BAD_DIR, "ci.yml"))
    check("bad workflow: pull_request_target trigger found",
          "pull_request_target" in ps.normalise_triggers(bad))
    check("bad workflow: two jobs parsed",
          len(list(ps.iter_jobs(bad))) == 2)
    # Duplicate keys must be an error, not a silent overwrite.
    try:
        ps.load_workflow("on: push\npermissions: {}\npermissions: {}\n")
        dup_raises = False
    except ValueError:
        dup_raises = True
    check("duplicate key raises ValueError", dup_raises)
    # A random YAML file is skipped, not scanned as a workflow.
    with tempfile.NamedTemporaryFile("w", suffix=".yml",
                                     delete=False) as fh:
        fh.write("name: not-a-workflow\nfoo: bar\n")
        tmp = fh.name
    _f, errors, _s = ps.scan_one_file(tmp, "random.yml")
    os.unlink(tmp)
    check("non-workflow YAML is skipped with a note",
          any("Not a workflow" in e for e in errors))


def step2():
    print("\nStep 2 — trigger check")
    bad = load(os.path.join(BAD_DIR, "ci.yml"))
    f = ps.check_triggers(bad, "ci.yml")
    p1 = of_rule(f, "PG-001")
    check("PG-001 Critical: checkout ref is PR head sha",
          any(x["severity"] == "critical" for x in p1))
    check("PG-001 line is the ref: line",
          any(x["line"] == find_line(
              os.path.join(BAD_DIR, "ci.yml"),
              "ref: ${{ github.event.pull_request.head.sha }}")
              for x in p1))
    check("PG-001 High: plain checkout in the package job",
          any(x["severity"] == "high" for x in p1))
    notify = load(os.path.join(BAD_DIR, "notify.yml"))
    f = ps.check_triggers(notify, "notify.yml")
    check("PG-002 High: pull_request_target without checkout",
          len(of_rule(f, "PG-002")) == 1
          and of_rule(f, "PG-002")[0]["severity"] == "high")
    art = load(os.path.join(BAD_DIR, "artifacts.yml"))
    f = ps.check_triggers(art, "artifacts.yml")
    check("PG-003 High: workflow_run + download-artifact + run",
          len(of_rule(f, "PG-003")) == 1)
    clean = load(os.path.join(CLEAN_DIR, "ci.yml"))
    f = ps.check_triggers(clean, "ci.yml")
    check("clean workflow: no trigger findings",
          not rules_of(f) & {"PG-001", "PG-002", "PG-003"})


def step3():
    print("\nStep 3 — pinning check")
    check("full 40-hex SHA counts as pinned",
          ps.pin_status("b5d2142d2c33b2e2b4b8c99551d533bcfcceb365") == "pinned")
    check("major tag v4 is unpinned",
          ps.pin_status("v4") == "unpinned")
    check("short SHA (7 chars) is unpinned",
          ps.pin_status("abc1234") == "unpinned")
    check("local action ./... is never flagged",
          ps.parse_uses("./.github/actions/my-action")["kind"] == "local")
    check("docker:// with a tag is a docker action",
          ps.parse_uses("docker://alpine:3.19")["kind"] == "docker")
    clean = load(os.path.join(CLEAN_DIR, "ci.yml"))
    f = ps.check_pinning(clean, "ci.yml")
    check("clean workflow: no pinning findings", f == [])
    bad = load(os.path.join(BAD_DIR, "ci.yml"))
    f = ps.check_pinning(bad, "ci.yml")
    check("bad workflow: third-party tj-actions flagged PG-005",
          any(x["severity"] == "high" for x in of_rule(f, "PG-005")))
    check("bad workflow: docker://alpine flagged PG-005",
          any("docker" in x["evidence"].lower()
              for x in of_rule(f, "PG-005")))
    check("bad workflow: first-party @v4 flagged PG-006 Medium",
          any(x["severity"] == "medium" for x in of_rule(f, "PG-006")))
    f = ps.check_pinning(bad, "ci.yml", strict=True)
    check("--strict escalates PG-006 to High",
          all(x["severity"] == "high" for x in of_rule(f, "PG-006")))


def step4():
    print("\nStep 4 — secret-echo check")
    bad = load(os.path.join(BAD_DIR, "ci.yml"))
    f = ps.check_secret_echo(bad, "ci.yml")
    p7 = of_rule(f, "PG-007")
    check("PG-007 fires 6 times in bad ci.yml", len(p7) == 6)
    check("echo $MY_TOKEN is Medium",
          any(x["severity"] == "medium" and "MY_TOKEN" in x["evidence"]
              for x in p7))
    check("printenv is High",
          any(x["severity"] == "high" and "printenv" in x["evidence"]
              for x in p7))
    check("set -x is High",
          any(x["severity"] == "high" and "set -x" in x["evidence"]
              for x in p7))
    check("encoded echo ($MY_TOKEN | base64) is High",
          any(x["severity"] == "high" and "encoded" in x["evidence"]
              for x in p7))
    check("PG-007 line is the echo line",
          any(x["line"] == find_line(os.path.join(BAD_DIR, "ci.yml"),
                                     "run: echo $MY_TOKEN")
              for x in p7))
    clean = load(os.path.join(CLEAN_DIR, "ci.yml"))
    f = ps.check_secret_echo(clean, "ci.yml")
    check("clean workflow: secret via env: and never echoed is fine",
          of_rule(f, "PG-007") == [])
    f = ps.check_secret_echo(bad, "ci.yml")
    check("curl | sh is PG-019 Medium",
          len(of_rule(f, "PG-019")) == 1
          and of_rule(f, "PG-019")[0]["severity"] == "medium")


def step5():
    print("\nStep 5 — script-injection check")
    check("PR title is dangerous",
          ps.expr_is_dangerous("github.event.pull_request.title") is not None)
    check("github.sha is safe",
          ps.expr_is_dangerous("github.sha") is None)
    check("secrets.* is not injection (it is a PG-007 echo instead)",
          ps.expr_is_dangerous("secrets.MY_TOKEN") is None)
    check("format() wrapper does not sanitise",
          ps.expr_is_dangerous(
              "format('x {0}', github.event.pull_request.title)") is not None)
    bad = load(os.path.join(BAD_DIR, "ci.yml"))
    f = ps.check_injection(bad, "ci.yml",
                           ps.normalise_triggers(bad))
    check("PG-004 Critical in bad ci.yml",
          len(of_rule(f, "PG-004")) == 1
          and of_rule(f, "PG-004")[0]["severity"] == "critical")
    check("PG-004 line is the ${{ }} line",
          of_rule(f, "PG-004")[0]["line"] == find_line(
              os.path.join(BAD_DIR, "ci.yml"), "github.event.pull_request.title"))
    clean = load(os.path.join(CLEAN_DIR, "ci.yml"))
    f = ps.check_injection(clean, "ci.yml",
                           ps.normalise_triggers(clean))
    check("clean workflow: title passed via env: is not injection",
          of_rule(f, "PG-004") == [])


def step6():
    print("\nStep 6 — permissions check + report")
    bad = load(os.path.join(BAD_DIR, "ci.yml"))
    f = ps.check_permissions(bad, "ci.yml")
    check("PG-008 High: permissions: write-all",
          len(of_rule(f, "PG-008")) == 1)
    dep = load(os.path.join(BAD_DIR, "deploy.yml"))
    f = ps.check_permissions(dep, "deploy.yml")
    check("PG-009 High: workflow-level contents: write",
          any(x["severity"] == "high" for x in of_rule(f, "PG-009")))
    check("PG-009 Medium: workflow-level issues: write",
          any(x["severity"] == "medium" for x in of_rule(f, "PG-009")))
    check("PG-011 Medium: id-token: write in the build job",
          len(of_rule(f, "PG-011")) == 1)
    check("PG-011 not fired for the deploy job",
          not any("deploy" in x["object"] and "build" not in x["object"]
                  for x in of_rule(f, "PG-011")))
    art = load(os.path.join(BAD_DIR, "artifacts.yml"))
    f = ps.check_permissions(art, "artifacts.yml")
    check("PG-010 Medium: no permissions: block at all",
          len(of_rule(f, "PG-010")) == 1)
    # The report file must carry file, line, severity and fix.
    code, findings, _s, _g = scan(BAD_DIR)
    report = open(os.path.join(tempfile.gettempdir(),
                               "ps_test_report.txt"), encoding="utf-8").read()
    check("report contains a PG-001 finding with file and line",
          "PG-001" in report and "ci.yml" in report
          and "line" in report)
    check("report contains a Fix: line",
          "Fix:" in report)
    check("report contains the pinning defensive lesson",
          "Defensive lesson" in report and "commit SHA" in report)
    # JSON report: same findings, structured.
    tmp_json = os.path.join(tempfile.gettempdir(), "ps_test.json")
    scan(BAD_DIR, json=tmp_json)
    data = json.load(open(tmp_json, encoding="utf-8"))
    check("JSON report has file/line/rule/severity/fix per finding",
          all(set(("file", "line", "rule", "severity", "fix")) <= set(x)
              for x in data["findings"]))
    check("JSON report score matches the text run", data["score"] == 0)


def step7():
    print("\nStep 7 — full run on the test folders")
    code, findings, score, grade = scan(BAD_DIR)
    # PG-020 needs --verify-online (network), so offline it cannot fire.
    check("bad folder: all 19 offline rules fire",
          rules_of(findings) == set(ps.RULES) - {"PG-020"})
    check("bad folder: 38 findings", len(findings) == 38)
    counts = ps.summary_counts(findings)
    check("bad folder: 5 critical, 19 high, 12 medium, 2 low",
          (counts["critical"], counts["high"], counts["medium"],
           counts["low"]) == (5, 19, 12, 2))
    check("bad folder: score 0/100 grade F", score == 0 and grade == "F")
    check("bad folder: exit code 2", code == 2)
    code, findings, score, grade = scan(CLEAN_DIR)
    check("clean folder: 0 findings", findings == [])
    check("clean folder: score 100/100 grade A",
          score == 100 and grade == "A")
    check("clean folder: exit code 0", code == 0)
    # Jenkinsfile step tests.
    code, findings, score, grade = scan(JENKINS_BAD)
    check("bad Jenkinsfile: PG-015 fires 5 times",
          len(of_rule(findings, "PG-015")) == 5)
    check("bad Jenkinsfile: PG-016 fires 3 times",
          len(of_rule(findings, "PG-016")) == 3)
    check("bad Jenkinsfile: PG-017 fires once",
          len(of_rule(findings, "PG-017")) == 1)
    check("bad Jenkinsfile: AKIA line is exact",
          any(x["line"] == find_line(
              os.path.join(JENKINS_BAD, "Jenkinsfile"),
              "AKIAIOSFODNN7EXAMPLE") for x in of_rule(findings, "PG-015")))
    code, findings, score, grade = scan(JENKINS_CLEAN)
    check("clean Jenkinsfile: 0 findings", findings == [])
    # Baseline mode: record the bad folder, then nothing is new.
    base_path = os.path.join(tempfile.gettempdir(), "ps_test_baseline.json")
    _c, bad_findings, _s, _g = scan(BAD_DIR)
    ps.save_baseline(base_path, bad_findings, repo=BAD_DIR)
    by_key, by_hash = ps.load_baseline(base_path)
    new, known = ps.split_new_vs_known(bad_findings, by_key, by_hash)
    check("baseline: same folder again reports 0 new findings",
          new == [] and len(known) == len(bad_findings))
    code, _f, _s, _g = scan(BAD_DIR, baseline=base_path)
    check("baseline: exit code 0 when nothing is new", code == 0)
    code, _f, _s, _g = scan(CLEAN_DIR, baseline=base_path)
    check("baseline: clean folder vs bad baseline — 0 new, exit 0",
          code == 0)
    _c, clean_findings, _s, _g = scan(CLEAN_DIR)
    ps.save_baseline(base_path, clean_findings, repo=CLEAN_DIR)
    by_key, by_hash = ps.load_baseline(base_path)
    new, _known = ps.split_new_vs_known(bad_findings, by_key, by_hash)
    check("baseline: bad folder vs clean baseline — all 38 are new",
          len(new) == 38)
    code, _f, _s, _g = scan(BAD_DIR, baseline=base_path)
    check("baseline: exit code 2 when new criticals exist", code == 2)
    # Baseline never stores secret values.
    raw = open(base_path, encoding="utf-8").read()
    check("baseline stores no secret values",
          "s3cret-db-password" not in raw
          and "AKIAIOSFODNN7EXAMPLE" not in raw)
    # Menu doctor + list checks run without crashing.
    check("doctor returns 0", ps.doctor() == 0)
    check("list_checks runs", ps.list_checks() is None)


def _fake_github_server():
    """A tiny local server that mimics the GitHub API endpoints PG-020
    uses — so the full online flow is verified deterministically, even
    when the real API is offline or rate-limited."""
    import http.server
    import threading

    zeros = "0" * 40
    routes = {
        "/repos/actions/checkout/git/refs/tags/v4.2.1":
            (200, {"object": {"type": "commit",
                              "sha": "eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871"}}),
        "/repos/tj-actions/changed-files/git/refs/tags/v45":
            (200, {"object": {"type": "commit",
                              "sha": "48d8f15b2aaa3d255ca5af3eba4870f807ce6b3c"}}),
        "/repos/actions/checkout/commits/" + zeros:
            (404, {"message": "Not Found"}),
        "/repos/tj-actions/changed-files/commits/" + zeros:
            (404, {"message": "Not Found"}),
        "/repos/actions/checkout/commits/eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871":
            (200, {"sha": "eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871"}),
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status, payload = routes.get(
                self.path, (404, {"message": "Not Found"}))
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def step8():
    print("\nStep 8 — online SHA verification (PG-020)")
    # Part 1 — real GitHub API smoke test. Skips cleanly when offline
    # or rate-limited (unauthenticated limit is 60/hr per IP — a shared
    # IP can burn it). A ValueError means "could not verify", not
    # "verification failed".
    try:
        sha = ps.tag_commit_sha("actions", "checkout", "v4.2.1", {})
        check("tag v4.2.1 resolves to its real SHA (live API)",
              sha == "eef61447b9ff4aafe5dcd4e0bbf5d482be7e7871")
    except ValueError as exc:
        print("  [SKIP] live-API check — %s" % exc)
    # Part 2 — local fake GitHub API: the full online flow, always runs.
    server = _fake_github_server()
    old = os.environ.get("PIPE_SENTRY_GITHUB_API")
    os.environ["PIPE_SENTRY_GITHUB_API"] = (
        "http://127.0.0.1:%d" % server.server_address[1])
    try:
        check("fake API: tag v45 resolves to its real SHA",
              ps.tag_commit_sha("tj-actions", "changed-files", "v45", {})
              == "48d8f15b2aaa3d255ca5af3eba4870f807ce6b3c")
        check("fake API: bogus SHA does not exist upstream",
              not ps.commit_exists("actions", "checkout", "0" * 40, {}))
        # Clean folder: the real pins verify, still 0 findings.
        code, findings, score, grade = scan(CLEAN_DIR, verify_online=True)
        check("clean folder verifies online: 0 findings", findings == [])
        check("clean folder verifies online: exit 0", code == 0)
        # Bad folder: the bogus pin fires PG-020 (39 findings online).
        code, findings, score, grade = scan(BAD_DIR, verify_online=True)
        check("bad folder online: PG-020 fires once",
              len(of_rule(findings, "PG-020")) == 1)
        check("bad folder online: 39 findings", len(findings) == 39)
        check("bad folder online: PG-020 line is the bogus pin",
              any(x["line"] == find_line(
                  os.path.join(BAD_DIR, "ci.yml"),
                  "0000000000000000000000000000000000000000")
                  for x in of_rule(findings, "PG-020")))
    finally:
        if old is None:
            del os.environ["PIPE_SENTRY_GITHUB_API"]
        else:
            os.environ["PIPE_SENTRY_GITHUB_API"] = old
        server.shutdown()


def run_all_tests():
    print("PipeSentry step tests — 7 steps from the build plan + step 8")
    print("=" * 58)
    step1()
    step2()
    step3()
    step4()
    step5()
    step6()
    step7()
    step8()
    print()
    print("=" * 58)
    print("PASSED: %d   FAILED: %d" % (PASSED, FAILED))
    if FAILED:
        print("Failed checks:")
        for name in FAILURES:
            print("  - %s" % name)
        print("ALL CHECKS FAILED" if PASSED == 0 else "SOME CHECKS FAILED")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(run_all_tests())
