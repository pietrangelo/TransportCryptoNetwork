#!/usr/bin/env python3
"""Structural checks of release-publish.yml (review 0013, A13-6).

    python3 packaging/release/tests/workflow_check.py [path/to/release-publish.yml]

Prints one line per check and exits 1 if any fails. Needs PyYAML (preinstalled on the GitHub
runners).
"""

import sys
from pathlib import Path

import yaml

here = Path(__file__).resolve().parent
path = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "../../../.github/workflows/release-publish.yml"
text = path.read_text(encoding="utf-8")
wf = yaml.safe_load(text)
# PyYAML reads the key `on` as the boolean True.
triggers = wf.get("on", wf.get(True)) or {}
jobs = wf.get("jobs") or {}
failures = 0


def check(name, ok):
    global failures
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        failures += 1


def steps_of(job):
    return job.get("steps") or []


def runs(step):
    return step.get("run") or ""


dispatch = triggers.get("workflow_dispatch") if isinstance(triggers, dict) else None
check("started by hand only (workflow_dispatch)", isinstance(triggers, dict) and set(triggers) == {"workflow_dispatch"})
check("no tag input: the tag is the ref the run was started from", not (dispatch or {}).get("inputs"))
check("no expression reads an input", "inputs." not in text)
check("the run must start from a tag (github.ref_type)", "github.ref_type" in text or "GITHUB_REF_TYPE" in text)
check("the tag's commit must be on main", "merge-base --is-ancestor" in text)

openssl_jobs = [n for n, j in jobs.items() if any("build-openssl.sh" in runs(s) for s in steps_of(j))]
check("OpenSSL is built in exactly one job", len(openssl_jobs) == 1)
for name in openssl_jobs:
    job = jobs[name]
    perms = job.get("permissions") or {}
    check(f"{name}: read-only token while OpenSSL builds", perms == {"contents": "read"})
    check(f"{name}: no GH_TOKEN in the job that builds OpenSSL", "GH_TOKEN" not in yaml.safe_dump(job))
    check(f"{name}: not in the release environment", "environment" not in job)

publish_jobs = [n for n, j in jobs.items() if any("--draft=false" in runs(s) for s in steps_of(j))]
check("one job publishes", len(publish_jobs) == 1)
for name in publish_jobs:
    job = jobs[name]
    check(f"{name}: in the protected release environment", job.get("environment") == "release")
    check(f"{name}: needs the OpenSSL job", bool(openssl_jobs) and openssl_jobs[0] in (job.get("needs") or []))
    check(f"{name}: GH_TOKEN only on the steps that call gh", "GH_TOKEN" not in (job.get("env") or {}))
    for step in steps_of(job):
        env = step.get("env") or {}
        if "GH_TOKEN" in env:
            check(f"{name}: a step with GH_TOKEN only calls gh ({step.get('name', '?')})",
                  "tcn-release.sh" not in runs(step) and "openssl" not in runs(step).lower())
    steps = steps_of(job)
    publish_at = next(i for i, s in enumerate(steps) if "--draft=false" in runs(s))
    before = "\n".join(runs(s) for s in steps[:publish_at + 1])
    check(f"{name}: the asset list is checked before publishing", "--json assets" in before)
    check(f"{name}: the assets are downloaded again and compared before publishing",
          before.count("gh release download") >= 2 and "cmp" in before)
    check(f"{name}: verified by the script and pins of the default branch",
          "default_branch" in text and "trusted/packaging/release/tcn-release.sh" in before)
    check(f"{name}: verify is bound to the tag (--tag)", "--tag" in before)

sys.exit(1 if failures else 0)
