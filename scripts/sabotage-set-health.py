#!/usr/bin/env python3
"""Sabotage scorer for auth-store's SetHealth success branch.

Written by the 201st nightly pass, 2026-08-15, working step 2 of noteboard card
25ac6a72-a5a0-4ada-b4a9-aeeb4e688177 — the sweep of boolean parameters that no
test ever passes both values to.

A test that passes is not a test that works. This script breaks the code the new
tests were written to pin, one edit at a time, and reports whether the suite
noticed. Run it from the repo root:

    python3 scripts/sabotage-set-health.py

Exit 0 means every mutation was caught. Exit 3 means at least one survived, and
the survivor is named — a surviving mutation is a hole in the tests, not a
failure of this script.

Two rules are enforced here because earlier passes lost time to both:

  * Every needle must occur EXACTLY ONCE in its file, checked before the write.
    A needle that matches nothing produces a green run indistinguishable from a
    surviving mutation. The 201st pass hit exactly this on its first attempt and
    briefly recorded a false survivor.
  * The unmutated tree must be green first. Scoring a red suite measures nothing.

The MINE column below (`-run` filtered to the new tests) is not attribution on
its own. To ask what the new tests added, move the new test file out of the
package and re-run: that is the PRIOR column, and it is the only one that can
distinguish "these tests catch it" from "something in the package already did".
Comparing a filtered run against the whole package cannot — the package contains
the filter.
"""
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = '.'
RUN = 'TestSetHealth'
CASES = [
    {
        "name": "success branch no longer resets error_count",
        "file": "credentials.go",
        "find": "SET last_error = '', error_count = 0, last_used_at = ?",
        "replace": "SET last_error = '', last_used_at = ?"
    },
    {
        "name": "success branch no longer clears last_error",
        "file": "credentials.go",
        "find": "SET last_error = '', error_count = 0, last_used_at = ?",
        "replace": "SET error_count = 0, last_used_at = ?"
    },
    {
        "name": "success branch stops stamping last_used_at",
        "file": "credentials.go",
        "find": "SET last_error = '', error_count = 0, last_used_at = ? WHERE id = ?`, now, id)",
        "replace": "SET last_error = '', error_count = 0 WHERE id = ?`, id)"
    },
    {
        "name": "success and failure branches swapped",
        "file": "credentials.go",
        "find": "\tnow := time.Now().UnixMilli()\n\tif success {\n\t\ts.db.Exec(`UPDATE credentials SET last_error = ''",
        "replace": "\tnow := time.Now().UnixMilli()\n\tif !success {\n\t\ts.db.Exec(`UPDATE credentials SET last_error = ''"
    },
    {
        "name": "success branch stores its message as an error",
        "file": "credentials.go",
        "find": "\t\ts.db.Exec(`UPDATE credentials SET last_error = '', error_count = 0, last_used_at = ? WHERE id = ?`, now, id)",
        "replace": "\t\ts.db.Exec(`UPDATE credentials SET last_error = ?, error_count = 0, last_used_at = ? WHERE id = ?`, errMsg, now, id)"
    },
    {
        "name": "MarkReloginSuccess stops clearing last_error_at",
        "file": "credentials.go",
        "find": "SET last_refreshed_at = ?, last_error = '', last_error_at = 0, error_count = 0 WHERE id = ?",
        "replace": "SET last_refreshed_at = ?, last_error = '', error_count = 0 WHERE id = ?"
    },
    {
        "name": "Resolve stops ranking on error_count",
        "file": "credentials.go",
        "find": "\tsql += ` ORDER BY priority ASC, error_count ASC`",
        "replace": "\tsql += ` ORDER BY priority ASC`"
    }
]


def run_tests(selector):
    r = subprocess.run(
        ["go", "test", PKG, "-run", selector, "-count=1"],
        cwd=REPO, capture_output=True, text=True,
    )
    return r.returncode == 0


def main():
    originals = {}
    for case in CASES:
        path = os.path.join(REPO, case["file"])
        if case["file"] not in originals:
            originals[case["file"]] = open(path).read()

    def restore():
        for name, content in originals.items():
            open(os.path.join(REPO, name), "w").write(content)

    if not run_tests(RUN):
        print("CONTROL FAILED - the suite is red before any mutation. Score is void.")
        return 1
    print("control (unmutated) ..... GREEN\n")

    caught, unnoticed = [], []
    try:
        for case in CASES:
            src = originals[case["file"]]
            n = src.count(case["find"])
            if n != 1:
                print("  ABORT  %s: needle occurs %d times, want exactly 1" % (case["name"], n))
                return 2
            path = os.path.join(REPO, case["file"])
            open(path, "w").write(src.replace(case["find"], case["replace"], 1))
            green = run_tests(RUN)
            restore()
            if green:
                unnoticed.append(case["name"])
                print("  UNNOTICED  " + case["name"])
            else:
                caught.append(case["name"])
                print("  caught     " + case["name"])
    finally:
        restore()

    print("\n%d/%d caught" % (len(caught), len(CASES)))
    if unnoticed:
        print("UNNOTICED:")
        for name in unnoticed:
            print("  - " + name)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
