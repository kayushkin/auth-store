#!/usr/bin/env python3
"""Score whether anything notices when auth-store serves a credential unmasked.

`toView` (internal/server/credentials.go) is the single funnel from a stored
credential to the JSON the HTTP API returns. It masks `api_key` and `token` and
answers `has_refresh_token` / `has_client_secret` / `has_password` instead of
carrying those three. Four routes reach it. Nothing held any of that: the package
had no test file, so dropping either `MaskSecret` call served live credential
material over HTTP and reddened nothing.

Each arm rewrites one line in the working tree, runs the suite, restores the file,
and records whether the suite went red.

Contract (see ~/.nightly-shared/README.md):

    sabotage-credential-masking.py                    score every arm
    sabotage-credential-masking.py --list-sabotages   one arm name per line, exit 0
    sabotage-credential-masking.py --arm <name>       score one arm
    <anything else>                                   exit 2

`rig-can-go-red-without-the-new-tests` is the liveness arm and it exists for a
specific reason: before these tests, auth-store's ONLY test file was
internal/oauth/anthropic_test.go. A rig scored against a package with no tests
returns all-SURVIVED whether it works or not, so the BEFORE run has to contain at
least one arm that reddens through a test that already existed.
"""

import argparse
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
VIEW = "internal/server/credentials.go"
STORE = "credentials.go"
MW = "internal/server/middleware.go"
ROUTES = "internal/server/server.go"
OAUTH = "internal/oauth/anthropic.go"

# name -> (relative file, needle, replacement, must_redden, why)
ARMS = {
    "apikey-not-masked": (
        VIEW,
        "APIKey:          authstore.MaskSecret(c.APIKey),",
        "APIKey:          c.APIKey,",
        True,
        "the stored API key goes on the wire in full",
    ),
    "token-not-masked": (
        VIEW,
        "Token:           authstore.MaskSecret(c.Token),",
        "Token:           c.Token,",
        True,
        "the stored access token goes on the wire in full",
    ),
    "masked-apikey-emptied": (
        VIEW,
        "APIKey:          authstore.MaskSecret(c.APIKey),",
        'APIKey:          "",',
        True,
        "asserting only that the secret is ABSENT is satisfied by serving nothing",
    ),
    "has-refresh-token-inverted": (
        VIEW,
        "HasRefreshToken: c.RefreshToken != \"\",",
        "HasRefreshToken: c.RefreshToken == \"\",",
        True,
        "the boolean that stands in for a secret answers about the wrong state",
    ),
    "bearer-check-removed": (
        MW,
        'if !strings.HasPrefix(auth, "Bearer ") || auth[7:] != s.cfg.AuthToken {',
        'if strings.HasPrefix(auth, "Bearer ") && auth[7:] != s.cfg.AuthToken {',
        True,
        "a mask that holds is no use if the route answers an unauthenticated reader",
    ),
    "mask-helper-returns-raw-secret": (
        STORE,
        'return s[:4] + "..." + s[len(s)-4:]',
        "return s",
        True,
        "known-positive control: the helper itself must be held",
    ),
    "rig-can-go-red-without-the-new-tests": (
        OAUTH,
        "if i := strings.IndexByte(code, '#'); i >= 0 {",
        "if i := strings.IndexByte(code, '#'); i < 0 {",
        True,
        "liveness: reddens through internal/oauth, which had the repo's only test file",
    ),
    "comment-only-crywolf": (
        ROUTES,
        "// Public.",
        "// cry-wolf control: an edit that changes no behaviour",
        False,
        "cry-wolf control: a green rig must stay green here",
    ),
}


def go(*a):
    p = subprocess.run(["go", *a], cwd=REPO, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr)


def run_suite():
    return go("test", "./...")


def builds_and_vets():
    """A mutated tree that does not compile — or that `go test`'s own vet pass would
    reject — reddens the suite for a reason that is not a test noticing anything.
    Detecting that by matching error prose is a guess; asking the toolchain is not."""
    code, out = go("build", "./...")
    if code != 0:
        return "mutated tree does not COMPILE", out
    code, out = go("vet", "./...")
    if code != 0:
        return "mutated tree does not VET (go test runs vet, so this reddens on its own)", out
    return None, ""


def git(*a):
    return subprocess.run(
        ["git", *a], cwd=REPO, capture_output=True, text=True
    ).stdout.strip()


def refuse(msg):
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(2)


def score_arm(name):
    rel, needle, repl, must_redden, why = ARMS[name]
    path = REPO / rel
    original = path.read_text()
    hits = original.count(needle)
    if hits == 0:
        return {"arm": name, "verdict": "SKIPPED", "reason": "anchor not found",
                "must_redden": must_redden, "why": why}
    if hits > 1:
        return {"arm": name, "verdict": "REFUSED",
                "reason": f"anchor matches {hits} times — a needle that hits the wrong "
                          "copy prints green and reads exactly like a control that behaved",
                "must_redden": must_redden, "why": why}
    try:
        path.write_text(original.replace(needle, repl))
        broken, detail = builds_and_vets()
        if broken:
            return {"arm": name, "verdict": "REFUSED",
                    "reason": broken + " — a build failure is not a caught bug",
                    "detail": detail.strip().splitlines()[-3:],
                    "must_redden": must_redden, "why": why}
        code, _ = run_suite()
        reddened = code != 0
    finally:
        path.write_text(original)
    return {
        "arm": name,
        "verdict": ("CAUGHT" if reddened else "SURVIVED") if must_redden
        else ("GREEN" if not reddened else "CRIED-WOLF"),
        "reddened": reddened,
        "must_redden": must_redden,
        "behaved": reddened == must_redden,
        "why": why,
    }


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--list-sabotages", action="store_true")
    ap.add_argument("--arm")
    ap.add_argument("--json")
    args = ap.parse_args()

    if args.list_sabotages:
        for n in ARMS:
            print(n)
        return 0
    if args.arm and args.arm not in ARMS:
        refuse(f"unknown arm {args.arm!r}")

    modified = git("status", "--porcelain", "--untracked-files=no")
    if modified:
        refuse("a TRACKED file is modified — restore it before scoring, or an arm "
               "restores the wrong text and the score is against a tree nobody chose\n"
               + modified)
    code, out = run_suite()
    if code != 0:
        refuse("BASELINE IS RED -- fix that before scoring any arm; a red baseline "
               "grades every arm as caught\n" + out[-2000:])

    names = [args.arm] if args.arm else list(ARMS)
    rows = [score_arm(n) for n in names]
    behaved = sum(1 for r in rows if r.get("behaved"))
    for r in rows:
        print(f"{'ok ' if r.get('behaved') else 'XX '}{r['arm']:<38} "
              f"{r['verdict']:<10} {r['why']}")
    print(f"\nSCORE {behaved}/{len(rows)} arms behaved")

    result = {
        "repo": str(REPO),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "commit": git("rev-parse", "HEAD"),
        "tracked_modified": bool(git("status", "--porcelain", "--untracked-files=no")),
        "untracked": git("status", "--porcelain", "--untracked-files=all").splitlines(),
        "score": f"{behaved}/{len(rows)}",
        "rows": rows,
    }
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(result, indent=2))
    return 0 if behaved == len(rows) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        refuse(f"{type(e).__name__}: {e}")
