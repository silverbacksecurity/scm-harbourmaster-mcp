#!/usr/bin/env python
"""Block pushes to the public mirror that contain tenant-identifying content.

The public repo (remote `pub`) is a hand-mirrored snapshot of this private
dev repo. Gitignore keeps whole tenant-named files out, but it can't catch a
tenant identifier written into the *content* of an otherwise-innocuous
tracked file (e.g. a real tenant name mentioned in ROADMAP.md prose) — that
is exactly how the 2026-07-13 leak happened, and gitleaks' secret patterns
don't catch it either since customer names aren't secrets.

This script is the same check either way it's invoked:

  * As a pre-push hook (installed via pre-commit, see .pre-commit-config.yaml)
    it reads git's pre-push protocol (remote name/URL as argv, ref updates on
    stdin) and only enforces when the target remote is the public mirror.
  * Run manually — ``uv run python scripts/check_public_leak.py --commit HEAD``
    — to audit a commit before a manual ``git push pub``.

Tenant identifiers are sourced from settings.toml (gitignored, never itself
published) rather than a second maintained list, so there is one source of
truth for "what must never appear in the public mirror."
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_PATH = REPO_ROOT / "settings.toml"

# Only enforce against the actual public mirror — never the private dev
# remote, where tenant content is expected and fine.
PUBLIC_REMOTE_SUFFIX = "/scm-mcp-mssp.git"
PRIVATE_REMOTE_SUFFIX = "/scm-mcp-mssp-dev.git"

# Identifiers shorter than this are too generic to grep safely (false-positive
# noise) — tenant keys/labels in practice are always longer than this.
MIN_IDENTIFIER_LEN = 4

ZERO_SHA = "0" * 40


def load_identifiers() -> list[str]:
    if not SETTINGS_PATH.exists():
        return []
    with SETTINGS_PATH.open("rb") as f:
        data = tomllib.load(f)
    tenants = data.get("tenants", {})
    idents: set[str] = set()
    for key, cfg in tenants.items():
        idents.add(key)
        label = (cfg or {}).get("label")
        if label:
            idents.add(str(label))
    return sorted(i for i in idents if len(i) >= MIN_IDENTIFIER_LEN)


def is_public_remote(remote_url: str) -> bool:
    url = remote_url.rstrip("/")
    return url.endswith(PUBLIC_REMOTE_SUFFIX) and not url.endswith(PRIVATE_REMOTE_SUFFIX)


def scan_filenames(commit: str, identifiers: list[str]) -> list[str]:
    result = subprocess.run(  # noqa: S603
        ["git", "ls-tree", "-r", "--name-only", commit],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    hits = []
    for path in result.stdout.splitlines():
        low = path.lower()
        for ident in identifiers:
            if ident.lower() in low:
                hits.append(f"{path}  <- filename contains tenant identifier '{ident}'")
    return hits


def scan_contents(commit: str, identifiers: list[str]) -> list[str]:
    if not identifiers:
        return []
    cmd = ["git", "grep", "--fixed-strings", "--ignore-case", "-I", "-n"]
    for ident in identifiers:
        cmd += ["-e", ident]
    cmd += [commit]
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)  # noqa: S603
    if result.returncode == 0:
        return result.stdout.splitlines()
    if result.returncode == 1:
        return []  # no matches
    raise RuntimeError(f"git grep failed: {result.stderr.strip()}")


def check_commit(commit: str, identifiers: list[str]) -> list[str]:
    return scan_filenames(commit, identifiers) + scan_contents(commit, identifiers)


def run_hook_mode() -> int:
    """Standard git pre-push protocol: remote name/URL, then stdin lines of
    ``<local ref> <local sha> <remote ref> <remote sha>``.

    pre-commit's pre-push stage exposes the remote via
    ``PRE_COMMIT_REMOTE_NAME``/``PRE_COMMIT_REMOTE_URL`` rather than argv, so
    those are checked first; a native (non-pre-commit) ``.git/hooks/pre-push``
    invocation falls back to git's own argv1/argv2 protocol.
    """
    remote_url = os.environ.get("PRE_COMMIT_REMOTE_URL") or (
        sys.argv[2] if len(sys.argv) > 2 else ""
    )
    if not is_public_remote(remote_url):
        return 0  # not pushing to the public mirror — nothing to do

    identifiers = load_identifiers()
    all_hits: list[str] = []
    for line in sys.stdin:
        parts = line.split()
        if len(parts) != 4:
            continue
        _local_ref, local_sha, _remote_ref, _remote_sha = parts
        if local_sha == ZERO_SHA:
            continue  # branch/tag deletion, nothing to scan
        all_hits.extend(check_commit(local_sha, identifiers))

    if all_hits:
        print(
            "BLOCKED: tenant-identifying content found in commit(s) bound for the public mirror:",
            file=sys.stderr,
        )
        for hit in all_hits:
            print(f"  {hit}", file=sys.stderr)
        print(
            "\nRemove or redact this content before pushing to `pub`. "
            "If a match is a false positive, tighten settings.toml's tenant "
            "label/key or adjust scripts/check_public_leak.py.",
            file=sys.stderr,
        )
        return 1

    print("check_public_leak: no tenant identifiers found — push allowed.")
    return 0


def run_manual_mode(commit: str) -> int:
    identifiers = load_identifiers()
    hits = check_commit(commit, identifiers)
    if hits:
        print(f"Tenant-identifying content found in {commit}:", file=sys.stderr)
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        return 1
    print(f"check_public_leak: {commit} is clean of known tenant identifiers.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--commit",
        default=None,
        help="Scan this commit/ref manually instead of running as a pre-push hook.",
    )
    args, _unknown = parser.parse_known_args()

    if args.commit:
        return run_manual_mode(args.commit)
    return run_hook_mode()


if __name__ == "__main__":
    sys.exit(main())
