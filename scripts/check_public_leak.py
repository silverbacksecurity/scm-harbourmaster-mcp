#!/usr/bin/env python
"""Block pushes to the public mirror that contain tenant-identifying content.

The public repo (remote `pub`) is a hand-mirrored snapshot of this private
dev repo. Gitignore keeps whole tenant-named files out, but it can't catch a
tenant identifier written into the *content* of an otherwise-innocuous
tracked file (e.g. a real tenant name mentioned in ROADMAP.md prose) — that
is exactly how the 2026-07-13 leak happened, and gitleaks' secret patterns
don't catch it either since customer names aren't secrets.

Invocation paths:

  * Under **pre-commit** (`stages: [pre-push]`), git's pre-push stdin is
    consumed by pre-commit itself, which re-exports the range as
    ``PRE_COMMIT_FROM_REF``/``PRE_COMMIT_TO_REF`` and the target as
    ``PRE_COMMIT_REMOTE_URL``. Reading stdin here would see nothing, so the
    env vars are the primary source.
  * Under a **native** ``.git/hooks/pre-push``, git passes remote name/URL as
    argv and the ref updates on stdin (the documented pre-push protocol).
  * Manually: ``uv run python scripts/check_public_leak.py --commit HEAD``
    (single commit) or ``--range A..B``, to audit before a manual push.

Every commit in the pushed range is scanned, not just the tip: a tenant name
added in one commit and removed in the next is still published permanently in
the mirror's history, which is precisely the shape of the original leak.

Tenant identifiers are sourced from settings.toml (gitignored, never itself
published) rather than a second maintained list, so there is one source of
truth for "what must never appear in the public mirror". If that file is
missing the check FAILS CLOSED — a guard that cannot load its identifiers
must refuse, not wave the push through.
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
# remote, where tenant content is expected and fine. Compared after
# normalising away a trailing ".git" / slash, since `gh` and the GitHub UI
# hand out both forms and a missed match would silently disable the guard.
PUBLIC_REPO_SUFFIX = "/scm-harbourmaster-mcp"
PRIVATE_REPO_SUFFIX = "/scm-harbourmaster-mcp-dev"

# Identifiers shorter than this are too generic to grep safely (false-positive
# noise) — tenant keys/labels in practice are always longer than this.
MIN_IDENTIFIER_LEN = 4

ZERO_SHA = "0" * 40


def load_identifiers() -> list[str]:
    """Tenant keys + labels from settings.toml. Raises if it can't be read."""
    if not SETTINGS_PATH.exists():
        raise FileNotFoundError(
            f"{SETTINGS_PATH} not found — cannot determine which tenant identifiers "
            "must be kept out of the public mirror."
        )
    with SETTINGS_PATH.open("rb") as f:
        data = tomllib.load(f)
    tenants = data.get("tenants", {})
    idents: set[str] = set()
    for key, cfg in tenants.items():
        idents.add(key)
        label = (cfg or {}).get("label")
        if label:
            idents.add(str(label))
    found = sorted(i for i in idents if len(i) >= MIN_IDENTIFIER_LEN)
    if not found:
        raise ValueError(
            f"No [tenants.*] entries found in {SETTINGS_PATH} — refusing to report a "
            "clean result from an empty identifier list."
        )
    return found


def _normalise_remote(url: str) -> str:
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[: -len(".git")]
    return url


def is_public_remote(remote_url: str) -> bool:
    url = _normalise_remote(remote_url)
    return url.endswith(PUBLIC_REPO_SUFFIX) and not url.endswith(PRIVATE_REPO_SUFFIX)


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True
    )


def commits_in_range(from_ref: str, to_ref: str) -> list[str]:
    """Every commit being published. Falls back to the tip if the base is
    unknown to us (a first push, or a remote sha we don't have locally)."""
    if (
        from_ref
        and from_ref != ZERO_SHA
        and _git("cat-file", "-e", f"{from_ref}^{{commit}}").returncode == 0
    ):
        spec = f"{from_ref}..{to_ref}"
    else:
        # No known base — scan what this ref adds beyond anything already public.
        spec = to_ref
    result = _git("rev-list", spec)
    if result.returncode != 0:
        return [to_ref]
    return [c for c in result.stdout.split() if c]


def scan_filenames(commit: str, identifiers: list[str]) -> list[str]:
    result = _git("ls-tree", "-r", "--name-only", commit)
    if result.returncode != 0:
        return []
    hits = []
    for path in result.stdout.splitlines():
        low = path.lower()
        for ident in identifiers:
            if ident.lower() in low:
                hits.append(f"{commit[:9]} {path}  <- filename contains '{ident}'")
    return hits


def scan_contents(commit: str, identifiers: list[str]) -> list[str]:
    cmd = ["grep", "--fixed-strings", "--ignore-case", "-I", "-n"]
    for ident in identifiers:
        cmd += ["-e", ident]
    cmd += [commit]
    result = _git(*cmd)
    if result.returncode == 0:
        return [f"{commit[:9]} {line}" for line in result.stdout.splitlines()]
    if result.returncode == 1:
        return []  # no matches
    raise RuntimeError(f"git grep failed: {result.stderr.strip()}")


def check_commit(commit: str, identifiers: list[str]) -> list[str]:
    return scan_filenames(commit, identifiers) + scan_contents(commit, identifiers)


def check_commits(commits: list[str], identifiers: list[str]) -> list[str]:
    hits: list[str] = []
    for commit in commits:
        hits.extend(check_commit(commit, identifiers))
    return hits


def _report(hits: list[str], scanned: int) -> int:
    if hits:
        print(
            "BLOCKED: tenant-identifying content found in commit(s) bound for the public mirror:",
            file=sys.stderr,
        )
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        print(
            "\nRemove or redact this content before pushing to `pub`. Rewriting only "
            "the tip is not enough — every commit in the pushed range is published.",
            file=sys.stderr,
        )
        return 1
    print(f"check_public_leak: {scanned} commit(s) scanned, no tenant identifiers found.")
    return 0


def _stdin_ranges() -> list[tuple[str, str]]:
    """Native pre-push protocol: '<local ref> <local sha> <remote ref> <remote sha>'."""
    ranges = []
    if sys.stdin.isatty():
        return ranges
    for line in sys.stdin:
        parts = line.split()
        if len(parts) != 4:
            continue
        _local_ref, local_sha, _remote_ref, remote_sha = parts
        if local_sha == ZERO_SHA:
            continue  # branch/tag deletion
        ranges.append((remote_sha, local_sha))
    return ranges


def run_hook_mode() -> int:
    remote_url = os.environ.get("PRE_COMMIT_REMOTE_URL") or (
        sys.argv[2] if len(sys.argv) > 2 else ""
    )
    if not remote_url:
        print(
            "check_public_leak: no remote URL supplied — cannot tell whether this push "
            "targets the public mirror; refusing.",
            file=sys.stderr,
        )
        return 1
    if not is_public_remote(remote_url):
        print(f"check_public_leak: {remote_url} is not the public mirror — skipped.")
        return 0

    identifiers = load_identifiers()

    # pre-commit consumes git's stdin and re-exports the range; fall back to
    # the native stdin protocol when running as a plain .git/hooks/pre-push.
    from_ref = os.environ.get("PRE_COMMIT_FROM_REF", "")
    to_ref = os.environ.get("PRE_COMMIT_TO_REF", "")
    ranges = [(from_ref, to_ref)] if to_ref else _stdin_ranges()

    if not ranges:
        print(
            "check_public_leak: could not determine which commits are being pushed "
            "(no PRE_COMMIT_TO_REF and no ref updates on stdin); refusing rather than "
            "reporting a clean result.",
            file=sys.stderr,
        )
        return 1

    commits: list[str] = []
    for base, tip in ranges:
        commits.extend(commits_in_range(base, tip))
    commits = list(dict.fromkeys(commits))
    return _report(check_commits(commits, identifiers), len(commits))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", help="Scan a single commit/ref manually.")
    parser.add_argument("--range", dest="rev_range", help="Scan a range, e.g. origin/master..HEAD")
    args, _unknown = parser.parse_known_args()

    try:
        if args.rev_range:
            base, _, tip = args.rev_range.partition("..")
            commits = commits_in_range(base, tip or "HEAD")
            return _report(check_commits(commits, load_identifiers()), len(commits))
        if args.commit:
            return _report(check_commit(args.commit, load_identifiers()), 1)
        return run_hook_mode()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"check_public_leak: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
