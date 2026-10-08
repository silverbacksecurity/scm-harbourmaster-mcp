#!/usr/bin/env python
"""Regenerate src/scm_harbourmaster_mcp/resources/endpoint_catalog.json from pan.dev.

The catalog is a compact index of every endpoint in the pan.dev OpenAPI specs
(MIT-licensed) for the API trees this server talks to: sase, scm, access.
It powers:

  * exact REST-fallback URLs in audit.extractor (instead of naive slug guesses)
  * the spec-drift section of scm_check_updates (per-file git blob SHAs)

Usage:
    uv run --with pyyaml python scripts/gen_endpoint_catalog.py [--specs-dir DIR]

Without --specs-dir a temporary sparse clone of PaloAltoNetworks/pan.dev is
made (blob-less, ~10 MB checkout). Requires git and network in that case.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import yaml

REPO_URL = "https://github.com/PaloAltoNetworks/pan.dev"
# Product trees this server integrates with: SASE/SCM plus the adjacent
# security products an MSSP managing those tenants also touches (classic
# Prisma SD-WAN, standalone DLP/DNS-Security, Cloud NGFW-for-AWS, CDL log
# forwarding, email DLP, Prisma Browser).
#
# Deliberately excluded — real pan.dev product families, but different
# platforms outside this server's SCM/SASE scope: openapi-specs/mssp (Prisma
# *Cloud's* MSSP backend — CSPM/CWPP tenant management, not Prisma SASE),
# compute/cwpp/cspm/dspm (Prisma Cloud workload & posture — thousands of
# files), iot (IoT Security), prisma-airs* (AI security), threat-vault,
# action-plan, aiops-ngfw-bpa, code (docs-site tooling, not an API).
TREES = (
    "openapi-specs/sase",
    "openapi-specs/scm",
    "openapi-specs/access",
    "openapi-specs/sdwan",
    "openapi-specs/dlp",
    "openapi-specs/dns-security",
    "openapi-specs/cloudngfw",
    "openapi-specs/cdl",
    "openapi-specs/email-dlp",
    # Prisma Browser management (/seb-api/v1) — moved out of access/browser-mgmt
    # into its own pan.dev tree on 2026-09-18.
    "openapi-specs/prisma-browser",
)
OUT_DEFAULT = (
    Path(__file__).parent.parent
    / "src"
    / "scm_harbourmaster_mcp"
    / "resources"
    / "endpoint_catalog.json"
)


def _sparse_clone(tmp: str) -> Path:
    dest = Path(tmp) / "pan.dev"
    subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", REPO_URL, str(dest)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "sparse-checkout", "set", *TREES],
        check=True,
        capture_output=True,
    )
    return dest


def _blob_shas(repo: Path) -> dict[str, str]:
    """relpath → git blob SHA for every file under the spec trees."""
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "HEAD", *TREES],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    shas: dict[str, str] = {}
    for line in out.splitlines():
        # "<mode> blob <sha>\t<path>"
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "blob":
            shas[path] = parts[2]
    return shas


def build_catalog(repo: Path) -> dict:
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    shas = _blob_shas(repo)

    specs: dict[str, dict] = {}
    n_paths = 0
    for tree in TREES:
        for f in sorted((repo / tree).rglob("*")):
            if f.suffix not in (".yaml", ".yml", ".json") or not f.is_file():
                continue
            try:
                doc = (
                    json.loads(f.read_text())
                    if f.suffix == ".json"
                    else yaml.safe_load(f.read_text())
                )
            except Exception as exc:  # noqa: BLE001 — skip unparseable spec, keep going
                print(f"  skip {f}: {exc}", file=sys.stderr)
                continue
            if not isinstance(doc, dict) or "paths" not in doc:
                continue
            rel = str(f.relative_to(repo))
            parts = rel.split("/")
            # e.g. "sase/mt-interconnect"; falls back to just the top-level
            # product dir when specs sit flat under it with no subfolder
            # (e.g. "dlp/DataPatterns.yaml" -> family "dlp", not "dlp/DataPatterns.yaml")
            family = "/".join(parts[1:3]) if len(parts) > 3 else parts[1]
            servers = doc.get("servers") or []
            base = str(servers[0].get("url", "")) if servers else ""
            paths = {
                p: sorted(m for m in ops if m in ("get", "post", "put", "patch", "delete"))
                for p, ops in doc["paths"].items()
                if isinstance(ops, dict)
            }
            n_paths += len(paths)
            specs.setdefault(family, {"files": {}})["files"][rel] = {
                "sha": shas.get(rel, ""),
                "base": base,
                "paths": paths,
            }

    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pan_dev_commit": head,
        "trees": list(TREES),
        "total_paths": n_paths,
        # every yaml/json blob under the trees (parseable or not) so the
        # drift check compares the same file set the live tree API returns
        "file_shas": {
            rel: sha for rel, sha in shas.items() if rel.endswith((".yaml", ".yml", ".json"))
        },
        "specs": specs,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--specs-dir", help="existing pan.dev checkout (skips cloning)")
    ap.add_argument("--out", default=str(OUT_DEFAULT))
    args = ap.parse_args()

    if args.specs_dir:
        catalog = build_catalog(Path(args.specs_dir))
    else:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = build_catalog(_sparse_clone(tmp))

    out = Path(args.out)
    out.write_text(json.dumps(catalog, separators=(",", ":"), sort_keys=True) + "\n")
    print(
        f"wrote {out} — {catalog['total_paths']} paths, "
        f"{len(catalog['specs'])} families, pan.dev @ {catalog['pan_dev_commit'][:12]} "
        f"({out.stat().st_size // 1024} KB)"
    )


if __name__ == "__main__":
    main()
