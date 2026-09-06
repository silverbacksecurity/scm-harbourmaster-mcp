# Contributing to scm-mcp-mssp

## Branching model

```
master          ← stable, tagged releases only
  └── develop   ← integration branch; all feature work merges here first
        ├── feat/my-new-tool
        ├── feat/gp-session-tracker
        └── fix/cert-scan-edge-case
```

| Branch pattern | Base branch | Merges into | Purpose |
|---------------|-------------|-------------|---------|
| `feat/*` | `develop` | `develop` | New tools, capabilities, enhancements |
| `fix/*` | `develop` | `develop` | Bug fixes for unreleased work |
| `hotfix/*` | `master` | `master` + `develop` | Critical fixes for a released version |
| `release/*` | `develop` | `master` + `develop` | Release prep (version bump, changelog) |
| `chore/*` | `develop` | `develop` | CI, deps, tooling — no runtime change |
| `docs/*` | `develop` | `develop` | Documentation only |

**Never commit directly to `master` or `develop`.**  All changes arrive via pull request.

## Quickstart

```bash
git clone https://github.com/silverbacksecurity/scm-mcp-mssp
cd scm-mcp-mssp
uv sync
git checkout develop
git checkout -b feat/my-feature
```

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short imperative description>

[optional body]

[optional footer: Closes #123]
```

Types: `feat` `fix` `docs` `refactor` `chore` `test` `ci` `perf`

Examples:
```
feat: add scm_cert_scan tool for certificate expiry monitoring
fix: remove () from oauth.token_expires_soon property call
docs: add scm_gp_session_summary to TOOL_REFERENCE
chore: bump pan-scm-sdk to 0.16.0
```

The PR title must also follow this format — `pr-checks.yml` enforces it.

## Adding a new MCP tool

1. Pick the right module in `src/scm_mcp_mssp/tools/` (or create one).
2. Decorate with `@mcp.tool()` and write a full docstring — Claude reads it.
3. Register in `server.py` if a new module.
4. Update tool count in `README.md` and `docs/TOOL_REFERENCE.md`.
5. Add a CHANGELOG entry under `### Added`.
6. Test read-only against at least one real tenant before opening a PR.

## Local checks (run before pushing)

```bash
uv run ruff check src/         # lint
uv run ruff format --check src/ # format
uv run mypy src/               # types
uv run pytest                  # tests
```

All four must pass — the CI gate blocks merges if they don't.

## Pull request process

1. Open the PR against `develop` (or `master` for hotfixes).
2. Fill in the PR template — test plan section is required.
3. Ensure CI gate is green before requesting review.
4. Squash-merge preferred to keep history clean.
5. Delete the branch after merge.

## Security & secrets

- **Never** commit `.secrets.toml`, `.env`, report files (`*.md`/`*.docx` named after a tenant or customer, e.g. `tenant-*`), or backup JSON.
- The `.gitignore` blocks most of these; if you hit a false negative, fix `.gitignore` in the same PR.
- Rotate any credential that is accidentally committed immediately.
- This repo mirrors to a **public** repo (`pub` remote). Gitignore only stops whole tenant-named files — it does not catch a real tenant name written into the *content* of an otherwise-normal file (e.g. prose in `ROADMAP.md`), which is how a customer name leaked into public history on 2026-07-13. Run `uv run pre-commit install --hook-type pre-push` once (see README Development section) so `scripts/check_public_leak.py` blocks any push to `pub` containing a known tenant identifier from `settings.toml`. To audit a commit manually before a squash-publish: `uv run python scripts/check_public_leak.py --commit HEAD`.

## Release process

Releases are cut from `master` by tagging:

```bash
git checkout master
git pull
git tag v0.5.0
git push origin v0.5.0
```

The `release.yml` workflow builds the wheel, publishes to PyPI, and creates a GitHub Release automatically. Update `CHANGELOG.md` and bump `pyproject.toml` version in the `release/*` branch before merging.
