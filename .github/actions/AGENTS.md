# `.github/actions/` - Reusable Workflow Actions

Composite GitHub Actions shared by release and docs workflows.

## OVERVIEW

This directory owns reusable CI building blocks, not full workflow policy. Keep action behavior stable, parameterized, and safe for non-interactive runners.

## STRUCTURE

```tree
actions/
├── release-validate/  # manifest/tag consistency gate for publish flow
└── setup-ts/          # shared Bun/Node/Deno runtime bootstrap
```

## WHERE TO LOOK

| Task             | Location                                                      | Notes                                                 |
| ---------------- | ------------------------------------------------------------- | ----------------------------------------------------- |
| Release gating   | `release-validate/action.yml`, `release-validate/validate.sh` | checks `package.json`, `jsr.json`, and tag alignment  |
| Runtime setup    | `setup-ts/action.yml`                                         | installs Bun by default; Node/Deno optional           |
| Action consumers | `.github/workflows/`                                          | publish, docs deploy, and preview flows wire these in |

## CONVENTIONS

- Keep composite actions small and reusable; workflow-specific branching belongs in the workflow file unless reused elsewhere.
- Shell steps must be `bash` + `set -euo pipefail` and emit outputs only through `GITHUB_OUTPUT`.
- Prefer explicit inputs and outputs over hard-coded repo state.
- Treat `package.json` and `jsr.json` version parity as a release invariant.

## ANTI-PATTERNS

- Do not bake secrets, branch names, or one-off workflow assumptions into these actions.
- Do not make publish validation lenient; tag/manifests mismatch should fail closed.
- Do not install extra runtimes by default unless a shared workflow actually needs them.
