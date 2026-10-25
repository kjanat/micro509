# `.github/actions/` - Reusable Workflow Actions

Composite GitHub Actions shared by release and docs workflows.

## OVERVIEW

This directory owns reusable CI building blocks, not full workflow policy. Keep action behavior stable, parameterized, and safe for non-interactive runners.

## STRUCTURE

```tree
actions/
├── cache-tsc/         # compiler artifact restore/save
├── release-validate/  # manifest/tag consistency gate for publish flow
├── setup-openssl/     # pinned OpenSSL differential oracle from ghcr.io/kjanat/openssl-prebuilt
└── setup/             # shared Bun/Node/Deno runtime bootstrap
```

## WHERE TO LOOK

| Task             | Location                                                      | Notes                                                 |
| ---------------- | ------------------------------------------------------------- | ----------------------------------------------------- |
| Release gating   | `release-validate/action.yml`, `release-validate/validate.sh` | checks `package.json`, `jsr.json`, and tag alignment  |
| Runtime setup    | `setup/action.yml`                                            | installs Bun by default; Node/Deno optional           |
| OpenSSL oracle   | `setup-openssl/action.yml`                                    | installs a build published by `workflows/openssl.yml` |
| Action consumers | `.github/workflows/`                                          | publish, docs deploy, and preview flows wire these in |

## CONVENTIONS

- Keep composite actions small and reusable; workflow-specific branching belongs in the workflow file unless reused elsewhere.
- Shell steps use `shell: "bash -euo pipefail {0}"`; action outputs go through `GITHUB_OUTPUT`.
- Prefer explicit inputs and outputs over hard-coded repo state.
- Treat `package.json` and `jsr.json` version parity as a release invariant.

## ANTI-PATTERNS

- Do not bake secrets, branch names, or one-off workflow assumptions into these actions.
- Do not make publish validation lenient; tag/manifests mismatch should fail closed.
- Do not install extra runtimes by default unless a shared workflow actually needs them.
