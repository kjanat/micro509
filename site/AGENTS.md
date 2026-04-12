# `site/` - Docs Site Map

VitePress site for guides, reference pages, and generated API docs.

## OVERVIEW

`site/` is the published documentation surface. Authored content lives beside generated API markdown, with `.vitepress/config.ts` stitching package metadata, TypeDoc output, and browser import-map examples together.

## STRUCTURE

```tree
site/
├── .vitepress/config.ts  # nav, sidebar, plugins, import-map injection
├── guide/                # authored workflow guides
├── reference/            # standards, algorithms, runtime support
├── api/                  # generated TypeDoc markdown + sidebar JSON
├── assets/               # icons and static assets
└── index.md              # home page
```

## WHERE TO LOOK

| Task                  | Location                               | Notes                                       |
| --------------------- | -------------------------------------- | ------------------------------------------- |
| Site config           | `.vitepress/config.ts`                 | VitePress theme config, plugins, edit links |
| Landing page          | `index.md`                             | home hero and feature claims                |
| User guides           | `guide/*.md`                           | workflow-focused docs by domain             |
| Reference pages       | `reference/*.md`                       | scope, algorithms, runtime support          |
| API docs input/output | `api/typedoc-sidebar.json`, `api/*.md` | generated from `bun site:api`               |

## CONVENTIONS

- Edit authored docs in `guide/`, `reference/`, `index.md`, and `.vitepress/config.ts`; regenerate `api/` instead of hand-editing drift-prone output.
- Keep claims aligned with `docs/PKIX-SCOPE.md` and test-backed behavior.
- The import-map setup is pre-release-specific; update it with package publishing strategy changes.
- Preserve sidebar/nav grouping by user task: guide, API, reference.

## ANTI-PATTERNS

- Do not hand-tune generated `site/api/*.md` content unless the generation input changes.
- Do not add support claims here that exceed library scope docs or harness coverage.
- Do not couple site config to a local-only branch or filesystem assumption beyond the existing git-branch lookup.
