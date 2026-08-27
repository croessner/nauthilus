---
name: nauthilus-config-docs
description: Use for Nauthilus configuration loading, config schema and defaults, Viper-backed config formats, config dump behavior, vim syntax generation, template validation, prompt guideline sync, documentation under README/IDP/server docs, config converters, and generated documentation or syntax artifacts.
---

# Nauthilus Config Docs

## Expertise Lens

- Work as a configuration-surface and operator-documentation maintainer.
- Optimize for stable operator semantics, generated artifact freshness, readable docs, prompt-policy sync, and config examples that match runtime behavior.
- Treat stale syntax files, stale generated docs, mismatched prompt policy, config drift, and undocumented operator behavior as closeout blockers.

## Sources To Read

- `AGENTS.md`
- `POLICY.md`
- `.junie/guidelines.md`
- `server/config/`
- `server/docs/`
- `scripts/generate-vim-syntax.py`
- `scripts/validate-templates.go`
- relevant README or contrib docs

## Config Rules

- Use config getters instead of raw Viper state where possible.
- Keep `-config` and `-config-format` behavior stable.
- Keep YAML as the common operator format while preserving supported Viper formats.
- Keep config dumps, schema indexes, vim syntax, templates, and docs aligned with runtime structs.
- Keep comments and technical docs in English.
- Keep `AGENTS.md` synchronized with `.junie/guidelines.md` through Makefile checks.

## Implementation Workflow

1. Identify the runtime config owner and generated/documented surfaces.
2. Add tests for config parsing, defaults, dump output, validation, or conversion behavior.
3. Regenerate syntax or bindings through Makefile/script targets.
4. Update docs only where operator behavior actually changed.
5. Avoid rollout-stage wording in docs, filenames, commits, and tags.

## Validation

- Run `make sync-prompts-check`.
- Run `make policy-check`.
- Run `make generate-vim-syntax-check` when config syntax surfaces move.
- Run `make validate-templates` when templates move.
- Run focused config tests with `GOEXPERIMENT=runtimesecret`.
- Run `GOEXPERIMENT=runtimesecret make test` and `git diff --check`.
- Run `make guardrails` before commit or pull request.
