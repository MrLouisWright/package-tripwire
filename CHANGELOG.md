# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-13

### Added
- Lockfile diffing for `package-lock.json`/`npm-shrinkwrap.json` (v1–v3), `pnpm-lock.yaml` (v5–v9) and `yarn.lock` (v1 + Berry) against a git ref (`--base`) or a saved snapshot (`--baseline`, `--save-baseline`).
- Rules: `install-script`, `integrity-change`, `typosquat`, `publisher-change`, `recent-publish` (`--min-age`), `non-registry-source`, `maintainer-change`, `deprecated`, `new-dependency`, `unknown-package`, `registry-error`.
- npm registry metadata lookups for added/changed packages only; `--offline` lockfile-only mode.
- Config file with per-rule levels and an allowlist (globs, versions, rule scoping, expiry).
- Text, JSON, SARIF 2.1.0 and Markdown output; exit codes 0/1/2.
- Composite GitHub Action with job summary and SARIF support.
- Programmatic API with TypeScript types. Zero dependencies.
