# package-tripwire

> Fail CI when dependency changes look suspicious.

`package-tripwire` diffs your lockfile against a git ref (e.g. the PR base branch) or a saved baseline, looks up every new or changed package in the npm registry, and fails the build when something looks like a supply-chain attack. It works as a CLI, a library and a GitHub Action, and has zero dependencies.

Supported lockfiles: `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `pnpm-lock.yaml` (v5–v9), `yarn.lock` (classic v1 and Berry).

## What it flags

| Rule | Default | What it catches |
|---|---|---|
| `install-script` | error | New `preinstall` / `install` / `postinstall` scripts (or implicit `node-gyp`), or scripts that changed since the previous version |
| `integrity-change` | error | Same `name@version` with a different integrity hash or tarball source, or a lockfile hash that doesn't match the registry |
| `typosquat` | error | New names close to popular packages (edit distance, `-`/`_`/`.` confusion, homoglyphs like `rn`→`m`, `0`→`o`, scoped copies, `-js`/`node-` affixes) |
| `publisher-change` | error | The new version was published by a different npm user than the previous one |
| `recent-publish` | error | The resolved version was published less than `--min-age` ago (default 72h) |
| `non-registry-source` | warn | Git, GitHub, HTTP tarball or `file:` dependencies |
| `maintainer-change` | warn | The maintainer list changed between versions |
| `deprecated` | warn | The resolved version is deprecated |
| `unknown-package` / `registry-error` | warn | Not in the registry, or the lookup failed |
| `new-dependency` | note | Every newly added package (direct or transitive) |

Only packages that were added or changed are looked up, so runs stay fast. `--offline` skips the registry and keeps the lockfile-only checks (integrity, typosquat, git/URL, `hasInstallScript`).

## Install

```bash
npm install --save-dev package-tripwire
# or run it once
npx package-tripwire --base origin/main
```

Requires Node.js 18 or later.

## CLI

```bash
package-tripwire                          # compare working-tree lockfile against HEAD
package-tripwire --base origin/main       # compare against a branch / tag / commit
package-tripwire --save-baseline .tripwire/baseline.json   # snapshot the current lockfile
package-tripwire --baseline .tripwire/baseline.json         # compare against the snapshot
package-tripwire --min-age 7d --fail-on warn --sarif tripwire.sarif --json tripwire.json
```

| Option | Description |
|---|---|
| `--base <ref>` | Git ref to compare against (default `HEAD`) |
| `--baseline <file>` | Compare against a saved baseline (or any lockfile) instead of git |
| `--save-baseline <file>` | Write a baseline snapshot of the current lockfile and exit |
| `--lockfile <path>` | Lockfile to check (auto-detected by default) |
| `--min-age <dur>` | Minimum publish age: `90m`, `72h`, `3d`, `1w`, `0` |
| `--offline` | No registry lookups |
| `--registry <url>` | Registry URL (default `https://registry.npmjs.org`) |
| `--no-dev` | Ignore dev dependencies |
| `--config <file>` | Config file path |
| `--fail-on <level>` | `error` (default), `warn`, `note` or `none` |
| `--json [file]` | JSON report to a file, or stdout |
| `--sarif <file>` | SARIF 2.1.0 report for GitHub code scanning |
| `--markdown <file>` | Markdown report for PR comments and job summaries |
| `--quiet`, `--no-color` | Output tweaks |

**Exit codes:** `0` passed · `1` findings at or above `--fail-on` · `2` usage or runtime error.

### Sample output

```text
package-tripwire — 2 → 6 packages (4 added, 1 updated, 0 removed)
  ERROR [install-script] esbuild@0.24.0 runs install scripts → postinstall: node install.js
  ERROR [typosquat] expresss looks like a typosquat: edit distance 1 from "express"
  WARN  [maintainer-change] debug@4.4.3 maintainers changed -thebigredgeek,-tjholowaychuk
  WARN  [unknown-package] expresss@0.0.1 not found in registry
  WARN  [non-registry-source] my-fork@1.0.0 is installed from a git source: git+ssh://git@github.com/someone/my-fork.git#3f2c1a9
  WARN  [deprecated] request@2.88.2 is deprecated: request has been deprecated, see https://github.com/request/request/issues/3142
  NOTE  [new-dependency] esbuild@0.24.0 added
  ...

2 error(s), 4 warning(s), 4 note(s).
✖ Failing (fail-on: error).
```

## Configuration and allowlist

Put the config in `.package-tripwire.json` (or `.package-tripwirerc.json`, or a `"package-tripwire"` key in `package.json`):

```json
{
  "minAge": "72h",
  "failOn": "error",
  "includeDev": true,
  "registry": "https://registry.npmjs.org",
  "rules": { "new-dependency": "off", "deprecated": "error" },
  "popular": ["my-company-ui"],
  "allow": [
    "@my-company/*",
    "esbuild@0.24.0",
    { "package": "sharp", "rules": ["install-script"], "reason": "prebuilt binaries" },
    { "package": "left-pad", "version": "1.3.0", "rules": ["recent-publish"], "expires": "2026-12-31" }
  ]
}
```

- `rules` sets each rule's level to `error`, `warn`, `note` or `off`.
- `allow` entries can be `name`, `name@version` or a glob like `@scope/*`, or an object with `package`, `version`, `rules`, `reason` and `expires`. An expired entry stops matching, so exceptions don't stay forever.
- `popular` adds your own names to the list used for typosquat checks.

Allowlisted findings are counted in the summary and listed under `suppressed` in the JSON.

## GitHub Action

```yaml
name: Dependency tripwire
on: pull_request
permissions:
  contents: read
  security-events: write   # only needed for SARIF upload
jobs:
  tripwire:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: MrLouisWright/package-tripwire@v1
        with:
          min-age: 72h
          fail-on: error
          sarif: tripwire.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: tripwire.sarif }
```

On a pull request it compares against `origin/<base branch>` by default. Otherwise it uses `HEAD~1`.

| Input | Default | |
|---|---|---|
| `base` | PR base / `HEAD~1` | Git ref to compare against |
| `baseline` | | Baseline file, used instead of a git ref |
| `lockfile` | auto | Lockfile path |
| `min-age` | `72h` | Minimum publish age |
| `fail-on` | `error` | `error` / `warn` / `note` / `none` |
| `config` | | Config file path |
| `offline` | `false` | Skip registry lookups |
| `sarif`, `json` | | Report paths |
| `job-summary` | `true` | Write the Markdown report to the job summary |
| `args` | | Extra CLI arguments |

## Library

```js
import { run, analyze, parseAny, createRegistry, formatSarif } from 'package-tripwire';

const result = await run({ base: 'origin/main', config: { minAge: '3d' } });
console.log(result.findings);
```

TypeScript types are included.

## Limitations

- Typosquat detection is a heuristic built on a list of popular packages. Expect the occasional false positive, and allowlist it.
- For git, URL and `file:` dependencies there is no registry metadata, so only the source is flagged.
- Yarn Berry stores its own checksum format, so the check that compares lockfile integrity with the registry is skipped for Berry. The same-version change check still runs.

## License

MIT © Louis Wright
