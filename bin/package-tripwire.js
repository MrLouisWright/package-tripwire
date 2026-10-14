#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { run, saveBaseline, formatText, formatJson, formatSarif, formatMarkdown, exitCode, parseAny, detectLockfile, loadConfig, allowScriptsPolicy } from '../dist/index.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const HELP = `package-tripwire ${pkg.version} — fail CI when dependency changes look suspicious

Usage: package-tripwire [options]

Compare against:
  --base <ref>            Git ref to compare the lockfile against (default: HEAD)
  --baseline <file>       Compare against a saved baseline snapshot (or any lockfile)
  --save-baseline <file>  Write a baseline snapshot of the current lockfile and exit 0
  --lockfile <path>       Lockfile to check (default: auto-detect in cwd)

Rules:
  --min-age <dur>         Minimum age for newly resolved versions, e.g. 72h, 3d, 0 (default: 72h)
  --offline               Skip registry lookups (lockfile-only checks)
  --registry <url>        npm registry URL (default: https://registry.npmjs.org)
  --no-dev                Ignore devDependencies
  --no-signatures         Skip registry tarball signature verification
  --require-provenance    Fail when resolved versions lack provenance attestations
  --enforce-allow-scripts Require every install-script package to appear in allowScripts
  --write-allow-scripts <file>  Write allowScripts policy JSON from config and exit 0
  --config <file>         Config file (default: .package-tripwire.json or package.json "package-tripwire")
  --fail-on <level>       error | warn | note | none (default: error)

Output:
  --json [file]           JSON report to file, or to stdout if no file / "-"
  --sarif <file>          SARIF 2.1.0 report
  --markdown <file>       Markdown report (for PR comments / job summary)
  --quiet                 Only print the summary on success
  --no-color              Disable colours
  -h, --help | -v, --version

Exit codes: 0 pass, 1 findings at or above --fail-on, 2 usage or runtime error.
`;

function parseArgs(argv) {
  const o = { color: process.stdout.isTTY && !process.env.NO_COLOR || !!process.env.FORCE_COLOR, cfg: {} };
  const val = (i) => { const v = argv[i + 1]; if (v === undefined || (v.startsWith('--') && v !== '-')) throw new Error(`${argv[i]} needs a value`); return v; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': o.help = true; break;
      case '-v': case '--version': o.version = true; break;
      case '--base': o.base = val(i); i++; break;
      case '--baseline': o.baseline = val(i); i++; break;
      case '--save-baseline': o.saveBaseline = val(i); i++; break;
      case '--lockfile': o.lockfile = val(i); i++; break;
      case '--min-age': o.cfg.minAge = val(i); i++; break;
      case '--registry': o.cfg.registry = val(i); i++; break;
      case '--offline': o.offline = true; break;
      case '--no-dev': o.cfg.includeDev = false; break;
      case '--no-signatures': o.cfg.verifySignatures = false; break;
      case '--require-provenance': o.cfg.requireProvenance = true; break;
      case '--enforce-allow-scripts': o.cfg.enforceAllowScripts = true; break;
      case '--write-allow-scripts': o.writeAllowScripts = val(i); i++; break;
      case '--config': o.config = val(i); i++; break;
      case '--fail-on': o.failOn = val(i); i++; if (!['error', 'warn', 'note', 'none'].includes(o.failOn)) throw new Error(`Invalid --fail-on ${o.failOn}`); break;
      case '--json': { const n = argv[i + 1]; if (n && !n.startsWith('--')) { o.json = n; i++; } else o.json = '-'; break; }
      case '--sarif': o.sarif = val(i); i++; break;
      case '--markdown': o.markdown = val(i); i++; break;
      case '--quiet': o.quiet = true; break;
      case '--no-color': o.color = false; break;
      default: throw new Error(`Unknown option ${a}`);
    }
  }
  return o;
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`package-tripwire: ${e.message}\n\n${HELP}`); return 2; }
  if (o.help) { process.stdout.write(HELP); return 0; }
  if (o.version) { process.stdout.write(pkg.version + '\n'); return 0; }
  if (o.saveBaseline) {
    const lf = o.lockfile || detectLockfile('.');
    if (!lf) throw new Error('No lockfile found');
    const map = parseAny(fs.readFileSync(lf, 'utf8'), lf);
    saveBaseline(o.saveBaseline, map, { lockfile: lf });
    process.stdout.write(`Saved baseline of ${map.size} packages from ${lf} to ${o.saveBaseline}\n`);
    return 0;
  }
  if (o.writeAllowScripts) {
    const cfg = { ...loadConfig('.', o.config), ...o.cfg };
    if (!cfg.allowScripts?.length) throw new Error('--write-allow-scripts requires allowScripts in config');
    fs.mkdirSync(path.dirname(path.resolve(o.writeAllowScripts)), { recursive: true });
    fs.writeFileSync(o.writeAllowScripts, JSON.stringify(allowScriptsPolicy(cfg.allowScripts), null, 2) + '\n');
    process.stdout.write(`Wrote allowScripts policy (${cfg.allowScripts.length} entries) to ${o.writeAllowScripts}\n`);
    return 0;
  }
  const res = await run({ lockfile: o.lockfile, base: o.base, baseline: o.baseline, configPath: o.config, offline: o.offline, config: o.cfg });
  const failOn = o.failOn || res.failOn || 'error';
  const report = { findings: res.findings, suppressed: res.suppressed, stats: res.stats };
  const meta = { version: pkg.version, base: res.base, lockfile: res.lockfile, failOn, exitCode: exitCode(report, failOn) };
  if (o.sarif) fs.writeFileSync(o.sarif, formatSarif(report, { version: pkg.version }));
  if (o.markdown) fs.writeFileSync(o.markdown, formatMarkdown(report));
  if (o.json && o.json !== '-') fs.writeFileSync(o.json, formatJson(report, meta));
  if (o.json === '-') process.stdout.write(formatJson(report, meta));
  else if (!(o.quiet && !report.findings.length)) process.stdout.write(formatText(report, { color: o.color, failOn }));
  else process.stdout.write('package-tripwire: no suspicious dependency changes.\n');
  return meta.exitCode;
}

main().then((c) => { process.exitCode = c; }, (e) => { process.stderr.write(`package-tripwire: ${e.message}\n`); process.exitCode = 2; });
