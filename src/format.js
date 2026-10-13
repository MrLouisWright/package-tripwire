import { RULES } from './config.js';

const LV = { error: 3, warn: 2, note: 1, none: 99 };
export const meetsFailOn = (level, failOn) => (LV[level] || 0) >= (LV[failOn] ?? 3);

export function exitCode(result, failOn = 'error') {
  if (failOn === 'none') return 0;
  return result.findings.some((f) => meetsFailOn(f.level, failOn)) ? 1 : 0;
}

export function formatText(result, { color = false, failOn = 'error' } = {}) {
  const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const tag = { error: c('31;1', 'ERROR'), warn: c('33;1', 'WARN '), note: c('36', 'NOTE ') };
  const { findings, stats, suppressed } = result;
  const lines = [c('1', 'package-tripwire') + ` — ${stats.base} → ${stats.head} packages (${stats.added} added, ${stats.updated} updated, ${stats.removed} removed)`];
  if (!findings.length) lines.push(c('32', '✔ No suspicious dependency changes.'));
  for (const f of findings) lines.push(`  ${tag[f.level]} [${f.rule}] ${f.message}`);
  const n = (l) => findings.filter((f) => f.level === l).length;
  lines.push('', `${n('error')} error(s), ${n('warn')} warning(s), ${n('note')} note(s)${suppressed.length ? `, ${suppressed.length} allowlisted` : ''}.`);
  const fail = findings.some((f) => meetsFailOn(f.level, failOn));
  lines.push(fail ? c('31;1', `✖ Failing (fail-on: ${failOn}).`) : c('32', `Passing (fail-on: ${failOn}).`));
  return lines.join('\n') + '\n';
}

export function formatJson(result, meta = {}) {
  return JSON.stringify({ tool: 'package-tripwire', ...meta, ...result }, null, 2) + '\n';
}

export function formatMarkdown(result) {
  const { findings, stats } = result;
  const icon = { error: '🔴', warn: '🟡', note: '🔵' };
  const out = ['## package-tripwire', '', `${stats.base} → ${stats.head} packages · ${stats.added} added · ${stats.updated} updated · ${stats.removed} removed`, ''];
  if (!findings.length) out.push('✅ No suspicious dependency changes.');
  else {
    out.push('| | Rule | Package | Detail |', '|---|---|---|---|');
    for (const f of findings) out.push(`| ${icon[f.level]} | \`${f.rule}\` | \`${f.package}@${f.version}\` | ${f.message.replace(/\|/g, '\\|')} |`);
  }
  return out.join('\n') + '\n';
}

export function formatSarif(result, { version = '0.0.0' } = {}) {
  const map = { error: 'error', warn: 'warning', note: 'note' };
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'package-tripwire', version, informationUri: 'https://github.com/MrLouisWright/package-tripwire',
        rules: Object.entries(RULES).map(([id, r]) => ({ id, name: id, shortDescription: { text: r.title }, defaultConfiguration: { level: map[r.level] } })) } },
      results: result.findings.map((f) => ({
        ruleId: f.rule, level: map[f.level], message: { text: f.message },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.lockfile }, region: { startLine: 1 } } }],
        partialFingerprints: { packageTripwire: `${f.rule}:${f.package}@${f.version}` },
        properties: { package: f.package, version: f.version, previousVersion: f.previousVersion },
      })),
    }],
  }, null, 2) + '\n';
}
