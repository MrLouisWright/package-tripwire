export type Level = 'error' | 'warn' | 'note';
export type RuleId = 'install-script' | 'integrity-change' | 'typosquat' | 'publisher-change' | 'recent-publish' | 'non-registry-source' | 'maintainer-change' | 'deprecated' | 'new-dependency' | 'unknown-package' | 'registry-error';
export interface Entry { name: string; version: string; resolved: string | null; integrity: string | null; hasInstallScript: boolean; dev: boolean; source: 'registry' | 'git' | 'url' | 'file'; }
export type LockMap = Map<string, Entry>;
export interface Finding { rule: RuleId; level: Level; title: string; package: string; version: string; previousVersion?: string; message: string; details: Record<string, unknown>; lockfile: string; }
export interface AllowEntry { package: string; version?: string; rules?: RuleId[]; reason?: string; expires?: string; }
export interface Config { minAge?: string | number; registry?: string; failOn?: Level | 'none'; rules?: Partial<Record<RuleId, Level | 'off'>>; allow?: (string | AllowEntry)[]; popular?: string[]; includeDev?: boolean; concurrency?: number; cacheDir?: string; }
export interface Result { findings: Finding[]; suppressed: Finding[]; stats: { base: number; head: number; added: number; updated: number; removed: number }; }
export interface Registry { packument(name: string): Promise<any | null>; }
export function analyze(base: LockMap, head: LockMap, opts?: { registry?: Registry | null; config?: Config; now?: number; lockfile?: string }): Promise<Result>;
export function parseLockfile(text: string, type: 'npm' | 'pnpm' | 'yarn' | 'baseline'): LockMap;
export function parseAny(text: string, hintFile?: string): LockMap;
export function detectLockfile(dir?: string): string | null;
export function toBaseline(map: LockMap, meta?: Record<string, unknown>): object;
export function classifySource(resolved?: string | null, version?: string): Entry['source'];
export function createRegistry(opts?: { registry?: string; token?: string; fetchImpl?: typeof fetch; cacheDir?: string; timeoutMs?: number; retries?: number }): Registry;
export function loadConfig(dir?: string, explicit?: string): Config;
export function parseDuration(v: string | number): number;
export function isAllowed(allow: (string | AllowEntry)[], finding: Finding, now?: number): boolean;
export const RULES: Record<RuleId, { level: Level; title: string }>;
export function typosquatOf(name: string, popular?: string[]): { target: string; reason: string } | null;
export function levenshtein(a: string, b: string): number;
export const POPULAR: string[];
export function formatText(r: Result, o?: { color?: boolean; failOn?: string }): string;
export function formatJson(r: Result, meta?: object): string;
export function formatSarif(r: Result, o?: { version?: string }): string;
export function formatMarkdown(r: Result): string;
export function exitCode(r: Result, failOn?: string): 0 | 1;
export function readAtRef(ref: string, file: string, cwd?: string): string | null;
export function run(opts?: { cwd?: string; lockfile?: string; base?: string; baseline?: string; config?: Config; configPath?: string; offline?: boolean; registry?: Registry; now?: number }): Promise<Result & { base: string; lockfile: string; failOn: string; head: LockMap }>;
export function saveBaseline(file: string, map: LockMap, meta?: object): void;
