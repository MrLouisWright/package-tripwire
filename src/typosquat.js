// Typosquat heuristics: edit distance, separator/scope confusion, char swaps, homoglyph-ish substitutions.
export const POPULAR = `react react-dom vue angular svelte next nuxt express koa fastify hapi lodash underscore ramda axios
node-fetch request got superagent moment dayjs date-fns luxon chalk colors kleur commander yargs minimist debug
dotenv uuid nanoid classnames prop-types redux react-redux mobx zustand rxjs typescript tslib ts-node webpack
rollup vite esbuild parcel babel-core @babel/core @babel/preset-env eslint prettier jest mocha chai sinon vitest
jquery bootstrap tailwindcss postcss autoprefixer sass less socket.io ws body-parser cookie-parser cors helmet
morgan mongoose mongodb mysql mysql2 pg sequelize prisma knex redis ioredis jsonwebtoken bcrypt bcryptjs
passport multer sharp jimp cheerio puppeteer playwright glob rimraf mkdirp fs-extra chokidar nodemon pm2
concurrently cross-env semver yaml js-yaml ajv joi zod qs inquirer ora boxen execa shelljs async bluebird
core-js regenerator-runtime graphql apollo-server electron react-native expo styled-components emotion
immer immutable uglify-js terser coffee-script cross-spawn event-stream eslint-scope ua-parser-js coa rc
node-ipc colors faker discord.js openai aws-sdk @aws-sdk/client-s3 firebase stripe twilio nodemailer
handlebars ejs pug mustache marked markdown-it highlight.js d3 three chart.js leaflet socket.io-client
preact inferno solid-js react-is redux-thunk yarn npm pnpm nx lerna turbo web3 ethers bignumber.js crypto-js node-sass serve http-server live-server json-server`.split(/\s+/).filter(Boolean);

export function levenshtein(a, b) {
  // Damerau (optimal string alignment) distance.
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return 99;
  const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 1; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) {
    const c = a[i - 1] === b[j - 1] ? 0 : 1;
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c);
    if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
  }
  return d[m][n];
}

const norm = (s) => s.toLowerCase().replace(/^@[^/]+\//, '').replace(/[-_.]/g, '').replace(/js$/, '')
  .replace(/0/g, 'o').replace(/1/g, 'l').replace(/rn/g, 'm').replace(/vv/g, 'w');

/** Returns { target, reason } if `name` looks like a typosquat of a popular package, else null. */
export function typosquatOf(name, popular = POPULAR) {
  if (popular.includes(name) || name.startsWith('@types/')) return null;
  const bare = name.replace(/^@[^/]+\//, '');
  for (const p of popular) {
    const pb = p.replace(/^@[^/]+\//, '');
    if (name.startsWith('@') && !name.startsWith('@types/') && bare === pb && !p.startsWith('@')) return { target: p, reason: `scoped copy of "${p}"` };
    if (bare === pb) continue;
    if (norm(bare) === norm(pb)) return { target: p, reason: `same as "${p}" after separator/homoglyph normalisation` };
    if (pb.length >= 5) {
      const dist = levenshtein(bare, pb);
      if (dist === 1 || (dist === 2 && pb.length >= 9)) return { target: p, reason: `edit distance ${dist} from "${p}"` };
    }
    if (pb.length >= 4 && (bare === `${pb}-js` || bare === `${pb}js` || bare === `node-${pb}` || bare === `${pb}-node` || bare === `${pb}2` || bare === `${pb}-dev`))
      return { target: p, reason: `affixed variant of "${p}"` };
  }
  return null;
}
