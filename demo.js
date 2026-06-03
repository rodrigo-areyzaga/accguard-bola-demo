#!/usr/bin/env node
'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// accguard-bola-demo
//
// git clone https://github.com/rodrigo-areyzaga/accguard-bola-demo
// cd accguard-bola-demo
// npm install
// npm run demo
// ─────────────────────────────────────────────────────────────────────────────

const http = require('http');

const BANK_PORT  = 3200;
const PROXY_PORT = 8877;
const TARGET     = `http://127.0.0.1:${BANK_PORT}`;

const TOKEN_ALICE = 'tok-alice';
const TOKEN_BOB   = 'tok-bob';

// ── Require accguard internals ────────────────────────────────────────────────

let SessionStore, ProxyCore, runReplay, printFindings, saveReport, verifyTarget, verifyScope;

try {
  ({ SessionStore }              = require('accguard/src/session-store'));
  ({ ProxyCore }                 = require('accguard/src/proxy'));
  ({ runReplay }                 = require('accguard/src/replay'));
  ({ printFindings, saveReport } = require('accguard/src/reporter'));
  ({ verifyTarget, verifyScope } = require('accguard/src/safety'));
} catch {
  console.error('\n  accguard not found. Run: npm install\n');
  process.exit(1);
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

function request(port, path, token, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path,
      method,
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: 'Bearer ' + token } : {}),
        ...(payload ? { 'content-length': Buffer.byteLength(payload) } : {}),
      },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        let data;
        try { data = JSON.parse(Buffer.concat(chunks).toString()); }
        catch { data = null; }
        resolve({ status: res.statusCode, data, bodyLength: Buffer.concat(chunks).length });
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Formatting ────────────────────────────────────────────────────────────────

const RESET  = '\x1b[0m';
const DIM    = '\x1b[2m';
const BOLD   = '\x1b[1m';
const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN   = '\x1b[36m';

function line(char = '─', len = 60) { return char.repeat(len); }
function ok(msg)   { return `  ${GREEN}✓${RESET}  ${msg}`; }
function fail(msg) { return `  ${RED}✗${RESET}  ${msg}`; }
function step(n, msg) { return `${DIM}[${n}]${RESET} ${msg}`; }

// ── Main ──────────────────────────────────────────────────────────────────────

async function run() {
  console.log(`\n${line()}`);
  console.log(`${BOLD}  accguard × BOLA demo${RESET}`);
  console.log(`  Alice has acct-1. Bob has acct-2.`);
  console.log(`  Bob should not be able to read Alice's account.`);
  console.log(`  The API forgets to check. accguard catches it.`);
  console.log(line());

  // ── 1. Start the vulnerable bank API ───────────────────────────────────────

  console.log(`\n${step(1, 'Starting vulnerable bank API...')}`);
  const bank = require('./server');
  await new Promise((resolve, reject) => {
    bank.once('error', reject);
    bank.listen(BANK_PORT, '127.0.0.1', resolve);
  });
  console.log(ok(`Bank API running   → http://127.0.0.1:${BANK_PORT}`));
  console.log(`${DIM}       Endpoints: POST /login  GET /me  GET /accounts/:id  GET /accounts/:id/transactions${RESET}`);

  // ── 2. Start accguard proxy ─────────────────────────────────────────────────

  console.log(`\n${step(2, 'Starting accguard proxy...')}`);
  await verifyTarget(TARGET);
  verifyScope(['/accounts', '/me']);

  const store = new SessionStore();
  const proxy = new ProxyCore({
    target:  TARGET,
    scope:   ['/accounts', '/me'],
    exclude: ['/login'],
    store,
    logger:  { log: () => {}, error: console.error },
  });
  await proxy.listen(PROXY_PORT);
  console.log(ok(`accguard proxy running → http://127.0.0.1:${PROXY_PORT} → ${TARGET}`));

  // ── 3. Alice logs in and uses her account ───────────────────────────────────

  console.log(`\n${step(3, 'Alice logs in and accesses her account...')}`);
  console.log(`${DIM}       (traffic flows through the accguard proxy)${RESET}\n`);

  // Login goes direct — not through proxy (auth endpoint excluded)
  const loginRes = await request(BANK_PORT, '/login', null, 'POST', {
    email: 'alice@example.com',
    password: 'password123',
  });

  const calls = [
    { path: '/me',                          label: 'Alice reads her own profile' },
    { path: '/accounts',                    label: 'Alice lists her accounts' },
    { path: '/accounts/acct-1',             label: 'Alice reads acct-1 ($84,320.00)' },
    { path: '/accounts/acct-1/transactions', label: 'Alice reads acct-1 transactions' },
  ];

  for (const { path, label } of calls) {
    const r = await request(PROXY_PORT, path, TOKEN_ALICE);
    console.log(ok(`${label.padEnd(42)} ${DIM}${r.status}${RESET}`));
  }

  console.log(`\n${DIM}  ${store.size()} requests recorded · ${store.replayable().length} replay candidates${RESET}`);

  // ── 4. Close the proxy and replay as Bob ────────────────────────────────────

  console.log(`\n${step(4, 'Replaying Alice\'s requests as Bob...')}`);
  console.log(`${DIM}       Bob never visited /accounts/acct-1. accguard sends the request for him.${RESET}\n`);
  await proxy.close();

  const findings = await runReplay({
    store,
    targetUrl:   TARGET,
    secondToken: TOKEN_BOB,
    logger:      { log: () => {} },
  });

  // ── 5. Print results ────────────────────────────────────────────────────────

  console.log(`\n${line()}`);

  if (findings.length === 0) {
    console.log(`\n  ${GREEN}No broken access control detected.${RESET}\n`);
  } else {
    console.log(`\n  ${RED}${BOLD}BROKEN ACCESS CONTROL DETECTED${RESET}\n`);

    findings.forEach((f, i) => {
      const ids = f.resourceIds.map(r => r.value).join(', ');
      console.log(`  ${RED}[!]${RESET} ${BOLD}Finding ${i + 1}${RESET} — ${f.method} ${CYAN}${f.path}${RESET}`);
      console.log(`      Resource : ${ids}`);
      console.log(`      Alice got: ${f.originalStatus} (${f.originalSize} bytes)`);
      console.log(`      Bob got  : ${f.replayStatus}  (${f.replaySize} bytes)`);
      console.log(`      Match    : ${YELLOW}response bodies are identical${RESET}`);
      console.log(`      Bob read : balance, SSN last 4, routing number, email`);
      console.log(`\n      Reproduce:`);
      console.log(`      ${DIM}${f.curl}${RESET}\n`);
    });

    saveReport(findings, store, 'accguard-demo-report.json');

    console.log(line());
    console.log(`\n  ${findings.length} authorization regression${findings.length !== 1 ? 's' : ''} confirmed.`);
    console.log(`  Bob accessed Alice's financial data without authorization.`);
    console.log(`  Full report → ${CYAN}accguard-demo-report.json${RESET}`);
    console.log(`\n  Fix: add ownership check in ${CYAN}server.js${RESET} lines 90 and 103:`);
    console.log(`  ${DIM}if (account.owner !== user.id) return json(res, 403, { error: 'forbidden' });${RESET}\n`);
  }

  bank.close();
  process.exit(findings.length > 0 ? 0 : 1);
}

run().catch(err => {
  console.error(`\n  ${RED}Error:${RESET} ${err.message}`);
  console.error(`  Make sure nothing is already running on ports ${BANK_PORT} or ${PROXY_PORT}.\n`);
  process.exit(1);
});
