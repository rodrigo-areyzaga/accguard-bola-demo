'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// accguard-bola-demo — deliberately vulnerable banking API
//
// DO NOT deploy this server anywhere. It is intentionally broken.
// It exists to demonstrate BOLA (Broken Object Level Authorization),
// also known as IDOR — OWASP API Security Top 10 #1.
//
// The bug: GET /accounts/:id checks "is the user logged in?"
//          but NOT "does this account belong to this user?"
//
// Alice cannot see this bug in the UI. Bob cannot see it either.
// accguard will.
// ─────────────────────────────────────────────────────────────────────────────

const http = require('http');
const PORT = parseInt(process.env.BANK_PORT || '3200', 10);

// ── Seed data ─────────────────────────────────────────────────────────────────

const USERS = {
  'tok-alice': {
    id:    'user-alice',
    name:  'Alice Monroe',
    email: 'alice@example.com',
  },
  'tok-bob': {
    id:    'user-bob',
    name:  'Bob Garland',
    email: 'bob@example.com',
  },
};

// The account data that Bob should never see but will.
const ACCOUNTS = {
  'acct-1': {
    id:         'acct-1',
    owner:      'user-alice',
    type:       'Checking',
    balance:    84320.00,
    email:      'alice@example.com',
    ssn_last4:  '4821',
    routing:    '021000021',
    number:     '****9104',
  },
  'acct-2': {
    id:         'acct-2',
    owner:      'user-bob',
    type:       'Checking',
    balance:    3105.22,
    email:      'bob@example.com',
    ssn_last4:  '7732',
    routing:    '021000021',
    number:     '****5523',
  },
};

const TRANSACTIONS = {
  'acct-1': [
    { id: 'txn-001', date: '2026-05-28', description: 'Payroll deposit',     amount: +6800.00 },
    { id: 'txn-002', date: '2026-05-27', description: 'Mortgage payment',    amount: -2100.00 },
    { id: 'txn-003', date: '2026-05-24', description: 'Wire to savings',     amount: -5000.00 },
    { id: 'txn-004', date: '2026-05-20', description: 'Amazon',              amount:  -149.99 },
  ],
  'acct-2': [
    { id: 'txn-101', date: '2026-05-29', description: 'Freelance payment',   amount: +1200.00 },
    { id: 'txn-102', date: '2026-05-25', description: 'Rent',                amount: -1500.00 },
  ],
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function getUser(req) {
  const auth = (req.headers['authorization'] || '').replace(/^bearer\s+/i, '').trim();
  return USERS[auth] || null;
}

function json(res, status, data) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(status, {
    'content-type':   'application/json',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise(resolve => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); }
      catch { resolve({}); }
    });
  });
}

// ── Router ────────────────────────────────────────────────────────────────────

async function router(req, res) {
  const url    = new URL(req.url, 'http://localhost');
  const p      = url.pathname;
  const method = req.method.toUpperCase();
  const user   = getUser(req);

  // POST /login — public
  if (method === 'POST' && p === '/login') {
    const body  = await readBody(req);
    const found = Object.values(USERS).find(u => u.email === body.email);
    if (!found) return json(res, 401, { error: 'invalid credentials' });
    const token = Object.keys(USERS).find(k => USERS[k].id === found.id);
    return json(res, 200, { token, user: found });
  }

  // All routes below require auth
  if (!user) return json(res, 401, { error: 'unauthorized' });

  // GET /me — correct: returns only your own profile
  if (method === 'GET' && p === '/me') {
    return json(res, 200, user);
  }

  // GET /accounts — correct: returns only your own accounts
  if (method === 'GET' && p === '/accounts') {
    const mine = Object.values(ACCOUNTS).filter(a => a.owner === user.id);
    return json(res, 200, mine);
  }

  // GET /accounts/:id — !! BUG !!
  // Checks: is the user logged in? ✓
  // Checks: does this account belong to this user? ✗  ← the BOLA
  const acctMatch = p.match(/^\/accounts\/([^/]+)$/);
  if (method === 'GET' && acctMatch) {
    const account = ACCOUNTS[acctMatch[1]];
    if (!account) return json(res, 404, { error: 'account not found' });
    // Missing: if (account.owner !== user.id) return json(res, 403, ...)
    return json(res, 200, account);
  }

  // GET /accounts/:id/transactions — !! BUG !!
  // Same missing ownership check.
  const txnMatch = p.match(/^\/accounts\/([^/]+)\/transactions$/);
  if (method === 'GET' && txnMatch) {
    const id   = txnMatch[1];
    const acct = ACCOUNTS[id];
    if (!acct) return json(res, 404, { error: 'account not found' });
    // Missing: if (acct.owner !== user.id) return json(res, 403, ...)
    return json(res, 200, TRANSACTIONS[id] || []);
  }

  return json(res, 404, { error: 'not found' });
}

const server = http.createServer((req, res) => {
  router(req, res).catch(err => {
    res.writeHead(500);
    res.end(JSON.stringify({ error: 'internal server error' }));
  });
});

module.exports = server;

if (require.main === module) {
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`bank-api listening on http://127.0.0.1:${PORT}`);
  });
}
