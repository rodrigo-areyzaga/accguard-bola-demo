# accguard-bola-demo

A deliberately vulnerable banking API that demonstrates **BOLA** (Broken Object Level Authorization) — [OWASP API Security #1](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).

Used to show what [accguard](https://github.com/your-org/accguard) catches.

---

## Try it in 90 seconds

```bash
git clone https://github.com/your-org/accguard-bola-demo
cd accguard-bola-demo
npm install
npm run demo
```

You'll see accguard catch Bob reading Alice's account — balance, SSN, routing number — in real time.

---

## The bug

The API has two users:

| User  | Account  | Balance     |
|-------|----------|-------------|
| Alice | `acct-1` | $84,320.00  |
| Bob   | `acct-2` | $3,105.22   |

`GET /accounts/:id` checks whether you're logged in. It does **not** check whether the account belongs to you.

```js
// server.js — the vulnerable handler
const account = ACCOUNTS[acctMatch[1]];
if (!account) return json(res, 404, { error: 'account not found' });
// ❌ Missing: if (account.owner !== user.id) return json(res, 403, ...)
return json(res, 200, account);  // Bob gets Alice's SSN, balance, routing number
```

The fix is one line. The bug is invisible to any UI-level test.

---

## What accguard does

1. Proxies Alice's authenticated requests and records them
2. Replays each one using Bob's token
3. Compares response bodies using SHA-256 hash
4. Flags any endpoint where Bob gets the same data Alice got

```
[1] Proxy running — recording Alice's traffic
[2] Alice reads her own account: GET /accounts/acct-1 → 200
[3] Replay: Bob requests GET /accounts/acct-1
[4] Response bodies match — SHA-256 identical
[!] BROKEN ACCESS CONTROL — Bob read Alice's financial data
```

---

## What accguard does not do

- It does not attack third-party targets
- It does not bypass authentication
- It does not replace manual AppSec review
- It is intended for owned test environments only

---

## Fix it yourself

Open `server.js` and add the ownership check on lines 90 and 103:

```js
if (account.owner !== user.id) return json(res, 403, { error: 'forbidden' });
```

Run `npm run demo` again. accguard finds nothing. That's the goal.

---

## About accguard

[accguard](https://github.com/your-org/accguard) is an authorization regression testing proxy for local and CI environments. It detects broken access control using real authenticated traffic — no configuration, no false positives.
