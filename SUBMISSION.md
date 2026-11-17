# SignGuard — Wildcard submission text (zkVerify Agent Games Season 01)

Prepared 2026-11-17 for the Wildcard track dashboard form. Fill the REPO and
ENDPOINT placeholders once the public repo is pushed and the service is hosted;
everything else below is ready to paste.

## Title (dashboard)

```
SignGuard — a pre-signing transaction guard for BSC wallets
```

## Category

Wildcard

## Submission links

- Agent link (public repo): https://github.com/Ryukein19/signguard (created + pushed 2026-11-17 ~09:12 WIB, commit 64e34c2, PUBLIC)
- Public endpoint: https://signguard-production.up.railway.app (Railway, deployed 2026-11-17 ~09:16 WIB, verified live ~09:23 WIB: GET /health {"ok":true}, POST /analyze unlimited USDT approve → BLOCK 75/100)
- Demo: `POST /analyze` examples in README.md (unlimited approve → BLOCK 75/100; router approve → ALLOW 0/100)

## Use case (what problem, who it helps, what it does)

Wallets show users hex. In November 2026 our agent wallet was drained through
a wallet-signed swap on an unverified site — the signature was the attack.
SignGuard sits between the user and the signature: paste a transaction's `to` +
`data` + `value` and it decodes the calldata, flags unlimited approvals,
unknown spenders, `permit` traps, and approvals hidden inside `multicall`
batches, and returns ALLOW / REVIEW / BLOCK with a 0–100 score and a
per-check breakdown. It helps anyone who signs BSC/EVM transactions —
especially agents and small holders who cannot read calldata by hand — decide
before signing instead of regretting after. It never signs, sends, or
broadcasts: it is analysis only, so it cannot move funds.

## Build context (how it works, key decisions)

- Node.js stdlib only, zero dependencies. `guard.js` is a deterministic policy
  engine (no LLM in the decision path, so the same input always gives the
  same verdict); `server.js` exposes `GET /health` and `POST /analyze`.
- Rules are fixed and auditable: unlimited approval (≥ 2²⁵⁵) +50, unknown
  spender +25, `permit` +20, long permit deadline +10, hidden multicall
  approval +40, BNB with calldata to an unknown contract +30, recipient
  mismatch +45, unknown selector +30. Verdict: ≥ 70 BLOCK, 30–69 REVIEW,
  < 30 ALLOW.
- Inner `multicall` calls are ABI-decoded and scored with the same rules
  (depth 1); undecodable batches fall back to a labelled heuristic scan.
- Known contracts are a small verified allowlist (PancakeSwap V2 Router, WBNB,
  BSC USDT) — everything else is "unknown" until a human adds it with a
  source. Fail closed: unknown or malformed input raises the score.
- Verified 2026-11-17: 8/8 crafted calldata vectors pass (`node
  test-vectors.js`), plus a live HTTP smoke test (`/health` OK, unlimited
  approve → BLOCK 75/100, bad input → 200 with verdict ERROR).

## zkVerify (optional)

Not attached yet — stated plainly, not claimed. The checkable claim today is
reproducibility: anyone can re-run the code on the same input and get the
same verdict. The next step is a Groth16 proof of the policy evaluation (the
same pattern as the Proof Gatekeeper track: prove the decision followed the
rules without revealing the policy internals), which would make each verdict
independently verifiable through zkVerify.

## Endpoint note (for the user, not the form)

The public HTTPS endpoint is the one open item. This VM has no public IP and
free tunnels were blocked in earlier probes. Probed again 2026-11-17 ~09:05 WIB:
no tunnel binary on PATH; trycloudflare.com → 403; bore.pub unreachable;
localtunnel.me → 302 but `npx localtunnel` produced no URL within 30s (still
downloading/connecting when the probe window ended); egress is IPv6-only.
Options:
1. Railway / Render free tier — needs the user's account; the service is a
   single Node process (`node server.js`, `PORT` env), no database.
2. Tailscale Funnel — needs the user's Tailscale network; serves the local
   service on a public `*.ts.net` HTTPS URL.
3. Any always-on host the user already has — copy the `zkguard/` folder,
   `node server.js`, point the domain at it.

## Supporting context (dashboard optional field, ≤1000 chars)

```
SignGuard is a deterministic pre-signing guard for BSC/EVM wallets: it decodes transaction calldata and returns ALLOW / REVIEW / BLOCK with a 0-100 risk score before anything is signed. It flags unlimited approvals, unknown spenders, permit traps, and approvals hidden inside multicall batches (inner calls are ABI-decoded and scored with the same rules). Built after our agent wallet was drained through a wallet-signed swap on an unverified site — the signature was the attack. Zero dependencies, no LLM in the decision path, read-only analysis (it never signs or broadcasts). Verified with 8/8 crafted calldata vectors plus a live HTTP smoke test.
```
