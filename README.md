# SignGuard — BSC/EVM pre-signing transaction guard

A deterministic guard that checks a transaction **before** you sign it. Paste a
`to` + `data` + `value` and it tells you, in plain terms, what the call does
and whether it is safe: `ALLOW`, `REVIEW`, or `BLOCK`, with a 0–100 risk score
and a per-check breakdown.

Built for the zkVerify Agent Games 2026 Season 01 — Wildcard track.

## Why this exists

In November 2026 our agent wallet was drained through a wallet-signed swap on
an unverified site. The lesson: **never sign what you have not read**. A
wallet shows you hex; SignGuard reads the hex for you — it decodes the
calldata, flags unlimited approvals, unknown spenders, `permit` traps, and
approvals hidden inside `multicall` batches, before any signature happens.

## What it does

`POST /analyze` with `{ to, data, value, from?, expectedRecipient? }`:

| Check | Points | Meaning |
|---|---:|---|
| `UNLIMITED_APPROVAL` | +50 | `approve` / `setApprovalForAll` / `permit` amount ≥ 2²⁵⁵ |
| `UNKNOWN_SPENDER` | +25 | Approval target is not on the known-spender allowlist |
| `KNOWN_SPENDER_UNLIMITED` | +15 | Unlimited approval even to a known router |
| `PERMIT` | +20 | Signed approval, spendable without another tx from the owner |
| `PERMIT_LONG_DEADLINE` | +10 | Permit deadline > 1y out, or max uint256 |
| `MULTICALL_NESTED_APPROVAL` | +40 | Approval selector inside an undecodable batch (fallback) |
| `NATIVE_VALUE_WITH_CALLDATA` | +30 | BNB sent with calldata to an unknown contract |
| `RECIPIENT_MISMATCH` | +45 | Decoded recipient ≠ `expectedRecipient` you supplied |
| `UNKNOWN_SELECTOR` | +30 | Selector not in the known table — cannot verify what it does |

Verdict: **≥ 70 BLOCK, 30–69 REVIEW, < 30 ALLOW.** Scores cap at 100.
Inner `multicall` calls are ABI-decoded and scored with the same rules
(depth 1); if a batch cannot be decoded, a heuristic selector scan is used
and labelled as such.

Known contracts (verified addresses, BSC):
- PancakeSwap V2 Router `0x10ED43C718714eb63d5aA57B78B54704E256024E` (allowlist)
- WBNB `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`
- BSC USDT `0x55d398326f99059fF775485246999027B3197955`

## Run it

Zero dependencies — Node.js 18+ stdlib only.

```sh
node server.js            # PORT env, default 8080; HOST env, default 127.0.0.1
```

```sh
curl -s http://127.0.0.1:8080/health
# {"ok":true,"service":"signguard","version":"0.1.0","uptimeSec":0}

# Unlimited USDT approve to an unknown address -> BLOCK 75/100
curl -s -X POST http://127.0.0.1:8080/analyze -H 'Content-Type: application/json' -d '{
  "to": "0x55d398326f99059fF775485246999027B3197955",
  "data": "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "value": "0"
}'
```

## Tests

```sh
node test-vectors.js     # 8/8 vectors pass (2026-11-17)
```

1. Unlimited USDT approve to unknown EOA → BLOCK 75/100
2. Limited USDT approve (100 USDT) to PancakeSwap V2 router → ALLOW 0/100
3. `setApprovalForAll(true)` to unknown EOA → BLOCK 75/100
4. Plain BNB transfer, no calldata → ALLOW 0/100
5. `multicall` hiding an unlimited approve → BLOCK 75/100
6. `permit`, unknown spender, max deadline → REVIEW 55/100
7. Unknown selector `0xdeadbeef` → REVIEW 30/100
8. Transfer to wrong recipient (`expectedRecipient` mismatch) → REVIEW 45/100

## Design decisions

- **Deterministic, no LLM in the decision path.** The verdict comes from
  fixed rules over decoded calldata, so the same input always gives the same
  output — and anyone can re-run it to check.
- **Read-only analysis.** The service never signs, sends, or broadcasts. It
  cannot move funds; the worst it can do is warn.
- **Fail closed.** Unknown selectors, malformed calldata, and undecodable
  batches raise the score instead of passing silently.
- **Small, auditable allowlist.** One verified router, two verified tokens.
  Everything else is "unknown" until a human adds it with a source.

## Limitations (honest)

- Pure calldata policy: no on-chain simulation, no balance/allowance reads,
  no contract-code check (a "known" address could be redeployed — the
  allowlist is a starting point, not a proof of safety).
- Nested `multicall` is decoded one level deep; deeper nesting falls back to
  the heuristic selector scan, which is labelled in the output.
- No zkVerify proof yet: the claim "this input scores X" is checkable by
  re-running the code, not by a Groth16 proof. Attaching a proof of the
  policy evaluation (same pattern as the Gatekeeper track) is the next step,
  not a claim made here.

## Files

- `guard.js` — policy engine (`analyze`, `analyzeCall`, `decodeMulticallCalls`)
- `server.js` — stdlib HTTP service (`GET /`, `GET /health`, `POST /analyze`)
- `test-vectors.js` — 8 crafted calldata vectors with expected verdicts
