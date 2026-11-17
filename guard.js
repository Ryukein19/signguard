'use strict';
/**
 * SignGuard — BSC/EVM pre-signing transaction guard (Wildcard track).
 * Deterministic policy engine, zero dependencies, no LLM in the decision path.
 * It ANALYZES a transaction and returns a verdict + risk score. It never
 * signs, sends, or broadcasts anything.
 *
 * Scoring (0-100, capped):
 *   UNLIMITED_APPROVAL            +50  approve/setApprovalForAll >= 2^255
 *   UNKNOWN_SPENDER               +25  approval target not on the allowlist
 *   KNOWN_SPENDER_UNLIMITED       +15  unlimited approval even to a known router
 *   PERMIT                        +20  signed approval (spendable without a tx)
 *   PERMIT_LONG_DEADLINE          +10  deadline > 1y out or max uint256
 *   MULTICALL_NESTED_APPROVAL     +40  approval selector inside an undecodable batch (fallback)
 *   NATIVE_VALUE_WITH_CALLDATA    +30  BNB sent with calldata to unknown contract
 *   RECIPIENT_MISMATCH            +45  decoded recipient != expectedRecipient
 *   UNKNOWN_SELECTOR              +30  function selector not in the known table
 * Verdict: score >= 70 BLOCK, 30-69 REVIEW, < 30 ALLOW.
 * Inner multicall calls are decoded and scored with the same rules (depth 1).
 */

const UNLIMITED_THRESHOLD = 2n ** 255n;

// Allowlist of well-known BSC contracts (verified addresses, see README).
const KNOWN_SPENDERS = new Set([
  '0x10ed43c718714eb63d5aa57b78b54704e256024e', // PancakeSwap V2 Router
]);
const KNOWN_CONTRACTS = new Set([
  ...KNOWN_SPENDERS,
  '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c', // WBNB
  '0x55d398326f99059ff775485246999027b3197955', // BSC USDT
]);

const SELECTORS = {
  '095ea7b3': { name: 'approve', args: ['address:spender', 'uint256:amount'] },
  'a22cb465': { name: 'setApprovalForAll', args: ['address:operator', 'bool:approved'] },
  'd505accf': { name: 'permit', args: ['address:owner', 'address:spender', 'uint256:value', 'uint256:deadline', 'uint8:v', 'bytes32:r', 'bytes32:s'] },
  'a9059cbb': { name: 'transfer', args: ['address:recipient', 'uint256:amount'] },
  '23b872dd': { name: 'transferFrom', args: ['address:from', 'address:to', 'uint256:amount'] },
  'ac9650d8': { name: 'multicall', args: ['bytes[]:calls'] },
};

function isAddress(s) {
  return typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s);
}
function isHex(s) {
  return typeof s === 'string' && /^0x([0-9a-fA-F]*)$/.test(s);
}
function wordAt(hex, i) {
  // i-th 32-byte word after the 4-byte selector. hex includes '0x'.
  const start = 2 + 8 + i * 64;
  return hex.slice(start, start + 64);
}
function wordAddress(hex, i) {
  const w = wordAt(hex, i);
  if (w.length !== 64) return null;
  return '0x' + w.slice(24);
}
function wordUint(hex, i) {
  const w = wordAt(hex, i);
  if (w.length !== 64) return null;
  try { return BigInt('0x' + w); } catch { return null; }
}
function wordBool(hex, i) {
  const w = wordAt(hex, i);
  if (w.length !== 64) return null;
  return w.slice(62) === '01';
}

/** Decode a multicall(bytes[]) payload into inner calldata strings. Returns null on malformed input. */
function decodeMulticallCalls(data) {
  try {
    const hex = data.slice(2); // strip 0x, starts with 8-char selector
    const word = (i) => hex.slice(8 + i * 64, 8 + (i + 1) * 64);
    const offset = parseInt(word(0), 16);
    if (!Number.isFinite(offset) || offset < 0 || offset > 100000) return null;
    const arrPos = 8 + offset * 2; // hex-char position of the array
    const countHex = hex.slice(arrPos, arrPos + 64);
    if (countHex.length !== 64) return null;
    const count = parseInt(countHex, 16);
    if (!Number.isFinite(count) || count < 0 || count > 64) return null;
    const calls = [];
    for (let j = 0; j < count; j++) {
      const offHex = hex.slice(arrPos + 64 + j * 64, arrPos + 64 + (j + 1) * 64);
      if (offHex.length !== 64) return null;
      const elemOff = parseInt(offHex, 16);
      const elemPos = arrPos + 64 + elemOff * 2; // offsets are relative to the offsets section (right after the length word)
      const lenHex = hex.slice(elemPos, elemPos + 64);
      if (lenHex.length !== 64) return null;
      const len = parseInt(lenHex, 16);
      if (!Number.isFinite(len) || len < 0 || len > 100000) return null;
      const callHex = hex.slice(elemPos + 64, elemPos + 64 + len * 2);
      if (callHex.length !== len * 2) return null;
      calls.push('0x' + callHex);
    }
    return calls;
  } catch { return null; }
}

/** Score one call (outer or inner). Returns { score, checks, decoded }. */
function analyzeCall(tx) {
  const { to, data, value, expectedRecipient } = tx;
  const checks = [];
  const decoded = {};
  let score = 0;
  const add = (id, points, severity, detail, passed) => {
    score += points;
    checks.push({ id, points, severity, detail, passed: !!passed });
  };
  const toKnown = KNOWN_CONTRACTS.has(to);
  const body = data.slice(2);

  if (body.length === 0) {
    decoded.function = 'native_transfer';
    decoded.args = { to, valueWei: value.toString() };
    add('NATIVE_TRANSFER', 0, 'info', 'Plain BNB transfer, no calldata.', true);
    return { score, checks, decoded };
  }

  const selector = body.slice(0, 8).toLowerCase();
  const spec = SELECTORS[selector];

  if (!spec) {
    decoded.function = 'unknown';
    decoded.selector = '0x' + selector;
    add('UNKNOWN_SELECTOR', 30, 'medium', 'Function selector is not in the known table; what this call does cannot be verified.', false);
    if (value > 0n && !toKnown) {
      add('NATIVE_VALUE_WITH_CALLDATA', 30, 'high', 'BNB is sent with calldata to an unknown contract.', false);
    }
    return { score, checks, decoded };
  }

  decoded.function = spec.name;
  decoded.selector = '0x' + selector;

  if (spec.name === 'approve') {
    const spender = wordAddress(data, 0);
    const amount = wordUint(data, 1);
    decoded.args = { spender, amount: amount === null ? null : amount.toString() };
    if (spender === null || amount === null) {
      add('MALFORMED_CALLDATA', 30, 'medium', 'approve calldata is shorter than expected.', false);
      return { score, checks, decoded };
    }
    const spenderKnown = KNOWN_SPENDERS.has(spender.toLowerCase());
    if (amount >= UNLIMITED_THRESHOLD) {
      add('UNLIMITED_APPROVAL', 50, 'high', `approve() amount ${amount.toString()} is >= 2^255 (effectively unlimited).`, false);
      if (spenderKnown) add('KNOWN_SPENDER_UNLIMITED', 15, 'medium', 'Spender is a known router, but an unlimited approval is still risky.', false);
      else add('UNKNOWN_SPENDER', 25, 'high', `Spender ${spender} is not on the known-spender allowlist.`, false);
    } else if (!spenderKnown) {
      add('UNKNOWN_SPENDER', 25, 'medium', `Spender ${spender} is not on the known-spender allowlist (limited amount).`, false);
    } else {
      add('KNOWN_SPENDER_LIMITED', 0, 'info', 'Limited approval to a known router.', true);
    }
  } else if (spec.name === 'setApprovalForAll') {
    const operator = wordAddress(data, 0);
    const approved = wordBool(data, 1);
    decoded.args = { operator, approved };
    if (operator === null || approved === null) {
      add('MALFORMED_CALLDATA', 30, 'medium', 'setApprovalForAll calldata is shorter than expected.', false);
      return { score, checks, decoded };
    }
    if (approved) {
      const opKnown = KNOWN_SPENDERS.has(operator.toLowerCase());
      add('UNLIMITED_APPROVAL', 50, 'high', 'setApprovalForAll(true) grants access to ALL tokens of this collection.', false);
      if (!opKnown) add('UNKNOWN_SPENDER', 25, 'high', `Operator ${operator} is not on the known-spender allowlist.`, false);
      else add('KNOWN_SPENDER_UNLIMITED', 15, 'medium', 'Operator is known, but approval covers all tokens.', false);
    } else {
      add('REVOKE_ALL', 0, 'info', 'setApprovalForAll(false) revokes access — safe.', true);
    }
  } else if (spec.name === 'permit') {
    const spender = wordAddress(data, 1);
    const pValue = wordUint(data, 2);
    const deadline = wordUint(data, 3);
    decoded.args = {
      owner: wordAddress(data, 0), spender,
      value: pValue === null ? null : pValue.toString(),
      deadline: deadline === null ? null : deadline.toString(),
    };
    add('PERMIT', 20, 'medium', 'permit() is a signed approval — spendable without a further on-chain transaction from the owner.', false);
    if (spender !== null && !KNOWN_SPENDERS.has(spender.toLowerCase())) {
      add('UNKNOWN_SPENDER', 25, 'high', `Permit spender ${spender} is not on the known-spender allowlist.`, false);
    }
    if (pValue !== null && pValue >= UNLIMITED_THRESHOLD) {
      add('UNLIMITED_APPROVAL', 50, 'high', 'Permit value is >= 2^255 (effectively unlimited).', false);
    }
    if (deadline !== null) {
      const nowSec = BigInt(Math.floor(Date.now() / 1000));
      const oneYear = nowSec + 365n * 24n * 3600n;
      const maxUint = 2n ** 256n - 1n;
      if (deadline === maxUint || deadline > oneYear) {
        add('PERMIT_LONG_DEADLINE', 10, 'medium', 'Permit deadline is effectively never-expiring.', false);
      }
    }
  } else if (spec.name === 'transfer' || spec.name === 'transferFrom') {
    const recipient = spec.name === 'transfer' ? wordAddress(data, 0) : wordAddress(data, 1);
    const amount = wordUint(data, spec.name === 'transfer' ? 1 : 2);
    decoded.args = { recipient, amount: amount === null ? null : amount.toString() };
    add('TOKEN_TRANSFER', 0, 'info', `${spec.name} moves tokens to a stated recipient; no approval is granted.`, true);
    if (expectedRecipient && typeof expectedRecipient === 'string') {
      const exp = expectedRecipient.toLowerCase();
      if (recipient !== null && recipient.toLowerCase() !== exp) {
        add('RECIPIENT_MISMATCH', 45, 'high', `Decoded recipient ${recipient} does not match expected recipient ${expectedRecipient}.`, false);
      }
    }
  } else if (spec.name === 'multicall') {
    const inner = decodeMulticallCalls(data);
    if (inner === null) {
      // Fallback: heuristic scan for approval selectors inside the payload.
      const rest = body.slice(8);
      const hits = [];
      for (const sel of ['095ea7b3', 'a22cb465', 'd505accf']) {
        let idx = rest.indexOf(sel);
        while (idx !== -1) { hits.push(sel); idx = rest.indexOf(sel, idx + 1); }
      }
      decoded.args = { innerCalls: null, nestedApprovalSelectors: hits, note: 'payload could not be ABI-decoded; heuristic scan used' };
      if (hits.length > 0) {
        add('MULTICALL_NESTED_APPROVAL', 40, 'high', `multicall payload contains ${hits.length} approval selector(s) (${hits.map(s => '0x' + s).join(', ')}) — approvals hidden inside a batch.`, false);
      } else {
        add('MULTICALL_NO_APPROVAL_SEEN', 10, 'low', 'No approval selector found inside the multicall payload (heuristic scan).', true);
      }
    } else {
      decoded.args = { innerCalls: inner.map((c) => c.slice(0, 18) + '…') };
      if (inner.length === 0) {
        add('MULTICALL_EMPTY', 10, 'low', 'multicall with zero inner calls.', true);
      }
      // Score each inner call with the same rules (depth 1; inner value is 0).
      inner.forEach((call, j) => {
        const r = analyzeCall({ to, data: call, value: 0n, expectedRecipient });
        score += r.score;
        for (const c of r.checks) {
          checks.push({ ...c, detail: `[inner #${j + 1}] ${c.detail}` });
        }
        decoded.args[`inner${j + 1}`] = r.decoded;
      });
    }
    if (value > 0n && !toKnown) {
      add('NATIVE_VALUE_WITH_CALLDATA', 30, 'high', 'BNB is sent with calldata to an unknown contract.', false);
    }
  }

  return { score, checks, decoded };
}

function analyze(input) {
  const errors = [];
  const to = typeof input.to === 'string' ? input.to.toLowerCase() : '';
  const data = typeof input.data === 'string' && input.data !== '' ? input.data : '0x';
  let value = 0n;
  if (input.value === undefined || input.value === null || input.value === '') {
    value = 0n;
  } else {
    try {
      value = BigInt(input.value);
    } catch {
      // Tolerate decimal numbers (e.g. a probe sending value: 0.5) by
      // flooring to whole wei instead of rejecting the whole request.
      const n = Number(input.value);
      if (Number.isFinite(n) && n >= 0) value = BigInt(Math.floor(n));
      else errors.push('value must be a decimal wei string');
    }
  }
  if (value < 0n) errors.push('value must not be negative');
  if (!isAddress(to)) errors.push('to must be a 0x address (40 hex chars)');
  if (!isHex(data)) errors.push('data must be 0x hex');
  if (errors.length) return { verdict: 'ERROR', score: null, errors };

  const { score: rawScore, checks, decoded } = analyzeCall({
    to, data, value,
    expectedRecipient: input.expectedRecipient,
  });
  const score = Math.min(100, rawScore);
  const verdict = score >= 70 ? 'BLOCK' : score >= 30 ? 'REVIEW' : 'ALLOW';
  return {
    verdict, score,
    to, toKnownContract: KNOWN_CONTRACTS.has(to),
    valueWei: value.toString(),
    decoded, checks,
    summary: `${verdict} (${score}/100) — ${checks.filter(c => !c.passed).length} failed check(s), ${checks.filter(c => c.passed).length} passed.`,
  };
}

module.exports = { analyze, analyzeCall, decodeMulticallCalls, SELECTORS, KNOWN_SPENDERS };
