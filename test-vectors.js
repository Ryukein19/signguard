'use strict';
/**
 * SignGuard test vectors — crafts real calldata and asserts verdicts.
 * Run: node test-vectors.js   (exit 0 = all pass)
 * No network, no wallet, no signing.
 */
const { analyze } = require('./guard');

const USDT = '0x55d398326f99059fF775485246999027B3197955';
const ROUTER_V2 = '0x10ED43C718714eb63d5aA57B78B54704E256024E';
const EOA = '0x1111111111111111111111111111111111111111';
const MAX_UINT = (2n ** 256n - 1n).toString();

function wordAddr(a) { return a.toLowerCase().replace(/^0x/, '').padStart(64, '0'); }
function wordUint(n) { return BigInt(n).toString(16).padStart(64, '0'); }
function wordBool(b) { return (b ? '01' : '00').padStart(64, '0'); }

function approve(spender, amount) {
  return '0x095ea7b3' + wordAddr(spender) + wordUint(amount);
}
function setApprovalForAll(op, approved) {
  return '0xa22cb465' + wordAddr(op) + wordBool(approved);
}
function permit(spender, value, deadline) {
  // permit(owner, spender, value, deadline, v, r, s)
  return '0xd505accf'
    + wordAddr(EOA) + wordAddr(spender) + wordUint(value) + wordUint(deadline)
    + wordUint(27) + '0'.repeat(64) + '0'.repeat(64);
}
function transfer(recipient, amount) {
  return '0xa9059cbb' + wordAddr(recipient) + wordUint(amount);
}
function multicallWith(innerCalldata) {
  // multicall(bytes[]) — one inner call. ABI: offset(0) + len(1) + elemOffset(0) + elemLen + data padded.
  const inner = innerCalldata.replace(/^0x/, '');
  const elemLen = inner.length / 2;
  const padded = inner.padEnd(Math.ceil(inner.length / 64) * 64, '0');
  return '0xac9650d8'
    + wordUint(32) + wordUint(1) + wordUint(32) + wordUint(elemLen) + padded;
}

const cases = [
  {
    name: '1. unlimited USDT approve to unknown EOA -> BLOCK',
    input: { to: USDT, data: approve(EOA, MAX_UINT), value: '0' },
    expect: 'BLOCK',
  },
  {
    name: '2. limited USDT approve (100 USDT) to PancakeSwap V2 router -> ALLOW',
    input: { to: USDT, data: approve(ROUTER_V2, 100_000_000), value: '0' },
    expect: 'ALLOW',
  },
  {
    name: '3. setApprovalForAll(true) to unknown EOA -> BLOCK',
    input: { to: '0x2222222222222222222222222222222222222222', data: setApprovalForAll(EOA, true), value: '0' },
    expect: 'BLOCK',
  },
  {
    name: '4. plain BNB transfer, no calldata -> ALLOW',
    input: { to: EOA, data: '0x', value: '1000000000000000' },
    expect: 'ALLOW',
  },
  {
    name: '5. multicall hiding an unlimited approve -> BLOCK',
    input: { to: '0x3333333333333333333333333333333333333333', data: multicallWith(approve(EOA, MAX_UINT)), value: '0' },
    expect: 'BLOCK',
  },
  {
    name: '6. permit, unknown spender, max deadline -> REVIEW',
    input: { to: USDT, data: permit(EOA, 1000_000_000, MAX_UINT), value: '0' },
    expect: 'REVIEW',
  },
  {
    name: '7. unknown selector 0xdeadbeef -> REVIEW',
    input: { to: '0x4444444444444444444444444444444444444444', data: '0xdeadbeef' + '00'.repeat(32), value: '0' },
    expect: 'REVIEW',
  },
  {
    name: '8. transfer to wrong recipient (expectedRecipient mismatch) -> REVIEW',
    input: { to: USDT, data: transfer(EOA, 1000), value: '0', expectedRecipient: '0x9999999999999999999999999999999999999999' },
    expect: 'REVIEW',
  },
];

let pass = 0;
for (const c of cases) {
  const out = analyze(c.input);
  const ok = out.verdict === c.expect;
  if (ok) pass++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${c.name}  (got ${out.verdict} ${out.score}/100)`);
  if (!ok) {
    console.log('   full output:', JSON.stringify(out, null, 2));
  }
}
console.log(`\n${pass}/${cases.length} vectors pass`);
process.exit(pass === cases.length ? 0 : 1);
