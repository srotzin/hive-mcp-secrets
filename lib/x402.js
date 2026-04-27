/**
 * x402 envelope helpers + ethers signature verification + Base RPC reads
 * for hive-mcp-secrets.
 *
 * Inbound only. Caller submits a Base USDC tx_hash that paid the asking
 * amount to W1; the shim reads the tx receipt from Base RPC and decodes
 * the USDC Transfer log to confirm recipient and amount.
 *
 * Settlement: USDC on Base L2 → W1 MONROE 0x15184bf50b3d3f52b60434f8942b7d52f2eb436e.
 */

import { ethers } from 'ethers';

export const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const USDC_DECIMALS = 6;
export const TRANSFER_TOPIC = ethers.id('Transfer(address,address,uint256)');

// Spec pricing — keep in sync with README, smithery.yaml, RELEASE_NOTES.md.
export const PRICES = {
  secrets_get: 0.002,
  secrets_put: 0.005,
  secrets_audit: 0.002,
  secrets_list: 0,
};

let _provider = null;
function provider() {
  if (_provider) return _provider;
  const url = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
  _provider = new ethers.JsonRpcProvider(url);
  return _provider;
}

export function envelope({ kind, amount_usd, pay_to, asset, network, nonce }) {
  return {
    type: 'x402',
    version: '1',
    kind,
    asking_usd: amount_usd,
    accept_min_usd: amount_usd,
    asset: asset || 'USDC',
    asset_address: USDC_BASE,
    network: network || 'base',
    pay_to,
    nonce: nonce || Math.random().toString(36).slice(2),
    issued_ms: Date.now(),
  };
}

/**
 * Verify a Base USDC transfer to pay_to of at least amount_usd.
 * Returns { ok, reason?, payer?, amount_usd?, tx_hash }.
 */
export async function verifyBaseUsdcPayment({ tx_hash, pay_to, min_usd }) {
  if (!tx_hash || typeof tx_hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(tx_hash)) {
    return { ok: false, reason: 'invalid_tx_hash', tx_hash };
  }
  let receipt;
  try {
    receipt = await provider().getTransactionReceipt(tx_hash);
  } catch (err) {
    return { ok: false, reason: `rpc_error: ${err.message}`, tx_hash };
  }
  if (!receipt) return { ok: false, reason: 'tx_not_found_or_pending', tx_hash };
  if (receipt.status !== 1) return { ok: false, reason: 'tx_reverted', tx_hash };

  const usdcLogs = (receipt.logs || []).filter(l =>
    l.address.toLowerCase() === USDC_BASE.toLowerCase() &&
    l.topics?.[0] === TRANSFER_TOPIC,
  );
  let total = 0n;
  let payer = null;
  for (const log of usdcLogs) {
    const to = '0x' + log.topics[2].slice(26).toLowerCase();
    if (to !== pay_to.toLowerCase()) continue;
    const from = '0x' + log.topics[1].slice(26).toLowerCase();
    payer = payer || from;
    total += BigInt(log.data);
  }
  if (total === 0n) return { ok: false, reason: 'no_transfer_to_pay_to', tx_hash };

  const amount_usd = Number(total) / 10 ** USDC_DECIMALS;
  if (amount_usd + 1e-9 < min_usd) {
    return { ok: false, reason: 'underpaid', tx_hash, amount_usd, required_usd: min_usd };
  }
  return { ok: true, tx_hash, payer, amount_usd };
}

/**
 * Verify an ECDSA signature over `message` recovers `claimed_address`.
 */
export function verifyOwnerSignature({ message, signature, claimed_address }) {
  if (!message || !signature || !claimed_address) {
    return { ok: false, reason: 'missing_fields' };
  }
  try {
    const recovered = ethers.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== claimed_address.toLowerCase()) {
      return { ok: false, reason: 'signature_mismatch', recovered };
    }
    return { ok: true, recovered };
  } catch (err) {
    return { ok: false, reason: `verify_error: ${err.message}` };
  }
}
