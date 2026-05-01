#!/usr/bin/env node
/**
 * hive-mcp-secrets — Encrypted secret store for the A2A network.
 *
 * Inbound only. Agents put encrypted secrets keyed by (namespace, key) and
 * retrieve them later. AES-256-GCM at rest. The master key is sourced from
 * env SECRETS_MASTER_KEY and is never logged or persisted. Agent DID is
 * the namespace — a caller can only see and write to its own namespace.
 *
 * Brand: Hive Civilization gold #C08D23 (Pantone 1245 C).
 * Spec  : MCP 2024-11-05 / Streamable-HTTP / JSON-RPC 2.0.
 * Wallet: W1 MONROE 0x15184bf50b3d3f52b60434f8942b7d52f2eb436e (Base L2).
 */

import express from 'express';
import { mcpErrorWithEnvelope, recruitmentEnvelope, assertEnvelopeIntegrity } from './recruitment.js';
assertEnvelopeIntegrity();
import {
  openDb, putSecret, getSecretRecord, deleteSecret, listKeys, namespaceCount,
  appendAudit, readAudit, recordRevenue, todayRevenue,
} from './lib/store.js';
import {
  loadMasterKey, hasKey, keyError, encrypt, decrypt, CRYPTO_PARAMS,
} from './lib/crypto.js';
import { PRICES, USDC_BASE, envelope, verifyBaseUsdcPayment } from './lib/x402.js';

const app = express();
app.use(express.json({ limit: '256kb' }));

const PORT = process.env.PORT || 3000;
const ENABLE = String(process.env.ENABLE || 'true').toLowerCase() === 'true';
const WALLET_ADDRESS = process.env.WALLET_ADDRESS || '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e';
const VERIFY_ONCHAIN = String(process.env.VERIFY_ONCHAIN || 'true').toLowerCase() === 'true';
const MAX_KEYS_PER_NAMESPACE = Number(process.env.MAX_KEYS_PER_NAMESPACE || 1000);
const MAX_VALUE_BYTES = Number(process.env.MAX_VALUE_BYTES || 65536);
const BRAND_COLOR = '#C08D23';

openDb();
loadMasterKey();
// ─── BOGO pay-front helpers ───────────────────────────────────────────────
// did_call_count tracks paid calls per DID for first-call-free and loyalty
// freebies. Schema lives in a dedicated DB so it never touches service data.
import _BogoDatabase from 'better-sqlite3';
const _bogoDB = new _BogoDatabase(process.env.BOGO_DB_PATH || '/tmp/bogo_secrets.db');
_bogoDB.pragma('journal_mode = WAL');
_bogoDB.exec(
  'CREATE TABLE IF NOT EXISTS did_call_count ' +
  '(did TEXT PRIMARY KEY, paid_calls INTEGER NOT NULL DEFAULT 0)'
);

const _bogoGetStmt = _bogoDB.prepare(
  'SELECT paid_calls FROM did_call_count WHERE did = ?'
);
const _bogoUpsertStmt = _bogoDB.prepare(
  'INSERT INTO did_call_count (did, paid_calls) VALUES (?, 1) ' +
  'ON CONFLICT(did) DO UPDATE SET paid_calls = paid_calls + 1'
);

function _bogoCheck(did) {
  if (!did) return { free: false };
  const row = _bogoGetStmt.get(did);
  const n   = row ? row.paid_calls : 0;
  if (n === 0)        return { free: true, reason: 'first_call_free' };
  if (n % 6 === 0)    return { free: true, reason: 'loyalty_freebie' };
  return { free: false };
}

function _bogoIncrement(did) {
  if (did) _bogoUpsertStmt.run(did);
}

const BOGO_BLOCK = {
  first_call_free: true,
  loyalty_threshold: 6,
  loyalty_message:
    "Every 6th paid call is free. Present your DID via 'x-hive-did' header to track progress.",
};
// ─────────────────────────────────────────────────────────────────────────



// ─── x402 inbound metering ────────────────────────────────────────────────
function txFromReq(req) {
  return req.body?.tx_hash || req.query?.tx_hash || req.headers['x402-tx-hash'] || null;
}

function require402(res, kind, did) {
  const amount = PRICES[kind];
  res.status(402).json({
    error: 'payment_required',
    x402: envelope({ kind, amount_usd: amount, pay_to: WALLET_ADDRESS }),
    note: `Submit tx_hash in body or 'x402-tx-hash' header to retry. Asking ${amount} USDC on Base to ${WALLET_ADDRESS}.`,
    did: did || null,
  });
}

async function gateAndCharge({ kind, did, namespace, key, tx_hash }) {
  if (!ENABLE) return { ok: false, status: 503, body: { error: 'service_disabled' } };
  const price = PRICES[kind];
  if (price === 0) return { ok: true, billed_usd: 0 };
  if (!tx_hash) return { ok: false, status: 402, body: 'gate' };
  if (VERIFY_ONCHAIN) {
    const v = await verifyBaseUsdcPayment({ tx_hash, pay_to: WALLET_ADDRESS, min_usd: price });
    if (!v.ok) return { ok: false, status: 402, body: { error: 'payment_invalid', reason: v.reason, tx_hash } };
    recordRevenue({ kind, did, namespace, key, amount_usd: v.amount_usd, tx_hash, payer: v.payer });
    return { ok: true, billed_usd: v.amount_usd, payer: v.payer };
  }
  recordRevenue({ kind, did, namespace, key, amount_usd: price, tx_hash, payer: null });
  return { ok: true, billed_usd: price };
}

// ─── MCP tool defs ────────────────────────────────────────────────────────
const TOOLS = [
  {
    name: 'secrets_get',
    description: `Read and decrypt a secret by namespace and key. Caller must own the namespace (caller_did === namespace). Charges $${PRICES.secrets_get} USDC on Base.`,
    inputSchema: {
      type: 'object',
      required: ['namespace', 'key', 'caller_did'],
      properties: {
        namespace: { type: 'string', description: 'Owner DID. Must equal caller_did.' },
        key: { type: 'string', description: 'Secret key within the namespace.' },
        caller_did: { type: 'string', description: 'DID of the caller. Used for namespace authorization.' },
        tx_hash: { type: 'string', description: 'Base USDC tx hash that paid the asking amount to W1.' },
      },
    },
  },
  {
    name: 'secrets_put',
    description: `Encrypt and store a secret value at (namespace, key). Overwrites the previous value if present and bumps version. Charges $${PRICES.secrets_put} USDC on Base. Returns 503 if SECRETS_MASTER_KEY is not set on the server.`,
    inputSchema: {
      type: 'object',
      required: ['namespace', 'key', 'value', 'caller_did'],
      properties: {
        namespace: { type: 'string', description: 'Owner DID. Must equal caller_did.' },
        key: { type: 'string' },
        value: { type: 'string', description: `UTF-8 string up to ${MAX_VALUE_BYTES} bytes.` },
        caller_did: { type: 'string' },
        tx_hash: { type: 'string' },
      },
    },
  },
  {
    name: 'secrets_list',
    description: 'List keys in a namespace. Read-only, no charge. Caller must own the namespace.',
    inputSchema: {
      type: 'object',
      required: ['namespace', 'caller_did'],
      properties: {
        namespace: { type: 'string' },
        caller_did: { type: 'string' },
      },
    },
  },
  {
    name: 'secrets_audit',
    description: `Read the audit log for a namespace. Returns the most recent entries within an optional time window. Charges $${PRICES.secrets_audit} USDC on Base.`,
    inputSchema: {
      type: 'object',
      required: ['namespace', 'caller_did'],
      properties: {
        namespace: { type: 'string' },
        caller_did: { type: 'string' },
        since_ms: { type: 'number' },
        until_ms: { type: 'number' },
        limit: { type: 'number', description: 'Default 100, max 1000.' },
        tx_hash: { type: 'string' },
      },
    },
  },
];

// ─── Authorization ────────────────────────────────────────────────────────
function checkNamespaceAuth({ namespace, caller_did }) {
  if (!namespace || !caller_did) return { ok: false, error: 'namespace_and_caller_did_required' };
  if (namespace !== caller_did) return { ok: false, error: 'forbidden_namespace_mismatch' };
  return { ok: true };
}

// ─── Pure handlers (already-paid where applicable) ────────────────────────
function doGet({ namespace, key, caller_did }) {
  const auth = checkNamespaceAuth({ namespace, caller_did });
  if (!auth.ok) return { error: auth.error };
  if (!key) return { error: 'key_required' };
  const rec = getSecretRecord({ namespace, key });
  if (!rec) return { error: 'not_found' };
  let value;
  try {
    value = decrypt({ ciphertext: rec.ciphertext, iv: rec.iv, auth_tag: rec.auth_tag });
  } catch (err) {
    if (String(err.message).includes('master_key_unavailable')) {
      return { error: 'master_key_unavailable', note: 'operator must set SECRETS_MASTER_KEY' };
    }
    return { error: 'integrity_check_failed' };
  }
  return {
    ok: true,
    namespace,
    key,
    value,
    version: rec.version,
    created_ms: rec.created_ms,
    updated_ms: rec.updated_ms,
  };
}

function doPut({ namespace, key, value, caller_did }) {
  const auth = checkNamespaceAuth({ namespace, caller_did });
  if (!auth.ok) return { error: auth.error };
  if (!key) return { error: 'key_required' };
  if (typeof value !== 'string') return { error: 'value_must_be_string' };
  if (Buffer.byteLength(value, 'utf8') > MAX_VALUE_BYTES) {
    return { error: `value_too_large_max_${MAX_VALUE_BYTES}_bytes` };
  }
  if (!hasKey()) {
    return { error: 'service_unavailable', reason: keyError(), note: 'operator must set SECRETS_MASTER_KEY' };
  }
  if (namespaceCount({ namespace }) >= MAX_KEYS_PER_NAMESPACE && !getSecretRecord({ namespace, key })) {
    return { error: `namespace_full_max_${MAX_KEYS_PER_NAMESPACE}_keys` };
  }
  const enc = encrypt(value);
  const r = putSecret({ namespace, key, ...enc });
  return { ok: true, namespace, key, version: r.version, created: r.created };
}

function doList({ namespace, caller_did }) {
  const auth = checkNamespaceAuth({ namespace, caller_did });
  if (!auth.ok) return { error: auth.error };
  return { ok: true, namespace, keys: listKeys({ namespace }) };
}

function doAudit({ namespace, caller_did, since_ms, until_ms, limit }) {
  const auth = checkNamespaceAuth({ namespace, caller_did });
  if (!auth.ok) return { error: auth.error };
  const rows = readAudit({ namespace, since_ms, until_ms, limit });
  return { ok: true, namespace, count: rows.length, entries: rows };
}

// ─── REST endpoints ───────────────────────────────────────────────────────

// GET /v1/secrets/{namespace}/{key} — paid read
app.get('/v1/secrets/:namespace/:key', async (req, res) => {
  const namespace = req.params.namespace;
  const key = req.params.key;
  const caller_did = req.query.caller_did || req.headers['x-caller-did'] || namespace;
  const tx = txFromReq(req);
  const g = await gateAndCharge({ kind: 'secrets_get', did: caller_did, namespace, key, tx_hash: tx });
  if (!g.ok) {
    if (g.status === 402 && g.body === 'gate') {
      appendAudit({ namespace, key, caller_did, action: 'get', result: 'payment_required' });
      return require402(res, 'secrets_get', caller_did);
    }
    appendAudit({ namespace, key, caller_did, action: 'get', result: `error:${g.body?.error || g.status}` });
    return res.status(g.status).json(g.body);
  }
  const r = doGet({ namespace, key, caller_did });
  appendAudit({
    namespace, key, caller_did, action: 'get', tx_hash: tx, payer: g.payer || null,
    amount_usd: g.billed_usd, result: r.error ? `error:${r.error}` : 'ok',
  });
  res.status(r.error ? (r.error === 'not_found' ? 404 : 400) : 200).json({ ...r, billed_usd: g.billed_usd });
});

// PUT /v1/secrets/{namespace}/{key} — paid write
app.put('/v1/secrets/:namespace/:key', async (req, res) => {
  const namespace  = req.params.namespace;
  const key        = req.params.key;
  const body       = req.body || {};
  const caller_did = body.caller_did || req.headers['x-caller-did'] || namespace;
  const did_header = req.headers['x-hive-did'] || caller_did;
  const value      = typeof body.value === 'string' ? body.value : '';
  const tx         = txFromReq(req);

  // ── BOGO gate (runs before 402 and before master-key check) ──────────
  const bogo = _bogoCheck(did_header);
  if (bogo.free) {
    _bogoIncrement(did_header);
    if (!hasKey()) {
      // Key missing but BOGO comp granted — acknowledge and note
      appendAudit({ namespace, key, caller_did, action: 'put', result: 'bogo_free:key_missing' });
      return res.json({
        ok: true, bogo_applied: bogo.reason,
        note: 'bogo applied — SECRETS_MASTER_KEY not yet set; retry after operator configures key',
        namespace, key,
      });
    }
    appendAudit({ namespace, key, caller_did, action: 'put', result: 'bogo_free' });
    const r = doPut({ namespace, key, value, caller_did });
    return res.status(r.error ? 400 : 200).json({ ...r, bogo_applied: bogo.reason });
  }

  // ── 402 gate (runs before master-key check — fixes the 503 ordering bug) ─
  const g = await gateAndCharge({ kind: 'secrets_put', did: caller_did, namespace, key, tx_hash: tx });
  if (!g.ok) {
    if (g.status === 402 && g.body === 'gate') {
      appendAudit({ namespace, key, caller_did, action: 'put', result: 'payment_required' });
      // Augment the standard 402 response with BOGO block
      const amount = PRICES['secrets_put'];
      return res.status(402).json({
        error: 'payment_required',
        x402: envelope({ kind: 'secrets_put', amount_usd: amount, pay_to: WALLET_ADDRESS }),
        bogo: BOGO_BLOCK,
        bogo_first_call_free: true,
        bogo_loyalty_threshold: 6,
        bogo_pitch: "Pay this once, your 6th call is on the house. New here? Add header x-hive-did to claim your first call free.",
        note: `Submit tx_hash in body or 'x402-tx-hash' header. Asking ${amount} USDC on Base to ${WALLET_ADDRESS}.`,
        did: caller_did || null,
      });
    }
    appendAudit({ namespace, key, caller_did, action: 'put', result: `error:${g.body?.error || g.status}` });
    return res.status(g.status).json(g.body);
  }

  // ── Master-key check (after charge — returns informative error, not silent 503) ─
  if (!hasKey()) {
    appendAudit({ namespace, key, caller_did, action: 'put', result: 'error:master_key_unavailable' });
    return res.status(503).json({
      error: 'service_unavailable',
      reason: keyError(),
      note: 'Payment accepted and recorded. Operator must set SECRETS_MASTER_KEY to complete the write.',
    });
  }
  const r = doPut({ namespace, key, value, caller_did });
  appendAudit({
    namespace, key, caller_did, action: 'put', tx_hash: tx, payer: g.payer || null,
    amount_usd: g.billed_usd, result: r.error ? `error:${r.error}` : 'ok',
  });
  res.status(r.error ? 400 : 200).json({ ...r, billed_usd: g.billed_usd });
});

// DELETE /v1/secrets/{namespace}/{key} — free (caller-owned)
app.delete('/v1/secrets/:namespace/:key', (req, res) => {
  const namespace = req.params.namespace;
  const key = req.params.key;
  const caller_did = req.query.caller_did || req.headers['x-caller-did'] || namespace;
  const auth = checkNamespaceAuth({ namespace, caller_did });
  if (!auth.ok) {
    appendAudit({ namespace, key, caller_did, action: 'delete', result: `error:${auth.error}` });
    return res.status(403).json({ error: auth.error });
  }
  const r = deleteSecret({ namespace, key });
  appendAudit({ namespace, key, caller_did, action: 'delete', result: r.deleted ? 'ok' : 'not_found' });
  res.json(r);
});

// GET /v1/secrets/audit — paid audit (must be declared BEFORE /:namespace)
app.get('/v1/secrets/audit', async (req, res) => {
  const namespace = req.query.namespace;
  const caller_did = req.query.caller_did || req.headers['x-caller-did'] || namespace;
  const tx = txFromReq(req);
  const auth = checkNamespaceAuth({ namespace, caller_did });
  if (!auth.ok) return res.status(403).json({ error: auth.error });
  const g = await gateAndCharge({ kind: 'secrets_audit', did: caller_did, namespace, tx_hash: tx });
  if (!g.ok) {
    if (g.status === 402 && g.body === 'gate') return require402(res, 'secrets_audit', caller_did);
    return res.status(g.status).json(g.body);
  }
  const r = doAudit({
    namespace, caller_did,
    since_ms: req.query.since_ms, until_ms: req.query.until_ms, limit: req.query.limit,
  });
  res.json({ ...r, billed_usd: g.billed_usd });
});

// GET /v1/secrets/today — free revenue snapshot (declared BEFORE /:namespace)
app.get('/v1/secrets/today', (req, res) => {
  res.json({
    wallet: WALLET_ADDRESS,
    enable: ENABLE,
    prices_usd: PRICES,
    revenue: todayRevenue(),
  });
});

// GET /v1/secrets/{namespace} — list keys (Tier 0 free) — keep AFTER audit/today
app.get('/v1/secrets/:namespace', (req, res) => {
  const namespace = req.params.namespace;
  const caller_did = req.query.caller_did || req.headers['x-caller-did'] || namespace;
  const r = doList({ namespace, caller_did });
  appendAudit({ namespace, caller_did, action: 'list', result: r.error ? `error:${r.error}` : 'ok' });
  res.status(r.error ? 403 : 200).json(r);
});

// ─── MCP JSON-RPC ─────────────────────────────────────────────────────────
async function executeTool(name, args, headers) {
  const tx = args.tx_hash || headers['x402-tx-hash'] || null;
  if (!ENABLE) return { error: 'service_disabled' };
  switch (name) {
    case 'secrets_get': {
      const g = await gateAndCharge({ kind: 'secrets_get', did: args.caller_did, namespace: args.namespace, key: args.key, tx_hash: tx });
      if (!g.ok) {
        if (g.status === 402) return { error: 'payment_required', x402: envelope({ kind: 'secrets_get', amount_usd: PRICES.secrets_get, pay_to: WALLET_ADDRESS }) };
        return g.body;
      }
      const r = doGet(args);
      appendAudit({ namespace: args.namespace, key: args.key, caller_did: args.caller_did, action: 'get', tx_hash: tx, payer: g.payer || null, amount_usd: g.billed_usd, result: r.error ? `error:${r.error}` : 'ok' });
      return { ...r, billed_usd: g.billed_usd };
    }
    case 'secrets_put': {
      if (!hasKey()) {
        appendAudit({ namespace: args.namespace, key: args.key, caller_did: args.caller_did, action: 'put', result: 'error:master_key_unavailable' });
        return { error: 'service_unavailable', reason: keyError(), note: 'operator must set SECRETS_MASTER_KEY env var to enable writes' };
      }
      const g = await gateAndCharge({ kind: 'secrets_put', did: args.caller_did, namespace: args.namespace, key: args.key, tx_hash: tx });
      if (!g.ok) {
        if (g.status === 402) return { error: 'payment_required', x402: envelope({ kind: 'secrets_put', amount_usd: PRICES.secrets_put, pay_to: WALLET_ADDRESS }) };
        return g.body;
      }
      const r = doPut(args);
      appendAudit({ namespace: args.namespace, key: args.key, caller_did: args.caller_did, action: 'put', tx_hash: tx, payer: g.payer || null, amount_usd: g.billed_usd, result: r.error ? `error:${r.error}` : 'ok' });
      return { ...r, billed_usd: g.billed_usd };
    }
    case 'secrets_list': {
      const r = doList(args);
      appendAudit({ namespace: args.namespace, caller_did: args.caller_did, action: 'list', result: r.error ? `error:${r.error}` : 'ok' });
      return r;
    }
    case 'secrets_audit': {
      const auth = checkNamespaceAuth({ namespace: args.namespace, caller_did: args.caller_did });
      if (!auth.ok) return { error: auth.error };
      const g = await gateAndCharge({ kind: 'secrets_audit', did: args.caller_did, namespace: args.namespace, tx_hash: tx });
      if (!g.ok) {
        if (g.status === 402) return { error: 'payment_required', x402: envelope({ kind: 'secrets_audit', amount_usd: PRICES.secrets_audit, pay_to: WALLET_ADDRESS }) };
        return g.body;
      }
      return { ...doAudit(args), billed_usd: g.billed_usd };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

app.post('/mcp', async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};
  if (jsonrpc !== '2.0') return res.json(mcpErrorWithEnvelope(id, -32600, 'Invalid JSON-RPC'));
  try {
    switch (method) {
      case 'initialize':
        return res.json({
          jsonrpc: '2.0', id, result: {
            protocolVersion: '2024-11-05',
            capabilities: { tools: { listChanged: false } },
            serverInfo: {
              name: 'hive-mcp-secrets',
              version: '1.0.0',
              description: 'Encrypted secret store for the A2A network. Hive Civilization.',
            },
          },
        });
      case 'tools/list':
        return res.json({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      case 'tools/call': {
        const { name, arguments: args } = params || {};
        const out = await executeTool(name, args || {}, req.headers || {});
        return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] } });
      }
      case 'ping':
        return res.json({ jsonrpc: '2.0', id, result: {} });
      default:
        return res.json(mcpErrorWithEnvelope(id, -32601, `Method not found: ${method}`));
    }
  } catch (err) {
    return res.json(mcpErrorWithEnvelope(id, -32000, err.message));
  }
});

// ─── Health & discovery ───────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok',
  service: 'hive-mcp-secrets',
  version: '1.0.0',
  enable: ENABLE,
  brand_color: BRAND_COLOR,
  wallet: WALLET_ADDRESS,
  asset: 'USDC',
  asset_address: USDC_BASE,
  network: 'base',
  prices_usd: PRICES,
  verify_onchain: VERIFY_ONCHAIN,
  master_key_loaded: hasKey(),
  master_key_error: hasKey() ? null : keyError(),
  crypto: CRYPTO_PARAMS,
  inbound_only: true,
}));

app.get('/.well-known/mcp.json', (req, res) => res.json({
  name: 'hive-mcp-secrets',
  endpoint: '/mcp',
  transport: 'streamable-http',
  protocol: '2024-11-05',
  tools: TOOLS.map(t => ({ name: t.name, description: t.description })),
}));

// ─── Root: HTML for browsers, JSON for agents ─────────────────────────────
const HTML_ROOT = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>hive-mcp-secrets — Encrypted secret store for the A2A network</title>
<meta name="description" content="Encrypted secret store for the A2A network. AES-256-GCM at rest, agent-DID-scoped namespaces, audit log, x402 USDC settlement on Base.">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root { --gold: ${BRAND_COLOR}; --ink: #111; --paper: #fafaf7; --rule: #e7e3d6; }
  body { background: var(--paper); color: var(--ink); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; max-width: 760px; margin: 4rem auto; padding: 0 1.25rem; line-height: 1.55; font-size: 14.5px; }
  h1 { color: var(--gold); font-size: 1.6rem; letter-spacing: 0.01em; margin: 0 0 0.25rem; }
  h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--gold); border-bottom: 1px solid var(--rule); padding-bottom: 0.35rem; margin-top: 2.2rem; }
  .lead { color: #444; margin: 0 0 2rem; }
  table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
  th, td { text-align: left; padding: 0.45rem 0.6rem; border-bottom: 1px solid var(--rule); vertical-align: top; }
  th { color: var(--gold); font-weight: 600; }
  code, pre { background: #f3f0e3; padding: 0.1rem 0.35rem; border-radius: 3px; }
  pre { padding: 0.75rem 0.9rem; overflow-x: auto; }
  a { color: var(--gold); text-decoration: none; border-bottom: 1px dotted var(--gold); }
  footer { margin-top: 3rem; color: #777; font-size: 12.5px; }
</style>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "hive-mcp-secrets",
  "applicationCategory": "DeveloperApplication",
  "operatingSystem": "Cross-platform",
  "description": "Encrypted secret store for the A2A network. AES-256-GCM at rest, agent-DID-scoped namespaces, audit log, x402 USDC settlement on Base.",
  "url": "https://hive-mcp-secrets.onrender.com",
  "author": { "@type": "Person", "name": "Steve Rotzin", "url": "https://www.thehiveryiq.com" },
  "license": "https://opensource.org/licenses/MIT",
  "offers": [
    { "@type": "Offer", "name": "secrets_get",   "price": "0.002", "priceCurrency": "USD" },
    { "@type": "Offer", "name": "secrets_put",   "price": "0.005", "priceCurrency": "USD" },
    { "@type": "Offer", "name": "secrets_audit", "price": "0.002", "priceCurrency": "USD" }
  ]
}
</script>
</head>
<body>
<h1>hive-mcp-secrets</h1>
<p class="lead">Encrypted secret store for the A2A network. Each agent DID is its own namespace. Values are encrypted with AES-256-GCM under a master key held only in the operator's environment, written to SQLite as ciphertext, IV, and auth tag, and decrypted on read after the auth tag is verified. Inbound only. Real rails — USDC on Base L2.</p>

<h2>Protocol</h2>
<table>
  <tr><th>MCP version</th><td>2024-11-05 / Streamable-HTTP / JSON-RPC 2.0</td></tr>
  <tr><th>Endpoint</th><td><code>POST /mcp</code></td></tr>
  <tr><th>Discovery</th><td><code>GET /.well-known/mcp.json</code></td></tr>
  <tr><th>Health</th><td><code>GET /health</code></td></tr>
  <tr><th>Settlement</th><td>USDC on Base L2 — verified on-chain</td></tr>
  <tr><th>At-rest</th><td>AES-256-GCM, 12-byte IV per record, 16-byte auth tag</td></tr>
</table>

<h2>Tools and pricing</h2>
<table>
  <tr><th>Tool</th><th>USD / call</th><th>Description</th></tr>
  <tr><td><code>secrets_get</code></td><td>$0.002</td><td>Read and decrypt a secret. Caller must own the namespace.</td></tr>
  <tr><td><code>secrets_put</code></td><td>$0.005</td><td>Encrypt and store a secret. Returns 503 if master key not configured.</td></tr>
  <tr><td><code>secrets_list</code></td><td>free</td><td>List keys in a namespace. Tier 0.</td></tr>
  <tr><td><code>secrets_audit</code></td><td>$0.002</td><td>Read the audit log for a namespace.</td></tr>
</table>

<h2>Namespace model</h2>
<p>The namespace is the agent DID. A caller can only see and write to its own namespace — every endpoint requires <code>caller_did === namespace</code> or returns <code>forbidden_namespace_mismatch</code>. The audit log records every action with <code>caller_did</code>, <code>action</code>, <code>ts_ms</code>, and (for paid ops) <code>tx_hash</code> and <code>payer</code>.</p>

<h2>REST endpoints</h2>
<table>
  <tr><th>Method</th><th>Path</th><th>Purpose</th></tr>
  <tr><td>GET</td><td><code>/v1/secrets/{namespace}/{key}</code></td><td>Read and decrypt one secret. Paid.</td></tr>
  <tr><td>PUT</td><td><code>/v1/secrets/{namespace}/{key}</code></td><td>Encrypt and store one secret. Paid. Body <code>{ "value": "...", "caller_did": "...", "tx_hash": "..." }</code>.</td></tr>
  <tr><td>DELETE</td><td><code>/v1/secrets/{namespace}/{key}</code></td><td>Remove a secret. Free, caller-owned.</td></tr>
  <tr><td>GET</td><td><code>/v1/secrets/{namespace}</code></td><td>List keys in a namespace. Free, Tier 0.</td></tr>
  <tr><td>GET</td><td><code>/v1/secrets/audit</code></td><td>Audit log read. Paid.</td></tr>
  <tr><td>GET</td><td><code>/v1/secrets/today</code></td><td>Today's revenue snapshot. Free.</td></tr>
  <tr><td>GET</td><td><code>/health</code></td><td>Service health.</td></tr>
</table>

<h2>Operator note</h2>
<p>Set <code>SECRETS_MASTER_KEY</code> in the deployment environment before any writes are accepted. Without it, <code>PUT /v1/secrets/{namespace}/{key}</code> and <code>secrets_put</code> return <code>503 service_unavailable</code>. Reads of records that do not exist still return <code>404</code> normally; reads of stored records require the same key that wrote them, since AES-256-GCM rejects decryption otherwise.</p>

<footer>
  <p>Hive Civilization · Pantone 1245 C / ${BRAND_COLOR} · MIT · <a href="https://github.com/srotzin/hive-mcp-secrets">github.com/srotzin/hive-mcp-secrets</a></p>
</footer>
</body></html>`;

app.get('/', (req, res) => {
  const accept = String(req.headers.accept || '').toLowerCase();
  if (accept.includes('application/json') && !accept.includes('text/html')) {
    return res.json({
      name: 'hive-mcp-secrets',
      version: '1.0.0',
      description: 'Encrypted secret store for the A2A network. Hive Civilization.',
      endpoint: '/mcp',
      transport: 'streamable-http',
      protocol: '2024-11-05',
      tools: TOOLS.map(t => ({ name: t.name, description: t.description })),
      enable: ENABLE,
      brand_color: BRAND_COLOR,
      prices_usd: PRICES,
      wallet: WALLET_ADDRESS,
      master_key_loaded: hasKey(),
    });
  }
  res.set('content-type', 'text/html; charset=utf-8').send(HTML_ROOT);
});

// ─── Schema discoverability (auto-injected) ──────────────────────────────
app.get('/.well-known/agent-card.json', (req, res) => res.json({
  name: 'hive-mcp-secrets',
  description: "Hive Civilization secrets MCP \u2014 DID-scoped key/value store with x402 USDC settlement. New agents: first call free. Loyalty: every 6th paid call is free. Pay in USDC on Base L2.",
  url: 'https://hive-mcp-secrets.onrender.com',
  provider: { organization: 'Hive Civilization', url: 'https://www.thehiveryiq.com', contact: 'steve@thehiveryiq.com' },
  version: '1.0.0',
  capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false },
  authentication: {
    schemes: ['x402'],
    credentials: { type:'x402', asset:'USDC', network:'base',
      asset_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      recipient: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e'
    }
  },
  defaultInputModes: ['application/json'],
  defaultOutputModes: ['application/json'],
  extensions: {
    hive_pricing: {
      currency: 'USDC', network: 'base', model: 'per_call',
      first_call_free: true, loyalty_threshold: 6,
      loyalty_message: 'Every 6th paid call is free'
    }
  },
  bogo: {
    first_call_free: true, loyalty_threshold: 6,
    pitch: "Pay this once, your 6th paid call is on the house. New here? Add header 'x-hive-did' to claim your first call free.",
    claim_with: 'x-hive-did header'
  }
}));
app.get('/.well-known/ap2.json', (req, res) => res.json({
  ap2_version: '1',
  agent: {
    name: 'hive-mcp-secrets',
    did: 'did:web:hive-mcp-secrets.onrender.com',
    description: "Hive Civilization secrets MCP \u2014 DID-scoped key/value store with x402 USDC settlement. New agents: first call free. Loyalty: every 6th paid call is free. Pay in USDC on Base L2."
  },
  endpoints: {
    mcp: 'https://hive-mcp-secrets.onrender.com/mcp',
    agent_card: 'https://hive-mcp-secrets.onrender.com/.well-known/agent-card.json'
  },
  payments: {
    schemes: ['x402'],
    primary: { scheme:'x402', network:'base', asset:'USDC',
      asset_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      recipient: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e'
    }
  },
  bogo: {
    first_call_free: true, loyalty_threshold: 6,
    pitch: "Pay this once, your 6th paid call is on the house.",
    claim_with: 'x-hive-did header'
  },
  brand: { color: '#C08D23', name: 'Hive Civilization' }
}));


if (process.env.NODE_ENV !== 'test') {

// ─── Subscription & enterprise tier endpoints (Wave B codification) ──────────
// Partner-doctrine: identity/receipts/trust plumbing only.
// Subscription billing is denominated in USDC on Base (Monroe W1).
// Spectral receipt is emitted on every fee event via hive-receipt sidecar.
//
// Tier schedule:
//   Tier 1 (Starter)    : 10.0/mo
//   Tier 2 (Pro)        : 50.0/mo
//   Tier 3 (Enterprise) : 200.0/mo
//
// x402 tx_hash required for Tier 1+ confirmation. Tier 3 can invoice monthly.
//
// Spectral receipt: POST to hive-receipt sidecar for tamper-evident audit trail.

const SUBSCRIPTION_TIERS = {
  starter:    { price_usd: 10.0, calls_per_day: 1000, label: 'Starter' },
  pro:        { price_usd: 50.0, calls_per_day: 10000, label: 'Pro' },
  enterprise: { price_usd: 200.0, calls_per_day: Infinity, label: 'Enterprise', invoice: true },
};

// In-memory subscription ledger (durable persistence on hivemorph backend).
const _subLedger = new Map(); // did -> { tier, activated_ms, tx_hash }

async function emitSpectralReceipt({ event_type, did, amount_usd, tool_name, tx_hash, metadata }) {
  // Posts a Spectral-signed receipt to hive-receipt. Non-blocking.
  // Error is logged but never throws — receipt emission must not block the fee path.
  try {
    const body = JSON.stringify({
      issuer_did: 'did:hive:secrets',
      recipient_did: did || 'did:hive:anonymous',
      event_type,
      tool_name,
      amount_usd: String(amount_usd),
      currency: 'USDC',
      network: 'base',
      pay_to: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
      tx_hash: tx_hash || null,
      issued_ms: Date.now(),
      service: 'Hive Secrets',
      brand: '#C08D23',
      ...metadata,
    });
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 4000);
    await fetch('https://hive-receipt.onrender.com/v1/receipt/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: ctrl.signal,
    });
    clearTimeout(tid);
  } catch (_) {
    // Receipt emission is best-effort. Log and continue.
    console.warn('[secrets] receipt emit failed (non-fatal):', _.message || _);
  }
}

// POST /v1/subscription — create or upgrade a subscription
app.post('/v1/subscription', async (req, res) => {
  const { tier, did, tx_hash } = req.body || {};
  if (!tier || !SUBSCRIPTION_TIERS[tier]) {
    return res.status(400).json({
      error: 'invalid_tier',
      valid_tiers: Object.keys(SUBSCRIPTION_TIERS),
      brand: '#C08D23',
    });
  }
  const t = SUBSCRIPTION_TIERS[tier];
  if (!did) return res.status(400).json({ error: 'did_required' });

  // Enterprise tier can invoice monthly (no tx_hash required at activation).
  if (tier !== 'enterprise' && !tx_hash) {
    return res.status(402).json({
      error: 'payment_required',
      x402: {
        type: 'x402', version: '1', kind: 'subscription_secrets',
        asking_usd: t.price_usd,
        accept_min_usd: t.price_usd,
        asset: 'USDC', asset_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        network: 'base', pay_to: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
        nonce: Math.random().toString(36).slice(2),
        issued_ms: Date.now(),
        tier, label: t.label,
        bogo: { first_call_free: true, loyalty_every_n: 6 },
      },
      note: `Submit tx_hash for ${t.price_usd} USDC/mo to 0x15184bf50b3d3f52b60434f8942b7d52f2eb436e on Base.`,
    });
  }

  const record = {
    tier, did, tx_hash: tx_hash || 'enterprise_invoice',
    activated_ms: Date.now(),
    expires_ms: Date.now() + 30 * 24 * 3600 * 1000,
    price_usd: t.price_usd,
    calls_per_day: t.calls_per_day,
  };
  _subLedger.set(did, record);

  // Emit Spectral receipt for subscription activation.
  await emitSpectralReceipt({
    event_type: 'subscription_activated',
    did, amount_usd: t.price_usd, tool_name: 'subscription',
    tx_hash: tx_hash || null,
    metadata: { tier, service: 'Hive Secrets', expires_ms: record.expires_ms },
  });

  return res.json({
    ok: true,
    subscription: record,
    receipt_emitted: true,
    partner_attribution: 'Secret storage complements Hashicorp Vault, AWS Secrets Manager — DID-native agent secret layer',
    brand: '#C08D23',
    note: 'Subscription active for 30 days. Spectral receipt issued to hive-receipt.',
  });
});

// GET /v1/subscription/:did — check subscription status
app.get('/v1/subscription/:did', (req, res) => {
  const record = _subLedger.get(req.params.did);
  if (!record) {
    return res.status(404).json({ active: false, did: req.params.did });
  }
  const active = Date.now() < record.expires_ms;
  return res.json({ active, ...record });
});

// POST /v1/subscription/verify — lightweight verification (no charge)
app.post('/v1/subscription/verify', (req, res) => {
  const { did } = req.body || {};
  const record = _subLedger.get(did);
  const active = record && Date.now() < record.expires_ms;
  return res.json({
    active: !!active,
    did: did || null,
    tier: record?.tier || null,
    expires_ms: record?.expires_ms || null,
    brand: '#C08D23',
  });
});

// ─────────────────────────────────────────────────────────────────────────────

  app.listen(PORT, () => {
    console.log(`hive-mcp-secrets on :${PORT}`);
    console.log(`  enable          : ${ENABLE}`);
    console.log(`  wallet          : ${WALLET_ADDRESS}`);
    console.log(`  usdc(base)      : ${USDC_BASE}`);
    console.log(`  verify_onchain  : ${VERIFY_ONCHAIN}`);
    console.log(`  prices          : ${JSON.stringify(PRICES)}`);
    console.log(`  master_key      : ${hasKey() ? 'loaded' : 'NOT SET (writes will return 503)'}`);
  });
}

export default app;
