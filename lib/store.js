/**
 * SQLite-backed encrypted secret store for hive-mcp-secrets.
 *
 * Stores AES-256-GCM ciphertext, IV, and auth_tag per (namespace, key).
 * Namespace is the agent DID — agents can only see and write to their
 * own namespace. The audit_log table captures every get/put/delete with
 * caller DID, action, ts, and pay-tx hash for billable ops.
 */

import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

const DB_PATH = process.env.DB_PATH || '/tmp/secrets.db';
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

let db;

export function openDb() {
  if (db) return db;
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      namespace   TEXT NOT NULL,
      key         TEXT NOT NULL,
      ciphertext  TEXT NOT NULL,
      iv          TEXT NOT NULL,
      auth_tag    TEXT NOT NULL,
      created_ms  INTEGER NOT NULL,
      updated_ms  INTEGER NOT NULL,
      version     INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY (namespace, key)
    );
    CREATE INDEX IF NOT EXISTS secrets_ns_idx ON secrets(namespace);

    CREATE TABLE IF NOT EXISTS audit_log (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      namespace    TEXT NOT NULL,
      key          TEXT,
      caller_did   TEXT NOT NULL,
      action       TEXT NOT NULL,
      ts_ms        INTEGER NOT NULL,
      tx_hash      TEXT,
      payer        TEXT,
      amount_usd   REAL,
      result       TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_ns_idx ON audit_log(namespace, ts_ms);
    CREATE INDEX IF NOT EXISTS audit_caller_idx ON audit_log(caller_did, ts_ms);

    CREATE TABLE IF NOT EXISTS revenue (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      kind       TEXT NOT NULL,
      did        TEXT,
      namespace  TEXT,
      key        TEXT,
      amount_usd REAL NOT NULL,
      tx_hash    TEXT UNIQUE,
      payer      TEXT,
      ts_ms      INTEGER NOT NULL
    );
  `);
  return db;
}

export function putSecret({ namespace, key, ciphertext, iv, auth_tag }) {
  const now = Date.now();
  const existing = db.prepare('SELECT version FROM secrets WHERE namespace = ? AND key = ?').get(namespace, key);
  if (existing) {
    db.prepare(`
      UPDATE secrets SET ciphertext = ?, iv = ?, auth_tag = ?, updated_ms = ?, version = version + 1
      WHERE namespace = ? AND key = ?
    `).run(ciphertext, iv, auth_tag, now, namespace, key);
    return { ok: true, namespace, key, version: existing.version + 1, created: false };
  }
  db.prepare(`
    INSERT INTO secrets (namespace, key, ciphertext, iv, auth_tag, created_ms, updated_ms, version)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
  `).run(namespace, key, ciphertext, iv, auth_tag, now, now);
  return { ok: true, namespace, key, version: 1, created: true };
}

export function getSecretRecord({ namespace, key }) {
  return db.prepare(`
    SELECT namespace, key, ciphertext, iv, auth_tag, created_ms, updated_ms, version
    FROM secrets WHERE namespace = ? AND key = ?
  `).get(namespace, key) || null;
}

export function deleteSecret({ namespace, key }) {
  const r = db.prepare('DELETE FROM secrets WHERE namespace = ? AND key = ?').run(namespace, key);
  return { ok: true, deleted: r.changes > 0 };
}

export function listKeys({ namespace }) {
  const rows = db.prepare(`
    SELECT key, created_ms, updated_ms, version
    FROM secrets WHERE namespace = ?
    ORDER BY key ASC
  `).all(namespace);
  return rows;
}

export function namespaceCount({ namespace }) {
  const r = db.prepare('SELECT COUNT(*) AS n FROM secrets WHERE namespace = ?').get(namespace);
  return r.n;
}

export function appendAudit({ namespace, key, caller_did, action, tx_hash, payer, amount_usd, result }) {
  db.prepare(`
    INSERT INTO audit_log (namespace, key, caller_did, action, ts_ms, tx_hash, payer, amount_usd, result)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    namespace,
    key || null,
    caller_did,
    action,
    Date.now(),
    tx_hash || null,
    payer || null,
    amount_usd || null,
    result,
  );
}

export function readAudit({ namespace, since_ms, until_ms, limit }) {
  const lim = Math.min(Number(limit) || 100, 1000);
  const since = Number(since_ms) || 0;
  const until = Number(until_ms) || Date.now() + 1;
  return db.prepare(`
    SELECT id, namespace, key, caller_did, action, ts_ms, tx_hash, payer, amount_usd, result
    FROM audit_log
    WHERE namespace = ? AND ts_ms BETWEEN ? AND ?
    ORDER BY ts_ms DESC
    LIMIT ?
  `).all(namespace, since, until, lim);
}

export function recordRevenue({ kind, did, namespace, key, amount_usd, tx_hash, payer }) {
  try {
    db.prepare(`
      INSERT INTO revenue (kind, did, namespace, key, amount_usd, tx_hash, payer, ts_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(kind, did || null, namespace || null, key || null, amount_usd, tx_hash || null, payer || null, Date.now());
  } catch (err) {
    // tx_hash UNIQUE — replay attempts ignored
    if (!String(err.message).includes('UNIQUE')) throw err;
  }
}

export function todayRevenue() {
  const now = new Date();
  const utcStart = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const rows = db.prepare(`
    SELECT kind, COUNT(*) AS n, COALESCE(SUM(amount_usd), 0) AS revenue_usd
    FROM revenue WHERE ts_ms >= ?
    GROUP BY kind
  `).all(utcStart);
  const total = rows.reduce((a, r) => a + r.revenue_usd, 0);
  const counts = {};
  for (const r of rows) counts[r.kind] = { calls: r.n, revenue_usd: r.revenue_usd };
  return {
    utc_day_start_ms: utcStart,
    total_revenue_usd: Number(total.toFixed(6)),
    by_kind: counts,
  };
}
