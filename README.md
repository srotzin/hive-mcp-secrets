# hive-mcp-secrets

[![srotzin/hive-mcp-secrets MCP server](https://glama.ai/mcp/servers/srotzin/hive-mcp-secrets/badges/score.svg)](https://glama.ai/mcp/servers/srotzin/hive-mcp-secrets)

**Encrypted secret store for the A2A network — Hive Civilization.** AES-256-GCM at rest, agent-DID-scoped namespaces, audit log, x402 USDC settlement on Base L2. MCP `2024-11-05`. Inbound only.

Agents put encrypted secrets keyed by `(namespace, key)` and retrieve them later. The namespace is the agent DID — a caller can only see and write to its own namespace. The master key lives in the operator's environment and is never committed, logged, or returned over the wire.

```
brand : Hive Civilization gold #C08D23 (Pantone 1245 C)
spec  : MCP 2024-11-05 / Streamable-HTTP / JSON-RPC 2.0
wallet: W1 MONROE 0x15184bf50b3d3f52b60434f8942b7d52f2eb436e (Base)
crypto: AES-256-GCM, 12-byte IV per record, 16-byte auth tag, node:crypto
```

## Quick start

```bash
git clone https://github.com/srotzin/hive-mcp-secrets
cd hive-mcp-secrets
npm install

# 32 random bytes as hex — never commit this value
export SECRETS_MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

npm start
# hive-mcp-secrets on :3000
```

Hosted endpoint: `https://hive-mcp-secrets.onrender.com/mcp`

## Tools and pricing

| Tool | USD / call | Notes |
|---|---|---|
| `secrets_get`   | $0.002 | Read and decrypt a secret. Caller must own the namespace. |
| `secrets_put`   | $0.005 | Encrypt and store a secret. Returns 503 if master key not configured. |
| `secrets_list`  | free   | List keys in a namespace. Tier 0. |
| `secrets_audit` | $0.002 | Read the audit log for a namespace. |

All payments are inbound. Submit a Base USDC `tx_hash` (caller → W1) in the request body or `x402-tx-hash` header. The shim reads the receipt from Base RPC, decodes the USDC `Transfer` log, and verifies recipient and amount before serving the call.

## Operator note — master key required for writes

`hive-mcp-secrets` reads `SECRETS_MASTER_KEY` from the process environment at startup.

- If set, it is parsed as 64-char hex → 32 raw bytes; or as base64 → 32 raw bytes; or otherwise SHA-256 hashed to 32 bytes.
- If not set, writes return `503 service_unavailable` with `reason: "SECRETS_MASTER_KEY not set"`. Reads of records that do not exist return `404` as usual; reads of stored records require the same key that wrote them, since AES-256-GCM rejects decryption with any other key.

The key is never committed to the repository, never logged, and never returned over the wire. Operators are expected to set it in the deployment environment (Render env var, Kubernetes secret, etc.) before enabling production traffic. Rotating the key invalidates all previously stored ciphertexts.

## Namespace model

The `namespace` parameter on every endpoint is the agent DID that owns the data. Every endpoint enforces `caller_did === namespace` and returns `forbidden_namespace_mismatch` otherwise. There is no superuser, no cross-namespace read, and no multi-DID sharing in v1.

The audit log is per-namespace and records every action — `get`, `put`, `delete`, `list`, `audit`, plus the negative paths `payment_required`, `error:not_found`, `error:integrity_check_failed`, etc. Entries store `caller_did`, `action`, `ts_ms`, and (for paid ops) `tx_hash`, `payer`, and `amount_usd`.

## REST endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET`    | `/v1/secrets/{namespace}/{key}` | Read and decrypt one secret. **Paid**. |
| `PUT`    | `/v1/secrets/{namespace}/{key}` | Encrypt and store one secret. **Paid**. Returns `503` without master key. |
| `DELETE` | `/v1/secrets/{namespace}/{key}` | Remove a secret. Free, caller-owned. |
| `GET`    | `/v1/secrets/{namespace}`       | List keys in a namespace. Free, Tier 0. |
| `GET`    | `/v1/secrets/audit`             | Audit log read. **Paid**. Query: `namespace`, `caller_did`, `since_ms?`, `until_ms?`, `limit?`. |
| `GET`    | `/v1/secrets/today`             | Today's revenue snapshot. Free. |
| `GET`    | `/health`                       | Service health, including `master_key_loaded`. |
| `GET`    | `/.well-known/mcp.json`         | MCP discovery. |
| `POST`   | `/mcp`                          | MCP JSON-RPC. |

### `PUT /v1/secrets/{namespace}/{key}` body

```json
{
  "value": "the-secret-string",
  "caller_did": "did:hive:0xabc...",
  "tx_hash": "0x...64-char-tx-on-base..."
}
```

Without `tx_hash`, the response is a 402 envelope:

```json
{
  "error": "payment_required",
  "x402": {
    "type": "x402", "version": "1", "kind": "secrets_put",
    "asking_usd": 0.005, "accept_min_usd": 0.005,
    "asset": "USDC", "asset_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "network": "base", "pay_to": "0x15184bf50b3d3f52b60434f8942b7d52f2eb436e",
    "nonce": "...", "issued_ms": 1714200000000
  }
}
```

## Encryption details

- Algorithm: `aes-256-gcm` (FIPS-recognized AEAD)
- Key length: 32 bytes
- IV length: 12 bytes, fresh `crypto.randomBytes(12)` per record
- Auth tag length: 16 bytes
- Storage: SQLite `secrets` table — `(namespace, key, ciphertext, iv, auth_tag, created_ms, updated_ms, version)` with PRIMARY KEY `(namespace, key)`
- Write path: `node:crypto.createCipheriv → update → final`, then `getAuthTag()`. All three values stored as base64 TEXT.
- Read path: `createDecipheriv → setAuthTag → update → final`. Any single bit flipped in `ciphertext`, `iv`, or `auth_tag` causes `final()` to throw, which surfaces as `integrity_check_failed`.

The smoke test below verifies tampered ciphertext fails to decrypt — this is real AES-GCM, not an integrity check tacked on after the fact.

## MCP usage

```bash
curl -X POST https://hive-mcp-secrets.onrender.com/mcp \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

```bash
curl -X POST https://hive-mcp-secrets.onrender.com/mcp \
  -H "content-type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":2,"method":"tools/call",
    "params":{
      "name":"secrets_put",
      "arguments":{
        "namespace":"did:hive:0xabc",
        "key":"openai_api_key",
        "value":"sk-...",
        "caller_did":"did:hive:0xabc",
        "tx_hash":"0x..."
      }
    }
  }'
```

## Local smoke test

```bash
export SECRETS_MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
npm start &
sleep 1

# Tier 0 list (empty)
curl -s "http://localhost:3000/v1/secrets/did:hive:0xa/" | jq .

# PUT without tx_hash → 402 envelope
curl -s -X PUT "http://localhost:3000/v1/secrets/did:hive:0xa/k1" \
  -H "content-type: application/json" \
  -d '{"value":"hello","caller_did":"did:hive:0xa"}' | jq .

# PUT with stub tx (set VERIFY_ONCHAIN=false locally)
VERIFY_ONCHAIN=false curl -s -X PUT "http://localhost:3000/v1/secrets/did:hive:0xa/k1" \
  -H "content-type: application/json" \
  -d '{"value":"hello","caller_did":"did:hive:0xa","tx_hash":"0xtest"}' | jq .

# GET round-trip
VERIFY_ONCHAIN=false curl -s "http://localhost:3000/v1/secrets/did:hive:0xa/k1?caller_did=did:hive:0xa&tx_hash=0xtest" | jq .
```

## Hosting

Deployed to Render: `srv hive-mcp-secrets`, `oregon`, `starter`, `autoDeploy=true`. The Render env var `SECRETS_MASTER_KEY` is **the operator's responsibility to set**. Without it, the deployed service still runs, `/health` reports `master_key_loaded: false`, and writes return `503`.

## License

MIT — see `LICENSE`.

## Hive Civilization Directory

Part of the Hive Civilization — agent-native financial infrastructure.

- Endpoint Directory: https://thehiveryiq.com
- Live Leaderboard: https://hive-a2amev.onrender.com/leaderboard
- Revenue Dashboard: https://hivemine-dashboard.onrender.com
- Other MCP Servers: https://github.com/srotzin?tab=repositories&q=hive-mcp

Brand: #C08D23
<!-- /hive-footer -->
