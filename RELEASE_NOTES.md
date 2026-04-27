# hive-mcp-secrets v1.0.0

Encrypted secret store for the A2A network — Hive Civilization. Inbound only. MCP `2024-11-05`.

## What it does

Agents put encrypted secrets keyed by `(namespace, key)` and retrieve them later. The namespace is the agent DID — a caller can only see and write its own namespace. AES-256-GCM at rest under an operator-held master key. Per-namespace audit log.

## Settlement

USDC on Base L2 → W1 MONROE `0x15184bf50b3d3f52b60434f8942b7d52f2eb436e`. Verified on-chain via `ethers.JsonRpcProvider(BASE_RPC_URL).getTransactionReceipt(tx_hash)`, USDC `Transfer(address,address,uint256)` log decoded, recipient and 6-decimal amount checked against the asking price.

## Pricing

| Tool            | USD / call |
|---              |---         |
| `secrets_get`   | $0.002     |
| `secrets_put`   | $0.005     |
| `secrets_audit` | $0.002     |
| `secrets_list`  | free       |

## Real rails (no mocks)

- `better-sqlite3` WAL persistence at `/tmp/secrets.db`. Tables: `secrets`, `audit_log`, `revenue` (with `tx_hash UNIQUE` for replay protection).
- `node:crypto` AES-256-GCM. 12-byte fresh IV per record. 16-byte auth tag verified on every read; tampering surfaces as `integrity_check_failed`.
- `ethers.verifyMessage(message, signature)` for owner DID claim binding.
- `ethers.JsonRpcProvider(BASE_RPC_URL).getTransactionReceipt(tx_hash)` against Base mainnet, USDC `Transfer` log decode, recipient and amount validation.

## Master key handling

`SECRETS_MASTER_KEY` is sourced from the process environment. Accepted forms: 64-char hex, base64-encoded 32 bytes, or any passphrase (SHA-256 hashed to 32 bytes). The key is never logged, never persisted, never returned over the wire.

If the env var is not set, `/health` reports `master_key_loaded: false`, writes return `503 service_unavailable`, and the v1.0.0 deployment to Render ships with the env var **deliberately unset** — the operator must add it.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET`    | `/v1/secrets/{namespace}/{key}` | Read and decrypt one secret. Paid. |
| `PUT`    | `/v1/secrets/{namespace}/{key}` | Encrypt and store one secret. Paid. 503 without master key. |
| `DELETE` | `/v1/secrets/{namespace}/{key}` | Remove a secret. Free, caller-owned. |
| `GET`    | `/v1/secrets/{namespace}`       | List keys in a namespace. Free, Tier 0. |
| `GET`    | `/v1/secrets/audit`             | Audit log read. Paid. |
| `GET`    | `/v1/secrets/today`             | Today's revenue snapshot. Free. |
| `GET`    | `/health`                       | Service health. |
| `GET`    | `/.well-known/mcp.json`         | MCP discovery. |
| `POST`   | `/mcp`                          | MCP JSON-RPC. |

## Smoke

- Local (with `SECRETS_MASTER_KEY` set, `VERIFY_ONCHAIN=false`):
  - `PUT /v1/secrets/did:hive:0xa/k1` round-trips with `GET /v1/secrets/did:hive:0xa/k1` returning the original plaintext.
  - Tampering one byte of stored ciphertext causes the next `GET` to surface `integrity_check_failed` — confirms AES-GCM auth tag is enforced.
- Live (without `SECRETS_MASTER_KEY` set):
  - `/health` returns `master_key_loaded: false`.
  - `PUT /v1/secrets/...` returns `503 service_unavailable, reason: SECRETS_MASTER_KEY not set`.

## Brand and voice

Hive Civilization gold `#C08D23` (Pantone 1245 C). Stripe Docs voice — no exclamation, emoji, or superlatives.

## License

MIT.
