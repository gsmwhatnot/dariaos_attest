# Daria Attestation Service

A standalone Android attestation verification service with a browser-based admin console for API key management and audit logging.

## Features
- Verifies SafetyNet / KeyMint attestation chains, including optional Remote Key Provisioning (RKP) enforcement.
- REST API (`POST /api/v1/verify`) that returns `Authorized`/`Unauthorized`.
- Admin panel (`/admin`) to manage API keys.
- Structured logging: access/audit JSONL files plus a `device_attest.jsonl` ledger keyed by device serial.

## Quick Start
```bash
git clone https://github.com/gsmwhatnot/dariaos_attest.git
cd dariaos_attest
npm install
cp .env.example .env   # adjust values as needed
npm start
```
The service listens on `PORT` (default `8080`). Visit `http://localhost:8080/admin` and sign in with the default admin password (you will be prompted to change it).

## Environment Variables
You can configure the service via environment variables or a dotenv file (`.env`). Defaults are shown in parentheses.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SITE_NAME` | `"Daria Attestation Service"` | Display name used in the admin UI and health endpoint. |
| `PORT` | `8080` | HTTP port to bind the Express server. |
| `BASE_URL` | `""` | Public origin + base path when running behind a reverse proxy. Leave blank for direct/relative hosting. |
| `DEFAULT_ADMIN_PASSWORD` | `"admin"` | Seed password for the admin account; must be changed on first login. |
| `ATTESTATION_TIMEOUT` | `600` | Maximum allowed age (seconds) between an attestation's timestamp and the current time. |
| `ENFORCE_API_KEY` | `false` | When `true`, `/api/v1/verify` requires a valid API key; when `false` the endpoint skips key checks. |
| `ENFORCE_REMOTE_KEY_PROVISION` | `false` | When `true`, only RKP (CBOR) attestation chains are accepted. See [RKP docs](https://source.android.com/docs/security/features/remote-key-provisioning/attestation). |
| `SESSION_SECRET` | `"change-me-session-secret"` | Secret used to sign admin session tokens. |
| `GOOGLE_ATTESTATION_ROOTS_URL` | Google default | Override for the Google root certificate bundle. |
| `GOOGLE_ATTESTATION_STATUS_URL` | Google default | Override for the Google certificate revocation list. |
| `DEBUG_ATTESTATION` | unset | Set to `1` to print a rich ASN.1 dump for each verify request. |

See `.env.example` for a annotated template.

## API Overview
- `POST /api/v1/verify`
  - Body: `{ "apiKey": "...", "data": "dot-delimited-base64-chain" }`
  - Response: `{ "reason": "Authorized" | "Unauthorized", "errorcode": 200 | 401 }`
  - When `debug=1` query param is present, the server logs the decoded ASN.1 structure to stdout.

Example request/response:

```bash
curl -X POST http://localhost:8080/api/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "apiKey": "01234567-89ab-cdef-0123-456789abcdef",
    "data": "MIICIjCC...base64 chain trimmed..."
  }'
```

```json
{
  "reason": "Unauthorized",
  "errorcode": 401
}
```

## Logs & Storage
- `logs/access_YYYY-MM-DD.jsonl` – per-request API telemetry (status, masked API key, device info).
- `logs/audit_YYYY-MM-DD.jsonl` – admin actions (login, key lifecycle).
- `logs/device_attest.jsonl` – JSON object `{ "devices": [ { device, value: [ { model, serial, createdAt, updatedAt, keyDescription } ] } ] }` updated on each verify.
- Persistent JSON stores live under `data/` (admin account, API keys, cached Google roots/CRL).

## Development Notes
- Source is organized under `src/` with dedicated modules for chain validation (`core/chain.js`), device extraction (`core/device.js`), policy evaluation, debug rendering, and ledger persistence.
- The attestation decoder uses ASN.1 parsing from `node-forge` plus schema definitions in `core/attestationDecoder.js`.

## Further Reading
- [Android Keystore attestation overview](https://source.android.com/docs/security/features/keystore/attestation)

## License
Daria Open-Source License Agreement – DOSLA v1.0.
