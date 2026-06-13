# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-06-12

### Added
- `save_login_item` tool. Agents can now save sign-in credentials as a real Vaultwarden login item (cipher type 1) instead of a secure note. Accepts `username`, `password`, `uri`, `totp` (seed), `notes`, `used_in`, `expires_in_days`. Requires at least one of username or password. CREATE-only into `mcp-agent-created`, with the same name-collision guard, the same E2E encryption, and READ_ONLY / DRY_RUN honored. Items created this way support `get_totp_code` when a TOTP seed is supplied.
- 8 new tests (4 tool-layer + 4 real-client): success path, field passthrough, type-1 login-cipher payload with encrypted credentials, name collision, missing-credentials rejection, READ_ONLY block (75 total).

## [0.1.4] — 2026-05-24

### Fixed
- Vaultwarden 1.36.0 omits KDF fields from `/api/sync` profile — `initializeKeys` now calls `POST /identity/accounts/prelogin` when `kdfIterations` is absent; `kdfInfo` cached per instance to avoid redundant calls
- `profile.kdf` / `profile.kdfType` fallback retained for servers that do include KDF in sync profile
- 2 new prelogin fallback tests: response shape parse + kdfInfo caching across re-auths (67 total)

## [0.1.3] — 2026-05-24

### Fixed
- `SyncProfile.kdf` field added — Vaultwarden and Bitwarden Cloud send `kdf` (not `kdfType`) in `/api/sync` profile; absence caused PBKDF2 users to fall into Argon2id branch → "Time cost is too small" error
- `initializeKeys` now resolves `profile.kdf ?? profile.kdfType ?? 0`; legacy `kdfType` alias kept for safety
- 5 new KDF field-mapping tests covering all resolution cases (65 total)

## [0.1.2] — 2026-05-24

### Fixed
- Auth `client_credentials` payload now includes `deviceType: '14'`, `deviceIdentifier` (stable UUID per VaultClient instance), `deviceName: 'aiwerk-mcp-server-vault'` — required by Vaultwarden 1.32+ and Bitwarden Cloud; absence caused 400 Bad Request in production
- `Bitwarden-Client-Version: 2026.1.0` header added to token request — required by Vaultwarden 1.36.x
- 2 new auth tests: device fields present + deviceIdentifier stability across re-auths (60 total)

## [0.1.1] — 2026-05-24

### Added
- `VAULT_REGION` env var: `self-hosted` (default, backward-compat), `us` (Bitwarden Cloud US), `eu` (Bitwarden Cloud EU)
- `resolveRegionUrls()` exported for testing — maps region to `identityBaseUrl`, `apiBaseUrl`, `webVaultUrl`
- `VAULT_API_BASE` now only required when `VAULT_REGION=self-hosted`; ignored for cloud regions
- 9 new tests covering `resolveRegionUrls` and `loadConfig` region handling

### Changed
- `VaultConfig`: `apiBase` replaced by `region`, `identityBaseUrl`, `apiBaseUrl`, `webVaultUrl`
- Auth token endpoint: `{apiBase}/identity/connect/token` → `{identityBaseUrl}/connect/token`
- API calls: `{apiBase}/api{path}` → `{apiBaseUrl}{path}`
- Send URL construction uses `webVaultUrl` (web vault base) instead of `apiBase`
- `health_check.vault_url` now returns `apiBaseUrl`

## [0.1.0] — 2026-05-22

### Added
- Initial release: 6 tools (`list_vault_items`, `get_vault_metadata`, `reveal_secret_via_send`, `get_totp_code`, `save_generated_secret`, `health_check`)
- Auth: Bitwarden Personal API (OAuth2 client_credentials) via `VAULT_CLIENT_ID` + `VAULT_CLIENT_SECRET`
- Crypto: full Bitwarden E2E decryption chain — PBKDF2 / Argon2id master key → HKDF stretched key → vault symkey → org key (RSA-OAEP) → cipher decryption (AES-256-CBC + HMAC-SHA256)
- Bitwarden Send creation with client-side key generation (HKDF derivation) for `reveal_secret_via_send`
- TOTP computation (RFC 6238) for `get_totp_code` — supports `otpauth://` URI and bare base32 secrets
- DRY_RUN + READ_ONLY orthogonal safety layers
- 5 safety-claim tests: no value leak, collection whitelist, no update/delete tools, no-overwrite, Send TTL enforcement
- `save_generated_secret` type: `password | api-key` (note type excluded — stores value in notes field, safety boundary)
- Tests: vitest, 49 tests (unit + safety)
- README with setup, env-vars, tool table
