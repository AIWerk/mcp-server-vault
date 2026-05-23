# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
