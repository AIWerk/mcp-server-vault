# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial v0.1.0: 6 tools (`list_vault_items`, `get_vault_metadata`, `reveal_secret_via_send`, `get_totp_code`, `save_generated_secret`, `health_check`)
- Auth: Bitwarden Personal API (OAuth2 client_credentials) via `VAULT_CLIENT_ID` + `VAULT_CLIENT_SECRET`
- Crypto: full Bitwarden E2E decryption chain — PBKDF2 / Argon2id master key → HKDF stretched key → vault symkey → org key (RSA-OAEP) → cipher decryption (AES-256-CBC + HMAC-SHA256)
- Bitwarden Send creation with client-side key generation (HKDF derivation) for `reveal_secret_via_send`
- TOTP computation (RFC 6238) for `get_totp_code` — supports `otpauth://` URI and bare base32 secrets
- DRY_RUN + READ_ONLY orthogonal safety layers
- 5 safety-claim tests: no value leak, collection whitelist, no update/delete tools, no-overwrite, Send TTL enforcement
- Tests: vitest, 47 tests (unit + safety)
- README with setup, env-vars, tool table
