# @aiwerk/mcp-server-vault

Bitwarden / Vaultwarden MCP server — BYOK vault access for AI agents.

Exposes 6 tools over stdio. Secret values are **never** sent in plaintext through `list_vault_items` or `get_vault_metadata` — secrets are delivered only through Bitwarden Sends (E2E-encrypted one-time URLs).

## Install

```bash
npx -y @aiwerk/mcp-server-vault
```

## Configure

| Variable | Required | Default | Description |
|---|---|---|---|
| `VAULT_API_BASE` | ✅ | — | Base URL of your Bitwarden/Vaultwarden instance (no trailing slash), e.g. `https://pass.aiwerk.ch` |
| `VAULT_CLIENT_ID` | ✅ | — | Personal API key `client_id` (e.g. `user.abc-def-1234`) |
| `VAULT_CLIENT_SECRET` | ✅ | — | Personal API key `client_secret` |
| `VAULT_MASTER_PASSWORD` | ✅ | — | Vault master password (used for E2E decryption key derivation) |
| `VAULT_EXPOSED_COLLECTION` | — | `mcp-exposed` | Name of the collection visible to agents |
| `VAULT_AGENT_CREATED_COLLECTION` | — | `mcp-agent-created` | Name of the collection for agent-created secrets |
| `VAULT_API_TIMEOUT_MS` | — | `15000` | HTTP timeout in milliseconds |
| `DRY_RUN` | — | `0` | Set `1` to log write operations without executing them |
| `READ_ONLY` | — | `0` | Set `1` to block all write operations (Send creation and save) |

## Auth — Personal API Key

1. Log in to your Bitwarden/Vaultwarden instance
2. Go to **Account Settings → Security → Keys → API Key**
3. Note the `client_id` and `client_secret`
4. Reference: https://bitwarden.com/help/personal-api-key/

## Vault Setup

Before using this server, create two collections in your Vaultwarden organization:
- **`mcp-exposed`** — items you want to expose to agents (your existing secrets: API keys, passwords, etc.)
- **`mcp-agent-created`** — items written by agents via `save_generated_secret`

Add items to `mcp-exposed` via the Vaultwarden web UI.

### Custom fields

Optionally add these custom fields to items in `mcp-exposed` for fine-grained control:

| Field | Type | Purpose |
|---|---|---|
| `mcp-scope` | text | Comma-separated glob list of tool/server names allowed to use this item (e.g. `stripe.*,openai`) |
| `mcp-chat-reveal-allowed` | text | `"true"` to allow chat delivery of the Send URL |
| `mcp-delivery-channel` | text | `"chat"` (default), `"telegram"`, or `"email"` |

## Tools

| Tool | Description |
|---|---|
| `list_vault_items` | List items from `mcp-exposed` and `mcp-agent-created`. Returns metadata only — no secret values. |
| `get_vault_metadata` | Get full metadata for a named item (name, type, username, URIs, custom fields, expiry). No password/secret. |
| `reveal_secret_via_send` | Reveal a secret via a Bitwarden Send (E2E-encrypted one-time URL with configurable TTL and max-views). |
| `get_totp_code` | Get the current TOTP code for a login item, including remaining seconds in the period. |
| `save_generated_secret` | Save an agent-generated secret into `mcp-agent-created`. CREATE-only — no overwrite. |
| `health_check` | Check connectivity: auth status, API version, collection visibility, item counts, latency. |

## Security model

- **Opt-in exposure**: only items in `mcp-exposed` or `mcp-agent-created` are accessible; all other items return `item_not_visible`
- **Read-only existing items**: no `update_*`, `delete_*`, or `change_*` tools exist
- **Secret value delivery via Send only**: `list_vault_items` and `get_vault_metadata` never return passwords, TOTP seeds, or api-key values
- **E2E encryption preserved**: the server decrypts vault data locally (master password stays in env vars, never sent over the wire)
- **Constrained agent writes**: `save_generated_secret` is CREATE-only into the dedicated `mcp-agent-created` collection

> **Note:** Actual `{{vault:NAME}}` placeholder resolution in tool call arguments happens in the AIWerk hosted bridge, not in this server. The bridge's resolution uses the same BYOC credentials. See the bridge-patch companion document for details.

## License

MIT — AIWerk <kontakt@aiwerk.ch>

Homepage: https://aiwerkmcp.com
