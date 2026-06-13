#!/usr/bin/env node
import { realpathSync } from 'fs';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import {
  VaultConfigError,
  VaultAuthError,
  VaultConnectionError,
  VaultItemNotFound,
  VaultFieldNotPresent,
  VaultNameCollision,
  VaultWriteForbidden,
  VaultPayloadTooLarge,
  VaultCollectionMissing,
  VaultTOTPNotConfigured,
  VaultEmpty,
  VaultTimeoutError,
  VaultClient,
  loadConfig,
} from './api.js';
import { VERSION } from './version.js';
import {
  listVaultItemsInput, listVaultItems,
  getVaultMetadataInput, getVaultMetadata,
  revealSecretViaSendInput, revealSecretViaSend,
  getTotpCodeInput, getTotpCode,
  saveGeneratedSecretInput, saveGeneratedSecret,
  saveLoginItemInput, saveLoginItem,
  healthCheckInput, healthCheck,
} from './tools/vault.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toolSuccess(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

export function toolError(error: unknown) {
  let message: string;
  if (error instanceof VaultTimeoutError) {
    message = `Vault timeout: ${error.message}. Raise VAULT_API_TIMEOUT_MS or retry.`;
  } else if (error instanceof VaultConnectionError) {
    message = `Vault connection error: ${error.message}. Check VAULT_API_BASE and network connectivity.`;
  } else if (error instanceof VaultAuthError) {
    message = `Vault auth error: ${error.message}. Check VAULT_CLIENT_ID, VAULT_CLIENT_SECRET, VAULT_MASTER_PASSWORD.`;
  } else if (error instanceof VaultConfigError) {
    message = `Vault configuration error: ${error.message}`;
  } else if (error instanceof VaultItemNotFound) {
    message = `${error.message}. Use list_vault_items to see available items.`;
  } else if (error instanceof VaultFieldNotPresent) {
    message = `${error.message}. Use get_vault_metadata to check available fields.`;
  } else if (error instanceof VaultTOTPNotConfigured) {
    message = `${error.message}`;
  } else if (error instanceof VaultNameCollision) {
    message = `${error.message}. Choose a different name.`;
  } else if (error instanceof VaultWriteForbidden) {
    message = `${error.message}`;
  } else if (error instanceof VaultPayloadTooLarge) {
    message = `${error.message}`;
  } else if (error instanceof VaultCollectionMissing) {
    message = `${error.message}. Create the required collections in Vaultwarden UI first.`;
  } else if (error instanceof VaultEmpty) {
    message = `${error.message}. Create mcp-exposed and/or mcp-agent-created collections in Vaultwarden.`;
  } else if (error instanceof Error) {
    message = error.message;
  } else {
    message = String(error);
  }
  return { isError: true, content: [{ type: 'text' as const, text: message }] };
}

function wrap<TArgs, TResult>(fn: (args: TArgs) => Promise<TResult>) {
  return async (args: TArgs) => {
    try {
      return toolSuccess(await fn(args));
    } catch (err) {
      return toolError(err);
    }
  };
}

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

export function createServer(client?: VaultClient): McpServer {
  // client can be injected for testing; otherwise load from env
  const vaultClient = client ?? new VaultClient(loadConfig());

  const server = new McpServer({ name: 'mcp-server-vault', version: VERSION });

  server.registerTool(
    'list_vault_items',
    {
      description:
        'List vault items from the mcp-exposed and mcp-agent-created collections. ' +
        'Returns metadata only — secret values are NEVER included. ' +
        'Use reveal_secret_via_send to obtain the actual value through a secure Bitwarden Send URL.',
      inputSchema: listVaultItemsInput,
      annotations: { title: 'List Vault Items', readOnlyHint: true, openWorldHint: true },
    },
    wrap((args) => listVaultItems(vaultClient, args)),
  );

  server.registerTool(
    'get_vault_metadata',
    {
      description:
        'Get full metadata for a named vault item. ' +
        'Returns name, type, username (for login items), URIs, custom fields, scope, expiry. ' +
        'Password, TOTP seed, and api-key values are NEVER returned — use reveal_secret_via_send or get_totp_code instead.',
      inputSchema: getVaultMetadataInput,
      annotations: { title: 'Get Vault Item Metadata', readOnlyHint: true, openWorldHint: true },
    },
    wrap((args) => getVaultMetadata(vaultClient, args)),
  );

  server.registerTool(
    'reveal_secret_via_send',
    {
      description:
        'Reveal a vault secret through a Bitwarden Send — an E2E-encrypted one-time URL. ' +
        'Creates a temporary Send with a configurable TTL and max-views limit. ' +
        'The secret value is encrypted client-side; only the URL fragment (never sent to server) can decrypt it. ' +
        'Blocked when READ_ONLY=1. Logs to DRY_RUN without creating a real Send when DRY_RUN=1.',
      inputSchema: revealSecretViaSendInput,
      annotations: { title: 'Reveal Secret via Send', readOnlyHint: false, openWorldHint: true },
    },
    wrap((args) => revealSecretViaSend(vaultClient, args)),
  );

  server.registerTool(
    'get_totp_code',
    {
      description:
        'Get the current TOTP code for a vault login item with TOTP configured. ' +
        'Returns the 6-digit code, the remaining seconds in the current period, and the algorithm. ' +
        'Use the remaining_seconds field to decide whether to use the code immediately or wait for a fresh period.',
      inputSchema: getTotpCodeInput,
      annotations: { title: 'Get TOTP Code', readOnlyHint: true, openWorldHint: true },
    },
    wrap((args) => getTotpCode(vaultClient, args)),
  );

  server.registerTool(
    'save_generated_secret',
    {
      description:
        'Save an agent-generated secret into the mcp-agent-created collection. ' +
        'CREATE-only — cannot overwrite an existing item (name collision returns an error). ' +
        'The secret is E2E-encrypted with the vault org key before transmission. ' +
        'Sets mcp-created-by, mcp-created-at, mcp-expires-at, and mcp-used-in custom fields automatically. ' +
        'Blocked when READ_ONLY=1. Logs to DRY_RUN without creating a real cipher when DRY_RUN=1.',
      inputSchema: saveGeneratedSecretInput,
      annotations: { title: 'Save Generated Secret', readOnlyHint: false, openWorldHint: true },
    },
    wrap((args) => saveGeneratedSecret(vaultClient, args)),
  );

  server.registerTool(
    'save_login_item',
    {
      description:
        'Save login credentials (username, password, URL, optional TOTP seed) as a Vaultwarden login item ' +
        'in the mcp-agent-created collection. Use this instead of save_generated_secret when the credential ' +
        'is a sign-in (username + password), so it surfaces as a real login item with get_totp_code support. ' +
        'CREATE-only — cannot overwrite an existing item (name collision returns an error). ' +
        'At least one of username or password is required. ' +
        'All fields are E2E-encrypted with the vault org key before transmission. ' +
        'Sets mcp-created-by, mcp-created-at, mcp-expires-at, and mcp-used-in custom fields automatically. ' +
        'Blocked when READ_ONLY=1. Logs to DRY_RUN without creating a real cipher when DRY_RUN=1.',
      inputSchema: saveLoginItemInput,
      annotations: { title: 'Save Login Item', readOnlyHint: false, openWorldHint: true },
    },
    wrap((args) => saveLoginItem(vaultClient, args)),
  );

  server.registerTool(
    'health_check',
    {
      description:
        'Check connectivity and configuration of the Bitwarden/Vaultwarden vault. ' +
        'Authenticates, syncs, and reports: auth status, API version, collection visibility, item counts, latency. ' +
        'Run this first after a new install or after rotating credentials.',
      inputSchema: healthCheckInput,
      annotations: { title: 'Health Check', readOnlyHint: true, openWorldHint: true },
    },
    wrap((_args) => healthCheck(vaultClient, {})),
  );

  return server;
}

// ---------------------------------------------------------------------------
// CLI entry
// ---------------------------------------------------------------------------

async function main() {
  const server = createServer();
  await server.connect(new StdioServerTransport());
}

export function isCliEntry(
  moduleUrl: string = import.meta.url,
  argv1: string | undefined = process.argv[1],
): boolean {
  if (!argv1) return false;
  try {
    return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(argv1);
  } catch {
    return false;
  }
}

if (isCliEntry()) {
  main().catch((err) => {
    console.error('[mcp-server-vault] fatal:', err);
    process.exit(1);
  });
}
