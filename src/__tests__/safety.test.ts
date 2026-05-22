/**
 * Safety-claim tests for @aiwerk/mcp-server-vault.
 *
 * Each test MUST FAIL if the corresponding safety feature is removed from the code.
 * These mirror the 5 required safety claims from the scope-spec.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as crypto from 'node:crypto';
import {
  VaultClient,
  VaultNameCollision,
  VaultWriteForbidden,
  type VaultItemSummary,
  type VaultItemDetail,
} from '../api.js';
import { encryptAesCbc256, type SymKey } from '../crypto.js';
import { createServer } from '../server.js';

// ---------------------------------------------------------------------------
// Helpers — build synthetic encrypted cipher data
// ---------------------------------------------------------------------------

function makeSymKey(): SymKey {
  return { encKey: crypto.randomBytes(32), macKey: crypto.randomBytes(32) };
}

function enc(plain: string, symKey: SymKey): string {
  return encryptAesCbc256(plain, symKey);
}

const ORG_ID = 'org-test-id';
const EXPOSED_ID = 'col-exposed-id';
const AGENT_ID = 'col-agent-id';
const OTHER_COL_ID = 'col-other-id';

function makeCipher(opts: {
  id: string;
  name: string;
  type: 1 | 2;
  collectionIds: string[];
  symKey: SymKey;
  password?: string;
  notes?: string;
  mcpType?: string;
  hiddenField?: { name: string; value: string };
}): Record<string, unknown> {
  const fields: Array<{ name: string; value: string; type: number }> = [];
  if (opts.mcpType) {
    fields.push({ name: enc('mcp-type', opts.symKey), value: enc(opts.mcpType, opts.symKey), type: 0 });
  }
  if (opts.hiddenField) {
    // type 1 = hidden
    fields.push({ name: enc(opts.hiddenField.name, opts.symKey), value: enc(opts.hiddenField.value, opts.symKey), type: 1 });
  }

  return {
    id: opts.id,
    organizationId: ORG_ID,
    collectionIds: opts.collectionIds,
    type: opts.type,
    name: enc(opts.name, opts.symKey),
    notes: opts.notes ? enc(opts.notes, opts.symKey) : null,
    fields: fields.length > 0 ? fields : null,
    login: opts.type === 1 ? {
      username: null,
      password: opts.password ? enc(opts.password, opts.symKey) : null,
      totp: null,
      uris: null,
    } : null,
    secureNote: opts.type === 2 ? { type: 0 } : null,
    creationDate: '2026-01-01T00:00:00Z',
    revisionDate: '2026-01-01T00:00:00Z',
    deletedDate: null,
  };
}

function setupClient(ciphers: Record<string, unknown>[], orgSymKey: SymKey): VaultClient {
  const client = new VaultClient({
    apiBase: 'https://pass.example.com',
    clientId: 'user.test',
    clientSecret: 'secret',
    masterPassword: 'pass',
    exposedCollection: 'mcp-exposed',
    agentCreatedCollection: 'mcp-agent-created',
    timeoutMs: 15000,
    dryRun: false,
    readOnly: false,
  });

  // Inject synthetic state to bypass HTTP/crypto initialization
  const c = client as unknown as Record<string, unknown>;
  c['initialized'] = true;
  c['orgSymKeys'] = new Map([[ORG_ID, orgSymKey]]);
  c['collectionIds'] = { exposed: EXPOSED_ID, agentCreated: AGENT_ID };
  c['syncData'] = {
    profile: { id: 'p1', email: 'test@example.com', key: '', privateKey: '', kdfType: 0, kdfIterations: 600000, organizations: [] },
    collections: [
      { id: EXPOSED_ID, organizationId: ORG_ID, name: enc('mcp-exposed', orgSymKey) },
      { id: AGENT_ID, organizationId: ORG_ID, name: enc('mcp-agent-created', orgSymKey) },
    ],
    ciphers,
  };
  return client;
}

// ---------------------------------------------------------------------------
// SAFETY CLAIM 1:
// "The vault MCP server NEVER returns the plaintext secret value through
//  list_vault_items or get_vault_metadata."
// Test fails if parseSummary or getItemDetail starts including password/notes for api-key items.
// ---------------------------------------------------------------------------

describe('Safety Claim 1 — list_vault_items and get_vault_metadata never expose secret values', () => {
  it('list_vault_items result has no "value", "password", or "notes" for api-key items', async () => {
    const symKey = makeSymKey();
    const cipher = makeCipher({
      id: 'c1', name: 'my-api-key', type: 2, collectionIds: [EXPOSED_ID],
      symKey, notes: 'SECRET_VALUE_12345', mcpType: 'api-key',
    });
    const client = setupClient([cipher], symKey);

    const items = await client.listItems();
    expect(items).toHaveLength(1);

    const item = items[0];
    // These properties must NEVER appear in summary output for api-key type
    expect(item).not.toHaveProperty('value');
    expect(item).not.toHaveProperty('password');
    // notes_preview must be absent for api-key (it stores the secret in notes)
    expect(item.notes_preview).toBeUndefined();
    // The actual secret 'SECRET_VALUE_12345' must not appear anywhere in the serialized response
    const serialized = JSON.stringify(item);
    expect(serialized).not.toContain('SECRET_VALUE_12345');
  });

  it('get_vault_metadata does not return notes content for api-key type items', async () => {
    const symKey = makeSymKey();
    const cipher = makeCipher({
      id: 'c2', name: 'stripe-key', type: 2, collectionIds: [EXPOSED_ID],
      symKey, notes: 'sk_live_SUPERSECRET', mcpType: 'api-key',
    });
    const client = setupClient([cipher], symKey);

    const detail = await client.getItemDetail('stripe-key');
    expect(detail.notes).toBeUndefined();
    const serialized = JSON.stringify(detail);
    expect(serialized).not.toContain('sk_live_SUPERSECRET');
  });

  it('hidden-type custom field values are never included in metadata', async () => {
    const symKey = makeSymKey();
    const cipher = makeCipher({
      id: 'c3', name: 'config-item', type: 2, collectionIds: [EXPOSED_ID],
      symKey, mcpType: 'note',
      hiddenField: { name: 'secret_token', value: 'HIDDEN_SECRET_VALUE' },
    });
    const client = setupClient([cipher], symKey);

    const detail = await client.getItemDetail('config-item');
    // custom_fields should not include hidden-type fields
    const serialized = JSON.stringify(detail);
    expect(serialized).not.toContain('HIDDEN_SECRET_VALUE');
    if (detail.custom_fields) {
      expect(Object.values(detail.custom_fields)).not.toContain('HIDDEN_SECRET_VALUE');
    }
  });
});

// ---------------------------------------------------------------------------
// SAFETY CLAIM 2:
// "Items outside mcp-exposed / mcp-agent-created are invisible to the agent."
// Test fails if isWhitelisted() check is removed or bypassed.
// ---------------------------------------------------------------------------

describe('Safety Claim 2 — items outside whitelisted collections are invisible', () => {
  it('list_vault_items does not return items from a third collection', async () => {
    const symKey = makeSymKey();
    const exposedCipher = makeCipher({
      id: 'c-exposed', name: 'visible-key', type: 2, collectionIds: [EXPOSED_ID],
      symKey, mcpType: 'api-key',
    });
    const otherCipher = makeCipher({
      id: 'c-other', name: 'invisible-key', type: 2, collectionIds: [OTHER_COL_ID],
      symKey, mcpType: 'api-key',
    });
    const client = setupClient([exposedCipher, otherCipher], symKey);

    const items = await client.listItems();
    expect(items).toHaveLength(1);
    expect(items[0].name).toBe('visible-key');
    // Explicitly verify the item from 'other' collection is absent
    const names = items.map(i => i.name);
    expect(names).not.toContain('invisible-key');
  });

  it('item_not_visible error for item outside whitelisted collections via getItemDetail', async () => {
    const symKey = makeSymKey();
    const otherCipher = makeCipher({
      id: 'c-other2', name: 'outside-item', type: 2, collectionIds: [OTHER_COL_ID],
      symKey, mcpType: 'api-key',
    });
    const client = setupClient([otherCipher], symKey);

    await expect(client.getItemDetail('outside-item')).rejects.toThrow('not found');
  });
});

// ---------------------------------------------------------------------------
// SAFETY CLAIM 3:
// "Agent cannot update or delete existing items."
// Test fails if an update_*, delete_*, change_*, or set_* tool is added.
// ---------------------------------------------------------------------------

describe('Safety Claim 3 — no mutating tool names exposed to agent', () => {
  it('no tool name matches update_*, delete_*, change_*, or set_*', () => {
    const mockClient = {
      config: {
        apiBase: 'https://pass.example.com',
        clientId: 'test', clientSecret: 'test', masterPassword: 'test',
        exposedCollection: 'mcp-exposed', agentCreatedCollection: 'mcp-agent-created',
        timeoutMs: 15000, dryRun: false, readOnly: false,
      },
      listItems: vi.fn(),
      getItemDetail: vi.fn(),
      getItemValue: vi.fn(),
      revealViaSend: vi.fn(),
      getTotpCode: vi.fn(),
      saveGeneratedSecret: vi.fn(),
      healthCheck: vi.fn(),
      initialize: vi.fn(),
      refetchSync: vi.fn(),
    } as unknown as VaultClient;

    const server = createServer(mockClient);
    const tools = (server as unknown as { _registeredTools: Record<string, unknown> })._registeredTools;
    const forbiddenPrefixes = ['update_', 'delete_', 'change_', 'set_'];

    for (const toolName of Object.keys(tools)) {
      for (const prefix of forbiddenPrefixes) {
        expect(toolName).not.toMatch(new RegExp(`^${prefix}`));
      }
    }
  });
});

// ---------------------------------------------------------------------------
// SAFETY CLAIM 4:
// "save_generated_secret cannot overwrite an existing item."
// Test fails if the name-collision check is removed.
// ---------------------------------------------------------------------------

describe('Safety Claim 4 — save_generated_secret cannot overwrite', () => {
  it('throws VaultNameCollision when item already exists in mcp-agent-created', async () => {
    const symKey = makeSymKey();
    const existingCipher = makeCipher({
      id: 'c-existing', name: 'my-password', type: 2, collectionIds: [AGENT_ID],
      symKey, mcpType: 'password', notes: 'original_secret',
    });
    const client = setupClient([existingCipher], symKey);

    // Verify the original item exists
    const items = await client.listItems();
    const original = items.find(i => i.name === 'my-password');
    expect(original).toBeDefined();

    // Attempt to overwrite — must throw
    await expect(
      client.saveGeneratedSecret({
        name: 'my-password',
        value: 'new_overwriting_secret',
        type: 'password',
      }),
    ).rejects.toThrow(VaultNameCollision);
  });
});

// ---------------------------------------------------------------------------
// SAFETY CLAIM 5:
// "Bitwarden Send is created with the requested TTL and max_views."
// Test fails if revealViaSend ignores the ttl/max_views params or bypasses them.
// ---------------------------------------------------------------------------

describe('Safety Claim 5 — Send is created with exact TTL and max_views', () => {
  it('DRY_RUN mode reflects the exact requested TTL and max_views in the response', async () => {
    const symKey = makeSymKey();
    const cipher = makeCipher({
      id: 'c-reveal', name: 'reveal-key', type: 2, collectionIds: [EXPOSED_ID],
      symKey, notes: 'secret_to_reveal', mcpType: 'api-key',
    });
    const client = setupClient([cipher], symKey);
    // Override to DRY_RUN so no actual HTTP call is made
    (client as unknown as Record<string, unknown>)['config'] = {
      ...client.config,
      dryRun: true,
    };

    const result = await client.revealViaSend('reveal-key', 'value', 60, 2);
    expect(result.max_views).toBe(2);
    // Verify TTL is reflected in expires_at (60s from now, with 5s tolerance)
    const expiresAt = new Date(result.expires_at).getTime();
    const expectedExpiry = Date.now() + 60 * 1000;
    expect(Math.abs(expiresAt - expectedExpiry)).toBeLessThan(5000);
    expect(result.send_url).toContain('DRY_RUN');
  });

  it('revealViaSend enforces TTL range [30, 86400]', async () => {
    const symKey = makeSymKey();
    const cipher = makeCipher({
      id: 'c-reveal2', name: 'another-key', type: 2, collectionIds: [EXPOSED_ID],
      symKey, notes: 'secret2', mcpType: 'api-key',
    });
    const client = setupClient([cipher], symKey);
    (client as unknown as Record<string, unknown>)['config'] = {
      ...client.config,
      dryRun: true,
    };

    // TTL below minimum (10s) should be clamped to 30s
    const resultMin = await client.revealViaSend('another-key', 'value', 10, 1);
    const expiresAtMin = new Date(resultMin.expires_at).getTime();
    // Should expire at ~30s from now (not 10s)
    expect(Math.abs(expiresAtMin - (Date.now() + 30 * 1000))).toBeLessThan(5000);
  });
});
