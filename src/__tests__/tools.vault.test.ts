import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  VaultAuthError,
  VaultConnectionError,
  VaultItemNotFound,
  VaultFieldNotPresent,
  VaultNameCollision,
  VaultWriteForbidden,
  VaultPayloadTooLarge,
  VaultTOTPNotConfigured,
  VaultCollectionMissing,
  VaultClient,
  type VaultItemSummary,
  type VaultItemDetail,
} from '../api.js';
import { toolError } from '../server.js';
import {
  listVaultItems,
  getVaultMetadata,
  revealSecretViaSend,
  getTotpCode,
  saveGeneratedSecret,
  healthCheck,
} from '../tools/vault.js';

// ---------------------------------------------------------------------------
// Mock VaultClient factory
// ---------------------------------------------------------------------------

const testConfig = {
  apiBase: 'https://pass.example.com',
  clientId: 'user.test',
  clientSecret: 'secret',
  masterPassword: 'pass',
  exposedCollection: 'mcp-exposed',
  agentCreatedCollection: 'mcp-agent-created',
  timeoutMs: 15000,
  dryRun: false,
  readOnly: false,
};

function makeMock(overrides: Partial<Record<string, unknown>> = {}): VaultClient {
  return {
    config: testConfig,
    listItems: vi.fn().mockResolvedValue([]),
    getItemDetail: vi.fn(),
    getItemValue: vi.fn(),
    revealViaSend: vi.fn(),
    getTotpCode: vi.fn(),
    saveGeneratedSecret: vi.fn(),
    healthCheck: vi.fn(),
    initialize: vi.fn(),
    refetchSync: vi.fn(),
    ...overrides,
  } as unknown as VaultClient;
}

const mockSummary: VaultItemSummary = {
  name: 'stripe_live_key',
  type: 'api-key',
  collection: 'mcp-exposed',
  scope: 'stripe.*',
  has_username: false,
  has_totp: false,
  has_uris: false,
  created_at: '2026-01-01T00:00:00Z',
};

const mockDetail: VaultItemDetail = {
  ...mockSummary,
  has_password: false,
  custom_fields: { 'env': 'production' },
};

// ---------------------------------------------------------------------------
// list_vault_items
// ---------------------------------------------------------------------------

describe('list_vault_items', () => {
  it('returns items from listItems', async () => {
    const client = makeMock({ listItems: vi.fn().mockResolvedValue([mockSummary]) });
    const result = await listVaultItems(client, {});
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('stripe_live_key');
  });

  it('passes filter and collection args', async () => {
    const spy = vi.fn().mockResolvedValue([]);
    const client = makeMock({ listItems: spy });
    await listVaultItems(client, { filter: 'stripe', collection: 'mcp-exposed' });
    expect(spy).toHaveBeenCalledWith('stripe', 'mcp-exposed');
  });

  it('returns empty array when vault has no matching items', async () => {
    const client = makeMock({ listItems: vi.fn().mockResolvedValue([]) });
    const result = await listVaultItems(client, {});
    expect(result).toEqual([]);
  });

  it('propagates VaultConnectionError', async () => {
    const client = makeMock({
      listItems: vi.fn().mockRejectedValue(new VaultConnectionError('unreachable')),
    });
    try {
      await listVaultItems(client, {});
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/connection error/i);
    }
  });

  it('propagates VaultAuthError', async () => {
    const client = makeMock({
      listItems: vi.fn().mockRejectedValue(new VaultAuthError('invalid creds')),
    });
    try {
      await listVaultItems(client, {});
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/auth error/i);
    }
  });
});

// ---------------------------------------------------------------------------
// get_vault_metadata
// ---------------------------------------------------------------------------

describe('get_vault_metadata', () => {
  it('returns item detail', async () => {
    const client = makeMock({ getItemDetail: vi.fn().mockResolvedValue(mockDetail) });
    const result = await getVaultMetadata(client, { name: 'stripe_live_key' });
    expect(result.name).toBe('stripe_live_key');
    expect(result.type).toBe('api-key');
  });

  it('propagates VaultItemNotFound', async () => {
    const client = makeMock({
      getItemDetail: vi.fn().mockRejectedValue(new VaultItemNotFound('Item "foo" not found')),
    });
    try {
      await getVaultMetadata(client, { name: 'foo' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/list_vault_items/);
    }
  });
});

// ---------------------------------------------------------------------------
// reveal_secret_via_send
// ---------------------------------------------------------------------------

describe('reveal_secret_via_send', () => {
  it('returns send result on success', async () => {
    const mockResult = {
      send_url: 'https://pass.example.com/#/send/abc/def',
      expires_at: '2026-05-22T21:00:00Z',
      max_views: 1,
      delivery: 'chat' as const,
      audit_id: 'audit-uuid',
    };
    const client = makeMock({ revealViaSend: vi.fn().mockResolvedValue(mockResult) });
    const result = await revealSecretViaSend(client, { name: 'stripe_live_key' });
    expect(result.send_url).toContain('pass.example.com');
    expect(result.max_views).toBe(1);
    expect(result.audit_id).toBeTruthy();
  });

  it('passes ttl_seconds and max_views to revealViaSend', async () => {
    const spy = vi.fn().mockResolvedValue({
      send_url: 'https://x.com/#/send/a/b', expires_at: '', max_views: 3, delivery: 'chat', audit_id: 'x',
    });
    const client = makeMock({ revealViaSend: spy });
    await revealSecretViaSend(client, { name: 'key', ttl_seconds: 60, max_views: 3 });
    expect(spy).toHaveBeenCalledWith('key', undefined, 60, 3);
  });

  it('propagates VaultWriteForbidden (READ_ONLY)', async () => {
    const client = makeMock({
      revealViaSend: vi.fn().mockRejectedValue(
        new VaultWriteForbidden('reveal blocked — READ_ONLY=1'),
      ),
    });
    try {
      await revealSecretViaSend(client, { name: 'key' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/READ_ONLY/);
    }
  });

  it('propagates VaultItemNotFound', async () => {
    const client = makeMock({
      revealViaSend: vi.fn().mockRejectedValue(new VaultItemNotFound('not found')),
    });
    try {
      await revealSecretViaSend(client, { name: 'missing' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// get_totp_code
// ---------------------------------------------------------------------------

describe('get_totp_code', () => {
  it('returns TOTP code shape', async () => {
    const mockResult = {
      code: '123456',
      period: 30,
      remainingSeconds: 15,
      algorithm: 'SHA1',
      digits: 6,
      audit_id: 'audit-1',
    };
    const client = makeMock({ getTotpCode: vi.fn().mockResolvedValue(mockResult) });
    const result = await getTotpCode(client, { name: 'github' });
    expect(result.code).toBe('123456');
    expect(result.period_seconds).toBe(30);
    expect(result.remaining_seconds).toBe(15);
    expect(result.algorithm).toBe('SHA1');
    expect(result.digits).toBe(6);
  });

  it('propagates VaultTOTPNotConfigured', async () => {
    const client = makeMock({
      getTotpCode: vi.fn().mockRejectedValue(
        new VaultTOTPNotConfigured('Item "github" has no TOTP seed'),
      ),
    });
    try {
      await getTotpCode(client, { name: 'github' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/no TOTP/i);
    }
  });

  it('propagates VaultItemNotFound', async () => {
    const client = makeMock({
      getTotpCode: vi.fn().mockRejectedValue(new VaultItemNotFound('not found')),
    });
    try {
      await getTotpCode(client, { name: 'missing' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// save_generated_secret
// ---------------------------------------------------------------------------

describe('save_generated_secret', () => {
  it('returns save result on success', async () => {
    const mockResult = {
      saved_as: 'publish_key_2026_05',
      expires_at: '2026-06-21T00:00:00Z',
      collection: 'mcp-agent-created' as const,
      audit_id: 'audit-2',
    };
    const client = makeMock({ saveGeneratedSecret: vi.fn().mockResolvedValue(mockResult) });
    const result = await saveGeneratedSecret(client, {
      name: 'publish_key_2026_05',
      value: 'supersecret',
      type: 'password',
    });
    expect(result.saved_as).toBe('publish_key_2026_05');
    expect(result.collection).toBe('mcp-agent-created');
    expect(result.audit_id).toBeTruthy();
  });

  it('propagates VaultNameCollision', async () => {
    const client = makeMock({
      saveGeneratedSecret: vi.fn().mockRejectedValue(
        new VaultNameCollision('Item "dup" already exists'),
      ),
    });
    try {
      await saveGeneratedSecret(client, { name: 'dup', value: 'v', type: 'note' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/different name/i);
    }
  });

  it('propagates VaultPayloadTooLarge', async () => {
    const client = makeMock({
      saveGeneratedSecret: vi.fn().mockRejectedValue(
        new VaultPayloadTooLarge('value length 5000 exceeds limit'),
      ),
    });
    try {
      await saveGeneratedSecret(client, { name: 'x', value: 'x'.repeat(5000), type: 'note' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
    }
  });

  it('propagates VaultWriteForbidden (READ_ONLY)', async () => {
    const client = makeMock({
      saveGeneratedSecret: vi.fn().mockRejectedValue(
        new VaultWriteForbidden('blocked — READ_ONLY=1'),
      ),
    });
    try {
      await saveGeneratedSecret(client, { name: 'x', value: 'v', type: 'password' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/READ_ONLY/);
    }
  });

  it('propagates VaultCollectionMissing', async () => {
    const client = makeMock({
      saveGeneratedSecret: vi.fn().mockRejectedValue(
        new VaultCollectionMissing('mcp-agent-created not found'),
      ),
    });
    try {
      await saveGeneratedSecret(client, { name: 'x', value: 'v', type: 'api-key' });
      expect.fail('should have thrown');
    } catch (err) {
      const r = toolError(err);
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toMatch(/mcp-agent-created/);
    }
  });
});

// ---------------------------------------------------------------------------
// health_check
// ---------------------------------------------------------------------------

describe('health_check', () => {
  it('returns health object', async () => {
    const mockHealth = {
      status: 'ok' as const,
      vault_url: 'https://pass.example.com',
      api_version: '1.36.0',
      authenticated: true,
      exposed_collection_visible: true,
      agent_created_collection_visible: true,
      items_in_exposed: 5,
      items_in_agent_created: 2,
      latency_ms: 120,
    };
    const client = makeMock({ healthCheck: vi.fn().mockResolvedValue(mockHealth) });
    const result = await healthCheck(client, {});
    expect(result.status).toBe('ok');
    expect(result.authenticated).toBe(true);
    expect(result.items_in_exposed).toBe(5);
  });

  it('returns error status on VaultConnectionError', async () => {
    const mockHealth = {
      status: 'error' as const,
      vault_url: 'https://pass.example.com',
      api_version: 'unknown',
      authenticated: false,
      exposed_collection_visible: false,
      agent_created_collection_visible: false,
      items_in_exposed: 0,
      items_in_agent_created: 0,
      latency_ms: 15000,
    };
    const client = makeMock({ healthCheck: vi.fn().mockResolvedValue(mockHealth) });
    const result = await healthCheck(client, {});
    expect(result.status).toBe('error');
    expect(result.authenticated).toBe(false);
  });
});
