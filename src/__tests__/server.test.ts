import { describe, it, expect, vi, beforeEach } from 'vitest';
import { isCliEntry, toolError, createServer } from '../server.js';
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
} from '../api.js';

// ---------------------------------------------------------------------------
// isCliEntry
// ---------------------------------------------------------------------------

describe('isCliEntry', () => {
  it('returns false when no argv1', () => {
    expect(isCliEntry('file:///some/path.js', undefined)).toBe(false);
  });

  it('returns false when paths differ', () => {
    expect(isCliEntry('file:///app/server.js', '/other/file.js')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// toolError
// ---------------------------------------------------------------------------

describe('toolError', () => {
  it('maps VaultTimeoutError', () => {
    const r = toolError(new VaultTimeoutError('timed out'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/timeout/i);
    expect(r.content[0].text).toMatch(/VAULT_API_TIMEOUT_MS/);
  });

  it('maps VaultConnectionError', () => {
    const r = toolError(new VaultConnectionError('ECONNREFUSED'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/connection error/i);
    expect(r.content[0].text).toMatch(/VAULT_API_BASE/);
  });

  it('maps VaultAuthError', () => {
    const r = toolError(new VaultAuthError('invalid credentials'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/auth error/i);
    expect(r.content[0].text).toMatch(/VAULT_CLIENT_ID/);
  });

  it('maps VaultConfigError', () => {
    const r = toolError(new VaultConfigError('missing VAULT_API_BASE'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/configuration error/i);
  });

  it('maps VaultItemNotFound', () => {
    const r = toolError(new VaultItemNotFound('Item "foo" not found'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/foo/);
    expect(r.content[0].text).toMatch(/list_vault_items/);
  });

  it('maps VaultFieldNotPresent', () => {
    const r = toolError(new VaultFieldNotPresent('no password'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/get_vault_metadata/);
  });

  it('maps VaultTOTPNotConfigured', () => {
    const r = toolError(new VaultTOTPNotConfigured('no TOTP'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/no TOTP/);
  });

  it('maps VaultNameCollision', () => {
    const r = toolError(new VaultNameCollision('item exists'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/different name/i);
  });

  it('maps VaultWriteForbidden', () => {
    const r = toolError(new VaultWriteForbidden('READ_ONLY=1'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/READ_ONLY/);
  });

  it('maps VaultPayloadTooLarge', () => {
    const r = toolError(new VaultPayloadTooLarge('too big'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/too big/);
  });

  it('maps VaultCollectionMissing', () => {
    const r = toolError(new VaultCollectionMissing('no collection'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/no collection/);
    expect(r.content[0].text).toMatch(/Vaultwarden UI/);
  });

  it('maps VaultEmpty', () => {
    const r = toolError(new VaultEmpty('no collections'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toMatch(/mcp-exposed/);
  });

  it('maps generic Error', () => {
    const r = toolError(new Error('something went wrong'));
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toBe('something went wrong');
  });

  it('maps unknown value', () => {
    const r = toolError('string error');
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toBe('string error');
  });
});

// ---------------------------------------------------------------------------
// createServer
// ---------------------------------------------------------------------------

describe('createServer', () => {
  it('returns a server with exactly 6 tools', () => {
    const mockClient = {
      config: {
        region: 'self-hosted' as const,
        identityBaseUrl: 'https://pass.example.com/identity',
        apiBaseUrl: 'https://pass.example.com/api',
        webVaultUrl: 'https://pass.example.com',
        clientId: 'user.test',
        clientSecret: 'secret',
        masterPassword: 'pass',
        exposedCollection: 'mcp-exposed',
        agentCreatedCollection: 'mcp-agent-created',
        timeoutMs: 15000,
        dryRun: false,
        readOnly: false,
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
    // MCP server has a _registeredTools plain object — we can check its keys
    const tools = (server as unknown as { _registeredTools: Record<string, unknown> })._registeredTools;
    expect(Object.keys(tools).length).toBe(6);
  });
});
