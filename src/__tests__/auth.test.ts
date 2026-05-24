import { describe, it, expect, vi, afterEach } from 'vitest';
import { VaultClient, VaultAuthError } from '../api.js';

const BASE_CONFIG = {
  region: 'self-hosted' as const,
  identityBaseUrl: 'https://pass.example.com/identity',
  apiBaseUrl: 'https://pass.example.com/api',
  webVaultUrl: 'https://pass.example.com',
  clientId: 'user.test',
  clientSecret: 'secret',
  masterPassword: 'pass',
  exposedCollection: 'mcp-exposed',
  agentCreatedCollection: 'mcp-agent-created',
  timeoutMs: 5000,
  dryRun: false,
  readOnly: false,
};

describe('authenticate — device fields', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('auth request includes deviceType, deviceIdentifier, deviceName, and Bitwarden-Client-Version header', async () => {
    let capturedInit: RequestInit | undefined;

    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
      capturedInit = init;
      return new Response(
        JSON.stringify({ access_token: 'tok', expires_in: 3600, token_type: 'Bearer' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }));

    const client = new VaultClient(BASE_CONFIG);
    // Trigger authenticate via ensureToken (private) by calling initialize() which calls apiGet
    // Instead, access authenticate indirectly: stub sync endpoint too and call listItems
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      if ((url as string).includes('/connect/token')) {
        capturedInit = init;
        return new Response(
          JSON.stringify({ access_token: 'tok', expires_in: 3600, token_type: 'Bearer' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      // sync endpoint — return minimal valid response to avoid parse failures
      return new Response(JSON.stringify({
        profile: {
          id: 'p1', email: 'test@example.com', key: '', privateKey: '',
          kdfType: 0, kdfIterations: 600000, organizations: [],
        },
        collections: [],
        ciphers: [],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }));

    // initialize() will throw (crypto can't decrypt empty keys) — we only care about the auth request
    await client.listItems().catch(() => null);

    expect(capturedInit).toBeDefined();
    const body = new URLSearchParams(capturedInit!.body as string);
    expect(body.get('deviceType')).toBe('14');
    expect(body.get('deviceIdentifier')).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
    expect(body.get('deviceName')).toBe('aiwerk-mcp-server-vault');
    const headers = capturedInit!.headers as Record<string, string>;
    expect(headers['Bitwarden-Client-Version']).toBe('2026.1.0');
  });

  it('deviceIdentifier is stable across multiple auth calls on the same instance', async () => {
    const seenIds = new Set<string>();
    let callCount = 0;

    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      if ((url as string).includes('/connect/token')) {
        const body = new URLSearchParams(init.body as string);
        seenIds.add(body.get('deviceIdentifier') ?? '');
        callCount++;
        return new Response(
          JSON.stringify({ access_token: `tok${callCount}`, expires_in: 1, token_type: 'Bearer' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response(JSON.stringify({
        profile: {
          id: 'p1', email: 'test@example.com', key: '', privateKey: '',
          kdfType: 0, kdfIterations: 600000, organizations: [],
        },
        collections: [],
        ciphers: [],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }));

    const client = new VaultClient(BASE_CONFIG);
    // Force two auth calls by triggering two listItems (token expires_in=1 → re-auth on second)
    await client.listItems().catch(() => null);
    // Expire the token
    (client as unknown as Record<string, unknown>)['tokenExpiry'] = 0;
    await client.listItems().catch(() => null);

    expect(callCount).toBeGreaterThanOrEqual(2);
    // Same UUID used across all auth calls on this instance
    expect(seenIds.size).toBe(1);
  });
});
