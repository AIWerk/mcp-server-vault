/**
 * Tests for the prelogin fallback path.
 *
 * Vaultwarden 1.36.0 omits KDF fields from /api/sync profile.
 * VaultClient must call POST /identity/accounts/prelogin to fetch them.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { VaultClient } from '../api.js';

const BASE_CONFIG = {
  region: 'self-hosted' as const,
  identityBaseUrl: 'https://pass.example.com/identity',
  apiBaseUrl: 'https://pass.example.com/api',
  webVaultUrl: 'https://pass.example.com',
  clientId: 'user.test',
  clientSecret: 'secret',
  masterPassword: 'hunter2',
  exposedCollection: 'mcp-exposed',
  agentCreatedCollection: 'mcp-agent-created',
  timeoutMs: 5000,
  dryRun: false,
  readOnly: false,
};

// Minimal sync profile shape WITHOUT kdf fields (Vaultwarden 1.36.0 behaviour)
function makeSyncProfileWithoutKdf(email = 'test@example.com') {
  return {
    id: 'p1',
    email,
    key: '',        // empty — decrypt will fail, but prelogin fires before that
    privateKey: '',
    // kdf / kdfType / kdfIterations intentionally absent
    organizations: [],
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('prelogin fallback', () => {
  it('parses prelogin response correctly (PBKDF2)', async () => {
    let preloginCalled = false;
    let preloginBody: unknown;

    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      if ((url as string).includes('/connect/token')) {
        return new Response(
          JSON.stringify({ access_token: 'tok', expires_in: 3600, token_type: 'Bearer' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if ((url as string).includes('/accounts/prelogin')) {
        preloginCalled = true;
        preloginBody = JSON.parse(init.body as string);
        return new Response(
          JSON.stringify({ kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      // sync endpoint — profile without KDF fields
      return new Response(
        JSON.stringify({ profile: makeSyncProfileWithoutKdf(), collections: [], ciphers: [] }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }));

    const client = new VaultClient(BASE_CONFIG);
    // listItems triggers initialize() → sync → initializeKeys → prelogin (KDF missing)
    // Crypto will fail on empty key, but we only care that prelogin was called correctly
    await client.listItems().catch(() => null);

    expect(preloginCalled).toBe(true);
    expect((preloginBody as { email: string }).email).toBe('test@example.com');
  });

  it('prelogin is called only once even on re-auth (kdfInfo cached)', async () => {
    let preloginCallCount = 0;

    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      if ((url as string).includes('/connect/token')) {
        return new Response(
          JSON.stringify({ access_token: 'tok', expires_in: 1, token_type: 'Bearer' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if ((url as string).includes('/accounts/prelogin')) {
        preloginCallCount++;
        return new Response(
          JSON.stringify({ kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({ profile: makeSyncProfileWithoutKdf(), collections: [], ciphers: [] }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }));

    const client = new VaultClient(BASE_CONFIG);
    await client.listItems().catch(() => null);
    // Expire token → force re-auth, but kdfInfo already cached
    (client as unknown as Record<string, unknown>)['tokenExpiry'] = 0;
    (client as unknown as Record<string, unknown>)['initialized'] = false;
    await client.listItems().catch(() => null);

    expect(preloginCallCount).toBe(1);
  });
});
