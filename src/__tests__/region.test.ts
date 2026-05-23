import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolveRegionUrls, loadConfig, VaultConfigError } from '../api.js';

// ---------------------------------------------------------------------------
// resolveRegionUrls
// ---------------------------------------------------------------------------

describe('resolveRegionUrls', () => {
  it('us → bitwarden.com URLs', () => {
    const urls = resolveRegionUrls('us', '');
    expect(urls.identityBaseUrl).toBe('https://identity.bitwarden.com');
    expect(urls.apiBaseUrl).toBe('https://api.bitwarden.com');
    expect(urls.webVaultUrl).toBe('https://vault.bitwarden.com');
  });

  it('eu → bitwarden.eu URLs', () => {
    const urls = resolveRegionUrls('eu', '');
    expect(urls.identityBaseUrl).toBe('https://identity.bitwarden.eu');
    expect(urls.apiBaseUrl).toBe('https://api.bitwarden.eu');
    expect(urls.webVaultUrl).toBe('https://vault.bitwarden.eu');
  });

  it('self-hosted → appends /identity and /api to provided base', () => {
    const urls = resolveRegionUrls('self-hosted', 'https://pass.aiwerk.ch');
    expect(urls.identityBaseUrl).toBe('https://pass.aiwerk.ch/identity');
    expect(urls.apiBaseUrl).toBe('https://pass.aiwerk.ch/api');
    expect(urls.webVaultUrl).toBe('https://pass.aiwerk.ch');
  });

  it('self-hosted with trailing slash → strips it', () => {
    const urls = resolveRegionUrls('self-hosted', 'https://pass.aiwerk.ch/');
    expect(urls.identityBaseUrl).toBe('https://pass.aiwerk.ch/identity');
    expect(urls.apiBaseUrl).toBe('https://pass.aiwerk.ch/api');
  });

  it('self-hosted with empty apiBase → throws VaultConfigError', () => {
    expect(() => resolveRegionUrls('self-hosted', '')).toThrow(VaultConfigError);
    expect(() => resolveRegionUrls('self-hosted', '')).toThrow('VAULT_API_BASE required');
  });
});

// ---------------------------------------------------------------------------
// loadConfig — region env var handling
// ---------------------------------------------------------------------------

describe('loadConfig — VAULT_REGION', () => {
  const saved: Record<string, string | undefined> = {};

  function setEnv(vars: Record<string, string | undefined>) {
    for (const [k, v] of Object.entries(vars)) {
      saved[k] = process.env[k];
      if (v === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = v;
      }
    }
  }

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = v;
      }
    }
    Object.keys(saved).forEach(k => delete saved[k]);
  });

  it('VAULT_REGION=us resolves cloud URLs and ignores VAULT_API_BASE', () => {
    setEnv({
      VAULT_REGION: 'us',
      VAULT_CLIENT_ID: 'user.test',
      VAULT_CLIENT_SECRET: 'secret',
      VAULT_MASTER_PASSWORD: 'pass',
      VAULT_API_BASE: undefined,
    });
    const config = loadConfig();
    expect(config.region).toBe('us');
    expect(config.identityBaseUrl).toBe('https://identity.bitwarden.com');
    expect(config.apiBaseUrl).toBe('https://api.bitwarden.com');
    expect(config.webVaultUrl).toBe('https://vault.bitwarden.com');
  });

  it('VAULT_REGION=eu resolves EU cloud URLs', () => {
    setEnv({
      VAULT_REGION: 'eu',
      VAULT_CLIENT_ID: 'user.test',
      VAULT_CLIENT_SECRET: 'secret',
      VAULT_MASTER_PASSWORD: 'pass',
      VAULT_API_BASE: undefined,
    });
    const config = loadConfig();
    expect(config.region).toBe('eu');
    expect(config.identityBaseUrl).toBe('https://identity.bitwarden.eu');
    expect(config.apiBaseUrl).toBe('https://api.bitwarden.eu');
  });

  it('default (no VAULT_REGION) behaves as self-hosted and requires VAULT_API_BASE', () => {
    setEnv({
      VAULT_REGION: undefined,
      VAULT_API_BASE: 'https://pass.aiwerk.ch',
      VAULT_CLIENT_ID: 'user.test',
      VAULT_CLIENT_SECRET: 'secret',
      VAULT_MASTER_PASSWORD: 'pass',
    });
    const config = loadConfig();
    expect(config.region).toBe('self-hosted');
    expect(config.identityBaseUrl).toBe('https://pass.aiwerk.ch/identity');
    expect(config.apiBaseUrl).toBe('https://pass.aiwerk.ch/api');
  });

  it('self-hosted without VAULT_API_BASE throws VaultConfigError', () => {
    setEnv({
      VAULT_REGION: 'self-hosted',
      VAULT_API_BASE: undefined,
      VAULT_CLIENT_ID: 'user.test',
      VAULT_CLIENT_SECRET: 'secret',
      VAULT_MASTER_PASSWORD: 'pass',
    });
    expect(() => loadConfig()).toThrow(VaultConfigError);
    expect(() => loadConfig()).toThrow('VAULT_API_BASE');
  });
});
