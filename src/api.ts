/**
 * VaultClient — REST API client + Bitwarden E2E decryption layer.
 *
 * Handles:
 *  - OAuth2 client_credentials auth against /identity/connect/token
 *  - GET /api/sync → decrypt vault symkey → decrypt org keys → resolve collections
 *  - Per-cipher field decryption (name, notes, custom fields, login fields, totp)
 *  - Send creation (POST /api/sends) with proper keyMaterial / HKDF derivation
 *  - Cipher creation (POST /api/ciphers/create) encrypted with org symkey
 *  - DRY_RUN + READ_ONLY orthogonal layers
 */

import * as crypto from 'node:crypto';
import pino from 'pino';
import {
  type KdfSettings,
  type SymKey,
  type TotpResult,
  deriveMasterKey,
  stretchMasterKey,
  parseSymKey,
  decryptAesCbc256,
  encryptAesCbc256,
  decryptRsaEncString,
  deriveSendKey,
  generateSendKeyMaterial,
  buildSendUrl,
  computeTotp,
  generateAuditId,
} from './crypto.js';

// ---------------------------------------------------------------------------
// Logger (stderr only — MCP spec)
// ---------------------------------------------------------------------------

const log = pino({ level: 'info', base: { pid: process.pid } }, pino.destination(2));

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

export class VaultConfigError extends Error {
  constructor(m: string) { super(m); this.name = 'VaultConfigError'; }
}
export class VaultAuthError extends Error {
  constructor(m: string) { super(m); this.name = 'VaultAuthError'; }
}
export class VaultConnectionError extends Error {
  constructor(m: string) { super(m); this.name = 'VaultConnectionError'; }
}
export class VaultItemNotFound extends Error {
  constructor(m: string) { super(m); this.name = 'VaultItemNotFound'; }
}
export class VaultFieldNotPresent extends Error {
  constructor(m: string) { super(m); this.name = 'VaultFieldNotPresent'; }
}
export class VaultNameCollision extends Error {
  constructor(m: string) { super(m); this.name = 'VaultNameCollision'; }
}
export class VaultWriteForbidden extends Error {
  constructor(m: string) { super(m); this.name = 'VaultWriteForbidden'; }
}
export class VaultPayloadTooLarge extends Error {
  constructor(m: string) { super(m); this.name = 'VaultPayloadTooLarge'; }
}
export class VaultCollectionMissing extends Error {
  constructor(m: string) { super(m); this.name = 'VaultCollectionMissing'; }
}
export class VaultTOTPNotConfigured extends Error {
  constructor(m: string) { super(m); this.name = 'VaultTOTPNotConfigured'; }
}
export class VaultEmpty extends Error {
  constructor(m: string) { super(m); this.name = 'VaultEmpty'; }
}
export class VaultTimeoutError extends Error {
  constructor(m: string) { super(m); this.name = 'VaultTimeoutError'; }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export type VaultRegion = 'self-hosted' | 'us' | 'eu';

interface ResolvedUrls {
  identityBaseUrl: string;
  apiBaseUrl: string;
  webVaultUrl: string;
}

export function resolveRegionUrls(region: VaultRegion, apiBase: string): ResolvedUrls {
  switch (region) {
    case 'us':
      return {
        identityBaseUrl: 'https://identity.bitwarden.com',
        apiBaseUrl: 'https://api.bitwarden.com',
        webVaultUrl: 'https://vault.bitwarden.com',
      };
    case 'eu':
      return {
        identityBaseUrl: 'https://identity.bitwarden.eu',
        apiBaseUrl: 'https://api.bitwarden.eu',
        webVaultUrl: 'https://vault.bitwarden.eu',
      };
    case 'self-hosted':
    default: {
      if (!apiBase) throw new VaultConfigError('VAULT_API_BASE required for self-hosted');
      const base = apiBase.replace(/\/$/, '');
      return {
        identityBaseUrl: `${base}/identity`,
        apiBaseUrl: `${base}/api`,
        webVaultUrl: base,
      };
    }
  }
}

export interface VaultConfig {
  region: VaultRegion;
  identityBaseUrl: string;
  apiBaseUrl: string;
  webVaultUrl: string;
  clientId: string;
  clientSecret: string;
  masterPassword: string;
  exposedCollection: string;
  agentCreatedCollection: string;
  timeoutMs: number;
  dryRun: boolean;
  readOnly: boolean;
}

export function loadConfig(): VaultConfig {
  const missing: string[] = [];
  const req = (name: string): string => {
    const v = process.env[name];
    if (!v) missing.push(name);
    return v ?? '';
  };
  const opt = (name: string): string => process.env[name] ?? '';

  const region = (opt('VAULT_REGION') || 'self-hosted') as VaultRegion;
  if (!['self-hosted', 'us', 'eu'].includes(region)) {
    throw new VaultConfigError(`Invalid VAULT_REGION "${region}" — must be self-hosted, us, or eu`);
  }

  // VAULT_API_BASE only required for self-hosted
  const apiBase = region === 'self-hosted' ? req('VAULT_API_BASE') : opt('VAULT_API_BASE');
  const clientId = req('VAULT_CLIENT_ID');
  const clientSecret = req('VAULT_CLIENT_SECRET');
  const masterPassword = req('VAULT_MASTER_PASSWORD');

  if (missing.length > 0) {
    throw new VaultConfigError(`Missing required env vars: ${missing.join(', ')}`);
  }

  const urls = resolveRegionUrls(region, apiBase);

  return {
    region,
    ...urls,
    clientId,
    clientSecret,
    masterPassword,
    exposedCollection: opt('VAULT_EXPOSED_COLLECTION') || 'mcp-exposed',
    agentCreatedCollection: opt('VAULT_AGENT_CREATED_COLLECTION') || 'mcp-agent-created',
    timeoutMs: Number(opt('VAULT_API_TIMEOUT_MS') || 15000),
    dryRun: process.env.DRY_RUN === '1',
    readOnly: process.env.READ_ONLY === '1',
  };
}

// ---------------------------------------------------------------------------
// Bitwarden API response types (sync endpoint)
// ---------------------------------------------------------------------------

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

interface SyncOrg {
  id: string;
  name: string;
  key: string;  // RSA EncString
}

interface SyncProfile {
  id: string;
  email: string;
  key: string;     // AES EncString — protected vault symkey
  privateKey: string;  // AES EncString — encrypted RSA private key DER
  kdf?: 0 | 1;         // Vaultwarden + Bitwarden Cloud field name (camelCase rename_all)
  kdfType?: 0 | 1;     // legacy alias — kept for safety
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  organizations: SyncOrg[];
}

interface SyncCollection {
  id: string;
  organizationId: string;
  name: string;  // AES EncString
}

interface SyncField {
  name: string;   // AES EncString
  value: string;  // AES EncString
  type: 0 | 1 | 2;  // 0=text, 1=hidden, 2=boolean
}

interface SyncLoginUri {
  uri: string;  // AES EncString
  match: number | null;
}

interface SyncLogin {
  username: string | null;  // AES EncString
  password: string | null;  // AES EncString
  totp: string | null;      // AES EncString
  uris: SyncLoginUri[] | null;
}

interface SyncCipher {
  id: string;
  organizationId: string | null;
  collectionIds: string[];
  type: 1 | 2 | 3 | 4;  // 1=login, 2=note, 3=card, 4=identity
  name: string;  // AES EncString
  notes: string | null;  // AES EncString
  fields: SyncField[] | null;
  login: SyncLogin | null;
  secureNote: { type: number } | null;
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
}

interface SyncResponse {
  profile: SyncProfile;
  collections: SyncCollection[];
  ciphers: SyncCipher[];
}

// ---------------------------------------------------------------------------
// Public tool response types
// ---------------------------------------------------------------------------

export type VaultItemType = 'api-key' | 'login' | 'password' | 'note' | 'card' | 'identity';

export interface VaultItemSummary {
  name: string;
  type: VaultItemType;
  collection: 'mcp-exposed' | 'mcp-agent-created';
  scope?: string;
  has_username: boolean;
  has_totp: boolean;
  has_uris: boolean;
  notes_preview?: string;
  created_at: string;
  expires_at?: string;
  created_by?: string;
}

export interface VaultItemDetail extends VaultItemSummary {
  username?: string;
  uris?: string[];
  has_password: boolean;
  notes?: string;
  custom_fields?: Record<string, string>;
}

export interface SendRevealResult {
  send_url: string;
  expires_at: string;
  max_views: number;
  delivery: 'chat' | 'telegram' | 'email';
  audit_id: string;
}

export interface SaveSecretResult {
  saved_as: string;
  expires_at: string;
  collection: 'mcp-agent-created';
  audit_id: string;
}

export interface HealthResult {
  status: 'ok' | 'degraded' | 'error';
  vault_url: string;
  api_version: string;
  authenticated: boolean;
  exposed_collection_visible: boolean;
  agent_created_collection_visible: boolean;
  items_in_exposed: number;
  items_in_agent_created: number;
  latency_ms: number;
}

// ---------------------------------------------------------------------------
// VaultClient
// ---------------------------------------------------------------------------

export class VaultClient {
  private accessToken: string | null = null;
  private tokenExpiry = 0;
  private syncData: SyncResponse | null = null;
  private vaultSymKey: SymKey | null = null;
  private orgSymKeys: Map<string, SymKey> = new Map();
  private collectionIds: { exposed: string | null; agentCreated: string | null } = {
    exposed: null,
    agentCreated: null,
  };
  private initialized = false;
  // Stable per-instance device ID — Vaultwarden 1.32+ and Bitwarden Cloud require
  // deviceIdentifier to be non-blank in client_credentials auth payloads.
  private readonly deviceIdentifier = crypto.randomUUID();

  constructor(public readonly config: VaultConfig) {}

  // -------------------------------------------------------------------------
  // HTTP helpers
  // -------------------------------------------------------------------------

  private async doFetch(url: string, init: RequestInit): Promise<Response> {
    let res: Response;
    try {
      res = await fetch(url, { ...init, signal: AbortSignal.timeout(this.config.timeoutMs) });
    } catch (err) {
      if (err instanceof Error && err.name === 'TimeoutError') {
        throw new VaultTimeoutError(`Request to ${url} timed out after ${this.config.timeoutMs}ms`);
      }
      throw new VaultConnectionError(err instanceof Error ? err.message : String(err));
    }
    return res;
  }

  // -------------------------------------------------------------------------
  // Auth
  // -------------------------------------------------------------------------

  private async authenticate(): Promise<void> {
    const url = `${this.config.identityBaseUrl}/connect/token`;
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      deviceType: '14',  // 14 = SDK — required by Vaultwarden 1.32+ and Bitwarden Cloud
      deviceIdentifier: this.deviceIdentifier,
      deviceName: 'aiwerk-mcp-server-vault',
    });

    const res = await this.doFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Bitwarden-Client-Version': '2026.1.0',
      },
      body: body.toString(),
    });

    if (res.status === 400 || res.status === 401) {
      const body = await res.json().catch(() => null) as { error?: string; error_description?: string } | null;
      throw new VaultAuthError(
        `Authentication failed: ${body?.error_description ?? body?.error ?? res.statusText}`,
      );
    }
    if (!res.ok) {
      throw new VaultConnectionError(`Token endpoint returned ${res.status} ${res.statusText}`);
    }

    const data = await res.json() as TokenResponse;
    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
    log.info({ event: 'auth_ok' }, 'Authenticated with Bitwarden API');
  }

  private async ensureToken(): Promise<string> {
    if (!this.accessToken || Date.now() >= this.tokenExpiry) {
      await this.authenticate();
    }
    return this.accessToken!;
  }

  private async apiGet<T>(path: string): Promise<T> {
    const token = await this.ensureToken();
    const res = await this.doFetch(`${this.config.apiBaseUrl}${path}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    });
    if (res.status === 401) {
      // Token expired mid-session, re-auth once
      await this.authenticate();
      const res2 = await this.doFetch(`${this.config.apiBaseUrl}${path}`, {
        headers: { Authorization: `Bearer ${this.accessToken!}`, Accept: 'application/json' },
      });
      if (!res2.ok) throw new VaultConnectionError(`API ${path} returned ${res2.status}`);
      return await res2.json() as T;
    }
    if (!res.ok) throw new VaultConnectionError(`API ${path} returned ${res.status} ${res.statusText}`);
    return await res.json() as T;
  }

  private async apiPost<T>(path: string, body: unknown): Promise<T> {
    const token = await this.ensureToken();
    const res = await this.doFetch(`${this.config.apiBaseUrl}${path}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (res.status === 401) throw new VaultAuthError('API returned 401 — token invalid');
    if (!res.ok) {
      const rb = await res.json().catch(() => null) as { message?: string } | null;
      throw new VaultConnectionError(`API ${path} returned ${res.status}: ${rb?.message ?? res.statusText}`);
    }
    return await res.json() as T;
  }

  private async apiDelete(path: string): Promise<void> {
    const token = await this.ensureToken();
    const res = await this.doFetch(`${this.config.apiBaseUrl}${path}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok && res.status !== 404) {
      throw new VaultConnectionError(`API DELETE ${path} returned ${res.status}`);
    }
  }

  // -------------------------------------------------------------------------
  // Initialization (auth + sync + key derivation + collection resolution)
  // -------------------------------------------------------------------------

  private async initializeKeys(profile: SyncProfile): Promise<void> {
    const kdf: KdfSettings = {
      kdfType: (profile.kdf ?? profile.kdfType ?? 0) as 0 | 1,
      kdfIterations: profile.kdfIterations,
      kdfMemory: profile.kdfMemory,
      kdfParallelism: profile.kdfParallelism,
    };

    const masterKey = await deriveMasterKey(this.config.masterPassword, profile.email, kdf);
    const stretchedKey = stretchMasterKey(masterKey);

    // Decrypt vault symmetric key
    const vaultSymKeyRaw = decryptAesCbc256(profile.key, stretchedKey);
    this.vaultSymKey = parseSymKey(vaultSymKeyRaw);

    // Decrypt RSA private key
    const privateKeyDer = decryptAesCbc256(profile.privateKey, this.vaultSymKey);

    // Decrypt org symmetric keys
    for (const org of profile.organizations) {
      try {
        const orgSymKeyRaw = decryptRsaEncString(org.key, privateKeyDer);
        this.orgSymKeys.set(org.id, parseSymKey(orgSymKeyRaw));
      } catch (err) {
        log.warn({ orgId: org.id, err: String(err) }, 'Failed to decrypt org key — skipping org');
      }
    }
  }

  private resolveCollections(collections: SyncCollection[]): void {
    for (const col of collections) {
      const symKey = this.orgSymKeys.get(col.organizationId);
      if (!symKey) continue;
      let name: string;
      try {
        name = decryptAesCbc256(col.name, symKey).toString('utf8');
      } catch {
        continue;
      }
      if (name === this.config.exposedCollection) this.collectionIds.exposed = col.id;
      if (name === this.config.agentCreatedCollection) this.collectionIds.agentCreated = col.id;
    }
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    const sync = await this.apiGet<SyncResponse>('/sync?excludeDomains=true');
    this.syncData = sync;
    await this.initializeKeys(sync.profile);
    this.resolveCollections(sync.collections);
    this.initialized = true;
    log.info(
      { exposedId: this.collectionIds.exposed, agentCreatedId: this.collectionIds.agentCreated },
      'Vault initialized',
    );
  }

  async refetchSync(): Promise<void> {
    this.initialized = false;
    this.syncData = null;
    this.vaultSymKey = null;
    this.orgSymKeys.clear();
    this.collectionIds = { exposed: null, agentCreated: null };
    await this.initialize();
  }

  // -------------------------------------------------------------------------
  // Cipher helpers
  // -------------------------------------------------------------------------

  private getSymKeyForCipher(cipher: SyncCipher): SymKey {
    if (!cipher.organizationId) {
      if (!this.vaultSymKey) throw new VaultAuthError('Vault not initialized');
      return this.vaultSymKey;
    }
    const k = this.orgSymKeys.get(cipher.organizationId);
    if (!k) throw new Error(`No sym key for org ${cipher.organizationId}`);
    return k;
  }

  private decryptStr(enc: string | null | undefined, symKey: SymKey): string | null {
    if (!enc) return null;
    try {
      return decryptAesCbc256(enc, symKey).toString('utf8');
    } catch {
      return null;
    }
  }

  private getCustomFields(cipher: SyncCipher, symKey: SymKey): Record<string, string> {
    const out: Record<string, string> = {};
    for (const f of cipher.fields ?? []) {
      const name = this.decryptStr(f.name, symKey);
      if (!name) continue;
      if (f.type === 1) continue;  // hidden fields excluded from metadata
      const value = this.decryptStr(f.value, symKey);
      if (value !== null) out[name] = value;
    }
    return out;
  }

  private getMcpField(cipher: SyncCipher, symKey: SymKey, fieldName: string): string | undefined {
    for (const f of cipher.fields ?? []) {
      const name = this.decryptStr(f.name, symKey);
      if (name === fieldName) return this.decryptStr(f.value, symKey) ?? undefined;
    }
    return undefined;
  }

  private cipherToType(cipher: SyncCipher, symKey: SymKey): VaultItemType {
    if (cipher.type === 3) return 'card';
    if (cipher.type === 4) return 'identity';
    if (cipher.type === 1) return 'login';
    // type 2 = secure note — distinguish by mcp-type custom field
    const mcpType = this.getMcpField(cipher, symKey, 'mcp-type');
    if (mcpType === 'api-key') return 'api-key';
    if (mcpType === 'password') return 'password';
    return 'note';
  }

  private isWhitelisted(cipher: SyncCipher): 'mcp-exposed' | 'mcp-agent-created' | null {
    if (this.collectionIds.exposed && cipher.collectionIds.includes(this.collectionIds.exposed))
      return 'mcp-exposed';
    if (this.collectionIds.agentCreated && cipher.collectionIds.includes(this.collectionIds.agentCreated))
      return 'mcp-agent-created';
    return null;
  }

  private parseSummary(cipher: SyncCipher): VaultItemSummary | null {
    const collection = this.isWhitelisted(cipher);
    if (!collection) return null;
    if (cipher.deletedDate) return null;  // skip deleted items

    const symKey = this.getSymKeyForCipher(cipher);
    const name = this.decryptStr(cipher.name, symKey);
    if (!name) return null;

    const type = this.cipherToType(cipher, symKey);
    const scope = this.getMcpField(cipher, symKey, 'mcp-scope');
    const expiresAt = this.getMcpField(cipher, symKey, 'mcp-expires-at');
    const createdBy = this.getMcpField(cipher, symKey, 'mcp-created-by');

    const hasTotp = !!(cipher.login?.totp);
    const hasUris = !!(cipher.login?.uris?.length);
    const hasUsername = !!(cipher.login?.username);

    // For notes_preview: only for non-secret types (login and note)
    let notesPreview: string | undefined;
    if ((type === 'note' || type === 'login') && cipher.notes) {
      const notes = this.decryptStr(cipher.notes, symKey);
      if (notes) notesPreview = notes.substring(0, 80);
    }

    return {
      name,
      type,
      collection,
      scope,
      has_username: hasUsername,
      has_totp: hasTotp,
      has_uris: hasUris,
      notes_preview: notesPreview,
      created_at: cipher.creationDate,
      expires_at: expiresAt,
      created_by: createdBy,
    };
  }

  private findCipherByName(name: string): { cipher: SyncCipher; symKey: SymKey; collection: 'mcp-exposed' | 'mcp-agent-created' } {
    if (!this.syncData) throw new VaultAuthError('Vault not initialized');
    const matches = this.syncData.ciphers.filter(c => {
      const col = this.isWhitelisted(c);
      if (!col) return false;
      if (c.deletedDate) return false;
      const sk = this.getSymKeyForCipher(c);
      const n = this.decryptStr(c.name, sk);
      return n === name;
    });

    if (matches.length === 0) throw new VaultItemNotFound(`Item "${name}" not found in mcp-exposed or mcp-agent-created`);
    if (matches.length > 1) {
      log.warn({ name }, 'Multiple items share this name — returning most recent');
      matches.sort((a, b) => new Date(b.revisionDate).getTime() - new Date(a.revisionDate).getTime());
    }

    const cipher = matches[0];
    const symKey = this.getSymKeyForCipher(cipher);
    const collection = this.isWhitelisted(cipher)!;
    return { cipher, symKey, collection };
  }

  // -------------------------------------------------------------------------
  // Public tool methods
  // -------------------------------------------------------------------------

  async listItems(filter?: string, collection?: string): Promise<VaultItemSummary[]> {
    await this.initialize();
    if (!this.syncData) throw new VaultAuthError('Vault not initialized');

    const items: VaultItemSummary[] = [];
    for (const cipher of this.syncData.ciphers) {
      const summary = this.parseSummary(cipher);
      if (!summary) continue;
      if (collection && summary.collection !== collection) continue;
      if (filter && !summary.name.toLowerCase().includes(filter.toLowerCase())) continue;
      items.push(summary);
    }

    items.sort((a, b) => a.name.localeCompare(b.name));
    return items;
  }

  async getItemDetail(name: string): Promise<VaultItemDetail> {
    await this.initialize();
    const { cipher, symKey, collection } = this.findCipherByName(name);
    const type = this.cipherToType(cipher, symKey);
    const scope = this.getMcpField(cipher, symKey, 'mcp-scope');
    const expiresAt = this.getMcpField(cipher, symKey, 'mcp-expires-at');
    const createdBy = this.getMcpField(cipher, symKey, 'mcp-created-by');

    const username = cipher.login?.username
      ? this.decryptStr(cipher.login.username, symKey) ?? undefined
      : undefined;

    const uris: string[] = [];
    for (const u of cipher.login?.uris ?? []) {
      const uri = this.decryptStr(u.uri, symKey);
      if (uri) uris.push(uri);
    }

    // Notes: only include for note and login types (not api-key or password — those store the secret in notes)
    let notes: string | undefined;
    if ((type === 'note' || type === 'login') && cipher.notes) {
      notes = this.decryptStr(cipher.notes, symKey) ?? undefined;
    }

    const customFields = this.getCustomFields(cipher, symKey);
    // Remove internal mcp-* fields from user-visible custom_fields
    const publicFields: Record<string, string> = {};
    for (const [k, v] of Object.entries(customFields)) {
      if (!k.startsWith('mcp-')) publicFields[k] = v;
    }

    return {
      name,
      type,
      collection,
      scope,
      username,
      uris: uris.length > 0 ? uris : undefined,
      has_password: !!(cipher.login?.password),
      has_totp: !!(cipher.login?.totp),
      has_uris: !!(cipher.login?.uris?.length),
      has_username: !!(cipher.login?.username),
      notes,
      notes_preview: undefined,
      created_at: cipher.creationDate,
      expires_at: expiresAt,
      created_by: createdBy,
      custom_fields: Object.keys(publicFields).length > 0 ? publicFields : undefined,
    };
  }

  async getItemValue(name: string, field?: string): Promise<string> {
    await this.initialize();
    const { cipher, symKey } = this.findCipherByName(name);
    const type = this.cipherToType(cipher, symKey);

    // Resolve the field to use
    const requestedField = field ?? 'value';

    if (requestedField === 'value') {
      // Default value field based on type
      if (type === 'login') {
        const pw = cipher.login?.password ? this.decryptStr(cipher.login.password, symKey) : null;
        if (!pw) throw new VaultFieldNotPresent(`Item "${name}" has no password field`);
        return pw;
      }
      // api-key, password, note — value in notes
      const notes = cipher.notes ? this.decryptStr(cipher.notes, symKey) : null;
      if (notes === null) throw new VaultFieldNotPresent(`Item "${name}" has no value`);
      return notes;
    }

    if (requestedField === 'username') {
      const u = cipher.login?.username ? this.decryptStr(cipher.login.username, symKey) : null;
      if (!u) throw new VaultFieldNotPresent(`Item "${name}" has no username`);
      return u;
    }

    if (requestedField === 'password') {
      const pw = cipher.login?.password ? this.decryptStr(cipher.login.password, symKey) : null;
      if (!pw) throw new VaultFieldNotPresent(`Item "${name}" has no password`);
      return pw;
    }

    if (requestedField === 'totp') {
      const totp = cipher.login?.totp ? this.decryptStr(cipher.login.totp, symKey) : null;
      if (!totp) throw new VaultTOTPNotConfigured(`Item "${name}" has no TOTP seed`);
      return totp;
    }

    if (requestedField.startsWith('uri')) {
      const idx = parseInt(requestedField.replace('uri', '') || '0', 10);
      const uri = cipher.login?.uris?.[idx];
      if (!uri) throw new VaultFieldNotPresent(`Item "${name}" has no URI at index ${idx}`);
      const uriStr = this.decryptStr(uri.uri, symKey);
      if (!uriStr) throw new VaultFieldNotPresent(`Item "${name}" URI[${idx}] could not be decrypted`);
      return uriStr;
    }

    throw new VaultFieldNotPresent(`Unknown field "${requestedField}" for item "${name}"`);
  }

  async revealViaSend(
    name: string,
    field?: string,
    ttlSeconds?: number,
    maxViews?: number,
  ): Promise<SendRevealResult> {
    // READ_ONLY wins over DRY_RUN
    if (this.config.readOnly) {
      throw new VaultWriteForbidden('reveal_secret_via_send blocked — server started with READ_ONLY=1');
    }

    await this.initialize();
    const { cipher, symKey } = this.findCipherByName(name);

    const secretValue = await this.getItemValue(name, field ?? 'value');
    const delivery = (this.getMcpField(cipher, symKey, 'mcp-delivery-channel') ?? 'chat') as 'chat' | 'telegram' | 'email';
    const actualTtl = Math.min(Math.max(ttlSeconds ?? 300, 30), 86400);
    const actualMaxViews = Math.min(Math.max(maxViews ?? 1, 1), 100);

    const deletionDate = new Date(Date.now() + actualTtl * 1000).toISOString();
    const keyMaterial = generateSendKeyMaterial();
    const sendSymKey = deriveSendKey(keyMaterial);

    // Encrypt send name and text using the send key
    const sendName = encryptAesCbc256(`vault-reveal-${name}-${Date.now()}`, sendSymKey);
    const sendText = encryptAesCbc256(secretValue, sendSymKey);

    // Encrypt the sendKey itself with the vault/org symkey (for owner access from vault UI)
    const sendKeyForStorage = encryptAesCbc256(
      Buffer.concat([sendSymKey.encKey, sendSymKey.macKey]),
      symKey,
    );

    if (this.config.dryRun) {
      log.info(
        { event: 'dry_run_send', name, field, ttlSeconds: actualTtl, maxViews: actualMaxViews },
        'DRY_RUN: would create Bitwarden Send',
      );
      const auditId = generateAuditId();
      return {
        send_url: `${this.config.webVaultUrl}/#/send/DRY_RUN_ID/DRY_RUN_KEY`,
        expires_at: deletionDate,
        max_views: actualMaxViews,
        delivery,
        audit_id: auditId,
      };
    }

    const sendPayload = {
      type: 0,  // text send
      key: sendKeyForStorage,
      name: sendName,
      text: { text: sendText, hidden: false },
      maxAccessCount: actualMaxViews,
      deletionDate,
      expirationDate: deletionDate,
      disabled: false,
    };

    const created = await this.apiPost<{ id: string; accessId: string }>('/sends', sendPayload);
    const sendUrl = buildSendUrl(this.config.webVaultUrl, created.accessId, keyMaterial);

    const auditId = generateAuditId();
    log.info({ event: 'vault_reveal_sent', name, field, delivery, auditId, sendId: created.id }, 'Send created');

    return {
      send_url: sendUrl,
      expires_at: deletionDate,
      max_views: actualMaxViews,
      delivery,
      audit_id: auditId,
    };
  }

  async getTotpCode(name: string): Promise<TotpResult & { audit_id: string }> {
    await this.initialize();
    const { cipher, symKey } = this.findCipherByName(name);

    const totpRaw = cipher.login?.totp ? this.decryptStr(cipher.login.totp, symKey) : null;
    if (!totpRaw) throw new VaultTOTPNotConfigured(`Item "${name}" has no TOTP seed`);

    const result = computeTotp(totpRaw);
    const auditId = generateAuditId();
    log.info({ event: 'vault_totp_resolved', name, period: result.period, auditId }, 'TOTP resolved');
    return { ...result, audit_id: auditId };
  }

  async saveGeneratedSecret(input: {
    name: string;
    value: string;
    type: 'password' | 'api-key';
    notes?: string;
    used_in?: string;
    expires_in_days?: number;
  }): Promise<SaveSecretResult> {
    // READ_ONLY wins over DRY_RUN
    if (this.config.readOnly) {
      throw new VaultWriteForbidden('save_generated_secret blocked — server started with READ_ONLY=1');
    }

    if (input.value.length > 4096) {
      throw new VaultPayloadTooLarge(`Value length ${input.value.length} exceeds 4096 char limit`);
    }

    await this.initialize();

    if (!this.collectionIds.agentCreated) {
      throw new VaultCollectionMissing(
        `Collection "${this.config.agentCreatedCollection}" not found in vault. Create it first via Vaultwarden UI.`,
      );
    }

    // Get the org ID for the agent-created collection
    const agentCol = this.syncData!.collections.find(c => c.id === this.collectionIds.agentCreated);
    if (!agentCol) throw new VaultCollectionMissing('mcp-agent-created collection metadata not found');
    const orgId = agentCol.organizationId;
    const orgSymKey = this.orgSymKeys.get(orgId);
    if (!orgSymKey) throw new VaultAuthError(`No sym key for org ${orgId}`);

    // Check name collision in mcp-agent-created
    const existing = this.syncData!.ciphers.find(c => {
      if (!c.collectionIds.includes(this.collectionIds.agentCreated!)) return false;
      if (c.deletedDate) return false;
      const sk = this.getSymKeyForCipher(c);
      return this.decryptStr(c.name, sk) === input.name;
    });
    if (existing) throw new VaultNameCollision(`Item "${input.name}" already exists in mcp-agent-created`);

    const now = new Date().toISOString();
    const expiresInDays = Math.min(Math.max(input.expires_in_days ?? 30, 1), 365);
    const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString();
    const auditId = generateAuditId();

    // Build encrypted custom fields
    const fields = [
      { name: 'mcp-type', value: input.type },
      { name: 'mcp-created-by', value: 'mcp-server-vault' },
      { name: 'mcp-created-at', value: now },
      { name: 'mcp-expires-at', value: expiresAt },
      ...(input.used_in ? [{ name: 'mcp-used-in', value: input.used_in }] : []),
    ].map(f => ({
      name: encryptAesCbc256(f.name, orgSymKey),
      value: encryptAesCbc256(f.value, orgSymKey),
      type: 0,
    }));

    // Value goes in notes; supplementary notes (if any) go in a separate custom field to avoid ambiguity
    const encName = encryptAesCbc256(input.name, orgSymKey);
    const encValue = encryptAesCbc256(input.value, orgSymKey);
    const encNotes = input.notes ? encryptAesCbc256(input.notes, orgSymKey) : null;

    if (this.config.dryRun) {
      log.info(
        { event: 'dry_run_save', name: input.name, type: input.type, expiresAt, auditId },
        'DRY_RUN: would create cipher',
      );
      return { saved_as: input.name, expires_at: expiresAt, collection: 'mcp-agent-created', audit_id: auditId };
    }

    const cipherPayload = {
      cipher: {
        type: 2,  // secure note
        organizationId: orgId,
        name: encName,
        notes: encValue,  // the secret value stored in notes
        fields: [
          ...fields,
          ...(encNotes ? [{ name: encryptAesCbc256('notes', orgSymKey), value: encNotes, type: 0 }] : []),
        ],
        secureNote: { type: 0 },
      },
      collectionIds: [this.collectionIds.agentCreated],
    };

    await this.apiPost('/ciphers/create', cipherPayload);

    // Refetch sync so the new item is visible
    await this.refetchSync();

    log.info({ event: 'vault_secret_generated', name: input.name, type: input.type, expiresAt, auditId }, 'Secret saved');
    return { saved_as: input.name, expires_at: expiresAt, collection: 'mcp-agent-created', audit_id: auditId };
  }

  async healthCheck(): Promise<HealthResult> {
    const start = Date.now();
    let authenticated = false;
    let apiVersion = 'unknown';

    try {
      await this.ensureToken();
      authenticated = true;

      // Fetch version
      try {
        const ver = await this.apiGet<{ version?: string; object?: string }>('/version');
        apiVersion = ver.version ?? 'unknown';
      } catch {
        // version endpoint may not exist on all Vaultwarden versions
      }

      await this.initialize();
    } catch (err) {
      const latency = Date.now() - start;
      return {
        status: 'error',
        vault_url: this.config.apiBaseUrl,
        api_version: apiVersion,
        authenticated,
        exposed_collection_visible: false,
        agent_created_collection_visible: false,
        items_in_exposed: 0,
        items_in_agent_created: 0,
        latency_ms: latency,
      };
    }

    const ciphers = this.syncData?.ciphers ?? [];
    const exposedItems = ciphers.filter(c =>
      this.collectionIds.exposed && c.collectionIds.includes(this.collectionIds.exposed) && !c.deletedDate
    ).length;
    const agentCreatedItems = ciphers.filter(c =>
      this.collectionIds.agentCreated && c.collectionIds.includes(this.collectionIds.agentCreated) && !c.deletedDate
    ).length;

    const latency = Date.now() - start;
    const degraded = !this.collectionIds.exposed && !this.collectionIds.agentCreated;

    return {
      status: degraded ? 'degraded' : 'ok',
      vault_url: this.config.apiBaseUrl,
      api_version: apiVersion,
      authenticated,
      exposed_collection_visible: !!this.collectionIds.exposed,
      agent_created_collection_visible: !!this.collectionIds.agentCreated,
      items_in_exposed: exposedItems,
      items_in_agent_created: agentCreatedItems,
      latency_ms: latency,
    };
  }
}
