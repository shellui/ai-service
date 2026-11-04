#!/usr/bin/env node
/**
 * MCP conformance: official TypeScript SDK + Streamable HTTP + Shellui OAuth.
 */
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js';
class InMemoryOAuthClientProvider {
  constructor(redirectUrl, clientMetadata, onRedirect) {
    this._redirectUrl = redirectUrl;
    this._clientMetadata = clientMetadata;
    this._onRedirect = onRedirect || ((url) => console.error(`Redirect: ${url}`));
  }
  get redirectUrl() {
    return this._redirectUrl;
  }
  get clientMetadata() {
    return this._clientMetadata;
  }
  clientInformation() {
    return this._clientInformation;
  }
  saveClientInformation(clientInformation) {
    this._clientInformation = clientInformation;
  }
  tokens() {
    return this._tokens;
  }
  saveTokens(tokens) {
    this._tokens = tokens;
  }
  redirectToAuthorization(authorizationUrl) {
    this._onRedirect(authorizationUrl);
  }
  saveCodeVerifier(codeVerifier) {
    this._codeVerifier = codeVerifier;
  }
  codeVerifier() {
    if (!this._codeVerifier) throw new Error('No code verifier saved');
    return this._codeVerifier;
  }
}

const MCP_URL = process.env.MCP_URL || 'http://localhost:8006/c/1/mcp';
const GATEWAY_TOOL_NAME_RE =
  /^(?:ai|identity|storage|hosting|email|saas)_[a-z][a-z0-9]*(?:_[a-z][a-z0-9]+)+$/;
const ANNOTATION_KEYS = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'];
const CALLBACK_PORT = Number(process.env.MCP_E2E_CALLBACK_PORT || '8765');
const CALLBACK_URL = `http://127.0.0.1:${CALLBACK_PORT}/callback`;
const COMPOSE_FILE = process.env.MCP_E2E_COMPOSE_FILE;
const IDENTITY_ORIGIN = process.env.IDENTITY_ORIGIN || 'http://localhost:8001';
const HEADLESS = join(dirname(fileURLToPath(import.meta.url)), '..', 'headless_identity_oauth.py');
const SHELLUI_MCP_AUTHORIZE_QUERY_KEY = 'shellui_mcp_authorize_query';

async function appendShelluiAuthorizeParams(authorizationUrl, mcpUrl) {
  const mcp = new URL(mcpUrl);
  const parts = mcp.pathname.split('/').filter(Boolean);
  if (parts.length < 3 || parts[0] !== 'c' || parts.at(-1) !== 'mcp') return authorizationUrl;
  const companyId = parts[1];
  const metaUrl = `${mcp.origin}/.well-known/oauth-protected-resource/c/${companyId}/mcp`;
  let extra = {};
  try {
    const res = await fetch(metaUrl);
    if (res.ok) {
      const body = await res.json();
      const ext = body[SHELLUI_MCP_AUTHORIZE_QUERY_KEY];
      if (ext && typeof ext === 'object') extra = ext;
    }
  } catch {
    return authorizationUrl;
  }
  const url = new URL(authorizationUrl);
  for (const [key, value] of Object.entries(extra)) {
    if (!url.searchParams.has(key)) url.searchParams.set(key, String(value));
  }
  return url.toString();
}

function fail(msg) {
  console.error(`[ts-sdk] ${msg}`);
  process.exit(1);
}

function runHeadless(authUrl) {
  if (!COMPOSE_FILE) fail('MCP_E2E_COMPOSE_FILE is required');
  const py = process.env.MCP_E2E_PYTHON || 'python3';
  const result = spawnSync(
    py,
    [
      HEADLESS,
      '--authorization-url',
      authUrl,
      '--identity-origin',
      IDENTITY_ORIGIN,
      '--compose-file',
      COMPOSE_FILE,
      '--email',
      process.env.MCP_E2E_USER_EMAIL || 'dev@localhost',
      '--company-id',
      process.env.MCP_E2E_COMPANY_ID || '1',
    ],
    { encoding: 'utf-8' },
  );
  if (result.status !== 0) {
    fail(`headless OAuth failed: ${result.stderr || result.stdout}`);
  }
  return result.stdout.trim().split('\n')[0];
}

async function connectWithOAuth(client) {
  const clientMetadata = {
    client_name: 'Shellui MCP E2E (TypeScript SDK)',
    redirect_uris: [CALLBACK_URL],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  };
  let pendingAuthUrl = null;
  const oauthProvider = new InMemoryOAuthClientProvider(
    CALLBACK_URL,
    clientMetadata,
    (redirectUrl) => {
      pendingAuthUrl = redirectUrl.toString();
    },
  );
  const makeTransport = () =>
    new StreamableHTTPClientTransport(new URL(MCP_URL), { authProvider: oauthProvider });
  let transport = makeTransport();
  try {
    await client.connect(transport);
  } catch (error) {
    if (!(error instanceof UnauthorizedError)) throw error;
    if (!pendingAuthUrl) fail('OAuth redirect URL missing');
    const authUrl = await appendShelluiAuthorizeParams(pendingAuthUrl, MCP_URL);
    const code = runHeadless(authUrl);
    await transport.finishAuth(code);
    transport = makeTransport();
    await client.connect(transport);
  }
  return { transport, oauthProvider };
}

async function main() {
  const client = new Client({ name: 'shellui-mcp-e2e-ts', version: '1.0.0' }, { capabilities: {} });
  const { oauthProvider, transport } = await connectWithOAuth(client);
  const tools = await client.listTools();
  if (!tools.tools?.length) fail('tools/list returned no tools');
  const target = tools.tools.find((t) => t.name === 'ai_list_services');
  if (!target) fail('ai_list_services missing from tools/list');
  for (const t of tools.tools) {
    const name = String(t.name || '');
    if (name.includes('api_v1') || name.includes('__')) fail(`tool ${name} invalid name`);
    if (/_\d+$/.test(name)) fail(`tool ${name} numeric collision suffix`);
    if (!GATEWAY_TOOL_NAME_RE.test(name)) fail(`tool ${name} must match service_verb_noun`);
    if (!String(t.title || '').trim()) fail(`tool ${t.name} missing title`);
    if (String(t.description || '').trim().length < 20) fail(`tool ${t.name} description too short`);
    if (!t.annotations || typeof t.annotations !== 'object') fail(`tool ${t.name} missing annotations`);
    for (const key of ANNOTATION_KEYS) {
      if (!(key in t.annotations)) fail(`tool ${t.name} missing annotations.${key}`);
    }
  }
  const result = await client.callTool({ name: target.name, arguments: {} });
  if (result.isError) fail(`tools/call error: ${JSON.stringify(result)}`);
  const refresh = oauthProvider.tokens()?.refresh_token;
  if (!refresh) fail('no refresh_token after OAuth');
  const tokenFile = process.env.MCP_E2E_TOKEN_FILE;
  if (tokenFile) {
    writeFileSync(tokenFile, oauthProvider.tokens().access_token, 'utf8');
  }
  console.log('[ts-sdk] initialize, tools/list, tools/call, refresh_token: ok');
  await transport.close();
  await client.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
