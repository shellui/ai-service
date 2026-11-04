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

const MCP_URL = process.env.MCP_URL || 'http://127.0.0.1:8006/c/1/mcp';
const CALLBACK_PORT = Number(process.env.MCP_E2E_CALLBACK_PORT || '8765');
const CALLBACK_URL = `http://127.0.0.1:${CALLBACK_PORT}/callback`;
const COMPOSE_FILE = process.env.MCP_E2E_COMPOSE_FILE;
const IDENTITY_ORIGIN = process.env.IDENTITY_ORIGIN || 'http://127.0.0.1:8001';
const HEADLESS = join(dirname(fileURLToPath(import.meta.url)), '..', 'headless_identity_oauth.py');

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
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), { authProvider: oauthProvider });
  try {
    await client.connect(transport);
  } catch (error) {
    if (!(error instanceof UnauthorizedError)) throw error;
    if (!pendingAuthUrl) fail('OAuth redirect URL missing');
    const code = runHeadless(pendingAuthUrl);
    await transport.finishAuth(code);
    await client.connect(transport);
  }
  return { transport, oauthProvider };
}

async function main() {
  const client = new Client({ name: 'shellui-mcp-e2e-ts', version: '1.0.0' }, { capabilities: {} });
  const { oauthProvider, transport } = await connectWithOAuth(client);
  const tools = await client.listTools();
  if (!tools.tools?.length) fail('tools/list returned no tools');
  const target = tools.tools.find((t) => t.name === 'api_v1_mcp_services_list');
  if (!target) fail('api_v1_mcp_services_list missing from tools/list');
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
