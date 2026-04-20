#!/usr/bin/env node

import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { TwentyClient } from './client/twenty-client.js';
import { registerPersonTools, registerCompanyTools, registerTaskTools, registerOpportunityTools, registerUrlTools } from './tools/index.js';
import { WellKnownRoutes } from './routes/well-known.js';
import { AuthMiddleware, AuthenticatedRequest } from './auth/middleware.js';
import { TokenValidator } from './auth/token-validator.js';
import { ClerkClient } from './auth/clerk-client.js';
import { getKeyStorageService } from './auth/key-storage.js';
import { ApiKeyRoutes } from './routes/api-keys.js';
import { IPMiddleware } from './auth/ip-middleware.js';

async function main() {
  const port = parseInt(process.env.PORT || '3000');
  const authEnabled = process.env.AUTH_ENABLED === 'true';
  const wellKnownRoutes = new WellKnownRoutes();
  const ipMiddleware = new IPMiddleware();
  
  // Initialize auth components only if auth is enabled
  let clerkClient: ClerkClient | null = null;
  let tokenValidator: TokenValidator | null = null;
  let authMiddleware: AuthMiddleware | null = null;
  let keyStorage: any = null;
  let apiKeyRoutes: ApiKeyRoutes | null = null;
  
  if (authEnabled) {
    clerkClient = new ClerkClient();
    tokenValidator = new TokenValidator(clerkClient);
    authMiddleware = new AuthMiddleware(tokenValidator);
    keyStorage = getKeyStorageService();
    apiKeyRoutes = new ApiKeyRoutes();
  }

  // Map of MCP session ID -> live transport. Sticky sessions are required by
  // the Streamable HTTP spec: the initialize request creates a session, and
  // follow-up calls (tools/list, tool invocations) reuse the same transport.
  const transports: Record<string, StreamableHTTPServerTransport> = {};

  // Parse configuration from multiple sources
  async function parseConfig(url: string, userId?: string) {
    const urlObj = new URL(url, `http://localhost:${port}`);
    const params = urlObj.searchParams;
    
    // Check for user-specific stored API key first
    let apiKey = params.get('apiKey');
    let baseUrl = params.get('baseUrl');
    let webUrl = params.get('webUrl');

    if (authEnabled && userId && !apiKey && keyStorage) {
      const storedKey = await keyStorage.getApiKey(userId);
      if (storedKey) {
        apiKey = storedKey.twentyApiKey;
        baseUrl = storedKey.twentyBaseUrl || baseUrl;
      }
    }

    // Priority: URL params > User stored key > Environment variables > Smithery config
    return {
      apiKey: apiKey ||
              process.env.TWENTY_API_KEY ||
              process.env.SMITHERY_CONFIG_APIKEY ||
              process.env.apiKey,
      baseUrl: baseUrl ||
               process.env.TWENTY_BASE_URL ||
               process.env.SMITHERY_CONFIG_BASEURL ||
               process.env.baseUrl ||
               'https://api.twenty.com',
      webUrl: webUrl ||
              process.env.TWENTY_WEB_URL ||
              process.env.SMITHERY_CONFIG_WEBURL ||
              undefined,
    };
  }

  // Create HTTP server
  const httpServer = createServer(async (req, res) => {
    // Check IP allowlist first (before any other processing)
    if (!await ipMiddleware.checkAccess(req, res)) {
      return; // IP middleware already sent response
    }
    
    // Handle CORS preflight requests
    if (req.method === 'OPTIONS') {
      await wellKnownRoutes.handleOptions(req, res);
      return;
    }
    
    // Handle health check endpoint
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        status: 'healthy', 
        service: 'twenty-mcp-server', 
        authEnabled,
        ipProtection: ipMiddleware.getConfig().enabled
      }));
      return;
    }
    
    // Handle API key management endpoints
    if (req.url?.startsWith('/api/keys')) {
      if (!authEnabled || !authMiddleware || !apiKeyRoutes) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
        return;
      }
      const authReq = req as AuthenticatedRequest;
      if (!await authMiddleware.authenticate(authReq, res)) {
        return;
      }
      await apiKeyRoutes.handle(authReq, res);
      return;
    }
    
    // Handle OAuth discovery endpoints.
    // MCP clients following the Protected Resource Metadata spec fetch
    // /.well-known/oauth-protected-resource/<resource-path> (e.g. .../mcp).
    if (
      req.url === '/.well-known/oauth-protected-resource' ||
      req.url === '/.well-known/oauth-protected-resource/mcp'
    ) {
      if (!authEnabled) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
        return;
      }
      await wellKnownRoutes.handleProtectedResource(req, res);
      return;
    }
    
    if (req.url === '/.well-known/oauth-authorization-server') {
      if (!authEnabled) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
        return;
      }
      await wellKnownRoutes.handleAuthorizationServer(req, res);
      return;
    }

    // Only handle /mcp endpoint
    if (!req.url?.startsWith('/mcp')) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    try {
      // Authenticate request if auth is enabled
      const authReq = req as AuthenticatedRequest;
      if (authEnabled && authMiddleware) {
        if (!await authMiddleware.authenticate(authReq, res)) {
          return; // Auth middleware already sent response
        }
      }

      // Read the body up front on POST so we can detect initialize requests
      // before deciding whether to reuse a session or create a new one.
      let body: any = undefined;
      if (req.method === 'POST') {
        const chunks: Buffer[] = [];
        for await (const chunk of req) {
          chunks.push(chunk as Buffer);
        }
        const bodyText = Buffer.concat(chunks).toString();
        if (bodyText.trim()) {
          try {
            body = JSON.parse(bodyText);
          } catch (error) {
            console.error('Error parsing request body:', error);
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON in request body' }));
            return;
          }
        }
      }

      const sessionIdHeader = req.headers['mcp-session-id'];
      const sessionId = Array.isArray(sessionIdHeader) ? sessionIdHeader[0] : sessionIdHeader;

      let transport: StreamableHTTPServerTransport;

      if (sessionId && transports[sessionId]) {
        // Continue an existing MCP session.
        transport = transports[sessionId];
      } else if (!sessionId && req.method === 'POST' && isInitializeRequest(body)) {
        // New session: validate config, build a server + tools, spin up a transport.
        const userId = authReq.auth?.userId;
        const config = await parseConfig(req.url!, userId);

        if (!config.apiKey) {
          if (authEnabled && userId) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'No API key configured',
              error_description: 'Please configure your Twenty API key first',
            }));
            return;
          }
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing required apiKey parameter' }));
          return;
        }

        const server = new McpServer(
          { name: 'twenty-mcp-server', version: '1.0.0' },
          { capabilities: { tools: {} } },
        );

        const client = new TwentyClient({
          apiKey: config.apiKey,
          baseUrl: config.baseUrl,
          webUrl: config.webUrl,
        });

        registerPersonTools(server, client);
        registerCompanyTools(server, client);
        registerTaskTools(server, client);
        registerOpportunityTools(server, client);
        registerUrlTools(server, client);

        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId: string) => {
            transports[newSessionId] = transport;
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            delete transports[transport.sessionId];
          }
        };

        await server.connect(transport);
      } else {
        // Request references a session we don't have, or isn't an initialize.
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Invalid MCP request',
          error_description: sessionId
            ? 'Unknown or expired session ID; send an initialize request to start a new session'
            : 'Missing session ID; send an initialize request to start a new session',
        }));
        return;
      }

      await transport.handleRequest(req, res, body);
    } catch (error) {
      console.error('Error handling request:', error);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Internal server error',
          message: error instanceof Error ? error.message : 'Unknown error',
        }));
      }
    }
  });

  httpServer.listen(port, () => {
    console.log(`Twenty MCP Server running at http://localhost:${port}/mcp`);
    console.log(`Health check available at http://localhost:${port}/health`);
    
    // Log configuration source for debugging
    if (process.env.SMITHERY_CONFIG_APIKEY) {
      console.log('Running in Smithery environment');
    } else if (process.env.TWENTY_API_KEY) {
      console.log('Using environment variables for configuration');
    } else {
      console.log(`Example: http://localhost:${port}/mcp?apiKey=YOUR_API_KEY&baseUrl=https://api.twenty.com`);
    }
  });
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});