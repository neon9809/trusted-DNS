/**
 * Trusted-DNS Worker Entry Point
 *
 * Cloudflare Worker that serves as the secure relay between
 * Docker nodes and DoH upstream resolvers.
 *
 * Routes:
 *   POST /dns-query  - Main protocol endpoint (Bootstrap/Query/Refresh)
 *   GET  /health     - Health check endpoint
 */

import { handleRequest, Env } from './handlers';
import { GenerationStore } from './generation-store';

export { GenerationStore };

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const protocolPath = env.PROTOCOL_PATH || '/dns-query';

    // Health check
    if (url.pathname === '/health' && request.method === 'GET') {
      return new Response(JSON.stringify({
        status: 'ok',
        version: '0.1.0',
        protocol: 1,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Main protocol endpoint
    if (url.pathname === protocolPath && request.method === 'POST') {
      return handleRequest(request, env);
    }

    // Not found
    return new Response('Not Found', { status: 404 });
  },
};
