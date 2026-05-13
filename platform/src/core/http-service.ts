import type { RequestHooks } from './services/deps';

export interface HttpServiceConfig {
  protocolPath: string;
  protocolVersion: number;
  appVersion: string;
}

export interface HttpServiceHandlers {
  handleProtocolRequest(request: Request, requestHooks?: RequestHooks): Promise<Response>;
}

export function createHttpService(
  config: HttpServiceConfig,
  handlers: HttpServiceHandlers,
) {
  return {
    async handle(request: Request, requestHooks?: RequestHooks): Promise<Response> {
      const url = new URL(request.url);

      if (url.pathname === '/health' && request.method === 'GET') {
        return new Response(JSON.stringify({
          status: 'ok',
          version: config.appVersion,
          protocol: config.protocolVersion,
        }), {
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.pathname === config.protocolPath && request.method === 'POST') {
        return handlers.handleProtocolRequest(request, requestHooks);
      }

      return new Response('Not Found', { status: 404 });
    },
  };
}
