import { createStaticClientSelector, type StaticClientSelectorConfig } from './client-registry';
import { handleProtocolRequest } from './handlers';
import { createHttpService } from './core/http-service';
import type { GenerationBackend, RequestHooks, ServiceDeps } from './core/services/deps';
import type { Logger } from './core/interfaces';

export interface RuntimeHttpConfig {
  protocolPath: string;
  protocolVersion: number;
  appVersion: string;
}

export interface RuntimeServiceOptions {
  http: RuntimeHttpConfig;
  clients: StaticClientSelectorConfig;
  generation: GenerationBackend;
  logger?: Logger;
  nowMs?: () => bigint;
}

export function createRuntimeHttpHandler(options: RuntimeServiceOptions) {
  const deps: ServiceDeps = {
    clients: createStaticClientSelector(options.clients),
    generation: options.generation,
    nowMs: options.nowMs ?? (() => BigInt(Date.now())),
  };

  const service = createHttpService(options.http, {
    handleProtocolRequest(request, requestHooks) {
      return handleProtocolRequest(request, deps, options.logger, requestHooks);
    },
  });

  return {
    handle(request: Request, requestHooks?: RequestHooks) {
      return service.handle(request, requestHooks);
    },
  };
}
