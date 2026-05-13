import { GenerationStore } from './generation-store';
import { createCloudflareHttpAdapter } from './adapters/cloudflare/http-adapter';
import type { CloudflareEnv } from './adapters/cloudflare/env';

export { GenerationStore };

export default {
  async fetch(request: Request, env: CloudflareEnv, ctx: ExecutionContext): Promise<Response> {
    const adapter = createCloudflareHttpAdapter(env);
    return adapter.handle(request, ctx);
  },
};
