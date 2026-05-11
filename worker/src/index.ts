/**
 * Trusted-DNS Worker Entry Point
 *
 * v2 migration note:
 * The entrypoint now routes through a Cloudflare adapter so platform concerns
 * can be isolated from future service-core extraction.
 */

import { GenerationStore } from './generation-store';
import { createCloudflareHttpAdapter } from './adapters/cloudflare/http-adapter';
import type { CloudflareEnv } from './adapters/cloudflare/env';

export { GenerationStore };

export default {
  async fetch(request: Request, env: CloudflareEnv, ctx: ExecutionContext): Promise<Response> {
    const adapter = createCloudflareHttpAdapter(env);
    return adapter.handle(request);
  },
};
