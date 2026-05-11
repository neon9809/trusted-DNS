/**
 * Cloudflare runtime bindings for the current Worker deployment.
 *
 * The v2 goal is to keep this file as the only place that knows about concrete
 * Cloudflare bindings required by the adapter layer.
 */

export interface CloudflareEnv {
  ROOT_SEED: string;
  DOH_UPSTREAMS: string;
  GENERATION_STORE: DurableObjectNamespace;
  DOH_TIMEOUT_MS?: string;
  DEBUG_MODE?: string;
  PROTOCOL_PATH?: string;
}
