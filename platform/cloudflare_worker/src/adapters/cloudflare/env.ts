export interface CloudflareEnv {
  ROOT_SEED: string;
  DOH_UPSTREAMS: string;
  GENERATION_STORE: DurableObjectNamespace;
  DOH_TIMEOUT_MS?: string;
  GENERATION_CACHE_TTL_MS?: string;
  DEBUG_MODE?: string;
  PROTOCOL_PATH?: string;
  CLIENT_REGISTRY?: string;
}
