export interface ClientDescriptor {
  clientId: Uint8Array;
  clientIdPrefix: Uint8Array;
  enabled: boolean;
  metadata?: Record<string, string>;
}

export interface ClientRegistry {
  getByPrefix(clientIdPrefix: Uint8Array): Promise<ClientDescriptor | null>;
}

export interface GenerationRecord {
  latestBundleGen: number;
  firstUsedAt?: number;
  updatedAt: number;
}

export interface GenerationStore {
  get(clientId: Uint8Array): Promise<GenerationRecord>;
  advance(clientId: Uint8Array, newGen: number): Promise<GenerationRecord>;
  markUsed(clientId: Uint8Array, gen: number): Promise<GenerationRecord>;
}

export interface ReplayGuard {
  check(ticketId: number, seq: number, bundleGen: bigint): boolean;
  checkSeqWindow(seq: number, counterBase: number, queryBudget: number): boolean;
}

export interface ResolverResult {
  resolverId: number;
  rttMs: number;
  dnsResponse: Uint8Array;
  fallback: boolean;
}

export interface Resolver {
  resolve(dnsQuery: Uint8Array): Promise<ResolverResult>;
}

export interface Clock {
  nowMs(): bigint;
}

export interface Logger {
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}
