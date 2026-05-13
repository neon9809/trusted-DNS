export interface ClientConfig {
  rootSeedHex: string;
  dohUpstreams: string;
  dohTimeoutMs: number;
}

export interface ClientSelector {
  getClientConfig(clientIdPrefix: Uint8Array): Promise<ClientConfig | null>;
}

export interface GenerationStateLike {
  latestBundleGen: number;
  firstUsedAt?: number;
  updatedAt?: number;
}

export interface GenerationReadOptions {
  consistency?: 'eventual' | 'strong';
}

export interface CachedGenerationStateLike extends GenerationStateLike {
  fetchedAt: number;
  source: 'do' | 'local-write';
}

export interface GenerationBackend {
  getState(
    clientId: Uint8Array,
    options?: GenerationReadOptions,
  ): Promise<GenerationStateLike>;
  getCachedState(clientId: Uint8Array): Promise<CachedGenerationStateLike | null>;
  advance(clientId: Uint8Array, newGen: number): Promise<GenerationStateLike>;
  markUsed(clientId: Uint8Array, gen: number): Promise<GenerationStateLike>;
}

export interface RequestHooks {
  defer(task: () => Promise<unknown>): void;
}

export interface ServiceDeps {
  clients: ClientSelector;
  generation: GenerationBackend;
  nowMs(): bigint;
}
