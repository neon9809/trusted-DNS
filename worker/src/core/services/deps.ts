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

export interface GenerationBackend {
  getState(clientId: Uint8Array): Promise<GenerationStateLike>;
  advance(clientId: Uint8Array, newGen: number): Promise<GenerationStateLike>;
  markUsed(clientId: Uint8Array, gen: number): Promise<GenerationStateLike>;
}

export interface ServiceDeps {
  clients: ClientSelector;
  generation: GenerationBackend;
  nowMs(): bigint;
}
