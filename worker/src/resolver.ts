/**
 * Trusted-DNS DoH Upstream Resolver
 *
 * Implements the "Primary + Secondary Race, Tertiary Fallback" strategy.
 * Sends DNS wire-format queries to DoH upstreams via HTTP POST with
 * Content-Type: application/dns-message per RFC 8484.
 */

export interface ResolverResult {
  resolverId: number;      // 0-based index of the upstream that responded
  rttMs: number;           // round-trip time in milliseconds
  dnsResponse: Uint8Array; // raw DNS wire-format response
  fallback: boolean;       // whether tertiary fallback was used
}

export interface ResolverConfig {
  upstreams: string[];     // DoH endpoint URLs
  timeoutMs: number;       // per-upstream timeout
}

const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Resolve a DNS query using the race + fallback strategy.
 *
 * 1. Send to primary and secondary concurrently
 * 2. Return whichever responds first with a valid DNS response
 * 3. If both fail/timeout, try tertiary
 */
export async function resolve(
  dnsQuery: Uint8Array,
  config: ResolverConfig,
): Promise<ResolverResult> {
  const { upstreams, timeoutMs } = config;
  if (upstreams.length === 0) {
    throw new Error('No DoH upstreams configured');
  }

  // Helper: send DNS query to a single upstream
  const queryUpstream = async (
    url: string,
    index: number,
  ): Promise<ResolverResult> => {
    const start = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs || DEFAULT_TIMEOUT_MS);

    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message',
        },
        body: dnsQuery,
        signal: controller.signal,
      });

      if (!resp.ok) {
        throw new Error(`Upstream ${index} returned HTTP ${resp.status}`);
      }

      const contentType = resp.headers.get('content-type') || '';
      if (!contentType.includes('application/dns-message')) {
        throw new Error(`Upstream ${index} returned unexpected content-type: ${contentType}`);
      }

      const body = await resp.arrayBuffer();
      const dnsResponse = new Uint8Array(body);

      // Basic validity: DNS response must be at least 12 bytes (header)
      if (dnsResponse.length < 12) {
        throw new Error(`Upstream ${index} returned too-short DNS response`);
      }

      return {
        resolverId: index,
        rttMs: Date.now() - start,
        dnsResponse,
        fallback: false,
      };
    } finally {
      clearTimeout(timer);
    }
  };

  // Phase 1: Race primary and secondary
  const raceCandidates = upstreams.slice(0, Math.min(2, upstreams.length));
  const racePromises = raceCandidates.map((url, i) =>
    queryUpstream(url, i).catch((err) => {
      throw { index: i, error: err };
    }),
  );

  try {
    // Promise.any resolves with the first fulfilled promise
    const result = await Promise.any(racePromises);
    return result;
  } catch {
    // All race candidates failed
  }

  // Phase 2: Tertiary fallback
  if (upstreams.length > 2) {
    try {
      const result = await queryUpstream(upstreams[2], 2);
      result.fallback = true;
      return result;
    } catch {
      // Tertiary also failed
    }
  }

  throw new Error('All DoH upstreams failed');
}

/**
 * Parse DoH upstream configuration from environment variable.
 */
export function parseUpstreams(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.filter((u: unknown) => typeof u === 'string' && u.startsWith('https://'));
    }
  } catch {
    // Try comma-separated
    return raw
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.startsWith('https://'));
  }
  return [];
}
