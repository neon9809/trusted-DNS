/**
 * Trusted-DNS Anti-Replay Module
 *
 * Implements a short-window deduplication cache to detect and reject
 * replayed query requests. Uses (ticket_id, seq) pairs with TTL-based
 * expiration. This runs in Worker memory and is per-isolate.
 */

export interface ReplayEntry {
  ticketId: number;
  seq: number;
  timestamp: number;
}

export class AntiReplayCache {
  private cache: Map<string, number>; // key -> timestamp
  private readonly windowSize: number;
  private readonly ttlMs: number;
  private lastCleanup: number;

  /**
   * @param windowSize - Maximum number of entries to track
   * @param ttlMs - Time-to-live for each entry in milliseconds
   */
  constructor(windowSize: number = 4096, ttlMs: number = 60_000) {
    this.cache = new Map();
    this.windowSize = windowSize;
    this.ttlMs = ttlMs;
    this.lastCleanup = Date.now();
  }

  /**
   * Check if a (ticketId, seq) pair has been seen recently.
   * If not seen, records it and returns false.
   * If seen (replay detected), returns true.
   */
  check(ticketId: number, seq: number, bundleGen: bigint): boolean {
    const now = Date.now();
    const key = `${bundleGen}:${ticketId}:${seq}`;

    // Periodic cleanup
    if (now - this.lastCleanup > this.ttlMs) {
      this.cleanup(now);
    }

    // Check for replay
    const existing = this.cache.get(key);
    if (existing !== undefined && now - existing < this.ttlMs) {
      return true; // replay detected
    }

    // Record
    this.cache.set(key, now);

    // Evict oldest if over capacity
    if (this.cache.size > this.windowSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }

    return false; // not a replay
  }

  /**
   * Verify that seq is within the acceptable window for a ticket.
   * The seq must be >= counterBase and < counterBase + queryBudget.
   */
  checkSeqWindow(
    seq: number,
    counterBase: number,
    queryBudget: number,
  ): boolean {
    return seq >= counterBase && seq < counterBase + queryBudget;
  }

  private cleanup(now: number): void {
    for (const [key, ts] of this.cache) {
      if (now - ts > this.ttlMs) {
        this.cache.delete(key);
      }
    }
    this.lastCleanup = now;
  }
}
