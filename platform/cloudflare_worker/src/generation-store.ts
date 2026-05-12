/**
 * Trusted-DNS Generation State Store (Durable Object)
 *
 * Maintains the minimal per-client state: latest_bundle_gen.
 * Each client_id maps to a unique Durable Object instance.
 * This ensures "new generation invalidates old generation" semantics.
 */

export interface GenerationState {
  latestBundleGen: number;
  firstUsedAt?: number;    // timestamp when new gen was first used
  updatedAt: number;
}

export class GenerationStore implements DurableObject {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case '/get':
          return this.handleGet();
        case '/advance':
          return this.handleAdvance(request);
        case '/mark-used':
          return this.handleMarkUsed(request);
        default:
          return new Response('Not Found', { status: 404 });
      }
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  /**
   * GET /get - Retrieve current generation state
   */
  private async handleGet(): Promise<Response> {
    const gen = await this.state.storage.get<GenerationState>('gen');
    if (!gen) {
      return Response.json({ latestBundleGen: 0, updatedAt: 0 });
    }
    return Response.json(gen);
  }

  /**
   * POST /advance - Advance to next generation
   * Body: { newGen: number }
   */
  private async handleAdvance(request: Request): Promise<Response> {
    const body = await request.json() as { newGen: number };
    const current = await this.state.storage.get<GenerationState>('gen');
    const currentGen = current?.latestBundleGen ?? 0;

    if (body.newGen <= currentGen) {
      return Response.json(
        { error: 'new generation must be greater than current', currentGen },
        { status: 409 },
      );
    }

    const newState: GenerationState = {
      latestBundleGen: body.newGen,
      updatedAt: Date.now(),
    };

    await this.state.storage.put('gen', newState);
    return Response.json(newState);
  }

  /**
   * POST /mark-used - Mark that the current generation's ticket has been used
   * This finalizes the generation transition (old gen becomes invalid)
   */
  private async handleMarkUsed(request: Request): Promise<Response> {
    const body = await request.json() as { gen: number };
    const current = await this.state.storage.get<GenerationState>('gen');

    if (!current || current.latestBundleGen !== body.gen) {
      return Response.json(
        { error: 'generation mismatch', current: current?.latestBundleGen ?? 0 },
        { status: 409 },
      );
    }

    if (!current.firstUsedAt) {
      current.firstUsedAt = Date.now();
      await this.state.storage.put('gen', current);
    }

    return Response.json(current);
  }
}
