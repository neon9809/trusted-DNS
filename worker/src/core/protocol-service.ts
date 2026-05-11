/**
 * Protocol service facade.
 *
 * This is the first stable seam between runtime adapters and protocol request
 * handling. The initial implementation delegates to the legacy handler so we
 * can migrate bootstrap/query/refresh incrementally.
 */

export interface ProtocolService<RequestContext = unknown> {
  handleProtocolRequest(request: Request, context: RequestContext): Promise<Response>;
}

export function createProtocolService<RequestContext>(
  impl: ProtocolService<RequestContext>,
): ProtocolService<RequestContext> {
  return impl;
}
