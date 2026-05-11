export interface ProtocolService<RequestContext = unknown> {
  handleProtocolRequest(request: Request, context: RequestContext): Promise<Response>;
}

export function createProtocolService<RequestContext>(
  impl: ProtocolService<RequestContext>,
): ProtocolService<RequestContext> {
  return impl;
}
