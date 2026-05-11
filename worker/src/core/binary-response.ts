export function binaryResponse(data: Uint8Array): Response {
  return new Response(data, {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Cache-Control': 'no-store',
    },
  });
}
