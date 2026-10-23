// Serving the relay from Node's own HTTP server, for a single-process relay
// (`perch-relay` on the command line) or local testing. A Workers or Deno
// deployment calls `handleRelay` directly.

import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';

/** Largest request body read, bytes; the relay's own limit is smaller. */
const MAX_BODY = 64 * 1024;

/** A `node:http` request listener running a fetch-style handler. */
export function nodeListener(
  handle: (request: Request) => Promise<Response>,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  return async (req, res) => {
    try {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += (chunk as Buffer).length;
        if (size > MAX_BODY) {
          res.writeHead(413, { 'content-type': 'application/json' }).end('{"error":"body too large"}');
          req.destroy();
          return;
        }
        chunks.push(chunk as Buffer);
      }
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === 'string') headers.set(k, v);
      }
      const method = req.method ?? 'GET';
      const request = new Request(`http://${req.headers.host ?? 'localhost'}${req.url ?? '/'}`, {
        method,
        headers,
        body: method === 'GET' || method === 'HEAD' ? undefined : Buffer.concat(chunks),
      });
      const response = await handle(request);
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (e) {
      console.error(e);
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/json' });
      res.end('{"error":"internal error"}');
    }
  };
}

/** Listen on `host:port` (port 0 picks a free one) and resolve once
 * listening, with the URL it serves. */
export async function listen(
  handle: (request: Request) => Promise<Response>,
  port: number,
  host = '127.0.0.1',
): Promise<{ server: Server; url: string }> {
  const server = createServer((req, res) => void nodeListener(handle)(req, res));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });
  const address = server.address();
  const bound = typeof address === 'object' && address !== null ? address.port : port;
  return { server, url: `http://${host}:${bound}` };
}
