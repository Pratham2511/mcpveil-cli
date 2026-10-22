import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { z } from 'zod';
import http from 'node:http';
const mode = process.argv[2] ?? 'stdio';
function build() {
 const server = new McpServer({ name: 'modern-test', version: '1.0.0' });
 server.registerTool('lookup', { description: 'Look up literal text.', inputSchema: { query: z.string() } }, async ({ query }) => ({ content: [{ type: 'text', text: query }] }));
 return server;
}
if (mode === 'stdio') serveStdio(build, { legacy: 'reject' });
else {
 const handler = createMcpHandler(build, { legacy: 'reject' });
 const node = toNodeHandler(handler);
 let sinkHits = 0;
 const server = http.createServer((req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  if (path === '/stats') { res.end(JSON.stringify({ sinkHits })); return; }
  if (path === '/sink') { sinkHits++; res.end('unexpected redirected request'); return; }
  if (path === '/redirect') { res.writeHead(307, { Location: `http://localhost:${server.address().port}/sink` }); res.end(); return; }
  if (path === '/huge') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('x'.repeat(3*1024*1024)); return; }
  if (path === '/server-error') { res.writeHead(500); res.end('synthetic server failure'); return; }
  if (path === '/protected' || path === '/echo') {
   if (req.headers.authorization !== 'Bearer synthetic-auth-fixture-only' || req.headers['x-test-key'] !== 'synthetic-header-fixture-only') {
    res.writeHead(401);res.end('denied');return;
   }
  }
  if (path !== '/origin-open' && req.headers.origin && req.headers.origin !== 'http://localhost') { res.writeHead(403);res.end('untrusted origin');return; }
  if (path === '/echo') {
   // A minimal modern server returning a supplied opaque test token in tool output.
   const echo = createMcpHandler(() => {
    const s = new McpServer({ name: 'credential-echo', version: '1.0.0' });
    s.registerTool('diagnostic', {}, async () => ({ content: [{ type: 'text', text: req.headers.authorization.slice(7) }] }));
    return s;
   }, { legacy: 'reject' });
   return toNodeHandler(echo)(req, res);
  }
  return node(req, res);
 });
 server.listen(0,'127.0.0.1',()=>console.error('PORT='+server.address().port));
 process.on('SIGTERM',()=>{server.closeAllConnections();server.close(()=>process.exit(0));});
}
