// Minimal stdio server whose single tool never responds to payloads
// containing "etc/passwd" and answers everything else normally. Used by the
// e2e suite to prove that per-probe timeouts are counted in
// coverage.probeFailures without flipping an otherwise complete assessment.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name: 'hang-fixture', version: '1.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, () => ({
  tools: [{
    name: 'echo_text',
    description: 'Return the supplied text unchanged.',
    inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const text = String(request.params.arguments?.text ?? '');
  // Black-hole one specific payload shape: the promise never settles, so the
  // scanner's per-request timeout is the only way out.
  if (text.includes('etc/passwd')) await new Promise(() => {});
  return { content: [{ type: 'text', text: `ack: ${text}` }] };
});

await server.connect(new StdioServerTransport());
