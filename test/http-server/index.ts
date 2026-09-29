/**
 * HTTP fixture for the hardened control server — lets MCPVeil exercise its
 * streamable-HTTP transport and its SSE fallback locally.
 *
 *   streamable HTTP : POST/GET/DELETE  /mcp   (stateless JSON responses)
 *   legacy SSE      : GET /sse + POST /messages
 *
 * Stateless pattern: each POST gets a FRESH server + transport pair, because
 * StreamableHTTPServerTransport consumes its initialize handshake once.
 */
import http from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { buildSafeServer } from "../safe-server/app.js";

const PORT = 8123;

let sseTransport: SSEServerTransport | undefined;

const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

  try {
    if (url.pathname === "/mcp") {
      if (req.method === "POST") {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined, // stateless
          enableJsonResponse: true,
        });
        const server = buildSafeServer();
        res.on("close", () => {
          void transport.close();
          void server.close();
        });
        await server.connect(transport);
        await transport.handleRequest(req, res);
        return;
      }
      // no server-initiated SSE stream in stateless mode
      res.writeHead(405).end();
      return;
    }

    if (url.pathname === "/sse" && req.method === "GET") {
      const server = buildSafeServer();
      const transport = new SSEServerTransport("/messages", res);
      sseTransport = transport;
      res.on("close", () => void server.close());
      await server.connect(transport);
      return;
    }

    if (url.pathname === "/messages" && req.method === "POST") {
      if (!sseTransport) { res.writeHead(404).end(); return; }
      await sseTransport.handlePostMessage(req, res);
      return;
    }

    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  } catch (err) {
    process.stderr.write(`[http-fixture] request error on ${req.method} ${url.pathname}: ${err instanceof Error ? err.stack ?? err.message : err}\n`);
    if (!res.headersSent) res.writeHead(500, { "content-type": "text/plain" });
    res.end(`fixture error: ${err instanceof Error ? err.message : err}`);
  }
});

httpServer.listen(PORT, "127.0.0.1", () => {
  process.stderr.write(`[http-fixture] listening on http://127.0.0.1:${PORT}/mcp\n`);
});
