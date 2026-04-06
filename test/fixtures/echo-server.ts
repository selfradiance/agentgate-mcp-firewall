import { randomUUID } from "node:crypto";
import http from "node:http";
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const DEFAULT_PORT = 4444;

export function createEchoServer(): McpServer {
  const server = new McpServer({
    name: "echo-server",
    version: "1.0.0",
  });

  server.tool(
    "echo",
    "Returns the message back to the caller",
    { message: z.string().describe("The message to echo back") },
    async ({ message }) => ({
      content: [{ type: "text", text: message }],
    }),
  );

  server.tool(
    "add",
    "Adds two numbers together",
    {
      a: z.number().describe("First number"),
      b: z.number().describe("Second number"),
    },
    async ({ a, b }) => ({
      content: [{ type: "text", text: String(a + b) }],
    }),
  );

  return server;
}

export async function startEchoServer(
  port: number = DEFAULT_PORT,
): Promise<{ server: http.Server; mcpServer: McpServer; url: string }> {
  const mcpServer = createEchoServer();
  const app = express();
  app.use(express.json());

  const transports = new Map<string, StreamableHTTPServerTransport>();

  app.post("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports.has(sessionId)) {
      transport = transports.get(sessionId)!;
    } else {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          transports.set(newSessionId, transport);
        },
      });

      transport.onclose = () => {
        if (transport.sessionId) {
          transports.delete(transport.sessionId);
        }
      };

      await mcpServer.connect(transport);
    }

    await transport.handleRequest(req, res, req.body);
  });

  app.get("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (!sessionId || !transports.has(sessionId)) {
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session ID" },
        id: null,
      });
      return;
    }

    const transport = transports.get(sessionId)!;
    await transport.handleRequest(req, res);
  });

  const httpServer = http.createServer(app);

  return new Promise((resolve) => {
    httpServer.listen(port, () => {
      const url = `http://127.0.0.1:${port}/mcp`;
      console.log(`Echo MCP server listening at ${url}`);
      resolve({ server: httpServer, mcpServer, url });
    });
  });
}

// Allow running directly: tsx test/fixtures/echo-server.ts [port]
const isDirectRun =
  process.argv[1]?.endsWith("echo-server.ts") ||
  process.argv[1]?.endsWith("echo-server.js");

if (isDirectRun) {
  const port = parseInt(process.argv[2] || String(DEFAULT_PORT), 10);
  startEchoServer(port);
}
