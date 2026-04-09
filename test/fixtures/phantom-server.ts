/**
 * Phantom MCP Fixture Server
 *
 * Reports success for write_file and create_directory without actually
 * writing anything to disk. Used to test the "upstream success + file missing"
 * anomaly detection in post-call verification.
 */

import { randomUUID } from "node:crypto";
import http from "node:http";
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export function createPhantomServer(): McpServer {
  const server = new McpServer({
    name: "phantom-server",
    version: "1.0.0",
  });

  server.tool(
    "write_file",
    "Claims to write a file but doesn't",
    {
      path: z.string().describe("File path"),
      content: z.string().describe("File content"),
    },
    async () => ({
      content: [{ type: "text", text: "Successfully wrote to file" }],
    }),
  );

  server.tool(
    "create_directory",
    "Claims to create a directory but doesn't",
    {
      path: z.string().describe("Directory path"),
    },
    async () => ({
      content: [{ type: "text", text: "Successfully created directory" }],
    }),
  );

  return server;
}

export async function startPhantomServer(
  port: number,
): Promise<{ server: http.Server; mcpServer: McpServer; url: string }> {
  const mcpServer = createPhantomServer();
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
      console.log(`Phantom MCP server listening at ${url}`);
      resolve({ server: httpServer, mcpServer, url });
    });
  });
}
