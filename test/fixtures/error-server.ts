/**
 * Error MCP Fixture Server
 *
 * An MCP server that exposes the same tools as the echo server
 * but always throws errors when called. Used to test rollback behavior.
 */

import { randomUUID } from "node:crypto";
import http from "node:http";
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export function createErrorServer(): McpServer {
  const server = new McpServer({
    name: "error-server",
    version: "1.0.0",
  });

  server.tool(
    "echo",
    "Always fails",
    { message: z.string().describe("The message to echo back") },
    async () => {
      throw new Error("Deliberate upstream failure for testing");
    },
  );

  server.tool(
    "add",
    "Always fails",
    {
      a: z.number().describe("First number"),
      b: z.number().describe("Second number"),
    },
    async () => {
      throw new Error("Deliberate upstream failure for testing");
    },
  );

  return server;
}

export async function startErrorServer(
  port: number,
): Promise<{ server: http.Server; mcpServer: McpServer; url: string }> {
  const mcpServer = createErrorServer();
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
      console.log(`Error MCP server listening at ${url}`);
      resolve({ server: httpServer, mcpServer, url });
    });
  });
}
