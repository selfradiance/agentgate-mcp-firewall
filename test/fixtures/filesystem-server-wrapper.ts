/**
 * Filesystem Server HTTP Wrapper
 *
 * Spawns @modelcontextprotocol/server-filesystem as a child process over stdio,
 * connects to it as an MCP client, and re-exposes its tools over Streamable HTTP.
 *
 * This bridges the transport gap: the filesystem server only speaks stdio,
 * but the firewall's UpstreamClient connects via Streamable HTTP.
 *
 * This is a test fixture / infrastructure — not part of the firewall itself.
 */

import { randomUUID } from "node:crypto";
import http from "node:http";
import path from "node:path";
import express from "express";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const DEFAULT_PORT = 4444;

/** Resolve the filesystem server entry point from the installed package. */
function resolveFilesystemServerBin(): string {
  // The package's dist/index.js is the entry point (it has a #!/usr/bin/env node shebang)
  return path.resolve(
    import.meta.dirname,
    "../../node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
  );
}

export interface FilesystemWrapperOptions {
  /** Port to listen on (default: 4444) */
  port?: number;
  /** Allowed directory for the filesystem server */
  allowedDir: string;
}

export async function startFilesystemWrapper(
  options: FilesystemWrapperOptions,
): Promise<{
  server: http.Server;
  url: string;
  stop: () => Promise<void>;
}> {
  const port = options.port ?? DEFAULT_PORT;

  // --- Step 1: Spawn filesystem server over stdio ---
  const serverBin = resolveFilesystemServerBin();
  const stdioTransport = new StdioClientTransport({
    command: "node",
    args: [serverBin, options.allowedDir],
    stderr: "inherit",
  });

  const stdioClient = new Client({
    name: "filesystem-wrapper",
    version: "1.0.0",
  });

  await stdioClient.connect(stdioTransport);

  // --- Step 2: Discover upstream tools ---
  const toolsResult = await stdioClient.listTools();
  const upstreamTools: Tool[] = toolsResult.tools;
  console.log(
    `Filesystem wrapper discovered ${upstreamTools.length} tools: ${upstreamTools.map((t) => t.name).join(", ")}`,
  );

  // --- Step 3: Build HTTP server that proxies to the stdio client ---
  const app = express();
  app.use(express.json());

  // Create a single McpServer that registers all upstream tools
  const mcpServer = new McpServer({
    name: "filesystem-wrapper",
    version: "1.0.0",
  });

  // Register each upstream tool as a passthrough.
  // We use the raw z.any() schema for arguments since we just forward them.
  for (const tool of upstreamTools) {
    // Build a zod schema from the tool's inputSchema properties
    const properties = (tool.inputSchema as { properties?: Record<string, unknown> }).properties ?? {};
    const required = (tool.inputSchema as { required?: string[] }).required ?? [];
    const zodShape: Record<string, z.ZodTypeAny> = {};

    for (const [key, _schema] of Object.entries(properties)) {
      // Use z.any() for all properties — we're just forwarding, not validating
      if (required.includes(key)) {
        zodShape[key] = z.any();
      } else {
        zodShape[key] = z.any().optional();
      }
    }

    mcpServer.tool(
      tool.name,
      tool.description ?? "",
      zodShape,
      async (args) => {
        const result = await stdioClient.callTool({
          name: tool.name,
          arguments: args,
        });
        return result as { content: Array<{ type: "text"; text: string }> };
      },
    );
  }

  // Session management for Streamable HTTP
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

  const url = await new Promise<string>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, () => {
      httpServer.removeAllListeners("error");
      const addr = `http://127.0.0.1:${port}/mcp`;
      console.log(`Filesystem wrapper listening at ${addr}`);
      resolve(addr);
    });
  });

  const stop = async () => {
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => (err ? reject(err) : resolve()));
    });
    const pid = stdioTransport.pid;
    await stdioClient.close();
    // Safety net: if the child process is still alive after SDK cleanup, kill it
    if (pid) {
      try { process.kill(pid, 0); process.kill(pid, "SIGKILL"); } catch { /* already dead */ }
    }
  };

  return { server: httpServer, url, stop };
}

// Allow running directly: tsx test/fixtures/filesystem-server-wrapper.ts [port]
const isDirectRun =
  process.argv[1]?.endsWith("filesystem-server-wrapper.ts") ||
  process.argv[1]?.endsWith("filesystem-server-wrapper.js");

if (isDirectRun) {
  const port = parseInt(process.argv[2] || String(DEFAULT_PORT), 10);
  const allowedDir = process.argv[3] || path.join(process.env.HOME!, "mcp-firewall-sandbox");
  const wrapper = await startFilesystemWrapper({ port, allowedDir });
  console.log(`Wrapper running. Allowed dir: ${allowedDir}`);

  const shutdown = async () => {
    console.log("\nShutting down filesystem wrapper...");
    await wrapper.stop();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
