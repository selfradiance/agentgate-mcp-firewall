/**
 * MCP Firewall Proxy Server
 *
 * An MCP server that sits between clients and an upstream MCP server.
 * It discovers the upstream's tools and re-exposes them to clients.
 * For now this is pure transparent passthrough — no auth, no bond checking.
 *
 * Unsupported MCP features: notifications, resources, prompts.
 * These will return appropriate errors if clients attempt to use them.
 */

import { randomUUID } from "node:crypto";
import http from "node:http";
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { UpstreamClient } from "./upstream-client.js";

export interface FirewallServerOptions {
  /** Port the firewall listens on */
  port?: number;
  /** Full URL of the upstream MCP server endpoint */
  upstreamUrl: string;
}

const DEFAULT_PORT = 5555;

export class FirewallServer {
  private httpServer: http.Server | null = null;
  private upstream: UpstreamClient;
  private upstreamTools: Tool[] = [];
  private port: number;

  constructor(private options: FirewallServerOptions) {
    this.port = options.port ?? DEFAULT_PORT;
    this.upstream = new UpstreamClient({ url: options.upstreamUrl });
  }

  /** Start the firewall: connect to upstream, discover tools, listen for clients. */
  async start(): Promise<{ url: string }> {
    // Connect to the upstream MCP server and discover its tools
    await this.upstream.connect();
    this.upstreamTools = await this.upstream.listTools();
    console.log(
      `Firewall discovered ${this.upstreamTools.length} upstream tools: ${this.upstreamTools.map((t) => t.name).join(", ")}`,
    );

    // Set up the Express app and HTTP server
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

        // Create a low-level Server for this session with tool handlers
        const server = this.createServer();
        await server.connect(transport);
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

    this.httpServer = http.createServer(app);

    return new Promise((resolve) => {
      this.httpServer!.listen(this.port, () => {
        const url = `http://127.0.0.1:${this.port}/mcp`;
        console.log(`MCP Firewall listening at ${url}`);
        resolve({ url });
      });
    });
  }

  /** Create a low-level MCP Server that proxies tool calls to the upstream. */
  private createServer(): Server {
    const server = new Server(
      { name: "mcp-firewall", version: "0.1.0" },
      { capabilities: { tools: {} } },
    );

    // Handle tools/list — return the upstream's tools
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.upstreamTools,
    }));

    // Handle tools/call — forward to the upstream server
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      const result = await this.upstream.callTool(name, args ?? {});
      return result;
    });

    return server;
  }

  /** Shut down the firewall and disconnect from the upstream. */
  async stop(): Promise<void> {
    await this.upstream.close();
    if (this.httpServer) {
      await new Promise<void>((resolve, reject) => {
        this.httpServer!.close((err) => (err ? reject(err) : resolve()));
      });
      this.httpServer = null;
    }
  }
}
