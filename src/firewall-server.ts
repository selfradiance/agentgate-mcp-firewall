/**
 * MCP Firewall Proxy Server
 *
 * An MCP server that sits between clients and an upstream MCP server.
 * It discovers the upstream's tools and re-exposes them to clients.
 * Clients must call the "authenticate" tool with a valid AgentGate
 * identity and bond before any upstream tools are forwarded.
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
import type { AgentGateClient } from "./agentgate-client.js";

export interface FirewallServerOptions {
  /** Port the firewall listens on */
  port?: number;
  /** Full URL of the upstream MCP server endpoint */
  upstreamUrl: string;
  /** AgentGate client for identity verification (optional — if omitted, auth is disabled) */
  agentgateClient?: AgentGateClient;
}

interface SessionAuth {
  identityId: string;
  bondId: string;
}

const DEFAULT_PORT = 5555;

/** The authenticate tool definition exposed to MCP clients. */
const AUTHENTICATE_TOOL: Tool = {
  name: "authenticate",
  description:
    "Authenticate with the MCP Firewall by providing your AgentGate identity and bond. " +
    "Must be called before any other tool in this session.",
  inputSchema: {
    type: "object",
    properties: {
      identityId: {
        type: "string",
        description: "Your AgentGate identity ID (e.g. id_xxx)",
      },
      bondId: {
        type: "string",
        description: "Your active bond ID on AgentGate (e.g. bond_xxx)",
      },
    },
    required: ["identityId", "bondId"],
  },
};

export class FirewallServer {
  private httpServer: http.Server | null = null;
  private upstream: UpstreamClient;
  private upstreamTools: Tool[] = [];
  private port: number;
  private agentgateClient: AgentGateClient | undefined;
  private sessionAuth = new Map<string, SessionAuth>();

  constructor(private options: FirewallServerOptions) {
    this.port = options.port ?? DEFAULT_PORT;
    this.upstream = new UpstreamClient({ url: options.upstreamUrl });
    this.agentgateClient = options.agentgateClient;
  }

  /** Whether authentication is required (AgentGate client was provided). */
  private get authRequired(): boolean {
    return this.agentgateClient !== undefined;
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
            this.sessionAuth.delete(transport.sessionId);
          }
        };

        // Create a low-level Server for this session with tool handlers
        const server = this.createServer(transport);
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
  private createServer(transport: StreamableHTTPServerTransport): Server {
    const server = new Server(
      { name: "mcp-firewall", version: "0.1.0" },
      { capabilities: { tools: {} } },
    );

    // Handle tools/list — return authenticate tool + upstream tools
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools = this.authRequired
        ? [AUTHENTICATE_TOOL, ...this.upstreamTools]
        : this.upstreamTools;
      return { tools };
    });

    // Handle tools/call — authenticate or forward to upstream
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      // Handle the authenticate tool
      if (name === "authenticate" && this.authRequired) {
        return this.handleAuthenticate(transport, args ?? {});
      }

      // Gate upstream tools behind authentication
      if (this.authRequired) {
        const sessionId = transport.sessionId;
        if (!sessionId || !this.sessionAuth.has(sessionId)) {
          return {
            content: [
              {
                type: "text",
                text: "Authentication required. Call the 'authenticate' tool with your AgentGate identityId and bondId before using any other tools.",
              },
            ],
            isError: true,
          };
        }
      }

      // Forward to upstream
      const result = await this.upstream.callTool(name, args ?? {});
      return result;
    });

    return server;
  }

  /** Handle the authenticate tool call. */
  private async handleAuthenticate(
    transport: StreamableHTTPServerTransport,
    args: Record<string, unknown>,
  ) {
    const identityId = args.identityId as string | undefined;
    const bondId = args.bondId as string | undefined;

    if (!identityId || !bondId) {
      return {
        content: [
          {
            type: "text",
            text: "Both identityId and bondId are required.",
          },
        ],
        isError: true,
      };
    }

    // Verify the identity exists on AgentGate
    try {
      await this.agentgateClient!.checkIdentity(identityId);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown error";
      return {
        content: [
          {
            type: "text",
            text: `Authentication failed: ${message}`,
          },
        ],
        isError: true,
      };
    }

    // Bind identity and bond to this session
    const sessionId = transport.sessionId;
    if (!sessionId) {
      return {
        content: [
          { type: "text", text: "Internal error: no session ID available." },
        ],
        isError: true,
      };
    }

    this.sessionAuth.set(sessionId, { identityId, bondId });

    return {
      content: [
        {
          type: "text",
          text: `Authenticated. Identity ${identityId} with bond ${bondId} is now bound to this session.`,
        },
      ],
    };
  }

  /** Shut down the firewall and disconnect from the upstream. */
  async stop(): Promise<void> {
    await this.upstream.close();
    this.sessionAuth.clear();
    if (this.httpServer) {
      await new Promise<void>((resolve, reject) => {
        this.httpServer!.close((err) => (err ? reject(err) : resolve()));
      });
      this.httpServer = null;
    }
  }
}
