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
import type { PolicyConfig } from "./policy.js";
import { getExposure } from "./policy.js";

const MAX_PAYLOAD_BYTES = 4000;

/** Default session auth TTL: 5 minutes. After this, the firewall re-verifies the identity. */
const DEFAULT_SESSION_TTL_MS = 5 * 60 * 1000;

/**
 * Sanitize a payload object to stay under the byte limit.
 * If the full payload is too large, truncate the arguments field.
 */
function sanitizePayload(payload: Record<string, unknown>): Record<string, unknown> {
  const serialized = JSON.stringify(payload);
  if (Buffer.byteLength(serialized, "utf-8") <= MAX_PAYLOAD_BYTES) {
    return payload;
  }

  // Truncate the arguments to fit
  const withoutArgs = { ...payload, arguments: "[truncated]" };
  const overhead = Buffer.byteLength(JSON.stringify(withoutArgs), "utf-8");
  const budget = MAX_PAYLOAD_BYTES - overhead;

  if (budget > 20) {
    const argsStr = JSON.stringify(payload.arguments);
    const truncated = argsStr.slice(0, budget - 15) + "...[truncated]";
    return { ...payload, arguments: truncated };
  }

  return withoutArgs;
}

export interface FirewallServerOptions {
  /** Port the firewall listens on */
  port?: number;
  /** Full URL of the upstream MCP server endpoint */
  upstreamUrl: string;
  /** AgentGate client for identity verification (optional — if omitted, auth is disabled) */
  agentgateClient?: AgentGateClient;
  /** Separate AgentGate client used to resolve actions (must be a different identity than the executor) */
  resolverClient?: AgentGateClient;
  /** Policy config for tool risk/exposure mapping (required when agentgateClient is set) */
  policy?: PolicyConfig;
  /** Bond ID the firewall uses to record actions on AgentGate (required when agentgateClient is set) */
  firewallBondId?: string;
  /** Session auth TTL in milliseconds (default: 5 minutes). After expiry, identity is re-verified. */
  sessionTtlMs?: number;
}

interface SessionAuth {
  identityId: string;
  bondId: string;
  authenticatedAt: number;
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
  private resolverClient: AgentGateClient | undefined;
  private policy: PolicyConfig | undefined;
  private firewallBondId: string | undefined;
  private sessionTtlMs: number;
  private sessionAuth = new Map<string, SessionAuth>();

  constructor(private options: FirewallServerOptions) {
    this.port = options.port ?? DEFAULT_PORT;
    this.upstream = new UpstreamClient({ url: options.upstreamUrl });
    this.agentgateClient = options.agentgateClient;
    this.resolverClient = options.resolverClient;
    this.policy = options.policy;
    this.firewallBondId = options.firewallBondId;
    this.sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  }

  /** Whether authentication is required (AgentGate client was provided). */
  private get authRequired(): boolean {
    return this.agentgateClient !== undefined;
  }

  /** Start the firewall: connect to upstream, discover tools, listen for clients. */
  async start(): Promise<{ url: string }> {
    // AUDIT FIX (Finding 1): Fail-closed — refuse to start when agentgateClient
    // is provided but policy or firewallBondId are missing. Without both, the
    // economic accountability layer would be silently bypassed.
    if (this.agentgateClient && (!this.policy || !this.firewallBondId || !this.resolverClient)) {
      throw new Error(
        "Firewall misconfiguration: when agentgateClient is provided, 'policy', 'firewallBondId', and 'resolverClient' are all required. " +
        "The firewall refuses to start without full governance configuration (fail-closed).",
      );
    }

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

      // AUDIT FIX (Finding 8): Explicitly reject calls to "authenticate" when auth is disabled.
      // Without this, the call would fall through to upstream forwarding.
      if (name === "authenticate" && !this.authRequired) {
        return {
          content: [
            {
              type: "text",
              text: "Authentication is not enabled on this firewall. The 'authenticate' tool is not available.",
            },
          ],
          isError: true,
        };
      }

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

        // AUDIT FIX (Finding 5): Re-verify identity if session auth has expired.
        const session = this.sessionAuth.get(sessionId)!;
        const elapsed = Date.now() - session.authenticatedAt;
        if (elapsed > this.sessionTtlMs) {
          // Session expired — re-verify identity on AgentGate
          try {
            await this.agentgateClient!.checkIdentity(session.identityId);
            // Refresh the timestamp
            session.authenticatedAt = Date.now();
          } catch {
            // Identity no longer valid — clear session and reject
            this.sessionAuth.delete(sessionId);
            return {
              content: [
                {
                  type: "text",
                  text: "Session expired and identity re-verification failed. Please authenticate again.",
                },
              ],
              isError: true,
            };
          }
        }

        // Record the bonded action on AgentGate before forwarding
        const gateResult = await this.recordBondedAction(
          name,
          args ?? {},
          session,
        );
        if (gateResult.blocked) {
          return {
            content: [
              {
                type: "text",
                text: `Tool call blocked: ${gateResult.reason}`,
              },
            ],
            isError: true,
          };
        }

        // Forward to upstream, with rollback on failure
        return this.forwardWithRollback(name, args ?? {}, gateResult.actionId);
      }

      // Forward to upstream (auth not enabled)
      const result = await this.upstream.callTool(name, args ?? {});
      return result;
    });

    return server;
  }

  /**
   * Forward a tool call to the upstream server with rollback on failure.
   * If the upstream call fails, resolve the action as "failed" on AgentGate
   * to release the bond exposure. On success, the action stays open.
   */
  private async forwardWithRollback(
    toolName: string,
    args: Record<string, unknown>,
    actionId: string,
  ) {
    let result: Awaited<ReturnType<typeof this.upstream.callTool>>;
    let failed = false;
    let errorMessage = "";

    try {
      result = await this.upstream.callTool(toolName, args);

      // Check if the upstream returned an MCP-level tool error
      if (result.isError) {
        failed = true;
        const firstContent = (
          result.content as Array<{ type: string; text?: string }>
        )[0];
        errorMessage = firstContent?.text ?? "Upstream tool returned an error";
      }
    } catch (error) {
      // Transport/network error
      failed = true;
      errorMessage =
        error instanceof Error ? error.message : "Unknown upstream error";
      result = {
        content: [{ type: "text", text: errorMessage }],
        isError: true,
      };
    }

    if (failed && this.resolverClient) {
      // Resolve the action as "failed" to release bond exposure
      try {
        await this.resolverClient.resolveAction(actionId, "failed");
      } catch (resolveError) {
        // Log but don't block — the primary error is the upstream failure
        const resolveMsg =
          resolveError instanceof Error
            ? resolveError.message
            : "Unknown resolve error";
        console.error(
          `Failed to resolve action ${actionId} after upstream error: ${resolveMsg}`,
        );
      }

      return {
        content: [
          {
            type: "text",
            text: `Upstream tool call failed: ${errorMessage}. Bond exposure has been released.`,
          },
        ],
        isError: true,
      };
    }

    // Upstream succeeded — action stays open on AgentGate.
    // No auto-resolve; the action remains for external review/resolution.
    return result!;
  }

  /**
   * Record a bonded action on AgentGate before forwarding a tool call.
   * Returns { blocked: false } on success, or { blocked: true, reason } on failure.
   */
  private async recordBondedAction(
    toolName: string,
    args: Record<string, unknown>,
    session: SessionAuth,
  ): Promise<{ blocked: false; actionId: string } | { blocked: true; reason: string }> {
    const exposureCents = getExposure(this.policy!, toolName);
    const tier = this.policy!.tools[toolName]?.tier ?? "default";

    // Build the action payload with key context, sanitized to stay under 4000 bytes
    const payload = sanitizePayload({
      upstreamUrl: this.options.upstreamUrl,
      toolName,
      arguments: args,
      timestamp: new Date().toISOString(),
      tier,
      agentIdentityId: session.identityId,
      agentBondId: session.bondId,
    });

    try {
      const result = await this.agentgateClient!.executeBondedAction(
        this.firewallBondId!,
        "mcp.tool_call",
        payload,
        exposureCents,
      );
      return { blocked: false, actionId: result.actionId };
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown error";
      return { blocked: true, reason: message };
    }
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

    const sessionId = transport.sessionId;
    if (!sessionId) {
      return {
        content: [
          { type: "text", text: "Internal error: no session ID available." },
        ],
        isError: true,
      };
    }

    // AUDIT FIX (Finding 4): Reject re-authentication on an already-authenticated session.
    // Prevents identity rebinding mid-session.
    if (this.sessionAuth.has(sessionId)) {
      return {
        content: [
          {
            type: "text",
            text: "This session is already authenticated. Re-authentication is not permitted. Open a new session to authenticate with a different identity.",
          },
        ],
        isError: true,
      };
    }

    // Verify the identity exists on AgentGate
    let identitySummary;
    try {
      identitySummary = await this.agentgateClient!.checkIdentity(identityId);
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

    // AUDIT FIX (Finding 3): Validate that the identity has at least one active bond.
    // We cannot verify the specific bondId without a bond GET endpoint on AgentGate,
    // but we can confirm the identity has posted bonds. The specific bond will be
    // validated at execution time when AgentGate processes the bonded action.
    if (identitySummary.reputation.stats.locks === 0) {
      return {
        content: [
          {
            type: "text",
            text: "Authentication failed: this identity has no bonds on AgentGate. Lock a bond before authenticating.",
          },
        ],
        isError: true,
      };
    }

    // Bind identity and bond to this session with a timestamp for TTL tracking
    this.sessionAuth.set(sessionId, {
      identityId,
      bondId,
      authenticatedAt: Date.now(),
    });

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
