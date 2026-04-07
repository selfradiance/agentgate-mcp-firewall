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
import { AUTHENTICATION_EXPOSURE_CENTS } from "./authentication.js";

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
  /** When true, an authenticate call is in progress but not yet confirmed. */
  pending?: boolean;
  identityId: string;
  bondId: string;
  authenticatedAt: number;
  authActionId?: string;
}

const DEFAULT_PORT = 5555;

/** The authenticate tool definition exposed to MCP clients. */
const AUTHENTICATE_TOOL: Tool = {
  name: "authenticate",
  description:
    "Authenticate with the MCP Firewall by providing your AgentGate identity and bond. " +
    `Must be called before any other tool in this session. Reserves ${AUTHENTICATION_EXPOSURE_CENTS} cent on your bond while the session is open.`,
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
      nonce: {
        type: "string",
        description: "A unique nonce used when signing the authentication request.",
      },
      timestamp: {
        type: "string",
        description: "The signed timestamp for the authentication proof.",
      },
      signature: {
        type: "string",
        description:
          "Ed25519 signature over the firewall auth action, bound to the current MCP session.",
      },
    },
    required: ["identityId", "bondId", "nonce", "timestamp", "signature"],
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
    if (this.authRequired) {
      const missingPolicyEntries = this.upstreamTools
        .filter((tool) => !this.policy!.tools[tool.name])
        .map((tool) => tool.name);

      if (missingPolicyEntries.length > 0) {
        await this.upstream.close();
        throw new Error(
          "Policy is missing explicit entries for upstream tools: " +
            missingPolicyEntries.join(", "),
        );
      }
    }
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
            void this.releaseSession(transport.sessionId);
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

    app.delete("/mcp", async (req, res) => {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (!sessionId || !transports.has(sessionId)) {
        res.status(404).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Session not found" },
          id: null,
        });
        return;
      }

      const transport = transports.get(sessionId)!;
      await transport.close();
      res.status(200).end();
    });

    app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      const detail = error instanceof Error ? error.message : String(error);
      console.error(`MCP transport error: ${detail}`);

      if (res.headersSent) {
        return;
      }

      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Internal server error" },
        id: null,
      });
    });

    this.httpServer = http.createServer(app);

    return new Promise((resolve, reject) => {
      const server = this.httpServer!;

      const onError = (error: Error) => {
        server.off("error", onError);
        this.httpServer = null;
        void this.upstream.close().catch(() => {});
        reject(error);
      };

      server.once("error", onError);
      server.listen(this.port, () => {
        server.off("error", onError);
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

      if (!this.upstreamTools.some((tool) => tool.name === name)) {
        return {
          content: [
            {
              type: "text",
              text: `Tool "${name}" is not exposed by this firewall.`,
            },
          ],
          isError: true,
        };
      }

      // Gate upstream tools behind authentication
      if (this.authRequired) {
        const sessionId = transport.sessionId;
        const session = sessionId ? this.sessionAuth.get(sessionId) : undefined;
        if (!sessionId || !session || session.pending) {
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

        // Re-verify the authenticated identity periodically for long-lived sessions.
        const elapsed = Date.now() - session.authenticatedAt;
        if (elapsed > this.sessionTtlMs) {
          try {
            await this.agentgateClient!.checkIdentity(session.identityId);
            session.authenticatedAt = Date.now();
          } catch {
            await this.releaseSession(sessionId);
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
      const detail =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Bonded action recording failed for tool "${toolName}": ${detail}`);
      // Return a generic message — do not expose AgentGate internals to the client
      const reason = detail.includes("INSUFFICIENT_BOND_CAPACITY")
        ? "insufficient bond capacity"
        : "bond verification failed";
      return { blocked: true, reason };
    }
  }

  private async releaseSession(sessionId: string): Promise<void> {
    const session = this.sessionAuth.get(sessionId);
    if (!session) {
      return;
    }

    this.sessionAuth.delete(sessionId);

    if (session.pending || !session.authActionId || !this.resolverClient) {
      return;
    }

    try {
      await this.resolverClient.resolveAction(session.authActionId, "success");
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Unknown error";
      console.error(
        `Failed to release authentication action ${session.authActionId}: ${detail}`,
      );
    }
  }

  private getAuthenticationFailureMessage(error: unknown): string {
    const detail = error instanceof Error ? error.message : String(error);

    if (
      detail.includes("INVALID_SIGNATURE") ||
      detail.includes("Signature") ||
      detail.includes("401")
    ) {
      return "Authentication failed: signature could not be verified.";
    }

    if (detail.includes("IDENTITY_NOT_FOUND")) {
      return "Authentication failed: identity could not be verified.";
    }

    if (
      detail.includes("BOND_NOT_FOUND") ||
      detail.includes("BOND_IDENTITY_MISMATCH") ||
      detail.includes("BOND_NOT_ACTIVE") ||
      detail.includes("BOND_EXPIRED") ||
      detail.includes("INSUFFICIENT_BOND_CAPACITY")
    ) {
      return "Authentication failed: bond could not be verified.";
    }

    return "Authentication failed: AgentGate could not validate this session.";
  }

  /** Handle the authenticate tool call. */
  private async handleAuthenticate(
    transport: StreamableHTTPServerTransport,
    args: Record<string, unknown>,
  ) {
    const identityId = args.identityId;
    const bondId = args.bondId;
    const nonce = args.nonce;
    const timestamp = args.timestamp;
    const signature = args.signature;

    if (
      typeof identityId !== "string" || identityId.length === 0 ||
      typeof bondId !== "string" || bondId.length === 0 ||
      typeof nonce !== "string" || nonce.length === 0 ||
      typeof timestamp !== "string" || timestamp.length === 0 ||
      typeof signature !== "string" || signature.length === 0
    ) {
      return {
        content: [
          {
            type: "text",
            text:
              "identityId, bondId, nonce, timestamp, and signature are all required and must be non-empty strings.",
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

    // AUDIT FIX (Finding 4 + Round 4 Finding 1): Reject if session already has an entry
    // (either pending or authenticated). The pending marker closes the TOCTOU race —
    // the first authenticate call claims the slot synchronously before any async work.
    if (this.sessionAuth.has(sessionId)) {
      return {
        content: [
          {
            type: "text",
            text: "This session is already authenticated or authentication is in progress. Re-authentication is not permitted. Open a new session to authenticate with a different identity.",
          },
        ],
        isError: true,
      };
    }

    // Claim the session slot immediately (synchronous) to prevent concurrent
    // authenticate calls from racing past the has() check above.
    this.sessionAuth.set(sessionId, {
      pending: true,
      identityId,
      bondId,
      authenticatedAt: 0,
    });

    try {
      const authAction = await this.agentgateClient!.reserveAuthenticationBond({
        identityId,
        bondId,
        nonce,
        timestamp,
        signature,
      }, sessionId);

      this.sessionAuth.set(sessionId, {
        identityId,
        bondId,
        authenticatedAt: Date.now(),
        authActionId: authAction.actionId,
      });
    } catch (error) {
      // Verification failed — release the pending slot
      this.sessionAuth.delete(sessionId);
      const detail =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Authentication failed for "${identityId}": ${detail}`);
      return {
        content: [
          {
            type: "text",
            text: this.getAuthenticationFailureMessage(error),
          },
        ],
        isError: true,
      };
    }

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
    await Promise.allSettled(
      Array.from(this.sessionAuth.keys()).map((sessionId) =>
        this.releaseSession(sessionId),
      ),
    );
    if (this.httpServer) {
      await new Promise<void>((resolve, reject) => {
        this.httpServer!.close((err) => (err ? reject(err) : resolve()));
      });
      this.httpServer = null;
    }
  }
}
