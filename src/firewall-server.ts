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
import fs from "node:fs";
import path from "node:path";
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
const DEFAULT_MAX_SESSIONS = 1000;

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
    const argsBuf = Buffer.from(argsStr, "utf-8");
    // Truncate at byte boundary, then decode back to string (safe: invalid trailing bytes are replaced)
    const sliced = argsBuf.subarray(0, budget - 15).toString("utf-8");
    const truncated = sliced + "...[truncated]";
    return { ...payload, arguments: truncated };
  }

  return withoutArgs;
}

export type PathValidationResult =
  | { status: "valid"; resolvedPath: string }
  | { status: "malicious" };

/**
 * Validate that a requested path is inside the governed root.
 *
 * Two checks are BOTH required:
 * 1. fs.realpathSync() on the parent directory — defeats symlink escapes
 *    (a symlink inside governed_root pointing to /etc/ resolves to /etc/).
 * 2. Separator-appended prefix check — defeats sibling prefix bypasses
 *    (e.g. /governed_root-evil/... would pass a naive startsWith check).
 *
 * Neither check alone is sufficient.
 *
 * On success, returns the canonical resolved path (resolved parent + basename).
 * This resolved path should be used for post-call verification (fs.existsSync),
 * not the raw path from the tool arguments.
 *
 * If the parent directory doesn't exist, realpathSync throws. The catch
 * returns 'malicious' (fail closed) — callers never see a thrown exception
 * from this function.
 */
export function validatePath(
  requestedPath: string,
  governedRoot: string,
): PathValidationResult {
  try {
    const parentDir = path.dirname(requestedPath);
    const resolvedParent = fs.realpathSync(parentDir);
    const normalizedRoot = governedRoot.endsWith(path.sep)
      ? governedRoot
      : governedRoot + path.sep;
    if (resolvedParent.startsWith(normalizedRoot) || resolvedParent === governedRoot) {
      // Canonical path: resolved parent + original basename
      const resolvedPath = path.join(resolvedParent, path.basename(requestedPath));
      return { status: "valid", resolvedPath };
    }
    return { status: "malicious" };
  } catch {
    // Parent doesn't exist or realpathSync failed — fail closed
    return { status: "malicious" };
  }
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
  /** Maximum concurrent sessions (default: 1000). New sessions are rejected with 503 when the limit is hit. */
  maxSessions?: number;
  /** Host/interface to bind to (default: "127.0.0.1"). Set to "0.0.0.0" to accept connections from all interfaces. */
  host?: string;
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
  private host: string;
  private agentgateClient: AgentGateClient | undefined;
  private resolverClient: AgentGateClient | undefined;
  private policy: PolicyConfig | undefined;
  private firewallBondId: string | undefined;
  private sessionTtlMs: number;
  private maxSessions: number;
  private sessionAuth = new Map<string, SessionAuth>();
  private transports = new Map<string, StreamableHTTPServerTransport>();

  constructor(private options: FirewallServerOptions) {
    this.port = options.port ?? DEFAULT_PORT;
    this.host = options.host ?? "127.0.0.1";
    this.upstream = new UpstreamClient({ url: options.upstreamUrl });
    this.agentgateClient = options.agentgateClient;
    this.resolverClient = options.resolverClient;
    this.policy = options.policy;
    this.firewallBondId = options.firewallBondId;
    this.sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    this.maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS;
  }

  /** Whether authentication is required (AgentGate client was provided). */
  private get authRequired(): boolean {
    return this.agentgateClient !== undefined;
  }

  /**
   * Connect to the upstream MCP server with exponential backoff.
   * 3 attempts: delays of 1s, 2s, 4s between retries.
   */
  private async connectWithRetry(): Promise<void> {
    const delays = [1000, 2000, 4000];
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= delays.length; attempt++) {
      try {
        await this.upstream.connect();
        return;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < delays.length) {
          console.log(
            `Upstream connection attempt ${attempt + 1} failed, retrying in ${delays[attempt]}ms...`,
          );
          await new Promise((resolve) => setTimeout(resolve, delays[attempt]));
        }
      }
    }

    throw new Error(
      `Upstream MCP server not reachable after ${delays.length + 1} attempts — is the filesystem wrapper running? Last error: ${lastError?.message}`,
    );
  }

  /**
   * Canary write probe: write a timestamped file to governed_root via the upstream,
   * verify it exists on disk, then delete it. Proves functional write access.
   */
  private async canaryWriteProbe(governedRoot: string): Promise<void> {
    const canaryPath = path.join(governedRoot, ".mcp-firewall-canary");
    const canaryContent = `canary-${Date.now()}`;

    try {
      const result = await this.upstream.callTool("write_file", {
        path: canaryPath,
        content: canaryContent,
      });

      if (result.isError) {
        const text = (result.content as Array<{ type: string; text?: string }>)[0]?.text ?? "unknown error";
        throw new Error(`Upstream write_file returned error: ${text}`);
      }
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Canary write probe failed — upstream cannot write to governed_root. ` +
        `Check filesystem server allowed directories include "${governedRoot}". ` +
        `Error: ${detail}`,
      );
    }

    if (!fs.existsSync(canaryPath)) {
      throw new Error(
        `Canary write probe failed — upstream reported success but file not found at "${canaryPath}". ` +
        `The firewall and upstream may not share the same filesystem view.`,
      );
    }

    try {
      fs.unlinkSync(canaryPath);
    } catch {
      // Non-fatal — canary file left behind is harmless
      console.warn(`Warning: could not delete canary file at ${canaryPath}`);
    }

    console.log("Canary write probe passed: upstream write access to governed_root verified.");
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

    // Step 3a: Secure governed_root if configured
    if (this.policy?.governed_root) {
      try {
        fs.mkdirSync(this.policy.governed_root, { recursive: true, mode: 0o700 });
        // Canonicalize governed_root after creation. On macOS, /tmp symlinks to
        // /private/tmp — without this, realpathSync on children returns
        // /private/tmp/... while governed_root is /tmp/..., failing the prefix check.
        this.policy.governed_root = fs.realpathSync(this.policy.governed_root);
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        throw new Error(
          `Failed to secure governed_root "${this.policy.governed_root}": ${detail}`,
        );
      }
      console.log(`Governed root secured: ${this.policy.governed_root}`);
    }

    // Step 3b: Connect to the upstream MCP server with exponential backoff
    await this.connectWithRetry();
    this.upstreamTools = await this.upstream.listTools();
    // Filter upstream tools to only those listed in policy (allowlist).
    // Tools not in policy are silently blocked — they won't appear in the
    // tool list and calls to them are rejected.
    if (this.authRequired) {
      const allUpstreamTools = this.upstreamTools;
      this.upstreamTools = allUpstreamTools.filter(
        (tool) => !!this.policy!.tools[tool.name],
      );

      const blocked = allUpstreamTools
        .filter((tool) => !this.policy!.tools[tool.name])
        .map((tool) => tool.name);

      if (blocked.length > 0) {
        console.log(
          `Firewall blocking ${blocked.length} upstream tools not in policy: ${blocked.join(", ")}`,
        );
      }

      if (this.upstreamTools.length === 0) {
        await this.upstream.close();
        throw new Error(
          "No upstream tools match the policy allowlist. Check policy config.",
        );
      }
    }
    console.log(
      `Firewall exposing ${this.upstreamTools.length} upstream tools: ${this.upstreamTools.map((t) => t.name).join(", ")}`,
    );

    // Step 3c: Canary write probe — verify upstream can write to governed_root
    if (this.policy?.governed_root) {
      await this.canaryWriteProbe(this.policy.governed_root);
    }

    // Set up the Express app and HTTP server
    const app = express();
    app.use(express.json());

    app.post("/mcp", async (req, res) => {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      let transport: StreamableHTTPServerTransport;

      if (sessionId && this.transports.has(sessionId)) {
        transport = this.transports.get(sessionId)!;
      } else {
        if (this.transports.size >= this.maxSessions) {
          res.status(503).json({
            jsonrpc: "2.0",
            error: { code: -32000, message: "Server session limit reached. Try again later." },
            id: null,
          });
          return;
        }

        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            this.transports.set(newSessionId, transport);
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            this.transports.delete(transport.sessionId);
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

      if (!sessionId || !this.transports.has(sessionId)) {
        res.status(400).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Bad Request: No valid session ID" },
          id: null,
        });
        return;
      }

      const transport = this.transports.get(sessionId)!;
      await transport.handleRequest(req, res);
    });

    app.delete("/mcp", async (req, res) => {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (!sessionId || !this.transports.has(sessionId)) {
        res.status(404).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Session not found" },
          id: null,
        });
        return;
      }

      const transport = this.transports.get(sessionId)!;
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
      server.listen(this.port, this.host, () => {
        server.off("error", onError);
        const url = `http://${this.host}:${this.port}/mcp`;
        console.log(`MCP Firewall listening at ${url}`);
        resolve({ url });
      });
    });
  }

  /** Create a low-level MCP Server that proxies tool calls to the upstream. */
  private createServer(transport: StreamableHTTPServerTransport): Server {
    const server = new Server(
      { name: "mcp-firewall", version: "0.2.0" },
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
        const safeName = typeof name === "string" && name.length > 128
          ? name.slice(0, 128) + "...[truncated]"
          : name;
        return {
          content: [
            {
              type: "text",
              text: `Tool "${safeName}" is not exposed by this firewall.`,
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

        // Preflight path validation for governed filesystem tools.
        // resolvedPath (if valid) is the canonical location used for post-call verification.
        let resolvedPath: string | undefined;
        if (this.policy?.governed_root && typeof (args ?? {}).path === "string") {
          const requestedPath = (args as Record<string, unknown>).path as string;
          const pathResult = validatePath(requestedPath, this.policy.governed_root);

          if (pathResult.status === "malicious") {
            // Sequential: execute → resolve('malicious') → return error.
            // Both must complete before the client gets a response.
            return this.handlePreflightRejection(session, requestedPath);
          }

          resolvedPath = pathResult.resolvedPath;
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

        // Forward to upstream, with post-call verification for governed tools
        return this.forwardWithVerification(
          name,
          args ?? {},
          gateResult.actionId,
          resolvedPath,
        );
      }

      // Forward to upstream (auth not enabled)
      const result = await this.upstream.callTool(name, args ?? {});
      return result;
    });

    return server;
  }

  /**
   * Forward a tool call to the upstream server with outcome evaluation.
   *
   * Outcome rules:
   *   - Upstream error (MCP-level or transport) → resolve as "failed" (bond released)
   *   - Upstream success + resolvedPath provided + artifact exists → resolve as "success" (bond released)
   *   - Upstream success + resolvedPath provided + artifact missing → resolve as "malicious" (bond slashed)
   *   - Upstream success + no resolvedPath (non-governed tool) → action stays open for external review
   *   - Unclassifiable state → resolve as "malicious" (conservative default)
   *
   * @param resolvedPath Canonical path from validatePath. Used for post-call fs.existsSync() verification.
   */
  private async forwardWithVerification(
    toolName: string,
    args: Record<string, unknown>,
    actionId: string,
    resolvedPath?: string,
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

    // Outcome: upstream error → resolve as "failed" (bond released)
    if (failed && this.resolverClient) {
      try {
        await this.resolverClient.resolveAction(actionId, "failed");
      } catch (resolveError) {
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

    // Post-call verification for governed filesystem tools
    if (!failed && resolvedPath && this.resolverClient) {
      const artifactExists = fs.existsSync(resolvedPath);

      if (artifactExists) {
        // Outcome: upstream success + artifact confirmed → resolve as "success"
        try {
          await this.resolverClient.resolveAction(actionId, "success");
        } catch (resolveError) {
          const msg = resolveError instanceof Error ? resolveError.message : String(resolveError);
          console.error(`Failed to resolve action ${actionId} as success: ${msg}`);
        }
      } else {
        // Outcome: upstream success + artifact missing → anomaly → resolve as "malicious"
        console.error(
          `Post-call verification failed: upstream reported success for "${toolName}" ` +
          `but artifact not found at "${resolvedPath}". Resolving as malicious.`,
        );
        try {
          await this.resolverClient.resolveAction(actionId, "malicious");
        } catch (resolveError) {
          const msg = resolveError instanceof Error ? resolveError.message : String(resolveError);
          console.error(`Failed to resolve action ${actionId} as malicious: ${msg}`);
        }

        return {
          content: [
            {
              type: "text",
              text: "Tool call completed but post-call verification failed. Bond has been slashed.",
            },
          ],
          isError: true,
        };
      }
    }

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

  /**
   * Handle a preflight rejection: path validation caught a traversal attempt.
   *
   * Sequential pattern — both steps must complete before the error is returned:
   *   1. executeBondedAction with actionType "firewall.preflight_rejection"
   *   2. resolveAction as "malicious" (bond slashed)
   *   3. Return error to client
   *
   * The attempted path is truncated to 256 characters before inclusion in the
   * AgentGate payload — raw user input is never passed unsanitized.
   */
  private async handlePreflightRejection(
    session: SessionAuth,
    attemptedPath: string,
  ) {
    const MAX_PATH_LENGTH = 256;
    const sanitizedPath = attemptedPath.length > MAX_PATH_LENGTH
      ? attemptedPath.slice(0, MAX_PATH_LENGTH) + "...[truncated]"
      : attemptedPath;

    const payload = {
      attemptedPath: sanitizedPath,
      agentIdentityId: session.identityId,
      agentBondId: session.bondId,
      timestamp: new Date().toISOString(),
      reason: "Path resolves outside governed workspace",
    };

    try {
      const result = await this.agentgateClient!.executeBondedAction(
        this.firewallBondId!,
        "firewall.preflight_rejection",
        payload,
        getExposure(this.policy!, "write_file"),
      );

      await this.resolverClient!.resolveAction(result.actionId, "malicious");
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      console.error(`Preflight rejection bond accounting failed: ${detail}`);
      // Bond accounting failed, but we still reject the request.
      // The failure is logged — manual reconciliation may be needed.
    }

    return {
      content: [
        {
          type: "text",
          text: "Path validation failed: requested path is outside governed workspace.",
        },
      ],
      isError: true,
    };
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

    // Length limits prevent memory bloat and oversized AgentGate payloads.
    const MAX_ID_LENGTH = 256;
    const MAX_SIGNATURE_LENGTH = 512;
    if (
      identityId.length > MAX_ID_LENGTH ||
      bondId.length > MAX_ID_LENGTH ||
      nonce.length > MAX_ID_LENGTH ||
      timestamp.length > MAX_ID_LENGTH ||
      signature.length > MAX_SIGNATURE_LENGTH
    ) {
      return {
        content: [
          {
            type: "text",
            text: "Authentication fields exceed maximum allowed length.",
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
    // Close all transports explicitly to free MCP Server instances
    await Promise.allSettled(
      Array.from(this.transports.values()).map((t) => t.close()),
    );
    this.transports.clear();
    if (this.httpServer) {
      await new Promise<void>((resolve, reject) => {
        this.httpServer!.close((err) => (err ? reject(err) : resolve()));
      });
      this.httpServer = null;
    }
  }
}
