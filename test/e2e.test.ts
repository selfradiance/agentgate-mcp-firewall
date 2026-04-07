/**
 * End-to-End Integration Test
 *
 * IMPORTANT: These tests require a running AgentGate instance on localhost:3000.
 * Start AgentGate before running: cd ~/Desktop/projects/agentgate && npm run dev
 *
 * Proves the full MCP Firewall loop:
 * - Identity registration and bond locking on AgentGate
 * - Firewall startup with upstream discovery
 * - Session authentication via the authenticate tool
 * - Bonded tool calls proxied through the firewall
 * - Action recording on AgentGate with correct payloads
 * - Action resolution releasing bond exposure
 * - Unauthenticated sessions are rejected
 */

import http from "node:http";
import path from "node:path";
import { unlinkSync, existsSync } from "node:fs";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startEchoServer } from "./fixtures/echo-server.js";
import { FirewallServer } from "../src/firewall-server.js";
import { AgentGateClient } from "../src/agentgate-client.js";
import type { PolicyConfig } from "../src/policy.js";

const AGENTGATE_URL = "http://127.0.0.1:3000";
const API_KEY = process.env.AGENTGATE_REST_KEY ?? "testkey123";
const ECHO_PORT = 4570;
const FIREWALL_PORT = 5570;
// Low exposure values to fit within Tier 1 bond cap (100 cents) with 1.2x multiplier
const E2E_POLICY: PolicyConfig = {
  tools: {
    echo: { tier: "low", exposure_cents: 10 },
    add: { tier: "medium", exposure_cents: 10 },
  },
  default_exposure_cents: 10,
};

const EXECUTOR_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-e2e-executor-identity.json",
);
const RESOLVER_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-e2e-resolver-identity.json",
);
const AGENT_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-e2e-agent-identity.json",
);

const IDENTITY_PATHS = [
  EXECUTOR_IDENTITY_PATH,
  RESOLVER_IDENTITY_PATH,
  AGENT_IDENTITY_PATH,
];

async function isAgentGateRunning(): Promise<boolean> {
  try {
    const response = await fetch(`${AGENTGATE_URL}/health`);
    return response.ok;
  } catch {
    return false;
  }
}

function cleanupFiles() {
  for (const p of IDENTITY_PATHS) {
    if (existsSync(p)) unlinkSync(p);
  }
}

describe("end-to-end", () => {
  let echoHttpServer: http.Server;
  let firewall: FirewallServer;
  let client: Client;
  let transport: StreamableHTTPClientTransport;
  let running: boolean;

  // AgentGate clients
  let executorClient: AgentGateClient;
  let resolverClient: AgentGateClient;
  let agentClient: AgentGateClient;

  // IDs
  let agentIdentityId: string;
  let agentBondId: string;
  let executorBondId: string;

  beforeAll(async () => {
    running = await isAgentGateRunning();
    if (!running) {
      console.warn(
        "\n⚠️  AgentGate is not running on localhost:3000 — skipping e2e tests.\n" +
          "   Start AgentGate: cd ~/Desktop/projects/agentgate && npm run dev\n",
      );
      return;
    }

    cleanupFiles();

    // 1. Create firewall executor identity on AgentGate
    executorClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: EXECUTOR_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await executorClient.registerIdentity();

    // Lock a bond for the executor (Tier 1 cap: 100 cents)
    const executorBond = await executorClient.lockBond(
      executorClient.identityId!,
      100,
      "USD",
      3600,
      "e2e test executor bond",
    );
    executorBondId = executorBond.bondId;

    // 2. Create firewall resolver identity on AgentGate
    resolverClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: RESOLVER_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await resolverClient.registerIdentity();

    // 3. Create test agent identity on AgentGate
    agentClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: AGENT_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    const agentReg = await agentClient.registerIdentity();
    agentIdentityId = agentReg.identityId;

    // Lock a bond for the agent with enough capacity for multiple calls
    const agentBond = await agentClient.lockBond(
      agentIdentityId,
      100,
      "USD",
      3600,
      "e2e test agent bond",
    );
    agentBondId = agentBond.bondId;

    // 4. Start the echo fixture server
    const echo = await startEchoServer(ECHO_PORT);
    echoHttpServer = echo.server;

    // 5. Start the firewall with all components wired together
    firewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: echo.url,
      agentgateClient: executorClient,
      resolverClient,
      policy: E2E_POLICY,
      firewallBondId: executorBondId,
    });
    await firewall.start();

    // 7. Connect a test MCP client to the firewall
    client = new Client({ name: "e2e-test-client", version: "1.0.0" });
    transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await client.connect(transport);
  });

  afterAll(async () => {
    if (!running) return;
    if (client) await client.close();
    if (firewall) await firewall.stop();
    if (echoHttpServer) {
      await new Promise<void>((resolve, reject) => {
        echoHttpServer.close((err) => (err ? reject(err) : resolve()));
      });
    }
    cleanupFiles();
  });

  it("should complete the full happy path: authenticate, echo, add", async () => {
    if (!running) return;

    // Record executor action count before
    const beforeSummary = await executorClient.checkIdentity(
      executorClient.identityId!,
    );
    const actionsBefore = beforeSummary.reputation.stats.actions;

    // Authenticate with the agent's identity and bond
    const authResult = await client.callTool({
      name: "authenticate",
      arguments: agentClient.createAuthenticationArguments(
        agentIdentityId,
        agentBondId,
        transport.sessionId!,
      ),
    });
    expect(authResult.isError).toBeUndefined();
    const authText = (
      authResult.content as Array<{ type: string; text: string }>
    )[0].text;
    expect(authText).toMatch(/[Aa]uthenticated/);
    expect(authText).toContain(agentIdentityId);
    expect(authText).toContain(agentBondId);

    // Call echo through the firewall
    const echoResult = await client.callTool({
      name: "echo",
      arguments: { message: "end-to-end test" },
    });
    expect(echoResult.isError).toBeUndefined();
    const echoText = (
      echoResult.content as Array<{ type: string; text: string }>
    )[0].text;
    expect(echoText).toBe("end-to-end test");

    // Call add through the firewall
    const addResult = await client.callTool({
      name: "add",
      arguments: { a: 7, b: 8 },
    });
    expect(addResult.isError).toBeUndefined();
    const addText = (
      addResult.content as Array<{ type: string; text: string }>
    )[0].text;
    expect(addText).toBe("15");

    // Verify actions were recorded on AgentGate
    const afterSummary = await executorClient.checkIdentity(
      executorClient.identityId!,
    );
    const actionsAfter = afterSummary.reputation.stats.actions;
    expect(actionsAfter).toBe(actionsBefore + 2); // echo + add = 2 new actions
  });

  it("should resolve an action with outcome success and release bond exposure", async () => {
    if (!running) return;

    // Execute an action directly on the executor's bond so we get the actionId
    const action = await executorClient.executeBondedAction(
      executorBondId,
      "mcp.tool_call",
      {
        upstreamUrl: `http://127.0.0.1:${ECHO_PORT}/mcp`,
        toolName: "echo",
        arguments: { message: "resolve test" },
        timestamp: new Date().toISOString(),
        tier: "low",
        agentIdentityId,
        agentBondId,
      },
      10,
    );
    expect(action.actionId).toMatch(/^action_/);
    expect(action.status).toBe("open");

    // Resolve the action as success using the resolver identity
    const resolution = await resolverClient.resolveAction(
      action.actionId,
      "success",
    );
    expect(resolution.actionId).toBe(action.actionId);
    expect(resolution.outcome).toBe("success");
    // On success, full exposure is refunded
    expect(resolution.refundCents).toBeGreaterThan(0);
    expect(resolution.slashedCents).toBe(0);
    expect(resolution.burnedCents).toBe(0);
  });

  it("should reject tool calls from an unauthenticated session", async () => {
    if (!running) return;

    // Connect a fresh client (new session, no authentication)
    const freshClient = new Client({
      name: "unauthenticated-client",
      version: "1.0.0",
    });
    const freshTransport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await freshClient.connect(freshTransport);

    // Try to call echo without authenticating
    const result = await freshClient.callTool({
      name: "echo",
      arguments: { message: "should be rejected" },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toMatch(/[Aa]uthenticat/);

    await freshClient.close();
  });
});
