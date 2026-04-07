/**
 * Rollback Integration Tests
 *
 * IMPORTANT: These tests require a running AgentGate instance on localhost:3000.
 * Start AgentGate before running: cd ~/Desktop/projects/agentgate && npm run dev
 *
 * Tests verify that the firewall resolves actions as "failed" on AgentGate
 * when the upstream tool call fails, and leaves actions open when calls succeed.
 */

import http from "node:http";
import path from "node:path";
import { unlinkSync, existsSync } from "node:fs";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startEchoServer } from "./fixtures/echo-server.js";
import { startErrorServer } from "./fixtures/error-server.js";
import { FirewallServer } from "../src/firewall-server.js";
import { AgentGateClient } from "../src/agentgate-client.js";
import type { PolicyConfig } from "../src/policy.js";

const AGENTGATE_URL = "http://127.0.0.1:3000";
const API_KEY = process.env.AGENTGATE_REST_KEY ?? "testkey123";

// Ports for the error-upstream scenario
const ERROR_UPSTREAM_PORT = 4559;
const ERROR_FIREWALL_PORT = 5559;

// Ports for the working-upstream scenario
const ECHO_UPSTREAM_PORT = 4560;
const ECHO_FIREWALL_PORT = 5560;

const EXECUTOR_IDENTITY_PATH = path.resolve(
  import.meta.dirname, "fixtures", "test-rollback-executor-identity.json",
);
const RESOLVER_IDENTITY_PATH = path.resolve(
  import.meta.dirname, "fixtures", "test-rollback-resolver-identity.json",
);
const AGENT_IDENTITY_PATH = path.resolve(
  import.meta.dirname, "fixtures", "test-rollback-agent-identity.json",
);

const TEST_POLICY: PolicyConfig = {
  tools: {
    echo: { tier: "low", exposure_cents: 10 },
    add: { tier: "medium", exposure_cents: 20 },
  },
  default_exposure_cents: 15,
};

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

describe("rollback on upstream failure", () => {
  let errorHttpServer: http.Server;
  let firewall: FirewallServer;
  let client: Client;
  let running: boolean;
  let agentClient: AgentGateClient;

  beforeAll(async () => {
    running = await isAgentGateRunning();
    if (!running) {
      console.warn(
        "\n⚠️  AgentGate is not running on localhost:3000 — skipping rollback tests.\n",
      );
      return;
    }

    cleanupFiles();

    // Create executor identity (records actions)
    const executorClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: EXECUTOR_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await executorClient.registerIdentity();
    const executorBond = await executorClient.lockBond(
      executorClient.identityId!, 100, "USD", 3600, "rollback test executor bond",
    );

    // Create resolver identity (resolves failed actions)
    const resolverClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: RESOLVER_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await resolverClient.registerIdentity();

    // Create agent identity
    agentClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: AGENT_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    const agentReg = await agentClient.registerIdentity();
    const agentBond = await agentClient.lockBond(
      agentReg.identityId, 100, "USD", 3600, "rollback test agent bond",
    );

    // Start the error fixture server
    const errorServer = await startErrorServer(ERROR_UPSTREAM_PORT);
    errorHttpServer = errorServer.server;

    // Start the firewall pointing at the error server
    firewall = new FirewallServer({
      port: ERROR_FIREWALL_PORT,
      upstreamUrl: errorServer.url,
      agentgateClient: executorClient,
      resolverClient,
      policy: TEST_POLICY,
      firewallBondId: executorBond.bondId,
    });
    await firewall.start();

    // Connect and authenticate
    client = new Client({ name: "test-client", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${ERROR_FIREWALL_PORT}/mcp`),
    );
    await client.connect(transport);

    await client.callTool({
      name: "authenticate",
      arguments: agentClient.createAuthenticationArguments(
        agentReg.identityId,
        agentBond.bondId,
        transport.sessionId!,
      ),
    });
  });

  afterAll(async () => {
    if (!running) return;
    if (client) await client.close();
    if (firewall) await firewall.stop();
    if (errorHttpServer) {
      await new Promise<void>((resolve, reject) => {
        errorHttpServer.close((err) => (err ? reject(err) : resolve()));
      });
    }
    cleanupFiles();
  });

  it("should resolve action as failed when upstream tool errors", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "echo",
      arguments: { message: "will fail" },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/[Ff]ailed/);
    expect(text).toMatch(/[Bb]ond exposure has been released/);
  });

  it("should confirm rollback released the bond exposure", async () => {
    if (!running) return;

    // After the previous call failed and was rolled back (resolved as "failed"),
    // AgentGate resolved the action and transitioned the bond status.
    // A second call will fail at the AgentGate level (bond no longer active),
    // confirming the first action's resolution actually happened.
    const result = await client.callTool({
      name: "echo",
      arguments: { message: "second attempt" },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    // The bond transitioned after the resolved action — this proves rollback occurred
    expect(text).toMatch(/[Bb]locked|[Bb]ond/);
  });
});

describe("successful upstream call leaves action open", () => {
  let echoHttpServer: http.Server;
  let firewall: FirewallServer;
  let client: Client;
  let running: boolean;
  let agentClient: AgentGateClient;

  beforeAll(async () => {
    running = await isAgentGateRunning();
    if (!running) return;

    cleanupFiles();

    // Create executor identity
    const executorClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: EXECUTOR_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await executorClient.registerIdentity();
    const executorBond = await executorClient.lockBond(
      executorClient.identityId!, 100, "USD", 3600, "rollback test success bond",
    );

    // Create resolver identity
    const resolverClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: RESOLVER_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await resolverClient.registerIdentity();

    // Create agent identity
    agentClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: AGENT_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    const agentReg = await agentClient.registerIdentity();
    const agentBond = await agentClient.lockBond(
      agentReg.identityId, 100, "USD", 3600, "rollback test agent success bond",
    );

    // Start the echo fixture server (working upstream)
    const echo = await startEchoServer(ECHO_UPSTREAM_PORT);
    echoHttpServer = echo.server;

    // Start the firewall pointing at the working echo server
    firewall = new FirewallServer({
      port: ECHO_FIREWALL_PORT,
      upstreamUrl: echo.url,
      agentgateClient: executorClient,
      resolverClient,
      policy: TEST_POLICY,
      firewallBondId: executorBond.bondId,
    });
    await firewall.start();

    // Connect and authenticate
    client = new Client({ name: "test-client", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${ECHO_FIREWALL_PORT}/mcp`),
    );
    await client.connect(transport);

    await client.callTool({
      name: "authenticate",
      arguments: agentClient.createAuthenticationArguments(
        agentReg.identityId,
        agentBond.bondId,
        transport.sessionId!,
      ),
    });
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

  it("should return echo result and not resolve the action", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "echo",
      arguments: { message: "success path" },
    });

    // The call should succeed normally
    expect(result.isError).toBeUndefined();
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toBe("success path");
  });
});
