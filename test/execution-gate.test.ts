/**
 * Execution Gate Integration Tests
 *
 * IMPORTANT: These tests require a running AgentGate instance on localhost:3000.
 * Start AgentGate before running: cd ~/Desktop/projects/agentgate && npm run dev
 *
 * Tests verify that the firewall records bonded actions on AgentGate
 * before forwarding tool calls, and blocks calls when the bond has
 * insufficient capacity.
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
const ECHO_PORT = 4558;
const FIREWALL_PORT = 5558;
const FIREWALL_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-exec-firewall-identity.json",
);
const RESOLVER_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-exec-resolver-identity.json",
);
const AGENT_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-exec-agent-identity.json",
);

// Policy: echo costs 10 cents, add costs 20 cents, default 15 cents
const TEST_POLICY: PolicyConfig = {
  tools: {
    echo: { tier: "low", exposure_cents: 10 },
    add: { tier: "medium", exposure_cents: 20 },
  },
  default_exposure_cents: 15,
};

async function isAgentGateRunning(): Promise<boolean> {
  try {
    const response = await fetch(`${AGENTGATE_URL}/health`);
    return response.ok;
  } catch {
    return false;
  }
}

describe("execution gate", () => {
  let echoHttpServer: http.Server;
  let firewall: FirewallServer;
  let client: Client;
  let running: boolean;
  let agentIdentityId: string;
  let agentBondId: string;
  let firewallBondId: string;

  beforeAll(async () => {
    running = await isAgentGateRunning();
    if (!running) {
      console.warn(
        "\n⚠️  AgentGate is not running on localhost:3000 — skipping execution gate tests.\n" +
          "   Start AgentGate: cd ~/Desktop/projects/agentgate && npm run dev\n",
      );
      return;
    }

    // Clean up leftover identity files
    for (const p of [FIREWALL_IDENTITY_PATH, RESOLVER_IDENTITY_PATH, AGENT_IDENTITY_PATH]) {
      if (existsSync(p)) unlinkSync(p);
    }

    // Create the firewall's AgentGate client and register its identity
    const firewallAgClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: FIREWALL_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await firewallAgClient.registerIdentity();

    // Lock a bond for the firewall identity (Tier 1 cap: 100 cents)
    const firewallBond = await firewallAgClient.lockBond(
      firewallAgClient.identityId!,
      100,
      "USD",
      3600,
      "MCP firewall execution gate test",
    );
    firewallBondId = firewallBond.bondId;

    // Create resolver identity (required by fail-closed validation)
    const resolverClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: RESOLVER_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await resolverClient.registerIdentity();

    // Create a separate agent identity and lock a bond for it
    const agentClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: AGENT_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    const agentReg = await agentClient.registerIdentity();
    agentIdentityId = agentReg.identityId;

    const agentBond = await agentClient.lockBond(
      agentIdentityId,
      100,
      "USD",
      3600,
      "MCP firewall agent test bond",
    );
    agentBondId = agentBond.bondId;

    // Start the echo fixture server
    const echo = await startEchoServer(ECHO_PORT);
    echoHttpServer = echo.server;

    // Start the firewall with all governance components (all required by fail-closed validation)
    firewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: echo.url,
      agentgateClient: firewallAgClient,
      resolverClient,
      policy: TEST_POLICY,
      firewallBondId,
    });
    await firewall.start();

    // Connect a test MCP client to the firewall
    client = new Client({ name: "test-client", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await client.connect(transport);

    // Authenticate the agent on the firewall
    const authResult = await client.callTool({
      name: "authenticate",
      arguments: { identityId: agentIdentityId, bondId: agentBondId },
    });
    const authText = (
      authResult.content as Array<{ type: string; text: string }>
    )[0].text;
    expect(authText).toMatch(/[Aa]uthenticated/);
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

    for (const p of [FIREWALL_IDENTITY_PATH, RESOLVER_IDENTITY_PATH, AGENT_IDENTITY_PATH]) {
      if (existsSync(p)) unlinkSync(p);
    }
  });

  it("should record a bonded action and forward the echo tool call", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "echo",
      arguments: { message: "bonded call" },
    });

    // The call should succeed — echo returns the message
    expect(result.isError).toBeUndefined();
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toBe("bonded call");
  });

  it("should record a bonded action for add with medium tier exposure", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "add",
      arguments: { a: 7, b: 8 },
    });

    expect(result.isError).toBeUndefined();
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toBe("15");
  });

  it("should block tool calls when bond has insufficient capacity", async () => {
    if (!running) return;

    // The firewall bond has 100 cents. Each echo call uses 10 cents with 1.2x
    // multiplier = 12 effective cents. After several calls the bond will be exhausted.
    // We already used some capacity above. Keep calling until blocked.
    let blocked = false;
    let lastResult;

    for (let i = 0; i < 15; i++) {
      lastResult = await client.callTool({
        name: "echo",
        arguments: { message: `capacity test ${i}` },
      });
      if (lastResult.isError) {
        blocked = true;
        break;
      }
    }

    expect(blocked).toBe(true);
    const text = (
      lastResult!.content as Array<{ type: string; text: string }>
    )[0].text;
    expect(text).toMatch(/[Bb]locked/);
  });
});
