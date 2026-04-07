/**
 * Authentication Integration Tests
 *
 * IMPORTANT: These tests require a running AgentGate instance on localhost:3000.
 * Start AgentGate before running: cd ~/Desktop/projects/agentgate && npm run dev
 *
 * Tests verify that the firewall's authenticate tool gates access to upstream tools.
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
const ECHO_PORT = 4557;
const FIREWALL_PORT = 5557;
const FIREWALL_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-auth-firewall-identity.json",
);
const RESOLVER_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-auth-resolver-identity.json",
);
const AGENT_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-auth-agent-identity.json",
);

// Low exposure values to fit within Tier 1 bond cap (100 cents) with 1.2x multiplier
const AUTH_TEST_POLICY: PolicyConfig = {
  tools: {
    echo: { tier: "low", exposure_cents: 10 },
    add: { tier: "medium", exposure_cents: 10 },
  },
  default_exposure_cents: 10,
};

async function isAgentGateRunning(): Promise<boolean> {
  try {
    const response = await fetch(`${AGENTGATE_URL}/health`);
    return response.ok;
  } catch {
    return false;
  }
}

describe("authenticate tool", () => {
  let echoHttpServer: http.Server;
  let firewall: FirewallServer;
  let client: Client;
  let transport: StreamableHTTPClientTransport;
  let running: boolean;
  let agentClient: AgentGateClient;
  let agentIdentityId: string;
  let bondId: string;
  let firewallBondId: string;

  beforeAll(async () => {
    running = await isAgentGateRunning();
    if (!running) {
      console.warn(
        "\n⚠️  AgentGate is not running on localhost:3000 — skipping auth tests.\n" +
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

    // Lock a bond for the firewall identity (required by fail-closed validation)
    const firewallBond = await firewallAgClient.lockBond(
      firewallAgClient.identityId!,
      100,
      "USD",
      3600,
      "MCP firewall auth test - firewall bond",
    );
    firewallBondId = firewallBond.bondId;

    // Create resolver identity (required by fail-closed validation)
    const resolverClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: RESOLVER_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await resolverClient.registerIdentity();

    // Create a separate "agent" identity that will authenticate through the firewall
    agentClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: AGENT_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    const agentReg = await agentClient.registerIdentity();
    agentIdentityId = agentReg.identityId;

    // Lock a bond for the agent identity
    // Tier 1 identities on AgentGate are capped at 100 cents
    const bondResult = await agentClient.lockBond(
      agentIdentityId,
      100,
      "USD",
      3600,
      "MCP firewall auth test",
    );
    bondId = bondResult.bondId;

    // Start the echo fixture server
    const echo = await startEchoServer(ECHO_PORT);
    echoHttpServer = echo.server;

    // Start the firewall with all governance components (all required by fail-closed validation)
    firewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: echo.url,
      agentgateClient: firewallAgClient,
      resolverClient,
      policy: AUTH_TEST_POLICY,
      firewallBondId,
    });
    await firewall.start();

    // Connect a test MCP client to the firewall
    client = new Client({ name: "test-client", version: "1.0.0" });
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

    // Clean up identity files
    for (const p of [FIREWALL_IDENTITY_PATH, RESOLVER_IDENTITY_PATH, AGENT_IDENTITY_PATH]) {
      if (existsSync(p)) unlinkSync(p);
    }
  });

  it("should list authenticate tool alongside upstream tools", async () => {
    if (!running) return;

    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);
    expect(toolNames).toContain("authenticate");
    expect(toolNames).toContain("echo");
    expect(toolNames).toContain("add");
  });

  it("should reject upstream tool calls before authentication", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "echo",
      arguments: { message: "should fail" },
    });
    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toMatch(/[Aa]uthenticat/);
  });

  it("should authenticate with a valid identity and bond", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "authenticate",
      arguments: agentClient.createAuthenticationArguments(
        agentIdentityId,
        bondId,
        transport.sessionId!,
      ),
    });
    expect(result.isError).toBeUndefined();
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toMatch(/[Aa]uthenticated/);
    expect(text).toContain(agentIdentityId);
    expect(text).toContain(bondId);
  });

  it("should allow upstream tool calls after authentication", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "echo",
      arguments: { message: "hello after auth" },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toBe("hello after auth");
  });

  it("should reject authenticate with a non-existent identity", async () => {
    if (!running) return;

    // Create a fresh client on a new session
    const client2 = new Client({ name: "test-client-2", version: "1.0.0" });
    const transport2 = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await client2.connect(transport2);

    const result = await client2.callTool({
      name: "authenticate",
      arguments: {
        identityId: "id_nonexistent",
        bondId: "bond_fake",
        nonce: "nonce_fake",
        timestamp: String(Date.now()),
        signature: "signature_fake",
      },
    });
    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toMatch(/[Ff]ailed/);

    await client2.close();
  });

  it("should reject authenticate when the signed bond ID does not exist", async () => {
    if (!running) return;

    const client3 = new Client({ name: "test-client-3", version: "1.0.0" });
    const transport3 = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await client3.connect(transport3);

    const fakeArgs = agentClient.createAuthenticationArguments(
      agentIdentityId,
      "bond_fake_not_real",
      transport3.sessionId!,
    );
    const result = await client3.callTool({
      name: "authenticate",
      arguments: fakeArgs,
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toMatch(/[Bb]ond/);

    await client3.close();
  });
});
