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

const AGENTGATE_URL = "http://127.0.0.1:3000";
const API_KEY = process.env.AGENTGATE_REST_KEY ?? "testkey123";
const ECHO_PORT = 4557;
const FIREWALL_PORT = 5557;
const FIREWALL_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-auth-firewall-identity.json",
);
const AGENT_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-auth-agent-identity.json",
);

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
  let running: boolean;
  let agentIdentityId: string;
  let bondId: string;

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
    for (const p of [FIREWALL_IDENTITY_PATH, AGENT_IDENTITY_PATH]) {
      if (existsSync(p)) unlinkSync(p);
    }

    // Create the firewall's AgentGate client and register its identity
    const firewallAgClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: FIREWALL_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await firewallAgClient.registerIdentity();

    // Create a separate "agent" identity that will authenticate through the firewall
    const agentClient = new AgentGateClient({
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

    // Start the firewall with the AgentGate client (auth enabled)
    firewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: echo.url,
      agentgateClient: firewallAgClient,
    });
    await firewall.start();

    // Connect a test MCP client to the firewall
    client = new Client({ name: "test-client", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(
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
    for (const p of [FIREWALL_IDENTITY_PATH, AGENT_IDENTITY_PATH]) {
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
      arguments: { identityId: agentIdentityId, bondId },
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
      arguments: { identityId: "id_nonexistent", bondId: "bond_fake" },
    });
    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toMatch(/[Ff]ailed/);

    await client2.close();
  });
});
