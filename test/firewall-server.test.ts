import http from "node:http";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startEchoServer } from "./fixtures/echo-server.js";
import { FirewallServer } from "../src/firewall-server.js";

const ECHO_PORT = 4444;
const FIREWALL_PORT = 5555;

describe("FirewallServer", () => {
  let echoHttpServer: http.Server;
  let firewall: FirewallServer;
  let client: Client;
  let serverUrl: string;

  beforeAll(async () => {
    // Start the upstream echo fixture server
    const echo = await startEchoServer(ECHO_PORT);
    echoHttpServer = echo.server;
    serverUrl = echo.url;

    // Start the firewall pointing at the echo server
    firewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: serverUrl,
    });
    await firewall.start();

    // Connect a test client to the firewall
    client = new Client({ name: "test-client", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await client.connect(transport);
  });

  afterAll(async () => {
    await client.close();
    await firewall.stop();
    await new Promise<void>((resolve, reject) => {
      echoHttpServer.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should list echo and add tools through the firewall", async () => {
    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);
    expect(toolNames).toContain("echo");
    expect(toolNames).toContain("add");
  });

  it("should proxy echo tool calls through the firewall", async () => {
    const result = await client.callTool({
      name: "echo",
      arguments: { message: "proxied" },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toBe("proxied");
  });

  it("should proxy add tool calls through the firewall", async () => {
    const result = await client.callTool({
      name: "add",
      arguments: { a: 10, b: 20 },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toBe("30");
  });

  it("should reject tool calls that are not exposed by the firewall", async () => {
    const result = await client.callTool({
      name: "hidden_tool",
      arguments: {},
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toMatch(/not exposed/i);
  });

  it("should only expose upstream tools that are in the policy allowlist", async () => {
    const guardedEcho = await startEchoServer(ECHO_PORT + 1);
    const guardedFirewall = new FirewallServer({
      port: FIREWALL_PORT + 1,
      upstreamUrl: guardedEcho.url,
      agentgateClient: {} as any,
      resolverClient: {} as any,
      policy: {
        tools: {
          echo: { tier: "low", exposure_cents: 10 },
          // "add" deliberately omitted — should be blocked
        },
        default_exposure_cents: 10,
      },
      firewallBondId: "bond_test",
    });

    await guardedFirewall.start();

    // Connect a client and verify only "echo" + "authenticate" are listed
    const testClient = new Client({ name: "test-client", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT + 1}/mcp`),
    );
    await testClient.connect(transport);

    const result = await testClient.listTools();
    const toolNames = result.tools.map((t) => t.name);
    expect(toolNames).toContain("echo");
    expect(toolNames).toContain("authenticate");
    expect(toolNames).not.toContain("add");

    await testClient.close();
    await guardedFirewall.stop();
    await new Promise<void>((resolve, reject) => {
      guardedEcho.server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should fail closed when no upstream tools match the policy", async () => {
    const guardedEcho = await startEchoServer(ECHO_PORT + 3);
    const guardedFirewall = new FirewallServer({
      port: FIREWALL_PORT + 3,
      upstreamUrl: guardedEcho.url,
      agentgateClient: {} as any,
      resolverClient: {} as any,
      policy: {
        tools: {
          nonexistent_tool: { tier: "low", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
      firewallBondId: "bond_test",
    });

    await expect(guardedFirewall.start()).rejects.toThrow(
      /No upstream tools match the policy allowlist/,
    );

    await guardedFirewall.stop();
    await new Promise<void>((resolve, reject) => {
      guardedEcho.server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should fail closed when filesystem policy is loaded against wrong upstream", async () => {
    // Simulates misconfiguration: filesystem policy (write_file, create_directory)
    // loaded against an upstream that only exposes echo/add.
    const wrongEcho = await startEchoServer(ECHO_PORT + 5);
    const wrongFirewall = new FirewallServer({
      port: FIREWALL_PORT + 5,
      upstreamUrl: wrongEcho.url,
      agentgateClient: {} as any,
      resolverClient: {} as any,
      policy: {
        governed_root: "/Users/jamestoole/mcp-firewall-sandbox",
        tools: {
          write_file: { tier: "medium", exposure_cents: 50 },
          create_directory: { tier: "low", exposure_cents: 10 },
        },
        default_exposure_cents: 100,
      },
      firewallBondId: "bond_test",
    });

    await expect(wrongFirewall.start()).rejects.toThrow(
      /No upstream tools match the policy allowlist/,
    );

    await wrongFirewall.stop();
    await new Promise<void>((resolve, reject) => {
      wrongEcho.server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should reject new sessions when session limit is reached", async () => {
    const limitEcho = await startEchoServer(ECHO_PORT + 10);
    const limitFirewall = new FirewallServer({
      port: FIREWALL_PORT + 10,
      upstreamUrl: limitEcho.url,
      maxSessions: 3,
    });
    await limitFirewall.start();

    const firewallUrl = `http://127.0.0.1:${FIREWALL_PORT + 10}/mcp`;
    const clients: Client[] = [];

    // Open 3 sessions using proper MCP clients (the configured maxSessions)
    for (let i = 0; i < 3; i++) {
      const c = new Client({ name: `limit-test-${i}`, version: "1.0.0" });
      const t = new StreamableHTTPClientTransport(new URL(firewallUrl));
      await c.connect(t);
      clients.push(c);
    }

    // The 4th client should fail to connect (503 from the server)
    const extraClient = new Client({ name: "limit-test-extra", version: "1.0.0" });
    const extraTransport = new StreamableHTTPClientTransport(new URL(firewallUrl));
    await expect(extraClient.connect(extraTransport)).rejects.toThrow();

    for (const c of clients) {
      await c.close();
    }
    await limitFirewall.stop();
    await new Promise<void>((resolve, reject) => {
      limitEcho.server.close((err) => (err ? reject(err) : resolve()));
    });
  }, 30_000);

  it("should reject startup when the listening port is already in use", async () => {
    const conflictingEcho = await startEchoServer(ECHO_PORT + 4);
    const conflictingFirewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: conflictingEcho.url,
    });

    await expect(conflictingFirewall.start()).rejects.toThrow(/EADDRINUSE/);
    await conflictingFirewall.stop();
    await new Promise<void>((resolve, reject) => {
      conflictingEcho.server.close((err) => (err ? reject(err) : resolve()));
    });
  });
});
