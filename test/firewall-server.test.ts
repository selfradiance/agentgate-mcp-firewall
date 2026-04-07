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

  it("should fail closed when policy entries are missing for discovered tools", async () => {
    const guardedEcho = await startEchoServer(ECHO_PORT + 1);
    const guardedFirewall = new FirewallServer({
      port: FIREWALL_PORT + 1,
      upstreamUrl: guardedEcho.url,
      agentgateClient: {} as any,
      resolverClient: {} as any,
      policy: {
        tools: {
          echo: { tier: "low", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
      firewallBondId: "bond_test",
    });

    await expect(guardedFirewall.start()).rejects.toThrow(
      /Policy is missing explicit entries.*add/,
    );

    await guardedFirewall.stop();
    await new Promise<void>((resolve, reject) => {
      guardedEcho.server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should reject startup when the listening port is already in use", async () => {
    const conflictingEcho = await startEchoServer(ECHO_PORT + 2);
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
