import http from "node:http";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startEchoServer } from "./fixtures/echo-server.js";

const TEST_PORT = 4555;

describe("echo MCP server", () => {
  let httpServer: http.Server;
  let client: Client;
  let serverUrl: string;

  beforeAll(async () => {
    const result = await startEchoServer(TEST_PORT);
    httpServer = result.server;
    serverUrl = result.url;

    client = new Client({ name: "test-client", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(serverUrl));
    await client.connect(transport);
  });

  afterAll(async () => {
    await client.close();
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should list echo and add tools", async () => {
    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);
    expect(toolNames).toContain("echo");
    expect(toolNames).toContain("add");
  });

  it("should echo a message back", async () => {
    const result = await client.callTool({
      name: "echo",
      arguments: { message: "hello" },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toBe("hello");
  });

  it("should add two numbers", async () => {
    const result = await client.callTool({
      name: "add",
      arguments: { a: 2, b: 3 },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0]
      .text;
    expect(text).toBe("5");
  });
});
