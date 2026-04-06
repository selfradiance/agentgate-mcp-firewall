import http from "node:http";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { UpstreamClient } from "../src/upstream-client.js";
import { startEchoServer } from "./fixtures/echo-server.js";

const TEST_PORT = 4556;

describe("UpstreamClient", () => {
  let httpServer: http.Server;
  let upstream: UpstreamClient;
  let serverUrl: string;

  beforeAll(async () => {
    const result = await startEchoServer(TEST_PORT);
    httpServer = result.server;
    serverUrl = result.url;

    upstream = new UpstreamClient({ url: serverUrl });
    await upstream.connect();
  });

  afterAll(async () => {
    await upstream.close();
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should list tools from the upstream server", async () => {
    const tools = await upstream.listTools();
    const toolNames = tools.map((t) => t.name);
    expect(toolNames).toContain("echo");
    expect(toolNames).toContain("add");
  });

  it("should throw if listTools called before connect", async () => {
    const disconnected = new UpstreamClient({ url: serverUrl });
    await expect(disconnected.listTools()).rejects.toThrow(
      "not connected",
    );
  });
});
