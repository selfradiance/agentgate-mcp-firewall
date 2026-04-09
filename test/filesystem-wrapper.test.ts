/**
 * Smoke test for the filesystem server HTTP wrapper.
 *
 * Starts the wrapper with ~/mcp-firewall-sandbox as the allowed directory,
 * connects via the firewall's UpstreamClient (Streamable HTTP), writes a file,
 * and confirms it appears on disk.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { startFilesystemWrapper } from "./fixtures/filesystem-server-wrapper.js";
import { UpstreamClient } from "../src/upstream-client.js";

const SANDBOX = path.join(process.env.HOME!, "mcp-firewall-sandbox");
const WRAPPER_PORT = 4446; // avoid collisions with echo server and default

describe("Filesystem Server HTTP Wrapper", () => {
  let wrapper: Awaited<ReturnType<typeof startFilesystemWrapper>>;
  let client: UpstreamClient;

  beforeAll(async () => {
    // Ensure sandbox exists
    fs.mkdirSync(SANDBOX, { recursive: true });

    wrapper = await startFilesystemWrapper({
      port: WRAPPER_PORT,
      allowedDir: SANDBOX,
    });

    client = new UpstreamClient({ url: wrapper.url });
    await client.connect();
  }, 30_000);

  afterAll(async () => {
    await client?.close();
    await wrapper?.stop();
  });

  it("discovers upstream filesystem tools", async () => {
    const tools = await client.listTools();
    const toolNames = tools.map((t) => t.name);

    // The filesystem server should expose these tools at minimum
    expect(toolNames).toContain("write_file");
    expect(toolNames).toContain("read_file");
    expect(toolNames).toContain("create_directory");
    expect(toolNames).toContain("list_directory");

    console.log("Discovered tools:", toolNames.join(", "));
  });

  it("writes a file through the wrapper and confirms it on disk", async () => {
    const testFile = path.join(SANDBOX, "wrapper-smoke-test.txt");
    const content = `Smoke test at ${new Date().toISOString()}`;

    // Clean up from previous run
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }

    // Write via MCP
    const result = await client.callTool("write_file", {
      path: testFile,
      content,
    });

    expect(result.isError).toBeFalsy();

    // Confirm on disk
    expect(fs.existsSync(testFile)).toBe(true);
    const onDisk = fs.readFileSync(testFile, "utf-8");
    expect(onDisk).toBe(content);

    // Clean up
    fs.unlinkSync(testFile);
  });

  it("creates a directory through the wrapper and confirms it on disk", async () => {
    const testDir = path.join(SANDBOX, "wrapper-smoke-dir");

    // Clean up from previous run
    if (fs.existsSync(testDir)) {
      fs.rmdirSync(testDir);
    }

    const result = await client.callTool("create_directory", {
      path: testDir,
    });

    expect(result.isError).toBeFalsy();

    // Confirm on disk
    expect(fs.existsSync(testDir)).toBe(true);
    expect(fs.statSync(testDir).isDirectory()).toBe(true);

    // Clean up
    fs.rmdirSync(testDir);
  });

  it("rejects writes outside the allowed directory", async () => {
    const result = await client.callTool("write_file", {
      path: "/tmp/should-not-work.txt",
      content: "this should fail",
    });

    // The filesystem server should reject this
    expect(result.isError).toBe(true);

    // Confirm file was NOT created
    expect(fs.existsSync("/tmp/should-not-work.txt")).toBe(false);
  });
});
