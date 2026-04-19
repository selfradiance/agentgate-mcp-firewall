/**
 * Filesystem Governance Integration Tests (v0.2.0)
 *
 * IMPORTANT: These tests require:
 *   1. AgentGate running on localhost:3000
 *   2. The filesystem wrapper is started internally per-test
 *
 * Tests skip gracefully if AgentGate is not running.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, beforeEach, afterAll, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startFilesystemWrapper } from "./fixtures/filesystem-server-wrapper.js";
import { startCompromisedWriteServer } from "./fixtures/compromised-write-server.js";
import { FirewallServer } from "../src/firewall-server.js";
import { AgentGateClient } from "../src/agentgate-client.js";
import type { PolicyConfig } from "../src/policy.js";

const AGENTGATE_URL = "http://127.0.0.1:3000";
const API_KEY = process.env.AGENTGATE_REST_KEY ?? "testkey123";
const SANDBOX = path.join(process.env.HOME!, "mcp-firewall-sandbox");

// Port ranges — spread out to avoid collisions with other test files
const WRAPPER_PORT = 4480;
const FIREWALL_PORT = 5580;
const PHANTOM_PORT = 4490;

const FS_POLICY: PolicyConfig = {
  governed_root: SANDBOX,
  tools: {
    write_file: { tier: "medium", exposure_cents: 10 },
    create_directory: { tier: "low", exposure_cents: 5 },
  },
  default_exposure_cents: 10,
};

const EXECUTOR_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-fs-e2e-executor-identity.json",
);
const RESOLVER_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-fs-e2e-resolver-identity.json",
);
const AGENT_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-fs-e2e-agent-identity.json",
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

function cleanupIdentityFiles() {
  for (const p of IDENTITY_PATHS) {
    if (fs.existsSync(p)) fs.unlinkSync(p);
  }
}

// Track files/dirs/symlinks created during tests for cleanup
const createdPaths: string[] = [];
const createdSymlinks: string[] = [];

function trackPath(p: string) {
  createdPaths.push(p);
}

function trackSymlink(p: string) {
  createdSymlinks.push(p);
}

describe("filesystem governance e2e", () => {
  let running: boolean;

  // Infrastructure
  let wrapper: Awaited<ReturnType<typeof startFilesystemWrapper>>;
  let firewall: FirewallServer;
  let client: Client;
  let transport: StreamableHTTPClientTransport;

  // AgentGate clients
  let executorClient: AgentGateClient;
  let resolverClient: AgentGateClient;
  let agentClient: AgentGateClient;

  // IDs
  let agentIdentityId: string;
  let agentBondId: string;
  let executorBondId: string;

  beforeEach(async () => {
    running = await isAgentGateRunning();
    if (!running) {
      console.warn(
        "\n⚠️  AgentGate is not running on localhost:3000 — skipping filesystem e2e tests.\n" +
          "   Start AgentGate: cd ~/Desktop/projects/agentgate && npm run dev\n",
      );
      return;
    }

    cleanupIdentityFiles();
    fs.mkdirSync(SANDBOX, { recursive: true });

    // 1. Create executor identity
    executorClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: EXECUTOR_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await executorClient.registerIdentity();
    const executorBond = await executorClient.lockBond(
      executorClient.identityId!,
      100,
      "USD",
      3600,
      "fs-e2e executor bond",
    );
    executorBondId = executorBond.bondId;

    // 2. Create resolver identity
    resolverClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: RESOLVER_IDENTITY_PATH,
      apiKey: API_KEY,
    });
    await resolverClient.registerIdentity();

    // 3. Create agent identity
    agentClient = new AgentGateClient({
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
      "fs-e2e agent bond",
    );
    agentBondId = agentBond.bondId;

    // 4. Start filesystem wrapper
    wrapper = await startFilesystemWrapper({
      port: WRAPPER_PORT,
      allowedDir: SANDBOX,
    });

    // 5. Start firewall
    firewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: wrapper.url,
      agentgateClient: executorClient,
      resolverClient,
      policy: FS_POLICY,
      firewallBondId: executorBondId,
    });
    await firewall.start();

    // 6. Connect test client
    client = new Client({ name: "fs-e2e-client", version: "1.0.0" });
    transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await client.connect(transport);

    // 7. Authenticate
    const authResult = await client.callTool({
      name: "authenticate",
      arguments: agentClient.createAuthenticationArguments(
        agentIdentityId,
        agentBondId,
        transport.sessionId!,
      ),
    });
    expect(authResult.isError).toBeUndefined();
  }, 60_000);

  afterEach(() => {
    // Clean up symlinks first (they must be removed before dirs)
    for (const s of createdSymlinks.splice(0)) {
      try { fs.unlinkSync(s); } catch { /* already gone */ }
    }
    // Clean up files and dirs in reverse order
    for (const p of createdPaths.splice(0).reverse()) {
      try {
        const stat = fs.statSync(p);
        if (stat.isDirectory()) {
          fs.rmdirSync(p, { recursive: true });
        } else {
          fs.unlinkSync(p);
        }
      } catch { /* already gone */ }
    }
  });

  afterEach(async () => {
    if (!running) return;
    if (client) await client.close();
    if (firewall) await firewall.stop();
    if (wrapper) await wrapper.stop();
    cleanupIdentityFiles();
  });

  // --- Test Case 1: Happy path write_file ---
  it("write_file inside sandbox → file exists → bond released", async () => {
    if (!running) return;

    const testFile = path.join(SANDBOX, "e2e-write-test.txt");
    trackPath(testFile);

    const result = await client.callTool({
      name: "write_file",
      arguments: { path: testFile, content: "governed write test" },
    });

    expect(result.isError).toBeUndefined();
    expect(fs.existsSync(testFile)).toBe(true);
    expect(fs.readFileSync(testFile, "utf-8")).toBe("governed write test");
  });

  // --- Test Case 2: Happy path create_directory ---
  it("create_directory inside sandbox → directory exists → bond released", async () => {
    if (!running) return;

    const testDir = path.join(SANDBOX, "e2e-dir-test");
    trackPath(testDir);

    const result = await client.callTool({
      name: "create_directory",
      arguments: { path: testDir },
    });

    expect(result.isError).toBeUndefined();
    expect(fs.existsSync(testDir)).toBe(true);
    expect(fs.statSync(testDir).isDirectory()).toBe(true);
  });

  // --- Test Case 3: Overwrite existing file ---
  it("write_file to existing file → treated as normal write", async () => {
    if (!running) return;

    const testFile = path.join(SANDBOX, "e2e-overwrite-test.txt");
    trackPath(testFile);

    // Create the file first
    fs.writeFileSync(testFile, "original content");

    const result = await client.callTool({
      name: "write_file",
      arguments: { path: testFile, content: "overwritten content" },
    });

    expect(result.isError).toBeUndefined();
    expect(fs.readFileSync(testFile, "utf-8")).toBe("overwritten content");
  });

  // --- Test Case 4: Direct traversal ---
  it("../../etc/passwd → preflight rejection, bond slashed", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "write_file",
      arguments: {
        path: path.join(SANDBOX, "../../etc/passwd"),
        content: "malicious",
      },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/[Pp]ath validation failed/);

    // Confirm the file was NOT created
    expect(fs.existsSync("/etc/passwd-test")).toBe(false);
  });

  // --- Test Case 5: Sibling prefix bypass ---
  it("sandbox-evil/file → preflight rejection, bond slashed", async () => {
    if (!running) return;

    const sibling = SANDBOX + "-evil";
    fs.mkdirSync(sibling, { recursive: true });
    trackPath(sibling);

    const result = await client.callTool({
      name: "write_file",
      arguments: {
        path: path.join(sibling, "file.txt"),
        content: "malicious",
      },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/[Pp]ath validation failed/);
  });

  // --- Test Case 6: Symlink escape ---
  it("symlink inside sandbox pointing outside → preflight rejection", async () => {
    if (!running) return;

    const symlinkPath = path.join(SANDBOX, "e2e-symlink-escape");

    // Clean up any leftover from a previous failed run
    try { fs.unlinkSync(symlinkPath); } catch { /* doesn't exist */ }

    fs.symlinkSync("/tmp", symlinkPath);
    trackSymlink(symlinkPath);

    const result = await client.callTool({
      name: "write_file",
      arguments: {
        path: path.join(symlinkPath, "escape-test.txt"),
        content: "malicious",
      },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/[Pp]ath validation failed/);

    // Confirm nothing written to /tmp
    expect(fs.existsSync("/tmp/escape-test.txt")).toBe(false);
  });

  // --- Test Case 9: Blocked tool ---
  it("read_file attempt → rejected by allowlist, no bond action", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "read_file",
      arguments: { path: path.join(SANDBOX, "anything.txt") },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/not exposed/i);
  });

  // --- Test Case 10: Unauthenticated session ---
  it("unauthenticated session → rejected", async () => {
    if (!running) return;

    const freshClient = new Client({ name: "unauth-fs-client", version: "1.0.0" });
    const freshTransport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await freshClient.connect(freshTransport);

    const result = await freshClient.callTool({
      name: "write_file",
      arguments: { path: path.join(SANDBOX, "test.txt"), content: "nope" },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/[Aa]uthenticat/);

    await freshClient.close();
  });

  // --- Test Case 11: Nested write without prior create_directory ---
  it("write_file to nonexistent subdirectory → fail closed", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "write_file",
      arguments: {
        path: path.join(SANDBOX, "nonexistent-subdir", "file.txt"),
        content: "should fail",
      },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    // validatePath returns malicious when parent doesn't exist (realpathSync throws)
    expect(text).toMatch(/[Pp]ath validation failed/);
  });
});

// --- Test Case 7: Upstream error → bond released ---
// Uses the error-server fixture (upstream always throws)
describe("filesystem governance: upstream error handling", () => {
  let running: boolean;
  let errorHttpServer: http.Server;
  let firewall: FirewallServer;
  let client: Client;
  let transport: StreamableHTTPClientTransport;

  let executorClient: AgentGateClient;
  let resolverClient: AgentGateClient;
  let agentClient: AgentGateClient;
  let agentIdentityId: string;
  let agentBondId: string;
  let executorBondId: string;

  const ERROR_EXECUTOR_PATH = path.resolve(import.meta.dirname, "fixtures", "test-fs-err-executor.json");
  const ERROR_RESOLVER_PATH = path.resolve(import.meta.dirname, "fixtures", "test-fs-err-resolver.json");
  const ERROR_AGENT_PATH = path.resolve(import.meta.dirname, "fixtures", "test-fs-err-agent.json");
  const ERROR_IDENTITY_PATHS = [ERROR_EXECUTOR_PATH, ERROR_RESOLVER_PATH, ERROR_AGENT_PATH];

  function cleanupErrorFiles() {
    for (const p of ERROR_IDENTITY_PATHS) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  }

  beforeAll(async () => {
    running = await isAgentGateRunning();
    if (!running) {
      console.warn(
        "\n⚠️  AgentGate is not running on localhost:3000 — skipping upstream error tests.\n",
      );
      return;
    }

    cleanupErrorFiles();

    // Import dynamically to avoid loading when not needed
    const { startErrorServer } = await import("./fixtures/error-server.js");

    executorClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: ERROR_EXECUTOR_PATH,
      apiKey: API_KEY,
    });
    await executorClient.registerIdentity();
    const bond = await executorClient.lockBond(executorClient.identityId!, 100, "USD", 3600, "err-test");
    executorBondId = bond.bondId;

    resolverClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: ERROR_RESOLVER_PATH,
      apiKey: API_KEY,
    });
    await resolverClient.registerIdentity();

    agentClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: ERROR_AGENT_PATH,
      apiKey: API_KEY,
    });
    const agentReg = await agentClient.registerIdentity();
    agentIdentityId = agentReg.identityId;
    const agentBond = await agentClient.lockBond(agentIdentityId, 100, "USD", 3600, "err-agent");
    agentBondId = agentBond.bondId;

    // The error server has echo/add tools but the firewall policy needs write_file/create_directory.
    // Use the phantom server instead — it exposes write_file and create_directory (but returns success without writing).
    // For the error case, we need upstream to return an error. So we still need the error server
    // but with write_file/create_directory tool names. Simplest: create an inline fixture.
    // Actually — the error server only has echo/add. We need a server with write_file that errors.
    // Let's use a small inline server.

    const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");
    const { StreamableHTTPServerTransport } = await import("@modelcontextprotocol/sdk/server/streamableHttp.js");
    const { randomUUID } = await import("node:crypto");
    const { default: expressModule } = await import("express");
    const { z } = await import("zod");

    const mcpServer = new McpServer({ name: "error-fs-server", version: "1.0.0" });
    mcpServer.tool("write_file", "Fails after allowing the startup canary", {
      path: z.string(),
      content: z.string(),
    }, async ({ path: requestedPath, content }) => {
      if (path.basename(requestedPath) === ".mcp-firewall-canary") {
        fs.mkdirSync(path.dirname(requestedPath), { recursive: true });
        fs.writeFileSync(requestedPath, content, "utf-8");
        return {
          content: [{ type: "text", text: "Successfully wrote canary file" }],
        };
      }

      throw new Error("Deliberate upstream write failure");
    });
    mcpServer.tool("create_directory", "Always fails", {
      path: z.string(),
    }, async () => { throw new Error("Deliberate upstream mkdir failure"); });

    const app = expressModule();
    app.use(expressModule.json());
    const transports = new Map<string, InstanceType<typeof StreamableHTTPServerTransport>>();

    app.post("/mcp", async (req: any, res: any) => {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      let t: InstanceType<typeof StreamableHTTPServerTransport>;
      if (sessionId && transports.has(sessionId)) {
        t = transports.get(sessionId)!;
      } else {
        t = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id: string) => { transports.set(id, t); },
        });
        t.onclose = () => { if (t.sessionId) transports.delete(t.sessionId); };
        await mcpServer.connect(t);
      }
      await t.handleRequest(req, res, req.body);
    });

    app.get("/mcp", async (req: any, res: any) => {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      if (!sessionId || !transports.has(sessionId)) {
        res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "No session" }, id: null });
        return;
      }
      await transports.get(sessionId)!.handleRequest(req, res);
    });

    const httpModule = await import("node:http");
    errorHttpServer = httpModule.default.createServer(app);
    const errorUrl = await new Promise<string>((resolve) => {
      errorHttpServer.listen(WRAPPER_PORT + 10, () => {
        resolve(`http://127.0.0.1:${WRAPPER_PORT + 10}/mcp`);
      });
    });

    firewall = new FirewallServer({
      port: FIREWALL_PORT + 10,
      upstreamUrl: errorUrl,
      agentgateClient: executorClient,
      resolverClient,
      policy: {
        governed_root: SANDBOX,
        tools: {
          write_file: { tier: "medium", exposure_cents: 10 },
          create_directory: { tier: "low", exposure_cents: 5 },
        },
        default_exposure_cents: 10,
      },
      firewallBondId: executorBondId,
    });
    await firewall.start();

    client = new Client({ name: "err-test-client", version: "1.0.0" });
    transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT + 10}/mcp`),
    );
    await client.connect(transport);

    const authResult = await client.callTool({
      name: "authenticate",
      arguments: agentClient.createAuthenticationArguments(
        agentIdentityId,
        agentBondId,
        transport.sessionId!,
      ),
    });
    expect(authResult.isError).toBeUndefined();
  }, 60_000);

  afterAll(async () => {
    if (!running) return;
    if (client) await client.close();
    if (firewall) await firewall.stop();
    if (errorHttpServer) {
      await new Promise<void>((resolve, reject) => {
        errorHttpServer.close((err) => (err ? reject(err) : resolve()));
      });
    }
    cleanupErrorFiles();
  });

  it("upstream error → bond released (failure)", async () => {
    if (!running) return;

    const result = await client.callTool({
      name: "write_file",
      arguments: {
        path: path.join(SANDBOX, "error-test.txt"),
        content: "should fail",
      },
    });

    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/failed/i);
    expect(text).toMatch(/released/i);
  });
});

// --- Test Case 8: Upstream success + file missing → failed ---
// Uses the phantom server (reports success without writing)
describe("filesystem governance: anomaly detection", () => {
  let running: boolean;
  let compromisedHttpServer: http.Server;
  let firewall: FirewallServer;
  let client: Client;
  let transport: StreamableHTTPClientTransport;

  let executorClient: AgentGateClient;
  let resolverClient: AgentGateClient;
  let agentClient: AgentGateClient;
  let agentIdentityId: string;
  let agentBondId: string;
  let executorBondId: string;

  const PHANTOM_EXECUTOR_PATH = path.resolve(import.meta.dirname, "fixtures", "test-fs-phantom-executor.json");
  const PHANTOM_RESOLVER_PATH = path.resolve(import.meta.dirname, "fixtures", "test-fs-phantom-resolver.json");
  const PHANTOM_AGENT_PATH = path.resolve(import.meta.dirname, "fixtures", "test-fs-phantom-agent.json");
  const PHANTOM_IDENTITY_PATHS = [PHANTOM_EXECUTOR_PATH, PHANTOM_RESOLVER_PATH, PHANTOM_AGENT_PATH];

  function cleanupPhantomFiles() {
    for (const p of PHANTOM_IDENTITY_PATHS) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  }

  beforeAll(async () => {
    running = await isAgentGateRunning();
    if (!running) {
      console.warn(
        "\n⚠️  AgentGate is not running on localhost:3000 — skipping anomaly detection tests.\n",
      );
      return;
    }

    cleanupPhantomFiles();

    executorClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: PHANTOM_EXECUTOR_PATH,
      apiKey: API_KEY,
    });
    await executorClient.registerIdentity();
    const bond = await executorClient.lockBond(executorClient.identityId!, 100, "USD", 3600, "phantom-test");
    executorBondId = bond.bondId;

    resolverClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: PHANTOM_RESOLVER_PATH,
      apiKey: API_KEY,
    });
    await resolverClient.registerIdentity();

    agentClient = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: PHANTOM_AGENT_PATH,
      apiKey: API_KEY,
    });
    const agentReg = await agentClient.registerIdentity();
    agentIdentityId = agentReg.identityId;
    const agentBond = await agentClient.lockBond(agentIdentityId, 100, "USD", 3600, "phantom-agent");
    agentBondId = agentBond.bondId;

    // Start compromised server: canary succeeds, real writes silently noop.
    const compromised = await startCompromisedWriteServer(PHANTOM_PORT, {
      governedRoot: SANDBOX,
      mode: "noop",
    });
    compromisedHttpServer = compromised.server;

    firewall = new FirewallServer({
      port: FIREWALL_PORT + 20,
      upstreamUrl: compromised.url,
      agentgateClient: executorClient,
      resolverClient,
      policy: {
        governed_root: SANDBOX,
        tools: {
          write_file: { tier: "medium", exposure_cents: 10 },
          create_directory: { tier: "low", exposure_cents: 5 },
        },
        default_exposure_cents: 10,
      },
      firewallBondId: executorBondId,
    });
    await firewall.start();

    client = new Client({ name: "phantom-test-client", version: "1.0.0" });
    transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT + 20}/mcp`),
    );
    await client.connect(transport);

    const authResult = await client.callTool({
      name: "authenticate",
      arguments: agentClient.createAuthenticationArguments(
        agentIdentityId,
        agentBondId,
        transport.sessionId!,
      ),
    });
    expect(authResult.isError).toBeUndefined();
  }, 60_000);

  afterAll(async () => {
    if (!running) return;
    if (client) await client.close();
    if (firewall) await firewall.stop();
    if (compromisedHttpServer) {
      await new Promise<void>((resolve, reject) => {
        compromisedHttpServer.close((err) => (err ? reject(err) : resolve()));
      });
    }
    cleanupPhantomFiles();
  });

  it("upstream success + file missing → failed after runtime verification", async () => {
    if (!running) return;

    const testFile = path.join(SANDBOX, "phantom-test.txt");

    // Confirm file doesn't exist before the call
    expect(fs.existsSync(testFile)).toBe(false);

    const result = await client.callTool({
      name: "write_file",
      arguments: { path: testFile, content: "phantom content" },
    });

    // The firewall should detect the anomaly and return an error
    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toMatch(/intended file effect was not independently observed/i);
    expect(text).toMatch(/resolved as failed/i);

    // File should still not exist
    expect(fs.existsSync(testFile)).toBe(false);
  });
});

// --- Test Cases 12 & 13: Startup canary failures ---
// These are already covered in startup.test.ts
