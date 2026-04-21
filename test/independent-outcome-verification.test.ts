import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { FirewallServer } from "../src/firewall-server.js";
import {
  FilesystemWriteFileVerifier,
  type WriteFileVerifier,
} from "../src/write-file-verifier.js";
import { startFilesystemWrapper } from "./fixtures/filesystem-server-wrapper.js";
import { startCompromisedWriteServer } from "./fixtures/compromised-write-server.js";
import { startDeleteFileServer } from "./fixtures/delete-file-server.js";

let nextPort = 4600;

function allocatePort(): number {
  const port = nextPort;
  nextPort += 1;
  return port;
}

function createFakeAgentGate() {
  let actionCounter = 0;

  return {
    async executeBondedAction() {
      actionCounter += 1;
      return { actionId: `action_${actionCounter}` };
    },
    async checkIdentity() {
      return {
        identityId: "id_test",
        publicKey: "public",
        reputation: {
          score: 0,
          stats: {
            locks: 0,
            actions: 0,
            successes: 0,
            failures: 0,
            malicious: 0,
          },
        },
      };
    },
    async reserveAuthenticationBond() {
      return { actionId: "auth_action" };
    },
  };
}

function createFakeResolver() {
  const calls: Array<{ actionId: string; resolution: string }> = [];

  return {
    calls,
    client: {
      async resolveAction(actionId: string, resolution: string) {
        calls.push({ actionId, resolution });
        return {
          actionId,
          outcome: resolution,
          refundCents: 0,
          burnedCents: 0,
          slashedCents: resolution === "malicious" ? 10 : 0,
        };
      },
    },
  };
}

async function createAuthenticatedClient(
  firewall: FirewallServer,
  firewallPort: number,
): Promise<Client> {
  const client = new Client({
    name: "independent-outcome-test-client",
    version: "1.0.0",
  });
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${firewallPort}/mcp`),
  );
  await client.connect(transport);

  (firewall as any).sessionAuth.set(transport.sessionId, {
    identityId: "id_test",
    bondId: "bond_test",
    authenticatedAt: Date.now(),
  });

  return client;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("independent write_file outcome verification", () => {
  it("resolves success only when the intended file effect is independently verified", async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v030-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);

    const wrapper = await startFilesystemWrapper({
      port: allocatePort(),
      allowedDir: governedRoot,
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: wrapper.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          write_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const targetPath = path.join(governedRoot, "verified.txt");
      const result = await client.callTool({
        name: "write_file",
        arguments: { path: targetPath, content: "verified-content" },
      });

      expect(result.isError).toBeUndefined();
      expect(fs.readFileSync(targetPath, "utf-8")).toBe("verified-content");
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "success" },
      ]);
    } finally {
      await client?.close();
      await firewall.stop();
      await wrapper.stop();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("treats upstream-reported success as failed when no file effect is observed and logs the basis", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v030-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);

    const compromised = await startCompromisedWriteServer(allocatePort(), {
      governedRoot,
      mode: "noop",
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: compromised.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          write_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const targetPath = path.join(governedRoot, "missing.txt");
      const result = await client.callTool({
        name: "write_file",
        arguments: { path: targetPath, content: "never-written" },
      });

      expect(result.isError).toBe(true);
      expect(fs.existsSync(targetPath)).toBe(false);
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "failed" },
      ]);

      const auditLine = logSpy.mock.calls
        .map((call) => call[0])
        .find(
          (value): value is string =>
            typeof value === "string" &&
            value.startsWith("FIREWALL_OUTCOME "),
        );

      expect(auditLine).toBeDefined();

      const audit = JSON.parse(auditLine!.slice("FIREWALL_OUTCOME ".length)) as {
        requestedToolCall: { name: string };
        upstreamReported: { status: string };
        verification: { reasonCode: string };
        finalResolution: string;
      };

      expect(audit.requestedToolCall.name).toBe("write_file");
      expect(audit.upstreamReported.status).toBe("success");
      expect(audit.verification.reasonCode).toBe("target_missing");
      expect(audit.finalResolution).toBe("failed");
    } finally {
      await client?.close();
      await firewall.stop();
      await new Promise<void>((resolve, reject) => {
        compromised.server.close((error) => (error ? reject(error) : resolve()));
      });
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("resolves malicious when the upstream reports success but writes the wrong governed path", async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v030-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);

    const wrongTargetPath = path.join(governedRoot, "rogue-output.txt");
    const compromised = await startCompromisedWriteServer(allocatePort(), {
      governedRoot,
      mode: "wrong_target",
      wrongTargetPath,
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: compromised.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          write_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const requestedPath = path.join(governedRoot, "expected.txt");
      const result = await client.callTool({
        name: "write_file",
        arguments: { path: requestedPath, content: "misdirected" },
      });

      expect(result.isError).toBe(true);
      expect(fs.existsSync(requestedPath)).toBe(false);
      expect(fs.readFileSync(wrongTargetPath, "utf-8")).toBe("misdirected");
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "malicious" },
      ]);
    } finally {
      await client?.close();
      await firewall.stop();
      await new Promise<void>((resolve, reject) => {
        compromised.server.close((error) => (error ? reject(error) : resolve()));
      });
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("fails closed when the verifier itself errors instead of trusting upstream success", async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v030-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);

    const wrapper = await startFilesystemWrapper({
      port: allocatePort(),
      allowedDir: governedRoot,
    });

    const baseVerifier = new FilesystemWriteFileVerifier();
    const throwingVerifier: WriteFileVerifier = {
      prepare(input) {
        return baseVerifier.prepare(input);
      },
      verify() {
        throw new Error("simulated verifier failure");
      },
    };

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: wrapper.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          write_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
      writeFileVerifier: throwingVerifier,
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const targetPath = path.join(governedRoot, "verifier-error.txt");
      const result = await client.callTool({
        name: "write_file",
        arguments: { path: targetPath, content: "written-but-unverified" },
      });

      expect(result.isError).toBe(true);
      expect(fs.readFileSync(targetPath, "utf-8")).toBe("written-but-unverified");
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "failed" },
      ]);
    } finally {
      await client?.close();
      await firewall.stop();
      await wrapper.stop();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });
});

describe("independent delete_file outcome verification", () => {
  it("resolves success only when the requested regular file is deleted with no other governed-path mutation", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v040-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);
    const targetPath = path.join(governedRoot, "delete-me.txt");
    fs.writeFileSync(targetPath, "delete me", "utf-8");

    const deleteServer = await startDeleteFileServer(allocatePort(), {
      governedRoot,
      mode: "honest",
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: deleteServer.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          delete_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const result = await client.callTool({
        name: "delete_file",
        arguments: { path: targetPath },
      });

      expect(result.isError).toBeUndefined();
      expect(fs.existsSync(targetPath)).toBe(false);
      expect(deleteServer.deleteCalls).toEqual([targetPath]);
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "success" },
      ]);

      const auditLine = logSpy.mock.calls
        .map((call) => call[0])
        .find(
          (value): value is string =>
            typeof value === "string" &&
            value.startsWith("FIREWALL_OUTCOME "),
        );

      expect(auditLine).toBeDefined();

      const audit = JSON.parse(auditLine!.slice("FIREWALL_OUTCOME ".length)) as {
        requestedToolCall: { name: string };
        upstreamReported: { status: string };
        verification: {
          reasonCode: string;
          changedPaths: string[];
          unexpectedPaths: string[];
        };
        finalResolution: string;
      };

      expect(audit.requestedToolCall.name).toBe("delete_file");
      expect(audit.upstreamReported.status).toBe("success");
      expect(audit.verification.reasonCode).toBe("verified_target_deleted");
      expect(audit.verification.changedPaths).toEqual([targetPath]);
      expect(audit.verification.unexpectedPaths).toEqual([]);
      expect(audit.finalResolution).toBe("success");
    } finally {
      await client?.close();
      await firewall.stop();
      await new Promise<void>((resolve, reject) => {
        deleteServer.server.close((error) => (error ? reject(error) : resolve()));
      });
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("fails before forwarding when the target is missing in pre-state", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v040-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);
    const targetPath = path.join(governedRoot, "missing.txt");

    const deleteServer = await startDeleteFileServer(allocatePort(), {
      governedRoot,
      mode: "honest",
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: deleteServer.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          delete_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const result = await client.callTool({
        name: "delete_file",
        arguments: { path: targetPath },
      });

      expect(result.isError).toBe(true);
      expect(deleteServer.deleteCalls).toEqual([]);
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "failed" },
      ]);

      const auditLine = logSpy.mock.calls
        .map((call) => call[0])
        .find(
          (value): value is string =>
            typeof value === "string" &&
            value.startsWith("FIREWALL_OUTCOME "),
        );

      expect(auditLine).toBeDefined();

      const audit = JSON.parse(auditLine!.slice("FIREWALL_OUTCOME ".length)) as {
        upstreamReported: { status: string };
        verification: { reasonCode: string };
        finalResolution: string;
      };

      expect(audit.upstreamReported.status).toBe("not_called");
      expect(audit.verification.reasonCode).toBe("target_missing_prestate");
      expect(audit.finalResolution).toBe("failed");
    } finally {
      await client?.close();
      await firewall.stop();
      await new Promise<void>((resolve, reject) => {
        deleteServer.server.close((error) => (error ? reject(error) : resolve()));
      });
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("fails before forwarding when the target exists but is not a regular file", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v040-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);
    const targetPath = path.join(governedRoot, "dir-target");
    fs.mkdirSync(targetPath);

    const deleteServer = await startDeleteFileServer(allocatePort(), {
      governedRoot,
      mode: "honest",
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: deleteServer.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          delete_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const result = await client.callTool({
        name: "delete_file",
        arguments: { path: targetPath },
      });

      expect(result.isError).toBe(true);
      expect(deleteServer.deleteCalls).toEqual([]);
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "failed" },
      ]);

      const auditLine = logSpy.mock.calls
        .map((call) => call[0])
        .find(
          (value): value is string =>
            typeof value === "string" &&
            value.startsWith("FIREWALL_OUTCOME "),
        );

      expect(auditLine).toBeDefined();

      const audit = JSON.parse(auditLine!.slice("FIREWALL_OUTCOME ".length)) as {
        upstreamReported: { status: string };
        verification: { reasonCode: string };
        finalResolution: string;
      };

      expect(audit.upstreamReported.status).toBe("not_called");
      expect(audit.verification.reasonCode).toBe("target_not_regular_file_prestate");
      expect(audit.finalResolution).toBe("failed");
    } finally {
      await client?.close();
      await firewall.stop();
      await new Promise<void>((resolve, reject) => {
        deleteServer.server.close((error) => (error ? reject(error) : resolve()));
      });
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("resolves failed when the upstream claims success but leaves the target unchanged", async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v040-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);
    const targetPath = path.join(governedRoot, "still-here.txt");
    fs.writeFileSync(targetPath, "still here", "utf-8");

    const deleteServer = await startDeleteFileServer(allocatePort(), {
      governedRoot,
      mode: "noop",
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: deleteServer.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          delete_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const result = await client.callTool({
        name: "delete_file",
        arguments: { path: targetPath },
      });

      expect(result.isError).toBe(true);
      expect(fs.readFileSync(targetPath, "utf-8")).toBe("still here");
      expect(deleteServer.deleteCalls).toEqual([targetPath]);
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "failed" },
      ]);
    } finally {
      await client?.close();
      await firewall.stop();
      await new Promise<void>((resolve, reject) => {
        deleteServer.server.close((error) => (error ? reject(error) : resolve()));
      });
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("resolves malicious when another governed path changes during the claimed delete", async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v040-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);
    const targetPath = path.join(governedRoot, "delete-me.txt");
    const roguePath = path.join(governedRoot, "rogue-delete-output.txt");
    fs.writeFileSync(targetPath, "delete me", "utf-8");

    const deleteServer = await startDeleteFileServer(allocatePort(), {
      governedRoot,
      mode: "extra_change",
      extraPath: roguePath,
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: deleteServer.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          delete_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const result = await client.callTool({
        name: "delete_file",
        arguments: { path: targetPath },
      });

      expect(result.isError).toBe(true);
      expect(fs.existsSync(targetPath)).toBe(false);
      expect(fs.readFileSync(roguePath, "utf-8")).toBe("unexpected governed mutation");
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "malicious" },
      ]);
    } finally {
      await client?.close();
      await firewall.stop();
      await new Promise<void>((resolve, reject) => {
        deleteServer.server.close((error) => (error ? reject(error) : resolve()));
      });
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it("resolves malicious when the target still exists but is mutated instead of deleted", async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-v040-"));
    const governedRootPath = path.join(tempRoot, "governed");
    fs.mkdirSync(governedRootPath, { recursive: true });
    const governedRoot = fs.realpathSync(governedRootPath);
    const targetPath = path.join(governedRoot, "mutated.txt");
    fs.writeFileSync(targetPath, "before", "utf-8");

    const deleteServer = await startDeleteFileServer(allocatePort(), {
      governedRoot,
      mode: "mutate_target",
      mutatedContent: "after",
    });

    const resolver = createFakeResolver();
    const firewallPort = allocatePort();
    const firewall = new FirewallServer({
      port: firewallPort,
      upstreamUrl: deleteServer.url,
      agentgateClient: createFakeAgentGate() as any,
      resolverClient: resolver.client as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          delete_file: { tier: "high", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });

    let client: Client | undefined;

    try {
      await firewall.start();
      client = await createAuthenticatedClient(firewall, firewallPort);

      const result = await client.callTool({
        name: "delete_file",
        arguments: { path: targetPath },
      });

      expect(result.isError).toBe(true);
      expect(fs.readFileSync(targetPath, "utf-8")).toBe("after");
      expect(deleteServer.deleteCalls).toEqual([targetPath]);
      expect(resolver.calls).toEqual([
        { actionId: "action_1", resolution: "malicious" },
      ]);
    } finally {
      await client?.close();
      await firewall.stop();
      await new Promise<void>((resolve, reject) => {
        deleteServer.server.close((error) => (error ? reject(error) : resolve()));
      });
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });
});
