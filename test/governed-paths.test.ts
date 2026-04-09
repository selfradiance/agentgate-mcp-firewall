import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startFilesystemWrapper } from "./fixtures/filesystem-server-wrapper.js";
import { FirewallServer } from "../src/firewall-server.js";

const WRAPPER_PORT = 4470;
const FIREWALL_PORT = 5572;

function getText(result: { content?: Array<{ type: string; text?: string }> }): string {
  return result.content?.[0]?.type === "text" ? (result.content[0].text ?? "") : "";
}

describe("governed path validation", () => {
  let tempRoot: string;
  let allowedRoot: string;
  let governedRoot: string;
  let outsideRoot: string;
  let wrapper: Awaited<ReturnType<typeof startFilesystemWrapper>>;
  let firewall: FirewallServer;
  let client: Client;

  beforeAll(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-governed-"));
    allowedRoot = path.join(tempRoot, "allowed");
    governedRoot = path.join(allowedRoot, "governed");
    outsideRoot = path.join(allowedRoot, "outside");

    fs.mkdirSync(governedRoot, { recursive: true });
    fs.mkdirSync(outsideRoot, { recursive: true });

    wrapper = await startFilesystemWrapper({
      port: WRAPPER_PORT,
      allowedDir: allowedRoot,
    });

    const fakeAgentGate = {
      async executeBondedAction() {
        return { actionId: "action_test" };
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
        return { actionId: "action_auth" };
      },
    };

    const fakeResolver = {
      async resolveAction() {
        return {
          actionId: "action_test",
          outcome: "success",
          refundCents: 0,
          burnedCents: 0,
          slashedCents: 0,
        };
      },
    };

    firewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: wrapper.url,
      agentgateClient: fakeAgentGate as any,
      resolverClient: fakeResolver as any,
      firewallBondId: "bond_test",
      policy: {
        governed_root: governedRoot,
        tools: {
          move_file: { tier: "medium", exposure_cents: 10 },
          read_multiple_files: { tier: "low", exposure_cents: 10 },
        },
        default_exposure_cents: 10,
      },
    });
    await firewall.start();

    client = new Client({ name: "governed-path-test", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${FIREWALL_PORT}/mcp`),
    );
    await client.connect(transport);

    (firewall as any).sessionAuth.set(transport.sessionId, {
      identityId: "id_test",
      bondId: "bond_test",
      authenticatedAt: Date.now(),
    });
  }, 30_000);

  afterEach(() => {
    fs.rmSync(governedRoot, { recursive: true, force: true });
    fs.rmSync(outsideRoot, { recursive: true, force: true });
    fs.mkdirSync(governedRoot, { recursive: true });
    fs.mkdirSync(outsideRoot, { recursive: true });
  });

  afterAll(async () => {
    await client?.close();
    await firewall?.stop();
    await wrapper?.stop();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it("blocks move_file when source is outside governed_root", async () => {
    const source = path.join(fs.realpathSync(outsideRoot), "outside.txt");
    const destination = path.join(fs.realpathSync(governedRoot), "moved.txt");

    fs.writeFileSync(source, "outside content");

    const result = await client.callTool({
      name: "move_file",
      arguments: { source, destination },
    });

    expect(result.isError).toBe(true);
    expect(getText(result)).toMatch(/[Pp]ath validation failed/);
    expect(fs.existsSync(source)).toBe(true);
    expect(fs.existsSync(destination)).toBe(false);
  });

  it("blocks move_file when destination is outside governed_root", async () => {
    const source = path.join(fs.realpathSync(governedRoot), "inside.txt");
    const destination = path.join(fs.realpathSync(outsideRoot), "moved.txt");

    fs.writeFileSync(source, "inside content");

    const result = await client.callTool({
      name: "move_file",
      arguments: { source, destination },
    });

    expect(result.isError).toBe(true);
    expect(getText(result)).toMatch(/[Pp]ath validation failed/);
    expect(fs.existsSync(source)).toBe(true);
    expect(fs.existsSync(destination)).toBe(false);
  });

  it("blocks read_multiple_files when any requested path is outside governed_root", async () => {
    const inside = path.join(fs.realpathSync(governedRoot), "inside.txt");
    const outside = path.join(fs.realpathSync(outsideRoot), "outside.txt");

    fs.writeFileSync(inside, "inside content");
    fs.writeFileSync(outside, "outside content");

    const result = await client.callTool({
      name: "read_multiple_files",
      arguments: { paths: [inside, outside] },
    });

    expect(result.isError).toBe(true);
    expect(getText(result)).toMatch(/[Pp]ath validation failed/);
    expect(getText(result)).not.toContain("outside content");
  });
});
