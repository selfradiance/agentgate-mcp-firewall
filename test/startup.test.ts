/**
 * Startup sequence tests for the firewall.
 *
 * Tests governed_root securing, upstream readiness with backoff,
 * and canary write probe.
 */

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { startFilesystemWrapper } from "./fixtures/filesystem-server-wrapper.js";
import { FirewallServer } from "../src/firewall-server.js";

const SANDBOX = path.join(process.env.HOME!, "mcp-firewall-sandbox");

describe("startup sequence", () => {
  it("should secure governed_root with 0o700 on startup", async () => {
    const testRoot = path.join(SANDBOX, "startup-test-root");

    // Ensure it doesn't exist beforehand
    if (fs.existsSync(testRoot)) {
      fs.rmdirSync(testRoot, { recursive: true });
    }

    // Use a wrapper so the canary write succeeds (testRoot is inside SANDBOX)
    const wrapper = await startFilesystemWrapper({
      port: 4460,
      allowedDir: SANDBOX,
    });

    try {
      const firewall = new FirewallServer({
        port: 5560,
        upstreamUrl: wrapper.url,
        agentgateClient: {} as any,
        resolverClient: {} as any,
        policy: {
          governed_root: testRoot,
          tools: {
            write_file: { tier: "medium", exposure_cents: 50 },
            create_directory: { tier: "low", exposure_cents: 10 },
          },
          default_exposure_cents: 100,
        },
        firewallBondId: "bond_test",
      });

      await firewall.start();
      await firewall.stop();
    } finally {
      await wrapper.stop();
    }

    expect(fs.existsSync(testRoot)).toBe(true);
    const stats = fs.statSync(testRoot);
    // 0o700 = owner rwx only
    expect(stats.mode & 0o777).toBe(0o700);

    // Clean up
    fs.rmdirSync(testRoot);
  }, 30_000);

  it("should pass canary write probe when upstream can write to governed_root", async () => {
    const wrapper = await startFilesystemWrapper({
      port: 4461,
      allowedDir: SANDBOX,
    });

    try {
      const firewall = new FirewallServer({
        port: 5561,
        upstreamUrl: wrapper.url,
        agentgateClient: {} as any,
        resolverClient: {} as any,
        policy: {
          governed_root: SANDBOX,
          tools: {
            write_file: { tier: "medium", exposure_cents: 50 },
            create_directory: { tier: "low", exposure_cents: 10 },
          },
          default_exposure_cents: 100,
        },
        firewallBondId: "bond_test",
      });

      await firewall.start();

      // Canary file should have been cleaned up
      expect(fs.existsSync(path.join(SANDBOX, ".mcp-firewall-canary"))).toBe(false);

      await firewall.stop();
    } finally {
      await wrapper.stop();
    }
  }, 30_000);

  it("should fail closed when canary write fails (governed_root not in upstream allowed dirs)", async () => {
    const wrongRoot = "/tmp/mcp-firewall-wrong-root";
    fs.mkdirSync(wrongRoot, { recursive: true, mode: 0o700 });

    const wrapper = await startFilesystemWrapper({
      port: 4462,
      allowedDir: SANDBOX,
    });

    try {
      const firewall = new FirewallServer({
        port: 5562,
        upstreamUrl: wrapper.url,
        agentgateClient: {} as any,
        resolverClient: {} as any,
        policy: {
          governed_root: wrongRoot,
          tools: {
            write_file: { tier: "medium", exposure_cents: 50 },
            create_directory: { tier: "low", exposure_cents: 10 },
          },
          default_exposure_cents: 100,
        },
        firewallBondId: "bond_test",
      });

      await expect(firewall.start()).rejects.toThrow(
        /Canary write probe failed/,
      );

      await firewall.stop();
    } finally {
      await wrapper.stop();
      fs.rmdirSync(wrongRoot);
    }
  }, 30_000);

  it("should fail closed when upstream is not reachable", async () => {
    const firewall = new FirewallServer({
      port: 5563,
      upstreamUrl: "http://127.0.0.1:19999/mcp", // nothing running here
      agentgateClient: {} as any,
      resolverClient: {} as any,
      policy: {
        governed_root: SANDBOX,
        tools: {
          write_file: { tier: "medium", exposure_cents: 50 },
          create_directory: { tier: "low", exposure_cents: 10 },
        },
        default_exposure_cents: 100,
      },
      firewallBondId: "bond_test",
    });

    await expect(firewall.start()).rejects.toThrow(
      /Upstream MCP server not reachable/,
    );

    await firewall.stop();
  }, 30_000);
});
