/**
 * AgentGate Client Integration Tests
 *
 * IMPORTANT: These tests require a running AgentGate instance on localhost:3000.
 * Start AgentGate before running: cd ~/Desktop/projects/agentgate && npm run dev
 *
 * If AgentGate requires an API key (AGENTGATE_REST_KEY), set it in .env or
 * pass it via the AGENTGATE_REST_KEY environment variable.
 */

import path from "node:path";
import { unlinkSync, existsSync } from "node:fs";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AgentGateClient } from "../src/agentgate-client.js";

const AGENTGATE_URL = "http://127.0.0.1:3000";
const TEST_IDENTITY_PATH = path.resolve(
  import.meta.dirname,
  "fixtures",
  "test-firewall-identity.json",
);

// Check if AgentGate is running before attempting tests
async function isAgentGateRunning(): Promise<boolean> {
  try {
    const response = await fetch(`${AGENTGATE_URL}/health`);
    return response.ok;
  } catch {
    return false;
  }
}

describe("AgentGateClient", () => {
  let client: AgentGateClient;
  let running: boolean;

  beforeAll(async () => {
    running = await isAgentGateRunning();
    if (!running) {
      console.warn(
        "\n⚠️  AgentGate is not running on localhost:3000 — skipping integration tests.\n" +
          "   Start AgentGate: cd ~/Desktop/projects/agentgate && npm run dev\n",
      );
      return;
    }

    // Clean up any leftover identity file from previous test runs
    if (existsSync(TEST_IDENTITY_PATH)) {
      unlinkSync(TEST_IDENTITY_PATH);
    }

    client = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: TEST_IDENTITY_PATH,
      apiKey: process.env.AGENTGATE_REST_KEY ?? "testkey123",
    });
  });

  afterAll(() => {
    // Clean up test identity file
    if (existsSync(TEST_IDENTITY_PATH)) {
      unlinkSync(TEST_IDENTITY_PATH);
    }
  });

  it("should register the firewall identity on AgentGate", async () => {
    if (!running) return;

    const result = await client.registerIdentity();
    expect(result.identityId).toBeDefined();
    expect(result.identityId).toMatch(/^id_/);
    expect(client.identityId).toBe(result.identityId);
    expect(client.publicKey).toBeDefined();
  });

  it("should check the firewall identity and confirm it is valid", async () => {
    if (!running) return;

    const summary = await client.checkIdentity(client.identityId!);
    expect(summary.identityId).toBe(client.identityId);
    expect(summary.publicKey).toBe(client.publicKey);
    expect(summary.reputation).toBeDefined();
    expect(summary.reputation.score).toBeTypeOf("number");
    expect(summary.reputation.stats).toBeDefined();
  });

  it("should skip registration if identity already exists in file", async () => {
    if (!running) return;

    // Create a second client pointing at the same identity file
    const client2 = new AgentGateClient({
      agentgateUrl: AGENTGATE_URL,
      identityPath: TEST_IDENTITY_PATH,
      apiKey: process.env.AGENTGATE_REST_KEY ?? "testkey123",
    });

    const result = await client2.registerIdentity();
    // Should return the same identity ID without hitting AgentGate
    expect(result.identityId).toBe(client.identityId);
  });
});
