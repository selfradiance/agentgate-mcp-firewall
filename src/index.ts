/**
 * MCP Firewall Entry Point
 *
 * Loads configuration, creates AgentGate identities, locks a bond,
 * and starts the firewall proxy server. Handles graceful shutdown.
 */

import "dotenv/config";
import { loadPolicy } from "./policy.js";
import { AgentGateClient } from "./agentgate-client.js";
import { FirewallServer } from "./firewall-server.js";

const UPSTREAM_MCP_URL =
  process.env.UPSTREAM_MCP_URL ?? "http://127.0.0.1:4444/mcp";

const FIREWALL_PORT = Number(process.env.FIREWALL_PORT) || 5555;

const FIREWALL_IDENTITY_PATH =
  process.env.FIREWALL_IDENTITY_PATH ?? "./agent-identity-firewall.json";

const RESOLVER_IDENTITY_PATH =
  process.env.RESOLVER_IDENTITY_PATH ?? "./agent-identity-resolver.json";

/** Bond amount in cents the firewall locks on AgentGate at startup. */
const FIREWALL_BOND_CENTS = Number(process.env.FIREWALL_BOND_CENTS) || 100;

/** Bond TTL in seconds (default: 1 hour). */
const FIREWALL_BOND_TTL_SECONDS =
  Number(process.env.FIREWALL_BOND_TTL_SECONDS) || 3600;

async function main() {
  console.log("MCP Firewall starting...");

  // 1. Load policy config
  let policy;
  try {
    policy = loadPolicy();
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`Failed to load policy: ${msg}`);
    process.exit(1);
  }
  console.log(
    `Policy loaded: ${Object.keys(policy.tools).length} tool(s) configured, default exposure ${policy.default_exposure_cents} cents`,
  );

  // 2. Create and register the firewall's executor identity
  const executorClient = new AgentGateClient({
    identityPath: FIREWALL_IDENTITY_PATH,
  });
  try {
    const reg = await executorClient.registerIdentity();
    console.log(`Executor identity: ${reg.identityId}`);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`Failed to register executor identity: ${msg}`);
    process.exit(1);
  }

  // 3. Create and register the resolver identity (separate keypair)
  const resolverClient = new AgentGateClient({
    identityPath: RESOLVER_IDENTITY_PATH,
  });
  try {
    const reg = await resolverClient.registerIdentity();
    console.log(`Resolver identity: ${reg.identityId}`);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`Failed to register resolver identity: ${msg}`);
    process.exit(1);
  }

  // 4. Lock a bond for the firewall's executor identity
  let firewallBondId: string;
  try {
    const bond = await executorClient.lockBond(
      executorClient.identityId!,
      FIREWALL_BOND_CENTS,
      "USD",
      FIREWALL_BOND_TTL_SECONDS,
      "MCP Firewall execution bond",
    );
    firewallBondId = bond.bondId;
    console.log(
      `Bond locked: ${firewallBondId} (${FIREWALL_BOND_CENTS} cents, TTL ${FIREWALL_BOND_TTL_SECONDS}s)`,
    );
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`Failed to lock bond: ${msg}`);
    process.exit(1);
  }

  // 5. Create and start the firewall
  const firewall = new FirewallServer({
    port: FIREWALL_PORT,
    upstreamUrl: UPSTREAM_MCP_URL,
    agentgateClient: executorClient,
    resolverClient,
    policy,
    firewallBondId,
  });

  try {
    const { url } = await firewall.start();
    console.log(`MCP Firewall ready at ${url}`);
    console.log(`Proxying to upstream: ${UPSTREAM_MCP_URL}`);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`Failed to start firewall: ${msg}`);
    process.exit(1);
  }

  // 6. Graceful shutdown
  const shutdown = async (signal: string) => {
    console.log(`\n${signal} received — shutting down...`);
    try {
      await firewall.stop();
      console.log("Firewall stopped.");
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      console.error(`Error during shutdown: ${msg}`);
    }
    process.exit(0);
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((error) => {
  console.error("Unexpected error:", error);
  process.exit(1);
});
