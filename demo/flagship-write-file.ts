import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { AgentGateClient } from "../src/agentgate-client.js";
import { FirewallServer } from "../src/firewall-server.js";
import type { PolicyConfig } from "../src/policy.js";
import { startFilesystemWrapper } from "../test/fixtures/filesystem-server-wrapper.js";

const AGENTGATE_URL = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
const WRAPPER_PORT = Number(process.env.DEMO_WRAPPER_PORT ?? "4444");
const FIREWALL_PORT = Number(process.env.DEMO_FIREWALL_PORT ?? "5555");
const SANDBOX =
  process.env.DEMO_SANDBOX ??
  path.join(process.env.HOME!, "mcp-firewall-sandbox");
const DATA_DIR = path.resolve(process.cwd(), "data", "flagship-demo");
const TARGET_PATH = path.join(SANDBOX, "flagship-demo-output.txt");
const TARGET_CONTENT = [
  "AgentGate + MCP Firewall flagship demo",
  "governed write_file verified from observed disk state",
].join("\n");

const EXECUTOR_IDENTITY_PATH = path.join(DATA_DIR, "executor-identity.json");
const RESOLVER_IDENTITY_PATH = path.join(DATA_DIR, "resolver-identity.json");
const AGENT_IDENTITY_PATH = path.join(DATA_DIR, "agent-identity.json");

const FLAGSHIP_POLICY: PolicyConfig = {
  governed_root: SANDBOX,
  tools: {
    write_file: { tier: "medium", exposure_cents: 10 },
  },
  default_exposure_cents: 10,
};

type FilesystemWrapperHandle = Awaited<ReturnType<typeof startFilesystemWrapper>>;

let wrapper: FilesystemWrapperHandle | undefined;
let firewall: FirewallServer | undefined;
let client: Client | undefined;

function removeIfExists(filePath: string): void {
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
}

function resultText(result: unknown): string {
  if (
    typeof result !== "object" ||
    result === null ||
    !("content" in result) ||
    !Array.isArray(result.content) ||
    result.content.length === 0
  ) {
    return "(no text content)";
  }

  const first = result.content[0];
  if (
    typeof first === "object" &&
    first !== null &&
    "text" in first &&
    typeof first.text === "string"
  ) {
    return first.text;
  }

  return "(no text content)";
}

async function ensureAgentGateRunning(): Promise<void> {
  let response: Response;

  try {
    response = await fetch(`${AGENTGATE_URL}/health`);
  } catch {
    throw new Error(
      `AgentGate is not reachable at ${AGENTGATE_URL}. ` +
      "Start it in another terminal with: cd ~/Desktop/projects/agentgate && npm run dev",
    );
  }

  if (!response.ok) {
    throw new Error(
      `AgentGate health check failed at ${AGENTGATE_URL} with ${response.status} ${response.statusText}.`,
    );
  }
}

async function cleanup(): Promise<void> {
  if (client) {
    await client.close();
    client = undefined;
  }

  if (firewall) {
    await firewall.stop();
    firewall = undefined;
  }

  if (wrapper) {
    await wrapper.stop();
    wrapper = undefined;
  }
}

async function main(): Promise<void> {
  console.log("Flagship demo: AgentGate + MCP Firewall + governed write_file");
  console.log(`AgentGate: ${AGENTGATE_URL}`);
  console.log(`Sandbox: ${SANDBOX}`);
  console.log(`Target file: ${TARGET_PATH}`);

  if (process.env.AGENTGATE_REST_KEY) {
    console.log("Using AGENTGATE_REST_KEY from the environment.");
  } else {
    console.log(
      "AGENTGATE_REST_KEY is not set. This is fine if AgentGate is running in dev/open mode.",
    );
  }

  await ensureAgentGateRunning();

  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(SANDBOX, { recursive: true });
  removeIfExists(TARGET_PATH);
  removeIfExists(EXECUTOR_IDENTITY_PATH);
  removeIfExists(RESOLVER_IDENTITY_PATH);
  removeIfExists(AGENT_IDENTITY_PATH);

  const executorClient = new AgentGateClient({
    agentgateUrl: AGENTGATE_URL,
    identityPath: EXECUTOR_IDENTITY_PATH,
  });
  const resolverClient = new AgentGateClient({
    agentgateUrl: AGENTGATE_URL,
    identityPath: RESOLVER_IDENTITY_PATH,
  });
  const agentClient = new AgentGateClient({
    agentgateUrl: AGENTGATE_URL,
    identityPath: AGENT_IDENTITY_PATH,
  });

  console.log("\n1. Registering demo identities on AgentGate...");
  const executorReg = await executorClient.registerIdentity();
  const resolverReg = await resolverClient.registerIdentity();
  const agentReg = await agentClient.registerIdentity();
  console.log(`   executor: ${executorReg.identityId}`);
  console.log(`   resolver: ${resolverReg.identityId}`);
  console.log(`   agent:    ${agentReg.identityId}`);

  console.log("\n2. Locking executor and agent bonds...");
  const executorBond = await executorClient.lockBond(
    executorReg.identityId,
    100,
    "USD",
    3600,
    "flagship demo executor bond",
  );
  const agentBond = await agentClient.lockBond(
    agentReg.identityId,
    100,
    "USD",
    3600,
    "flagship demo agent bond",
  );
  console.log(`   executor bond: ${executorBond.bondId}`);
  console.log(`   agent bond:    ${agentBond.bondId}`);

  console.log("\n3. Starting the filesystem wrapper...");
  wrapper = await startFilesystemWrapper({
    port: WRAPPER_PORT,
    allowedDir: SANDBOX,
  });
  console.log(`   upstream: ${wrapper.url}`);

  console.log("\n4. Starting MCP Firewall with governed write_file only...");
  firewall = new FirewallServer({
    port: FIREWALL_PORT,
    upstreamUrl: wrapper.url,
    agentgateClient: executorClient,
    resolverClient,
    policy: FLAGSHIP_POLICY,
    firewallBondId: executorBond.bondId,
  });
  const { url: firewallUrl } = await firewall.start();
  console.log(`   firewall: ${firewallUrl}`);

  console.log(
    "\n5. Connecting a demo MCP client and authenticating the session...",
  );
  client = new Client({
    name: "flagship-write-file-demo",
    version: "1.0.0",
  });
  const transport = new StreamableHTTPClientTransport(new URL(firewallUrl));
  await client.connect(transport);

  if (!transport.sessionId) {
    throw new Error("MCP session ID missing after connect.");
  }

  const authResult = await client.callTool({
    name: "authenticate",
    arguments: {
      ...agentClient.createAuthenticationArguments(
        agentReg.identityId,
        agentBond.bondId,
        transport.sessionId,
      ),
    },
  });

  if (authResult.isError) {
    throw new Error(`Authentication failed: ${resultText(authResult)}`);
  }

  console.log(`   ${resultText(authResult)}`);

  console.log("\n6. Calling governed write_file through the firewall...");
  const writeResult = await client.callTool({
    name: "write_file",
    arguments: {
      path: TARGET_PATH,
      content: TARGET_CONTENT,
    },
  });

  if (writeResult.isError) {
    throw new Error(`write_file failed: ${resultText(writeResult)}`);
  }

  console.log(`   upstream tool response: ${resultText(writeResult)}`);

  if (!fs.existsSync(TARGET_PATH)) {
    throw new Error(`Expected demo file was not created at ${TARGET_PATH}.`);
  }

  const observed = fs.readFileSync(TARGET_PATH, "utf-8");
  if (observed !== TARGET_CONTENT) {
    throw new Error("The demo file exists, but its content did not match.");
  }

  console.log("\n7. Verifying the observed file on disk...");
  console.log(`   file exists: yes`);
  console.log(`   bytes: ${Buffer.byteLength(observed, "utf-8")}`);
  console.log(`   content matches requested content: yes`);

  console.log("\nDemo complete.");
  console.log(`Created file: ${TARGET_PATH}`);
  console.log(
    'Look above for the FIREWALL_OUTCOME log with "finalResolution":"success".',
  );
  console.log("The file is left in place for inspection.");
}

let shuttingDown = false;

async function shutdown(signal?: string): Promise<void> {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;

  if (signal) {
    console.log(`\n${signal} received - shutting down demo services...`);
  }

  try {
    await cleanup();
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.error(`Cleanup failed: ${detail}`);
  }
}

process.on("SIGINT", () => {
  void shutdown("SIGINT").finally(() => process.exit(0));
});
process.on("SIGTERM", () => {
  void shutdown("SIGTERM").finally(() => process.exit(0));
});

main()
  .catch(async (error) => {
    const detail = error instanceof Error ? error.message : String(error);
    console.error(`\nFlagship demo failed: ${detail}`);
    console.error(
      "If AgentGate is not in open dev mode, export AGENTGATE_REST_KEY or start AgentGate with AGENTGATE_DEV_MODE=true before rerunning.",
    );
    await shutdown();
    process.exit(1);
  })
  .then(async () => {
    await shutdown();
  });
