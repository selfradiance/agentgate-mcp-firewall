import "dotenv/config";
import { createHash } from "node:crypto";
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
const OUTCOME_LOG_PATH = path.join(DATA_DIR, "last-firewall-outcome.json");
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

interface DemoOutcomeAuditEntry {
  requestedToolCall: {
    name: string;
    arguments: unknown;
  };
  intendedEffect:
    | {
        type?: string;
        targetPath?: string;
        expectedContentBytes?: number;
        expectedContentSha256?: string;
      }
    | null;
  upstreamReported: {
    status: string;
    summary: string;
  };
  verification: {
    status: string;
    reasonCode: string;
    message: string;
    changedPaths?: string[];
    unexpectedPaths?: string[];
  };
  finalResolution: string;
  reasonCode: string;
  reason: string;
}

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

function sha256Utf8(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex");
}

function printDetail(label: string, value: string): void {
  console.log(`   ${label}: ${value}`);
}

function formatPaths(paths: string[] | undefined): string {
  if (!paths || paths.length === 0) {
    return "(none)";
  }

  return paths.join(", ");
}

function captureOutcomeAuditLogs() {
  const entries: DemoOutcomeAuditEntry[] = [];
  const originalConsoleLog = console.log.bind(console);

  console.log = (...args: unknown[]) => {
    const first = args[0];

    if (typeof first === "string" && first.startsWith("FIREWALL_OUTCOME ")) {
      const raw = first.slice("FIREWALL_OUTCOME ".length);

      try {
        entries.push(JSON.parse(raw) as DemoOutcomeAuditEntry);
      } catch {
        // Let the raw line through; the demo will fail later if it cannot parse evidence.
      }
    }

    originalConsoleLog(...args);
  };

  return {
    entries,
    restore() {
      console.log = originalConsoleLog;
    },
  };
}

async function ensureAgentGateRunning(): Promise<void> {
  let response: Response;

  try {
    response = await fetch(`${AGENTGATE_URL}/health`);
  } catch {
    throw new Error(
      `AgentGate is not reachable at ${AGENTGATE_URL}. ` +
      "Start it from your local agentgate checkout using the auth setup described in the README Flagship Demo section.",
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
  const outcomeAuditCapture = captureOutcomeAuditLogs();

  try {
    console.log("Flagship demo: AgentGate + MCP Firewall + governed write_file");
    console.log(`AgentGate: ${AGENTGATE_URL}`);
    console.log(`Sandbox: ${SANDBOX}`);
    console.log(`Target file: ${TARGET_PATH}`);
    console.log(`Audit log copy: ${OUTCOME_LOG_PATH}`);

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
    removeIfExists(OUTCOME_LOG_PATH);
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
    printDetail("executor", executorReg.identityId);
    printDetail("resolver", resolverReg.identityId);
    printDetail("agent", agentReg.identityId);

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
    printDetail("executor bond", executorBond.bondId);
    printDetail("agent bond", agentBond.bondId);

    console.log("\n3. Starting the filesystem wrapper...");
    wrapper = await startFilesystemWrapper({
      port: WRAPPER_PORT,
      allowedDir: SANDBOX,
    });
    printDetail("upstream", wrapper.url);

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
    printDetail("firewall", firewallUrl);

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

    printDetail("authentication", resultText(authResult));

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

    printDetail("upstream tool response", resultText(writeResult));

    if (!fs.existsSync(TARGET_PATH)) {
      throw new Error(`Expected demo file was not created at ${TARGET_PATH}.`);
    }

    const observed = fs.readFileSync(TARGET_PATH, "utf-8");
    if (observed !== TARGET_CONTENT) {
      throw new Error("The demo file exists, but its content did not match.");
    }

    const observedBytes = Buffer.byteLength(observed, "utf-8");
    const observedSha256 = sha256Utf8(observed);

    console.log("\n7. Verifying the observed file on disk...");
    printDetail("file exists", "yes");
    printDetail("bytes", String(observedBytes));
    printDetail("sha256", observedSha256);
    printDetail("content matches requested content", "yes");

    const writeOutcome = [...outcomeAuditCapture.entries]
      .reverse()
      .find((entry) => entry.requestedToolCall.name === "write_file");

    if (!writeOutcome) {
      throw new Error(
        "Expected a FIREWALL_OUTCOME entry for the governed write_file call, but none was captured.",
      );
    }

    if (writeOutcome.upstreamReported.status !== "success") {
      throw new Error(
        `Expected FIREWALL_OUTCOME upstream status to be success, got ${writeOutcome.upstreamReported.status}.`,
      );
    }

    if (writeOutcome.verification.status !== "verified") {
      throw new Error(
        `Expected FIREWALL_OUTCOME verification status to be verified, got ${writeOutcome.verification.status}.`,
      );
    }

    if (writeOutcome.finalResolution !== "success") {
      throw new Error(
        `Expected FIREWALL_OUTCOME finalResolution to be success, got ${writeOutcome.finalResolution}.`,
      );
    }

    const expectedSha256 = writeOutcome.intendedEffect?.expectedContentSha256;
    if (typeof expectedSha256 !== "string") {
      throw new Error(
        "FIREWALL_OUTCOME did not include the expected content hash for the governed write_file call.",
      );
    }

    const auditTargetPath = writeOutcome.intendedEffect?.targetPath;
    if (typeof auditTargetPath !== "string") {
      throw new Error(
        "FIREWALL_OUTCOME did not include the canonical target path for the governed write_file call.",
      );
    }

    const expectedAuditTargetPath = path.join(
      fs.realpathSync(path.dirname(TARGET_PATH)),
      path.basename(TARGET_PATH),
    );

    if (auditTargetPath !== expectedAuditTargetPath) {
      throw new Error(
        `FIREWALL_OUTCOME target path did not match the canonical target path. Expected ${expectedAuditTargetPath}, got ${auditTargetPath}.`,
      );
    }

    if (observedSha256 !== expectedSha256) {
      throw new Error(
        "Observed file hash did not match the expected hash recorded in FIREWALL_OUTCOME.",
      );
    }

    const changedPaths = writeOutcome.verification.changedPaths ?? [];
    const unexpectedPaths = writeOutcome.verification.unexpectedPaths ?? [];

    if (!changedPaths.includes(auditTargetPath)) {
      throw new Error(
        "FIREWALL_OUTCOME did not record the target path as part of the independently verified change set.",
      );
    }

    if (unexpectedPaths.length > 0) {
      throw new Error(
        `FIREWALL_OUTCOME reported unexpected governed-path changes: ${unexpectedPaths.join(", ")}`,
      );
    }

    fs.writeFileSync(OUTCOME_LOG_PATH, `${JSON.stringify(writeOutcome, null, 2)}\n`);

    console.log("\n8. Parsing FIREWALL_OUTCOME into demo evidence...");
    printDetail("upstream reported", writeOutcome.upstreamReported.status);
    printDetail("verification status", writeOutcome.verification.status);
    printDetail("final resolution", writeOutcome.finalResolution);
    printDetail("reason code", writeOutcome.reasonCode);
    printDetail("audit target path", auditTargetPath);
    printDetail("changed paths", formatPaths(changedPaths));
    printDetail("unexpected paths", formatPaths(unexpectedPaths));
    printDetail("audit expected sha256", expectedSha256);
    printDetail("saved audit JSON", OUTCOME_LOG_PATH);

    console.log("\nRESULT: SUCCESS");
    console.log(
      "The upstream reported success, but the firewall's decision was backed by an independent disk check of the governed target path.",
    );
    console.log(`Created file: ${TARGET_PATH}`);
    console.log(`Saved audit evidence: ${OUTCOME_LOG_PATH}`);
    console.log("Both files are left in place for inspection.");
  } finally {
    outcomeAuditCapture.restore();
  }
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
    console.error("\nRESULT: FAILURE");
    console.error(`Flagship demo failed: ${detail}`);
    console.error(
      "Recheck the README Flagship Demo auth guidance: either run AgentGate in local dev mode without a REST key, or export the same AGENTGATE_REST_KEY value before rerunning this demo.",
    );
    await shutdown();
    process.exit(1);
  })
  .then(async () => {
    await shutdown();
  });
