import "dotenv/config";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { AgentGateClient } from "../src/agentgate-client.js";
import { FirewallServer } from "../src/firewall-server.js";
import type { PolicyConfig } from "../src/policy.js";
import { startDeleteFileServer } from "../test/fixtures/delete-file-server.js";

const AGENTGATE_URL = process.env.AGENTGATE_URL ?? "http://127.0.0.1:3000";
const UPSTREAM_PORT = Number(process.env.DEMO_DELETE_UPSTREAM_PORT ?? "4448");
const FIREWALL_PORT = Number(process.env.DEMO_DELETE_FIREWALL_PORT ?? "5558");
const SANDBOX =
  process.env.DEMO_SANDBOX ??
  path.join(process.env.HOME!, "mcp-firewall-sandbox");
const DATA_DIR = path.resolve(process.cwd(), "data", "delete-file-demo");
const OUTCOME_LOG_PATH = path.join(DATA_DIR, "last-firewall-outcome.json");
const TARGET_PATH = path.join(SANDBOX, "flagship-delete-target.txt");
const TARGET_CONTENT = [
  "AgentGate + MCP Firewall delete proof demo",
  "governed delete_file verified from observed disk state",
].join("\n");

const EXECUTOR_IDENTITY_PATH = path.join(DATA_DIR, "executor-identity.json");
const RESOLVER_IDENTITY_PATH = path.join(DATA_DIR, "resolver-identity.json");
const AGENT_IDENTITY_PATH = path.join(DATA_DIR, "agent-identity.json");

const DELETE_POLICY: PolicyConfig = {
  governed_root: SANDBOX,
  tools: {
    delete_file: { tier: "medium", exposure_cents: 10 },
  },
  default_exposure_cents: 10,
};

interface DemoOutcomeAuditEntry {
  requestedToolCall: {
    name: string;
    arguments: unknown;
  };
  intendedEffect:
    | {
        type?: string;
        targetPath?: string;
        requiredPreState?: string;
        preStateObserved?: boolean;
        preStateTargetKind?: string;
        preStateTargetBytes?: number;
        preStateTargetSha256?: string;
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

type DeleteServerHandle = Awaited<ReturnType<typeof startDeleteFileServer>>;

let deleteServer: DeleteServerHandle | undefined;
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
      "Start it from your local agentgate checkout using the auth setup described in the README delete proof demo section.",
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

  if (deleteServer) {
    await new Promise<void>((resolve, reject) => {
      deleteServer!.server.close((error) => (error ? reject(error) : resolve()));
    });
    deleteServer = undefined;
  }
}

async function main(): Promise<void> {
  const outcomeAuditCapture = captureOutcomeAuditLogs();

  try {
    console.log("Delete proof demo: AgentGate + MCP Firewall + governed delete_file");
    console.log(`AgentGate: ${AGENTGATE_URL}`);
    console.log(`Sandbox: ${SANDBOX}`);
    console.log(`Target file: ${TARGET_PATH}`);
    console.log(`Audit log copy: ${OUTCOME_LOG_PATH}`);
    console.log(
      "Upstream surface: dedicated delete-file test fixture with a real named single-path delete_file tool.",
    );

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

    fs.writeFileSync(TARGET_PATH, TARGET_CONTENT, "utf-8");
    const preStateContent = fs.readFileSync(TARGET_PATH, "utf-8");
    const preStateBytes = Buffer.byteLength(preStateContent, "utf-8");
    const preStateSha256 = sha256Utf8(preStateContent);

    console.log("\n1. Recording the target's pre-state before the governed call...");
    printDetail("pre-state exists", "yes");
    printDetail("pre-state kind", "file");
    printDetail("pre-state bytes", String(preStateBytes));
    printDetail("pre-state sha256", preStateSha256);

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

    console.log("\n2. Registering demo identities on AgentGate...");
    const executorReg = await executorClient.registerIdentity();
    const resolverReg = await resolverClient.registerIdentity();
    const agentReg = await agentClient.registerIdentity();
    printDetail("executor", executorReg.identityId);
    printDetail("resolver", resolverReg.identityId);
    printDetail("agent", agentReg.identityId);

    console.log("\n3. Locking executor and agent bonds...");
    const executorBond = await executorClient.lockBond(
      executorReg.identityId,
      100,
      "USD",
      3600,
      "delete proof demo executor bond",
    );
    const agentBond = await agentClient.lockBond(
      agentReg.identityId,
      100,
      "USD",
      3600,
      "delete proof demo agent bond",
    );
    printDetail("executor bond", executorBond.bondId);
    printDetail("agent bond", agentBond.bondId);

    console.log("\n4. Starting the dedicated delete-capable upstream fixture...");
    deleteServer = await startDeleteFileServer(UPSTREAM_PORT, {
      governedRoot: SANDBOX,
      mode: "honest",
    });
    printDetail("upstream", deleteServer.url);

    console.log("\n5. Starting MCP Firewall with governed delete_file only...");
    firewall = new FirewallServer({
      port: FIREWALL_PORT,
      upstreamUrl: deleteServer.url,
      agentgateClient: executorClient,
      resolverClient,
      policy: DELETE_POLICY,
      firewallBondId: executorBond.bondId,
    });
    const { url: firewallUrl } = await firewall.start();
    printDetail("firewall", firewallUrl);

    console.log("\n6. Connecting a demo MCP client and authenticating the session...");
    client = new Client({
      name: "flagship-delete-file-demo",
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

    console.log("\n7. Calling governed delete_file through the firewall...");
    const deleteResult = await client.callTool({
      name: "delete_file",
      arguments: {
        path: TARGET_PATH,
      },
    });

    if (deleteResult.isError) {
      throw new Error(`delete_file failed: ${resultText(deleteResult)}`);
    }

    printDetail("upstream tool response", resultText(deleteResult));

    const targetExistsAfter = fs.existsSync(TARGET_PATH);
    if (targetExistsAfter) {
      throw new Error(`Expected demo target to be absent after delete at ${TARGET_PATH}.`);
    }

    console.log("\n8. Verifying the observed post-state on disk...");
    printDetail("target absent after call", "yes");

    const deleteOutcome = [...outcomeAuditCapture.entries]
      .reverse()
      .find((entry) => entry.requestedToolCall.name === "delete_file");

    if (!deleteOutcome) {
      throw new Error(
        "Expected a FIREWALL_OUTCOME entry for the governed delete_file call, but none was captured.",
      );
    }

    if (deleteOutcome.upstreamReported.status !== "success") {
      throw new Error(
        `Expected FIREWALL_OUTCOME upstream status to be success, got ${deleteOutcome.upstreamReported.status}.`,
      );
    }

    if (deleteOutcome.verification.status !== "verified") {
      throw new Error(
        `Expected FIREWALL_OUTCOME verification status to be verified, got ${deleteOutcome.verification.status}.`,
      );
    }

    if (deleteOutcome.finalResolution !== "success") {
      throw new Error(
        `Expected FIREWALL_OUTCOME finalResolution to be success, got ${deleteOutcome.finalResolution}.`,
      );
    }

    if (deleteOutcome.reasonCode !== "verified_target_deleted") {
      throw new Error(
        `Expected FIREWALL_OUTCOME reasonCode to be verified_target_deleted, got ${deleteOutcome.reasonCode}.`,
      );
    }

    if (deleteOutcome.intendedEffect?.preStateObserved !== true) {
      throw new Error(
        "FIREWALL_OUTCOME did not record that the target was observed in pre-state before forwarding.",
      );
    }

    if (deleteOutcome.intendedEffect?.preStateTargetKind !== "file") {
      throw new Error(
        "FIREWALL_OUTCOME did not record the target as a pre-state regular file.",
      );
    }

    if (deleteOutcome.intendedEffect?.preStateTargetSha256 !== preStateSha256) {
      throw new Error(
        "FIREWALL_OUTCOME did not record the expected pre-state sha256 for the delete target.",
      );
    }

    if (deleteOutcome.intendedEffect?.preStateTargetBytes !== preStateBytes) {
      throw new Error(
        "FIREWALL_OUTCOME did not record the expected pre-state byte count for the delete target.",
      );
    }

    const auditTargetPath = deleteOutcome.intendedEffect?.targetPath;
    if (typeof auditTargetPath !== "string") {
      throw new Error(
        "FIREWALL_OUTCOME did not include the canonical target path for the governed delete_file call.",
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

    const changedPaths = deleteOutcome.verification.changedPaths ?? [];
    const unexpectedPaths = deleteOutcome.verification.unexpectedPaths ?? [];

    if (changedPaths.length !== 1 || changedPaths[0] !== auditTargetPath) {
      throw new Error(
        `FIREWALL_OUTCOME did not record exactly one governed-path change for the delete target. Got: ${formatPaths(changedPaths)}`,
      );
    }

    if (unexpectedPaths.length > 0) {
      throw new Error(
        `FIREWALL_OUTCOME reported unexpected governed-path changes: ${unexpectedPaths.join(", ")}`,
      );
    }

    fs.writeFileSync(OUTCOME_LOG_PATH, `${JSON.stringify(deleteOutcome, null, 2)}\n`);

    console.log("\n9. Parsing FIREWALL_OUTCOME into demo evidence...");
    printDetail("upstream reported", deleteOutcome.upstreamReported.status);
    printDetail("verification status", deleteOutcome.verification.status);
    printDetail("final resolution", deleteOutcome.finalResolution);
    printDetail("reason code", deleteOutcome.reasonCode);
    printDetail("audit target path", auditTargetPath);
    printDetail("changed paths", formatPaths(changedPaths));
    printDetail("unexpected paths", formatPaths(unexpectedPaths));
    printDetail("audit pre-state sha256", String(deleteOutcome.intendedEffect?.preStateTargetSha256));
    printDetail("saved audit JSON", OUTCOME_LOG_PATH);

    console.log("\nRESULT: SUCCESS");
    console.log(
      "The upstream reported success, and the firewall resolved the action from the observed delete effect on the governed target path.",
    );
    console.log(
      "This proof uses the dedicated delete-capable fixture upstream in this repo, not @modelcontextprotocol/server-filesystem.",
    );
    console.log(`Deleted target: ${TARGET_PATH}`);
    console.log(`Saved audit evidence: ${OUTCOME_LOG_PATH}`);
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
    console.error(`Delete proof demo failed: ${detail}`);
    console.error(
      "Recheck the README delete proof demo guidance: the dedicated delete-capable fixture upstream is started by the script, but AgentGate must still be running locally.",
    );
    await shutdown();
    process.exit(1);
  })
  .then(async () => {
    await shutdown();
  });
