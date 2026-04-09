# MCP Firewall

A governance proxy for MCP tool calls. The MCP Firewall sits between MCP clients (Claude Desktop, coding agents, browser agents) and MCP servers (tool providers), intercepting every tool call. Before forwarding a call, it verifies the calling agent has an active bond on AgentGate and reserves exposure proportional to the tool's risk tier. Bad outcomes get slashed.

## Why This Exists

MCP adoption is exploding. Agents can now call arbitrary tools — file systems, databases, APIs, browsers, code execution environments — through a standardized protocol. But there's no enforcement layer between "agent wants to call a tool" and "tool executes." The trust model is binary: either the tool is available or it isn't.

The MCP Firewall is the missing middle layer: the agent can call the tool, but it costs something if the outcome is bad.

## How It Relates to AgentGate

[AgentGate](https://github.com/selfradiance/agentgate) is the enforcement substrate. The firewall calls AgentGate's API to verify agent identity, check bond status, record actions (tool calls) against bonds, and resolve outcomes. The firewall is a client of AgentGate, not an extension — no changes to AgentGate core were needed.

This is the project that connects the AgentGate ecosystem to what the industry is actually deploying. Agents 001–006 and the Delegation Identity Proof demonstrate the model in controlled environments. The MCP Firewall demonstrates it on live MCP infrastructure.

## What It Does

The firewall is an MCP proxy. It connects to an upstream MCP server (currently the `@modelcontextprotocol/server-filesystem` server via an HTTP wrapper), discovers its tools, and re-exposes a policy-filtered subset to clients. Only tools listed in the policy are exposed — everything else is silently blocked.

Before any tool call is forwarded, the firewall:

1. **Authenticates the caller** — the agent must prove identity ownership via Ed25519 proof-of-possession, bound to the MCP session.
2. **Validates the path** — for filesystem tools, the requested path is validated against the governed workspace using `fs.realpathSync()` (defeats symlink escapes) and a separator-appended prefix check (defeats sibling prefix bypass). Both checks are required.
3. **Records a bonded action** on AgentGate with exposure proportional to the tool's risk tier.
4. **Forwards the call** to the upstream server.
5. **Verifies the outcome** — for write operations, the firewall checks that the expected artifact exists on disk after the upstream reports success. Upstream success + missing artifact is resolved as malicious (bond slashed).

## Architecture

```
MCP Client (agent)
      |
      | Streamable HTTP
      v
+------------------+
|   MCP Firewall   |  <- authentication, path validation, bond enforcement
|   (port 5555)    |
+------------------+
      |
      | Streamable HTTP
      v
+---------------------+
| Filesystem Wrapper  |  <- stdio-to-HTTP bridge (test fixture)
|   (port 4445)       |
+---------------------+
      |
      | stdio
      v
+---------------------+
| @modelcontextprotocol|
| /server-filesystem   |  <- actual filesystem operations
+---------------------+
      |
      v
  ~/mcp-firewall-sandbox/   <- governed workspace (0o700)
```

AgentGate runs separately on port 3000 and is called by the firewall for identity verification, bond management, and action recording/resolution.

## Quick Start

### Prerequisites

- Node.js 20+
- AgentGate running locally (`cd agentgate && npm run dev`)

### 1. Install dependencies

```bash
npm install
```

### 2. Start AgentGate

```bash
cd ~/Desktop/projects/agentgate && npm run dev
```

### 3. Start the filesystem wrapper

The wrapper bridges the filesystem server (stdio-only) to Streamable HTTP so the firewall can connect to it.

```bash
npx tsx test/fixtures/filesystem-server-wrapper.ts 4445 ~/mcp-firewall-sandbox
```

### 4. Create a policy file

Create `policy.json` in the project root:

```json
{
  "governed_root": "/Users/yourname/mcp-firewall-sandbox",
  "tools": {
    "write_file": {
      "tier": "medium",
      "exposure_cents": 50
    },
    "create_directory": {
      "tier": "low",
      "exposure_cents": 10
    }
  },
  "default_exposure_cents": 100
}
```

Set `governed_root` to the absolute path of your sandbox directory.

### 5. Start the firewall

```bash
npm run dev
```

The firewall will:
- Load the policy
- Register executor and resolver identities on AgentGate
- Lock a bond
- Connect to the upstream wrapper with exponential backoff
- Filter upstream tools to the policy allowlist
- Run a canary write probe to verify upstream write access
- Start listening on port 5555

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_MCP_URL` | `http://127.0.0.1:4444/mcp` | Upstream MCP server URL |
| `FIREWALL_PORT` | `5555` | Port the firewall listens on |
| `FIREWALL_POLICY_PATH` | `./policy.json` | Path to the policy config file |
| `FIREWALL_IDENTITY_PATH` | `./agent-identity-firewall.json` | Executor identity keypair file |
| `RESOLVER_IDENTITY_PATH` | `./agent-identity-resolver.json` | Resolver identity keypair file |
| `FIREWALL_BOND_CENTS` | `100` | Bond amount in cents |
| `FIREWALL_BOND_TTL_SECONDS` | `3600` | Bond TTL in seconds |
| `AGENTGATE_URL` | `http://127.0.0.1:3000` | AgentGate base URL |

## Behavioral Constraints

**You must create parent directories before writing nested files.** The upstream filesystem server does not create intermediate directories automatically. If you call `write_file` with path `~/mcp-firewall-sandbox/subdir/file.txt`, the call will fail unless `subdir` already exists. Call `create_directory` first.

## Known Limitations

These are intentional proof-of-concept tradeoffs, not bugs:

1. **Race condition between path validation and upstream execution.** The firewall validates the path, then forwards the call to the upstream server as two separate steps. A sufficiently fast filesystem change between validation and execution could theoretically alter what the path resolves to. Closing this gap would require atomic validate-and-execute, which the MCP protocol does not support.

2. **Shared filesystem assumption.** The post-call verification (`fs.existsSync` on the resolved path) assumes the firewall process and the upstream filesystem server see the same filesystem. If they run on different machines or in different containers with separate mounts, verification will always fail. This is by design for the single-machine POC.

3. **Same-user assumption.** The firewall secures `governed_root` with `0o700` (owner-only). This only provides isolation if the firewall and upstream run as the same OS user, which they do in the POC configuration. Multi-user or multi-tenant isolation would require OS-level sandboxing (containers, namespaces).

4. **Orphaned upstream on firewall crash.** If the firewall process crashes or is killed without graceful shutdown, the upstream filesystem wrapper continues running. The wrapper has no auth and will accept tool calls from anything that connects. In production, the wrapper would need its own lifecycle management or be supervised alongside the firewall.

5. **Path validation checks `args.path` only.** Tools that use different field names for file paths (e.g., `source`, `destination`) are not protected by the boundary check and must not be added to the policy allowlist without updating the validation logic in `firewall-server.ts`.

## Startup Verification

On startup, the firewall verifies it can write to the governed workspace via the upstream server. It sends a `write_file` call for a canary file (`.mcp-firewall-canary`) through the full MCP chain — firewall to wrapper to filesystem server to disk — then checks that the file actually appeared on disk, then deletes it. If the canary write fails or the file doesn't appear, the firewall refuses to start. This proves functional write access through the entire proxy chain, not just that the upstream is reachable.

## Tests

71 tests across 14 files. Run with:

```bash
npm test
```

Integration tests that require AgentGate skip gracefully with a warning when AgentGate is not running on localhost:3000. Unit tests (path validation, policy loading, upstream client, startup sequence) run without any external dependencies.

## Scope / Non-Goals

v0.2.0 explicitly does not:

- **Evaluate file content.** The firewall checks where files are written, not what they contain. Content-based policies (e.g., "don't write credentials to disk") are out of scope.
- **Support multi-tenant isolation.** One firewall instance governs one workspace for one user. There is no tenant separation, namespace isolation, or per-agent workspace partitioning.
- **Target production deployment.** This is a proof-of-concept demonstrating that MCP tool calls can be economically governed via bond enforcement. It runs on localhost, uses a test fixture as the transport bridge, and assumes a trusted single-machine environment.
- **Implement content-addressed verification.** Post-call verification checks existence, not integrity. A future version could hash file contents and compare against expected outputs.

## Related Projects

- [AgentGate](https://github.com/selfradiance/agentgate) — the bond-and-slash enforcement substrate
- [AgentGate Agents](https://github.com/selfradiance/agentgate-agents) — reference agent implementations (001–006)
- [Delegation Identity Proof](https://github.com/selfradiance/delegation-identity-proof) — Ed25519 identity delegation demonstration
