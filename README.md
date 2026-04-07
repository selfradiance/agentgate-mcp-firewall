# MCP Firewall

A governance proxy for the Model Context Protocol (MCP). The MCP Firewall sits between MCP clients (Claude Desktop, coding agents, browser agents) and MCP servers (tool providers), intercepting every tool call. Before forwarding a call, it verifies the calling agent has an active bond on [AgentGate](https://github.com/selfradiance/agentgate) and reserves exposure proportional to the tool's risk tier. If the upstream call fails, the exposure is released. If it succeeds, the action stays open for external resolution. This is AgentGate's bond-and-slash model applied to the real-world infrastructure AI agents are actually using.

## Architecture

```
+------------------+     +------------------+     +------------------+
|  MCP Client       |---->|  MCP Firewall     |---->|  MCP Server       |
|  (Claude Desktop, |     |  (Governance      |     |  (Tool Provider)  |
|   coding agent,   |<----|   Proxy)          |<----|                   |
|   browser agent)  |     |                   |     |                   |
+------------------+     +--------+----------+     +------------------+
                                  |
                                  | bond check
                                  | record action
                                  | resolve on failure
                                  |
                                  v
                         +------------------+
                         |  AgentGate        |
                         |  (Bond ledger,    |
                         |   identity,       |
                         |   resolution)     |
                         +------------------+
```

## How It Works

1. **Agent authenticates.** The agent calls the `authenticate` tool on the firewall with its AgentGate identity ID and bond ID. The firewall verifies the identity exists on AgentGate, confirms it has at least one active bond, and binds it to the MCP session. Re-authentication on the same session is rejected.

2. **Agent calls a tool.** The agent calls any upstream tool (e.g. `echo`, `write_file`, `query_db`) through the firewall as if it were calling the upstream server directly.

3. **Firewall checks session.** The firewall verifies the session is authenticated. Sessions have a configurable TTL (default 5 minutes) — expired sessions trigger an identity re-verification on AgentGate before proceeding.

4. **Firewall checks policy.** The firewall looks up the tool name in its policy config to determine the risk tier and required exposure in cents.

5. **Firewall reserves exposure on AgentGate.** The firewall calls `executeBondedAction` on AgentGate, reserving the exposure amount against the firewall's bond. The action payload records the tool name, upstream URL, arguments, timestamp, and tier.

6. **Firewall forwards to upstream.** If the bond reservation succeeds, the tool call is forwarded to the upstream MCP server.

7. **Result or rollback.** If the upstream call succeeds, the result is returned to the agent and the action stays open on AgentGate for external resolution. If it fails, the firewall resolves the action as "failed" on AgentGate via a separate resolver identity, releasing the bond exposure.

8. **External resolution.** A separate resolver identity can later resolve open actions as "success", "failed", or "malicious" — triggering refund, burn, or slash on AgentGate.

9. **Session cleanup.** Clients can send a DELETE request to `/mcp` with their session ID to terminate the session. The firewall cleans up session auth state and transport resources.

## Quick Start

### Prerequisites

- Node.js 20+
- [AgentGate](https://github.com/selfradiance/agentgate) running locally on port 3000

### Install

```bash
git clone https://github.com/selfradiance/agentgate-mcp-firewall.git
cd agentgate-mcp-firewall
npm install
```

### Create a Policy File

Create `policy.json` in the project root:

```json
{
  "tools": {
    "echo": {
      "tier": "low",
      "exposure_cents": 100
    },
    "write_file": {
      "tier": "high",
      "exposure_cents": 1000
    },
    "query_db": {
      "tier": "medium",
      "exposure_cents": 500
    }
  },
  "default_exposure_cents": 200
}
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_MCP_URL` | `http://127.0.0.1:4444/mcp` | Full URL of the upstream MCP server to proxy |
| `FIREWALL_PORT` | `5555` | Port the firewall listens on |
| `AGENTGATE_URL` | `http://127.0.0.1:3000` | AgentGate server URL |
| `AGENTGATE_REST_KEY` | (none) | API key for AgentGate (not needed in dev mode) |
| `FIREWALL_POLICY_PATH` | `./policy.json` | Path to the policy config file |
| `FIREWALL_IDENTITY_PATH` | `./agent-identity-firewall.json` | Path to the firewall's executor Ed25519 identity file |
| `RESOLVER_IDENTITY_PATH` | `./agent-identity-resolver.json` | Path to the resolver Ed25519 identity file |
| `FIREWALL_BOND_CENTS` | `100` | Bond amount in cents locked at startup |
| `FIREWALL_BOND_TTL_SECONDS` | `3600` | Bond TTL in seconds (default: 1 hour) |

### Run

```bash
npm run dev
```

The firewall will:
1. Load the policy config from `policy.json`
2. Generate Ed25519 identities on first run (executor + resolver) and register them with AgentGate
3. Lock a bond on AgentGate for the executor identity
4. Connect to the upstream MCP server, discover its tools
5. Start listening for MCP client connections

Shut down gracefully with Ctrl+C.

## Policy Config Reference

```json
{
  "tools": {
    "<tool-name>": {
      "tier": "<risk-tier-label>",
      "exposure_cents": <positive-integer>
    }
  },
  "default_exposure_cents": <positive-integer>
}
```

- **tool-name**: Must match the tool name exactly as exposed by the upstream MCP server.
- **tier**: A label for the risk category (e.g. "low", "medium", "high"). Recorded in the action payload on AgentGate for audit purposes.
- **exposure_cents**: The bond exposure reserved on AgentGate for each call to this tool. AgentGate applies a 1.2x risk multiplier on top of this value.
- **default_exposure_cents**: Fallback exposure for any tool not explicitly listed.

## Session Security

- **Authentication gating.** Upstream tools are blocked until the agent authenticates with a valid AgentGate identity and bond ID.
- **Session TTL.** Sessions expire after 5 minutes (configurable via `sessionTtlMs`). Expired sessions trigger identity re-verification on AgentGate. If re-verification fails, the session is cleared and the agent must re-authenticate.
- **Re-authentication prevention.** A session can only be authenticated once. Attempting to re-authenticate (even with the same identity) is rejected. This prevents identity rebinding mid-session.
- **Concurrent auth protection.** A synchronous pending marker prevents concurrent authenticate calls from racing past the duplicate check.
- **Session cleanup.** Clients can terminate sessions via DELETE `/mcp`. Transport and auth state are cleaned up.

## Outbound Resilience

- **AgentGate timeouts.** All requests to AgentGate (identity verification, bonded action recording, action resolution) have a 10-second timeout. If AgentGate is slow or unreachable, the firewall fails fast.
- **Upstream timeouts.** MCP operations against the upstream server (connect, tool discovery, tool calls) have a 30-second timeout.
- **Redirect rejection.** Signed requests to AgentGate reject HTTP redirects to prevent forwarding of sensitive headers.

## Known Limitations (v0.1.0)

- **Identifier-based auth.** The `authenticate` tool accepts an identity ID and bond ID. It does not require cryptographic proof-of-possession (the agent does not sign a challenge). A future version should require the agent to prove it holds the private key for the claimed identity.
- **Single upstream server.** The firewall connects to one upstream MCP server. Multi-upstream support is not yet implemented.
- **No automated outcome evaluation.** Actions stay open after successful tool calls. Resolution requires a separate resolver identity to manually or programmatically assess outcomes. There is no built-in evaluation of whether a tool call produced a "good" or "bad" result.
- **Tool-name-only policy.** The policy config maps exposure by tool name only. It does not consider tool arguments (e.g. a `write_file` call to a temp directory vs. a system config file would have the same exposure).
- **HTTP transport only.** The firewall uses Streamable HTTP. Stdio transport is not supported.
- **Tier 1 bond cap.** New identities on AgentGate start at Tier 1 with a 100-cent bond cap. The firewall's own bond is subject to this limit until the identity builds reputation.
- **Static tool discovery.** The upstream tool list is fetched once at startup and cached. If the upstream adds or removes tools at runtime, the firewall's list is stale until restart.

## Tech Stack

- **Language:** TypeScript
- **Runtime:** Node.js 20+
- **MCP SDK:** @modelcontextprotocol/sdk
- **Testing:** Vitest
- **HTTP framework:** Express (for the firewall's MCP transport)
- **Signing:** Node.js built-in crypto (Ed25519)
- **Config:** dotenv + JSON policy file

## Tests

```bash
# Run all tests
npm test

# Run a specific test file
npx vitest run test/policy.test.ts
```

Unit tests (policy, placeholder) run without external dependencies. Integration tests require AgentGate running locally on port 3000:

```bash
# Start AgentGate first
cd ~/Desktop/projects/agentgate && npm run dev

# Then run tests
cd ~/Desktop/projects/agentgate-mcp-firewall && npm test
```

Integration tests that require AgentGate will skip gracefully with a warning if it is not running.

**Note:** If AgentGate is not running in dev mode, integration tests require the `AGENTGATE_REST_KEY` environment variable to be set (e.g. `AGENTGATE_REST_KEY=testkey123 npm test`).

## License

MIT License. See [LICENSE](./LICENSE).
