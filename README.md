# MCP Firewall

An MCP governance proxy with AgentGate-backed accountability.

MCP Firewall v0.3.0 makes one narrow claim:

For `write_file` routed to one upstream filesystem-style MCP server, the firewall does not trust upstream-reported success alone. It independently verifies the postcondition on disk and resolves the action from the observed effect.

That means a compromised upstream can claim `"success"` and still be caught when:

- no file was actually written
- the wrong governed path was written
- the target path exists but does not contain the requested content

This release is intentionally small. It is a proof-of-concept for one independently checkable effect class, not a general proof against all compromised MCP behavior.

If you want the fastest proof path, jump to [First Run: Flagship Demo](#first-run-flagship-demo) and run `npm run demo:write-file`.

## Why This Exists

An MCP client normally has to trust the upstream MCP server's answer about whether a tool call succeeded. That is not a safe assumption for a governance proxy. If the upstream is compromised or dishonest, it can claim success without producing the intended effect, or it can produce a different effect than the one the client requested.

v0.3.0 proves that the firewall can govern one high-risk surface without trusting that self-report. The chosen surface is `write_file`, because it is easy to verify mechanically and easy to demonstrate honestly.

## v0.3.0 Scope

In scope for this release:

- one upstream MCP server
- one high-risk tool surface: `write_file`
- one deterministic verifier for filesystem write outcomes
- honest and dishonest upstream test scenarios
- structured outcome logging that records the basis for each governed decision

Not claimed in this release:

- generalized attestation
- anomaly scoring or reputation systems
- cryptographic proof of remote execution
- coverage for every filesystem tool
- protection against all possible upstream side effects

## What v0.3.0 Verifies

For governed `write_file` calls, the firewall records an intended effect and then verifies it after the upstream returns.

The intended effect is:

- the exact target path should exist as a regular file
- that file's content hash should match the requested content
- no other path inside `governed_root` should have changed during the call

The verifier works from the firewall's own filesystem view. It snapshots the governed tree before the upstream call, forwards the request, snapshots again after the upstream returns, and compares the observed effect with the intended one.

## Resolution Policy

v0.3.0 uses a simple deterministic mapping:

- verified intended effect present -> `success`
- claimed success but intended effect not observed -> `failed`
- claimed success with a policy-violating observed effect -> `malicious`

Concretely:

- target file missing after upstream success -> `failed`
- target file content mismatch -> `malicious`
- wrong governed path changed -> `malicious`
- verifier internal failure -> `failed`

The firewall returns the governed outcome and, when AgentGate is configured, resolves the bonded action with the same mapping.

## End-to-End Flow

1. The client sends `write_file` to the firewall.
2. The firewall verifies AgentGate identity and bond state as usual.
3. The firewall validates that the requested path stays inside `governed_root`.
4. The firewall records the bonded action.
5. The firewall snapshots the governed tree and records the intended effect.
6. The firewall forwards `write_file` to the upstream server.
7. The upstream returns success or failure.
8. The firewall independently verifies the postcondition on disk.
9. The firewall resolves the action from the observed effect, not from the upstream claim alone.

## Demo Scenarios

The repo now includes deterministic coverage for these three scenarios:

1. Honest upstream
   The upstream returns success, the exact file is written, verification passes, final resolution is `success`.
2. Lying upstream, no actual effect
   The upstream returns success, no file appears, verification fails, final resolution is `failed`.
3. Lying upstream, wrong or forbidden effect
   The upstream returns success, a different governed path is written, verification detects the unexpected change, final resolution is `malicious`.

There is also a focused failure-path test where the verifier itself throws. In that case the firewall still fails closed and does not treat upstream success as authoritative.

## Audit Trail

For each governed `write_file` decision, the firewall emits a structured `FIREWALL_OUTCOME` log entry with:

- requested tool call
- intended effect
- upstream reported status and summary
- independent verification result
- final resolution
- reason code and reason text

This is meant to make each decision inspectable without re-reading raw transport traffic.

## Architecture

```
MCP Client
   |
   | Streamable HTTP
   v
+------------------------+
|      MCP Firewall      |
| auth, bond gate,       |
| path validation,       |
| write_file verifier    |
+------------------------+
   |
   | Streamable HTTP
   v
+------------------------+
| Upstream MCP Server    |
| filesystem-style tool  |
| surface                |
+------------------------+
   |
   v
governed_root on disk
```

For the honest path in tests and local demos, the upstream is `@modelcontextprotocol/server-filesystem` behind the included HTTP wrapper.

## First Run: Flagship Demo

This is the default path for a newcomer. If you only run one thing in this repo, run this demo.

It is the shortest honest path through the real governed `write_file` flow. It reuses the same happy-path sequence already proven in the filesystem end-to-end test:

- start the filesystem wrapper
- start MCP Firewall with a `write_file`-only policy
- register executor, resolver, and client identities on AgentGate
- lock executor and client bonds
- authenticate the MCP session with a signed `authenticate` call
- call governed `write_file`
- verify the written file on disk while the firewall emits the real `FIREWALL_OUTCOME` audit log

One successful run gives you three inspectable artifacts in one session:

- the raw `FIREWALL_OUTCOME` line from the firewall process
- a parsed copy of that outcome entry saved to `./data/flagship-demo/last-firewall-outcome.json`
- the written file at `~/mcp-firewall-sandbox/flagship-demo-output.txt` by default

### Prerequisites

- Node.js 20+
- AgentGate running locally at `http://127.0.0.1:3000`
- `AGENTGATE_REST_KEY` exported only if your AgentGate instance requires a REST key

### Run it

Assumes you have local checkouts of both `agentgate` and `agentgate-mcp-firewall`; adjust the `cd` paths below to where you cloned them.

Terminal 1:

```bash
cd /path/to/agentgate
AGENTGATE_DEV_MODE=true npm run dev
```

Terminal 2:

```bash
cd /path/to/agentgate-mcp-firewall
npm install
npm run demo:write-file
```

If your AgentGate repo already has `AGENTGATE_REST_KEY` configured, export the same value in terminal 2 before running the demo:

```bash
export AGENTGATE_REST_KEY=your-key-here
npm run demo:write-file
```

`AGENTGATE_DEV_MODE=true` only skips REST auth when AgentGate starts without a REST key already configured. If you already run AgentGate with a valid REST key and do not need dev mode, plain `npm run dev` on the AgentGate repo also works.

If ports `4444` or `5555` are already in use:

```bash
DEMO_WRAPPER_PORT=4480 DEMO_FIREWALL_PORT=5580 npm run demo:write-file
```

The demo script:

- starts the filesystem wrapper internally, so you do not need a separate wrapper terminal
- starts the firewall internally, so you do not need a hand-written `policy.json`
- stores temporary demo identity files under `./data/flagship-demo/`
- saves the last governed `FIREWALL_OUTCOME` entry to `./data/flagship-demo/last-firewall-outcome.json`
- writes `~/mcp-firewall-sandbox/flagship-demo-output.txt` by default
- fails if the file on disk, the captured audit entry, or the final governed resolution do not agree
- leaves the written file in place so you can inspect it after the demo exits

### What you should see

- the firewall logs one real `FIREWALL_OUTCOME` line for the governed `write_file` call
- the demo prints a short evidence summary showing `upstreamReported.status: success`, `verification.status: verified`, and `finalResolution: success`
- the saved JSON audit copy at `./data/flagship-demo/last-firewall-outcome.json` matches that same governed call
- the target file exists on disk with the exact requested content
- the demo uses the real signed `authenticate` flow before calling `write_file`
- the important point is not just that the file exists; it is that the firewall resolved the action from the observed disk effect after the MCP call

## Manual Startup (Optional)

Use this only if you want to start the wrapper and firewall yourself. If you want one clean end-to-end demo, use the Flagship Demo above.

### Prerequisites

- Node.js 20+
- AgentGate running locally
- `AGENTGATE_REST_KEY` exported only if your AgentGate instance requires a REST key

### 1. Install dependencies

```bash
npm install
```

### 2. Start AgentGate

```bash
cd ~/Desktop/projects/agentgate && AGENTGATE_DEV_MODE=true npm run dev
```

### 3. Start the filesystem wrapper

The wrapper bridges the stdio-only filesystem server to Streamable HTTP so the firewall can connect to it.

```bash
npx tsx test/fixtures/filesystem-server-wrapper.ts 4444 ~/mcp-firewall-sandbox
```

### 4. Create a narrow `policy.json`

```json
{
  "governed_root": "/Users/yourname/mcp-firewall-sandbox",
  "tools": {
    "write_file": {
      "tier": "high",
      "exposure_cents": 50
    }
  },
  "default_exposure_cents": 100
}
```

Use an absolute path for `governed_root`.

### 5. Start the firewall

```bash
npm run dev
```

The firewall will:

- load the policy
- create/register executor and resolver identities on AgentGate
- lock a bond
- connect to the upstream
- filter exposed tools to the policy allowlist
- run a canary `write_file` probe to prove shared write access
- listen on port `5555`

### 6. Connect a real MCP client and call `write_file`

Use an existing directory inside `governed_root`, or create parent directories out of band first. The upstream filesystem server does not create missing parent directories automatically.

A real client call sequence is:

1. Connect to `http://127.0.0.1:5555/mcp`
2. Call `authenticate` with signed arguments from `AgentGateClient.createAuthenticationArguments(...)`
3. Call `write_file`

If you want a working example of that authenticated client flow, run:

```bash
npm run demo:write-file
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM_MCP_URL` | `http://127.0.0.1:4444/mcp` | Upstream MCP server URL |
| `FIREWALL_PORT` | `5555` | Firewall listen port |
| `FIREWALL_POLICY_PATH` | `./policy.json` | Policy config path |
| `FIREWALL_IDENTITY_PATH` | `./agent-identity-firewall.json` | Executor identity file |
| `RESOLVER_IDENTITY_PATH` | `./agent-identity-resolver.json` | Resolver identity file |
| `FIREWALL_BOND_CENTS` | `100` | Firewall bond amount in cents |
| `FIREWALL_BOND_TTL_SECONDS` | `3600` | Firewall bond TTL in seconds |
| `AGENTGATE_URL` | `http://127.0.0.1:3000` | AgentGate base URL |
| `AGENTGATE_REST_KEY` | unset | Optional REST key for AgentGate instances that are not running in open dev mode |

## Tests

Run the full suite with:

```bash
npm test
```

The v0.3.0 work adds focused tests for:

- honest `write_file` verification success
- upstream lies with no effect
- upstream lies with wrong-target write
- verifier failure path
- deterministic resolution mapping in the standalone verifier

Tests that require a local AgentGate instance still skip cleanly when AgentGate is not running.

## What v0.3.0 Still Does Not Solve

This section is deliberate. The repo should not claim more than the implementation proves.

- It verifies one surface only. The sharp v0.3.0 claim is about `write_file`, not every MCP tool.
- It verifies observable postconditions, not causality. If the target file already contained the requested content before the call, a dishonest no-op is indistinguishable from a real idempotent write.
- It watches `governed_root`, not the whole machine. A compromised upstream that writes outside the governed tree is out of scope for this verifier unless that behavior also produces an observable governed-tree violation.
- It assumes the firewall and upstream share the same filesystem view. If they do not share mounts, verification will fail or become meaningless.
- It assumes no unrelated concurrent writer is modifying `governed_root` during the governed call. Concurrent writes can create false malicious/failure signals because the verifier uses before/after snapshots.
- It is not a general attestation framework. There is no cryptographic proof that the upstream executed particular code, only an independent check of one observable effect class.
- It is still a localhost proof-of-concept. Production-grade isolation, supervision, and multi-tenant containment are out of scope here.

## Related Projects

- [AgentGate](https://github.com/selfradiance/agentgate) — bond-and-slash enforcement substrate
- [AgentGate Agents](https://github.com/selfradiance/agentgate-agents) — reference agent implementations
- [Delegation Identity Proof](https://github.com/selfradiance/delegation-identity-proof) — Ed25519 delegation demonstration
