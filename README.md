# MCP Firewall

MCP Firewall is a thin governance proxy that sits between MCP clients and upstream MCP servers. It requires governed/bonded authorization for protected tool calls before forwarding them upstream.

The current shipped proof is narrow: on two current filesystem proof surfaces, the firewall does not resolve from upstream-reported success alone. It independently verifies the filesystem effect it can observe on disk and resolves from that observed effect.

## Current Shipped Proof Surfaces

- governed `write_file` on one supported filesystem-style upstream surface
- governed single-path `delete_file` on one dedicated delete-capable upstream surface used in this repo's tests and delete proof demo

Both proof surfaces are intentionally small. They depend on:

- effects confined to `governed_root`
- a shared filesystem view between firewall and upstream
- deterministic postconditions the firewall can check directly

For the `delete_file` surface, the claim attaches only to the local [`delete-file-test-server`](test/fixtures/delete-file-server.ts) fixture. The pinned reference upstream `@modelcontextprotocol/server-filesystem` still does not expose a native named `delete_file` tool, so the `delete_file` proof does not attach to that upstream.

For these two shipped proof surfaces only, the firewall already performs governed-root before/after snapshot-diff verification in substance. The verifier is not limited to checking whether the requested target exists or whether requested content shows up at the target path. On these proof surfaces it captures a full governed-root snapshot before forwarding, captures a full governed-root snapshot after the upstream returns, diffs the changed governed paths, and treats non-target governed-path mutation as unexpected and `malicious`. On `delete_file`, it also records target pre-state and rejects missing or non-regular targets before forwarding. This still does not justify any broader general MCP verification claim.

## What This Repo Proves Today

- a thin governance proxy can sit in front of MCP tool calls and require governed/bonded authorization
- for the shipped `write_file` and `delete_file` proof surfaces only, it resolves from governed-root before/after snapshot-diff verification rather than upstream-reported success alone
- on those proof surfaces, it verifies the requested target effect and also detects other governed-path mutation
- a compromised upstream can claim `"success"` and still be caught when no effect happened, the wrong governed path changed, or the requested write/delete outcome is wrong

## What This Repo Does Not Prove

- general MCP verification
- independent verification for all MCP tools, all upstream servers, or all upstream results
- a general proof against all compromised MCP behavior
- a claim that every upstream result can be independently verified

> [!IMPORTANT]
> **Start Here First**
> The fastest outsider-readable proof path is the [Governed WriteFile Demo](https://github.com/selfradiance/agentgate-governed-writefile-demo). Run that first, then come back here for the implementation details behind this repo's firewall, verifier, policy gate, and audit trail.

## Quick Explainer

For a short visual introduction to the AgentGate / MCP Firewall idea, see:

**[AgentGate explainer thread on X](https://x.com/selfradiance11/status/2046010251128832398)**

Part 3 covers the governed `write_file` example directly.

## Why This Exists

An MCP client normally has to trust the upstream MCP server's answer about whether a tool call succeeded. That is not a safe assumption for a governance proxy. If the upstream is compromised or dishonest, it can claim success without producing the intended effect, or it can produce a different effect than the one the client requested.

The repo's claim remains intentionally small: it shows that the firewall can govern a small set of independently checkable filesystem effects without treating upstream self-report as authoritative. The first shipped proof surface was `write_file`, because it is easy to verify mechanically and easy to demonstrate honestly; the repo now also includes a second narrow `delete_file` proof surface on its dedicated test/demo upstream.

## Original v0.3.0 Write_File Scope

In scope for this release:

- one upstream filesystem-style MCP server
- one high-risk tool surface: `write_file`
- effects confined to `governed_root`
- a shared filesystem view between firewall and upstream
- one deterministic verifier for observable filesystem write outcomes
- honest and dishonest upstream test scenarios
- structured outcome logging that records the basis for each governed decision

Not claimed in this release:

- generalized attestation
- anomaly scoring or reputation systems
- cryptographic proof of remote execution
- coverage for every filesystem tool
- protection against all possible upstream side effects

## What The Shipped Verifier Checks

For the shipped `write_file` and `delete_file` proof surfaces, the verifier works from the firewall's own filesystem view. It captures a full governed-root snapshot before forwarding, forwards the request, captures a full governed-root snapshot after the upstream returns, diffs the changed paths, and then evaluates both the requested target effect and any other governed-path mutation it observed.

For governed `write_file` calls, the intended effect is:

- the exact target path should exist as a regular file
- that file's content hash and byte size should match the requested content
- no other path inside `governed_root` should have changed during the call

For governed single-path `delete_file` calls on the dedicated delete fixture in this repo, the intended effect is:

- the exact target path must exist as a regular file before forwarding, or the call is rejected before forward as `failed`
- that exact target path should be absent after the upstream-reported success
- no other path inside `governed_root` should have changed during the call

## Resolution Policy

The shipped proof surfaces use a simple deterministic mapping:

- verified intended effect present -> `success`
- claimed success but intended effect not observed -> `failed`
- claimed success with a policy-violating observed effect -> `malicious`

Concretely:

- `write_file`: target file missing after upstream success -> `failed`
- `write_file`: target file content mismatch -> `malicious`
- `write_file` or `delete_file`: non-target governed-path mutation -> `malicious`
- `delete_file`: target missing or non-regular in pre-state -> `failed`
- `delete_file`: target still present unchanged after upstream success -> `failed`
- verifier internal failure -> `failed`

The firewall returns the governed outcome and, when AgentGate is configured, resolves the bonded action with the same mapping.

## Write_File End-to-End Flow

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

For each governed `write_file` and `delete_file` decision on these shipped proof surfaces, the firewall emits a structured `FIREWALL_OUTCOME` log entry with:

- requested tool call
- intended effect
- upstream reported status and summary
- independent governed-root snapshot/diff verification result
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
| write/delete verifier |
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

For the honest `write_file` path in tests and local demos, the upstream is `@modelcontextprotocol/server-filesystem` behind the included HTTP wrapper.

## Implementation Demo in This Repo

If you are new to the project, run the companion [Governed WriteFile Demo](https://github.com/selfradiance/agentgate-governed-writefile-demo) first. It is the shortest outsider-readable proof of the shipped thesis.

Come back here when you want the implementation-level run that exercises this repo directly. If you only run one thing in this repo itself, run this demo.

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

### Dedicated `delete_file` Proof Demo

This repo also includes a narrow `delete_file` proof demo for the `v0.4.0` surface:

```bash
npm run demo:delete-file
```

If your local AgentGate instance is already configured with `AGENTGATE_REST_KEY`, export the same value before running this command.

That demo does not use `@modelcontextprotocol/server-filesystem`. It starts the dedicated delete-capable fixture upstream in this repo, calls governed single-path `delete_file`, and then checks that:

- the target existed as a regular file before the call
- the upstream reported success
- the target is absent after the call
- no other governed path changed
- the final resolution is `success`

The saved audit copy lands at `./data/delete-file-demo/last-firewall-outcome.json`.

## Manual Startup (Optional)

Use this only if you want to start the wrapper and firewall yourself after you already understand the proof path. For a first read, use the companion demo repo first; for an implementation-level run in this repo, use the demo above.

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

For the dedicated `delete_file` proof surface in this repo, run:

```bash
npm run demo:delete-file
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
- extra governed-path deletion during the claimed write
- governed-path type change during the claimed write
- verifier failure path
- deterministic resolution mapping in the standalone verifier

The repo also now includes focused `delete_file` tests on the dedicated delete-capable upstream fixture for:

- honest `delete_file` verification success
- pre-state ineligibility before forwarding
- unchanged target after claimed success
- extra governed-path mutation
- mutated target instead of delete

Tests that require a local AgentGate instance still skip cleanly when AgentGate is not running.

## What The Current Repo Still Does Not Solve

This section is deliberate. The repo should not claim more than the implementation proves.

- It verifies exactly two shipped proof surfaces: governed `write_file` on one filesystem-style upstream surface and governed single-path `delete_file` on the dedicated delete fixture used here. That still does not mean every MCP tool, every upstream, or general MCP verification.
- It verifies observable postconditions, not causality. If the target file already contained the requested content before the call, a dishonest no-op is indistinguishable from a real idempotent write.
- It watches `governed_root`, not the whole machine. A compromised upstream that writes outside the governed tree is out of scope for this verifier unless that behavior also produces an observable governed-tree violation.
- It assumes the firewall and upstream share the same filesystem view. If they do not share mounts, verification will fail or become meaningless.
- It assumes no unrelated concurrent writer is modifying `governed_root` during the governed call. Concurrent writes can create false malicious/failure signals because the verifier uses before/after snapshots.
- It is not a general attestation framework. There is no cryptographic proof that the upstream executed particular code, only an independent check of one observable effect class.
- It is still a localhost proof-of-concept. Production-grade isolation, supervision, and multi-tenant containment are out of scope here.

## Related Projects

- [AgentGate](https://github.com/selfradiance/agentgate) — bond-and-slash enforcement substrate
- [AgentGate Agents](https://github.com/selfradiance/agentgate-agents) — reference agent implementations
- [Governed WriteFile Demo](https://github.com/selfradiance/agentgate-governed-writefile-demo) — tiny companion demo repo showing the smallest outsider-readable path through AgentGate + MCP Firewall: identity -> bond -> authenticated governed `write_file` -> independent on-disk verification -> audit artifact
- [Delegation Identity Proof](https://github.com/selfradiance/delegation-identity-proof) — Ed25519 delegation demonstration
