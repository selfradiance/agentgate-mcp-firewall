# MCP Firewall (AgentGate as MCP Governance Proxy) — Project Context

**Last updated:** 2026-04-06
**Status:** v0.1.0 shipped
**Owner:** James Toole
**Repo:** TBD — new standalone repo (working name: `mcp-firewall` or `agentgate-mcp-firewall`)
**Local folder:** TBD — will be under ~/Desktop/projects/
**Skill level:** Beginner — James has no prior coding experience. He directs AI coding agents (Claude Code) to build the project. Explain everything simply. Take baby steps.

---

## What This Is

A thin proxy layer that sits between MCP clients (Claude Desktop, coding agents, browser agents) and MCP servers (tool providers). It intercepts every tool call flowing through, requires the calling agent to have a posted bond on AgentGate before the call is forwarded, and slashes the bond if the call produces a bad outcome.

This is AgentGate applied to the real-world infrastructure that AI agents are actually using right now. MCP (Model Context Protocol) is the emerging standard for how AI agents connect to tools, but nobody is building governance middleware for it. The MCP Firewall fills that gap.

---

## Why This Matters

MCP adoption is exploding. Agents can now call arbitrary tools — file systems, databases, APIs, browsers, code execution environments — through a standardized protocol. But there's no enforcement layer between "agent wants to call a tool" and "tool executes." The trust model is binary: either the tool is available or it isn't.

AgentGate's bond-and-slash model is the missing middle layer: the agent can call the tool, but it costs something if the outcome is bad. The MCP Firewall makes this concrete by sitting in the actual protocol path.

**Portfolio significance:** This is the project that connects the AgentGate ecosystem to what the industry is actually deploying. Agents 001–006 and the Delegation Identity Proof demonstrate the model in controlled environments. The MCP Firewall demonstrates it on live infrastructure.

---

## How It Works (Conceptual)

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  MCP Client       │────▶│  MCP Firewall     │────▶│  MCP Server       │
│  (Claude Desktop, │     │  (Governance      │     │  (Tool Provider)  │
│   coding agent,   │◀────│   Proxy)          │◀────│                   │
│   browser agent)  │     │                   │     │                   │
└──────────────────┘     └────────┬──────────┘     └──────────────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │  AgentGate        │
                         │  (Bond check,     │
                         │   slash on bad    │
                         │   outcome)        │
                         └──────────────────┘
```

1. MCP Client sends a tool call request (e.g., "write to file system," "execute SQL query," "send email")
2. MCP Firewall intercepts the request
3. Firewall checks: does this agent have an active bond on AgentGate with sufficient capacity for this tool call?
4. If yes → forward the request to the MCP Server, record the action on AgentGate
5. If no → reject the request (agent must post bond first)
6. MCP Server returns result → Firewall evaluates outcome
7. Good outcome → bond capacity released. Bad outcome → bond slashed via AgentGate resolution.

---

## What Needs to Be Designed

These are the open design questions. Standard multi-AI design audit process applies before building.

### Core Architecture

1. **Proxy mechanics:** How does the firewall intercept MCP traffic? Options: run as a separate MCP server that the client connects to (firewall acts as MCP server to client, MCP client to upstream server), or hook into the transport layer. The "proxy as MCP server" approach is cleaner and doesn't require modifying either client or server.

2. **Transport support:** MCP supports stdio and HTTP (Streamable HTTP). The firewall likely needs to support HTTP transport at minimum (it's a network proxy). Stdio would require a different interception model.

3. **Bond-per-tool vs. bond-per-session:** Does the agent need a separate bond for each tool call, or does it post one bond for a session and the firewall draws down capacity per call? AgentGate already supports capacity math — this is probably bond-per-session with per-call capacity reservation.

### Policy & Evaluation

4. **Tool risk classification:** Not all tool calls are equal. "Read a file" is lower risk than "delete a database." The firewall needs a way to classify tool calls by risk level and require proportional bond capacity. How is this configured? Static config file? Per-MCP-server policy? Dynamic classification via Claude API?

5. **Outcome evaluation:** How does the firewall determine if a tool call had a "bad outcome"? This is the hardest design question. Options: predefined rules per tool type, post-call evaluation via Claude API, human review queue, or some combination. This directly mirrors AgentGate's resolution mechanism.

6. **Policy format:** What does a firewall policy look like? Probably a config file that maps tool names to risk tiers, bond requirements, and evaluation rules. This could connect to the Machine-Readable Social Contract concept (#10 in pipeline) if that project is ever built.

### Identity & Integration

7. **Agent identity:** How does the firewall know which agent is making the call? MCP doesn't have a built-in identity layer. The firewall may need to require agents to authenticate with their AgentGate Ed25519 identity before tool calls are forwarded.

8. **AgentGate integration:** The firewall calls AgentGate's existing API (bond check, action execution, resolution). No changes to AgentGate core should be needed. The firewall is a client of AgentGate, not an extension.

9. **Multiple MCP servers:** Can the firewall proxy to multiple upstream MCP servers simultaneously? Probably yes — it's the single governance point for all tool access.

---

## Tech Stack (Likely)

- **Language:** TypeScript (consistent with AgentGate ecosystem)
- **Runtime:** Node.js 20+, tsx
- **MCP SDK:** @modelcontextprotocol/sdk (same as AgentGate's MCP integration)
- **Testing:** Vitest
- **HTTP client:** Native fetch (for AgentGate API calls)
- **Signing:** Node.js built-in crypto (Ed25519)
- **Config:** dotenv + policy config file (format TBD)
- **Coding tool:** Claude Code

---

## AgentGate Connection

AgentGate is the enforcement substrate. The firewall calls AgentGate's API to:
- Verify agent identity
- Check bond status and capacity
- Record actions (tool calls) against bonds
- Resolve outcomes (release or slash)

- **AgentGate local:** http://127.0.0.1:3000
- **AgentGate remote:** https://agentgate.run
- **AgentGate repo:** https://github.com/selfradiance/agentgate

---

## Cross-References

- **AgentGate MCP integration:** AgentGate already has an MCP server (port 3001) exposing 7 tools. The firewall is a different thing — it's an MCP proxy that governs access to *other* MCP servers, using AgentGate for enforcement.
- **CDP WebSocket Middleware idea (backlog):** Similar concept applied to browser automation. If the MCP Firewall architecture works, the CDP middleware could follow the same proxy pattern.
- **Machine-Readable Social Contract (#10):** Policy format for the firewall could evolve into a broader machine-readable norms specification.

---

## Audit Plan (Complete)

Per standard process (process-template-v3.md):

1. ✅ Multi-AI design audit before building (role-based framing)
2. ✅ Claude Code 8-round implementation audit — 17 findings fixed, Round 8 clean, final sweep clean
3. ✅ Codex cold-eyes audit with direct code access — 5 findings fixed, second pass clean
4. ✅ Claude Code cross-verification of Codex changes — clean, zero regressions

---

## What's NOT in Scope for v0.1.0

- Modifying AgentGate core — the firewall is a client, not an extension
- Stdio transport — HTTP first, stdio later if needed
- Dynamic risk classification via Claude API — static policy config for v0.1.0
- Multi-tenant support — single agent identity model first
- Production deployment — proof-of-concept only, like all AgentGate ecosystem projects

---

## Source

Originally recommended by Claude during the four-auditor pipeline evaluation on 2026-03-28. Listed as item #8 in `project-ideas.md`. Evaluated as the second-priority remaining build for the AgentGate portfolio on 2026-03-31 (after Sleeper Agent, before Epistemic Poisoning Simulator).

---

## Test Summary

36 tests across 10 files, all passing. Unit tests (policy, placeholder) run without external dependencies. Integration tests require AgentGate running locally on port 3000 and skip gracefully if it is not available. Integration tests also require `AGENTGATE_REST_KEY` when AgentGate is not in dev mode.

---

## Claude Code 8-Round Audit Summary

17 findings fixed across 7 rounds. Round 8 (Dependency & Supply Chain) was clean. Final sweep was clean (1 dead import removed).

**Key fixes:**

1. **Fail-closed startup validation.** Firewall refuses to start when agentgateClient is provided without policy, firewallBondId, and resolverClient. Prevents silent governance bypass.
2. **Session TTL and re-auth prevention.** Sessions expire after 5 minutes with identity re-verification. Re-authentication on an already-authenticated session is rejected to prevent identity rebinding.
3. **TOCTOU race fix on authenticate.** Synchronous pending marker in sessionAuth map prevents concurrent authenticate calls from racing past the duplicate check.
4. **Path injection guard.** validatePathSegment() rejects path separators, traversal sequences, and non-string types before any value is interpolated into a URL path.
5. **Strict type validation on authenticate.** Explicit typeof checks for identityId and bondId instead of unsafe TypeScript casts.
6. **Bond lock count check.** Authentication verifies the identity has at least one active bond on AgentGate before binding the session.
7. **Error message sanitization.** AgentGate internal error codes, URLs, and response bodies are logged to stderr only. Clients receive generic messages.
8. **DELETE session handler.** Clients can terminate sessions via DELETE /mcp, triggering cleanup of transport and auth state. Prevents session/memory leak.
9. **Outbound timeouts.** 10-second timeout on all AgentGate HTTP calls. 30-second timeout on upstream MCP operations. Firewall fails fast on downstream outages.
10. **Redirect rejection.** Signed requests to AgentGate reject HTTP redirects to prevent forwarding of API key and signature headers.
11. **Real entry point.** src/index.ts loads dotenv, policy, creates executor + resolver identities, locks a bond, starts the firewall, handles SIGINT/SIGTERM.
12. **Express as explicit dependency.** Added to package.json instead of relying on MCP SDK's transitive dependency.
13. **README accuracy.** Updated to match actual code: session security, outbound resilience, all environment variables, known limitations, test instructions.
14. **Authenticate tool rejection when auth disabled.** Explicit rejection block prevents fall-through to upstream forwarding.

**Findings accepted but not fixed (by design):**

- Zero-cent exposure allowed in policy — intentional for audit-only tools
- Static tool list caching — documented as known limitation, fail-closed on removed tools
- checkIdentity uses unsigned GET — AgentGate design, GET endpoints are public
- Multi-byte UTF-8 in payload truncation — 96-byte safety margin makes overflow unlikely

---

## Codex Cold-Eyes Audit Summary

5 findings fixed across 10 files. Second pass was clean.

**Findings fixed:**

1. **Proof-of-possession authentication.** Replaced the previous "check identity exists + has bonds" authentication with Ed25519 signature verification. The client now signs an AgentGate action execution body (including sessionId) proving it owns the claimed identity and bond. AgentGate verifies the signature server-side via `reserveAuthenticationBond()`. This resolved the Round 1 documented limitation ("proof-of-possession requires protocol-level changes") — it turned out to be achievable within the existing protocol. New shared contract in `src/authentication.ts`.
2. **Bond validation at authentication.** Authentication now verifies the agent's bond is real and active by executing a lightweight authentication action on AgentGate (1-cent exposure). Previous implementation only checked that the identity existed.
3. **Tool allowlist enforcement.** Firewall now rejects calls to tool names not present in the discovered upstream tool list. Prevents fabricated tool name injection.
4. **Key file permissions.** Identity key files are written with mode 0o600 (owner read/write only) via both `writeFileSync` mode option and explicit `chmodSync`.
5. **Server bind error handling.** `EADDRINUSE` and other bind errors now reject the `start()` promise instead of silently failing.

---

## Claude Code Cross-Verification

Codex's 10-file changeset was reviewed by Claude Code for correctness, security regressions, and unintended side effects. Result: **clean, zero regressions.** All 36 tests pass. The proof-of-possession authentication is correctly implemented — both sides build the same deterministic action body, the client signs it, and AgentGate verifies the signature.

## Completed Milestones

1. **Milestone 1: Project scaffold** — package.json, tsconfig.json, vitest config, placeholder source and test. TypeScript + Vitest + MCP SDK.
2. **Milestone 2: Echo/add test fixture** — MCP server exposing `echo` and `add` tools over Streamable HTTP. Used as the upstream target for all proxy tests.
3. **Milestone 3: Upstream client** — `UpstreamClient` class connecting to an upstream MCP server, discovering tools, and forwarding calls.
4. **Milestone 4: Firewall proxy server** — `FirewallServer` MCP server that connects to upstream, discovers tools, and re-exposes them to clients as transparent passthrough.
5. *(Milestone 5 was skipped in the build sequence.)*
6. **Milestone 6: Policy config** — `loadPolicy` and `getExposure` functions. JSON config mapping tool names to risk tiers and exposure amounts. Fail-closed validation.
7. **Milestone 7: AgentGate client** — `AgentGateClient` with Ed25519 keypair generation, identity registration, request signing (`sha256(nonce + method + path + timestamp + body)`), and identity checking.
8. **Milestone 8: Authenticate tool** — Custom `authenticate` MCP tool on the firewall. Per-session identity gating — upstream tools are blocked until the agent authenticates with a valid AgentGate identity and bond.
9. **Milestone 9: Execution gate** — Before forwarding a tool call, the firewall looks up policy exposure, calls `executeBondedAction` on AgentGate with a payload containing tool name, upstream URL, arguments, timestamp, and tier. Blocks calls on insufficient capacity.
10. **Milestone 10: Rollback on failure** — If the upstream tool call fails (MCP error or transport exception), the firewall resolves the action as "failed" on AgentGate to release bond exposure. Requires a separate resolver identity (AgentGate forbids self-resolution).
11. **Milestone 11: End-to-end test** — Comprehensive integration test proving the full loop: identity registration, bond locking, authentication, proxied tool calls, action recording on AgentGate, action resolution, and unauthenticated session rejection.
12. **Milestone 12: README and license** — Full project documentation with architecture diagram, how-it-works flow, quick start, policy reference, known limitations, and MIT license.
13. **Milestone 13: Claude Code 8-round security audit** — 17 findings fixed across 7 rounds (Round 8 clean). Key fixes: fail-closed startup validation, session TTL, TOCTOU race fix, path injection guard, error sanitization, outbound timeouts, redirect rejection, real entry point. Final sweep clean (1 dead import removed).
14. **Milestone 14: Codex cold-eyes audit** — 5 findings fixed. Key fix: proof-of-possession authentication replacing the previous "identity exists" check with Ed25519 signature verification, resolving the Round 1 documented limitation. Second pass clean.
15. **Milestone 15: Claude Code cross-verification** — Reviewed all Codex changes for correctness and security regressions. Clean, zero regressions. All 36 tests pass.
16. **Milestone 16: v0.1.0 release** — Tagged and pushed v0.1.0. Triple-audit complete.
