# MCP Firewall v0.3.0 Draft Release Note

MCP Firewall v0.3.0 adds independent outcome verification for one narrow high-risk MCP tool surface: `write_file` on a filesystem-style upstream server.

Instead of trusting upstream success alone, the firewall now:

- records the intended file effect before forwarding
- forwards the MCP tool call to the upstream
- independently verifies the postcondition on disk after the upstream returns
- resolves the action from the observed effect, not just the upstream claim

This release can now distinguish among three deterministic cases:

- honest upstream success -> `success`
- claimed success with no observed effect -> `failed`
- claimed success with a policy-violating observed effect -> `malicious`

Included in v0.3.0:

- focused `write_file` verifier based on target-path content hash and governed-tree diffing
- structured `FIREWALL_OUTCOME` audit logs
- deterministic tests for honest upstream, lying no-op upstream, wrong-target upstream, and verifier failure

What this release does not claim:

- it is not a general proof against all compromised upstream behavior
- it does not cover every MCP tool surface
- it does not prove causality when the requested postcondition already held before the call
- it does not detect arbitrary writes outside `governed_root`
