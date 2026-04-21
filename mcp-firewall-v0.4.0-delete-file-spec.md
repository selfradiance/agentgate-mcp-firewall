# Working Title

MCP Firewall v0.4.0: second independently verified tool proof for governed `delete_file`

## Current Shipped Baseline

`v0.3.0` is already shipped with one narrow claim: independent outcome verification for governed `write_file` on one filesystem-style upstream surface.

That shipped proof works by:

- recording the intended effect before forwarding
- forwarding the upstream call
- resolving from observed filesystem effect inside `governed_root`, not upstream self-report alone

The important continuity point for `v0.4.0` is that this is not a reinvention. It is the next narrow step in the same line of proof: strengthen the independently verified tool count from `n=1` to `n=2` without changing the basic honesty model.

## v0.4.0 Thesis

`v0.4.0` should add one second independently verified filesystem tool proof: governed single-path `delete_file` inside `governed_root`.

The public claim should stay explicit and small:

- this is a second independently verified tool proof
- it is still limited to one filesystem-style upstream surface
- it is still limited to effects the firewall can observe inside `governed_root`
- it is not general MCP verification

The core idea remains the same as `v0.3.0`: the firewall should not resolve governed `delete_file` from upstream-reported success alone. It should resolve from the observed post-call filesystem state, interpreted against recorded pre-call state.

## What It Proves

If the target file existed as a regular file before the call, and the request is a governed single-file delete inside `governed_root`, the firewall can independently determine whether the requested delete effect was actually observed.

More precisely, `v0.4.0` would prove that for this one narrow surface the firewall can:

- record that a specific governed file existed before forwarding
- forward the delete request upstream
- inspect the governed filesystem afterward
- resolve from the observed result rather than trusting upstream success text

That is a proof about one second independently checkable tool outcome. It is not a claim that the firewall now verifies arbitrary MCP tools, or that it generally neutralizes compromised upstreams.

## Exact Proposed Scope

In scope for `v0.4.0`:

- one tool surface only: `delete_file`
- one target shape only: a single existing regular file confirmed in pre-state before forwarding
- one location boundary only: inside `governed_root`
- one upstream style only: one filesystem-style upstream surface with shared filesystem visibility
- one proof rule only: resolve from pre-state plus post-state observation, not upstream self-report alone

Operationally, the flagship path should be:

- request asks to delete exactly one path
- path resolves inside `governed_root`
- pre-state shows that exact path exists as a regular file before forwarding
- upstream reports success
- post-state shows that exact path is now absent
- no other governed path changed during the call

If pre-state does not show an existing regular file at the target path, the request is not eligible for the `v0.4.0` proof surface and should resolve as `failed` before forwarding upstream.

Out of scope even if technically possible:

- deleting directories
- recursive delete
- deleting symlinks
- deleting special files
- rename or move treated as delete
- copy, batch, or multi-path operations
- arbitrary verifier coverage for other tools

If a file was already absent before the call, that must not count as the flagship proof path for `v0.4.0`.

## Proof Path

The intended proof path is:

1. Validate that the requested path stays inside `governed_root`.
2. Capture pre-state for the governed tree, with special attention to the target path.
3. Confirm that the target path exists before forwarding and is a regular file. If not, stop there and resolve as `failed` without forwarding upstream.
4. Record the intended effect: this exact governed file should transition from present to absent, with no other governed-path change.
5. Forward `delete_file` upstream.
6. Observe post-state from the firewall's own filesystem view.
7. Resolve from the observed result, not from upstream success text.

For delete semantics, pre-state capture is not optional. Write verification can prove presence and content after the call. Delete verification is different: absence after the call only means something if presence before the call was recorded first.

This is why delete is trickier than write:

- the intended effect is absence, which is only meaningful relative to prior presence
- an already-absent target can look superficially "correct" after the call even though nothing was proven
- a wrong delete can remove a different governed path while leaving the requested target in place
- a target can be replaced, moved, or otherwise changed in ways that are not the requested delete effect

So the delete proof must be explicitly two-sided:

- pre-state proves what existed
- post-state proves what no longer exists

## Deterministic Resolution Mapping

The mapping should stay mechanical and outsider-readable.

For `success`, exactly one governed effect must be observed: the requested target path transitions from present regular file to absent, and no other governed-path mutation occurs. Any additional governed-path mutation makes `success` unavailable.

| Observed situation | Resolution | Why |
|---|---|---|
| Pre-state target is missing before forward | `failed` | The request is not eligible for the `v0.4.0` proof surface and should fail before forwarding upstream. Absence after the call would not prove anything. |
| Pre-state target exists but is not a regular file | `failed` | The request is not eligible for the `v0.4.0` proof surface and should fail before forwarding upstream. |
| Upstream returns an error | `failed` | The requested delete did not complete successfully upstream. |
| Verifier preparation or execution fails | `failed` | Upstream success is not trusted when independent verification cannot run cleanly. |
| Upstream reports success, target was present before, target is absent after, and no other governed path changed | `success` | This is the intended independently verified delete effect, and it is the only governed-path mutation observed. |
| Upstream reports success, target was present before, target is still present after, and no other governed path changed | `failed` | The intended delete effect was not observed. |
| Upstream reports success, target path is absent after, but any other governed path also changed | `malicious` | A policy-violating governed effect occurred in addition to or instead of the requested delete. |
| Upstream reports success, target path is still present after but with different type or content | `malicious` | The upstream produced a different governed effect than the requested delete. |
| Upstream reports success, target remains present, and some other governed path changed | `malicious` | The observed governed effect does not match the request and includes unexpected path activity. |

The `failed` versus `malicious` line should remain mechanical:

- `failed` means the requested delete effect was not independently observed, but no separate policy-violating governed effect was observed either
- `malicious` means the upstream-reported success coincided with an observed governed effect that violated the requested single-path delete semantics

This wording is intentionally narrower than "the upstream is compromised." It only classifies the observed governed outcome.

## Required Preconditions / Assumptions

For `delete_file` to be independently verifiable in this release, all of these must hold:

- the request must target exactly one path
- that path must resolve inside `governed_root`
- the firewall and the upstream must share the same filesystem view for that governed path
- the target must exist in pre-state before forwarding
- the target must be a regular file in pre-state
- the governed tree must be observable before and after the call
- no unrelated concurrent writer should be modifying `governed_root` during the governed call
- the upstream surface must expose a single-path file delete operation with semantics the firewall can pin down

Recommended narrow operating assumption:

- if pre-state does not show an existing regular file at the target path, the request is not eligible for the `v0.4.0` proof surface and should resolve as `failed` before forwarding upstream

## Non-Goals

- general MCP verification
- general compromised-upstream handling
- deleting directories, symlinks, or other non-file targets
- recursive delete
- rename, move, copy, trash, or archive semantics
- batch delete or multi-path delete
- proving anything about effects outside `governed_root`
- proving causality when the target was already absent before the call
- broadening the claim beyond one second independently verified filesystem tool proof

## Main Honesty Risks

The main honesty risks are not implementation cleverness problems. They are claim-discipline problems.

Risk 1: treating "absent after the call" as proof without recording "present before the call"

If the file was already absent, the firewall has not verified a delete outcome. It has only observed absence.

Risk 2: collapsing all bad outcomes into one bucket

If the target simply remains present and nothing else changed, that is different from deleting the wrong governed file or changing extra governed paths. The first is a `failed` proof. The second is a `malicious` governed outcome.

Risk 3: speaking as if this extends to compromised upstreams in general

This release should not be framed as "the firewall now handles compromised upstreams." It only adds one second independently checked tool surface under narrow filesystem assumptions.

Risk 4: quietly broadening delete semantics

If the implementation starts accepting directory deletes, symlink deletes, move-as-delete, or already-absent idempotent success as part of the flagship proof, the public claim becomes muddy and harder to defend.

## Anti-Scope-Creep Guardrails

- Ship exactly one new verified surface: governed single-file `delete_file`.
- Keep the supported target to an existing regular file only. Symlink deletion stays out of scope.
- Keep the claim to one filesystem-style upstream surface inside `governed_root`.
- Do not broaden the flagship proof to directories, recursive delete, rename, move, copy, batch operations, or generic tool verifiers.
- Do not change repo messaging to imply that two verified tools means general MCP verification.
- Internal reuse from the `write_file` verifier is acceptable only as an implementation convenience. It must not widen the shipped claim.
- If the available upstream surface does not cleanly expose the narrow delete operation needed here, stop and resolve that explicitly rather than stretching the claim to fit a different tool.

## Smallest Demo Shape

The smallest honest `v0.4.0` demo is:

1. Start with a clean `governed_root`.
2. Create exactly one known regular file inside it before the governed call.
3. Authenticate and bond as in the shipped flow.
4. Call governed `delete_file` on that exact path.
5. Observe one `FIREWALL_OUTCOME` entry showing:
   - the target existed before the call
   - upstream reported success
   - the target is absent after the call
   - no other governed path changed
   - final resolution is `success`
6. Confirm on disk that the target path is absent after the call.

The demo should not use an already-absent file. That path is too weak to serve as the public proof.

## Acceptance Criteria

- A root-level `v0.4.0` implementation can be described in one sentence as: "MCP Firewall now has a second independently verified filesystem tool proof for governed single-file `delete_file`."
- The claim remains explicitly narrower than general MCP verification.
- The flagship success path requires pre-state evidence that the target existed as a regular file before forwarding.
- If pre-state does not show an existing regular file at the target path, the request is ineligible for the `v0.4.0` proof surface and resolves as `failed` before forwarding upstream.
- The success path resolves from observed absence after the call, not upstream self-report alone.
- `success` requires exactly one governed effect: the requested target path transitions from present regular file to absent, and no other governed-path mutation occurs.
- The deterministic mapping between `success`, `failed`, and `malicious` is documented and testable.
- A file already absent before the call cannot produce the flagship verified-success outcome.
- Directory deletes, recursive delete, rename, move, copy, batch delete, and arbitrary tool verification remain out of scope.
- Audit output for the governed delete path records enough basis to explain why the action resolved the way it did.
- The demo story stays small and outsider-readable.
- README language can later be updated without overclaiming because this brief already pins the public wording to "second independently verified tool proof."

## Open Questions That Must Be Resolved Before Coding

1. What exact upstream tool contract is `v0.4.0` targeting?
   The current repo's pinned reference upstream package does not obviously expose a native `delete_file` tool surface. Before coding starts, the implementation target must be pinned to a real, named, single-path delete surface that matches this proof. If the chosen upstream does not expose that, `v0.4.0` should not ship under the `delete_file` claim.

2. What should happen when the target is already absent in pre-state?
   This is no longer open at the scope level: the request is not eligible for the `v0.4.0` proof surface and should resolve as `failed` before forwarding upstream. The remaining question is only what exact audit/output wording should describe that pre-forward ineligibility.

3. What exact observed target-state change should count as `malicious` versus `failed` when the target still exists after upstream-reported success?
   The recommended rule is: target still present and otherwise unchanged -> `failed`; target still present but changed in type or content, or accompanied by any other governed-path change -> `malicious`. This should be locked before coding so tests, audit language, and README wording all stay aligned.
