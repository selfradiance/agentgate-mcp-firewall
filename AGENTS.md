# AGENTS.md — Agent Operating Rules for agentgate-mcp-firewall

## Files That Must Never Be Committed

- `_PROJECT_CONTEXT.md` (any file matching this name)
- `project_ideas.md`
- `process-template` files (any file matching this prefix)
- `.env` / `.env.local` (any `.env*` file)
- `agent-identity*.json` files

These are local-only files. They contain project context, credentials, or identity keys that must stay out of version control. The `.gitignore` covers them, but agents must also actively avoid staging them.

## Working Agreement

1. **No bulk staging.** Never use `git add .`, `git add -A`, or `git add -f`. Always stage files explicitly by name.
2. **Small focused diffs.** One concern per change. Don't bundle unrelated work into a single commit.
3. **Run all tests after every change.** Not just the tests you think are relevant — all of them.
4. **Commit with clear messages and push immediately.** Don't leave commits sitting unpushed.
5. **If tests fail, fix before doing anything else.** A failing test suite is a stop-everything problem.
6. **Never modify files outside the current task scope.** No drive-by refactors, no "while I'm here" improvements.
7. **If something seems wrong, ask before proceeding.** Don't guess. Don't assume. Ask.
