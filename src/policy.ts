/**
 * Policy Config Module
 *
 * Loads a JSON policy file that maps tool names to risk tiers and
 * exposure amounts in cents. Fail-closed: if the config is missing
 * or malformed, the firewall refuses to start.
 */

import { readFileSync } from "node:fs";

export interface ToolPolicy {
  tier: string;
  exposure_cents: number;
}

export interface PolicyConfig {
  tools: Record<string, ToolPolicy>;
  default_exposure_cents: number;
  /** Absolute path to the governed workspace directory used for governed filesystem verification. */
  governed_root?: string;
}

const DEFAULT_POLICY_PATH = "./policy.json";

/**
 * Load and validate a policy config from a JSON file.
 * Throws on missing file, malformed JSON, or invalid structure.
 */
export function loadPolicy(filePath?: string): PolicyConfig {
  const path = filePath ?? process.env.FIREWALL_POLICY_PATH ?? DEFAULT_POLICY_PATH;

  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (err) {
    throw new Error(`Policy file not found: ${path}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Policy file is not valid JSON: ${path}`);
  }

  return validatePolicy(parsed, path);
}

/**
 * Validate the parsed policy object has the correct structure.
 */
function validatePolicy(parsed: unknown, path: string): PolicyConfig {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Policy file must be a JSON object: ${path}`);
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.default_exposure_cents !== "number" || obj.default_exposure_cents < 0) {
    throw new Error(
      `Policy file must have a non-negative "default_exposure_cents" number: ${path}`,
    );
  }

  if (typeof obj.tools !== "object" || obj.tools === null || Array.isArray(obj.tools)) {
    throw new Error(`Policy file must have a "tools" object: ${path}`);
  }

  const tools = obj.tools as Record<string, unknown>;

  for (const [name, entry] of Object.entries(tools)) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error(`Policy tool "${name}" must be an object: ${path}`);
    }

    const toolEntry = entry as Record<string, unknown>;

    if (typeof toolEntry.tier !== "string" || toolEntry.tier.length === 0) {
      throw new Error(`Policy tool "${name}" must have a non-empty "tier" string: ${path}`);
    }

    if (typeof toolEntry.exposure_cents !== "number" || toolEntry.exposure_cents < 0) {
      throw new Error(
        `Policy tool "${name}" must have a non-negative "exposure_cents" number: ${path}`,
      );
    }
  }

  // Validate governed_root if present — must be an absolute path
  let governed_root: string | undefined;
  if (obj.governed_root !== undefined) {
    if (typeof obj.governed_root !== "string" || obj.governed_root.length === 0) {
      throw new Error(
        `Policy "governed_root" must be a non-empty string: ${path}`,
      );
    }
    if (!obj.governed_root.startsWith("/")) {
      throw new Error(
        `Policy "governed_root" must be an absolute path (starts with /): ${path}`,
      );
    }
    governed_root = obj.governed_root;
  }

  return {
    tools: tools as Record<string, ToolPolicy>,
    default_exposure_cents: obj.default_exposure_cents,
    governed_root,
  };
}

/**
 * Get the required exposure in cents for a tool call.
 * Returns the tool-specific exposure if configured, otherwise the default.
 */
export function getExposure(policy: PolicyConfig, toolName: string): number {
  const toolPolicy = policy.tools[toolName];
  if (toolPolicy) {
    return toolPolicy.exposure_cents;
  }
  return policy.default_exposure_cents;
}
