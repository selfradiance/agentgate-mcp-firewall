import path from "node:path";
import { describe, it, expect } from "vitest";
import { loadPolicy, getExposure } from "../src/policy.js";

const FIXTURES = path.resolve(import.meta.dirname, "fixtures");

describe("loadPolicy", () => {
  it("should load a valid policy config", () => {
    const policy = loadPolicy(path.join(FIXTURES, "test-policy.json"));
    expect(policy.default_exposure_cents).toBe(200);
    expect(policy.tools.echo.tier).toBe("low");
    expect(policy.tools.echo.exposure_cents).toBe(100);
    expect(policy.tools.add.tier).toBe("medium");
    expect(policy.tools.add.exposure_cents).toBe(500);
  });

  it("should throw on missing file", () => {
    expect(() => loadPolicy("/nonexistent/path/policy.json")).toThrow(
      "Policy file not found",
    );
  });

  it("should throw on malformed JSON", () => {
    expect(() => loadPolicy(path.join(FIXTURES, "bad-policy.json"))).toThrow(
      "not valid JSON",
    );
  });

  it("should load a valid policy with governed_root", () => {
    const policy = loadPolicy(path.join(FIXTURES, "filesystem-policy.json"));
    expect(policy.governed_root).toBe("/Users/jamestoole/mcp-firewall-sandbox");
    expect(policy.tools.write_file.tier).toBe("medium");
    expect(policy.tools.write_file.exposure_cents).toBe(50);
    expect(policy.tools.create_directory.tier).toBe("low");
    expect(policy.tools.create_directory.exposure_cents).toBe(10);
  });

  it("should accept a policy without governed_root (v0.1 compatibility)", () => {
    const policy = loadPolicy(path.join(FIXTURES, "test-policy.json"));
    expect(policy.governed_root).toBeUndefined();
  });

  it("should throw on relative governed_root", async () => {
    const fs = await import("node:fs");
    const tmpPath = path.join(FIXTURES, "tmp-relative-root.json");
    fs.writeFileSync(tmpPath, JSON.stringify({
      governed_root: "relative/path",
      tools: { write_file: { tier: "medium", exposure_cents: 50 } },
      default_exposure_cents: 100,
    }));
    try {
      expect(() => loadPolicy(tmpPath)).toThrow("must be an absolute path");
    } finally {
      fs.unlinkSync(tmpPath);
    }
  });

  it("should throw on empty governed_root", async () => {
    const fs = await import("node:fs");
    const tmpPath = path.join(FIXTURES, "tmp-empty-root.json");
    fs.writeFileSync(tmpPath, JSON.stringify({
      governed_root: "",
      tools: { write_file: { tier: "medium", exposure_cents: 50 } },
      default_exposure_cents: 100,
    }));
    try {
      expect(() => loadPolicy(tmpPath)).toThrow("must be a non-empty string");
    } finally {
      fs.unlinkSync(tmpPath);
    }
  });
});

describe("getExposure", () => {
  const policy = loadPolicy(path.join(FIXTURES, "test-policy.json"));

  it("should return tool-specific exposure for named tools", () => {
    expect(getExposure(policy, "echo")).toBe(100);
    expect(getExposure(policy, "add")).toBe(500);
  });

  it("should return default exposure for unlisted tools", () => {
    expect(getExposure(policy, "unknown-tool")).toBe(200);
    expect(getExposure(policy, "delete-everything")).toBe(200);
  });
});
