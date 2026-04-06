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
