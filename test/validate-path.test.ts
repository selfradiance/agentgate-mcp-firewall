/**
 * Unit tests for validatePath.
 *
 * No external dependencies — uses the real filesystem with temp directories.
 */

import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { validatePath } from "../src/firewall-server.js";

const SANDBOX = path.join(process.env.HOME!, "mcp-firewall-sandbox");

describe("validatePath", () => {
  beforeAll(() => {
    fs.mkdirSync(SANDBOX, { recursive: true });
  });

  it("accepts a path directly inside governed_root and returns resolved path", () => {
    const result = validatePath(
      path.join(SANDBOX, "file.txt"),
      SANDBOX,
    );
    expect(result.status).toBe("valid");
    if (result.status === "valid") {
      expect(result.resolvedPath).toBe(path.join(SANDBOX, "file.txt"));
    }
  });

  it("accepts a path in a subdirectory and returns resolved path", () => {
    const subdir = path.join(SANDBOX, "subdir-for-validate-test");
    fs.mkdirSync(subdir, { recursive: true });
    try {
      const result = validatePath(
        path.join(subdir, "file.txt"),
        SANDBOX,
      );
      expect(result.status).toBe("valid");
      if (result.status === "valid") {
        expect(result.resolvedPath).toBe(path.join(subdir, "file.txt"));
      }
    } finally {
      fs.rmdirSync(subdir);
    }
  });

  it("returns canonical resolved path for paths with . components", () => {
    // path.join normalizes . already, but test with a raw string
    const weirdPath = SANDBOX + "/./file.txt";
    const result = validatePath(weirdPath, SANDBOX);
    expect(result.status).toBe("valid");
    if (result.status === "valid") {
      // The resolved path should be canonical (no . components)
      expect(result.resolvedPath).toBe(path.join(SANDBOX, "file.txt"));
    }
  });

  it("rejects direct traversal (../../etc/passwd)", () => {
    const result = validatePath(
      path.join(SANDBOX, "../../etc/passwd"),
      SANDBOX,
    );
    expect(result.status).toBe("malicious");
  });

  it("rejects sibling prefix bypass (governed_root-evil/file)", () => {
    const sibling = SANDBOX + "-evil";
    fs.mkdirSync(sibling, { recursive: true });
    try {
      const result = validatePath(
        path.join(sibling, "file.txt"),
        SANDBOX,
      );
      expect(result.status).toBe("malicious");
    } finally {
      fs.rmdirSync(sibling);
    }
  });

  it("rejects symlink escape (symlink inside sandbox pointing outside)", () => {
    const symlinkDir = path.join(SANDBOX, "symlink-escape-test");
    try {
      fs.symlinkSync("/tmp", symlinkDir);
    } catch {
      fs.unlinkSync(symlinkDir);
      fs.symlinkSync("/tmp", symlinkDir);
    }

    try {
      const result = validatePath(
        path.join(symlinkDir, "file.txt"),
        SANDBOX,
      );
      expect(result.status).toBe("malicious");
    } finally {
      fs.unlinkSync(symlinkDir);
    }
  });

  it("returns malicious (not throw) when parent directory does not exist", () => {
    const result = validatePath(
      path.join(SANDBOX, "nonexistent-dir", "file.txt"),
      SANDBOX,
    );
    expect(result.status).toBe("malicious");
  });

  it("rejects absolute path outside governed_root", () => {
    const result = validatePath("/etc/passwd", SANDBOX);
    expect(result.status).toBe("malicious");
  });

  it("rejects path to governed_root's own parent", () => {
    const result = validatePath(
      path.join(path.dirname(SANDBOX), "some-file.txt"),
      SANDBOX,
    );
    expect(result.status).toBe("malicious");
  });
});
