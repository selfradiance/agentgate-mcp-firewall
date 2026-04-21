import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  DeleteFilePreparationError,
  FilesystemDeleteFileVerifier,
} from "../src/delete-file-verifier.js";

const tempRoots: string[] = [];

function createGovernedRoot(): string {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-firewall-delete-verifier-"));
  tempRoots.push(tempRoot);
  const governedRootPath = path.join(tempRoot, "governed");
  fs.mkdirSync(governedRootPath, { recursive: true });
  return fs.realpathSync(governedRootPath);
}

afterEach(() => {
  while (tempRoots.length > 0) {
    fs.rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("delete_file outcome verifier", () => {
  it("rejects a missing target before forwarding", () => {
    const verifier = new FilesystemDeleteFileVerifier();
    const governedRoot = createGovernedRoot();
    const targetPath = path.join(governedRoot, "missing.txt");

    expect(() => verifier.prepare({ governedRoot, targetPath })).toThrowError(
      DeleteFilePreparationError,
    );

    try {
      verifier.prepare({ governedRoot, targetPath });
    } catch (error) {
      expect(error).toBeInstanceOf(DeleteFilePreparationError);
      expect((error as DeleteFilePreparationError).reasonCode).toBe(
        "target_missing_prestate",
      );
    }
  });

  it("rejects a non-regular target before forwarding", () => {
    const verifier = new FilesystemDeleteFileVerifier();
    const governedRoot = createGovernedRoot();
    const targetPath = path.join(governedRoot, "not-a-file");
    fs.mkdirSync(targetPath);

    expect(() => verifier.prepare({ governedRoot, targetPath })).toThrowError(
      DeleteFilePreparationError,
    );

    try {
      verifier.prepare({ governedRoot, targetPath });
    } catch (error) {
      expect(error).toBeInstanceOf(DeleteFilePreparationError);
      expect((error as DeleteFilePreparationError).reasonCode).toBe(
        "target_not_regular_file_prestate",
      );
    }
  });

  it("maps exact target deletion to success", () => {
    const verifier = new FilesystemDeleteFileVerifier();
    const governedRoot = createGovernedRoot();
    const targetPath = path.join(governedRoot, "delete-me.txt");
    fs.writeFileSync(targetPath, "delete me", "utf-8");

    const plan = verifier.prepare({ governedRoot, targetPath });
    fs.unlinkSync(targetPath);
    const result = verifier.verify(plan);

    expect(result.resolution).toBe("success");
    expect(result.reasonCode).toBe("verified_target_deleted");
    expect(result.changedPaths).toEqual([targetPath]);
    expect(result.unexpectedPaths).toEqual([]);
  });

  it("maps an unchanged target to failed", () => {
    const verifier = new FilesystemDeleteFileVerifier();
    const governedRoot = createGovernedRoot();
    const targetPath = path.join(governedRoot, "still-here.txt");
    fs.writeFileSync(targetPath, "unchanged", "utf-8");

    const plan = verifier.prepare({ governedRoot, targetPath });
    const result = verifier.verify(plan);

    expect(result.resolution).toBe("failed");
    expect(result.reasonCode).toBe("target_still_present");
  });

  it("maps extra governed-path mutation to malicious", () => {
    const verifier = new FilesystemDeleteFileVerifier();
    const governedRoot = createGovernedRoot();
    const targetPath = path.join(governedRoot, "delete-me.txt");
    const roguePath = path.join(governedRoot, "rogue.txt");
    fs.writeFileSync(targetPath, "delete me", "utf-8");

    const plan = verifier.prepare({ governedRoot, targetPath });
    fs.unlinkSync(targetPath);
    fs.writeFileSync(roguePath, "unexpected change", "utf-8");
    const result = verifier.verify(plan);

    expect(result.resolution).toBe("malicious");
    expect(result.reasonCode).toBe("unexpected_paths_changed");
    expect(result.unexpectedPaths).toEqual([roguePath]);
  });

  it("maps a mutated target to malicious", () => {
    const verifier = new FilesystemDeleteFileVerifier();
    const governedRoot = createGovernedRoot();
    const targetPath = path.join(governedRoot, "mutated.txt");
    fs.writeFileSync(targetPath, "before", "utf-8");

    const plan = verifier.prepare({ governedRoot, targetPath });
    fs.writeFileSync(targetPath, "after", "utf-8");
    const result = verifier.verify(plan);

    expect(result.resolution).toBe("malicious");
    expect(result.reasonCode).toBe("target_mutated");
  });
});
