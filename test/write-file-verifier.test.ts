import { describe, expect, it } from "vitest";
import {
  evaluateWriteFileOutcome,
  hashUtf8String,
  type WriteFileVerificationPlan,
} from "../src/write-file-verifier.js";

function createPlan(targetPath: string, content: string): WriteFileVerificationPlan {
  return {
    governedRoot: "/tmp/governed",
    targetPath,
    expectedContentSha256: hashUtf8String(content),
    expectedContentBytes: Buffer.byteLength(content, "utf-8"),
    beforeSnapshot: {},
  };
}

describe("write_file outcome verifier", () => {
  it("maps exact target content to success", () => {
    const plan = createPlan("/tmp/governed/target.txt", "verified");

    const result = evaluateWriteFileOutcome(plan, {
      "/tmp/governed/target.txt": {
        kind: "file",
        sha256: hashUtf8String("verified"),
        sizeBytes: Buffer.byteLength("verified", "utf-8"),
      },
    });

    expect(result.resolution).toBe("success");
    expect(result.reasonCode).toBe("verified_target_content");
  });

  it("maps missing target to failed", () => {
    const plan = createPlan("/tmp/governed/target.txt", "verified");
    const result = evaluateWriteFileOutcome(plan, {});

    expect(result.resolution).toBe("failed");
    expect(result.reasonCode).toBe("target_missing");
  });

  it("maps unexpected path changes to malicious", () => {
    const plan = createPlan("/tmp/governed/target.txt", "verified");

    const result = evaluateWriteFileOutcome(plan, {
      "/tmp/governed/rogue.txt": {
        kind: "file",
        sha256: hashUtf8String("verified"),
        sizeBytes: Buffer.byteLength("verified", "utf-8"),
      },
    });

    expect(result.resolution).toBe("malicious");
    expect(result.reasonCode).toBe("unexpected_paths_changed");
    expect(result.unexpectedPaths).toEqual(["/tmp/governed/rogue.txt"]);
  });

  it("maps wrong target content to malicious", () => {
    const plan = createPlan("/tmp/governed/target.txt", "verified");

    const result = evaluateWriteFileOutcome(plan, {
      "/tmp/governed/target.txt": {
        kind: "file",
        sha256: hashUtf8String("tampered"),
        sizeBytes: Buffer.byteLength("tampered", "utf-8"),
      },
    });

    expect(result.resolution).toBe("malicious");
    expect(result.reasonCode).toBe("content_mismatch");
  });
});
