import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface FileSnapshotFileEntry {
  kind: "file";
  sha256: string;
  sizeBytes: number;
}

export interface FileSnapshotSymlinkEntry {
  kind: "symlink";
  target: string;
}

export interface FileSnapshotOtherEntry {
  kind: "other";
  sizeBytes: number;
}

export type FileSnapshotEntry =
  | FileSnapshotFileEntry
  | FileSnapshotSymlinkEntry
  | FileSnapshotOtherEntry;

export type FileSnapshot = Record<string, FileSnapshotEntry>;

export interface WriteFileVerificationPlan {
  governedRoot: string;
  targetPath: string;
  expectedContentSha256: string;
  expectedContentBytes: number;
  beforeSnapshot: FileSnapshot;
}

export interface WriteFileVerificationInput {
  governedRoot: string;
  targetPath: string;
  content: string;
}

export interface WriteFileVerificationResult {
  status: "verified" | "failed" | "malicious";
  resolution: "success" | "failed" | "malicious";
  reasonCode: string;
  message: string;
  targetPath: string;
  changedPaths: string[];
  unexpectedPaths: string[];
  expectedContentSha256: string;
  observedTarget?: FileSnapshotEntry;
}

export interface WriteFileVerifier {
  prepare(input: WriteFileVerificationInput): WriteFileVerificationPlan;
  verify(plan: WriteFileVerificationPlan): WriteFileVerificationResult;
}

function hashBuffer(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}

export function hashUtf8String(value: string): string {
  return hashBuffer(Buffer.from(value, "utf-8"));
}

function snapshotEntryEquals(
  left: FileSnapshotEntry | undefined,
  right: FileSnapshotEntry | undefined,
): boolean {
  if (!left || !right) {
    return left === right;
  }

  if (left.kind !== right.kind) {
    return false;
  }

  if (left.kind === "file" && right.kind === "file") {
    return left.sha256 === right.sha256 && left.sizeBytes === right.sizeBytes;
  }

  if (left.kind === "symlink" && right.kind === "symlink") {
    return left.target === right.target;
  }

  if (left.kind === "other" && right.kind === "other") {
    return left.sizeBytes === right.sizeBytes;
  }

  return false;
}

function walkSnapshot(currentPath: string, snapshot: FileSnapshot): void {
  const entries = fs.readdirSync(currentPath, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));

  for (const entry of entries) {
    const entryPath = path.join(currentPath, entry.name);

    if (entry.isDirectory()) {
      walkSnapshot(entryPath, snapshot);
      continue;
    }

    if (entry.isFile()) {
      const content = fs.readFileSync(entryPath);
      snapshot[entryPath] = {
        kind: "file",
        sha256: hashBuffer(content),
        sizeBytes: content.byteLength,
      };
      continue;
    }

    if (entry.isSymbolicLink()) {
      snapshot[entryPath] = {
        kind: "symlink",
        target: fs.readlinkSync(entryPath),
      };
      continue;
    }

    const stats = fs.lstatSync(entryPath);
    snapshot[entryPath] = {
      kind: "other",
      sizeBytes: stats.size,
    };
  }
}

export function captureFilesystemSnapshot(governedRoot: string): FileSnapshot {
  const snapshot: FileSnapshot = {};
  walkSnapshot(governedRoot, snapshot);
  return snapshot;
}

export function diffFilesystemSnapshots(
  beforeSnapshot: FileSnapshot,
  afterSnapshot: FileSnapshot,
): string[] {
  const allPaths = new Set([
    ...Object.keys(beforeSnapshot),
    ...Object.keys(afterSnapshot),
  ]);

  const changedPaths = Array.from(allPaths).filter((entryPath) => {
    return !snapshotEntryEquals(
      beforeSnapshot[entryPath],
      afterSnapshot[entryPath],
    );
  });

  changedPaths.sort();
  return changedPaths;
}

export function evaluateWriteFileOutcome(
  plan: WriteFileVerificationPlan,
  afterSnapshot: FileSnapshot,
): WriteFileVerificationResult {
  const changedPaths = diffFilesystemSnapshots(plan.beforeSnapshot, afterSnapshot);
  const unexpectedPaths = changedPaths.filter(
    (entryPath) => entryPath !== plan.targetPath,
  );
  const observedTarget = afterSnapshot[plan.targetPath];

  if (unexpectedPaths.length > 0) {
    return {
      status: "malicious",
      resolution: "malicious",
      reasonCode: "unexpected_paths_changed",
      message:
        `Observed write activity outside the intended target: ${unexpectedPaths.join(", ")}`,
      targetPath: plan.targetPath,
      changedPaths,
      unexpectedPaths,
      expectedContentSha256: plan.expectedContentSha256,
      observedTarget,
    };
  }

  if (!observedTarget) {
    return {
      status: "failed",
      resolution: "failed",
      reasonCode: "target_missing",
      message: `Expected target file not found at "${plan.targetPath}" after upstream success.`,
      targetPath: plan.targetPath,
      changedPaths,
      unexpectedPaths,
      expectedContentSha256: plan.expectedContentSha256,
    };
  }

  if (observedTarget.kind !== "file") {
    return {
      status: "malicious",
      resolution: "malicious",
      reasonCode: "target_not_regular_file",
      message:
        `Expected a regular file at "${plan.targetPath}" but observed ${observedTarget.kind}.`,
      targetPath: plan.targetPath,
      changedPaths,
      unexpectedPaths,
      expectedContentSha256: plan.expectedContentSha256,
      observedTarget,
    };
  }

  if (observedTarget.sha256 !== plan.expectedContentSha256) {
    return {
      status: "malicious",
      resolution: "malicious",
      reasonCode: "content_mismatch",
      message:
        `Target file content did not match the requested content at "${plan.targetPath}".`,
      targetPath: plan.targetPath,
      changedPaths,
      unexpectedPaths,
      expectedContentSha256: plan.expectedContentSha256,
      observedTarget,
    };
  }

  return {
    status: "verified",
    resolution: "success",
    reasonCode: "verified_target_content",
    message:
      `Verified requested file content at "${plan.targetPath}" with no unexpected governed-path changes.`,
    targetPath: plan.targetPath,
    changedPaths,
    unexpectedPaths,
    expectedContentSha256: plan.expectedContentSha256,
    observedTarget,
  };
}

export class FilesystemWriteFileVerifier implements WriteFileVerifier {
  prepare(input: WriteFileVerificationInput): WriteFileVerificationPlan {
    return {
      governedRoot: input.governedRoot,
      targetPath: input.targetPath,
      expectedContentSha256: hashUtf8String(input.content),
      expectedContentBytes: Buffer.byteLength(input.content, "utf-8"),
      beforeSnapshot: captureFilesystemSnapshot(input.governedRoot),
    };
  }

  verify(plan: WriteFileVerificationPlan): WriteFileVerificationResult {
    const afterSnapshot = captureFilesystemSnapshot(plan.governedRoot);
    return evaluateWriteFileOutcome(plan, afterSnapshot);
  }
}
