import { createHash } from "node:crypto";
import fs from "node:fs";
import {
  captureFilesystemSnapshot,
  diffFilesystemSnapshots,
  type FileSnapshot,
  type FileSnapshotEntry,
  type FileSnapshotFileEntry,
} from "./write-file-verifier.js";

export interface DeleteFileVerificationInput {
  governedRoot: string;
  targetPath: string;
}

export interface DeleteFileVerificationPlan {
  governedRoot: string;
  targetPath: string;
  beforeSnapshot: FileSnapshot;
  beforeTarget: FileSnapshotFileEntry;
}

export interface DeleteFileObservedDirectoryEntry {
  kind: "directory";
}

export type DeleteFileObservedTarget =
  | FileSnapshotEntry
  | DeleteFileObservedDirectoryEntry;

export interface DeleteFileVerificationResult {
  status: "verified" | "failed" | "malicious";
  resolution: "success" | "failed" | "malicious";
  reasonCode: string;
  message: string;
  targetPath: string;
  changedPaths: string[];
  unexpectedPaths: string[];
  observedTarget?: DeleteFileObservedTarget;
}

export interface DeleteFileVerifier {
  prepare(input: DeleteFileVerificationInput): DeleteFileVerificationPlan;
  verify(plan: DeleteFileVerificationPlan): DeleteFileVerificationResult;
}

export class DeleteFilePreparationError extends Error {
  constructor(
    readonly reasonCode: "target_missing_prestate" | "target_not_regular_file_prestate",
    message: string,
    readonly clientMessage: string,
  ) {
    super(message);
    this.name = "DeleteFilePreparationError";
  }
}

function hashBuffer(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}

function observeTargetPath(targetPath: string): DeleteFileObservedTarget | undefined {
  let stats: fs.Stats;

  try {
    stats = fs.lstatSync(targetPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }

  if (stats.isDirectory()) {
    return { kind: "directory" };
  }

  if (stats.isFile()) {
    const content = fs.readFileSync(targetPath);
    return {
      kind: "file",
      sha256: hashBuffer(content),
      sizeBytes: content.byteLength,
    };
  }

  if (stats.isSymbolicLink()) {
    return {
      kind: "symlink",
      target: fs.readlinkSync(targetPath),
    };
  }

  return {
    kind: "other",
    sizeBytes: stats.size,
  };
}

export function evaluateDeleteFileOutcome(
  plan: DeleteFileVerificationPlan,
  afterSnapshot: FileSnapshot,
  observedTarget = observeTargetPath(plan.targetPath),
): DeleteFileVerificationResult {
  const changedPaths = diffFilesystemSnapshots(plan.beforeSnapshot, afterSnapshot);
  const unexpectedPaths = changedPaths.filter(
    (entryPath) => entryPath !== plan.targetPath,
  );

  if (unexpectedPaths.length > 0) {
    return {
      status: "malicious",
      resolution: "malicious",
      reasonCode: "unexpected_paths_changed",
      message:
        `Observed governed-path mutation outside the requested delete target: ${unexpectedPaths.join(", ")}`,
      targetPath: plan.targetPath,
      changedPaths,
      unexpectedPaths,
      observedTarget,
    };
  }

  if (!observedTarget) {
    return {
      status: "verified",
      resolution: "success",
      reasonCode: "verified_target_deleted",
      message:
        `Verified requested file deletion at "${plan.targetPath}" with no other governed-path mutation.`,
      targetPath: plan.targetPath,
      changedPaths,
      unexpectedPaths,
    };
  }

  if (
    observedTarget.kind === "file" &&
    observedTarget.sha256 === plan.beforeTarget.sha256 &&
    observedTarget.sizeBytes === plan.beforeTarget.sizeBytes
  ) {
    return {
      status: "failed",
      resolution: "failed",
      reasonCode: "target_still_present",
      message:
        `Target file remained present at "${plan.targetPath}" after upstream-reported delete success.`,
      targetPath: plan.targetPath,
      changedPaths,
      unexpectedPaths,
      observedTarget,
    };
  }

  if (observedTarget.kind === "file") {
    return {
      status: "malicious",
      resolution: "malicious",
      reasonCode: "target_mutated",
      message:
        `Target path "${plan.targetPath}" still exists as a regular file with different content after upstream-reported delete success.`,
      targetPath: plan.targetPath,
      changedPaths,
      unexpectedPaths,
      observedTarget,
    };
  }

  return {
    status: "malicious",
    resolution: "malicious",
    reasonCode: "target_not_deleted_wrong_type",
    message:
      `Target path "${plan.targetPath}" still exists as ${observedTarget.kind} after upstream-reported delete success.`,
    targetPath: plan.targetPath,
    changedPaths,
    unexpectedPaths,
    observedTarget,
  };
}

export class FilesystemDeleteFileVerifier implements DeleteFileVerifier {
  prepare(input: DeleteFileVerificationInput): DeleteFileVerificationPlan {
    const beforeSnapshot = captureFilesystemSnapshot(input.governedRoot);
    const observedTarget = observeTargetPath(input.targetPath);

    if (!observedTarget) {
      throw new DeleteFilePreparationError(
        "target_missing_prestate",
        `delete_file verification requires an existing regular file at "${input.targetPath}" before forwarding.`,
        "delete_file could not be forwarded because the target file was already absent before the call. Action resolved as failed.",
      );
    }

    if (observedTarget.kind !== "file") {
      throw new DeleteFilePreparationError(
        "target_not_regular_file_prestate",
        `delete_file verification requires a regular file at "${input.targetPath}" before forwarding, but observed ${observedTarget.kind}.`,
        "delete_file could not be forwarded because the target was not an existing regular file. Action resolved as failed.",
      );
    }

    return {
      governedRoot: input.governedRoot,
      targetPath: input.targetPath,
      beforeSnapshot,
      beforeTarget: observedTarget,
    };
  }

  verify(plan: DeleteFileVerificationPlan): DeleteFileVerificationResult {
    const afterSnapshot = captureFilesystemSnapshot(plan.governedRoot);
    return evaluateDeleteFileOutcome(plan, afterSnapshot);
  }
}
