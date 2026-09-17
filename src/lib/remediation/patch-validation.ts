export const MAX_REMEDIATION_PATCH_CHARS = 100_000;
const MAX_REMEDIATION_PATCH_LINES = 5_000;
const MAX_REMEDIATION_HUNKS = 200;

export type PatchValidationResult =
  | { valid: true; patchDiff: string }
  | { valid: false; reason: string };

function normalizePath(value: string): string | null {
  const path = value.replace(/\\/g, "/").trim();

  if (
    !path ||
    path.includes("\u0000") ||
    path.startsWith("/") ||
    /^[A-Za-z]:\//.test(path)
  ) {
    return null;
  }

  const segments = path.split("/");
  if (segments.some((segment) => segment === ".." || segment === "")) {
    return null;
  }

  return path;
}

function parseHeaderPath(line: string, prefix: "a/" | "b/"): string | null {
  const raw = line.slice(4).split("\t", 1)[0].trim();
  if (!raw.startsWith(prefix)) return null;
  return normalizePath(raw.slice(2));
}

function parseHunkHeader(line: string): {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
} | null {
  const match = line.match(
    /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$/,
  );
  if (!match) return null;

  const oldStart = Number(match[1]);
  const oldCount = match[2] === undefined ? 1 : Number(match[2]);
  const newStart = Number(match[3]);
  const newCount = match[4] === undefined ? 1 : Number(match[4]);

  if (
    !Number.isSafeInteger(oldStart) ||
    !Number.isSafeInteger(oldCount) ||
    !Number.isSafeInteger(newStart) ||
    !Number.isSafeInteger(newCount) ||
    oldStart < 0 ||
    newStart < 0 ||
    oldCount < 0 ||
    newCount < 0
  ) {
    return null;
  }

  return { oldStart, oldCount, newStart, newCount };
}

export function validateUnifiedDiff(
  patchDiff: string,
  expectedFilePath: string,
): PatchValidationResult {
  if (typeof patchDiff !== "string" || !patchDiff.trim()) {
    return { valid: false, reason: "The remediation model returned an empty patch." };
  }

  if (patchDiff.length > MAX_REMEDIATION_PATCH_CHARS) {
    return {
      valid: false,
      reason: `The remediation patch exceeds the ${MAX_REMEDIATION_PATCH_CHARS}-character limit.`,
    };
  }

  if (/```/.test(patchDiff)) {
    return { valid: false, reason: "Markdown code fences are not valid unified-diff output." };
  }

  const expectedPath = normalizePath(expectedFilePath);
  if (!expectedPath) {
    return { valid: false, reason: "The target file path is unsafe or malformed." };
  }

  const lines = patchDiff.replace(/\r\n?/g, "\n").trim().split("\n");
  if (lines.length > MAX_REMEDIATION_PATCH_LINES) {
    return {
      valid: false,
      reason: `The remediation patch exceeds the ${MAX_REMEDIATION_PATCH_LINES}-line limit.`,
    };
  }

  const gitHeaders = lines.filter((line) => line.startsWith("diff --git "));
  if (gitHeaders.length > 1) {
    return { valid: false, reason: "Multi-file remediation patches are not allowed." };
  }

  if (gitHeaders.length === 1) {
    const match = gitHeaders[0].match(/^diff --git a\/(\S+) b\/(\S+)$/);
    if (!match) {
      return { valid: false, reason: "The diff --git header is malformed." };
    }

    const fromPath = normalizePath(match[1]);
    const toPath = normalizePath(match[2]);
    if (fromPath !== expectedPath || toPath !== expectedPath) {
      return { valid: false, reason: "The remediation patch targets a different file." };
    }
  }

  const oldHeaders = lines.filter((line) => line.startsWith("--- "));
  const newHeaders = lines.filter((line) => line.startsWith("+++ "));
  if (oldHeaders.length !== 1 || newHeaders.length !== 1) {
    return { valid: false, reason: "A single-file unified diff must contain one old and one new file header." };
  }

  const oldPath = oldHeaders[0] === "--- /dev/null" ? null : parseHeaderPath(oldHeaders[0], "a/");
  const newPath = newHeaders[0] === "+++ /dev/null" ? null : parseHeaderPath(newHeaders[0], "b/");
  if (oldPath !== expectedPath || newPath !== expectedPath) {
    return { valid: false, reason: "The unified diff headers do not match the target file." };
  }

  const forbiddenMetadata = /^(?:GIT binary patch|Binary files |rename |copy |similarity index |new file mode |deleted file mode |old mode |new mode )/;
  if (lines.some((line) => forbiddenMetadata.test(line))) {
    return { valid: false, reason: "Binary, rename, copy, or mode-change patches are not allowed." };
  }

  const firstHunk = lines.findIndex((line) => line.startsWith("@@ "));
  if (firstHunk === -1) {
    return { valid: false, reason: "The remediation patch contains no hunk." };
  }

  for (let index = 0; index < firstHunk; index += 1) {
    const line = lines[index];
    if (
      !line.startsWith("diff --git ") &&
      !line.startsWith("index ") &&
      !line.startsWith("--- ") &&
      !line.startsWith("+++ ")
    ) {
      return { valid: false, reason: "Unexpected content appears before the first diff hunk." };
    }
  }

  let hunkCount = 0;
  let sawChange = false;
  let oldConsumed = 0;
  let newConsumed = 0;
  let expectedOld = 0;
  let expectedNew = 0;

  const finishHunk = (): string | null => {
    if (oldConsumed !== expectedOld || newConsumed !== expectedNew) {
      return "A diff hunk does not contain the number of lines declared by its header.";
    }
    return null;
  };

  for (let index = firstHunk; index < lines.length; index += 1) {
    const line = lines[index];

    if (line.startsWith("@@ ")) {
      const previousError = hunkCount > 0 ? finishHunk() : null;
      if (previousError) return { valid: false, reason: previousError };

      hunkCount += 1;
      if (hunkCount > MAX_REMEDIATION_HUNKS) {
        return {
          valid: false,
          reason: `The remediation patch exceeds the ${MAX_REMEDIATION_HUNKS}-hunk limit.`,
        };
      }

      const header = parseHunkHeader(line);
      if (!header) {
        return { valid: false, reason: "A diff hunk header is malformed." };
      }

      oldConsumed = 0;
      newConsumed = 0;
      expectedOld = header.oldCount;
      expectedNew = header.newCount;
      continue;
    }

    if (line === "\\ No newline at end of file") {
      continue;
    }

    if (line.startsWith("diff --git ") || line.startsWith("--- ") || line.startsWith("+++ ")) {
      return { valid: false, reason: "A second file header appears inside the remediation hunks." };
    }

    if (line.startsWith("+")) {
      newConsumed += 1;
      sawChange = true;
      continue;
    }

    if (line.startsWith("-")) {
      oldConsumed += 1;
      sawChange = true;
      continue;
    }

    if (line.startsWith(" ")) {
      oldConsumed += 1;
      newConsumed += 1;
      continue;
    }

    return { valid: false, reason: "An invalid line appears inside a unified diff hunk." };
  }

  const finalHunkError = finishHunk();
  if (finalHunkError) return { valid: false, reason: finalHunkError };

  if (!sawChange) {
    return { valid: false, reason: "The remediation patch does not change any lines." };
  }

  return { valid: true, patchDiff: lines.join("\n") + "\n" };
}
