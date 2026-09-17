import { createHash } from "crypto";
import { redis } from "@/lib/redis";

const CACHE_TTL_SECONDS = 60 * 60 * 24; // 24 hours

/**
 * Bump when the explanation prompt, guard logic, or model routing changes in a
 * way that can alter the security meaning of a cached explanation.
 */
export const EXPLANATION_SECURITY_VERSION = "v2";

export interface CachedExplanation {
  explanation: string;
  remediationSuggestions: string;
  promptInjectionSuspected: boolean;
}

export function createExplanationCacheKey(input: {
  findingType: string;
  severity: string;
  fileLocation: string;
  codeSnippet: string;
  /** Optional model identity used by callers with explicit model routing. */
  model?: string;
  /** Optional caller-controlled prompt/guard revision. */
  securityVersion?: string;
}): string {
  const model = input.model || process.env.GROQ_MODEL || "default";
  const securityVersion = input.securityVersion || EXPLANATION_SECURITY_VERSION;

  const normalized = JSON.stringify({
    securityVersion,
    model,
    findingType: input.findingType,
    severity: input.severity,
    fileLocation: input.fileLocation,
    codeSnippet: input.codeSnippet,
  });

  const hash = createHash("sha256").update(normalized).digest("hex");

  return `ai-explanation:${securityVersion}:${hash}`;
}

export async function getCachedExplanation(key: string): Promise<CachedExplanation | null> {
  if (!redis) return null;

  try {
    const cached = await redis.get(key);

    if (!cached) return null;

    return JSON.parse(cached) as CachedExplanation;
  } catch (error) {
    console.warn("[AI_CACHE] Failed to read cache:", error);
    return null;
  }
}

export async function setCachedExplanation(key: string, result: CachedExplanation): Promise<void> {
  if (!redis) return;

  try {
    await redis.set(key, JSON.stringify(result), "EX", CACHE_TTL_SECONDS);
  } catch (error) {
    console.warn("[AI_CACHE] Failed to write cache:", error);
  }
}
