import { z } from "genkit";

import { ai, securityExplanationModel } from "@/ai/genkit";
import {
  validateUnifiedDiff,
  MAX_REMEDIATION_PATCH_CHARS,
} from "@/lib/remediation/patch-validation";

const PatchOutputSchema = z.object({
  patchDiff: z.string().max(MAX_REMEDIATION_PATCH_CHARS).describe("The unified diff patch to fix the vulnerability."),
  explanation: z.string().describe("Brief explanation of the changes made."),
});

const MAX_REMEDIATION_CODE_CHARS = 20_000;
const MAX_REMEDIATION_DESCRIPTION_CHARS = 4_000;
const MAX_REMEDIATION_PATH_CHARS = 512;

/**
 * Genkit AI Flow: Generate Remediation Patch
 * Analyzes a security finding and its surrounding code context to generate a unified diff patch.
 */

export const generateRemediationPatchFlow = ai.defineFlow(
  {
    name: "generateRemediationPatch",
    inputSchema: z.object({
      vulnerableCode: z.string().max(MAX_REMEDIATION_CODE_CHARS),
      findingDescription: z.string().max(MAX_REMEDIATION_DESCRIPTION_CHARS),
      filePath: z.string().max(MAX_REMEDIATION_PATH_CHARS),
    }),
    outputSchema: PatchOutputSchema,
  },
  async (input) => {
    const prompt = `
You are an expert security engineer. Your task is to generate a unified diff patch to fix the following security vulnerability.

File: ${input.filePath}

Vulnerability: ${input.findingDescription}

Current Code:

\`\`\`
${input.vulnerableCode}
\`\`\`

Provide ONLY the unified diff patch that fixes this issue securely. Do not include markdown code blocks around the diff, just the raw diff text. Also provide a brief 1-sentence explanation of the fix.

`;

    try {
      const { output } = await ai.generate({
        model: securityExplanationModel,
        prompt: prompt,
        output: { schema: PatchOutputSchema, format: "json" },
      });

      if (output) {
        const validation = validateUnifiedDiff(output.patchDiff, input.filePath);
        if (!validation.valid) {
          console.warn("[REMEDIATION] Rejected structurally invalid AI patch:", validation.reason);
          return {
            patchDiff: "",
            explanation:
              "The AI generated a patch that failed structural safety checks. Review the vulnerability manually before applying any remediation.",
          };
        }

        return {
          ...output,
          patchDiff: validation.patchDiff,
        };
      }
    } catch (error) {
      console.warn("[REMEDIATION] AI provider unavailable, using static fallback:", error);
    }

    return {
      patchDiff: "",
      explanation:
        "The AI remediation service is temporarily unavailable. Please review the vulnerability manually and apply the appropriate secure remediation before merging.",
    };
  },
);
