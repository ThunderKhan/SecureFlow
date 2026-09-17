import { withRateLimit, TIERS } from "@/lib/middleware/rate-limit";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/auth";
import prisma from "@/lib/prisma";
import { generateRemediationPatchFlow } from "@/ai/flows/generate-remediation-patch";

/**
 * POST /api/findings/[id]/remediate
 * Triggers the AI flow to generate a remediation patch for a specific finding.
 */
const handler = async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id } = await params;
    const findingId = id;

    // Scope the finding lookup through the repository ownership chain. Using
    // findFirst here is intentional: the finding id is unique, but the nested
    // authorization predicate cannot be expressed safely as an independent
    // authorization check without creating a time-of-check/time-of-use gap.
    const finding = await prisma.finding.findFirst({
      where: {
        id: findingId,
        scanResult: {
          pullRequest: {
            repository: {
              userId: session.user.id,
            },
          },
        },
      },
      select: {
        id: true,
        codeSnippet: true,
        description: true,
        fileLocation: true,
      },
    });

    if (!finding) {
      // Do not distinguish "missing" from "exists but belongs to someone else".
      return NextResponse.json({ error: "Finding not found" }, { status: 404 });
    }

    // Trigger AI flow
    const aiResult = await generateRemediationPatchFlow({
      vulnerableCode: finding.codeSnippet || "",
      findingDescription: finding.description,
      filePath: finding.fileLocation,
    });

    // Save to database
    const patch = await prisma.remediationPatch.upsert({
      where: { findingId },
      update: { patchDiff: aiResult.patchDiff, status: "GENERATED" },
      create: { findingId, patchDiff: aiResult.patchDiff, status: "GENERATED" },
    });

    return NextResponse.json({ success: true, patch, explanation: aiResult.explanation });
  } catch (error) {
    console.error("[REMEDIATE_PATCH_ERROR]", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
};

export const POST = withRateLimit(
  handler as (req: NextRequest, ...args: unknown[]) => Promise<NextResponse>,
  { ...TIERS.AI_STREAM, keyPrefix: "remediate:ip" },
) as typeof handler;
