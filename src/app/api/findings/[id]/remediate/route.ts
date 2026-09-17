import { withRateLimit, TIERS } from "@/lib/middleware/rate-limit";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/auth";
import prisma from "@/lib/prisma";
import { generateRemediationPatchFlow } from "@/ai/flows/generate-remediation-patch";

/**
 * POST /api/findings/[id]/remediate
 * Triggers the AI flow to generate a remediation patch for a specific finding.
 *
 * Findings whose stored analysis suspects prompt injection are blocked by
 * default. A caller may explicitly override this gate, but the override is
 * recorded in the audit log before any AI remediation call is made.
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

    let allowPromptInjectionOverride = false;
    const rawBody = await req.text();
    if (rawBody.trim()) {
      try {
        const body = JSON.parse(rawBody) as { allowPromptInjectionOverride?: unknown };
        allowPromptInjectionOverride = body.allowPromptInjectionOverride === true;
      } catch {
        return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
      }
    }

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
        promptInjectionSuspected: true,
        scanResult: {
          select: {
            pullRequest: {
              select: {
                repositoryId: true,
              },
            },
          },
        },
      },
    });

    if (!finding) {
      return NextResponse.json({ error: "Finding not found" }, { status: 404 });
    }

    if (finding.promptInjectionSuspected && !allowPromptInjectionOverride) {
      return NextResponse.json(
        {
          error: "AI remediation is blocked because this finding is marked as a suspected prompt-injection case",
          code: "PROMPT_INJECTION_REMEDIATION_BLOCKED",
          requiresExplicitOverride: true,
        },
        { status: 409 },
      );
    }

    if (finding.promptInjectionSuspected && allowPromptInjectionOverride) {
      try {
        await prisma.auditLog.create({
          data: {
            userId: session.user.id,
            action: "AI Remediation Prompt-Injection Override",
            resource: findingId,
            decision: "OVERRIDE",
            metadata: {
              repositoryId: finding.scanResult.pullRequest.repositoryId,
              promptInjectionSuspected: true,
              explicitOverride: true,
            },
          },
        });
      } catch (auditError) {
        console.error("[REMEDIATE_PATCH_AUDIT_ERROR]", auditError);
        return NextResponse.json(
          { error: "Unable to record the remediation override; no AI remediation was started" },
          { status: 503 },
        );
      }
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
