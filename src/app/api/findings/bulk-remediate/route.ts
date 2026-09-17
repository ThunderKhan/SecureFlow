import { withRateLimit, TIERS } from "@/lib/middleware/rate-limit";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/auth";
import prisma from "@/lib/prisma";
import { generateRemediationPatchFlow } from "@/ai/flows/generate-remediation-patch";

/* POST /api/findings/bulk-remediate */
const handler = async function POST(req: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const userId = session.user.id;

    let body: { findingIds?: unknown };
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const findingIds = body?.findingIds;
    if (
      !Array.isArray(findingIds) ||
      findingIds.length === 0 ||
      !findingIds.every((id) => typeof id === "string")
    ) {
      return NextResponse.json(
        { error: "findingIds must be a non-empty array of strings" },
        { status: 400 },
      );
    }

    // Load findings owned by the authenticated user
    const findings: any[] = await prisma.finding.findMany({
      where: {
        id: { in: findingIds },
        scanResult: { pullRequest: { repository: { userId } } },
      },
      include: {
        scanResult: {
          include: {
            pullRequest: {
              include: { repository: true },
            },
          },
        },
      },
    });

    if (findings.length === 0) {
      return NextResponse.json({ error: "No matching findings found" }, { status: 404 });
    }

    if (findings.length !== findingIds.length) {
      return NextResponse.json(
        { error: "One or more findings could not be found or access is denied" },
        { status: 403 },
      );
    }

    // A bulk patch is a single logical remediation artifact. Mixing findings
    // from different repositories would make its file paths ambiguous and can
    // cause a patch to be reviewed in the wrong repository context.
    const repositoryIds = new Set(
      findings.map((finding: any) => finding.scanResult.pullRequest.repositoryId),
    );
    if (repositoryIds.size !== 1) {
      return NextResponse.json(
        { error: "Bulk remediation requires all selected findings to belong to one repository" },
        { status: 400 },
      );
    }

    // Enforce type homogeneity: bulk remediation requires findings of the same vulnerability type
    const types = Array.from(new Set(findings.map((f: any) => f.type)));
    if (types.length > 1) {
      return NextResponse.json(
        {
          error:
            "Bulk remediation requires all selected findings to be of the same vulnerability type",
          details: { types },
        },
        { status: 400 },
      );
    }

    // Generate individual remediation patches and store them
    const results = await Promise.all(
      findings.map(async (finding: any) => {
        const aiResult = await generateRemediationPatchFlow({
          vulnerableCode: finding.codeSnippet || "",
          findingDescription:
            finding.explanation || finding.remediation || `${finding.type} vulnerability`,
          filePath: finding.fileLocation,
        });

        const patch = await prisma.remediationPatch.upsert({
          where: { findingId: finding.id },
          update: { patchDiff: aiResult.patchDiff, status: "GENERATED" },
          create: { findingId: finding.id, patchDiff: aiResult.patchDiff, status: "GENERATED" },
        });

        return {
          findingId: finding.id,
          fileLocation: finding.fileLocation,
          patch,
          explanation: aiResult.explanation,
        };
      }),
    );

    // Combine individual diffs into a unified multi-file diff
    const combinedDiff = results.map((r: any) => r.patch.patchDiff).join("\n\n");
    const combinedExplanation =
      `Bulk remediation patch for ${findings.length} ${types[0]} findings across repository:\n` +
      results.map((r: any) => `• ${r.fileLocation}: ${r.explanation}`).join("\n");

    return NextResponse.json({
      success: true,
      patch: {
        patchDiff: combinedDiff,
        status: "GENERATED",
      },
      explanation: combinedExplanation,
      count: findings.length,
      type: types[0],
    });
  } catch (error) {
    console.error("[BULK_REMEDIATE_ERROR]", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
};

export const POST = withRateLimit(
  handler as (req: NextRequest, ...args: unknown[]) => Promise<NextResponse>,
  { ...TIERS.AI_STREAM, keyPrefix: "bulk-remediate:ip" },
) as typeof handler;
