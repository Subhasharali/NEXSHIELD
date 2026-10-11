import { NextRequest, NextResponse } from 'next/server';
import { ZodError } from 'zod';
import {
  FirewallApiResponse,
  FirewallApiResponseSchema,
  FirewallInspectRequestSchema,
  getRiskLevelFromScore,
} from '@/core/schemas/firewall.schema';
import { analyzeInputWithHeuristics } from '@/core/firewall/heuristics';

/**
 * POST /api/firewall
 * Server-side blue-team AI firewall inspection endpoint.
 *
 * PRIME SECURITY INVARIANTS:
 * 1. Analyzes inputs deterministically using server-side normalizers and heuristics.
 * 2. An 'ALLOW' verdict is strictly advisory and NEVER authorizes a transaction.
 * 3. Enforces strict size limits and fails closed on ambiguity, threats, or errors.
 * 4. Never exposes internal stack traces or server paths to callers.
 */
export async function POST(req: NextRequest | Request) {
  try {
    // 1. Safe JSON parsing with malformed body rejection
    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        {
          error: 'Malformed JSON payload',
          details: 'The request body must be valid, well-formed JSON.',
        },
        { status: 400 }
      );
    }

    // 2. Strict Zod schema validation
    const parsed = FirewallInspectRequestSchema.safeParse(body);
    if (!parsed.success) {
      const errorMessages = parsed.error.issues.map((i) => i.message).join('; ');
      return NextResponse.json(
        {
          error: 'Validation Error',
          details: errorMessages,
        },
        { status: 400 }
      );
    }

    const { input } = parsed.data;

    // 3. Execute deterministic firewall engine
    const analysisResult = analyzeInputWithHeuristics(input);
    const riskLevel = getRiskLevelFromScore(analysisResult.riskScore);

    const apiResponse: FirewallApiResponse = {
      ...analysisResult,
      riskLevel,
      executionNotice:
        'Advisory firewall verdict only. This analysis does NOT authorize fund transfers or state mutations. Execution requires human-in-the-loop (HITL) confirmation.',
    };

    // 4. Validate output before responding
    const validatedResponse = FirewallApiResponseSchema.parse(apiResponse);

    return NextResponse.json(validatedResponse, {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (err: unknown) {
    // 5. Safe fail-closed error handling (never leak stack traces or internal details)
    if (err instanceof ZodError) {
      return NextResponse.json(
        {
          error: 'Schema Serialization Error',
          details: 'Output schema verification failed.',
        },
        { status: 500 }
      );
    }

    // Generic fail-closed response on internal error
    return NextResponse.json(
      {
        error: 'Security Engine Inspection Error',
        verdict: 'BLOCKED',
        riskScore: 1.0,
        riskLevel: 'CRITICAL',
        threatCategories: ['MALFORMED_INPUT'],
        signals: [
          {
            id: 'SIG-INTERNAL-FAIL-CLOSED',
            rule: 'Fail-Closed Security Invariant',
            category: 'MALFORMED_INPUT',
            severity: 'CRITICAL',
            evidence: 'Internal inspection failure',
            description:
              'An unexpected server error occurred during firewall inspection. Fail-closed policy enforced; transfer execution prohibited.',
          },
        ],
        isAdvisoryOnly: true,
        explanation:
          'Security engine encountered an unexpected error. Fail-closed policy enforced; execution prohibited.',
        evaluatedAt: new Date().toISOString(),
        evaluator: 'deterministic_heuristics_v1',
        executionNotice:
          'Fail-closed state enforced. No fund transfers or state mutations permitted.',
      },
      { status: 500 }
    );
  }
}
