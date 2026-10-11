import { NextRequest, NextResponse } from 'next/server';
import { TransferApiRequestSchema } from '@/core/schemas/transfer.schema';
import { globalLedger } from '@/core/banking/ledger';

/**
 * GET /api/transfer
 * Returns authoritative fictional accounts, balances, and audit logs.
 */
export async function GET() {
  return NextResponse.json(
    {
      accounts: globalLedger.getAllAccounts(),
      auditEvents: globalLedger.getAuditEvents(),
      transferRecords: globalLedger.getTransferRecords(),
    },
    {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'X-Content-Type-Options': 'nosniff',
      },
    }
  );
}

/**
 * POST /api/transfer
 * Server-side validated transfer policy gate and fictional ledger execution endpoint.
 *
 * PRIME SECURITY INVARIANTS:
 * 1. 100% Synthetic in-memory ledger — no external banking services.
 * 2. Never trusts client-provided firewall verdict, risk score, or confirmation claim.
 * 3. An advisory 'ALLOW' verdict never authorizes a transfer directly.
 * 4. Human-In-The-Loop (HITL) confirmation token required for all fund movements.
 * 5. Atomic concurrency locking prevents concurrent overspending.
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

    // 2. Strict Zod discriminated-union validation
    const parsed = TransferApiRequestSchema.safeParse(body);
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

    const requestData = parsed.data;

    // 3. Action routing
    if (requestData.action === 'prepare') {
      // Step 1: Pre-validate policies and issue short-lived confirmation token
      const result = globalLedger.prepareTransfer(requestData);

      if (!result.success) {
        return NextResponse.json(
          {
            error: 'Transfer Policy Rejection',
            code: result.rejectionCode,
            details: result.rejectionReason,
            status: result.status,
          },
          { status: 403 }
        );
      }

      return NextResponse.json(
        {
          status: result.status,
          confirmationToken: result.confirmationToken,
          expiresAt: result.expiresAt,
          transferSummary: result.transferSummary,
          notice:
            'Transfer requires explicit human confirmation. Token expires in 120 seconds.',
        },
        {
          status: 200,
          headers: {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'X-Content-Type-Options': 'nosniff',
          },
        }
      );
    }

    if (requestData.action === 'confirm') {
      // Step 2: Atomic execution with verified confirmation token under concurrency mutex
      const result = await globalLedger.executeTransfer(requestData);

      if (!result.success) {
        return NextResponse.json(
          {
            error: 'Transfer Execution Failed',
            code: result.errorCode,
            details: result.errorReason,
            status: result.status,
          },
          { status: 403 }
        );
      }

      return NextResponse.json(
        {
          status: result.status,
          transferId: result.transferId,
          sourceAccount: result.sourceAccount,
          destinationAccount: result.destinationAccount,
          amount: result.amount,
          remainingBalance: result.remainingBalance,
          timestamp: result.timestamp,
        },
        {
          status: 200,
          headers: {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'X-Content-Type-Options': 'nosniff',
          },
        }
      );
    }

    return NextResponse.json(
      { error: 'Invalid Action', details: 'Action must be either "prepare" or "confirm".' },
      { status: 400 }
    );
  } catch {
    // 4. Safe fail-closed error handling (never leak stack traces or internal details)
    return NextResponse.json(
      {
        error: 'Transfer Policy Gate Error',
        code: 'INTERNAL_POLICY_GATE_ERROR',
        details:
          'An unexpected server error occurred. Transfer was aborted in accordance with fail-closed security invariants.',
      },
      { status: 500 }
    );
  }
}
