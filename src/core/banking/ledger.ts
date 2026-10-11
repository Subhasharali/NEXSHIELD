import crypto from 'crypto';
import {
  FictionalAccount,
  TransferAuditEvent,
  TransferConfirmRequest,
  TransferPrepareRequest,
  TransferRecord,
} from '../schemas/transfer.schema';
import { createDefaultAccounts } from './accounts';
import {
  issueConfirmationToken,
  PolicyValidationResult,
  resetTokenStore,
  validateTransferPolicies,
  verifyAndConsumeConfirmationToken,
} from './policies';

/**
 * Mutex providing strict serialized concurrency control for ledger mutations.
 * Prevents race conditions and concurrent overspending.
 */
class AsyncMutex {
  private queue: Array<() => void> = [];
  private locked = false;

  async acquire(): Promise<() => void> {
    return new Promise((resolve) => {
      const execute = () => {
        this.locked = true;
        resolve(() => {
          this.locked = false;
          const next = this.queue.shift();
          if (next) next();
        });
      };

      if (!this.locked) {
        execute();
      } else {
        this.queue.push(execute);
      }
    });
  }
}

export interface PrepareTransferResult {
  success: boolean;
  status: 'REQUIRES_CONFIRMATION' | 'REJECTED';
  confirmationToken?: string;
  expiresAt?: number;
  transferSummary?: {
    sourceAccount: string;
    destinationAccount: string;
    amount: number;
    currency: 'USD';
    memo: string;
  };
  rejectionCode?: string;
  rejectionReason?: string;
}

export interface ExecuteTransferResult {
  success: boolean;
  status: 'COMPLETED' | 'FAILED' | 'REJECTED';
  transferId?: string;
  sourceAccount: string;
  destinationAccount: string;
  amount: number;
  remainingBalance?: number;
  timestamp: string;
  errorCode?: string;
  errorReason?: string;
}

/**
 * FictionalIn-Memory Banking Ledger.
 *
 * PRIME SECURITY INVARIANTS:
 * 1. 100% Synthetic Fictional Ledger — never integrates with real banks.
 * 2. Server-side policy gate enforcement — transfers fail closed on any violation.
 * 3. Human-in-the-loop (HITL) confirmation required for all state mutations.
 * 4. Atomic execution lock prevents concurrent overspending.
 */
export class FictionalBankingLedger {
  private accounts: Map<string, FictionalAccount>;
  private transferRecords: TransferRecord[] = [];
  private auditEvents: TransferAuditEvent[] = [];
  private executionMutex = new AsyncMutex();

  constructor() {
    this.accounts = createDefaultAccounts();
  }

  /**
   * Resets the ledger to seed accounts and clears logs (for test isolation).
   */
  reset(): void {
    this.accounts = createDefaultAccounts();
    this.transferRecords = [];
    this.auditEvents = [];
    resetTokenStore();
  }

  /**
   * Returns current account information by synthetic ID.
   */
  getAccount(id: string): FictionalAccount | undefined {
    const acc = this.accounts.get(id);
    return acc ? { ...acc } : undefined;
  }

  /**
   * Returns list of all fictional accounts.
   */
  getAllAccounts(): FictionalAccount[] {
    return Array.from(this.accounts.values()).map((a) => ({ ...a }));
  }

  /**
   * Returns all audit events recorded by the ledger.
   */
  getAuditEvents(): TransferAuditEvent[] {
    return [...this.auditEvents];
  }

  /**
   * Returns all completed transfer records.
   */
  getTransferRecords(): TransferRecord[] {
    return [...this.transferRecords];
  }

  /**
   * Step 1: Pre-validates transfer policies and issues a short-lived confirmation token.
   */
  prepareTransfer(request: TransferPrepareRequest): PrepareTransferResult {
    const { sourceAccount, destinationAccount, amount, memo, rawInput } = request;

    // Validate policies against current ledger state
    const policyCheck = validateTransferPolicies({
      sourceAccount,
      destinationAccount,
      amount,
      memo,
      rawInput,
      accounts: this.accounts,
    });

    if (!policyCheck.valid) {
      // Record audit event for blocked/rejected transfer attempt
      const eventType = policyCheck.code?.startsWith('FIREWALL_')
        ? 'TRANSFER_BLOCKED_FIREWALL'
        : 'TRANSFER_BLOCKED_POLICY';

      this.recordAuditEvent({
        eventType,
        sourceAccount,
        destinationAccount,
        amount,
        status: 'REJECTED',
        reason: policyCheck.reason || 'Policy validation failed',
      });

      return {
        success: false,
        status: 'REJECTED',
        rejectionCode: policyCheck.code,
        rejectionReason: policyCheck.reason,
      };
    }

    // Issue short-lived, single-use confirmation token
    const { token, expiresAt } = issueConfirmationToken({
      sourceAccount,
      destinationAccount,
      amount,
      memo,
    });

    this.recordAuditEvent({
      eventType: 'TRANSFER_PREPARED',
      sourceAccount,
      destinationAccount,
      amount,
      status: 'PENDING',
      reason: 'Transfer policy validated; single-use confirmation token issued.',
    });

    return {
      success: true,
      status: 'REQUIRES_CONFIRMATION',
      confirmationToken: token,
      expiresAt,
      transferSummary: {
        sourceAccount,
        destinationAccount,
        amount,
        currency: 'USD',
        memo,
      },
    };
  }

  /**
   * Step 2: Atomically executes a transfer using a validated confirmation token.
   * Concurrency is serialized via AsyncMutex to prevent race conditions.
   */
  async executeTransfer(request: TransferConfirmRequest): Promise<ExecuteTransferResult> {
    const releaseLock = await this.executionMutex.acquire();

    try {
      const { confirmationToken, sourceAccount, destinationAccount, amount, memo, userConfirmed } =
        request;

      // Invariant: User confirmation is mandatory
      if (!userConfirmed) {
        this.recordAuditEvent({
          eventType: 'TRANSFER_CONFIRMATION_FAILED',
          sourceAccount,
          destinationAccount,
          amount,
          status: 'REJECTED',
          reason: 'Explicit human confirmation was not provided.',
        });

        return {
          success: false,
          status: 'REJECTED',
          sourceAccount,
          destinationAccount,
          amount,
          timestamp: new Date().toISOString(),
          errorCode: 'UNCONFIRMED_TRANSFER',
          errorReason: 'Explicit human confirmation is required to execute transfer.',
        };
      }

      // Verify and consume confirmation token
      const tokenVerification = verifyAndConsumeConfirmationToken({
        token: confirmationToken,
        sourceAccount,
        destinationAccount,
        amount,
        memo,
      });

      if (!tokenVerification.valid) {
        this.recordAuditEvent({
          eventType: 'TRANSFER_CONFIRMATION_FAILED',
          sourceAccount,
          destinationAccount,
          amount,
          status: 'FAILED',
          reason: tokenVerification.reason || 'Confirmation token verification failed.',
        });

        return {
          success: false,
          status: 'FAILED',
          sourceAccount,
          destinationAccount,
          amount,
          timestamp: new Date().toISOString(),
          errorCode: tokenVerification.code,
          errorReason: tokenVerification.reason,
        };
      }

      // Re-validate atomic balance under lock right before mutation
      const src = this.accounts.get(sourceAccount);
      const dest = this.accounts.get(destinationAccount);

      if (!src || !dest) {
        return {
          success: false,
          status: 'FAILED',
          sourceAccount,
          destinationAccount,
          amount,
          timestamp: new Date().toISOString(),
          errorCode: 'ACCOUNT_NOT_FOUND',
          errorReason: 'Account could not be resolved in ledger.',
        };
      }

      if (src.balance < amount) {
        this.recordAuditEvent({
          eventType: 'TRANSFER_BLOCKED_POLICY',
          sourceAccount,
          destinationAccount,
          amount,
          status: 'FAILED',
          reason: `Concurrent overspending detected: balance insufficient at execution time.`,
        });

        return {
          success: false,
          status: 'FAILED',
          sourceAccount,
          destinationAccount,
          amount,
          timestamp: new Date().toISOString(),
          errorCode: 'INSUFFICIENT_FUNDS',
          errorReason: `Account balance ($${src.balance.toFixed(2)}) is insufficient for transfer of $${amount.toFixed(2)}.`,
        };
      }

      // Atomically apply debit and credit
      src.balance = Number((src.balance - amount).toFixed(2));
      dest.balance = Number((dest.balance + amount).toFixed(2));

      const transferId = `TX-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
      const timestamp = new Date().toISOString();

      const record: TransferRecord = {
        transferId,
        sourceAccount,
        destinationAccount,
        amount,
        currency: 'USD',
        memo,
        timestamp,
        status: 'COMPLETED',
      };

      this.transferRecords.push(record);

      this.recordAuditEvent({
        eventType: 'TRANSFER_EXECUTED',
        sourceAccount,
        destinationAccount,
        amount,
        status: 'SUCCESS',
        reason: `Transfer executed successfully. Transaction ID: ${transferId}`,
      });

      return {
        success: true,
        status: 'COMPLETED',
        transferId,
        sourceAccount,
        destinationAccount,
        amount,
        remainingBalance: src.balance,
        timestamp,
      };
    } finally {
      releaseLock();
    }
  }

  /**
   * Internal helper to record structured audit events.
   */
  private recordAuditEvent(params: {
    eventType: TransferAuditEvent['eventType'];
    sourceAccount: string;
    destinationAccount: string;
    amount: number;
    status: TransferAuditEvent['status'];
    reason: string;
  }): void {
    const event: TransferAuditEvent = {
      eventId: `EVT-${crypto.randomBytes(6).toString('hex').toUpperCase()}`,
      eventType: params.eventType,
      sourceAccount: params.sourceAccount,
      destinationAccount: params.destinationAccount,
      amount: params.amount,
      status: params.status,
      reason: params.reason,
      timestamp: new Date().toISOString(),
    };

    this.auditEvents.push(event);
  }
}

// Global singleton ledger instance for server execution
export const globalLedger = new FictionalBankingLedger();
