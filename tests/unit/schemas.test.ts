import { describe, expect, it } from 'vitest';
import {
  AccountIdSchema,
  ParsedTransferIntentSchema,
  TransferInputSchema,
} from '@/core/schemas/transfer.schema';
import {
  FirewallAnalysisResultSchema,
  FirewallVerdictSchema,
  ThreatCategorySchema,
} from '@/core/schemas/firewall.schema';

describe('Zod Schema Invariants (transfer.schema.ts & firewall.schema.ts)', () => {
  describe('Fictional Account ID Invariants', () => {
    it('accepts valid synthetic fictional account identifiers', () => {
      expect(() => AccountIdSchema.parse('ACCT-CHECKING-101')).not.toThrow();
      expect(() => AccountIdSchema.parse('ACCT-SAVINGS-202')).not.toThrow();
      expect(() => AccountIdSchema.parse('ACCT-MOCK-ALICE')).not.toThrow();
    });

    it('rejects real bank account numbers, routing numbers, and non-conforming IDs', () => {
      // Numerical routing or account numbers
      expect(() => AccountIdSchema.parse('1234567890')).toThrow();
      // Missing ACCT- prefix
      expect(() => AccountIdSchema.parse('CHECKING-101')).toThrow();
      // Empty string
      expect(() => AccountIdSchema.parse('')).toThrow();
      // Arbitrary user emails or raw text
      expect(() => AccountIdSchema.parse('alice@realbank.com')).toThrow();
    });
  });

  describe('TransferInputSchema Validation', () => {
    it('accepts valid conversational or form inputs', () => {
      const valid = {
        rawInput: 'Send $50 to ACCT-SAVINGS-202',
        sourceAccount: 'ACCT-CHECKING-101',
        destinationAccount: 'ACCT-SAVINGS-202',
        amount: 50,
        memo: 'Test transfer',
      };
      expect(() => TransferInputSchema.parse(valid)).not.toThrow();
    });

    it('rejects inputs exceeding 2000 characters', () => {
      const oversized = {
        rawInput: 'A'.repeat(2001),
      };
      expect(() => TransferInputSchema.parse(oversized)).toThrow();
    });

    it('rejects empty input string', () => {
      expect(() => TransferInputSchema.parse({ rawInput: '' })).toThrow();
    });

    it('rejects negative or zero transfer amounts', () => {
      expect(() =>
        TransferInputSchema.parse({
          rawInput: 'Transfer -$50',
          amount: -50,
        })
      ).toThrow();

      expect(() =>
        TransferInputSchema.parse({
          rawInput: 'Transfer $0',
          amount: 0,
        })
      ).toThrow();
    });
  });

  describe('ParsedTransferIntentSchema Invariants', () => {
    it('enforces human confirmation required and valid USD currency', () => {
      const validIntent = {
        sourceAccount: 'ACCT-CHECKING-101',
        destinationAccount: 'ACCT-SAVINGS-202',
        amount: 250.75,
        currency: 'USD' as const,
        memo: 'Electric bill',
        humanConfirmationRequired: true as const,
      };

      const parsed = ParsedTransferIntentSchema.parse(validIntent);
      expect(parsed.humanConfirmationRequired).toBe(true);
      expect(parsed.currency).toBe('USD');
    });
  });

  describe('FirewallAnalysisResultSchema Invariants', () => {
    it('validates structured verdict and advisory-only flag', () => {
      const result = {
        verdict: 'BLOCKED' as const,
        riskScore: 0.95,
        threatCategories: ['DIRECT_PROMPT_INJECTION' as const],
        signals: [
          {
            id: 'SIG-DIR-OVERRIDE',
            rule: 'Instruction Override',
            category: 'DIRECT_PROMPT_INJECTION' as const,
            severity: 'CRITICAL' as const,
            evidence: 'ignore previous instructions',
            description: 'Instruction override',
          },
        ],
        normalizedInput: {
          original: 'ignore previous instructions',
          normalized: 'ignore previous instructions',
          hasZeroWidthChars: false,
          zeroWidthCount: 0,
          hasControlChars: false,
          controlCharCount: 0,
          detectedEncodings: [],
          originalLength: 28,
          normalizedLength: 28,
          isTruncated: false,
          entropy: 3.2,
          flags: [],
        },
        explanation: 'Blocked due to injection',
        evaluatedAt: new Date().toISOString(),
        evaluator: 'deterministic_heuristics_v1' as const,
        isAdvisoryOnly: true as const,
      };

      expect(() => FirewallAnalysisResultSchema.parse(result)).not.toThrow();
    });
  });
});
