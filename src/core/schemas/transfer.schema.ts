import { z } from 'zod';

/**
 * Strict regex for fictional synthetic banking account IDs.
 * Real banking routing numbers, credentials, and accounts are forbidden per AGENTS.md.
 */
export const FictionalAccountIdRegex = /^ACCT-[A-Z0-9]+(?:-[A-Z0-9]+)*$/;

export const AccountIdSchema = z
  .string()
  .min(5, 'Account ID is too short')
  .max(40, 'Account ID is too long')
  .regex(
    FictionalAccountIdRegex,
    'Invalid account ID format. All accounts must be fictional synthetic IDs (e.g. ACCT-CHECKING-101)'
  );

export type AccountId = z.infer<typeof AccountIdSchema>;

/**
 * Fictional account representation in the in-memory ledger.
 */
export const FictionalAccountSchema = z.object({
  id: AccountIdSchema,
  name: z.string(),
  balance: z.number().nonnegative(),
  dailyLimit: z.number().positive(),
  currency: z.literal('USD'),
  status: z.enum(['ACTIVE', 'FROZEN']),
});

export type FictionalAccount = z.infer<typeof FictionalAccountSchema>;

/**
 * Schema for untrusted incoming conversational or form transfer input.
 */
export const TransferInputSchema = z.object({
  rawInput: z
    .string()
    .min(1, 'Input cannot be empty')
    .max(2000, 'Input exceeds maximum allowed length of 2000 characters'),
  sourceAccount: AccountIdSchema.optional(),
  destinationAccount: AccountIdSchema.optional(),
  amount: z
    .number()
    .positive('Transfer amount must be strictly greater than zero')
    .finite('Amount must be a finite number')
    .optional(),
  memo: z
    .string()
    .max(500, 'Payment memo exceeds maximum allowed length of 500 characters')
    .optional(),
});

export type TransferInput = z.infer<typeof TransferInputSchema>;

/**
 * Strict normalized representation of a fully specified transfer intent.
 */
export const ParsedTransferIntentSchema = z.object({
  sourceAccount: AccountIdSchema,
  destinationAccount: AccountIdSchema,
  amount: z.number().positive('Transfer amount must be strictly positive').finite(),
  currency: z.literal('USD'),
  memo: z.string().max(500),
  humanConfirmationRequired: z.literal(true), // All transfers require explicit HITL verification
});

export type ParsedTransferIntent = z.infer<typeof ParsedTransferIntentSchema>;

/**
 * Ambiguity evaluation findings.
 */
export const AmbiguityReportSchema = z.object({
  isAmbiguous: z.boolean(),
  reasons: z.array(z.string()),
  missingFields: z.array(z.string()),
  relativeTermsFound: z.array(z.string()),
  contradictionsFound: z.array(z.string()),
});

export type AmbiguityReport = z.infer<typeof AmbiguityReportSchema>;

/**
 * Step 1: Prepare transfer request schema (requesting confirmation token).
 */
export const TransferPrepareRequestSchema = z.object({
  action: z.literal('prepare'),
  sourceAccount: AccountIdSchema,
  destinationAccount: AccountIdSchema,
  amount: z
    .number({ required_error: 'Amount is required' })
    .positive('Transfer amount must be strictly greater than zero')
    .finite('Amount must be a finite number'),
  memo: z.string().max(500, 'Memo exceeds 500 characters').default(''),
  rawInput: z.string().max(2000).optional(),
});

export type TransferPrepareRequest = z.infer<typeof TransferPrepareRequestSchema>;

/**
 * Step 2: Confirm transfer request schema (submitting signed token + confirmation).
 */
export const TransferConfirmRequestSchema = z.object({
  action: z.literal('confirm'),
  confirmationToken: z.string().min(10, 'Confirmation token is required and must be valid'),
  userConfirmed: z.literal(true, {
    errorMap: () => ({ message: 'Human confirmation is strictly required to execute a transfer' }),
  }),
  sourceAccount: AccountIdSchema,
  destinationAccount: AccountIdSchema,
  amount: z
    .number({ required_error: 'Amount is required' })
    .positive('Amount must be positive')
    .finite('Amount must be a finite number'),
  memo: z.string().max(500).default(''),
});

export type TransferConfirmRequest = z.infer<typeof TransferConfirmRequestSchema>;

/**
 * Unified request payload for POST /api/transfer.
 */
export const TransferApiRequestSchema = z.discriminatedUnion('action', [
  TransferPrepareRequestSchema,
  TransferConfirmRequestSchema,
]);

export type TransferApiRequest = z.infer<typeof TransferApiRequestSchema>;

/**
 * Immutable record of an executed ledger transfer.
 */
export const TransferRecordSchema = z.object({
  transferId: z.string(),
  sourceAccount: AccountIdSchema,
  destinationAccount: AccountIdSchema,
  amount: z.number().positive(),
  currency: z.literal('USD'),
  memo: z.string(),
  timestamp: z.string(),
  status: z.literal('COMPLETED'),
});

export type TransferRecord = z.infer<typeof TransferRecordSchema>;

/**
 * Audit event schema for all attempted, prepared, or blocked transfers.
 */
export const TransferAuditEventSchema = z.object({
  eventId: z.string(),
  eventType: z.enum([
    'TRANSFER_EXECUTED',
    'TRANSFER_PREPARED',
    'TRANSFER_BLOCKED_POLICY',
    'TRANSFER_BLOCKED_FIREWALL',
    'TRANSFER_CONFIRMATION_FAILED',
  ]),
  sourceAccount: z.string(),
  destinationAccount: z.string(),
  amount: z.number(),
  status: z.enum(['SUCCESS', 'REJECTED', 'FAILED', 'PENDING']),
  reason: z.string(),
  timestamp: z.string(),
});

export type TransferAuditEvent = z.infer<typeof TransferAuditEventSchema>;
