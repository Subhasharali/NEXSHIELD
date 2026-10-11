import crypto from 'crypto';
import { FictionalAccount } from '../schemas/transfer.schema';
import { analyzeInputWithHeuristics } from '../firewall/heuristics';

// In-memory runtime fallback secret (only used in development/test/simulation mode when env secret is not set)
let runtimeFallbackSecret: string | null = null;
let testSecretOverride: string | null | undefined = undefined;

/**
 * Allows test suites to simulate secure, insecure, or missing signing secrets without modifying process.env.
 */
export function setTestSecretOverride(secret: string | null | undefined): void {
  testSecretOverride = secret;
}

export interface SecretValidationResult {
  secure: boolean;
  reason?: string;
}

/**
 * Validates that the confirmation-signing secret is securely configured.
 *
 * PRIME SECURITY INVARIANT (Requirement 7):
 * - Never hardcode production secrets.
 * - In production, NEXSHIELD_SERVER_SECRET must be explicitly provided in environment.
 * - Secret must be at least 32 characters (256-bit entropy).
 * - Known trivial or weak patterns are prohibited.
 * - If secret is missing or insecure, transfers are disabled safely.
 */
export function validateConfirmationSecret(): SecretValidationResult {
  const isProduction = process.env.NODE_ENV === 'production';
  const effectiveSecret =
    testSecretOverride !== undefined
      ? testSecretOverride
      : (process.env.NEXSHIELD_SERVER_SECRET || process.env.BANKISM_SERVER_SECRET);

  if (isProduction && !effectiveSecret) {
    return {
      secure: false,
      reason: 'NEXSHIELD_SERVER_SECRET is required in production environment.',
    };
  }

  if (effectiveSecret !== undefined && effectiveSecret !== null) {
    if (typeof effectiveSecret !== 'string' || effectiveSecret.length < 32) {
      return {
        secure: false,
        reason: 'Signing secret is too short. Minimum 32 characters required.',
      };
    }

    const trivialPatterns = [
      /^(.)\1+$/, // All repeated characters (e.g. "aaaaaaaa...")
      /^(?:password|secret|changeme|default|admin|12345678|bankism|nexshield)/i,
    ];

    for (const pattern of trivialPatterns) {
      if (pattern.test(effectiveSecret)) {
        return {
          secure: false,
          reason: 'Signing secret contains known trivial or insecure patterns.',
        };
      }
    }

    return { secure: true };
  }

  // In non-production without explicit env secret, ephemeral strong random key is permitted for simulation
  return { secure: true };
}

/**
 * Returns the active cryptographically strong confirmation signing secret.
 * Throws if the secret is missing or insecure.
 */
export function getConfirmationSigningSecret(): string {
  const validation = validateConfirmationSecret();
  if (!validation.secure) {
    throw new Error(`Transfers are disabled: ${validation.reason}`);
  }

  if (testSecretOverride !== undefined && testSecretOverride !== null) {
    return testSecretOverride;
  }

  if (process.env.NEXSHIELD_SERVER_SECRET) {
    return process.env.NEXSHIELD_SERVER_SECRET;
  }

  if (process.env.BANKISM_SERVER_SECRET) {
    return process.env.BANKISM_SERVER_SECRET;
  }

  if (!runtimeFallbackSecret) {
    runtimeFallbackSecret = crypto.randomBytes(32).toString('hex');
  }

  return runtimeFallbackSecret;
}

// Token time-to-live: 2 minutes
export const CONFIRMATION_TTL_MS = 120_000;
export const MAX_TOKEN_STORE_CAPACITY = 10_000;

export interface ConfirmationTokenRecord {
  tokenId: string;
  sourceAccount: string;
  destinationAccount: string;
  amount: number;
  memo: string;
  expiresAt: number;
  used: boolean;
}

// In-memory token store for single-use / replay-attack prevention
const tokenStore = new Map<string, ConfirmationTokenRecord>();

/**
 * Prunes expired confirmation tokens from the in-memory registry.
 *
 * SECURITY INVARIANTS:
 * - Pruning ONLY removes tokens where now >= expiresAt.
 * - Expired tokens are already permanently invalid under cryptographic and policy rules.
 * - Unexpired tokens (both pending and consumed) are NEVER evicted early,
 *   preserving single-use replay protection and pending confirmation validity.
 */
export function pruneExpiredTokens(now: number = Date.now()): number {
  let prunedCount = 0;
  for (const [tokenId, record] of tokenStore.entries()) {
    if (record.expiresAt <= now) {
      tokenStore.delete(tokenId);
      prunedCount++;
    }
  }
  return prunedCount;
}

/**
 * Returns current size of the confirmation token registry (for telemetry and test verification).
 */
export function getTokenStoreSize(): number {
  return tokenStore.size;
}

export interface PolicyValidationResult {
  valid: boolean;
  code?: string;
  reason?: string;
  details?: Record<string, unknown>;
}

/**
 * Resets the in-memory confirmation token store (primarily for test isolation).
 */
export function resetTokenStore(): void {
  tokenStore.clear();
}

/**
 * Generates a cryptographically signed, short-lived, single-use confirmation token
 * bound to exact transfer parameters.
 */
export function issueConfirmationToken(params: {
  sourceAccount: string;
  destinationAccount: string;
  amount: number;
  memo: string;
}): { token: string; expiresAt: number } {
  // Prune expired records prior to capacity verification and new token generation
  pruneExpiredTokens();

  if (tokenStore.size >= MAX_TOKEN_STORE_CAPACITY) {
    throw new Error(
      'Confirmation token capacity exceeded. System fail-closed under excessive pending load.'
    );
  }

  const secret = getConfirmationSigningSecret();
  const tokenId = crypto.randomBytes(16).toString('hex');
  const expiresAt = Date.now() + CONFIRMATION_TTL_MS;

  const payloadToSign = `${tokenId}:${params.sourceAccount}:${params.destinationAccount}:${params.amount.toFixed(
    2
  )}:${params.memo}:${expiresAt}`;

  const hmac = crypto
    .createHmac('sha256', secret)
    .update(payloadToSign)
    .digest('hex');

  const token = `${tokenId}.${expiresAt}.${hmac}`;

  // Store in single-use registry
  tokenStore.set(tokenId, {
    tokenId,
    sourceAccount: params.sourceAccount,
    destinationAccount: params.destinationAccount,
    amount: params.amount,
    memo: params.memo,
    expiresAt,
    used: false,
  });

  return { token, expiresAt };
}

/**
 * Verifies a confirmation token against submitted transfer parameters.
 * Enforces:
 * 1. Valid HMAC signature bound to exact parameters.
 * 2. Unexpired token lifetime.
 * 3. Single-use execution (atomic consumption).
 */
export function verifyAndConsumeConfirmationToken(params: {
  token: string;
  sourceAccount: string;
  destinationAccount: string;
  amount: number;
  memo: string;
}): PolicyValidationResult {
  if (!params.token || typeof params.token !== 'string') {
    return {
      valid: false,
      code: 'MISSING_CONFIRMATION_TOKEN',
      reason: 'A valid confirmation token is required to execute a transfer.',
    };
  }

  const parts = params.token.split('.');
  if (parts.length !== 3) {
    return {
      valid: false,
      code: 'INVALID_TOKEN_FORMAT',
      reason: 'Confirmation token format is malformed.',
    };
  }

  const [tokenId, expiresAtStr, providedHmac] = parts;
  const expiresAt = parseInt(expiresAtStr, 10);

  if (isNaN(expiresAt) || Date.now() > expiresAt) {
    return {
      valid: false,
      code: 'CONFIRMATION_TOKEN_EXPIRED',
      reason: 'Confirmation token has expired. A fresh transfer confirmation must be requested.',
    };
  }

  // Verify signing secret security
  const secretValidation = validateConfirmationSecret();
  if (!secretValidation.secure) {
    return {
      valid: false,
      code: 'SIGNING_SECRET_INSECURE',
      reason: `Transfers are safely disabled: ${secretValidation.reason}`,
    };
  }

  const secret = getConfirmationSigningSecret();

  // Verify HMAC signature
  const expectedPayload = `${tokenId}:${params.sourceAccount}:${params.destinationAccount}:${params.amount.toFixed(
    2
  )}:${params.memo}:${expiresAt}`;

  const expectedHmac = crypto
    .createHmac('sha256', secret)
    .update(expectedPayload)
    .digest('hex');

  const providedBuffer = Buffer.from(providedHmac, 'hex');
  const expectedBuffer = Buffer.from(expectedHmac, 'hex');

  if (
    providedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(providedBuffer, expectedBuffer)
  ) {
    return {
      valid: false,
      code: 'CONFIRMATION_TOKEN_TAMPERED',
      reason:
        'Confirmation token signature is invalid or does not match transfer parameters.',
    };
  }

  // Prune expired tokens to maintain memory bounds
  pruneExpiredTokens();

  // Verify in single-use registry
  const record = tokenStore.get(tokenId);
  if (!record) {
    return {
      valid: false,
      code: 'CONFIRMATION_TOKEN_UNKNOWN',
      reason: 'Confirmation token was not issued by this server.',
    };
  }

  if (record.used) {
    return {
      valid: false,
      code: 'CONFIRMATION_TOKEN_REPLAYED',
      reason: 'Confirmation token has already been used. Replay attacks are prohibited.',
    };
  }

  // Atomically mark token as used
  record.used = true;
  tokenStore.set(tokenId, record);

  return { valid: true };
}

/**
 * Validates deterministic transfer policies prior to preparing or executing a transfer.
 *
 * PRIME INVARIANT: Never trusts client-provided firewall verdict or risk scores.
 * Server re-evaluates all heuristics and policies independently.
 */
export function validateTransferPolicies(params: {
  sourceAccount: string;
  destinationAccount: string;
  amount: number;
  memo: string;
  rawInput?: string;
  accounts: Map<string, FictionalAccount>;
}): PolicyValidationResult {
  const { sourceAccount, destinationAccount, amount, memo, rawInput, accounts } = params;

  // 0. Server-Side Signing Secret Security Check (Fail closed if secret missing or insecure)
  const secretStatus = validateConfirmationSecret();
  if (!secretStatus.secure) {
    return {
      valid: false,
      code: 'SIGNING_SECRET_INSECURE',
      reason: `Transfers are safely disabled: ${secretStatus.reason}`,
    };
  }

  // 1. Amount validation
  if (!Number.isFinite(amount) || isNaN(amount)) {
    return {
      valid: false,
      code: 'INVALID_AMOUNT_NON_FINITE',
      reason: 'Transfer amount must be a finite numerical value.',
    };
  }

  if (amount <= 0) {
    return {
      valid: false,
      code: 'INVALID_AMOUNT_NON_POSITIVE',
      reason: 'Transfer amount must be strictly greater than $0.00.',
    };
  }

  // Sub-cent fractional precision guard (maximum 2 decimal places)
  if (Math.round(amount * 100) !== Number((amount * 100).toFixed(6))) {
    return {
      valid: false,
      code: 'INVALID_AMOUNT_PRECISION',
      reason: 'Transfer amount cannot contain fractional sub-cent values.',
    };
  }

  // 2. Account identity validation
  if (sourceAccount === destinationAccount) {
    return {
      valid: false,
      code: 'IDENTICAL_SOURCE_DESTINATION',
      reason: 'Source and destination accounts must be distinct.',
    };
  }

  const src = accounts.get(sourceAccount);
  if (!src) {
    return {
      valid: false,
      code: 'SOURCE_ACCOUNT_NOT_FOUND',
      reason: `Source account ${sourceAccount} does not exist in the fictional ledger.`,
    };
  }

  const dest = accounts.get(destinationAccount);
  if (!dest) {
    return {
      valid: false,
      code: 'DESTINATION_ACCOUNT_NOT_FOUND',
      reason: `Destination account ${destinationAccount} does not exist in the fictional ledger.`,
    };
  }

  if (src.status !== 'ACTIVE') {
    return {
      valid: false,
      code: 'SOURCE_ACCOUNT_FROZEN',
      reason: `Source account ${sourceAccount} is frozen and cannot initiate transfers.`,
    };
  }

  if (dest.status !== 'ACTIVE') {
    return {
      valid: false,
      code: 'DESTINATION_ACCOUNT_FROZEN',
      reason: `Destination account ${destinationAccount} is frozen and cannot accept transfers.`,
    };
  }

  // 3. Balance & Daily limit checks
  if (src.balance < amount) {
    return {
      valid: false,
      code: 'INSUFFICIENT_FUNDS',
      reason: `Insufficient funds in ${sourceAccount}. Available balance: $${src.balance.toFixed(
        2
      )}, requested: $${amount.toFixed(2)}.`,
    };
  }

  if (amount > src.dailyLimit) {
    return {
      valid: false,
      code: 'TRANSFER_LIMIT_EXCEEDED',
      reason: `Transfer amount ($${amount.toFixed(
        2
      )}) exceeds configured daily transaction limit of $${src.dailyLimit.toFixed(
        2
      )} for ${sourceAccount}.`,
    };
  }

  // 4. Server-Side Firewall Re-Evaluation (Independent Verification)
  // Re-evaluates both user text and payment memo
  const textToCheck = rawInput
    ? `${rawInput} Memo: ${memo}`
    : `Transfer $${amount} from ${sourceAccount} to ${destinationAccount}. Memo: ${memo}`;

  const firewallVerdict = analyzeInputWithHeuristics(textToCheck);

  if (firewallVerdict.verdict === 'BLOCKED') {
    return {
      valid: false,
      code: 'FIREWALL_SECURITY_BLOCK',
      reason: `Firewall blocked transfer input: ${firewallVerdict.explanation}`,
      details: { threatCategories: firewallVerdict.threatCategories, signals: firewallVerdict.signals },
    };
  }

  if (firewallVerdict.verdict === 'AMBIGUOUS') {
    return {
      valid: false,
      code: 'FIREWALL_AMBIGUITY_BLOCK',
      reason: `Firewall flagged transfer as ambiguous: ${firewallVerdict.explanation}`,
      details: { threatCategories: firewallVerdict.threatCategories },
    };
  }

  // 5. Conflicting or ambiguous recipient directives in payment memo
  // Legitimate memos may reference accounts passively (e.g. "Invoice for ACCT-CHECKING-101",
  // "Split bill with ACCT-SAVINGS-202"). Only explicit transfer/redirection directives
  // targeting an account conflicting with destinationAccount or conflicting with each other are rejected.
  const EXPLICIT_DIRECTIVE_PATTERNS = [
    // "send/transfer/pay/credit/deposit/wire/remit/forward/redirect/route [funds/money] to/into ACCT-..."
    /(?:(?:send|transfer|pay|credit|deposit|wire|remit|forward|redirect|route)\s+(?:funds\s+|money\s+)?(?:to|into)\s+)(ACCT-[A-Z0-9-]+)/gi,
    // "pay/credit/deposit ACCT-..."
    /\b(?:pay|credit|deposit)\s+(ACCT-[A-Z0-9-]+)\b/gi,
    // "recipient / beneficiary / destination: ACCT-..."
    /\b(?:recipient|beneficiary|dest(?:ination)?)\s*[:=]\s*(ACCT-[A-Z0-9-]+)\b/gi,
    // "payment/transfer/funds for ACCT-... instead"
    /\b(?:payment|transfer|funds|money)\s+for\s+(ACCT-[A-Z0-9-]+)\s+instead\b/gi,
    // "instead to ACCT-..." or "instead send/pay to ACCT-..."
    /\binstead\s+(?:to\s+|send\s+to\s+|pay\s+to\s+|pay\s+)(ACCT-[A-Z0-9-]+)\b/gi,
    // "send/pay/transfer ACCT-... instead"
    /\b(?:send|pay|transfer)\s+(ACCT-[A-Z0-9-]+)\s+instead\b/gi,
    // "change recipient/destination to ACCT-..."
    /\b(?:change\s+(?:recipient|destination)\s+to\s+)(ACCT-[A-Z0-9-]+)\b/gi,
  ];

  const directedRecipients = new Set<string>();
  for (const regex of EXPLICIT_DIRECTIVE_PATTERNS) {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(memo)) !== null) {
      if (match[1]) {
        directedRecipients.add(match[1].toUpperCase());
      }
    }
  }

  // Also catch if the memo is solely an isolated account identifier that differs from destination
  const trimmedMemo = memo.trim();
  if (/^ACCT-[A-Z0-9-]+$/i.test(trimmedMemo)) {
    directedRecipients.add(trimmedMemo.toUpperCase());
  }

  // If the memo directs funds to multiple conflicting accounts, fail-closed on ambiguity
  if (directedRecipients.size > 1) {
    return {
      valid: false,
      code: 'AMBIGUOUS_RECIPIENT_IN_MEMO',
      reason: `Payment memo contains multiple conflicting destination directives (${Array.from(directedRecipients).join(', ')}).`,
    };
  }

  // If the memo explicitly directs payment to a recipient differing from requested destination
  if (directedRecipients.size === 1) {
    const [directedAccount] = Array.from(directedRecipients);
    if (directedAccount !== destinationAccount.toUpperCase()) {
      return {
        valid: false,
        code: 'CONTRADICTORY_RECIPIENT_IN_MEMO',
        reason: `Payment memo specifies destination ${directedAccount} which contradicts requested recipient ${destinationAccount}.`,
      };
    }
  }

  return { valid: true };
}
