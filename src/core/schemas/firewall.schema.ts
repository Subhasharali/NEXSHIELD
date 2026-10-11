import { z } from 'zod';

/**
 * Threat categories recognized by the deterministic firewall.
 */
export const ThreatCategorySchema = z.enum([
  'DIRECT_PROMPT_INJECTION',
  'SYSTEM_OVERRIDE',
  'JAILBREAK_ATTEMPT',
  'INDIRECT_MEMO_INJECTION',
  'OBFUSCATION_EVASION',
  'UNAUTHORIZED_ACTION',
  'DATA_EXFILTRATION',
  'SUSPICIOUS_ENCODING',
  'MALFORMED_INPUT',
  'AMBIGUOUS_REQUEST',
  'NONE',
]);

export type ThreatCategory = z.infer<typeof ThreatCategorySchema>;

/**
 * Severity level of an individual heuristic signal.
 */
export const SeveritySchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

export type Severity = z.infer<typeof SeveritySchema>;

/**
 * Firewall verdict outcome.
 * IMPORTANT: 'ALLOW' indicates no heuristic threats were detected during analysis.
 * In accordance with AGENTS.md Prime Security Invariants, 'ALLOW' is advisory only
 * and NEVER authorizes a fund transfer directly.
 */
export const FirewallVerdictSchema = z.enum([
  'ALLOW', // Clean input, no heuristic threat detected
  'BLOCKED', // Threat signature matched; transaction must halt
  'FLAGGED', // Suspicious pattern detected; requires secondary manual review
  'AMBIGUOUS', // Ambiguous or conflicting intent parameters; fail-closed
]);

export type FirewallVerdict = z.infer<typeof FirewallVerdictSchema>;

/**
 * Details of encoded or obfuscated content detected in the input payload.
 * Crucial Invariant: Decoded content is NEVER trusted.
 */
export const DetectedEncodingSchema = z.object({
  type: z.enum(['BASE64', 'HEX', 'URL_PERCENT', 'UNICODE_ESCAPE']),
  raw: z.string(),
  decodedSnippet: z.string().optional(),
  suspicious: z.boolean(),
  reason: z.string(),
});

export type DetectedEncoding = z.infer<typeof DetectedEncodingSchema>;

/**
 * Structured output from normalizer and anti-obfuscation pipeline.
 */
export const NormalizedInputSchema = z.object({
  original: z.string(),
  normalized: z.string(),
  hasZeroWidthChars: z.boolean(),
  zeroWidthCount: z.number().int().nonnegative(),
  hasControlChars: z.boolean(),
  controlCharCount: z.number().int().nonnegative(),
  detectedEncodings: z.array(DetectedEncodingSchema),
  originalLength: z.number().int().nonnegative(),
  normalizedLength: z.number().int().nonnegative(),
  isTruncated: z.boolean(),
  entropy: z.number().nonnegative(),
  flags: z.array(z.string()),
});

export type NormalizedInput = z.infer<typeof NormalizedInputSchema>;

/**
 * Structured heuristic signal providing explainable evidence.
 */
export const HeuristicSignalSchema = z.object({
  id: z.string(),
  rule: z.string(),
  category: ThreatCategorySchema,
  severity: SeveritySchema,
  evidence: z.string(),
  description: z.string(),
});

export type HeuristicSignal = z.infer<typeof HeuristicSignalSchema>;

/**
 * Complete deterministic firewall analysis result.
 */
export const FirewallAnalysisResultSchema = z.object({
  verdict: FirewallVerdictSchema,
  riskScore: z.number().min(0).max(1),
  threatCategories: z.array(ThreatCategorySchema),
  signals: z.array(HeuristicSignalSchema),
  normalizedInput: NormalizedInputSchema,
  explanation: z.string(),
  evaluatedAt: z.string(),
  evaluator: z.literal('deterministic_heuristics_v1'),
  isAdvisoryOnly: z.literal(true),
});

export type FirewallAnalysisResult = z.infer<typeof FirewallAnalysisResultSchema>;

/**
 * Request payload schema for POST /api/firewall.
 */
export const FirewallInspectRequestSchema = z.object({
  input: z
    .string({
      required_error: 'Field "input" is required in request body',
      invalid_type_error: 'Field "input" must be a string',
    })
    .min(1, 'Input text cannot be empty')
    .max(2000, 'Input exceeds maximum allowed length of 2000 characters'),
});

export type FirewallInspectRequest = z.infer<typeof FirewallInspectRequestSchema>;

/**
 * Risk level classification for UI rendering and alert levels.
 */
export const RiskLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

/**
 * Helper to derive RiskLevel from numeric risk score.
 */
export function getRiskLevelFromScore(score: number): RiskLevel {
  if (score >= 0.85) return 'CRITICAL';
  if (score >= 0.6) return 'HIGH';
  if (score >= 0.3) return 'MEDIUM';
  return 'LOW';
}

/**
 * Enhanced API response schema for /api/firewall.
 */
export const FirewallApiResponseSchema = FirewallAnalysisResultSchema.extend({
  riskLevel: RiskLevelSchema,
  executionNotice: z.string(),
});

export type FirewallApiResponse = z.infer<typeof FirewallApiResponseSchema>;
