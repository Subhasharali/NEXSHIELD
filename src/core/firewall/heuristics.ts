import {
  FirewallAnalysisResult,
  FirewallAnalysisResultSchema,
  FirewallVerdict,
  HeuristicSignal,
  NormalizedInput,
  Severity,
  ThreatCategory,
} from '../schemas/firewall.schema';
import { normalizeInput } from './normalizer';

export interface HeuristicRule {
  id: string;
  name: string;
  category: ThreatCategory;
  severity: Severity;
  description: string;
  test: (
    normalizedText: string,
    rawText: string,
    normalizedData: NormalizedInput
  ) => { matched: boolean; evidence?: string };
}

/**
 * Deterministic heuristic inspection rules.
 * Uses strict syntactic pattern analysis to detect prompt injection,
 * delimiter tampering, jailbreaks, malicious memos, and ambiguous instructions.
 */
export const HEURISTIC_RULES: HeuristicRule[] = [
  // 1. DIRECT PROMPT INJECTION & SYSTEM OVERRIDES
  {
    id: 'SIG-DIR-OVERRIDE',
    name: 'Instruction Override Attempt',
    category: 'DIRECT_PROMPT_INJECTION',
    severity: 'CRITICAL',
    description: 'Attempts to override or ignore previous system instructions or rules',
    test: (norm) => {
      const match = norm.match(
        /\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:prior|previous|above|existing|system)?\s*(?:instructions|directions|rules|prompts|guidelines|safeguards|constraints)\b/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },
  {
    id: 'SIG-SYS-DELIMITER-SPOOF',
    name: 'System Delimiter Spoofing',
    category: 'SYSTEM_OVERRIDE',
    severity: 'CRITICAL',
    description: 'Injects simulated system tags, role markers, or prompt boundaries',
    test: (norm, raw) => {
      const combined = `${norm}\n${raw}`;
      const match = combined.match(
        /(?:\[SYSTEM\]|\[ADMIN\]|\[ASSISTANT\]|\[INSTRUCTION\]|<\|im_start\|>|<\|im_end\|>|<system>|<\/system>|<instruction>|<\/instruction>|---\s*END OF (?:SYSTEM|PROMPT|INSTRUCTION)\s*---)/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },
  {
    id: 'SIG-DEV-MODE-OVERRIDE',
    name: 'Developer/Debug Mode Activation',
    category: 'DIRECT_PROMPT_INJECTION',
    severity: 'CRITICAL',
    description: 'Attempts to force model into unrestricted developer or debug mode',
    test: (norm) => {
      const match = norm.match(
        /\b(?:system override|developer mode(?:\s+enabled|\s+active)?|debug mode(?:\s+on|\s+enabled)?|mode:\s*(?:dev|debug|root|admin))\b/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },

  // 2. JAILBREAK & ROLEPLAY SAFEGUARD BYPASSES
  {
    id: 'SIG-JAILBREAK-PERSONA',
    name: 'Adversarial Persona Jailbreak',
    category: 'JAILBREAK_ATTEMPT',
    severity: 'CRITICAL',
    description: 'Attempts persona simulation to bypass security constraints (e.g. DAN, FreeBankAI)',
    test: (norm) => {
      const match = norm.match(
        /\b(?:you are now (?:freebankai|dan|jailbreak|unrestricted|an ai without (?:safety|constraints|rules))|pretend (?:you have no|there are no) (?:rules|constraints|limits)|do anything now)\b/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },
  {
    id: 'SIG-CONFIRMATION-SUPPRESSION',
    name: 'Verification & Confirmation Suppression',
    category: 'JAILBREAK_ATTEMPT',
    severity: 'HIGH',
    description: 'Attempts to suppress human verification, 2FA, or confirmation steps',
    test: (norm) => {
      const match = norm.match(
        /\b(?:(?:do not|don'?t|skip|bypass|waive|disable)\s+(?:ask for\s+)?(?:additional\s+)?(?:user\s+)?(?:verification|confirmation|2fa|approval)|mark (?:the\s+)?transfer as pre-?approved|pre-?approved transfer)\b/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },
  {
    id: 'SIG-URGENCY-COERCION',
    name: 'Emergency Coercion Social Engineering',
    category: 'JAILBREAK_ATTEMPT',
    severity: 'HIGH',
    description: 'Uses extreme fabricated medical or emotional urgency to coerce bypass',
    test: (norm) => {
      const match = norm.match(
        /\b(?:emergency!?\s+(?:my\s+(?:child|grandmother|family|mother|father)\s+is\s+dying|someone will die)|bypass (?:confirmation|2fa|security)\s+or\s+(?:she|he|they|someone)\s+will die)\b/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },

  // 3. MALICIOUS INSTRUCTIONS IN PAYMENT MEMOS & MULTI-LINE PAYLOADS
  {
    id: 'SIG-MEMO-INDIRECT-INJECTION',
    name: 'Indirect Memo Prompt Injection',
    category: 'INDIRECT_MEMO_INJECTION',
    severity: 'CRITICAL',
    description: 'Embedded secondary directives within payment memos attempting to reroute funds',
    test: (norm) => {
      // Looks for invoice/memo followed by instruction to redirect or empty funds
      const match = norm.match(
        /(?:invoice|bill|memo|dinner|rent|refund)[^\n.]{0,80}(?:\n|\r|;|\/)\s*(?:\[(?:admin|system)\]:?|transfer\s+(?:all\s+)?(?:remaining\s+)?funds|send\s+\$?\d+[\d,.]*\s+to\s+acct-|disregard\s+previous\s+recipient)/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },
  {
    id: 'SIG-UNSAFE-CODE-TAGS',
    name: 'Embedded Script or Markup Tags',
    category: 'INDIRECT_MEMO_INJECTION',
    severity: 'HIGH',
    description: 'Contains HTML, script tags, or code injection vectors',
    test: (norm, raw) => {
      const combined = `${norm} ${raw}`;
      const match = combined.match(/<script\b[^>]*>|<\/script>|javascript:|onerror\s*=/i);
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },

  // 4. SUSPICIOUS OBFUSCATION & ENCODING
  {
    id: 'SIG-ZERO-WIDTH-OBFUSCATION',
    name: 'Zero-Width Character Token Smuggling',
    category: 'OBFUSCATION_EVASION',
    severity: 'HIGH',
    description: 'Input contained invisible zero-width characters used to fragment words',
    test: (_norm, _raw, normalizedData) => {
      if (normalizedData.hasZeroWidthChars && normalizedData.zeroWidthCount >= 3) {
        return {
          matched: true,
          evidence: `Stripped ${normalizedData.zeroWidthCount} zero-width evasion characters`,
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-SUSPICIOUS-BASE64-ENCODING',
    name: 'Suspicious Encoded Payload',
    category: 'SUSPICIOUS_ENCODING',
    severity: 'HIGH',
    description: 'Base64, Hex, or packed binary encoding detected in input',
    test: (_norm, _raw, normalizedData) => {
      const suspicious = normalizedData.detectedEncodings.filter((e) => e.suspicious);
      if (suspicious.length > 0) {
        return {
          matched: true,
          evidence: `${suspicious[0].type} payload: ${suspicious[0].raw.slice(0, 32)}...`,
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-LEETSPEAK-TOKEN-SMUGGLING',
    name: 'Leetspeak Token Smuggling',
    category: 'OBFUSCATION_EVASION',
    severity: 'HIGH',
    description: 'Alphanumeric substitutions attempting to evade keyword detection',
    test: (norm) => {
      const match = norm.match(
        /\b(?:tr[4a]nsf[3e]r|byp[4a]ss|0v[3e]rr[1i]d[3e]|1gn[0o]r[3e]|s[y5]st[3e]m)\b/i
      );
      // Only flag if actual leetspeak substitution exists (e.g. contains 4, 3, 0, 1 in place of letters)
      if (match && /[0-9]/.test(match[0])) {
        return { matched: true, evidence: match[0] };
      }
      return { matched: false };
    },
  },

  // 5. UNAUTHORIZED ACTIONS & DATA EXFILTRATION
  {
    id: 'SIG-SYSTEM-EXFILTRATION',
    name: 'System Prompt or Credential Exfiltration',
    category: 'DATA_EXFILTRATION',
    severity: 'HIGH',
    description: 'Attempts to extract underlying system prompts, instructions, or internal credentials',
    test: (norm) => {
      const match = norm.match(
        /\b(?:reveal|print|show|dump|leak|output)\s+(?:your\s+)?(?:system\s+(?:prompt|instructions)|database(?:\s+schema)?|credentials|env(?:ironment)?\s+variables|all\s+accounts(?:\s+and\s+balances)?)\b/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },

  // 6. AMBIGUOUS & CONTRADICTORY TRANSACTION REQUESTS
  {
    id: 'SIG-AMBIGUOUS-RELATIVE-AMOUNT',
    name: 'Non-Specific Relative Amount',
    category: 'AMBIGUOUS_REQUEST',
    severity: 'MEDIUM',
    description: 'Transfer request uses vague, relative, or undefined funds amounts',
    test: (norm) => {
      const match = norm.match(
        /\b(?:(?:transfer|send|move)\s+(?:half(?:\s+of)?(?:\s+my)?|all(?:\s+of)?(?:\s+my)?|whatever\s+is\s+left(?:\s+in)?)|empty\s+(?:out\s+)?(?:my\s+)?(?:checking|savings|account))\b/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },
  {
    id: 'SIG-AMBIGUOUS-MISSING-DESTINATION',
    name: 'Missing Destination Account',
    category: 'AMBIGUOUS_REQUEST',
    severity: 'MEDIUM',
    description: 'Transfer intent detected but destination account or payee is completely missing',
    test: (norm) => {
      const isTransferAction = /\b(?:transfer|send|move|wire)\s+\$?\d+/i.test(norm);
      const hasDestination = /\b(?:to|into|towards)\s+(?:ACCT-[A-Z0-9-]+|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+|alice|bob|charlie|savings|checking)\b/i.test(
        norm
      );
      if (isTransferAction && !hasDestination) {
        return {
          matched: true,
          evidence: 'Transfer requested with no destination recipient or account specified',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-AMBIGUOUS-MULTI-PARTY',
    name: 'Unresolved Multi-Party Split',
    category: 'AMBIGUOUS_REQUEST',
    severity: 'MEDIUM',
    description: 'Transfer divides funds among multiple recipients without explicit individual amounts',
    test: (norm) => {
      const match = norm.match(
        /\b(?:transfer|send|pay)\s+\$?\d+[\d,.]*\s+to\s+([A-Za-z]+)\s+and\s+([A-Za-z]+)\b/i
      );
      return { matched: !!match, evidence: match ? match[0] : undefined };
    },
  },
];

/**
 * Maps severity levels to base risk score weights.
 */
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 0.95,
  HIGH: 0.75,
  MEDIUM: 0.4,
  LOW: 0.15,
};

export interface HeuristicsOptions {
  maxLength?: number;
}

/**
 * Runs deterministic heuristic inspection across input.
 *
 * CRITICAL INVARIANT: A return of verdict 'ALLOW' indicates no heuristic threats
 * were found. It is an advisory assessment ONLY and never authorizes fund movement.
 */
export function analyzeInputWithHeuristics(
  rawInput: string,
  options?: HeuristicsOptions
): FirewallAnalysisResult {
  const normalizedData = normalizeInput(rawInput, options);
  const normText = normalizedData.normalized;
  const rawText = rawInput ?? '';

  const matchedSignals: HeuristicSignal[] = [];

  for (const rule of HEURISTIC_RULES) {
    const result = rule.test(normText, rawText, normalizedData);
    if (result.matched) {
      matchedSignals.push({
        id: rule.id,
        rule: rule.name,
        category: rule.category,
        severity: rule.severity,
        evidence: result.evidence ?? normText.slice(0, 80),
        description: rule.description,
      });
    }
  }

  // Calculate deterministic risk score
  let riskScore = 0;
  if (matchedSignals.length > 0) {
    const maxWeight = Math.max(...matchedSignals.map((s) => SEVERITY_WEIGHTS[s.severity]));
    const additionalBoost = (matchedSignals.length - 1) * 0.05;
    riskScore = Math.min(1.0, Number((maxWeight + additionalBoost).toFixed(2)));
  }

  // Determine unique threat categories
  const threatCategories: ThreatCategory[] =
    matchedSignals.length > 0
      ? Array.from(new Set(matchedSignals.map((s) => s.category)))
      : ['NONE'];

  // Determine verdict
  let verdict: FirewallVerdict = 'ALLOW';
  const hasCriticalOrHigh = matchedSignals.some(
    (s) => s.severity === 'CRITICAL' || s.severity === 'HIGH'
  );
  const hasAmbiguity = matchedSignals.some((s) => s.category === 'AMBIGUOUS_REQUEST');

  if (hasCriticalOrHigh) {
    verdict = 'BLOCKED';
  } else if (hasAmbiguity) {
    verdict = 'AMBIGUOUS';
  } else if (matchedSignals.length > 0) {
    verdict = 'FLAGGED';
  } else {
    verdict = 'ALLOW';
  }

  // Construct explainable summary
  let explanation = '';
  if (verdict === 'BLOCKED') {
    const topThreat = matchedSignals[0]?.rule ?? 'Threat signature';
    explanation = `Transaction input blocked: ${topThreat} matched. Fund execution prohibited.`;
  } else if (verdict === 'AMBIGUOUS') {
    explanation =
      'Transaction input ambiguous: Destination account or amount parameter is underspecified. Fail-closed enforced.';
  } else if (verdict === 'FLAGGED') {
    explanation = 'Transaction input flagged for secondary inspection due to anomalous patterns.';
  } else {
    explanation =
      'No deterministic heuristic threats detected. Input passed advisory inspection (execution requires policy gate & HITL verification).';
  }

  const analysisResult: FirewallAnalysisResult = {
    verdict,
    riskScore,
    threatCategories,
    signals: matchedSignals,
    normalizedInput: normalizedData,
    explanation,
    evaluatedAt: new Date().toISOString(),
    evaluator: 'deterministic_heuristics_v1',
    isAdvisoryOnly: true,
  };

  return FirewallAnalysisResultSchema.parse(analysisResult);
}
