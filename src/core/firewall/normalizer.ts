import {
  DetectedEncoding,
  NormalizedInput,
  NormalizedInputSchema,
} from '../schemas/firewall.schema';

export const MAX_INPUT_LENGTH = 2000;

// Regex matching zero-width, invisible, and bidirectional override characters
const ZERO_WIDTH_REGEX =
  /[\u200B-\u200D\uFEFF\u2060\u180E\u200E\u200F\u202A-\u202E\u2066-\u2069\u00AD]/g;

// Regex matching suspicious control characters (excluding standard whitespace \t, \n, \r)
const SUSPICIOUS_CONTROL_REGEX = /[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g;

// Regex matching ANSI escape sequences
const ANSI_ESCAPE_REGEX = /\u001b\[[0-9;]*[a-zA-Z]/g;

// Regex for candidate Base64 strings (minimum 12 chars: 3 blocks of 4)
const BASE64_CANDIDATE_REGEX =
  /(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})/g;

// Regex for candidate Hex strings (16+ hex characters or prefixed hex words)
const HEX_CANDIDATE_REGEX = /(?:0x|\\x)?[0-9a-fA-F]{16,}\b/g;

// Regex for URL percent encoding sequences
const URL_ENCODED_REGEX = /(?:%[0-9a-fA-F]{2}){2,}/g;

/**
 * Calculates Shannon entropy of a string (in bits per character).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

export interface NormalizerOptions {
  maxLength?: number;
}

/**
 * Normalizes untrusted input, strips invisible/zero-width evasion characters,
 * collapses Unicode homoglyphs via NFKC, and analyzes encoding obfuscation.
 *
 * CRITICAL INVARIANT: Decoded content is strictly treated as untrusted and is never
 * substituted in place of input to prevent token smuggling or decoding bypasses.
 */
export function normalizeInput(
  rawInput: string,
  options?: NormalizerOptions
): NormalizedInput {
  const maxLength = options?.maxLength ?? MAX_INPUT_LENGTH;
  const original = rawInput ?? '';
  const originalLength = original.length;
  const flags: string[] = [];

  let isTruncated = false;
  let workingText = original;

  // 1. Strict length enforcement
  if (workingText.length > maxLength) {
    workingText = workingText.slice(0, maxLength);
    isTruncated = true;
    flags.push(`INPUT_EXCEEDS_MAX_LENGTH_${maxLength}`);
  }

  // 2. Detect and count zero-width characters
  const zeroWidthMatches = workingText.match(ZERO_WIDTH_REGEX);
  const zeroWidthCount = zeroWidthMatches ? zeroWidthMatches.length : 0;
  const hasZeroWidthChars = zeroWidthCount > 0;
  if (hasZeroWidthChars) {
    flags.push(`DETECTED_${zeroWidthCount}_ZERO_WIDTH_CHARACTERS`);
  }

  // 3. Detect and count suspicious control characters and ANSI escapes
  const controlMatches = workingText.match(SUSPICIOUS_CONTROL_REGEX);
  const ansiMatches = workingText.match(ANSI_ESCAPE_REGEX);
  const controlCharCount = (controlMatches?.length ?? 0) + (ansiMatches?.length ?? 0);
  const hasControlChars = controlCharCount > 0;
  if (hasControlChars) {
    flags.push(`DETECTED_${controlCharCount}_CONTROL_CHARACTERS`);
  }

  // 4. Strip zero-width and harmful control characters from normalized output
  let sanitized = workingText
    .replace(ANSI_ESCAPE_REGEX, '')
    .replace(ZERO_WIDTH_REGEX, '')
    .replace(SUSPICIOUS_CONTROL_REGEX, '');

  // 5. Unicode NFKC normalization (collapses homoglyphs, accents, styled fonts)
  sanitized = sanitized.normalize('NFKC');

  // Normalize excessive whitespace while preserving single spaces and standard newlines
  sanitized = sanitized.replace(/[ \t]+/g, ' ').trim();

  // 6. Inspect for obfuscated encodings (Base64, Hex, URL-encoded)
  const detectedEncodings: DetectedEncoding[] = [];

  // 6a. Check Base64
  const base64Matches = workingText.match(BASE64_CANDIDATE_REGEX);
  if (base64Matches) {
    for (const match of Array.from(new Set(base64Matches))) {
      try {
        const decoded = Buffer.from(match, 'base64').toString('utf8');
        // Verify printable ASCII density
        const printableCount = decoded
          .split('')
          .filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length;
        const printableRatio = decoded.length > 0 ? printableCount / decoded.length : 0;

        if (printableRatio >= 0.75 && decoded.length >= 8) {
          detectedEncodings.push({
            type: 'BASE64',
            raw: match,
            decodedSnippet: decoded.slice(0, 100),
            suspicious: true,
            reason: 'High-density printable ASCII Base64 payload detected',
          });
          flags.push('SUSPICIOUS_BASE64_PAYLOAD_DETECTED');
        }
      } catch {
        // Not valid Base64
      }
    }
  }

  // 6b. Check Hex
  const hexMatches = workingText.match(HEX_CANDIDATE_REGEX);
  if (hexMatches) {
    for (const match of Array.from(new Set(hexMatches))) {
      try {
        const cleanHex = match.replace(/^(?:0x|\\x)/, '');
        if (cleanHex.length % 2 === 0 && cleanHex.length >= 16) {
          const decoded = Buffer.from(cleanHex, 'hex').toString('utf8');
          const printableCount = decoded
            .split('')
            .filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length;
          const printableRatio = decoded.length > 0 ? printableCount / decoded.length : 0;

          if (printableRatio >= 0.75 && decoded.length >= 8) {
            detectedEncodings.push({
              type: 'HEX',
              raw: match,
              decodedSnippet: decoded.slice(0, 100),
              suspicious: true,
              reason: 'Printable hex encoded byte sequence detected',
            });
            flags.push('SUSPICIOUS_HEX_PAYLOAD_DETECTED');
          }
        }
      } catch {
        // Not valid Hex
      }
    }
  }

  // 6c. Check URL Percent Encoding
  const urlMatches = workingText.match(URL_ENCODED_REGEX);
  if (urlMatches) {
    for (const match of Array.from(new Set(urlMatches))) {
      try {
        const decoded = decodeURIComponent(match);
        if (decoded !== match) {
          detectedEncodings.push({
            type: 'URL_PERCENT',
            raw: match,
            decodedSnippet: decoded.slice(0, 100),
            suspicious: true,
            reason: 'URL percent-encoded character sequence detected',
          });
          flags.push('URL_PERCENT_ENCODING_DETECTED');
        }
      } catch {
        // Malformed percent encoding
      }
    }
  }

  // 7. Calculate Shannon entropy
  const entropy = calculateShannonEntropy(sanitized);
  if (entropy > 4.6 && sanitized.length >= 32 && !sanitized.includes(' ')) {
    flags.push('HIGH_ENTROPY_PACKED_TOKEN');
  }

  const result: NormalizedInput = {
    original,
    normalized: sanitized,
    hasZeroWidthChars,
    zeroWidthCount,
    hasControlChars,
    controlCharCount,
    detectedEncodings,
    originalLength,
    normalizedLength: sanitized.length,
    isTruncated,
    entropy,
    flags,
  };

  return NormalizedInputSchema.parse(result);
}
