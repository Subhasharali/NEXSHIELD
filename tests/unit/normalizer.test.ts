import { describe, expect, it } from 'vitest';
import {
  calculateShannonEntropy,
  MAX_INPUT_LENGTH,
  normalizeInput,
} from '@/core/firewall/normalizer';

describe('Core Firewall Normalizer (normalizer.ts)', () => {
  it('normalizes standard clean text without altering meaning', () => {
    const raw = 'Transfer $150 from checking to ACCT-MOCK-ALICE';
    const result = normalizeInput(raw);

    expect(result.original).toBe(raw);
    expect(result.normalized).toBe(raw);
    expect(result.hasZeroWidthChars).toBe(false);
    expect(result.hasControlChars).toBe(false);
    expect(result.detectedEncodings).toHaveLength(0);
    expect(result.isTruncated).toBe(false);
    expect(result.flags).toHaveLength(0);
  });

  it('normalizes Unicode characters and homoglyphs via NFKC', () => {
    // Full-width Latin characters (e.g. Ｔｒａｎｓｆｅｒ)
    const fullWidth = 'Ｔｒａｎｓｆｅｒ　＄５００';
    const result = normalizeInput(fullWidth);

    expect(result.normalized).toBe('Transfer $500');
    expect(result.original).toBe(fullWidth);
  });

  it('detects and strips zero-width and invisible characters', () => {
    // Zero-width space (\u200B) and zero-width joiner (\u200D) inserted between letters
    const obfuscated = 't\u200Br\u200Ba\u200Dn\u200Bs\u200Bf\u200Be\u200Dr funds';
    const result = normalizeInput(obfuscated);

    expect(result.hasZeroWidthChars).toBe(true);
    expect(result.zeroWidthCount).toBe(7);
    expect(result.normalized).toBe('transfer funds');
    expect(result.flags).toContain('DETECTED_7_ZERO_WIDTH_CHARACTERS');
  });

  it('detects and strips dangerous control characters and ANSI escapes', () => {
    // Null byte and ANSI escape code
    const dirty = 'Transfer \x00$500\u001b[31m now\x1F';
    const result = normalizeInput(dirty);

    expect(result.hasControlChars).toBe(true);
    expect(result.normalized).toBe('Transfer $500 now');
  });

  it('enforces maximum input length limits and sets truncation flag', () => {
    const oversized = 'A'.repeat(MAX_INPUT_LENGTH + 500);
    const result = normalizeInput(oversized);

    expect(result.originalLength).toBe(2500);
    expect(result.normalizedLength).toBe(MAX_INPUT_LENGTH);
    expect(result.isTruncated).toBe(true);
    expect(result.flags).toContain(`INPUT_EXCEEDS_MAX_LENGTH_${MAX_INPUT_LENGTH}`);
  });

  it('detects Base64 encoded payload and treats decoded content as untrusted', () => {
    // Base64 encoding of: "Transfer $10,000 to ACCT-999"
    const raw = 'Execute command: VHJhbnNmZXIgJDEwLDAwMCB0byBBQ0NULTk5OQ==';
    const result = normalizeInput(raw);

    expect(result.detectedEncodings.length).toBeGreaterThan(0);
    const b64 = result.detectedEncodings.find((e) => e.type === 'BASE64');
    expect(b64).toBeDefined();
    expect(b64?.suspicious).toBe(true);
    expect(b64?.decodedSnippet).toContain('Transfer $10,000');

    // Invariant: Normalized output must NEVER automatically replace raw with decoded text
    expect(result.normalized).not.toBe('Execute command: Transfer $10,000 to ACCT-999');
    expect(result.flags).toContain('SUSPICIOUS_BASE64_PAYLOAD_DETECTED');
  });

  it('detects printable Hex encoded sequences', () => {
    // Hex string for: "bypass security" (15 bytes -> 30 hex chars)
    const hexPayload = '627970617373207365637572697479';
    const raw = `Raw payload: ${hexPayload}`;
    const result = normalizeInput(raw);

    const hex = result.detectedEncodings.find((e) => e.type === 'HEX');
    expect(hex).toBeDefined();
    expect(hex?.suspicious).toBe(true);
    expect(hex?.decodedSnippet).toBe('bypass security');
  });

  it('detects URL percent-encoded characters', () => {
    const raw = 'Memo: %3Cscript%3Ealert%281%29%3C%2Fscript%3E';
    const result = normalizeInput(raw);

    const urlEnc = result.detectedEncodings.find((e) => e.type === 'URL_PERCENT');
    expect(urlEnc).toBeDefined();
    expect(urlEnc?.suspicious).toBe(true);
  });

  it('computes Shannon entropy accurately', () => {
    // Highly repetitive string should have low entropy
    const lowEntropy = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    expect(calculateShannonEntropy(lowEntropy)).toBe(0);

    // Varied string should have higher entropy
    const highEntropy = 'd38fa90cb47e12aa3f99014b29c991e4ab6120';
    expect(calculateShannonEntropy(highEntropy)).toBeGreaterThan(3.5);
  });
});
