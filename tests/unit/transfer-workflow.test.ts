import { beforeEach, describe, expect, it } from 'vitest';
import { GET, POST } from '@/app/api/transfer/route';
import { globalLedger } from '@/core/banking/ledger';

function createJsonRequest(body: unknown): Request {
  return new Request('http://localhost:3000/api/transfer', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

describe('Milestone 4: Transfer API & Workflow Integration Tests', () => {
  beforeEach(() => {
    globalLedger.reset();
  });

  describe('Authoritative Account & Balance Retrieval (GET /api/transfer)', () => {
    it('returns authoritative fictional accounts, balances, and security headers', async () => {
      const res = await GET();
      expect(res.status).toBe(200);

      expect(res.headers.get('Cache-Control')).toContain('no-store');
      expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');

      const data = await res.json();
      expect(Array.isArray(data.accounts)).toBe(true);
      expect(data.accounts.length).toBeGreaterThanOrEqual(6);

      const checking = data.accounts.find((a: { id: string }) => a.id === 'ACCT-CHECKING-101');
      expect(checking).toBeDefined();
      expect(checking.balance).toBe(4500.0);
      expect(checking.currency).toBe('USD');

      // Verify all accounts are synthetic
      for (const acc of data.accounts) {
        expect(acc.id).toMatch(/^ACCT-[A-Z0-9-]+$/);
      }
    });
  });

  describe('Cancellation Workflow (Human Discards / Cancels Review)', () => {
    it('leaves balances strictly unchanged when transfer preparation is abandoned without confirmation', async () => {
      // Step 1: Initial authoritative balance check
      const initialGetRes = await GET();
      const initialData = await initialGetRes.json();
      const initialChecking = initialData.accounts.find((a: { id: string }) => a.id === 'ACCT-CHECKING-101');
      const initialAlice = initialData.accounts.find((a: { id: string }) => a.id === 'ACCT-MOCK-ALICE');

      expect(initialChecking.balance).toBe(4500.0);
      const aliceStartingBalance = initialAlice.balance;

      // Step 2: Prepare transfer (server validates policies and issues confirmation token)
      const prepReq = createJsonRequest({
        action: 'prepare',
        sourceAccount: 'ACCT-CHECKING-101',
        destinationAccount: 'ACCT-MOCK-ALICE',
        amount: 850.0,
        memo: 'Payment for consulting invoice #401',
      });
      const prepRes = await POST(prepReq);
      expect(prepRes.status).toBe(200);

      const prepData = await prepRes.json();
      expect(prepData.status).toBe('REQUIRES_CONFIRMATION');
      expect(prepData.confirmationToken).toBeDefined();

      // Step 3: User cancels/abandons in the UI dialog — NO confirm request is dispatched.
      // Now re-fetch authoritative ledger balances.
      const postCancelGetRes = await GET();
      const postCancelData = await postCancelGetRes.json();

      const checkingAfterCancel = postCancelData.accounts.find((a: { id: string }) => a.id === 'ACCT-CHECKING-101');
      const aliceAfterCancel = postCancelData.accounts.find((a: { id: string }) => a.id === 'ACCT-MOCK-ALICE');

      // Invariant: Balances must remain identical to before preparation
      expect(checkingAfterCancel.balance).toBe(4500.0);
      expect(aliceAfterCancel.balance).toBe(aliceStartingBalance);
    });
  });

  describe('Failed Confirmation Scenarios (Tampering, Expiration, Forgery)', () => {
    it('rejects confirmation when client attempts to modify the destination account', async () => {
      // Prepare for ACCT-MOCK-ALICE
      const prepRes = await POST(
        createJsonRequest({
          action: 'prepare',
          sourceAccount: 'ACCT-CHECKING-101',
          destinationAccount: 'ACCT-MOCK-ALICE',
          amount: 250.0,
          memo: 'Gift',
        })
      );
      const prepData = await prepRes.json();

      // Attacker attempts to switch destination to ACCT-MOCK-BOB with the same token
      const tamperedRes = await POST(
        createJsonRequest({
          action: 'confirm',
          confirmationToken: prepData.confirmationToken,
          userConfirmed: true,
          sourceAccount: 'ACCT-CHECKING-101',
          destinationAccount: 'ACCT-MOCK-BOB', // Swapped!
          amount: 250.0,
          memo: 'Gift',
        })
      );

      expect(tamperedRes.status).toBe(403);
      const tamperedData = await tamperedRes.json();
      expect(tamperedData.code).toBe('CONFIRMATION_TOKEN_TAMPERED');

      // Balances must not be altered
      const getRes = await GET();
      const data = await getRes.json();
      const checking = data.accounts.find((a: { id: string }) => a.id === 'ACCT-CHECKING-101');
      expect(checking.balance).toBe(4500.0);
    });

    it('rejects confirmation with an expired token and preserves balances', async () => {
      // Create a token with past expiry
      const expiredTimestamp = Date.now() - 5000;
      const expiredToken = `tok-simulated-expired.${expiredTimestamp}.invalidsig`;

      const confirmRes = await POST(
        createJsonRequest({
          action: 'confirm',
          confirmationToken: expiredToken,
          userConfirmed: true,
          sourceAccount: 'ACCT-CHECKING-101',
          destinationAccount: 'ACCT-MOCK-ALICE',
          amount: 100.0,
          memo: 'Late transfer',
        })
      );

      expect(confirmRes.status).toBe(403);
      const confirmData = await confirmRes.json();
      expect(confirmData.code).toBe('CONFIRMATION_TOKEN_EXPIRED');

      // Balance check
      const getRes = await GET();
      const data = await getRes.json();
      const checking = data.accounts.find((a: { id: string }) => a.id === 'ACCT-CHECKING-101');
      expect(checking.balance).toBe(4500.0);
    });

    it('rejects confirmation with an unverified forged token string', async () => {
      const forgedToken = `fake-token.${Date.now() + 100000}.invalidhmacsignature`;

      const confirmRes = await POST(
        createJsonRequest({
          action: 'confirm',
          confirmationToken: forgedToken,
          userConfirmed: true,
          sourceAccount: 'ACCT-CHECKING-101',
          destinationAccount: 'ACCT-MOCK-ALICE',
          amount: 50.0,
        })
      );

      expect(confirmRes.status).toBe(403);
      const confirmData = await confirmRes.json();
      expect(confirmData.code).toBe('CONFIRMATION_TOKEN_TAMPERED');
    });
  });

  describe('Repeated Submission & Replay Attack Prevention', () => {
    it('strictly prevents duplicate submissions using an already consumed confirmation token', async () => {
      // 1. Prepare
      const prepRes = await POST(
        createJsonRequest({
          action: 'prepare',
          sourceAccount: 'ACCT-CHECKING-101',
          destinationAccount: 'ACCT-MOCK-ALICE',
          amount: 500.0,
          memo: 'First payment',
        })
      );
      const prepData = await prepRes.json();
      const token = prepData.confirmationToken;

      const confirmPayload = {
        action: 'confirm',
        confirmationToken: token,
        userConfirmed: true,
        sourceAccount: 'ACCT-CHECKING-101',
        destinationAccount: 'ACCT-MOCK-ALICE',
        amount: 500.0,
        memo: 'First payment',
      };

      // 2. First submission — succeeds
      const firstRes = await POST(createJsonRequest(confirmPayload));
      expect(firstRes.status).toBe(200);
      const firstData = await firstRes.json();
      expect(firstData.status).toBe('COMPLETED');
      expect(firstData.remainingBalance).toBe(4000.0);

      // 3. Repeated submission with the SAME token — must fail
      const secondRes = await POST(createJsonRequest(confirmPayload));
      expect(secondRes.status).toBe(403);
      const secondData = await secondRes.json();
      expect(secondData.code).toBe('CONFIRMATION_TOKEN_REPLAYED');
      expect(secondData.details).toContain('already been used');

      // 4. Verify balance is NOT deducted twice
      const getRes = await GET();
      const data = await getRes.json();
      const checking = data.accounts.find((a: { id: string }) => a.id === 'ACCT-CHECKING-101');
      expect(checking.balance).toBe(4000.0); // Exactly 4500 - 500, NOT 3500!
    });
  });

  describe('Authoritative Balance Synchronization Across Consecutive Transfers', () => {
    it('accurately updates balances and audit ledger across multiple consecutive transfers', async () => {
      // Transfer 1: $1000 from Checking to Savings
      const prep1 = await (
        await POST(
          createJsonRequest({
            action: 'prepare',
            sourceAccount: 'ACCT-CHECKING-101',
            destinationAccount: 'ACCT-SAVINGS-202',
            amount: 1000.0,
            memo: 'Move to savings',
          })
        )
      ).json();

      const conf1 = await (
        await POST(
          createJsonRequest({
            action: 'confirm',
            confirmationToken: prep1.confirmationToken,
            userConfirmed: true,
            sourceAccount: 'ACCT-CHECKING-101',
            destinationAccount: 'ACCT-SAVINGS-202',
            amount: 1000.0,
            memo: 'Move to savings',
          })
        )
      ).json();

      expect(conf1.status).toBe('COMPLETED');
      expect(conf1.remainingBalance).toBe(3500.0);

      // Transfer 2: $500 from Savings to Alice
      const prep2 = await (
        await POST(
          createJsonRequest({
            action: 'prepare',
            sourceAccount: 'ACCT-SAVINGS-202',
            destinationAccount: 'ACCT-MOCK-ALICE',
            amount: 500.0,
            memo: 'Gift from savings',
          })
        )
      ).json();

      const conf2 = await (
        await POST(
          createJsonRequest({
            action: 'confirm',
            confirmationToken: prep2.confirmationToken,
            userConfirmed: true,
            sourceAccount: 'ACCT-SAVINGS-202',
            destinationAccount: 'ACCT-MOCK-ALICE',
            amount: 500.0,
            memo: 'Gift from savings',
          })
        )
      ).json();

      expect(conf2.status).toBe('COMPLETED');

      // Fetch authoritative state from GET /api/transfer
      const ledgerRes = await GET();
      const ledgerData = await ledgerRes.json();

      const checking = ledgerData.accounts.find((a: { id: string }) => a.id === 'ACCT-CHECKING-101');
      const savings = ledgerData.accounts.find((a: { id: string }) => a.id === 'ACCT-SAVINGS-202');
      const alice = ledgerData.accounts.find((a: { id: string }) => a.id === 'ACCT-MOCK-ALICE');

      // Checking: 4500 - 1000 = 3500
      expect(checking.balance).toBe(3500.0);
      // Savings: initial 12800 + 1000 - 500 = 13300
      expect(savings.balance).toBe(13300.0);
      // Alice: initial 750 + 500 = 1250
      expect(alice.balance).toBe(1250.0);

      // Verify audit events log
      expect(ledgerData.auditEvents.length).toBeGreaterThanOrEqual(4);
      expect(ledgerData.transferRecords.length).toBe(2);
    });
  });
});
