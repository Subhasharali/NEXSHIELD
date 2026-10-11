import { FictionalAccount } from '../schemas/transfer.schema';

/**
 * Seed data for 100% fictional synthetic banking accounts.
 *
 * PRIME SECURITY INVARIANT (AGENTS.md):
 * Every account, user, balance, and transaction must be 100% synthetic and fictional.
 * Real bank credentials, routing numbers, or financial APIs are strictly prohibited.
 */
export const INITIAL_ACCOUNTS: Record<string, FictionalAccount> = {
  'ACCT-CHECKING-101': {
    id: 'ACCT-CHECKING-101',
    name: 'Synthetic Primary Checking',
    balance: 4500.0,
    dailyLimit: 5000.0,
    currency: 'USD',
    status: 'ACTIVE',
  },
  'ACCT-SAVINGS-202': {
    id: 'ACCT-SAVINGS-202',
    name: 'Synthetic High-Yield Savings',
    balance: 12800.0,
    dailyLimit: 10000.0,
    currency: 'USD',
    status: 'ACTIVE',
  },
  'ACCT-EMERGENCY-303': {
    id: 'ACCT-EMERGENCY-303',
    name: 'Synthetic Emergency Reserve',
    balance: 25000.0,
    dailyLimit: 1000.0,
    currency: 'USD',
    status: 'ACTIVE',
  },
  'ACCT-MOCK-ALICE': {
    id: 'ACCT-MOCK-ALICE',
    name: 'Synthetic Payee Alice',
    balance: 750.0,
    dailyLimit: 5000.0,
    currency: 'USD',
    status: 'ACTIVE',
  },
  'ACCT-MOCK-BOB': {
    id: 'ACCT-MOCK-BOB',
    name: 'Synthetic Payee Bob',
    balance: 1200.0,
    dailyLimit: 5000.0,
    currency: 'USD',
    status: 'ACTIVE',
  },
  'ACCT-MOCK-UTILITY': {
    id: 'ACCT-MOCK-UTILITY',
    name: 'Synthetic Utility Provider',
    balance: 50000.0,
    dailyLimit: 100000.0,
    currency: 'USD',
    status: 'ACTIVE',
  },
};

/**
 * Creates a fresh deep-copy of the initial fictional accounts map.
 */
export function createDefaultAccounts(): Map<string, FictionalAccount> {
  const map = new Map<string, FictionalAccount>();
  for (const [id, acc] of Object.entries(INITIAL_ACCOUNTS)) {
    map.set(id, { ...acc });
  }
  return map;
}
