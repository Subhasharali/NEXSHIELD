# AGENTS.md — NEXSHIELD AI Firewall Project Guidelines

Welcome to **NEXSHIELD** (formerly codenamed Bankism), a blue-team AI firewall designed to protect banking applications against prompt injections, jailbreaks, malicious payment memos, obfuscated attacks, and ambiguous transaction requests.

All autonomous agents and contributors working in this repository **must** strictly adhere to the guidelines, constraints, and security invariants documented below.

---

## 1. Prime Security Invariants (Non-Negotiable)

1. **Fictional Banking Only**:
   - Every account, user, routing number, balance, and transaction must be 100% synthetic and fictional (e.g., `ACCT-CHECKING-101`, `ACCT-SAVINGS-202`).
   - Never reference real bank credentials, real routing numbers, or real individuals' financial data.

2. **Zero External Banking Services**:
   - Never integrate or attempt to connect to live banking networks, real payment gateways, or financial APIs (e.g., Plaid, Stripe, ACH, Fedwire, SWIFT, open-banking endpoints).
   - All accounts and ledgers reside exclusively in-memory or in isolated mock fixtures for simulation and testing.

3. **Server-Side Security Enforcement**:
   - All input validation, obfuscation stripping, heuristic checks, LLM inspection, and transfer gates **must execute on the server** (e.g., Next.js Server Actions or Route Handlers).
   - Client-side code is inherently untrusted. Never rely on client-side validation to guarantee security invariants.

4. **AI Never Authorises Transfers**:
   - The AI/LLM component acts strictly as an **advisory inspector and intent parser**.
   - The AI cannot authorize, finalize, or directly trigger any transaction.
   - All state mutations require deterministic server-side policy verification and explicit human-in-the-loop (HITL) confirmation.

5. **Fail-Closed on Ambiguity or Threat**:
   - Any transaction marked as `BLOCKED` or `AMBIGUOUS` **must never execute**.
   - If an intent lacks exact destination, definite amount, or has conflicting parameters, the engine must halt execution and return a clarification prompt or block reason.

---

## 2. Technology Stack & Tooling

- **Framework**: Next.js 15+ (App Router, Server Actions, Route Handlers)
- **Language**: TypeScript (strict type checking enabled, no implicit `any`)
- **Schema Validation**: Zod (strict schema validation for all inputs, intents, and payloads)
- **Testing**: Vitest (fast, native TypeScript unit & adversarial security test suite)
- **Styling**: Vanilla CSS / CSS Modules with rich, modern design aesthetics (cybersecurity blue-team palette, dark mode, high contrast, smooth transitions)
- **Runtime Environment**: Windows PowerShell (Node.js v24+, npm 11+). **Always invoke `npm.cmd` and `npx.cmd`** in PowerShell to avoid Windows script execution policy restrictions.

---

## 3. Recommended Project Structure

```
nexshield/
├── AGENTS.md                      # Project guidelines and rules (this file)
├── docs/
│   ├── problem-analysis.md        # Threat model and banking AI vulnerability analysis
│   ├── implementation-plan.md     # Architecture design and milestone roadmap
│   └── test-plan.md               # Adversarial and unit test matrix
├── src/
│   ├── app/                       # Next.js App Router pages and API routes
│   │   ├── layout.tsx             # Root layout with modern dark cyber theme
│   │   ├── page.tsx               # Main dashboard: Banking UI + Firewall Inspector
│   │   └── api/
│   │       ├── firewall/route.ts  # Firewall analysis endpoint
│   │       └── transfer/route.ts  # Deterministic transfer execution endpoint
│   ├── core/
│   │   ├── firewall/              # Blue-team firewall engine
│   │   │   ├── normalizer.ts      # De-obfuscation (Unicode, Base64, zero-width)
│   │   │   ├── heuristics.ts      # Pattern-matching for prompt injections & delimiters
│   │   │   ├── evaluator.ts       # AI inspection & semantic risk evaluation
│   │   │   └── decision-engine.ts # Aggregates layers into unified verdict
│   │   ├── banking/               # Fictional banking mock domain
│   │   │   ├── accounts.ts        # Synthetic accounts & seed data
│   │   │   ├── ledger.ts          # Deterministic state machine & transfer logic
│   │   │   └── policies.ts        # Invariants (limits, funds, HITL verification)
│   │   └── schemas/               # Zod validation schemas
│   │       ├── firewall.schema.ts # Payloads, verdicts, and telemetry types
│   │       └── transfer.schema.ts # Transfer requests and intent representations
│   └── components/                # Reusable UI components
│       ├── BankingApp/            # Transfer form, memo field, account balances
│       ├── FirewallMonitor/       # Live inspection pipeline telemetry & layer breakdown
│       ├── AttackPresets/         # Interactive red-team exploit simulations
│       └── AuditLog/              # Real-time firewall security events log
├── tests/
│   ├── unit/                      # Normalizers, heuristics, ledger invariants
│   ├── adversarial/               # Prompt injections, jailbreaks, obfuscation tests
│   └── fixtures/                  # Synthetic attack datasets and safe payloads
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── .gitignore
```

---

## 4. Development & Workflow Conventions

1. **Deterministic Core Logic**: Keep firewall normalizers, heuristics, and ledger state machines independent of external I/O so they can be unit-tested in isolation in milliseconds.
2. **Schema-First Design**: Define Zod schemas before writing business logic or API endpoints.
3. **No Overwriting Without Explanation**: When altering existing files, always provide clear rationale for modifications.
4. **Adversarial Test First**: Whenever introducing a new detection rule or guardrail, add a corresponding test case in `tests/adversarial/` proving the attack is blocked and legitimate transfers remain unblocked (false-positive prevention).
5. **No Placeholders**: Write fully typed, working implementations with realistic fixtures rather than dummy comments or `// TODO` stubs.
