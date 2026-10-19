# Bank8:FDX - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Bank8:FDX **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Bank8:FDX is the **open-banking data exchange** of the bank8 vertical -
the consent authority between the bank (data provider) and registered
third-party data recipients. The two parties are **independent
organizations**: a recipient may be another bank, a fintech company,
or an aggregator running on any technology - the platform a recipient
runs on is invisible to the consent contract. The ONLY contract
between the two institutions is the authorization server's: the
recipient registers as an OAuth client at the bank's auth server
(Sentin8:Auth when the bank runs Sentin8, or the bank's existing
third-party AS), the customer grants consent through that AS's
ceremony, and the recipient reads data over the bank's public FDX
API with the tokens the AS issued. **Each institution keeps its own
records - the bank keeps the grant, the fintech keeps its
connections.** The bank is the party that must capture, enforce,
revoke, and audit every grant (open-banking data-holder obligations),
so the grant record lives in the bank's own environment and is
created by the bank's own software from the authorization server's
grant event - never written by the fintech. The fintech keeps its own
connection registry (which of its customers connected which bank,
under which scopes, and the tokens it holds as the OAuth client) in
its own environment. No shared database, no cross-institution table
access - the two records stay in step because both are driven by the
same OAuth ceremony. It delivers:

- **Customer-controlled data sharing** - account and transaction data is
  shared with a third party only under a live, scope-limited, expiring,
  revocable consent the customer granted; every read is attributable to
  that grant.
- **Standards-based provider API** - a complete FDX v6.5 data-provider
  surface (`/fdx/v6/*`) that registered fintechs/aggregators can integrate
  against without bespoke agreements per endpoint.
- **Privacy by construction (CSDF)** - responses carry exactly the data
  clusters the customer consented to; anything outside the grant is
  stripped before it leaves the bank, not filtered by the recipient's
  goodwill.
- **Money-movement surfaces under consent** - transfers, payments, payees,
  recurring payments, and payment-initiation-party registration, all
  consent-gated and executed through Bank8:Payments.
- **A trust-worthy recipient onboarding** - recipients register their
  OAuth client dynamically at the bank's authorization server
  (RFC 7591 DCR), tokens are sender-constrained (DPoP),
  and no provider credential is ever stored in plaintext.
- **Event notifications** - subscribed recipients are told when consented
  data changes (HMAC-signed webhooks with retry), instead of polling the
  bank into the ground.
- **A hosted consent experience** - the customer approves or denies a
  consent inside the bank's own hosted consent screens, so the brand and
  the compliance story stay with the bank.

## 2. Business Scope (What the Service Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | Consents | Consent grants with data clusters, duration windows, introspection-based refresh, revocation with reasons |
| 2 | Provider account data | Consented reads of accounts, transactions, statements (download via signed URLs), payment networks |
| 3 | Provider customer data | Consented customer/current-customer reads |
| 4 | Provider money movement | Transfers (create/read/update/cancel), payments, payees (create/read/update), recurring payments |
| 5 | Payment initiation parties (PIP) | PIP registration with payment-method registration/removal |
| 6 | Payment network revocation | Per-account, per-network consent revocations |
| 7 | Recipient connections | The fintech's own registry of its customers' bank connections: start a consent at any listed provider, display active connections, refresh and revoke them |
| 8 | Notification subscriptions | Recipient callback subscriptions with event filters + HMAC-signed delivery and retry |
| 9 | Recipient surfaces | Provider discovery, consent start/list/detail/refresh/revoke, consented account + transaction reads, notifications - the API eFinTech-style recipient apps consume |
| 10 | Hosted consent UI | Approve/deny consent screens (RFW) served inside the platform's OAuth flow |
| 11 | Discovery | Capability, availability, certification metrics, and operation-support endpoints for recipients |
| 12 | Audit | Every provider data call recorded (`data_call*` actions); certification metrics computed from the trail |
| 13 | Admin console | Remote admin pages: overview, provider, recipients, consents, CSDF, settings (+ policy pages) |
| 14 | Domain events | 16 outbound event types on the `bank8:fdx:*` family |
| 15 | Health | Service health endpoint for fleet supervision |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Account/transaction data at rest (the record of truth) | Bank8:Ledger (FDX reads it via the public API) |
| Statement documents at rest | Sentin8:Storage (FDX hands out signed download URLs) |
| Recipient identities & OAuth token issuance | the provider's authorization server (Sentin8:Auth when the bank runs Sentin8; the recipient is an OAuth client THERE - FDX never proxies or mints identities) |
| Money movement execution | Bank8:Payments (FDX surfaces consented initiation; Payments executes) |
| Secrets/token plaintext storage | Sentin8:Secrets (FDX stores only references) |
| Workflow step execution engine | Sentin8:Flow (FDX implements its step profile) |
| Event transport & consumer delivery | Sentin8:Bus (FDX produces; recipients' webhooks are FDX's delivery worker) |
| API proxying to bank client apps | Sentin8:BFF |

## 3. Business Capabilities

### 3.1 Consents (the core asset)

| Capability | Business rule |
|---|---|
| Grant a consent | The customer grants a recipient access to specific data clusters for specific accounts, with an explicit duration model |
| Duration model | FDX-standard: `ONE_TIME` (single use, no window), `PERSISTENT` (open-ended until revoked), or `TIME_BOUND` (requires a `durationPeriod` in days > 0). Setting a duration on a one-time/persistent consent - or omitting it on a time-bound one - is rejected |
| Lookback window | A consent may carry a `lookbackPeriodDays` limiting how far back historical data is requestable from the request time |
| Scope limitation | A consent covers only what the customer selected - cluster-by-cluster, account-by-account |
| Expiry | Consents expire by their duration window; expiry is enforced from live introspection, never from a stale cache |
| Refresh | Consent windows can be refreshed through the recipient surface (re-introspection), extending validity without re-consent where policy allows |
| Revoke | The customer (or the bank) can revoke at any time; the reason (with optional free-text `otherReason`) and initiator are recorded in an immutable revocation record, and the consent flips to `revoked` in the same flow |
| Introspection | Provider routes check consent validity on **every** request - a revoked or expired consent yields 403, never stale data |
| Audit | Every data call is recorded against the consent it was served under |

### 3.2 Provider API (`/fdx/v6/*`) - what recipients integrate against

| Capability | Business rule |
|---|---|
| Account reads | Accounts, transactions, and statements are served only for accounts in the consent grant; statement download redirects to a time-limited signed URL |
| Customer reads | Customer identity data is served only under a consent covering the customer cluster |
| Money movement | Transfers (create/read/update/cancel) and payments are initiated only under a write-scoped consent; execution is Bank8:Payments' - FDX never moves money itself |
| Payees & recurring | Payee management (create/read/update) and recurring payment registration (frequency-driven occurrences) are consent-scoped like every other write |
| PIP | Payment-initiation parties register payment methods per consent; methods can be individually revoked |
| Payment networks | Per-account payment-network bindings are readable; customers can revoke a network binding explicitly (with reason + initiator recorded, mirroring consent revocations) |
| Contract compliance | Every request carries the FDX interaction id (`x-fapi-interaction-id`), echoed back - end-to-end traceability |
| Out-of-scope families | Return the FDX-standard unsupported-operation response (501 / code 1106) - never silent stubs, never partial data |

**Implemented vs out-of-scope operation map** (served at
`/fdx/v6/operation-support` so recipients can preflight):

| Status | FDX families |
|---|---|
| Implemented | accounts, transactions, statements, customers, consents, transfers, payments, payees, payment-initiation-parties, recurring-payments, payment-networks, notification-subscriptions, notifications, register, capability, availability, certification-metrics |
| Out of scope | reward-programs, transaction-images, tax-forms, payroll, fraud, data-providers, recipients-registry, terms-and-conditions, contacts, bills, investments, social-security, digital-wallet |

### 3.3 Consent-scoped data filter (CSDF)

| Capability | Business rule |
|---|---|
| Minimization | Responses are projected to the granted clusters **before** serialization - a recipient asking for more than the grant gets exactly the grant |
| Data clusters | Seven coarse-grained clusters: `ACCOUNTS`, `TRANSACTIONS`, `STATEMENTS`, `CUSTOMERS`, `TRANSFERS`, `PAYMENTS`, `TAX` |
| Scope-to-cluster mapping | OAuth scopes map deterministically: accountbasic/accountdetailed/balances reads → `ACCOUNTS`; transactions read → `TRANSACTIONS`; statements read → `STATEMENTS`; customer contact/personal reads → `CUSTOMERS`; transfers read/write → `TRANSFERS` + `PAYMENTS`; payments write → `PAYMENTS`; tax read → `TAX`. Unknown scopes grant nothing |
| Filter inputs | The filter is driven by consent scopes, product category (fields valid for the product type), and the recipient's requested fields - three narrowing layers |
| Enforcement layering | Consent is enforced twice: the middleware check (scope vs consent row) and RLS on every table - no route can bypass |
| Tamper resistance | Revoked consents can never be revived by introspection |

### 3.4 Recipient onboarding & identity

| Capability | Business rule |
|---|---|
| Dynamic registration | Recipients self-register (RFC 7591) and manage their registration (RFC 7592) - no manual client configuration |
| Sender-constrained tokens | Provider access tokens are DPoP-bound; a stolen token without the key is useless |
| Credential hygiene | Provider tokens and webhook secrets are stored as secret references only - never plaintext in any column |
| Recipient registry | Every registered recipient is mirrored and visible to operators in the admin console |

### 3.5 Notifications (event delivery to recipients)

| Capability | Business rule |
|---|---|
| Subscriptions | Recipients subscribe a callback URL with event filters per subscription |
| Delivery | Consent/data-change events are delivered as HMAC-signed webhooks - recipients can verify authenticity |
| Reliability | Failed deliveries retry with backoff; exhausted deliveries are marked failed for admin triage - never dropped silently, never hot-looped |
| Queue transparency | Pending/delivered/failed notification state is inspectable |

### 3.6 Recipient surfaces (`/v1/recipient/*`)

| Capability | Business rule |
|---|---|
| Provider discovery | Recipient apps list providers to connect to |
| Consent journey | Start (PAR/PKCE), list, inspect, refresh, and revoke consents on behalf of the bank's customer |
| Consented reads | Recipient apps read account data through the same consent enforcement - no parallel trust path |
| OAuth redirect | The provider-side consent callback completes the OAuth loop back into the app |

### 3.7 Hosted consent screens

| Capability | Business rule |
|---|---|
| Bank-hosted approve/deny | The customer sees the bank's consent screens inside the platform OAuth flow - not a recipient-embedded page |
| Account selection | The consent screen lists exactly the accounts the requested scopes can cover |
| Decision record | Approve and deny are recorded with the consent lifecycle event |

### 3.8 Discovery & certification

| Capability | Business rule |
|---|---|
| Capability & availability | Recipients can probe what the provider supports before integrating |
| Certification metrics | Data-call counts and consent grant/revoke transitions are served (cached briefly) as certification evidence |
| Operation support | The supported-operation map tells recipients which FDX families are live vs unsupported |

## 4. Business Events (Outbound)

Event names are the business contract - consumers subscribe on these.
Family prefix: `bank8:fdx:`.

| Event | Fires when |
|---|---|
| `bank8:fdx:consent:created` / `:updated` / `:revoked` | Consent lifecycle changes (revocation carries reason + initiator) |
| `bank8:fdx:recipientconsent:started` / `:refreshed` / `:revoked` | The fintech's connection registry changes (started / token refreshed / revoked) |
| `bank8:fdx:transfer:created` / `:cancelled` | Money-movement initiation via the provider API |
| `bank8:fdx:payment:created` | Payment initiation via the provider API |
| `bank8:fdx:recurringpayment:created` | Recurring payment registration |
| `bank8:fdx:payee:created` | Payee creation |
| `bank8:fdx:paymentinitiationparty:created` | PIP registration |
| `bank8:fdx:paymentnetwork:revoked` | A payment-network binding is revoked |
| `bank8:fdx:notificationsubscription:created` / `:deleted` | Notification subscription lifecycle |
| `bank8:fdx:providerprofile:updated` | Provider profile (re)registration at env-init |

**Inbound (consumed):**

| Event | Consumer behaviour |
|---|---|
| `sentin8:sys:service:updated` | Environment initialization: auto-registers/refreshes the provider profile (issuer URL, capabilities) |
| `sentin8:auth:grant:created` | Grant seeding (provider plane): the authorization server granted a consent - the bank's grant ledger records the consent handle, the customer, the scopes, and the selected accounts |

## 5. Business Rules & Invariants

1. **No consent, no data.** Every provider data call requires a valid,
   unexpired, unrevoked consent covering the requested cluster - checked
   in middleware on every request, backed by RLS. No route can bypass.
2. **The customer is in control.** Consents are scoped, expiring, and
   revocable at any time; revocation is terminal and takes effect on
   the very next call.
3. **Data minimization is structural.** CSDF strips everything outside
   the grant before serialization - the recipient cannot receive more
   than the customer allowed, even by accident.
4. **Every read is attributable.** Each data call is audited against the
   consent it served, with the FDX interaction id for end-to-end
   traceability.
5. **No plaintext credentials.** Provider tokens, refresh tokens, DPoP
   keys, and webhook secrets exist only as secret references resolved at
   call time.
6. **Tokens are sender-constrained.** Recipient tokens are DPoP-bound -
   token theft alone grants nothing.
7. **Registration is dynamic, not manual.** Recipients onboard through
   RFC 7591 DCR at the bank's authorization server; there is no
   hand-configured client list to drift.
8. **Unsupported means unsupported.** Out-of-scope FDX families return
   the standard unsupported-operation response - never stubbed or partial
   data that could mislead a recipient.
9. **Notifications are authentic and reliable.** Webhooks are
   HMAC-signed; failures retry with backoff and are surfaced for triage
   - never silently dropped.
10. **Money movement has one executor.** FDX surfaces consented
    initiation; Bank8:Payments executes; FDX never moves money itself.
11. **Tenant isolation is absolute.** All 15 domain tables are
    environment-scoped with forced row-level security.
12. **Stale data is impossible on the consent check.** Consent validity
    is introspected live - the consent lookup is never served from a
    cache.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Bank8:FDX |
|---|---|
| Bank customer | Grants/revokes consents on the bank-hosted screens; controls exactly which accounts and data clusters a fintech may see; revokes at any time |
| Data recipient / fintech aggregator | Registers its OAuth client dynamically at the bank's AS (DCR), subscribes to notifications, reads consented account/transaction data, initiates consented transfers/payments over the FDX v6.5 API |
| Recipient app user (via eFinTech) | Connects bank accounts through the recipient surface: start consent, approve in the bank's UI, then see consented data in the app |
| Compliance / privacy officer | Verifies every data call against its consent, reads the audit trail, uses certification metrics as evidence; relies on CSDF for data-minimization assurance |
| Open banking product owner | Configures provider capability/availability, monitors consent adoption and revocation reasons, reviews failed notification deliveries |
| Bank operations staff | Uses the admin console (overview, provider, recipients, consents, CSDF, settings) to triage recipients and consents |
| Downstream services | Subscribe to `bank8:fdx:*` events for consent lifecycle reactions |

## 7. KPIs / Success Criteria

- **Consent compliance**: 100% of provider data calls served under a
  valid consent; zero data served after revocation or expiry.
- **Data minimization fidelity**: zero incidents of data outside the
  granted clusters appearing in a response (CSDF coverage).
- **Audit completeness**: every provider data call produces an audit
  row; certification metrics reconcile with the audit trail.
- **Notification reliability**: webhook delivery success rate within
  SLA; failed deliveries surfaced (not dropped) within one retry budget.
- **Recipient onboarding time**: a new recipient can register, subscribe,
  and complete its first consented read without bank-side manual work.
- **Consent journey completion rate**: share of started consents that
  reach a decision (approve/deny) on the hosted screens.
- **Revocation responsiveness**: a revoked consent stops serving data on
  the next request - measurable, not aspirational.

## 8. Dependencies & Reliance on Other Services

| Relies on | For |
|---|---|
| Sentin8:Auth | The bank's authorization server: DCR + PAR + token endpoints for the consent ceremony; emits the grant event the bank's grant ledger seeds from; the consent RFW host |
| Bank8:Ledger | Consented account/transaction data (public API reads) |
| Bank8:Payments | Money-movement execution for consented transfers/payments |
| Sentin8:Storage | Statement documents (signed download URLs) |
| Sentin8:Secrets | Resolving token/DPoP/webhook secret references at call time |
| Sentin8:Bus | Durable delivery of the `bank8:fdx:*` event family; sys-family env-init consumption |
| Sentin8:Flow | The step engine FDX's step profile plugs into |
| Sentin8:Policy (Shield) | The authorization decision on every route |
| Sentin8:Sys | Central audit ingest via the journal pusher; service enablement events |
| Sentin8:BFF | Client traffic for the recipient surfaces |

## 9. Acceptance Criteria

1. A provider data call without a valid consent is rejected 403 and
   audited - for every route, with no exceptions.
2. A consent revoked mid-flight stops serving data on the next request;
   the revocation record captures reason, initiator, and timestamp.
3. A response contains only data clusters inside the grant (CSDF),
   verified for consents granting partial clusters.
4. A consent that expires by duration window yields 403 on the next
   call, and refresh (where policy allows) extends validity with an
   audit trail.
5. Statement downloads redirect to time-limited signed URLs; the
   document itself never travels through the FDX service.
6. A recipient can complete a full connection - register its client at
   the provider's authorization server, run the consent ceremony, and
   read consented data over the provider's public API - while both
   institutions' records stay in their OWN environments (the bank's
   grant ledger, the fintech's connection registry), with no shared
   table between them.
7. A failed webhook delivery retries with backoff and lands as
   `failed` in the admin view after exhausting the budget.
8. Money-movement requests under a write-scoped consent produce
   Bank8:Payments instructions; under a read-only consent they are
   rejected.
9. Out-of-scope FDX families return the standard unsupported-operation
   response.
10. No provider token, refresh token, DPoP key, or webhook secret
    exists as plaintext in any table - secret references only.
11. The hosted consent screen lists exactly the consent-coverable
    accounts, and both approve and deny produce their lifecycle events.
12. All tenant data is invisible to other tenants; each capability in
    §2 is operable through the admin pages and/or the BFF-proxied API.

## 10. Open Business Questions

- Recipient response caching is deferred by design (trigger: a
  recipient exceeding FDX poll guidance with degraded p95 latency) -
  what poll budget does the business want to advertise to recipients?
- Certification metrics are computed live from the audit trail; the
  daily rollup table + evidence admin page remain deferred - what scale
  of certification reporting do regulators require?
- Should consent duration policies (max window, refresh limits) be
  per-tenant configurable or platform-standard?
- Which additional FDX families (if any) are on the roadmap beyond the
  currently supported operation set - and does any require new ledger
  or payments read surfaces?

---

**Design attribution:** bank8:fdx and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
