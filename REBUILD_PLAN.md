# IndiFrame Agent Help Desk — Rebuild Plan

## Baseline and hosting decision

The current repository is a static HTML portal with Cloudflare Pages Functions and Cloudflare D1 authentication. The rebuild will retain this deployment model for the first phase. GitHub remains source control; Cloudflare Pages serves the site and Functions; D1 stores accounts and sessions. No Vercel or Supabase migration is assumed.

## Non-negotiable preservation rules

- Preserve the existing approved script library, including the full scripts and all scenario coverage.
- Preserve Product Quick Reference, Process SOP, FAQ / Objection content, CX Questions, Sales Team directory and Latest Updates.
- Keep the maximum retry policy at 15 attempts across 9 calendar days.
- Keep the out-of-service-area / Green Fortune routing scenario.
- Keep Team Lead approval, Agent role separation, forced first-login password change, account disable and session revocation.
- Do not add Log Call Outcome or Escalation Matrix as agent-facing modules.
- Never invent pricing, warranty, installation, delivery or technical guarantees.
- Never expose secrets in browser code or commit Cloudflare secrets to Git.

## Rebuild phases

### Phase 1 — Safety baseline
- Add automated repository and inline-JavaScript checks.
- Establish a dedicated rebuild branch.
- Keep `main` and the current deployed portal untouched until review.

### Phase 2 — Application structure
- Separate the large single-file portal into reusable styles, navigation, page modules and approved knowledge data.
- Keep a single approved content source for scripts, FAQs, products and SOPs.
- Add route-level smoke tests and accessibility checks.

### Phase 3 — Authentication and data
- Audit all API routes, middleware, D1 schema and password-recovery flows.
- Verify server-side role enforcement and account status checks.
- Add API regression tests for login, session expiry, password change, reset, disable and admin-only actions.

### Phase 4 — Agent experience
- Rebuild the navigation and dashboard with the approved off-white visual system, sky-blue headings and copper-orange accents.
- Make script access direct and full-length; improve search, filtering and mobile layouts.
- Keep agent-only and Team Lead-only views separated server-side.

### Phase 5 — AI and operational tools
- Connect AI Assist only to approved portal knowledge.
- Enforce answer grounding and safe fallbacks for unknown commercial or technical details.
- Add serviceability validation only against approved coverage data; do not infer PIN coverage from city clusters.

### Phase 6 — Release
- Run CI, authentication regression tests and manual role-based acceptance tests.
- Configure Cloudflare Pages production and D1 bindings only after environment review.
- Promote to production only after explicit approval.

## Current deployment caveat

The existing Pages deployment workflow is manual and the latest successful recorded deployment predates the latest `main` commits. A successful GitHub commit does not prove the current production website is updated. Confirm the Cloudflare Pages production project and D1 bindings before release.
