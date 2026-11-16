# IndiFrame Agent Portal — HRHNEXT · Agent Help Desk

A GitHub-hosted recreation of the IndiFrame Agent Portal knowledge hub.

## Current implementation

- Responsive navigation and home dashboard
- 20-section Scripts library populated with source-based guidance, call prompts, lead-stage rules, renovation handling, scenarios, objections, follow-ups, closing, qualification and CRM handover
- CX Questions page: 100 supplied questions mapped to the relevant script section
- Product guide with window types, glass options, colours and qualification guidance
- Process SOP timeline with operational controls
- FAQ and objection-handling reference
- Sales Team directory with search and city filter
- Latest Updates / Change Log
- My Quick Access with browser-local favorites

## Explicit exclusions

These are intentionally excluded from the navigation and standalone modules:

- Log Call / Log Call Outcome
- Escalation / Escalation Matrix

## Source-content notes

- The reviewed source documents conflict on unreachable-lead cadence: one finalized SOP states a maximum of 9 attempts over 12 calendar days; another script page mentions 15 attempts over 9 days. The portal flags this conflict and directs agents to the current Operations instruction until formally confirmed.
- A separate approved Inbound / Walk-in script was not found in the reviewed source set. The section identifies this gap instead of inventing an approved script.
- A verified Telugu reference script in English letters was not found in the reviewed source set. The section identifies this gap instead of publishing an unverified translation.
- Process SOP is marked Under Review in the supplied portal reference. Sample / under-review content must not be represented as approved.

## Run locally

Open `index.html` in a modern browser. No build step or external package is required.

## Publish with GitHub Pages

1. Open repository **Settings → Pages**.
2. Under **Build and deployment**, choose **Deploy from a branch**.
3. Select branch `main` and folder `/ (root)`.
4. Save. GitHub Pages will publish the portal after deployment completes.

## Content governance

The uploaded IndiFrame Library documents are the source of truth. Verify current pricing, warranty terms, serviceability, product availability, technical claims and operating cadence against the latest approved source before customer communication.

## Repository

https://github.com/NottyBuddy/INDINEXT-Agent-Help-Desk
