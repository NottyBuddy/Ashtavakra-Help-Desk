# IndiFrame Agent Portal — HRHNEXT · Agent Help Desk

A GitHub-hosted recreation of the IndiFrame Agent Portal knowledge hub.

## Current implementation

- Responsive navigation and home dashboard
- 20-section Scripts library populated with source-based guidance, call prompts, lead-stage rules, renovation handling, scenarios, objections, follow-ups, closing, qualification and CRM handover
- Scenario E: location outside direct service area / authorized Green Fortune partner routing, with C7 / ROUTE TO B2F handover
- Telugu reference script in English letters, paired with English prompts for opening, discovery, serviceability and closing
- Confirmed retry policy: maximum 15 call attempts across 9 calendar days; record the exact disposition after every attempt
- CX Questions page: 100 supplied questions mapped to relevant script sections
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

- Telugu transliteration is a practical English-letter rendering of the approved English call flow. Have a fluent Telugu speaker / Process Team review the wording before treating the translation as formally approved.
- A separate approved Inbound / Walk-in script was not found in the reviewed source set. The section identifies this gap instead of inventing an approved script.
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
