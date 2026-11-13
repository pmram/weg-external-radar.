# WEG Radar — Brand Impersonation Watch

Passive discovery of **potential WEG brand impersonation domains**, rather than websites that merely mention WEG.

## What qualifies as a candidate
- A non-allowlisted hostname incorporating `WEG` or a few defined lookalike spellings.
- Additional ranking signals from the indexed title/snippet (claims of being an official channel, authentication, payment, or account prompts).
- Domain-based deduplication and a human-review priority score.

**Candidate ≠ confirmed malicious.** Partners, distributors and legitimate independent sites can be flagged.

## Configuration
1. In repository **Settings → Pages**, use **GitHub Actions** as source.
2. In **Settings → Secrets and variables → Actions**, add a **BRAVE_SEARCH_API_KEY** repository secret (required to search).
3. Optionally set a variable `TRUSTED_DOMAINS` as a comma-separated allowlist of **verified** official company domains, e.g. `example.org,example.net`. Only add domains confirmed as owned or explicitly authorised by WEG.
4. Run **Actions → Scan public web → Run workflow** to refresh. Subsequent scans run daily at 07:13 UTC.
5. View the dashboard at https://pmram.github.io/weg-external-radar./

The app does not use Google News. Without API credentials it will report that collection is disabled; it does not present news as suspicious websites.

## Scope and limitations
This is a **passive OSINT heuristic**: it searches only publicly indexed results and scores URL hostnames and snippets. It does not visit candidate pages, inspect screenshots, assess DNS ownership, verify domain registrations, analyze login forms or detect all typosquats. It can miss sites not indexed by Brave. Manual verification is necessary before incident response, takedown requests, or labeling any site malicious.

Only `weg.net` and its subdomains are excluded by default as WEG-owned; other legitimate WEG properties should be added to `TRUSTED_DOMAINS` after verification.
