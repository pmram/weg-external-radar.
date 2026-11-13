# WEG External Radar

Public web intelligence dashboard for third-party pages mentioning WEG, excluding `weg.net` and all its subdomains.

## Setup
1. In **Settings → Pages**, select **GitHub Actions** as the build and deployment source.
2. In **Settings → Secrets and variables → Actions**, add `BRAVE_SEARCH_API_KEY` (recommended).
3. Run **Actions → Scan public web → Run workflow**.
4. Dashboard: https://pmram.github.io/weg-external-radar./

Scans run daily at 07:13 UTC. Without Brave credentials the fallback searches Google News RSS and flags redirect destinations as unverified. This is a static GitHub Pages app; searches update during scheduled or manual workflow runs, not in realtime. Only publicly indexed content is used. The results may contain false positives for the name WEG.
