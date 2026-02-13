# Repo Analyzer ⚡

Trust scoring for GitHub repos. One command, full breakdown. Built for crypto due diligence — catches rugs, fakes, and AI slop before you ape.

```
node analyze.js <github-url-or-owner/repo>
```

Zero dependencies. Just Node.js 20+.

## What It Checks

- **Commit Health** — real development or code dump? Evenly-spaced commits (faked history), GPG signatures, commit frequency
- **Contributors** — account age, repo count, follower count. Flags fresh throwaway accounts
- **Code Quality** — tests, CI/CD, license, lock files, docs, changelog, .gitignore
- **AI Slop Detection** — scans README for AI-generated patterns ("comprehensive solution", "leveraging the power", "seamless", etc.), emoji density
- **Social Signals** — star/fork ratio, botted star detection (high stars + no forks/contributors)
- **Activity** — last push date, release history, staleness
- **Crypto Red Flags** — pump.fun token mints, placeholder program IDs (not deployed), hardcoded wallets, rug pull patterns
- **Security** — exposed credential files, private keys in repo

## Trust Score

0-100 score with letter grade:

- **A (85-100)** — Legit. Well-maintained, real development, trustworthy.
- **B (70-84)** — Solid. Good signs, minor gaps. Probably legit.
- **C (55-69)** — Mixed. Some concerns. Do more research.
- **D (40-54)** — Sketchy. Multiple red flags. Extreme caution.
- **F (0-39)** — Avoid. High probability of scam/fake/abandoned.

## Examples

```bash
# Analyze any repo
node analyze.js https://github.com/openclaw/openclaw
node analyze.js ahhimquesting/quest-mvp
node analyze.js Don-GBot/G-Alpha

# JSON output (for piping)
node analyze.js openclaw/openclaw --json

# Verbose mode (shows progress)
node analyze.js openclaw/openclaw --verbose

# With GitHub token (higher rate limits)
GITHUB_TOKEN=ghp_xxx node analyze.js openclaw/openclaw
```

## Sample Output

```
════════════════════════════════════════════════════════════
  GITHUB REPO ANALYSIS: ahhimquesting/quest-mvp
════════════════════════════════════════════════════════════

  TRUST SCORE: 56/100 [C]
  ███████████░░░░░░░░░

  BREAKDOWN:
    Commit Health      █████░░░░░ 9/20
    Contributors       ███████░░░ 10/15
    Code Quality       ████░░░░░░ 9/25
    AI Authenticity    ██████████ 15/15
    Social Signals     █████░░░░░ 5/10
    Activity           ████████░░ 8/10
    Crypto Safety      ░░░░░░░░░░ 0/5

  🚩 FLAGS:
    - Placeholder program ID — not deployed
    - Token mint with pump.fun pattern
    - Placeholder program ID in contracts/Anchor.toml — not deployed

────────────────────────────────────────────────────────────
  VERDICT [C]: MIXED — Some concerns. Do more research before trusting.
────────────────────────────────────────────────────────────
```

## How It Works

Single Node.js script, zero external dependencies. Uses the GitHub REST API to pull:
- Repository metadata
- Commit history (last 100)
- Contributor profiles + account ages
- File tree (for quality signals)
- Raw README (for AI slop detection)
- Config files (for crypto-specific checks)

Works without a GitHub token (60 requests/hour). Add `GITHUB_TOKEN` env var for 5,000 requests/hour.

## Use Cases

- **Crypto due diligence** — someone shares a repo claiming a big-name dev is involved? Check if commits are signed, accounts are real, and code is actually deployed
- **Before you ape** — token project links a GitHub? Run it through the analyzer first
- **General repo assessment** — evaluate any open source project's health and trustworthiness
- **CI integration** — use `--json` output in automated pipelines

## License

MIT
