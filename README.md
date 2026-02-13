# Repo Analyzer ⚡

Trust scoring for GitHub repos. One command, full breakdown. Built for crypto due diligence — spots faked commits, throwaway accounts, and generated READMEs.

```
node analyze.js <github-url-or-owner/repo>
```

Zero dependencies. Node.js 20+ only.

## What It Checks

**Commit Health** — real development or code dump? Detects evenly-spaced timestamps (faked history), checks GPG signatures, separates human vs bot commits (dependabot, github-actions)

**Contributors** — checks account age, repo count, followers. Flags fresh throwaway accounts created just for the project

**Code Quality** — tests, CI/CD, license, lock files, docs, changelog, .gitignore. Missing basics = missing trust

**AI Detection** — scans README for generated text patterns, measures emoji density, flags long READMEs on repos with few commits

**Social Signals** — star/fork ratio analysis. High stars with no forks and one contributor = likely botted

**Activity** — last push date, release history, repo age vs commit count

**Crypto Checks** — token mints from launchpads, placeholder program IDs (contract not deployed), hardcoded wallet addresses, rug pull patterns in config files

**Security** — exposed credential files, private keys committed to repo (excludes test fixtures)

## Trust Score

0-100 with letter grade:

- **A (85-100)** — Legit. Real development, real contributors, maintained.
- **B (70-84)** — Solid. Minor gaps but probably trustworthy.
- **C (55-69)** — Mixed. Needs more research before trusting.
- **D (40-54)** — Sketchy. Multiple red flags.
- **F (0-39)** — Avoid. Likely scam, fake, or abandoned.

## Usage

```bash
# Analyze any public repo
node analyze.js https://github.com/openclaw/openclaw
node analyze.js owner/repo

# JSON output for scripts/pipelines
node analyze.js owner/repo --json

# Verbose (shows progress)
node analyze.js owner/repo --verbose

# Higher rate limits with GitHub token
GITHUB_TOKEN=ghp_xxx node analyze.js owner/repo
```

## Sample Output

```
════════════════════════════════════════════════════════════
  GITHUB REPO ANALYSIS: owner/repo
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

  FLAGS:
    - Placeholder program ID — contract not deployed
    - Launchpad token mint in config
    - 0% GPG signed commits — author identity unverified

  VERDICT [C]: MIXED — Needs more research before trusting.
────────────────────────────────────────────────────────────
```

## GitHub Token (recommended)

Without a token: 60 API requests/hour (~7 repo scans). With a token: 5,000/hour.

1. Go to [GitHub Settings → Developer settings → Fine-grained tokens](https://github.com/settings/tokens?type=beta)
2. Generate new token — name it anything, set "Public repositories (read-only)", no other permissions
3. Use it:

```bash
# Option A: env var (recommended)
export GITHUB_TOKEN=github_pat_xxx
node analyze.js owner/repo

# Option B: per-command
node analyze.js owner/repo --token github_pat_xxx
```

Each user needs their own token. Rate limits are per-token, not shared.

## How It Works

Single script using the GitHub REST API. Pulls repo metadata, commit history, contributor profiles, file tree, and raw README content. Analyzes everything locally.

## License

MIT
