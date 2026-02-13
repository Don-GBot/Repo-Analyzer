# Repo Analyzer ⚡

Trust scoring for GitHub repos. One command, full breakdown. Built for due diligence — spots faked commits, abandoned projects, unverified backers, and copy-paste code.

```
node analyze.js <github-url-or-owner/repo>
```

Zero dependencies. Node.js 20+ only.

## Install as OpenClaw Skill

Drop `repo-analyzer.skill` into your OpenClaw skills directory, or:

```bash
# From repo
cp SKILL.md scripts/analyze.js ~/.openclaw/skills/repo-analyzer/
```

Then just ask your OpenClaw: *"analyze this repo"*, *"is this legit?"*, *"trust score for owner/repo"*

## What It Checks (21 modules)

| Category | What it catches |
|----------|----------------|
| **Commit Health** | Code dumps, faked timestamps, GPG signatures, human vs bot |
| **Contributors** | Bus factor, throwaway accounts, contributor diversity |
| **Code Quality** | Tests, CI/CD, license, lock files, docs, changelog |
| **AI Detection** | Generated READMEs, emoji density, slop patterns |
| **Social Signals** | Star/fork ratio, botted stars detection |
| **Activity** | Push frequency, release history, repo age |
| **Crypto Checks** | Token mints, placeholder contracts, rug patterns, wallet addresses |
| **Security** | Exposed credentials, private keys in repo |
| **README Quality** | Install guide, examples, structure, API docs |
| **Maintainability** | File sizes, nesting depth, code/doc ratio |
| **Project Health** | Abandoned detection, issue response time, PR review patterns, velocity trends |
| **Originality** | Copy-paste detection, fork quality, template matching |
| **Author Reputation** | Committers' other repos, org memberships, suspicious projects |
| **Backer Verification** | README investor claims vs actual org membership |
| **License Risk** | Permissive vs copyleft vs none |

## Trust Score

0-100 with letter grade:

- **A (85+)** — Legit. Real development, real contributors, maintained.
- **B (70-84)** — Solid. Minor gaps but probably trustworthy.
- **C (55-69)** — Mixed. Needs more research before trusting.
- **D (40-54)** — Sketchy. Multiple red flags.
- **F (<40)** — Avoid. Likely scam, fake, or abandoned.

## Usage

```bash
# Single repo
node analyze.js https://github.com/openclaw/openclaw
node analyze.js owner/repo

# Batch mode — analyze multiple repos
node analyze.js --file repos.txt

# JSON output for pipelines
node analyze.js owner/repo --json

# One-line mode for bots/scripts
node analyze.js owner/repo --oneline
# → owner/repo: 85/100 [A]

# Shields.io badge markdown
node analyze.js owner/repo --badge
# → ![Trust Score](https://img.shields.io/badge/Trust_Score-85%2F100_A-brightgreen)

# Verbose (shows progress)
node analyze.js owner/repo --verbose
```

## Batch Mode

Create a text file with one repo per line:

```
# repos.txt
Uniswap/v3-core
aave/aave-v3-core
OpenZeppelin/openzeppelin-contracts
```

```bash
node analyze.js --file repos.txt
```

Outputs scores, grade distribution, top/bottom rankings, and average.

## GitHub Token (recommended)

Without a token: 60 API requests/hour (~4 scans). With a token: 5,000/hour.

```bash
# Fine-grained PAT with public repo read-only access
export GITHUB_TOKEN=github_pat_xxx
node analyze.js owner/repo
```

## Sample Output

```
════════════════════════════════════════════════════════════
  GITHUB REPO ANALYSIS: pancakeswap/pancake-smart-contracts
════════════════════════════════════════════════════════════

  TRUST SCORE: 62/100 [C]

  BREAKDOWN:
    Commit Health      █████████░ 17/20
    Contributors       ███████░░░ 10/15
    Code Quality       ███████░░░ 17/25
    Project Health     █░░░░░░░░░ 1/10
    ...

  PROJECT HEALTH:
    🔴 ABANDONED (last push 696d ago)
    ⚠️ No commits in 696 days

  LICENSE: 🔴 No license — legally cannot use, fork, or modify

  VERDICT [C]: MIXED — Some concerns. Do more research before trusting.
────────────────────────────────────────────────────────────
```

## How It Works

Single script using the GitHub REST API. Pulls repo metadata, commit history, contributor profiles, file tree, README content, issues, and PRs. Analyzes everything locally — nothing leaves your machine.

## License

MIT
