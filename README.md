# Repo Analyzer

Trust scoring for GitHub repositories. One command, deep analysis. Built for due diligence — catches faked commits, abandoned projects, prompt injection, credential harvesting, and copy-paste code.

```
node analyze.js <github-url-or-owner/repo>
```

Zero dependencies. Node.js 20+ only.

## Quick Start

```bash
git clone https://github.com/Don-GBot/Repo-Analyzer.git
cd Repo-Analyzer

# Analyze any public repo
node analyze.js owner/repo

# With higher rate limits (recommended)
export GITHUB_TOKEN=github_pat_xxx
node analyze.js owner/repo
```

## What It Checks

29 analysis modules across 12 scoring categories:

**Code Trust**
- Commit patterns, code dumps, faked timestamps, GPG verification
- Contributor diversity, bus factor, throwaway accounts
- Tests, CI/CD, license, lock files, docs, changelog
- AI-generated content detection (slop patterns, emoji density)

**Security**
- Agent safety: install script hooks, prompt injection in markdown, credential harvesting + exfiltration, obfuscation, crypto mining, shell injection, system path writes
- Hardcoded secrets: API keys, tokens, private keys (regex + entropy analysis)
- GitHub Actions audit: `pull_request_target`, unpinned actions, secrets in run commands
- Known compromised dependencies (event-stream, colors, faker, node-ipc)
- Exposed credential files, private keys in repo

**Project Health**
- Abandoned/stale/neglected detection with issue response analysis
- Commit velocity trends (accelerating/steady/declining)
- PR review patterns (self-merge vs reviewed)
- Fork quality check (zero-change forks flagged)

**Transparency**
- Author identity verification (email ↔ GitHub profile ↔ GPG)
- Author reputation: org memberships, suspicious repos, account age
- Backer/investor claims verified against committer org membership
- License risk scoring (permissive/copyleft/none)
- Copy-paste and template detection

**Intelligence**
- Network behavior mapping: categorizes all outbound domains
- Permissions manifest: what the code needs (network, filesystem, env vars, system commands)
- README quality scoring (install guide, examples, structure)
- Maintainability estimate (file sizes, nesting depth, code/doc ratio)
- Dependency tree depth and bloat detection
- Code complexity hotspots (large files, deep nesting, conditional density)
- Plugin/package format detection (OpenClaw, npm, GitHub Actions, Docker, Python)

## Trust Score

0-100 with letter grade:

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 85+ | Legit — real development, real contributors, maintained |
| B | 70-84 | Solid — minor gaps but probably trustworthy |
| C | 55-69 | Mixed — needs more research before trusting |
| D | 40-54 | Sketchy — multiple red flags |
| F | <40 | Avoid — likely scam, fake, or abandoned |

## Usage

```bash
# Single repo (URL or shorthand)
node analyze.js https://github.com/OpenZeppelin/openzeppelin-contracts
node analyze.js OpenZeppelin/openzeppelin-contracts

# Batch mode
node analyze.js --file repos.txt

# JSON output
node analyze.js owner/repo --json

# One-line (for scripts/bots)
node analyze.js owner/repo --oneline
# → owner/repo: 91/100 [A]

# Shields.io badge
node analyze.js owner/repo --badge

# Verbose progress
node analyze.js owner/repo --verbose
```

## Batch Mode

```
# repos.txt — one repo per line, # for comments
OpenZeppelin/openzeppelin-contracts
Uniswap/v3-core
aave/aave-v3-core
foundry-rs/foundry
```

```bash
node analyze.js --file repos.txt
```

Outputs individual scores, grade distribution, averages, and top/bottom rankings.

## GitHub Token

Without a token: 60 requests/hour (~4 repo scans). With a fine-grained PAT: 5,000/hour.

```bash
export GITHUB_TOKEN=github_pat_xxx

# Or pass directly
node analyze.js owner/repo --token github_pat_xxx
```

Create a token at [github.com/settings/tokens](https://github.com/settings/tokens?type=beta) — public repo read-only access is sufficient.

## OpenClaw Skill

Works as an [OpenClaw](https://github.com/openclaw/openclaw) skill for AI-assisted repo analysis:

```bash
cp SKILL.md scripts/analyze.js ~/.openclaw/skills/repo-analyzer/
```

Then ask your agent: *"analyze this repo"*, *"is this safe to install?"*, *"trust score for owner/repo"*

## How It Works

Single script, zero build step. Queries the GitHub REST API for repo metadata, commits, contributors, file tree, README, issues, PRs, and workflow files. All analysis runs locally — nothing leaves your machine except GitHub API calls.

## Architecture

```
analyze.js          Single analysis script (all 29 modules)
tests/              Test suite
docs/scoring.md     Scoring methodology
SKILL.md            OpenClaw skill definition
CHANGELOG.md        Version history
CONTRIBUTING.md     How to contribute
SECURITY.md         Security policy
```

## License

MIT
