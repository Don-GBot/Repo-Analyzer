---
name: repo-analyzer
description: GitHub repository trust scoring and due diligence. Use when asked to analyze, audit, score, or evaluate any GitHub repo — especially for crypto/DeFi project DD, checking if a repo is legit, evaluating code quality, verifying team credibility, or comparing multiple repos. Triggers on phrases like "analyze this repo", "is this legit", "check this GitHub", "trust score", "audit this project", "repo quality", "batch scan repos".
---

# Repo Analyzer

Zero-dependency GitHub trust scorer. Runs 21 analysis modules across 11 scoring categories.

## Usage

```bash
# Single repo
node scripts/analyze.js <owner/repo or github-url> [flags]

# Batch mode
node scripts/analyze.js --file <repos.txt> [--json]
```

### Flags
- `--json` — JSON output (for pipelines)
- `--oneline` — compact one-line score
- `--badge` — shields.io markdown badge
- `--verbose` — show progress
- `--token <pat>` — GitHub PAT (or set GITHUB_TOKEN env)
- `--file <path>` — batch mode, one repo per line (# comments ok)

### Environment
Requires `GITHUB_TOKEN` for 5000 req/hr. Without it: 60 req/hr (batch won't work).
Load with: `source ~/.bashrc` or `export GITHUB_TOKEN="..."`.

## What It Scores (11 categories, 135pts → normalized to 100)

| Category | Max | What it checks |
|----------|-----|----------------|
| Commit Health | 20 | Human vs bot, GPG sigs, code dumps, fake timestamps |
| Contributors | 15 | Bus factor, contributor diversity |
| Code Quality | 25 | Tests, CI, license, docs, lock files |
| AI Authenticity | 15 | AI slop detection in code/README |
| Social | 10 | Stars, forks, watchers |
| Activity | 10 | Recency, push frequency |
| Crypto Safety | 5 | Wallet addresses, token contracts, rug patterns |
| README Quality | 10 | Install guide, examples, structure, docs |
| Maintainability | 10 | File sizes, nesting, code/doc ratio |
| Project Health | 10 | Abandoned detection, issue response, PR review, velocity |
| Originality | 5 | Copy-paste detection, fork quality, backer verification |

## Grade Scale
- A (85+): LEGIT
- B (70-84): SOLID
- C (55-69): MIXED
- D (40-54): SKETCHY
- F (<40): AVOID

## Key Features
- **Author reputation**: Checks committers' other repos, org memberships, account age, suspicious projects
- **Backer verification**: Cross-references README investor claims against committer org membership
- **Copy-paste detection**: Identifies OpenZeppelin boilerplate, template repos, zero-change forks
- **Abandoned detection**: Last push age, unanswered issues, stale PRs
- **License risk**: Permissive vs copyleft vs none

## Batch File Format
```
# One repo per line, # for comments
Uniswap/v3-core
https://github.com/aave/aave-v3-core
OpenZeppelin/openzeppelin-contracts
```

## Output
Default: rich terminal report with bar charts, sections, verdict.
`--json`: Full structured data for programmatic use.
`--oneline`: `RepoName: 85/100 [A] — 2 flags`

## When Reporting to User
Keep it concise. Lead with score/grade and notable findings. Skip sections with nothing interesting. Example:

"OpenZeppelin scored 91/A — top marks. 100% GPG-signed commits, MIT license, active PRs with review. One committer (@ernestognw) is in the OpenZeppelin org, 8yr account."
