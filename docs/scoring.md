# Scoring Methodology

## Categories (150 points, normalized to 100)

| Category | Max Points | What It Measures |
|----------|-----------|------------------|
| Commit Health | 20 | Real development activity, GPG signing, code dumps |
| Contributors | 15 | Team diversity, bus factor, suspicious accounts |
| Code Quality | 25 | Tests, CI, license, docs, lock files, dependencies |
| AI Authenticity | 15 | Generated content detection, slop patterns |
| Social Signals | 10 | Stars, forks, star/fork ratio, botted stars |
| Activity | 10 | Recent pushes, releases |
| Crypto Safety | 5 | Token mints, rug patterns, wallet addresses |
| README Quality | 10 | Install guide, examples, structure, API docs |
| Maintainability | 10 | File sizes, nesting, code/doc ratio |
| Project Health | 10 | Abandoned detection, velocity, issue response, PR review |
| Originality | 5 | Copy-paste, fork quality, backer verification |
| Agent Safety | 15 | Install hooks, prompt injection, credential harvesting, secrets, CI security |

## Grade Thresholds

| Grade | Score Range | Interpretation |
|-------|------------|----------------|
| A | 85-100 | Legit — well-maintained, real development, trustworthy |
| B | 70-84 | Solid — good signs overall, minor gaps |
| C | 55-69 | Mixed — some concerns, do more research |
| D | 40-54 | Sketchy — multiple red flags |
| F | 0-39 | Avoid — major red flags, high probability of scam/fake/abandoned |

## Analysis Modules (29 total)

1. Repository metadata
2. Commit analysis (human vs bot, frequency, code dumps, faked timestamps)
3. Contributor analysis (diversity, bus factor, suspicious accounts)
4. Activity and health (push frequency, issues, releases)
5. Code quality signals (tests, CI, license, gitignore, lock files, docs)
6. Social signals (star/fork ratio, botted stars)
7. Crypto-specific checks (pump.fun, wallet addresses, placeholder contracts)
8. Dependency analysis (supply chain, typosquatting, unpinned versions)
9. Author identity verification (email-to-GitHub matching, GPG, corporate claims)
10. Author reputation (org memberships, suspicious repos, account age)
11. README quality (install guide, examples, structure, headings)
12. Maintainability estimate (file sizes, nesting depth, code/doc ratio)
13. Plugin/package format detection (OpenClaw, npm, GitHub Actions, Docker, Python)
14. License risk scoring (permissive vs copyleft vs none)
15. Abandoned project detection (stale, neglected, archived, unanswered issues)
16. Fork quality check (divergence from parent)
17. Commit velocity trends (accelerating, steady, declining)
18. Issue response time
19. PR merge patterns (self-merge vs reviewed)
20. Copy-paste/template detection (OpenZeppelin boilerplate, cookie-cutter signals)
21. Funding/backer verification (README claims vs org membership)
22. Agent safety (install hooks, prompt injection, credential harvesting, obfuscation, mining, shell injection, system paths, SKILL.md audit)
23. Network behavior mapping (domain categorization)
24. Secrets detection (regex + entropy analysis)
25. GitHub Actions audit (pull_request_target, unpinned actions, secrets in run)
26. Permissions manifest (network, filesystem, env vars, system commands)
27. Historical security (advisories, known compromised packages)
28. Dependency tree depth (transitive deps, bloat detection)
29. Code complexity hotspots (large files, nesting, conditional density)

## Deductions

- Security flags: -3 per flag (exposed credentials, private keys)
- Agent Safety critical findings: -5 each (prompt injection, credential exfiltration)
- Agent Safety warnings: -2 each
- Dependency issues: -2 each (unpinned, typosquats)
- Unverified corporate claims: -3 each
