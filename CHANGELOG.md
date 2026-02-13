# Changelog

## 2.0.0 (2026-02-14)

### Agent Safety Module
- Install script hook analysis (preinstall/postinstall detection)
- Prompt injection detection in markdown (8 patterns incl. steganography)
- Credential harvesting + exfiltration detection with smart whitelisting
- Obfuscation detection (base64 blobs, hex payloads)
- Crypto mining pattern detection
- Shell injection and system path write detection
- SKILL.md security audit (curl|bash, sudo, security disabling)
- Minified/bundled file skipping (false positive reduction)

### New Analysis Modules
- Network behavior mapping — categorizes all outbound domains
- Hardcoded secrets detection — regex + Shannon entropy analysis
- GitHub Actions security audit — pull_request_target, unpinned actions, secrets in run
- Permissions manifest — network, filesystem, env vars, system commands summary
- Historical security — advisories and known compromised packages
- Dependency tree depth — transitive dep estimation and bloat detection
- Code complexity hotspots — large files, nesting depth, conditional density

### Improvements
- 29 total modules (up from 21), 12 scoring categories (up from 11)
- Scoring rebalanced: 150 points normalized to 100
- Added SECURITY.md policy
- Expanded known domain whitelist (blockchain explorers, RPC providers, market data)

## 1.1.0 (2026-02-13)

### Features
- Author reputation deep-dive (org memberships, suspicious repos, account age)
- README quality scoring (0-10)
- Maintainability estimate (0-10)
- Plugin/package format detection (OpenClaw, npm, GitHub Actions, VS Code, Docker, Python)
- Badge generation (`--badge` for shields.io markdown)
- Batch mode (`--file repos.txt`)
- License risk scoring (permissive/copyleft/none)
- Abandoned project detection (stale/neglected/archived + unanswered issues)
- Fork quality check (divergence from parent)
- Commit velocity trends (accelerating/steady/declining)
- Issue response time analysis
- PR merge patterns (self-merge vs reviewed)
- Copy-paste/template detector (OpenZeppelin boilerplate)
- Funding/backer verification (README claims vs org membership)
- HTTP redirect following (301/302/307 for renamed orgs)
- Bearer auth for fine-grained PATs
- Graceful 404s in batch mode

## 1.0.0 (2026-02-13)

### Features
- Trust score 0-100 with letter grade (A-F)
- 7 analysis modules: commits, contributors, code quality, AI detection, social, activity, crypto
- Bot commit separation (dependabot, github-actions excluded from metrics)
- GPG signature verification
- Crypto-specific: launchpad token detection, placeholder program IDs, wallet scanning
- AI slop detection in READMEs
- Security scanning (exposed credentials, private keys)
- JSON output mode for pipelines
- Zero dependencies (Node.js built-ins only)
