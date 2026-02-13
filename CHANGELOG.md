# Changelog

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
