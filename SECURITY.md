# Security Policy

## Reporting Vulnerabilities

If you discover a security issue, please report it privately:

1. **Do not** open a public GitHub issue
2. Email: donog25@gmail.com
3. Include: description, reproduction steps, and potential impact

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Scope

This tool analyzes public GitHub repositories via the GitHub REST API. It does not:

- Execute any code from analyzed repositories
- Store or transmit repository data to third parties
- Require write access to any GitHub resources
- Use any dependencies beyond Node.js built-ins

## Security Design

- **Zero dependencies**: No supply chain attack surface from npm packages
- **Read-only**: Only uses GitHub API read endpoints
- **Local analysis**: All scoring logic runs on your machine
- **No telemetry**: Nothing phones home

## Token Handling

If you provide a `GITHUB_TOKEN`, it is:

- Used solely for GitHub API authentication (read-only)
- Never logged, stored, or transmitted anywhere besides `api.github.com`
- Passed via `Authorization: Bearer` header per GitHub's specification
