# Contributing

PRs welcome. Keep it simple.

## Quick Start

```bash
git clone https://github.com/Don-GBot/Repo-Analyzer.git
cd Repo-Analyzer
node tests/test-analyze.js    # run tests
node analyze.js owner/repo    # test a scan
```

## Adding Analysis Modules

Each module is a numbered section in `analyze.js`. To add a new check:

1. Add analysis logic in `analyzeRepo()` — follow the pattern of existing modules
2. Store results on the `results` object
3. Add scoring in the `// --- SCORING ---` section
4. Add display output in `printReport()`
5. Add a test in `tests/test-analyze.js`
6. Update `docs/scoring.md` with the new category
7. Update CHANGELOG.md

## Guidelines

- **Zero external dependencies.** Use Node.js built-ins only. This is non-negotiable.
- All checks must work without a GitHub token (lower rate limits are acceptable)
- Keep the single-file architecture — one script, no build step, no transpilation
- Handle API failures gracefully (try/catch, don't crash on 404s or rate limits)
- Minimize false positives — better to miss something than to cry wolf

## Code Style

- Functions use `async/await`
- HTTP via Node's built-in `https` module
- No semicolons at line ends (except in ambiguous cases)
- Descriptive variable names, minimal comments (code should be clear)

## Reporting Issues

- Include the repo URL that triggered the issue
- Include the full output (use `--verbose`)
- Note your Node.js version and whether you used a GitHub token
