# Contributing

PRs welcome. Keep it simple:

1. Fork the repo
2. Make changes
3. Run tests: `node tests/test-analyze.js`
4. Submit a PR

## Adding new checks

Each analysis module is a section in `analyze.js`. To add a new check:

1. Add the analysis logic in the `analyzeRepo` function
2. Add scoring in the scoring section
3. Add display in `printReport`
4. Add a test in `tests/test-analyze.js`
5. Update `docs/scoring.md` with the new category weights

## Guidelines

- Zero external dependencies. Use Node.js built-ins only.
- All checks must work without a GitHub token (lower rate limits are fine)
- Keep the single-file architecture. One script, no build step.
