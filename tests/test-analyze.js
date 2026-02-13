#!/usr/bin/env node
/**
 * Tests for repo analyzer
 * Run: node tests/test-analyze.js
 *
 * Tests 1-2 are offline (no API calls). Tests 3-7 require network.
 * Set GITHUB_TOKEN for reliable CI runs.
 */

const { execSync } = require('child_process');
const path = require('path');

const ANALYZE = path.join(__dirname, '..', 'analyze.js');
let passed = 0;
let failed = 0;
let skipped = 0;

function test(name, fn, requiresNetwork = false) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    if (requiresNetwork && /rate limit|Bad credentials|ENOTFOUND|ETIMEDOUT/i.test(e.message + (e.stderr?.toString() || '') + (e.stdout?.toString() || ''))) {
      console.log(`  ⊘ ${name} (skipped — rate limited or no network)`);
      skipped++;
    } else {
      console.log(`  ✗ ${name}: ${e.message}`);
      failed++;
    }
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

console.log('\nRepo Analyzer Tests\n');

// --- Offline tests ---

test('shows usage with no args', () => {
  try {
    execSync(`node ${ANALYZE} 2>&1`, { timeout: 10000 });
  } catch (e) {
    const output = (e.stdout?.toString() || '') + (e.stderr?.toString() || '');
    assert(output.includes('Usage'), 'Should show usage');
  }
});

test('rejects invalid input format', () => {
  try {
    execSync(`node ${ANALYZE} "not a valid repo" 2>&1`, { timeout: 10000 });
    assert(false, 'Should have exited with error');
  } catch (e) {
    assert(e.status !== 0, 'Should exit with non-zero');
  }
});

// --- Network tests ---

test('handles nonexistent repo', () => {
  try {
    execSync(`node ${ANALYZE} nonexistent-user-xyz/repo-that-doesnt-exist 2>&1`, { timeout: 30000 });
    assert(false, 'Should have exited with error');
  } catch (e) {
    assert(e.status !== 0, 'Should exit with non-zero');
  }
}, true);

test('parses github.com URLs', () => {
  const out = execSync(`node ${ANALYZE} https://github.com/Don-GBot/Repo-Analyzer --oneline 2>/dev/null`, { timeout: 60000 }).toString();
  assert(out.includes('Don-GBot/Repo-Analyzer'), `Should contain repo name, got: ${out.trim()}`);
}, true);

test('produces valid JSON with --json', () => {
  const out = execSync(`node ${ANALYZE} Don-GBot/Repo-Analyzer --json 2>/dev/null`, { timeout: 60000 }).toString();
  const data = JSON.parse(out);
  assert(typeof data.trustScore === 'number', 'trustScore should be a number');
  assert(data.grade.match(/^[A-F]$/), 'grade should be A-F');
  assert(data.scores && typeof data.scores === 'object', 'scores should be an object');
}, true);

test('trust score is 0-100', () => {
  const out = execSync(`node ${ANALYZE} Don-GBot/Repo-Analyzer --json 2>/dev/null`, { timeout: 60000 }).toString();
  const data = JSON.parse(out);
  assert(data.trustScore >= 0 && data.trustScore <= 100, `Score ${data.trustScore} out of range`);
}, true);

test('has all 12 scoring categories', () => {
  const out = execSync(`node ${ANALYZE} Don-GBot/Repo-Analyzer --json 2>/dev/null`, { timeout: 60000 }).toString();
  const data = JSON.parse(out);
  const expected = ['commits', 'contributors', 'codeQuality', 'aiAuthenticity', 'social', 'activity', 'cryptoRisk', 'readmeQuality', 'maintainability', 'projectHealth', 'originality', 'agentSafety2'];
  for (const key of expected) {
    assert(key in data.scores, `Missing score category: ${key}`);
  }
}, true);

test('agent safety module produces results', () => {
  const out = execSync(`node ${ANALYZE} Don-GBot/Repo-Analyzer --json 2>/dev/null`, { timeout: 60000 }).toString();
  const data = JSON.parse(out);
  assert(data.agentSafety, 'Should have agentSafety object');
  assert(['PASS', 'CAUTION', 'FAIL'].includes(data.agentSafety.verdict), `Invalid verdict: ${data.agentSafety.verdict}`);
  assert(Array.isArray(data.agentSafety.critical), 'Should have critical array');
  assert(Array.isArray(data.agentSafety.warning), 'Should have warning array');
}, true);

test('oneline output format', () => {
  const out = execSync(`node ${ANALYZE} Don-GBot/Repo-Analyzer --oneline 2>/dev/null`, { timeout: 60000 }).toString().trim();
  assert(/^\S+\/\S+: \d+\/100 \[[A-F]\]/.test(out), `Invalid oneline format: ${out}`);
}, true);

// --- Summary ---
console.log(`\n${passed} passed, ${failed} failed${skipped > 0 ? `, ${skipped} skipped` : ''}\n`);
process.exit(failed > 0 ? 1 : 0);
