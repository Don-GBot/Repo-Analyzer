#!/usr/bin/env node
/**
 * Basic tests for repo analyzer
 * Run: node tests/test-analyze.js
 */

const { execSync } = require('child_process');
const path = require('path');

const ANALYZE = path.join(__dirname, '..', 'analyze.js');
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

console.log('\nRepo Analyzer Tests\n');

// Test 1: No args shows usage
test('shows usage with no args', () => {
  try {
    execSync(`node ${ANALYZE} 2>&1`);
  } catch (e) {
    assert(e.stdout.toString().includes('Usage') || e.stderr.toString().includes('Usage'), 'Should show usage');
  }
});

// Test 2: Invalid repo returns error
test('handles invalid repo gracefully', () => {
  try {
    execSync(`node ${ANALYZE} nonexistent/repo-that-doesnt-exist-xyz 2>&1`);
  } catch (e) {
    assert(e.status !== 0, 'Should exit with non-zero');
  }
});

// Test 3: Parses GitHub URLs
test('parses github.com URLs', () => {
  // Test URL parsing by checking the output mentions the repo
  const out = execSync(`node ${ANALYZE} https://github.com/nodejs/node --json 2>/dev/null`).toString();
  const data = JSON.parse(out);
  assert(data.meta.name === 'nodejs/node', `Expected nodejs/node, got ${data.meta.name}`);
});

// Test 4: JSON output is valid
test('produces valid JSON with --json', () => {
  const out = execSync(`node ${ANALYZE} nodejs/node --json 2>/dev/null`).toString();
  const data = JSON.parse(out);
  assert(typeof data.trustScore === 'number', 'trustScore should be a number');
  assert(data.grade.match(/^[A-F]$/), 'grade should be A-F');
  assert(data.scores && typeof data.scores === 'object', 'scores should be an object');
});

// Test 5: Score is bounded
test('trust score is 0-100', () => {
  const out = execSync(`node ${ANALYZE} nodejs/node --json 2>/dev/null`).toString();
  const data = JSON.parse(out);
  assert(data.trustScore >= 0 && data.trustScore <= 100, `Score ${data.trustScore} out of range`);
});

// Test 6: Detects all score categories
test('has all scoring categories', () => {
  const out = execSync(`node ${ANALYZE} nodejs/node --json 2>/dev/null`).toString();
  const data = JSON.parse(out);
  const expected = ['commits', 'contributors', 'codeQuality', 'aiAuthenticity', 'social', 'activity', 'cryptoRisk'];
  for (const key of expected) {
    assert(key in data.scores, `Missing score category: ${key}`);
  }
});

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
