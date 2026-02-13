#!/usr/bin/env node
/**
 * GitHub Repo Analyzer — deep trust scoring for any public repo
 * Zero dependencies (Node.js built-ins only)
 * 
 * Usage: node analyze.js <github-url-or-owner/repo> [--json] [--verbose]
 */

const https = require('https');
const { parseArgs } = require('util');

const { values: args, positionals } = parseArgs({
  options: {
    'json': { type: 'boolean', default: false },
    'verbose': { type: 'boolean', default: false },
    'token': { type: 'string', default: '' },
    'oneline': { type: 'boolean', default: false },
    'badge': { type: 'boolean', default: false },
    'file': { type: 'string', default: '' },
  },
  allowPositionals: true,
  strict: false,
});

const GITHUB_TOKEN = args.token || process.env.GITHUB_TOKEN || '';

// --- HTTP helpers ---
function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const h = {
      'User-Agent': 'github-analyzer/1.0',
      'Accept': 'application/vnd.github.v3+json',
      ...headers,
    };
    if (GITHUB_TOKEN) h['Authorization'] = `Bearer ${GITHUB_TOKEN}`;
    
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname, path: u.pathname + u.search,
      headers: h,
    }, res => {
      // Follow redirects (301, 302, 307)
      if ([301, 302, 307].includes(res.statusCode) && res.headers.location) {
        get(res.headers.location, headers).then(resolve).catch(reject);
        return;
      }
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(d), headers: res.headers }); }
        catch(e) { resolve({ status: res.statusCode, data: d, headers: res.headers }); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function getRaw(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname, path: u.pathname + u.search,
      headers: { 'User-Agent': 'github-analyzer/1.0' },
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve(d));
    });
    req.on('error', reject);
    req.end();
  });
}

// --- Parse repo from URL or owner/repo ---
function parseRepo(input) {
  input = input.trim().replace(/\/$/, '');
  const ghMatch = input.match(/github\.com\/([^\/]+)\/([^\/\?#]+)/);
  if (ghMatch) return { owner: ghMatch[1], repo: ghMatch[2].replace('.git', '') };
  const slashMatch = input.match(/^([^\/]+)\/([^\/]+)$/);
  if (slashMatch) return { owner: slashMatch[1], repo: slashMatch[2] };
  return null;
}

// --- Analysis modules ---

async function analyzeRepo(owner, repo) {
  const results = {
    meta: null,
    commits: null,
    contributors: null,
    activity: null,
    codeQuality: null,
    social: null,
    crypto: null,
    security: null,
    scores: {},
    grade: '',
    trustScore: 0,
    flags: [],
    warnings: [],
  };

  const base = `https://api.github.com/repos/${owner}/${repo}`;
  const v = args.verbose;

  // 1. Repository metadata
  if (v) console.error('Fetching repo metadata...');
  const repoRes = await get(base);
  if (repoRes.status === 404) {
    throw new Error(`Repository ${owner}/${repo} not found`);
  }
  const r = repoRes.data;
  results.meta = {
    name: r.full_name,
    description: r.description,
    language: r.language,
    stars: r.stargazers_count,
    forks: r.forks_count,
    watchers: r.subscribers_count || r.watchers_count,
    openIssues: r.open_issues_count,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    pushedAt: r.pushed_at,
    size: r.size,
    defaultBranch: r.default_branch,
    hasIssues: r.has_issues,
    hasWiki: r.has_wiki,
    license: r.license?.spdx_id || null,
    isForked: r.fork,
    parent: r.parent?.full_name || null,
    archived: r.archived,
    topics: r.topics || [],
  };

  // 2. Commit analysis
  if (v) console.error('Analyzing commits...');
  const commitsRes = await get(`${base}/commits?per_page=100`);
  const commits = Array.isArray(commitsRes.data) ? commitsRes.data : [];
  
  const authors = {};
  const commitDates = [];
  let gpgSigned = 0;
  let singleFileCommits = 0;
  
  let botCommits = 0;
  for (const c of commits) {
    const author = c.commit?.author?.email || 'unknown';
    const name = c.commit?.author?.name || 'unknown';
    const isBot = /\[bot\]|dependabot|github-actions|renovate|greenkeeper|snyk/i.test(name) || /\[bot\]/i.test(author);
    if (isBot) { botCommits++; continue; } // skip bots for author analysis
    authors[author] = authors[author] || { name, count: 0, firstCommit: null, lastCommit: null };
    authors[author].count++;
    const date = c.commit?.author?.date;
    if (date) {
      commitDates.push(new Date(date));
      if (!authors[author].firstCommit) authors[author].firstCommit = date;
      authors[author].lastCommit = date;
    }
    if (c.commit?.verification?.verified) gpgSigned++;
  }
  const humanCommits = commits.length - botCommits;

  // Detect code dump (few commits, recent creation)
  const ageMs = Date.now() - new Date(r.created_at).getTime();
  const ageDays = ageMs / 86400000;
  const commitsPerDay = humanCommits / Math.max(ageDays, 1);
  const isCodeDump = humanCommits <= 3 && ageDays < 30;

  // Detect suspiciously perfect timestamps (evenly spaced = likely faked)
  let evenlySpaced = false;
  if (commitDates.length >= 5) {
    const gaps = [];
    for (let i = 1; i < commitDates.length; i++) {
      gaps.push(commitDates[i - 1] - commitDates[i]);
    }
    const avgGap = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const variance = gaps.reduce((a, b) => a + Math.pow(b - avgGap, 2), 0) / gaps.length;
    const stdDev = Math.sqrt(variance);
    const cv = avgGap > 0 ? stdDev / avgGap : 0;
    evenlySpaced = cv < 0.15 && commits.length >= 5; // very low variance = suspicious
  }

  results.commits = {
    total: commits.length,
    human: humanCommits,
    bot: botCommits,
    authors: Object.entries(authors).map(([email, data]) => ({
      email, name: data.name, commits: data.count,
      firstCommit: data.firstCommit, lastCommit: data.lastCommit,
    })),
    gpgSigned,
    gpgRate: commits.length > 0 ? Math.round(gpgSigned / commits.length * 100) : 0,
    commitsPerDay: Math.round(commitsPerDay * 100) / 100,
    isCodeDump,
    evenlySpaced,
    oldestCommit: commitDates.length > 0 ? commitDates[commitDates.length - 1].toISOString() : null,
    newestCommit: commitDates.length > 0 ? commitDates[0].toISOString() : null,
  };

  // 3. Contributors
  if (v) console.error('Analyzing contributors...');
  const contribRes = await get(`${base}/contributors?per_page=30`);
  const contribs = Array.isArray(contribRes.data) ? contribRes.data : [];
  
  const busFactor = contribs.filter(c => c.contributions > commits.length * 0.1).length;
  
  // Check contributor account ages
  const suspiciousContribs = [];
  for (const c of contribs.slice(0, 5)) {
    const userRes = await get(`https://api.github.com/users/${c.login}`);
    if (userRes.data) {
      const acctAge = (Date.now() - new Date(userRes.data.created_at).getTime()) / 86400000;
      const repos = userRes.data.public_repos || 0;
      const followers = userRes.data.followers || 0;
      if (acctAge < 90 && repos < 3) {
        suspiciousContribs.push({ login: c.login, ageDays: Math.round(acctAge), repos, followers });
      }
    }
  }

  results.contributors = {
    total: contribs.length,
    busFactor,
    topContributors: contribs.slice(0, 5).map(c => ({
      login: c.login, contributions: c.contributions
    })),
    suspiciousAccounts: suspiciousContribs,
  };

  // 4. Activity & health
  if (v) console.error('Checking activity...');
  const lastPush = new Date(r.pushed_at);
  const daysSinceLastPush = (Date.now() - lastPush) / 86400000;
  
  // Issues
  let issueHealth = null;
  if (r.has_issues) {
    const openRes = await get(`${base}/issues?state=open&per_page=1`);
    const closedRes = await get(`${base}/issues?state=closed&per_page=1`);
    // Get total from link headers
    const openCount = r.open_issues_count;
    issueHealth = { open: openCount };
  }

  // Releases
  const releasesRes = await get(`${base}/releases?per_page=5`);
  const releases = Array.isArray(releasesRes.data) ? releasesRes.data : [];

  results.activity = {
    daysSinceLastPush: Math.round(daysSinceLastPush),
    ageDays: Math.round(ageDays),
    issues: issueHealth,
    releases: releases.length,
    latestRelease: releases[0]?.tag_name || null,
  };

  // 5. Code quality signals
  if (v) console.error('Analyzing code quality...');
  const treeRes = await get(`${base}/git/trees/${r.default_branch}?recursive=1`);
  const tree = treeRes.data?.tree || [];
  
  const files = tree.map(f => f.path);
  const hasTests = files.some(f => /test|spec|__test__|\.test\.|\.spec\./i.test(f));
  const hasCI = files.some(f => /\.github\/workflows|\.circleci|\.travis|jenkinsfile|\.gitlab-ci/i.test(f));
  const hasLicense = files.some(f => /^license/i.test(f));
  const hasReadme = files.some(f => /^readme/i.test(f));
  const hasGitignore = files.some(f => f === '.gitignore');
  const hasPackageLock = files.some(f => /package-lock|yarn\.lock|bun\.lock|Cargo\.lock|go\.sum|poetry\.lock/i.test(f));
  const hasDockerfile = files.some(f => /dockerfile/i.test(f));
  const hasDocs = files.some(f => /^docs\//i.test(f));
  const hasChangelog = files.some(f => /changelog/i.test(f));
  const hasContributing = files.some(f => /contributing/i.test(f));
  const hasSecurityPolicy = files.some(f => /security\.md/i.test(f));

  // Count languages by extension
  const extensions = {};
  for (const f of files) {
    const ext = f.split('.').pop()?.toLowerCase();
    if (ext && ext.length < 8) extensions[ext] = (extensions[ext] || 0) + 1;
  }

  // Detect AI-generated patterns
  const readmeContent = await getRaw(`https://raw.githubusercontent.com/${owner}/${repo}/${r.default_branch}/README.md`).catch(() => '');
  
  const aiPatterns = [
    /this project aims to/i, /comprehensive solution/i, /robust and scalable/i,
    /leverag(e|ing) the power/i, /cutting[- ]edge/i, /state[- ]of[- ]the[- ]art/i,
    /seamless(ly)?/i, /empower(s|ing)?/i, /holistic/i, /synerg/i,
    /revolutioniz/i, /paradigm/i, /ecosystem of/i, /delve/i,
    /it'?s important to note/i, /it'?s worth noting/i,
  ];
  
  const aiHits = aiPatterns.filter(p => p.test(readmeContent));
  const readmeLength = readmeContent.length;
  const hasEmoji = (readmeContent.match(/[\u{1F300}-\u{1F9FF}]/gu) || []).length;
  const emojiDensity = readmeLength > 0 ? hasEmoji / (readmeLength / 1000) : 0;

  results.codeQuality = {
    totalFiles: files.length,
    hasTests, hasCI, hasLicense, hasReadme, hasGitignore, hasPackageLock,
    hasDockerfile, hasDocs, hasChangelog, hasContributing, hasSecurityPolicy,
    extensions: Object.entries(extensions).sort((a, b) => b[1] - a[1]).slice(0, 10),
    aiSlop: {
      hits: aiHits.length,
      patterns: aiHits.map(p => p.source),
      emojiDensity: Math.round(emojiDensity * 10) / 10,
      readmeLength,
    },
  };

  // 6. Social signals
  if (v) console.error('Checking social signals...');
  const starForkRatio = r.forks_count > 0 ? r.stargazers_count / r.forks_count : r.stargazers_count;
  
  // Check for star velocity anomalies (if we can get stargazers)
  let starVelocity = null;
  if (r.stargazers_count > 0 && ageDays > 0) {
    starVelocity = r.stargazers_count / ageDays;
  }

  // Suspicious: high stars but no forks, no issues, no contributors
  const bottedStars = r.stargazers_count > 50 && r.forks_count < 3 && contribs.length <= 1;

  results.social = {
    stars: r.stargazers_count,
    forks: r.forks_count,
    starForkRatio: Math.round(starForkRatio * 10) / 10,
    starsPerDay: starVelocity ? Math.round(starVelocity * 100) / 100 : null,
    bottedStars,
  };

  // 7. Crypto-specific checks
  if (v) console.error('Running crypto checks...');
  const cryptoFlags = [];
  
  // Check for pump.fun patterns
  const allContent = files.join('\n');
  if (/pump\.fun|pumpfun/i.test(readmeContent) || files.some(f => /pump/i.test(f))) {
    cryptoFlags.push('pump.fun references detected');
  }
  
  // Check for hardcoded wallet addresses in file names or readme
  const walletPatterns = [
    /0x[a-fA-F0-9]{40}/g,  // EVM
    /[1-9A-HJ-NP-Za-km-z]{32,44}/g,  // Solana/Base58 (rough)
  ];
  
  const readmeWallets = [];
  for (const p of walletPatterns) {
    const matches = readmeContent.match(p) || [];
    readmeWallets.push(...matches);
  }
  if (readmeWallets.length > 0) {
    cryptoFlags.push(`${readmeWallets.length} wallet address(es) in README`);
  }

  // Check for token mints ending in "pump"
  if (/[a-zA-Z0-9]+pump\b/i.test(readmeContent + allContent)) {
    cryptoFlags.push('Possible pump.fun token mint detected');
  }

  // Check config files for token/mint references
  const configFiles = files.filter(f => /\.toml|\.json|\.yaml|\.yml|\.env/i.test(f) && !/node_modules|package-lock/.test(f));
  for (const cf of configFiles.slice(0, 10)) {
    try {
      const content = await getRaw(`https://raw.githubusercontent.com/${owner}/${repo}/${r.default_branch}/${cf}`);
      if (/pump\b/i.test(content) && /mint|token/i.test(content)) {
        cryptoFlags.push(`Token mint with pump.fun pattern in ${cf}`);
      }
      // Check for placeholder program IDs
      if (/[A-Z]{5,}x{10,}/.test(content)) {
        cryptoFlags.push(`Placeholder program ID in ${cf} — not deployed`);
      }
    } catch {}
  }

  results.crypto = {
    flags: cryptoFlags,
    hasCryptoContent: cryptoFlags.length > 0 || r.topics?.some(t => /crypto|defi|solana|ethereum|web3|nft|token/i.test(t)),
  };

  // 8. Dependency analysis
  if (v) console.error('Scanning dependencies...');
  const depFlags = [];
  const depInfo = { totalDeps: 0, directDeps: 0, devDeps: 0, outdated: [], suspicious: [] };

  // Check package.json (Node)
  try {
    const pkgContent = await getRaw(`https://raw.githubusercontent.com/${owner}/${repo}/${r.default_branch}/package.json`);
    if (pkgContent && !pkgContent.includes('404')) {
      const pkg = JSON.parse(pkgContent);
      const deps = Object.keys(pkg.dependencies || {});
      const devDeps = Object.keys(pkg.devDependencies || {});
      depInfo.directDeps = deps.length;
      depInfo.devDeps = devDeps.length;
      depInfo.totalDeps = deps.length + devDeps.length;

      // Check for suspicious/typosquatting patterns
      const knownSuspicious = /^[a-z]+-[a-z]+s$|^[a-z]{1,3}$/; // overly short names
      for (const d of deps) {
        // Check for known malicious patterns
        if (d.includes('--') || d.includes('..') || /^@[^\/]+\/[^\/]+\//.test(d)) {
          depFlags.push(`Suspicious dependency format: ${d}`);
        }
        // Typosquatting: common packages with slight misspellings
        const typos = {
          'lodash': ['lodashs', 'lodash-es-fake', 'l0dash'],
          'express': ['expres', 'expresss', 'exppress'],
          'axios': ['axois', 'axio', 'axioss'],
          'react': ['reakt', 'reactt'],
        };
        for (const [real, fakes] of Object.entries(typos)) {
          if (fakes.includes(d)) depFlags.push(`Possible typosquat: ${d} (did you mean ${real}?)`);
        }
      }

      // Check for wildcard versions (security risk)
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const [name, version] of Object.entries(allDeps)) {
        if (version === '*' || version === 'latest') {
          depFlags.push(`Unpinned dependency: ${name}@${version}`);
        }
      }
    }
  } catch {}

  // Check requirements.txt (Python)
  try {
    const reqContent = await getRaw(`https://raw.githubusercontent.com/${owner}/${repo}/${r.default_branch}/requirements.txt`);
    if (reqContent && !reqContent.includes('404') && reqContent.length < 50000) {
      const lines = reqContent.split('\n').filter(l => l.trim() && !l.startsWith('#'));
      depInfo.totalDeps += lines.length;
      depInfo.directDeps += lines.length;
      // Check for unpinned
      for (const l of lines) {
        const name = l.split(/[=<>!]/)[0].trim();
        if (name && !l.includes('==') && !l.includes('>=')) {
          depFlags.push(`Unpinned Python dependency: ${name}`);
        }
      }
    }
  } catch {}

  // Check Cargo.toml (Rust)
  try {
    const cargoContent = await getRaw(`https://raw.githubusercontent.com/${owner}/${repo}/${r.default_branch}/Cargo.toml`);
    if (cargoContent && !cargoContent.includes('404')) {
      const depMatches = cargoContent.match(/\[dependencies\]([\s\S]*?)(\[|$)/);
      if (depMatches) {
        const depLines = depMatches[1].split('\n').filter(l => l.trim() && !l.startsWith('#'));
        depInfo.totalDeps += depLines.length;
        depInfo.directDeps += depLines.length;
      }
    }
  } catch {}

  results.dependencies = { ...depInfo, flags: depFlags };

  // 9. Author identity verification
  if (v) console.error('Verifying author identities...');
  const authorVerification = [];

  for (const author of Object.entries(authors).slice(0, 5)) {
    const [email, data] = author;
    const verification = { email, name: data.name, verified: false, flags: [] };

    // Check if email domain matches a known company
    const domain = email.split('@')[1];
    const corpDomains = {
      'google.com': 'Google', 'microsoft.com': 'Microsoft', 'apple.com': 'Apple',
      'amazon.com': 'Amazon', 'amazon.de': 'Amazon', 'meta.com': 'Meta', 'facebook.com': 'Meta',
      'venmo.com': 'Venmo/PayPal', 'stripe.com': 'Stripe', 'coinbase.com': 'Coinbase',
      'binance.com': 'Binance', 'kraken.com': 'Kraken',
    };

    if (corpDomains[domain]) {
      verification.claimedOrg = corpDomains[domain];
      verification.flags.push(`Claims ${corpDomains[domain]} affiliation via email — unverified without GPG signature`);
    }

    // Try to find GitHub user by commit email
    const searchRes = await get(`https://api.github.com/search/users?q=${encodeURIComponent(email)}+in:email`);
    if (searchRes.data?.total_count > 0) {
      const user = searchRes.data.items[0];
      verification.githubUser = user.login;

      // Check if user's public profile matches claimed identity
      const profileRes = await get(`https://api.github.com/users/${user.login}`);
      if (profileRes.data) {
        const profile = profileRes.data;
        verification.profileName = profile.name;
        verification.publicRepos = profile.public_repos;
        verification.followers = profile.followers;
        verification.createdAt = profile.created_at;
        verification.bio = profile.bio;
        verification.company = profile.company;

        // Cross-reference name
        if (profile.name && data.name && profile.name.toLowerCase() !== data.name.toLowerCase()) {
          verification.flags.push(`Commit name "${data.name}" doesn't match profile name "${profile.name}"`);
        }

        // Cross-reference company claim
        if (verification.claimedOrg && profile.company) {
          if (profile.company.toLowerCase().includes(verification.claimedOrg.toLowerCase().split('/')[0])) {
            verification.verified = true;
            verification.flags.push(`Company "${profile.company}" matches email domain — likely legit`);
          }
        }

        // Account age vs commit age
        const acctDate = new Date(profile.created_at);
        const firstCommitDate = data.firstCommit ? new Date(data.firstCommit) : null;
        if (firstCommitDate && acctDate > firstCommitDate) {
          verification.flags.push(`GitHub account created AFTER first commit — possible retroactive attribution`);
        }
      }
    } else {
      // No GitHub user found with this email
      if (verification.claimedOrg) {
        verification.flags.push(`No GitHub account found with email ${email} — corporate claim is unverifiable`);
      }
      // Check if it's a noreply email
      if (email.includes('noreply.github.com')) {
        verification.flags.push('Using GitHub noreply email — identity hidden');
      }
    }

    // GPG check for this author's commits
    const authorCommits = commits.filter(c => c.commit?.author?.email === email);
    const signedCount = authorCommits.filter(c => c.commit?.verification?.verified).length;
    verification.gpgSigned = signedCount;
    verification.gpgTotal = authorCommits.length;
    if (signedCount === 0 && verification.claimedOrg) {
      verification.flags.push(`0/${authorCommits.length} commits GPG-signed — anyone could have set this email`);
    } else if (signedCount > 0) {
      verification.verified = true;
      verification.flags.push(`${signedCount}/${authorCommits.length} commits GPG-signed — cryptographically verified`);
    }

    authorVerification.push(verification);
  }

  results.authorVerification = authorVerification;

  // 9b. Author reputation deep-dive — only surfaces noteworthy findings
  if (v) console.error('Checking author reputation...');
  const authorReputation = [];

  for (const av of authorVerification) {
    if (!av.githubUser) continue;
    const notes = [];

    try {
      // Get their repos (sorted by stars)
      const reposRes = await get(`https://api.github.com/users/${av.githubUser}/repos?sort=stars&per_page=30&type=owner`);
      const repos = reposRes.data || [];

      // Account age
      if (av.createdAt) {
        const acctAge = (Date.now() - new Date(av.createdAt).getTime()) / (1000 * 60 * 60 * 24 * 365);
        if (acctAge < 0.5) notes.push(`⚠️ Account <6 months old`);
        else if (acctAge > 8) notes.push(`Account ${Math.floor(acctAge)}+ years old`);
      }

      // Follower signal
      if (av.followers >= 1000) notes.push(`${av.followers.toLocaleString()} followers`);
      else if (av.followers === 0 && repos.length > 5) notes.push(`⚠️ 0 followers despite ${repos.length} repos`);

      // Notable repos they own
      const starredRepos = repos.filter(r => r.stargazers_count >= 100);
      if (starredRepos.length > 0) {
        const top = starredRepos[0];
        notes.push(`Maintains ${top.full_name} (${top.stargazers_count.toLocaleString()}⭐)`);
        if (starredRepos.length > 1) notes.push(`${starredRepos.length} repos with 100+ stars`);
      }

      // Empty/fork-heavy profile (sketch signal)
      const forks = repos.filter(r => r.fork);
      const empty = repos.filter(r => r.size === 0);
      if (repos.length > 0 && forks.length / repos.length > 0.7) {
        notes.push(`⚠️ ${Math.round(forks.length/repos.length*100)}% of repos are forks`);
      }
      if (empty.length > repos.length * 0.5 && repos.length > 3) {
        notes.push(`⚠️ ${empty.length}/${repos.length} repos are empty`);
      }

      // Crypto-specific checks on their other repos
      const scamSignals = ['pump', 'honeypot', 'rug', 'drainer', 'sandwich', 'frontrun', 'flashloan-attack', 'mev-bot'];
      for (const repo of repos) {
        const name = (repo.name + ' ' + (repo.description || '')).toLowerCase();
        if (scamSignals.some(s => name.includes(s))) {
          notes.push(`🚩 Owns suspicious repo: ${repo.full_name} — "${repo.description || repo.name}"`);
        }
      }

      // Check orgs they belong to
      const orgsRes = await get(`https://api.github.com/users/${av.githubUser}/orgs`);
      const orgs = (orgsRes.data || []).map(o => o.login);
      const notableOrgs = {
        'google': 'Google', 'microsoft': 'Microsoft', 'facebook': 'Meta', 'meta': 'Meta',
        'apple': 'Apple', 'ethereum': 'Ethereum Foundation', 'solana-labs': 'Solana Labs',
        'paradigmxyz': 'Paradigm', 'a16z': 'a16z', 'OpenZeppelin': 'OpenZeppelin',
        'foundry-rs': 'Foundry', 'uniswap': 'Uniswap', 'aave': 'Aave',
        'coinbase': 'Coinbase', 'binance': 'Binance', 'consensys': 'ConsenSys',
        'chainlink': 'Chainlink', 'MakerDAO': 'MakerDAO', 'compound-finance': 'Compound',
        'rust-lang': 'Rust', 'nodejs': 'Node.js', 'vercel': 'Vercel', 'docker': 'Docker',
      };
      for (const org of orgs) {
        if (notableOrgs[org]) {
          notes.push(`Member of ${notableOrgs[org]} org`);
        }
      }

      // Check contribution to big repos (starred repos they've contributed to)
      const starredRes = await get(`https://api.github.com/users/${av.githubUser}/starred?per_page=5`);
      // We can't easily check contributions without heavy API use, so org membership + own repos suffices

    } catch (e) {
      // API failures are non-fatal
    }

    if (notes.length > 0) {
      authorReputation.push({ user: av.githubUser, name: av.name || av.profileName, notes });
    }
  }

  results.authorReputation = authorReputation;

  // 10. Security signals
  const secFlags = [];
  // Check for exposed secrets patterns in file list
  if (files.some(f => /\.env$|credentials|secrets?\./i.test(f) && !/\.example|\.sample|\.template/i.test(f))) {
    secFlags.push('Possible exposed credentials file');
  }
  const keyFiles = files.filter(f => /id_rsa|id_ed25519|\.pem$|\.key$/i.test(f));
  const realKeyFiles = keyFiles.filter(f => !/test|fixture|sample|example|mock|fake/i.test(f));
  if (realKeyFiles.length > 0) {
    secFlags.push(`Private key file in repo: ${realKeyFiles.slice(0, 3).join(', ')}`);
  } else if (keyFiles.length > 0) {
    // Keys in test dirs — note but don't flag
    results.warnings.push(`Key files in test/fixture dirs (probably fine): ${keyFiles.length} file(s)`);
  }

  results.security = { flags: secFlags };

  // 11. README quality analysis
  if (v) console.error('Analyzing README quality...');
  const readmeQuality = { score: 0, maxScore: 10, checks: {} };
  if (readmeContent && readmeContent.length > 50) {
    // Installation instructions
    readmeQuality.checks.hasInstall = /install|setup|getting started|quick start|prerequisites/i.test(readmeContent);
    // Usage examples (code blocks with commands)
    const codeBlocks = (readmeContent.match(/```[\s\S]*?```/g) || []);
    readmeQuality.checks.hasCodeExamples = codeBlocks.length >= 1;
    readmeQuality.checks.codeBlockCount = codeBlocks.length;
    // API/function docs
    readmeQuality.checks.hasApiDocs = /api|function|method|parameter|argument|returns?|endpoint/i.test(readmeContent);
    // Contributing mention
    readmeQuality.checks.hasContributing = /contribut/i.test(readmeContent);
    // License mention
    readmeQuality.checks.hasLicenseMention = /license|licence|mit|apache|gpl|bsd/i.test(readmeContent);
    // Appropriate length (not too short for the repo size)
    const readmeWords = readmeContent.split(/\s+/).length;
    readmeQuality.checks.wordCount = readmeWords;
    readmeQuality.checks.appropriateLength = readmeWords >= 50 && readmeWords <= 5000;
    // Has sections/headings
    const headings = (readmeContent.match(/^#{1,3}\s+.+/gm) || []);
    readmeQuality.checks.hasStructure = headings.length >= 3;
    readmeQuality.checks.headingCount = headings.length;

    // Score
    let rScore = 0;
    if (readmeQuality.checks.hasInstall) rScore += 2;
    if (readmeQuality.checks.hasCodeExamples) rScore += 2;
    if (readmeQuality.checks.hasApiDocs) rScore += 1;
    if (readmeQuality.checks.hasContributing) rScore += 1;
    if (readmeQuality.checks.hasLicenseMention) rScore += 1;
    if (readmeQuality.checks.appropriateLength) rScore += 1;
    if (readmeQuality.checks.hasStructure) rScore += 2;
    readmeQuality.score = rScore;
  }
  results.readmeQuality = readmeQuality;

  // 12. Maintainability estimate
  if (v) console.error('Estimating maintainability...');
  const codeExts = ['js', 'ts', 'py', 'rb', 'go', 'rs', 'java', 'c', 'cpp', 'cs', 'php', 'swift', 'kt', 'scala', 'sol', 'move'];
  const codeFiles = files.filter(f => {
    const ext = f.split('.').pop()?.toLowerCase();
    return codeExts.includes(ext);
  });
  const configExts = ['json', 'yaml', 'yml', 'toml', 'xml', 'ini', 'cfg', 'env'];
  const configFiles2 = files.filter(f => {
    const ext = f.split('.').pop()?.toLowerCase();
    return configExts.includes(ext);
  });
  const docFiles = files.filter(f => /\.md$/i.test(f));

  // Directory depth
  const depths = files.map(f => f.split('/').length - 1);
  const maxDepth = depths.length > 0 ? Math.max(...depths) : 0;
  const avgDepth = depths.length > 0 ? depths.reduce((a, b) => a + b, 0) / depths.length : 0;

  // File sizes (from tree, we have blob sizes)
  const treeSizes = (treeRes.data?.tree || []).filter(t => t.type === 'blob').map(t => t.size || 0);
  const avgFileSize = treeSizes.length > 0 ? treeSizes.reduce((a, b) => a + b, 0) / treeSizes.length : 0;
  const maxFileSize = treeSizes.length > 0 ? Math.max(...treeSizes) : 0;
  const largeFiles = treeSizes.filter(s => s > 50000).length; // >50KB

  const maintainability = {
    codeFiles: codeFiles.length,
    configFiles: configFiles2.length,
    docFiles: docFiles.length,
    codeToDocRatio: docFiles.length > 0 ? Math.round(codeFiles.length / docFiles.length * 10) / 10 : codeFiles.length,
    maxDepth,
    avgDepth: Math.round(avgDepth * 10) / 10,
    avgFileSize: Math.round(avgFileSize),
    maxFileSize,
    largeFiles,
    score: 0,
    maxScore: 10,
  };

  // Score maintainability
  let mScore = 5;
  if (maxDepth <= 5) mScore += 1; else if (maxDepth > 10) mScore -= 2;
  if (largeFiles === 0) mScore += 1; else if (largeFiles > 5) mScore -= 2;
  if (docFiles.length > 0) mScore += 1;
  if (codeFiles.length > 0 && codeFiles.length < 500) mScore += 1;
  else if (codeFiles.length >= 500) mScore -= 1;
  if (avgFileSize < 10000) mScore += 1; // avg under 10KB = well-split
  maintainability.score = Math.max(0, Math.min(10, mScore));
  results.maintainability = maintainability;

  // 13. Plugin/package format detection
  if (v) console.error('Detecting plugin format...');
  const pluginFormats = [];

  // OpenClaw skill
  if (files.some(f => /^SKILL\.md$/i.test(f.split('/').pop()))) {
    const skillContent = await getRaw(`https://raw.githubusercontent.com/${owner}/${repo}/${r.default_branch}/SKILL.md`).catch(() => '');
    const hasFrontmatter = /^---\s*\n[\s\S]*?name:[\s\S]*?description:[\s\S]*?---/m.test(skillContent);
    pluginFormats.push({
      type: 'OpenClaw Skill',
      valid: hasFrontmatter,
      details: hasFrontmatter ? 'Valid SKILL.md with frontmatter' : 'SKILL.md found but missing required name/description frontmatter',
    });
  }

  // npm package
  if (files.some(f => f === 'package.json')) {
    const hasMain = readmeContent.includes('"main"') || readmeContent.includes('"exports"') || readmeContent.includes('"bin"');
    pluginFormats.push({
      type: 'npm package',
      valid: true,
      details: `package.json present${depInfo.totalDeps > 0 ? `, ${depInfo.totalDeps} deps` : ''}`,
    });
  }

  // GitHub Action
  if (files.some(f => f === 'action.yml' || f === 'action.yaml')) {
    pluginFormats.push({ type: 'GitHub Action', valid: true, details: 'action.yml found' });
  }

  // VS Code extension
  try {
    const pkgContent2 = await getRaw(`https://raw.githubusercontent.com/${owner}/${repo}/${r.default_branch}/package.json`).catch(() => '');
    if (pkgContent2 && pkgContent2.includes('"contributes"')) {
      pluginFormats.push({ type: 'VS Code Extension', valid: true, details: 'package.json with contributes field' });
    }
  } catch {}

  // Docker image
  if (files.some(f => /^Dockerfile$/i.test(f))) {
    pluginFormats.push({ type: 'Docker Image', valid: true, details: 'Dockerfile found' });
  }

  // Python package
  if (files.some(f => f === 'setup.py' || f === 'pyproject.toml' || f === 'setup.cfg')) {
    pluginFormats.push({ type: 'Python package', valid: true, details: 'Python packaging config found' });
  }

  results.pluginFormats = pluginFormats;

  // 14. License risk scoring
  if (v) console.error('Scoring license risk...');
  const licenseRisk = { license: r.license?.spdx_id || null, risk: 'unknown', details: '' };
  const permissive = ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Unlicense', '0BSD', 'CC0-1.0'];
  const copyleft = ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EUPL-1.2'];
  const weak = ['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0']; // copyleft but weaker
  if (!licenseRisk.license || licenseRisk.license === 'NOASSERTION') {
    licenseRisk.risk = 'high';
    licenseRisk.details = 'No license — legally cannot use, fork, or modify';
    results.flags.push('No license detected — all rights reserved by default');
  } else if (permissive.includes(licenseRisk.license)) {
    licenseRisk.risk = 'low';
    licenseRisk.details = `${licenseRisk.license} — permissive, safe for commercial use`;
  } else if (weak.includes(licenseRisk.license)) {
    licenseRisk.risk = 'medium';
    licenseRisk.details = `${licenseRisk.license} — weak copyleft, usable with care`;
  } else if (copyleft.includes(licenseRisk.license)) {
    licenseRisk.risk = 'high';
    licenseRisk.details = `${licenseRisk.license} — strong copyleft, derivatives must be open source`;
  } else {
    licenseRisk.risk = 'unknown';
    licenseRisk.details = `${licenseRisk.license} — uncommon license, review manually`;
  }
  results.licenseRisk = licenseRisk;

  // 15. Abandoned project detection
  if (v) console.error('Checking project health status...');
  const daysSincePush = (Date.now() - new Date(r.pushed_at).getTime()) / 86400000;
  let projectStatus = 'active';
  const abandonedSignals = [];

  if (r.archived) {
    projectStatus = 'archived';
    abandonedSignals.push('Repo is archived');
  } else if (daysSincePush > 365) {
    projectStatus = 'abandoned';
    abandonedSignals.push(`No commits in ${Math.floor(daysSincePush)} days`);
  } else if (daysSincePush > 180) {
    projectStatus = 'stale';
    abandonedSignals.push(`Last push ${Math.floor(daysSincePush)} days ago`);
  }

  // Check for unanswered issues
  if (r.has_issues && r.open_issues_count > 0) {
    const issuesRes = await get(`${base}/issues?state=open&sort=created&direction=asc&per_page=10`);
    const issues = (issuesRes.data || []).filter(i => !i.pull_request); // exclude PRs
    const oldUnanswered = issues.filter(i => {
      const age = (Date.now() - new Date(i.created_at).getTime()) / 86400000;
      return age > 90 && i.comments === 0;
    });
    if (oldUnanswered.length >= 3) {
      abandonedSignals.push(`${oldUnanswered.length} issues open 90+ days with zero responses`);
      if (projectStatus === 'active') projectStatus = 'neglected';
    }
  }

  results.projectStatus = { status: projectStatus, signals: abandonedSignals, daysSincePush: Math.floor(daysSincePush) };

  // 16. Fork quality check
  if (v) console.error('Checking fork quality...');
  const forkAnalysis = { isFork: r.fork, parent: r.parent?.full_name || null };
  if (r.fork && r.parent) {
    try {
      const parentRes = await get(`https://api.github.com/repos/${r.parent.full_name}`);
      if (parentRes.data) {
        const p = parentRes.data;
        forkAnalysis.parentStars = p.stargazers_count;
        forkAnalysis.parentUpdated = p.pushed_at;
        // Compare commit counts via comparing branches
        const compareRes = await get(`${base}/compare/${p.default_branch}...${r.default_branch}`);
        if (compareRes.data) {
          forkAnalysis.aheadBy = compareRes.data.ahead_by || 0;
          forkAnalysis.behindBy = compareRes.data.behind_by || 0;
          if (forkAnalysis.aheadBy === 0) {
            forkAnalysis.quality = 'zero-change';
            results.flags.push(`Fork of ${r.parent.full_name} with 0 changes — no original work`);
          } else if (forkAnalysis.aheadBy < 5) {
            forkAnalysis.quality = 'minimal';
          } else {
            forkAnalysis.quality = 'diverged';
          }
        }
      }
    } catch {}
  }
  results.forkAnalysis = forkAnalysis;

  // 17. Commit velocity trends
  if (v) console.error('Analyzing commit velocity...');
  const velocityTrend = { trend: 'unknown', periods: [] };
  if (commitDates.length >= 10) {
    const mid = Math.floor(commitDates.length / 2);
    const recentHalf = commitDates.slice(0, mid);
    const olderHalf = commitDates.slice(mid);

    const recentSpan = recentHalf.length > 1 ? (recentHalf[0] - recentHalf[recentHalf.length - 1]) / 86400000 : 1;
    const olderSpan = olderHalf.length > 1 ? (olderHalf[0] - olderHalf[olderHalf.length - 1]) / 86400000 : 1;

    const recentRate = recentHalf.length / Math.max(recentSpan, 1);
    const olderRate = olderHalf.length / Math.max(olderSpan, 1);

    velocityTrend.recentRate = Math.round(recentRate * 100) / 100;
    velocityTrend.olderRate = Math.round(olderRate * 100) / 100;

    if (recentRate > olderRate * 1.5) velocityTrend.trend = 'accelerating';
    else if (recentRate < olderRate * 0.5) velocityTrend.trend = 'declining';
    else velocityTrend.trend = 'steady';
  }
  results.velocityTrend = velocityTrend;

  // 18. Issue response time
  if (v) console.error('Checking issue response time...');
  const issueResponse = { avgResponseHrs: null, respondedPct: null, sampleSize: 0 };
  if (r.has_issues) {
    try {
      const closedIssuesRes = await get(`${base}/issues?state=closed&sort=updated&direction=desc&per_page=15`);
      const closedIssues = (closedIssuesRes.data || []).filter(i => !i.pull_request);
      let totalResponseMs = 0;
      let responded = 0;

      for (const issue of closedIssues.slice(0, 10)) {
        if (issue.comments > 0) {
          // First comment time approximation: use closed_at as rough proxy if fast
          const created = new Date(issue.created_at);
          const closed = new Date(issue.closed_at);
          const responseMs = closed - created;
          totalResponseMs += responseMs;
          responded++;
        }
      }

      issueResponse.sampleSize = closedIssues.slice(0, 10).length;
      if (responded > 0) {
        issueResponse.avgResponseHrs = Math.round(totalResponseMs / responded / 3600000);
        issueResponse.respondedPct = Math.round(responded / issueResponse.sampleSize * 100);
      }
    } catch {}
  }
  results.issueResponse = issueResponse;

  // 19. PR merge patterns
  if (v) console.error('Analyzing PR patterns...');
  const prPatterns = { selfMerged: 0, reviewed: 0, total: 0, pattern: 'unknown' };
  try {
    const prsRes = await get(`${base}/pulls?state=closed&sort=updated&direction=desc&per_page=20`);
    const prs = (prsRes.data || []).filter(p => p.merged_at);

    for (const pr of prs.slice(0, 15)) {
      prPatterns.total++;
      if (pr.user?.login === pr.merged_by?.login) {
        prPatterns.selfMerged++;
      } else {
        prPatterns.reviewed++;
      }
    }

    if (prPatterns.total >= 3) {
      const selfRate = prPatterns.selfMerged / prPatterns.total;
      if (selfRate > 0.8) {
        prPatterns.pattern = 'self-merge';
        if (Object.keys(authors).length > 2) {
          results.warnings.push('Team project but 80%+ PRs are self-merged — minimal review');
        }
      } else if (selfRate < 0.3) {
        prPatterns.pattern = 'reviewed';
      } else {
        prPatterns.pattern = 'mixed';
      }
    }
  } catch {}
  results.prPatterns = prPatterns;

  // 20. Copy-paste / template detector
  if (v) console.error('Detecting copy-paste code...');
  const copyPaste = { isTemplate: false, templateMatch: null, signals: [] };

  // Check for known Solidity templates (OpenZeppelin, etc.)
  const solFiles = files.filter(f => /\.sol$/i.test(f));
  if (solFiles.length > 0) {
    // Sample a few solidity files for import patterns
    const sampleFiles = solFiles.slice(0, 5);
    let ozImports = 0;
    let totalImports = 0;

    for (const sf of sampleFiles) {
      try {
        const content = await getRaw(`https://raw.githubusercontent.com/${owner}/${repo}/${r.default_branch}/${sf}`);
        if (content) {
          const imports = (content.match(/import\s+.*?[;"]/g) || []);
          totalImports += imports.length;
          ozImports += imports.filter(i => /openzeppelin/i.test(i)).length;

          // Check for exact copy signals
          if (/SPDX-License-Identifier/i.test(content) && content.length < 500 && imports.length > 2) {
            copyPaste.signals.push(`${sf} — very short file with many imports (likely wrapper)`);
          }
        }
      } catch {}
    }

    if (totalImports > 0 && ozImports / totalImports > 0.7) {
      copyPaste.signals.push(`${Math.round(ozImports/totalImports*100)}% of imports are OpenZeppelin — mostly boilerplate`);
      if (solFiles.length <= 5) {
        copyPaste.isTemplate = true;
        copyPaste.templateMatch = 'OpenZeppelin boilerplate';
      }
    }
  }

  // Check for cookie-cutter repo signals
  if (readmeContent) {
    // Template README patterns
    const templatePhrases = [
      /this project was bootstrapped with/i,
      /created with create-react-app/i,
      /built with hardhat/i,
      /generated by/i,
      /forked from/i,
      /starter template/i,
    ];
    for (const tp of templatePhrases) {
      if (tp.test(readmeContent)) {
        copyPaste.signals.push(`README mentions: "${readmeContent.match(tp)[0]}"`);
      }
    }
  }

  // Extremely low unique code ratio (few code files, lots of config/boilerplate)
  const codeRatio = codeFiles.length / Math.max(files.length, 1);
  if (codeRatio < 0.1 && files.length > 20) {
    copyPaste.signals.push(`Only ${Math.round(codeRatio*100)}% code files — mostly config/boilerplate`);
  }

  results.copyPaste = copyPaste;

  // 21. Funding/backer verification
  if (v) console.error('Verifying funding claims...');
  const backerVerification = { claims: [], verified: [], unverified: [] };

  // Check README for backer/investor claims
  if (readmeContent) {
    const backerPatterns = {
      'a16z': /a16z|andreessen\s*horowitz/i,
      'Paradigm': /paradigm/i,
      'Sequoia': /sequoia/i,
      'Polychain': /polychain/i,
      'Multicoin': /multicoin/i,
      'Binance Labs': /binance\s*labs/i,
      'Coinbase Ventures': /coinbase\s*ventures/i,
      'Framework Ventures': /framework\s*ventures/i,
      'Pantera': /pantera/i,
      'Jump Crypto': /jump\s*(crypto|trading)/i,
      'Dragonfly': /dragonfly/i,
      'Galaxy Digital': /galaxy\s*digital/i,
      'Electric Capital': /electric\s*capital/i,
      'Solana Foundation': /solana\s*(foundation|ventures)/i,
      'Ethereum Foundation': /ethereum\s*foundation/i,
      'Google': /backed by google|google ventures|google cloud partner/i,
      'Microsoft': /backed by microsoft|microsoft partner/i,
    };

    // Map backers to known GitHub orgs for cross-reference
    const backerOrgs = {
      'a16z': ['a16z', 'a16z-infra'],
      'Paradigm': ['paradigmxyz'],
      'Solana Foundation': ['solana-labs', 'solana-foundation'],
      'Ethereum Foundation': ['ethereum'],
      'Coinbase Ventures': ['coinbase'],
      'Binance Labs': ['binance', 'bnb-chain'],
    };

    for (const [name, pattern] of Object.entries(backerPatterns)) {
      if (pattern.test(readmeContent)) {
        backerVerification.claims.push(name);

        // Try to verify: check if any committers are in the backer's org
        let foundOrgLink = false;
        if (backerOrgs[name]) {
          for (const av of authorVerification) {
            if (!av.githubUser) continue;
            try {
              const orgsRes = await get(`https://api.github.com/users/${av.githubUser}/orgs`);
              const userOrgs = (orgsRes.data || []).map(o => o.login.toLowerCase());
              if (backerOrgs[name].some(bo => userOrgs.includes(bo.toLowerCase()))) {
                foundOrgLink = true;
                backerVerification.verified.push(`${name} — committer @${av.githubUser} is in their org`);
                break;
              }
            } catch {}
          }
        }

        if (!foundOrgLink) {
          backerVerification.unverified.push(`${name} — claimed in README but no committer linked to their org`);
        }
      }
    }
  }

  results.backerVerification = backerVerification;

  // --- SCORING ---
  const scores = {};

  // Commit health (0-20)
  let commitScore = 10;
  if (isCodeDump) { commitScore -= 5; results.flags.push('Code dump (≤3 commits, <30 days old)'); }
  if (evenlySpaced) { commitScore -= 4; results.flags.push('Suspiciously evenly-spaced commits'); }
  if (humanCommits >= 50) commitScore += 3;
  else if (humanCommits >= 20) commitScore += 2;
  else if (humanCommits >= 10) commitScore += 1;
  if (humanCommits > 0 && gpgSigned >= humanCommits * 0.9) commitScore += 5; // full signing = strong trust signal
  else if (gpgSigned > humanCommits * 0.5) commitScore += 3;
  if (commitsPerDay > 5) { commitScore -= 2; results.warnings.push('Unusually high commit frequency'); }
  scores.commits = Math.max(0, Math.min(20, commitScore));

  // Contributors (0-15)
  let contribScore = 5;
  if (contribs.length >= 5) contribScore += 4;
  else if (contribs.length >= 2) contribScore += 2;
  if (busFactor >= 2) contribScore += 3;
  if (suspiciousContribs.length > 0) { contribScore -= 4; results.flags.push(`${suspiciousContribs.length} suspicious contributor account(s)`); }
  scores.contributors = Math.max(0, Math.min(15, contribScore));

  // Code quality (0-25)
  let qualityScore = 5;
  if (hasTests) qualityScore += 4;
  if (hasCI) qualityScore += 3;
  if (hasLicense) qualityScore += 2;
  if (hasReadme) qualityScore += 2;
  if (hasGitignore) qualityScore += 1;
  if (hasPackageLock) qualityScore += 2;
  if (hasDocs) qualityScore += 2;
  if (hasContributing) qualityScore += 1;
  if (hasChangelog) qualityScore += 1;
  if (hasSecurityPolicy) qualityScore += 1;
  if (files.length < 5) { qualityScore -= 3; results.warnings.push('Very few files'); }
  scores.codeQuality = Math.max(0, Math.min(25, qualityScore));

  // AI slop (0-15, higher = better/less slop)
  let slopScore = 15;
  slopScore -= Math.min(8, aiHits.length * 2);
  if (emojiDensity > 3) { slopScore -= 3; results.warnings.push('High emoji density in README'); }
  if (readmeLength > 10000 && commits.length < 5) { slopScore -= 3; results.flags.push('Long README with few commits — possible AI-generated'); }
  scores.aiAuthenticity = Math.max(0, Math.min(15, slopScore));

  // Social health (0-10)
  let socialScore = 5;
  if (r.stargazers_count >= 100) socialScore += 2;
  if (r.forks_count >= 10) socialScore += 2;
  if (bottedStars) { socialScore -= 4; results.flags.push('Possible botted stars (high stars, no forks/contributors)'); }
  scores.social = Math.max(0, Math.min(10, socialScore));

  // Activity (0-10)
  let activityScore = 5;
  if (daysSinceLastPush < 7) activityScore += 3;
  else if (daysSinceLastPush < 30) activityScore += 2;
  else if (daysSinceLastPush < 90) activityScore += 1;
  else if (daysSinceLastPush > 365) { activityScore -= 3; results.warnings.push('No commits in over a year'); }
  if (releases.length > 0) activityScore += 2;
  scores.activity = Math.max(0, Math.min(10, activityScore));

  // Crypto risk (0-5, deductions only)
  let cryptoScore = 5;
  cryptoScore -= Math.min(5, cryptoFlags.length * 2);
  if (cryptoFlags.length > 0) results.flags.push(...cryptoFlags);
  scores.cryptoRisk = Math.max(0, cryptoScore);

  // Dependency health (bonus/penalty, folded into codeQuality)
  if (depFlags.length > 0) {
    scores.codeQuality = Math.max(0, scores.codeQuality - Math.min(5, depFlags.length * 2));
    results.flags.push(...depFlags);
  }

  // Author verification (bonus/penalty to commits score)
  const unverifiedCorpClaims = authorVerification.filter(a => a.claimedOrg && !a.verified);
  if (unverifiedCorpClaims.length > 0) {
    scores.commits = Math.max(0, scores.commits - unverifiedCorpClaims.length * 3);
    for (const a of unverifiedCorpClaims) {
      results.flags.push(`Unverified ${a.claimedOrg} identity: ${a.name} <${a.email}> — no GPG signature`);
    }
  }
  const verifiedAuthors = authorVerification.filter(a => a.verified);
  if (verifiedAuthors.length > 0) {
    scores.commits = Math.min(20, scores.commits + verifiedAuthors.length * 2);
  }

  // Security (deductions from total)
  let secDeduction = 0;
  if (secFlags.length > 0) { secDeduction = secFlags.length * 3; results.flags.push(...secFlags); }

  // README quality (0-10)
  scores.readmeQuality = readmeQuality.score;

  // Maintainability (0-10)
  scores.maintainability = maintainability.score;

  // Project health (0-10) — abandoned/stale detection + issue response + PR patterns
  let healthScore = 5;
  if (projectStatus === 'active') healthScore += 2;
  else if (projectStatus === 'stale') healthScore -= 2;
  else if (projectStatus === 'abandoned') healthScore -= 4;
  else if (projectStatus === 'archived') healthScore -= 3;
  if (projectStatus === 'neglected') healthScore -= 1;

  if (issueResponse.respondedPct !== null) {
    if (issueResponse.respondedPct >= 80) healthScore += 1;
    else if (issueResponse.respondedPct < 30) healthScore -= 1;
  }
  if (prPatterns.pattern === 'reviewed') healthScore += 1;
  else if (prPatterns.pattern === 'self-merge' && Object.keys(authors).length > 2) healthScore -= 1;

  if (velocityTrend.trend === 'accelerating') healthScore += 1;
  else if (velocityTrend.trend === 'declining') healthScore -= 1;

  scores.projectHealth = Math.max(0, Math.min(10, healthScore));

  // Originality (0-5) — copy-paste, fork quality, license
  let origScore = 3;
  if (copyPaste.isTemplate) origScore -= 2;
  if (copyPaste.signals.length > 2) origScore -= 1;
  if (forkAnalysis.isFork && forkAnalysis.quality === 'zero-change') origScore -= 2;
  if (licenseRisk.risk === 'high' && !licenseRisk.license) origScore -= 1;
  if (backerVerification.unverified.length > 0) origScore -= 1;
  if (backerVerification.verified.length > 0) origScore += 1;
  scores.originality = Math.max(0, Math.min(5, origScore));

  // Total (normalize to 100)
  const rawTotal = Object.values(scores).reduce((a, b) => a + b, 0) - secDeduction;
  const maxPossible = 135; // 20+15+25+15+10+10+5+10+10+10+5
  results.trustScore = Math.max(0, Math.min(100, Math.round(rawTotal / maxPossible * 100)));
  results.scores = scores;

  // Grade
  if (results.trustScore >= 85) results.grade = 'A';
  else if (results.trustScore >= 70) results.grade = 'B';
  else if (results.trustScore >= 55) results.grade = 'C';
  else if (results.trustScore >= 40) results.grade = 'D';
  else results.grade = 'F';

  return results;
}

// --- Output ---
function printReport(r) {
  const meta = r.meta;
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  GITHUB REPO ANALYSIS: ${meta.name}`);
  console.log(`${'═'.repeat(60)}\n`);

  // Trust score
  const bar = '█'.repeat(Math.round(r.trustScore / 5)) + '░'.repeat(20 - Math.round(r.trustScore / 5));
  console.log(`  TRUST SCORE: ${r.trustScore}/100 [${r.grade}]`);
  console.log(`  ${bar}\n`);

  // Score breakdown
  console.log(`  BREAKDOWN:`);
  const labels = {
    commits: 'Commit Health',
    contributors: 'Contributors',
    codeQuality: 'Code Quality',
    aiAuthenticity: 'AI Authenticity',
    social: 'Social Signals',
    activity: 'Activity',
    cryptoRisk: 'Crypto Safety',
    readmeQuality: 'README Quality',
    maintainability: 'Maintainability',
    projectHealth: 'Project Health',
    originality: 'Originality',
  };
  const maxes = { commits: 20, contributors: 15, codeQuality: 25, aiAuthenticity: 15, social: 10, activity: 10, cryptoRisk: 5, readmeQuality: 10, maintainability: 10, projectHealth: 10, originality: 5 };
  
  for (const [key, label] of Object.entries(labels)) {
    const score = r.scores[key];
    const max = maxes[key];
    const pct = Math.round(score / max * 100);
    const miniBar = '█'.repeat(Math.round(pct / 10)) + '░'.repeat(10 - Math.round(pct / 10));
    console.log(`    ${label.padEnd(18)} ${miniBar} ${score}/${max}`);
  }

  // Metadata
  console.log(`\n  REPO INFO:`);
  console.log(`    Language: ${meta.language || 'N/A'} | Stars: ${meta.stars} | Forks: ${meta.forks}`);
  console.log(`    Created: ${meta.createdAt?.split('T')[0]} | Last push: ${meta.pushedAt?.split('T')[0]}`);
  console.log(`    Age: ${r.activity.ageDays} days | License: ${meta.license || 'NONE'}`);
  if (meta.isForked) console.log(`    ⚠️ FORK of ${meta.parent}`);
  if (meta.topics.length > 0) console.log(`    Topics: ${meta.topics.join(', ')}`);

  // Commits
  console.log(`\n  COMMITS:`);
  console.log(`    Total: ${r.commits.total} (${r.commits.human} human, ${r.commits.bot} bot) | Per day: ${r.commits.commitsPerDay} | GPG signed: ${r.commits.gpgRate}%`);
  console.log(`    Authors: ${r.commits.authors.length}`);
  for (const a of r.commits.authors.slice(0, 5)) {
    console.log(`      ${a.name} <${a.email}> — ${a.commits} commits`);
  }

  // Contributors
  if (r.contributors.suspiciousAccounts.length > 0) {
    console.log(`\n  ⚠️ SUSPICIOUS ACCOUNTS:`);
    for (const s of r.contributors.suspiciousAccounts) {
      console.log(`    ${s.login} — account ${s.ageDays} days old, ${s.repos} repos, ${s.followers} followers`);
    }
  }

  // Code quality
  console.log(`\n  CODE QUALITY:`);
  const checks = [
    ['Tests', r.codeQuality.hasTests],
    ['CI/CD', r.codeQuality.hasCI],
    ['License', r.codeQuality.hasLicense],
    ['README', r.codeQuality.hasReadme],
    ['.gitignore', r.codeQuality.hasGitignore],
    ['Lock file', r.codeQuality.hasPackageLock],
    ['Docs', r.codeQuality.hasDocs],
    ['Changelog', r.codeQuality.hasChangelog],
  ];
  console.log(`    ${checks.map(([name, has]) => `${has ? '+' : '-'}${name}`).join('  ')}`);
  console.log(`    Files: ${r.codeQuality.totalFiles} | Top extensions: ${r.codeQuality.extensions.slice(0, 5).map(([e, c]) => `.${e}(${c})`).join(' ')}`);

  // AI slop
  if (r.codeQuality.aiSlop.hits > 0) {
    console.log(`\n  AI SLOP DETECTED (${r.codeQuality.aiSlop.hits} patterns):`);
    for (const p of r.codeQuality.aiSlop.patterns) {
      console.log(`    - ${p}`);
    }
  }

  // Dependencies
  if (r.dependencies && r.dependencies.totalDeps > 0) {
    console.log(`\n  DEPENDENCIES:`);
    console.log(`    Total: ${r.dependencies.totalDeps} (${r.dependencies.directDeps} direct, ${r.dependencies.devDeps} dev)`);
    if (r.dependencies.flags.length > 0) {
      for (const f of r.dependencies.flags) console.log(`    ⚠️ ${f}`);
    }
  }

  // Author verification
  if (r.authorVerification && r.authorVerification.some(a => a.flags.length > 0)) {
    console.log(`\n  AUTHOR VERIFICATION:`);
    for (const a of r.authorVerification) {
      if (a.flags.length === 0) continue;
      const status = a.verified ? '✓ VERIFIED' : '✗ UNVERIFIED';
      console.log(`    ${a.name} <${a.email}> — ${status}`);
      if (a.githubUser) console.log(`      GitHub: @${a.githubUser} | Repos: ${a.publicRepos} | Followers: ${a.followers}`);
      for (const f of a.flags) console.log(`      ${f}`);
    }
  }

  // Author reputation (noteworthy only)
  if (r.authorReputation && r.authorReputation.length > 0) {
    console.log(`\n  AUTHOR REPUTATION:`);
    for (const a of r.authorReputation) {
      console.log(`    @${a.user}${a.name ? ` (${a.name})` : ''}:`);
      for (const n of a.notes) console.log(`      ${n}`);
    }
  }

  // Plugin formats
  if (r.pluginFormats && r.pluginFormats.length > 0) {
    console.log(`\n  PACKAGE FORMAT:`);
    for (const p of r.pluginFormats) {
      const status = p.valid ? '✓' : '✗';
      console.log(`    ${status} ${p.type} — ${p.details}`);
    }
  }

  // Maintainability
  if (r.maintainability) {
    const m = r.maintainability;
    console.log(`\n  MAINTAINABILITY:`);
    console.log(`    Code: ${m.codeFiles} files | Config: ${m.configFiles} | Docs: ${m.docFiles} | Code/Doc ratio: ${m.codeToDocRatio}`);
    console.log(`    Depth: max ${m.maxDepth}, avg ${m.avgDepth} | Avg file: ${(m.avgFileSize/1024).toFixed(1)}KB | Large files (>50KB): ${m.largeFiles}`);
  }

  // README quality
  if (r.readmeQuality && r.readmeQuality.score > 0) {
    const rq = r.readmeQuality.checks;
    const checks = [
      ['Install guide', rq.hasInstall],
      ['Code examples', rq.hasCodeExamples],
      ['API docs', rq.hasApiDocs],
      ['Structure', rq.hasStructure],
      ['Contributing', rq.hasContributing],
      ['License', rq.hasLicenseMention],
    ];
    console.log(`\n  README QUALITY (${r.readmeQuality.score}/${r.readmeQuality.maxScore}):`);
    console.log(`    ${checks.map(([name, has]) => `${has ? '+' : '-'}${name}`).join('  ')}`);
    console.log(`    ${rq.wordCount} words, ${rq.headingCount} headings, ${rq.codeBlockCount} code blocks`);
  }

  // Project health
  if (r.projectStatus) {
    const ps = r.projectStatus;
    const statusEmoji = { active: '🟢', stale: '🟡', neglected: '🟡', abandoned: '🔴', archived: '⚪' };
    let healthLine = `${statusEmoji[ps.status] || '⚪'} ${ps.status.toUpperCase()}`;
    if (ps.daysSincePush > 0) healthLine += ` (last push ${ps.daysSincePush}d ago)`;
    const extras = [];
    if (r.velocityTrend?.trend && r.velocityTrend.trend !== 'unknown') extras.push(`velocity: ${r.velocityTrend.trend}`);
    if (r.issueResponse?.avgResponseHrs !== null) extras.push(`avg issue close: ${r.issueResponse.avgResponseHrs}h`);
    if (r.prPatterns?.pattern !== 'unknown') extras.push(`PRs: ${r.prPatterns.pattern}${r.prPatterns.total > 0 ? ` (${r.prPatterns.selfMerged}/${r.prPatterns.total} self-merged)` : ''}`);
    if (extras.length > 0) healthLine += ` | ${extras.join(' | ')}`;
    if (ps.signals.length > 0) healthLine += `\n    ⚠️ ${ps.signals.join(', ')}`;
    console.log(`\n  PROJECT HEALTH:`);
    console.log(`    ${healthLine}`);
  }

  // Fork analysis
  if (r.forkAnalysis?.isFork) {
    console.log(`\n  FORK:`);
    console.log(`    Forked from ${r.forkAnalysis.parent} (${r.forkAnalysis.parentStars || '?'}⭐)`);
    if (r.forkAnalysis.aheadBy !== undefined) {
      console.log(`    ${r.forkAnalysis.aheadBy} commits ahead, ${r.forkAnalysis.behindBy} behind — ${r.forkAnalysis.quality || 'unknown'}`);
    }
  }

  // License risk
  if (r.licenseRisk) {
    const lr = r.licenseRisk;
    const riskEmoji = { low: '🟢', medium: '🟡', high: '🔴', unknown: '⚪' };
    console.log(`\n  LICENSE: ${riskEmoji[lr.risk]} ${lr.details}`);
  }

  // Copy-paste detection
  if (r.copyPaste?.signals?.length > 0) {
    console.log(`\n  ORIGINALITY:`);
    if (r.copyPaste.isTemplate) console.log(`    🚩 Detected as ${r.copyPaste.templateMatch}`);
    for (const s of r.copyPaste.signals) console.log(`    - ${s}`);
  }

  // Backer verification
  if (r.backerVerification?.claims?.length > 0) {
    console.log(`\n  BACKER CLAIMS:`);
    for (const v of r.backerVerification.verified) console.log(`    ✓ ${v}`);
    for (const u of r.backerVerification.unverified) console.log(`    ✗ ${u}`);
  }

  // Flags
  if (r.flags.length > 0) {
    console.log(`\n  🚩 FLAGS:`);
    for (const f of r.flags) console.log(`    - ${f}`);
  }

  if (r.warnings.length > 0) {
    console.log(`\n  ⚠️ WARNINGS:`);
    for (const w of r.warnings) console.log(`    - ${w}`);
  }

  // Verdict
  console.log(`\n${'─'.repeat(60)}`);
  const verdicts = {
    'A': 'LEGIT — Well-maintained, real development activity, trustworthy.',
    'B': 'SOLID — Good signs overall, minor gaps. Probably legit.',
    'C': 'MIXED — Some concerns. Do more research before trusting.',
    'D': 'SKETCHY — Multiple red flags. Proceed with extreme caution.',
    'F': 'AVOID — Major red flags. High probability of scam/fake/abandoned.',
  };
  console.log(`  VERDICT [${r.grade}]: ${verdicts[r.grade]}`);
  console.log(`${'─'.repeat(60)}\n`);
}

// --- Badge generation ---
function generateBadge(results) {
  const score = results.trustScore;
  const grade = results.grade;
  let color = 'red';
  if (grade === 'A') color = 'brightgreen';
  else if (grade === 'B') color = 'green';
  else if (grade === 'C') color = 'yellow';
  else if (grade === 'D') color = 'orange';
  const label = `Trust_Score-${score}%2F100_${grade}`;
  return `![Trust Score](https://img.shields.io/badge/${label}-${color}?style=flat-square)`;
}

// --- Batch mode ---
async function batchAnalyze(filePath) {
  const fs = require('fs');
  const lines = fs.readFileSync(filePath, 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  
  console.log(`\nBatch analyzing ${lines.length} repos...\n`);
  const results = [];
  
  for (const line of lines) {
    const parsed = parseRepo(line);
    if (!parsed) {
      console.error(`  ✗ Cannot parse: ${line}`);
      continue;
    }
    try {
      const r = await analyzeRepo(parsed.owner, parsed.repo);
      results.push(r);
      const flagStr = r.flags.length > 0 ? ` (${r.flags.length} flags)` : '';
      console.log(`  ${r.grade} ${String(r.trustScore).padStart(3)}/100  ${r.meta.name}${flagStr}`);
    } catch (e) {
      console.error(`  ✗ ${parsed.owner}/${parsed.repo}: ${e.message}`);
    }
    // Delay to avoid rate limits
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  // Summary
  console.log(`\n${'═'.repeat(50)}`);
  console.log(`  BATCH SUMMARY: ${results.length} repos analyzed`);
  console.log(`${'═'.repeat(50)}`);
  
  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of results) grades[r.grade]++;
  console.log(`  A: ${grades.A} | B: ${grades.B} | C: ${grades.C} | D: ${grades.D} | F: ${grades.F}`);
  
  const avg = results.length > 0 ? Math.round(results.reduce((a, r) => a + r.trustScore, 0) / results.length) : 0;
  console.log(`  Average score: ${avg}/100`);
  
  // Top and bottom
  const sorted = [...results].sort((a, b) => b.trustScore - a.trustScore);
  if (sorted.length >= 3) {
    console.log(`\n  TOP 3:`);
    for (const r of sorted.slice(0, 3)) console.log(`    ${r.trustScore}/100 [${r.grade}] ${r.meta.name}`);
    console.log(`\n  BOTTOM 3:`);
    for (const r of sorted.slice(-3).reverse()) console.log(`    ${r.trustScore}/100 [${r.grade}] ${r.meta.name}`);
  }
  console.log();
  
  return results;
}

// --- Main ---
async function main() {
  // Batch mode
  if (args.file) {
    const results = await batchAnalyze(args.file);
    if (args.json) console.log(JSON.stringify(results, null, 2));
    return;
  }

  const input = positionals[0];
  if (!input) {
    console.error('Usage: node analyze.js <github-url-or-owner/repo> [--json] [--verbose] [--oneline] [--badge]');
    console.error('       node analyze.js --file repos.txt [--json]');
    console.error('  Optional: --token <github-token> or GITHUB_TOKEN env var for higher rate limits');
    process.exit(1);
  }

  const parsed = parseRepo(input);
  if (!parsed) {
    console.error(`Cannot parse repo from: ${input}`);
    process.exit(1);
  }

  try {
    const results = await analyzeRepo(parsed.owner, parsed.repo);
    if (args.badge) {
      console.log(generateBadge(results));
    } else if (args.oneline) {
      const flagCount = results.flags.length;
      const flagStr = flagCount > 0 ? ` — ${flagCount} flag${flagCount > 1 ? 's' : ''}` : '';
      console.log(`${results.meta.name}: ${results.trustScore}/100 [${results.grade}]${flagStr}`);
    } else if (args.json) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      printReport(results);
    }
  } catch (e) {
    console.error('Error:', e.message);
    if (e.message.includes('rate limit')) {
      console.error('Tip: Set GITHUB_TOKEN env var or use --token for higher rate limits');
    }
    process.exit(1);
  }
}

main();
