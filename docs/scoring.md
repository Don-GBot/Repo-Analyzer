# Scoring Methodology

## Overview

The trust score is a weighted composite of 7 categories, totaling 100 points maximum.

## Categories

### Commit Health (0-20 points)
- Base: 10
- +3/2/1 for 50+/20+/10+ human commits
- +5 for 90%+ GPG signing, +3 for 50%+ GPG signing
- -5 for code dump (≤3 commits, <30 days old)
- -4 for evenly-spaced commits (possible fake history)
- -2 for unusually high commit frequency

### Contributors (0-15 points)
- Base: 5
- +4 for 5+ contributors, +2 for 2+
- +3 for bus factor ≥ 2
- -4 for suspicious accounts (fresh, low repo count)

### Code Quality (0-25 points)
- Base: 5
- +4 tests, +3 CI/CD, +2 license, +2 README, +1 .gitignore
- +2 lock file, +2 docs, +1 contributing, +1 changelog, +1 security policy
- -3 for very few files (<5)

### AI Authenticity (0-15 points)
- Base: 15
- -2 per AI slop pattern detected (max -8)
- -3 for high emoji density
- -3 for long README + few commits

### Social Signals (0-10 points)
- Base: 5
- +2 for 100+ stars, +2 for 10+ forks
- -4 for suspected botted stars

### Activity (0-10 points)
- Base: 5
- +3/2/1 for push within 7/30/90 days
- -3 for no commits in a year
- +2 for releases

### Crypto Safety (0-5 points)
- Base: 5
- -2 per crypto red flag (launchpad mints, placeholder IDs, hardcoded wallets)

## Grades
- A: 85-100
- B: 70-84
- C: 55-69
- D: 40-54
- F: 0-39
