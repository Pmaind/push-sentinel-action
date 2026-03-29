const core = require('@actions/core');
const github = require('@actions/github');
const { execSync, spawnSync } = require('child_process');

// --- Patterns (same as push-sentinel npm package) ---

const PATTERNS = [
  {
    name: 'Private Key',
    severity: 'HIGH',
    regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |ECDSA )?PRIVATE KEY-----/,
    risk: 'Full server/certificate takeover.',
  },
  {
    name: 'AWS Access Key',
    severity: 'HIGH',
    regex: /AKIA[0-9A-Z]{16}/,
    risk: 'Full access to AWS resources.',
  },
  {
    name: 'GitHub Token',
    severity: 'HIGH',
    regex: /ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{36,}/,
    risk: 'Full read/write access to GitHub repositories.',
  },
  {
    name: 'Anthropic API Key',
    severity: 'MEDIUM',
    regex: /sk-ant-[a-zA-Z0-9\-]{32,}/,
    risk: 'Unauthorized API usage billed to your account.',
  },
  {
    name: 'OpenAI API Key',
    severity: 'MEDIUM',
    regex: /sk-[a-zA-Z0-9\-]{32,}/,
    risk: 'Unauthorized API usage billed to your account.',
  },
  {
    name: 'Generic API Key',
    severity: 'LOW',
    regex: /[Aa][Pp][Ii]_?[Kk][Ee][Yy]\s*=\s*["']?([^\s"']{16,})/,
    risk: 'May allow unauthorized access depending on the service.',
    captureGroup: 1,
  },
];

const VAR_NAME_KEYWORDS = /API|SECRET|TOKEN|KEY|PASSWORD/i;

// --- Entropy ---

function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    h -= p * Math.log2(p);
  }
  return h;
}

function isHighEntropy(candidate) {
  if (candidate.length < 16) return false;
  if (/^(.)\1+$/.test(candidate)) return false;
  return shannonEntropy(candidate) >= 3.5;
}

function isDummyValue(line) {
  return /\b(test_|fake_|example_|dummy_|placeholder)/i.test(line);
}

// --- Diff parsing ---

function getDiff() {
  const eventName = process.env.GITHUB_EVENT_NAME;
  const baseSha = process.env.GITHUB_BASE_REF
    ? spawnSync('git', ['rev-parse', `origin/${process.env.GITHUB_BASE_REF}`], { encoding: 'utf8', stdio: 'pipe' }).stdout.trim()
    : null;

  if (eventName === 'pull_request' && baseSha) {
    const result = spawnSync('git', ['diff', baseSha, 'HEAD'], { encoding: 'utf8', stdio: 'pipe' });
    if (result.status === 0) return result.stdout || '';
  }

  // push event: diff against parent
  const result = spawnSync('git', ['log', '-1', '-p', 'HEAD'], { encoding: 'utf8', stdio: 'pipe' });
  return result.status === 0 ? (result.stdout || '') : '';
}

function getChangedFiles() {
  const eventName = process.env.GITHUB_EVENT_NAME;
  const baseSha = process.env.GITHUB_BASE_REF
    ? spawnSync('git', ['rev-parse', `origin/${process.env.GITHUB_BASE_REF}`], { encoding: 'utf8', stdio: 'pipe' }).stdout.trim()
    : null;

  if (eventName === 'pull_request' && baseSha) {
    const result = spawnSync('git', ['diff', '--name-only', baseSha, 'HEAD'], { encoding: 'utf8', stdio: 'pipe' });
    if (result.status === 0) return result.stdout.split('\n').map(f => f.trim()).filter(Boolean);
  }

  const result = spawnSync('git', ['diff', '--name-only', 'HEAD~1', 'HEAD'], { encoding: 'utf8', stdio: 'pipe' });
  return result.status === 0 ? result.stdout.split('\n').map(f => f.trim()).filter(Boolean) : [];
}

function parseDiffAddedLines(diff) {
  const results = [];
  let currentFile = null;
  let lineNum = 0;

  for (const line of diff.split('\n')) {
    const fileMatch = line.match(/^\+\+\+ b\/(.+)$/);
    if (fileMatch) { currentFile = fileMatch[1]; lineNum = 0; continue; }
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) { lineNum = parseInt(hunkMatch[1], 10) - 1; continue; }
    if (!currentFile) continue;
    if (line.startsWith('+') && !line.startsWith('+++')) {
      lineNum++;
      results.push({ file: currentFile, lineNum, content: line.slice(1) });
    } else if (!line.startsWith('-')) {
      lineNum++;
    }
  }
  return results;
}

// --- Scan ---

function scan() {
  const findings = [];
  const path = require('path');

  // .env file check
  const changedFiles = getChangedFiles();
  for (const f of changedFiles) {
    if (f === '.env' || f.endsWith('/.env') || /^\.env(\.|$)/.test(path.basename(f))) {
      findings.push({
        file: f, lineNum: null, matchedValue: null,
        severity: 'MEDIUM', patternName: '.env file',
        risk: 'Committing a .env file may expose multiple secrets at once.',
      });
    }
  }

  const diff = getDiff();
  if (!diff) return findings;

  const addedLines = parseDiffAddedLines(diff);

  for (const { file, lineNum, content } of addedLines) {
    if (isDummyValue(content)) continue;

    let matched = false;
    for (const pattern of PATTERNS) {
      const skipVarFilter = ['Private Key', 'AWS Access Key', 'GitHub Token', 'OpenAI API Key', 'Anthropic API Key'];
      if (!skipVarFilter.includes(pattern.name) && !VAR_NAME_KEYWORDS.test(content)) continue;

      const match = content.match(pattern.regex);
      if (!match) continue;

      const candidate = pattern.captureGroup ? match[pattern.captureGroup] : match[0];
      if (pattern.name === 'Generic API Key' && !isHighEntropy(candidate)) continue;

      findings.push({
        file, lineNum, matchedValue: candidate,
        severity: pattern.severity, patternName: pattern.name, risk: pattern.risk,
      });
      matched = true;
      break;
    }

    if (matched) continue;

    // AWS Secret Key
    if (VAR_NAME_KEYWORDS.test(content) && /AWS.*SECRET|SECRET.*AWS/i.test(content)) {
      const valueMatch = content.match(/[a-zA-Z0-9/+=]{40}/);
      if (valueMatch && isHighEntropy(valueMatch[0])) {
        findings.push({
          file, lineNum, matchedValue: valueMatch[0],
          severity: 'HIGH', patternName: 'AWS Secret Key',
          risk: 'Full access to AWS resources.',
        });
      }
    }
  }

  return findings;
}

// --- Masking ---

function maskValue(value) {
  if (!value) return '(staged file)';
  const show = Math.min(6, value.length);
  return value.slice(0, show) + 'x'.repeat(Math.max(0, value.length - show)) + '...';
}

// --- Main ---

async function run() {
  try {
    const blockOnHigh = core.getInput('block-on-high') === 'true';
    const commentOnPr = core.getInput('comment-on-pr') === 'true';

    const findings = scan();

    if (findings.length === 0) {
      core.info('No secrets detected.');
      return;
    }

    // Annotations
    for (const f of findings) {
      const msg = `[${f.severity}] ${f.patternName}: ${maskValue(f.matchedValue)} — ${f.risk}`;
      if (f.severity === 'HIGH') {
        core.error(msg, { file: f.file, startLine: f.lineNum || undefined });
      } else {
        core.warning(msg, { file: f.file, startLine: f.lineNum || undefined });
      }
    }

    // PR comment
    if (commentOnPr && github.context.eventName === 'pull_request') {
      const token = process.env.GITHUB_TOKEN;
      if (token) {
        const octokit = github.getOctokit(token);
        const { owner, repo } = github.context.repo;
        const prNumber = github.context.payload.pull_request.number;

        const rows = findings.map(f => {
          const severity = f.severity === 'HIGH' ? '🔴' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
          const location = f.lineNum ? `\`${f.file}:${f.lineNum}\`` : `\`${f.file}\``;
          return `| ${severity} ${f.severity} | ${location} | ${f.patternName} | ${f.risk} |`;
        });

        const body = `## 🔒 push-sentinel: Potential secrets detected

| Severity | Location | Pattern | Risk |
|----------|----------|---------|------|
${rows.join('\n')}

> Remove the secret or add to \`.push-sentinel-ignore\` to suppress.`;

        await octokit.rest.issues.createComment({ owner, repo, issue_number: prNumber, body });
      }
    }

    // Summary
    core.summary
      .addHeading('push-sentinel', 2)
      .addRaw(`Found ${findings.length} potential secret(s).`)
      .write();

    const hasHigh = findings.some(f => f.severity === 'HIGH');
    if (blockOnHigh && hasHigh) {
      core.setFailed(`push-sentinel: ${findings.filter(f => f.severity === 'HIGH').length} HIGH severity secret(s) detected.`);
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
