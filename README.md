# push-sentinel-action

**GitHub Action that catches leaked secrets in pull requests and pushes.**

Scans your diff for API keys, tokens, and private keys. Posts findings as check annotations and PR comments.

## Usage

```yaml
name: Secret Scan
on: [pull_request, push]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Pmaind/push-sentinel-action@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## What it detects

| Pattern | Severity |
|---------|----------|
| Private Key (RSA, EC, DSA, PKCS#8) | 🔴 HIGH |
| AWS Access Key / Secret Key | 🔴 HIGH |
| GitHub Token (`ghp_`, `github_pat_`) | 🔴 HIGH |
| Anthropic API Key (`sk-ant-...`) | 🟡 MEDIUM |
| OpenAI API Key (`sk-...`) | 🟡 MEDIUM |
| Generic API Key (high entropy) | 🟢 LOW |
| `.env` file committed | 🟡 MEDIUM |

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `block-on-high` | `true` | Fail the check when HIGH severity secrets are found |
| `comment-on-pr` | `true` | Post a comment on the PR with findings |

## How it works

- **Pull requests**: scans the diff between the base branch and HEAD
- **Pushes**: scans all commits in the push
- Findings appear as **check annotations** on the exact file and line
- HIGH severity findings **fail the check** by default, preventing merge

## PR comment example

> ## 🔒 push-sentinel: Potential secrets detected
>
> | Severity | Location | Pattern | Risk |
> |----------|----------|---------|------|
> | 🔴 HIGH | `src/config.ts:12` | AWS Access Key | Full access to AWS resources. |

## Related

- [push-sentinel](https://www.npmjs.com/package/push-sentinel) — local pre-push hook (npm)
