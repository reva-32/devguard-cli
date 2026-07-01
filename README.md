# DevGuard 🛡️

> Stop credentials from reaching GitHub. Catch them on your machine first.

DevGuard is a CLI tool that scans your code for leaked API keys, passwords, and tokens — and blocks the `git push` if it finds any.

---

## How DevGuard compares

| Feature | gitleaks | detect-secrets | **DevGuard** |
|---|:---:|:---:|:---:|
| Regex-based detection | ✅ | ✅ | ✅ |
| Shannon entropy analysis | ✅ | ✅ | ✅ |
| Detects secrets in dicts, f-strings, comments | ⚠️ partial | ⚠️ partial | ✅ |
| Detects secrets in `.env` format | ✅ | ✅ | ✅ |
| False positive filter (commit SHAs, placeholders) | ⚠️ partial | ⚠️ partial | ✅ |
| Pre-push git hook | ✅ | ❌ | ✅ |
| **Pre-commit scan** (warns before you even commit) | ❌ | ❌ | ✅ |
| Line-preserving ignore list | ❌ | ❌ | ✅ |
| Two-tier audit trail (private log + committed report) | ❌ | ❌ | ✅ |
| Enterprise-overridable entropy threshold via config | ❌ | ❌ | ✅ |
| Custom org-specific regex patterns via config | ✅ | ✅ | ✅ |

### What those last three mean in practice

**Pre-commit scanning** — most tools only block at `git push`, which means you write code, stage it, commit it, *then* get told it's bad. DevGuard warns you during `devguard scan` before you commit anything, so you fix it at the source, not after the fact.

**Line-preserving ignore list** — when you mark a string as safe, most tools regenerate the entire config file and silently destroy every comment and custom indent a senior wrote into it. DevGuard rewrites only the one relevant line, leaving everything else byte-identical.

**Two-tier audit trail** — a private `audit.log` (never committed) stores full details per device. A sanitized `audit.report` gets committed to the repo so team leads can see who almost leaked what, without the secret value ever touching version control.

---

## Install

```bash
pip install devguard-cli
```

---

## Quickstart

```bash
# 1. Set up DevGuard inside your repo (one time)
devguard init

# 2. Scan manually anytime
devguard scan --path .

# 3. Filter by severity
devguard scan --path . --min-severity HIGH

# 4. View audit history
devguard report

# 5. Mark a false positive as safe (by its hash)
devguard ignore 9b55a56a4e3208b8

# 6. Check hook + config status
devguard status
```

After `devguard init`, every `git push` is automatically scanned. If a secret is found, the push is blocked entirely. Clean code goes through untouched.

---

## What gets detected

| Format | Method |
|---|---|
| AWS Access Key ID / Secret | Regex + entropy + context |
| Google API Key | Regex |
| JSON Web Token (JWT) | Regex |
| RSA / Private Key blocks | Regex |
| Slack Webhook URLs | Regex |
| Stripe Secret Keys | Regex |
| Custom org tokens | Regex via `.devguard.yml` |
| Unknown high-randomness strings | Shannon entropy analysis |

---

## Configuration

Running `devguard init` creates `.devguard.yml` in your repo root. Commit this — it's safe, it contains no secrets.

Every field is optional. DevGuard ships with sensible defaults; your config only needs to list what you want to override.

```yaml
# Override the default entropy threshold (default: 3.8)
# Lower = more sensitive, catches more strings but may increase false positives
# Enterprise teams with stricter standards can set this as low as 3.0
entropy_threshold: 3.5

# Add org-specific secret formats that no public tool would know about
custom_patterns:
  - name: "Internal API token"
    regex: "MYCOMPANY_[A-Z0-9]{32}"
  - name: "Legacy auth header"
    regex: "Bearer legacy_[a-z0-9]{24}"

# Files that should never be pushed, regardless of content
blacklisted_files:
  - "*.env"
  - "secrets.json"
  - "**/credentials/*.yml"

# Safe strings, stored as hashes — never paste the actual value here
allowlist:
  - "9b55a56a4e3208b8"  # confirmed safe: internal build token
```

The allowlist stores hashes of ignored strings, not the strings themselves. Safe to commit publicly, safe to code review.

---

## Audit trail

Every scan appends to two files:

```
.gitguard/
├── audit.log     # full detail, in .gitignore, never leaves your machine
└── audit.report  # sanitized, committed to repo, safe for team review
```

`audit.report` shows who, when, which file, which pattern — with no secret values or line numbers included.

---

## How the detection works

**Layer 1 — Regex:** Matches known secret formats by their structural shape, anywhere on a line, regardless of surrounding syntax. A key inside a dict, a comment, or an f-string is caught the same as a clean assignment.

**Layer 2 — Shannon Entropy:** Measures how random a string actually is. Real secrets (machine-generated) score high. Placeholders, UUIDs, and commit hashes score low and are ignored. Combined with proximity checking (does the word `aws`, `secret`, or `key` appear nearby?) to eliminate false positives.

---

## Development

```bash
git clone https://github.com/reva-32/test_cybersecurity
cd devguard-cli
pip install -e .
pytest tests/ -v
```

---

## License

MIT — free to use, modify, and distribute, including in commercial projects. Just keep the copyright notice.
