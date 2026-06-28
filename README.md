# 🛡️ GitGuard Enterprise Security Client

GitGuard is a light, context-aware DevSecOps source code analyzer built to catch hardcoded credentials, active api keys, and high-entropy secrets before they escape your local system runtime environment.

By combining deterministic regex signature maps with automated Shannon Entropy randomness assessments, GitGuard protects local code repositories from leaking critical infrastructure components.

---

## ⚙️ Key Architectural Features

* **Dynamic Multi-Tiered Ignoring:** Performs a dual-pass tree walk of the active workspace, parsing and obeying individual `.gitignore` configurations natively across monorepos.
* **Hybrid Detection Engine:** Uses enterprise signature mapping (AWS, JWT, Slack, GitHub Tokens) paired with a Shannon Entropy algorithm ($H(X) = -\sum P(x_i) \log_2 P(x_i)$) to isolate raw cryptographic token distributions.
* **Active Interception Injection:** Automatically injects a native shell hook directly into `.git/hooks/pre-push` to actively analyze and block vulnerability leaks before push operations complete.
* **Dual-Tier Visibility Isolation:** Splits telemetry into clean outputs:
  * `gitguard-audit.log`: Diagnostic deep-dives containing exact line details, which the tool automatically locks down via your `.gitignore`.
  * `gitguard-audit.json`: High-level compliance metadata records safe for tracking repository lineage.

---

## 🚀 Installation & Local Workspace Setup

Initialize active system configurations inside your target Git repository:
```bash
gitguard init
