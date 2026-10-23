# Detection Validation — Red Team Test (post-dataset)

After building the v4 dataset, a separate validation round was run to answer a specific question: **does detection hold up against attacks that look different from what generated the training/eval data?** This used different tools and deliberate evasion techniques, against a fresh, previously-unseen decoy account and payload variants.

## Test design

Everything here uses **different tools or techniques than any prior round** — the point was to simulate a real, independent attacker, not replay our own scripts.

| # | Test | Tool/technique (deliberately different from dataset generation) |
|---|---|---|
| R1 | SSH brute force → success | `ncrack` (vs. `hydra` used for the dataset), against a brand-new unseen decoy account (`svc_audit`) |
| R2 | Directory recon | `ffuf` (vs. `gobuster`), different wordlist (`dirb`'s `big.txt` instead of `common.txt`) |
| R3 | Reflected XSS, evasion attempt | SVG-based payload (`<svg/onload=...>`) deliberately avoiding `<script`, `onerror=`, and the literal string `alert(` — the exact substrings our custom rule checked for |
| R4 | Command injection, evasion attempt | `$()` command substitution and `&&` instead of `;`, `` ` ``, or `\|` — the exact operators our custom rule checked for |
| R5 | SSTI/RCE, evasion attempt | Split-string dunder technique (`'__built' + 'ins__'`) to avoid the literal keyword substrings our custom rule checked for |
| R6 | JWT-style forged header | Sent via `Authorization` header (known, documented blind spot — access logs don't capture headers) |

## Results

| Test | Outcome | Why |
|---|---|---|
| R1 (ncrack brute force) | ✅ **Caught** — native rule `40112` ("Multiple authentication failures followed by a success") | Detection is behavior-based (auth log pattern), not tool-fingerprint-based — genuinely generalizes to any SSH client |
| R2 (ffuf recon) | ✅ **Caught** — native rules `31101`/`31151` | Same reason — based on response-code frequency from one source, not which scanner sent it |
| R3 (XSS SVG evasion) | ❌ **Missed entirely**, initially | Our custom rule's pattern list was too narrow — no `<script`/`onerror=`/`alert(` present in the payload |
| R4 (command injection evasion) | ❌ **Missed entirely**, initially | Same problem — rule only checked `;`, `` ` ``, `\|`, not `$()` or `&&` |
| R5 (SSTI dunder-split evasion) | ✅ **Still caught** | The dunder-keyword check was bypassed as intended, but the rule *also* checks for the `{{` opening syntax, which the payload still needed to contain — accidental but genuine defense-in-depth within one rule |
| R6 (JWT header) | Not independently re-verified this round; consistent with the documented architectural blind spot from v3 (headers aren't in access logs at all) | Not a detection-quality issue — a monitoring-architecture limitation |

## What this proves, concretely

- **The parts of the system that matter most for "will this catch a real attacker" — Wazuh's native, mature rule engine — held up well against tools it had never seen before.** This is the strongest evidence yet that detection isn't just memorizing our own training scripts.
- **The three narrow custom rules we wrote (command injection, XSS, SSTI) were, as flagged earlier, genuinely weak against straightforward evasion.** This wasn't a hypothetical concern — R3 and R4 were real, working bypasses (the injected commands actually executed; we confirmed via response content).

## Remediation (applied immediately after the test)

Both failing rules were hardened with a broader pattern set covering the specific evasion techniques that succeeded (additional event handlers, `javascript:`, bracket-notation JS execution for XSS; `$()`, `&&`, `||`, newline/CR injection, and bare keyword matches for command injection — see `scripts/harden_rules.py` and `scripts/harden_rules2.py`/`harden_rules3.py` for the exact diffs). **The identical R3 and R4 payloads were re-sent after hardening and are now correctly caught** (confirmed via direct alert log inspection).

## Honest caveat

This is one round of adversarial testing against three specific rules, not a formal security audit. The hardened rules are broader, but still fundamentally pattern-matching — a sufficiently determined attacker with enough iteration could very plausibly find a third bypass (different encoding, different JS execution primitive, etc.). Rule-based detection is an arms race by nature; this round demonstrates the *process* of finding and closing a real gap, not a claim that the rules are now unbeatable.
