# Data Sovereignty Analysis

Qualitative comparison of what leaves the organization's network under each approach, per
alert classified. No experiment required — this follows directly from how each system is
architected.

## Our classifier

Runs entirely on the same VM as the Wazuh manager. The trained model (`.joblib` file) is
loaded once into local memory; every classification happens in-process. **Zero bytes of
alert data ever leave the host.** No third party, however trusted, ever sees a single log
line, IP address, username, or attack payload from this system.

## LLM-based triage (the baseline we compared against)

Every alert must be sent to a third-party API to be classified. For a single alert, that
means transmitting externally:

| Field sent | Example from our dataset |
|---|---|
| Real attacker IP addresses | `35.238.91.197` |
| Internal hostnames | `soc-target` |
| Usernames (including service/decoy accounts) | `svc_backup`, `testuser` |
| Full raw attack payloads | SQL injection strings, command injection syntax, XSS payloads |
| Rule descriptions revealing what detection logic exists | `"Possible OS command injection attempt in web request"` |

At realistic SOC volumes (10,000+ alerts/day, per the cost analysis in `08`), this is not an
occasional exposure — it is a **continuous, full-volume export of the organization's entire
live security telemetry** to an external vendor's infrastructure, for as long as the system
operates.

## Why this matters beyond "it would be nice to avoid"

- **Regulatory**: Many regulated environments (finance under PCI-DSS, healthcare under
  HIPAA, government/defense contractors under FedRAMP or similar) have explicit contractual
  or legal restrictions on sending security telemetry to third-party processors, particularly
  US/foreign-jurisdiction cloud APIs, regardless of that vendor's own security posture.
- **Threat-model irony**: the data being exported is, by definition, evidence of an active
  or attempted compromise. Sending details of an ongoing intrusion to an external party
  introduces a second party who now has knowledge of the organization's security state and
  vulnerabilities, outside the organization's own control.
- **Vendor dependency**: the third-party API's own logging, retention, and breach-notification
  policies become part of the organization's effective security posture, whether or not that
  tradeoff was deliberately accepted.

## Honest counterpoint

This is not an argument that no LLM-based security tooling should ever call an external API
— many organizations accept this tradeoff knowingly, and some providers offer on-premises
or VPC-isolated deployment options for exactly this reason (at additional cost/complexity).
The point for this paper is narrower and verifiable: **our architecture has this property by
construction, with no configuration required and no residual risk to evaluate**, which is a
meaningfully different guarantee than "the vendor says they don't retain your data."
