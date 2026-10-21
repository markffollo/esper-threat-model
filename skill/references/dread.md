# DREAD Risk Scoring Rubric

Score each dimension 0–10. Total = average of 5 dimensions.

## Dimensions

### Damage Potential (0–10)
How severe is the impact if exploited?
- **0–2:** Minimal — no sensitive data, minor inconvenience
- **3–4:** Limited — isolated data exposure, no lasting impact
- **5–6:** Significant — partial data breach, service disruption for some users
- **7–8:** Serious — full data breach, privilege escalation, sustained downtime
- **9–10:** Catastrophic — complete system compromise, mass data exfiltration, RCE

### Reproducibility (0–10)
How easy is it to reproduce the attack?
- **0–2:** Requires rare conditions (specific timing, insider access, physical access)
- **3–4:** Reproducible with significant effort and specific preconditions
- **5–6:** Reproducible with moderate effort and common tools
- **7–8:** Easily reproducible with standard tools and knowledge
- **9–10:** One-click or fully automated, no preconditions

### Exploitability (0–10)
How much skill and tooling does an attacker need?
- **0–2:** Nation-state capability required, custom tooling, deep expertise
- **3–4:** Skilled researcher with custom exploit development
- **5–6:** Knowledgeable attacker with public tooling
- **7–8:** Script-kiddie level, public PoC available
- **9–10:** No skill needed, automated scanners find and exploit it

### Affected Users (0–10)
How many users are impacted?
- **0–2:** Single user, isolated environment
- **3–4:** Small team or department
- **5–6:** Subset of users (one feature, one region)
- **7–8:** All users of a service
- **9–10:** All users across multiple services, public impact

### Discoverability (0–10)
How easy is it for an attacker to find this vulnerability?
- **0–2:** Internal-only, requires source code access, buried in obscure logic
- **3–4:** Requires authenticated enumeration or specific knowledge
- **5–6:** Findable with common scanning tools by authenticated users
- **7–8:** Public endpoint, findable with automated scanners
- **9–10:** Publicly indexed, obvious, scanners report it automatically

## Severity Tiers

| Score | Tier | Action |
|-------|------|--------|
| >= 8.0 | Critical | Fix immediately, block deploy |
| 6.0–7.9 | High | Fix before next release |
| 4.0–5.9 | Medium | Fix in current sprint |
| < 4.0 | Low | Track, fix when convenient |

## Calculation

```python
dread_score = (damage + reproducibility + exploitability + affected_users + discoverability) / 5
```
