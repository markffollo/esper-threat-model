# Threat Model: {project_name}

**Date:** {date}
**Analyzed by:** Hermes Agent Threat Modeling Skill
**Model:** {model_name}

## Architecture Summary

{brief description of the application architecture — 2-3 sentences}

**Languages:** {languages}
**Agentic:** {yes/no}
**Components:** {count}
**Trust Boundaries:** {count}

## Data Flow Diagram

See: {dfd_file_path}

## Findings

| ID | Category | Title | Severity | File:Line | DREAD |
|----|----------|-------|----------|-----------|-------|
| ... | ... | ... | ... | ... | ... |

### {severity_emoji} {finding_id}: {title}

**STRIDE Category:** {category}
**Severity:** {tier} (DREAD: {score})
**Location:** {file}:{line}

**Description:**
{what the vulnerability is}

**Attack Scenario:**
{how an attacker would exploit this}

**Evidence:**
```
{code snippet showing the issue}
```

**DREAD Breakdown:**
| Dimension | Score | Rationale |
|-----------|-------|----------|
| Damage | {n} | {why} |
| Reproducibility | {n} | {why} |
| Exploitability | {n} | {why} |
| Affected Users | {n} | {why} |
| Discoverability | {n} | {why} |

**Remediation:**
{specific fix with code}

**Attack Path:**
{if Critical/High: multi-step path through the DFD}

## Summary

| Severity | Count |
|----------|-------|
| Critical | {n} |
| High | {n} |
| Medium | {n} |
| Low | {n} |
| **Total** | {n} |
