---
name: threat-modeling
description: "STRIDE threat modeling for vibe-coded applications."
version: 0.1.0
author: Mark Follo (markffollo), Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [threat-modeling, security, stride, dread, data-flow-diagram, vibe-coding]
    related_skills: [architecture-diagram, bug-bounty-hunter]
---

# Threat Modeling

STRIDE threat modeling for vibe-coded applications. Scan a codebase to
discover its architecture (components, data flows, trust boundaries),
render a visual Data Flow Diagram, assess every boundary against STRIDE,
rank findings by DREAD severity, and output actionable remediation with
file-level evidence. Designed for apps built quickly with AI assistance
where security was not a primary consideration.

**Differentiation from existing tools (appsec-advisor, SecureVibes,
STRIDE-GPT):** runs on non-refusing models (GLM/DeepSeek via OpenRouter) —
STRIDE requires describing real attack paths, which Claude-based tools
water down or refuse. Conversational, not one-shot — the user confirms
the diagram before threat analysis, then drills into findings
interactively. Includes a vibe-code-specific failure pattern library
(hardcoded secrets, missing auth on AI endpoints, unvalidated LLM output
in SQL/shell, exposed debug routes, CORS wide open) that generic tools
don't target. Traces multi-step attack paths through the DFD, not just
isolated findings.

**Dependency:** the `architecture-diagram` skill for DFD rendering. No
external tools, APIs, or model calls required for the diagram itself.

## When to Use

- User asks to threat-model an application or codebase
- User has a vibe-coded app (AI-generated code) and wants to secure it
- User wants a security architecture review with STRIDE
- User wants a Data Flow Diagram of their application
- User asks "what are the security risks in this codebase?"

**Don't use for:** live production penetration testing (use
`bug-bounty-hunter`); compliance audit frameworks (SOC2, ISO 27001);
static analysis / SAST tool replacement (Semgrep, CodeQL).

## Prerequisites

- A codebase to analyze (local directory path)
- The `architecture-diagram` skill installed (ships with Hermes)
- No API keys, no external services — all analysis is local + the
  current session's model

## How to Run

All steps via Hermes tools (`search_files`, `read_file`, `terminal`,
`write_file`, `skill_view`). The skill runs in four phases with a
user gate between phases 1 and 2.

```
# Phase 1: Scan codebase and generate DFD
python3 scripts/scan_codebase.py /path/to/project    # outputs components.json
# → generate DFD HTML using architecture-diagram skill
# → GATE: present diagram to user for confirmation

# Phase 2: STRIDE assessment (after user confirms diagram)
# → for each component + trust boundary, apply STRIDE categories
# → if agentic app detected, add AI-specific threats (ASTRIDE)

# Phase 3: DREAD scoring
# → score each finding 0-10 on 5 dimensions, rank by severity

# Phase 4: Recommendations
# → concrete remediation with file:line references
# → output threat-model.md + threat-model.yaml
```

## Procedure

### Phase 1: Architecture Discovery → DFD

1. **Run the codebase scanner.** Execute `scripts/scan_codebase.py`
   against the target directory via `terminal`. The scanner walks the
   codebase and identifies:
   - Entry points (API routes, web handlers, server configs)
   - Data stores (databases, file storage, caches, queues)
   - External services (third-party APIs, LLM/AI providers, cloud services)
   - Auth mechanisms (JWT, OAuth, sessions, API keys)
   - Secrets and config (env files, hardcoded credentials)
   - AI/agentic patterns (LLM API calls, agent frameworks, tool execution)
   
   Output: structured JSON (`components`, `data_flows`,
   `trust_boundaries`, `is_agentic`, `languages`).
   
   Completion: scanner exits 0, JSON written to workspace.

2. **Enrich the model.** Read the scanner output. For each component,
   read the actual source files to fill in details the scanner can't
   infer automatically:
   - What data crosses each trust boundary (PII, credentials, tokens,
     user-generated content, LLM prompts/responses)
   - What protocols are used (HTTP, HTTPS, WebSocket, gRPC, raw TCP)
   - Whether auth is actually enforced (not just imported)
   - Whether the app is agentic (LLM calls, tool execution, agent loops)
   
   Use `read_file` and `search_files` to verify. Don't guess — if a
   detail isn't findable in the code, mark it as "unknown — ask user."
   
   Completion: enriched JSON with data types per flow, protocol per
   flow, auth enforcement status, agentic flag.

3. **Generate the DFD.** Load the `architecture-diagram` skill
   (`skill_view(name='architecture-diagram')` and its template at
   `templates/template.html`). Generate an HTML file with:
   - Each component as a colored box (frontend, backend, database,
     cloud, security, external, AI/LLM)
   - Each data flow as an arrow labeled with data type + protocol
   - Trust boundaries as dashed regions around component groups
   - A legend explaining colors and boundary types
   
   Save to `<project-name>-dfd.html` in the workspace.
   Deliver to user via `MEDIA:/path/to/file`.
   
   Completion: HTML file written, delivered inline.

4. **GATE — user confirms the diagram.** Present the DFD and ask:
   "Does this match your architecture? Anything missing, wrong, or
   that should be de-prioritized?" Wait for user response before
   proceeding to Phase 2. If the user corrects the model, update the
   enriched JSON and regenerate the diagram.
   
   Completion: user confirms or corrects the diagram.

### Phase 2: STRIDE Assessment

5. **Apply STRIDE per boundary.** For each component and each data
   flow crossing a trust boundary, evaluate against the six STRIDE
   categories. Load `references/stride.md` for the full category
   definitions and question prompts.
   
   For each potential threat:
   - Identify the STRIDE category (S/T/R/I/D/E)
   - Cite the specific file and line where the risk exists
   - Describe the attack scenario (how would an attacker exploit this?)
   - Note whether existing controls mitigate it (and how strong)
   
   Completion: every component × boundary × STRIDE category evaluated.

6. **AI-specific threats (if agentic).** If the scanner detected
   agentic patterns (LLM API calls, tool execution, agent frameworks),
   apply the 7th category "A" (AI Agent-Specific Attacks) per
   `references/stride.md` §ASTRIDE:
   - Prompt injection (indirect, direct, via tool outputs)
   - Unsafe tool invocation (tools with side effects, no allowlist)
   - Context/memory misuse (sensitive data in context window, memory
     poisoning)
   - Model impersonation (untrusted model endpoints)
   - Output manipulation (LLM output used in SQL, shell, eval without
     validation)
   
   Completion: if is_agentic, A-category threats enumerated with
   file:line evidence.

7. **Check vibe-code failure patterns.** Cross-reference findings
   against `references/vibe-code-patterns.md` — common security
   failures in AI-assisted code generation that STRIDE alone might
   miss or underweight.
   
   Completion: vibe-code pattern checklist completed for the codebase.

### Phase 3: DREAD Scoring

8. **Score each finding.** For every threat identified in Phase 2,
   score on five DREAD dimensions (0–10 each). Load
   `references/dread.md` for the scoring rubric.
   
   - **Damage** — how bad if exploited?
   - **Reproducibility** — how easy to reproduce?
   - **Exploitability** — how much skill/tools needed?
   - **Affected Users** — how many users impacted?
   - **Discoverability** — how easy to find?
   
   DREAD score = average of 5 dimensions. Tier:
   - ≥ 8.0 → Critical
   - 6.0–7.9 → High
   - 4.0–5.9 → Medium
   - < 4.0 → Low
   
   Completion: every finding has a DREAD score and severity tier.

9. **Rank findings.** Sort all findings by DREAD score descending.
   Present as a table: ID, STRIDE category, title, severity, file:line.
   
   Completion: ranked findings table presented to user.

### Phase 4: Recommendations

10. **Write remediation for each finding.** For each finding:
    - The specific file and what to change (not generic advice)
    - Code-level recommendation (show the fix, not just "add validation")
    - Priority matching the DREAD severity
    - If the fix is non-trivial, offer to apply it directly
    
    Completion: every finding has a concrete, file-specific remediation.

11. **Trace attack paths.** For Critical and High findings, trace
    multi-step attack paths through the DFD:
    "Attacker hits [endpoint A] → exploits [vulnerability B] →
    gains [access C] → uses it to [impact D]"
    
    This is where the conversational model advantage shines — the
    user can ask "what if the attacker does X?" and we trace it
    through the architecture in real time.
    
    Completion: top findings have documented attack paths.

12. **Generate the report.** Write the full threat model to:
    - `threat-model.md` — human-readable report (use
      `templates/threat-model.md` as structure)
    - `threat-model.yaml` — machine-readable (for CI/re-runs)
    
    Deliver `threat-model.md` inline via `MEDIA:`.
    
    Completion: both files written, report delivered to user.

## Pitfalls

- **Don't invent threats that don't apply to the code.** Every finding
  must cite specific file:line evidence. If you can't point to the code,
  it's a hypothesis — not a finding. Mark it as such.
- **The diagram is the foundation.** If the DFD is wrong, every finding
  downstream is wrong. The user gate between phases 1 and 2 is not
  optional.
- **Don't skip the agentic detection.** Most vibe-coded apps today use
  LLMs. Vanilla STRIDE misses prompt injection, tool abuse, and output
  manipulation — the ASTRIDE extension catches these.
- **Agentic = any LLM usage, not LLM + framework.** The scanner's
  `is_agentic` flag must be `has_llm or has_agent_framework or any(tool
  patterns)` — using `and` misses apps that call an LLM directly without
  an agent framework wrapper. Any file that imports `openai`,
  `anthropic`, or makes a `ChatCompletion` call is agentic.
- **Dangerous sink regex must match `subprocess.\w+\(`.** The pattern
  `(?:subprocess|os\.system|os\.popen)\s*\(` misses `subprocess.call()`
  and `subprocess.run()` because the group matches the module name but
  not the method call. Use `subprocess\.\w+\s*\(.*shell\s*=` to catch all
  subprocess methods including `.call`, `.run`, `.Popen`, `.check_output`.
- **DREAD is subjective but structured.** Score consistently using the
  rubric in `references/dread.md`. Don't inflate scores — a 3 is a 3.
- **The scanner is a starting point, not the answer.** It finds
  patterns; the model interprets them. Always verify scanner output
  against the actual code before reporting.
- **Read the actual code before claiming a vulnerability.** A missing
  import doesn't mean missing auth — the auth might be in middleware,
  a decorator, or a framework default. Verify before reporting.
- **Prioritize by exploitability, not just severity.** A Critical that
  requires internal network access is lower priority than a High that
  any internet user can hit. Note reachability in each finding.
- **Verify scanner regex syntax before first run.** A single unbalanced
  parenthesis in a pattern definition crashes the entire scanner with a
  SyntaxError. Run `python3 -c "import re; [re.compile(p) for p in patterns]"`
  or test the scanner against a small fixture before pointing it at a
  real codebase.

## Verification

- Every finding cites a specific file:line in the codebase
- Every finding has a DREAD score with all 5 dimensions
- The DFD was confirmed by the user before threat analysis ran
- If the app is agentic, A-category threats were evaluated
- Vibe-code pattern checklist was completed
- Top findings have traced attack paths
- `threat-model.md` and `threat-model.yaml` both written and delivered
- No finding lacks a concrete remediation with file-level specificity
