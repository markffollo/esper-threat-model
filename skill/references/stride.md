# STRIDE Threat Categories

## Standard STRIDE (Microsoft)

### S — Spoofing
**Question:** Can someone impersonate a legitimate user or system at this boundary?

Check for:
- Authentication missing or bypassable on endpoints
- Credentials/tokens stored insecurely (plaintext, client-side, hardcoded)
- No session validation or session fixation
- API keys with no rotation or revocation
- Certificate validation disabled (insecure TLS, `verify=False`)

### T — Tampering
**Question:** Can data be modified in transit or at rest without detection?

Check for:
- Input validation missing (no schema validation, raw user input used directly)
- No integrity checks on data (missing HMAC, checksums, signatures)
- Mutable data structures exposed to untrusted parties
- Database writes without authorization checks
- Unsigned/unchecked cookies or JWTs without signature verification

### R — Repudiation
**Question:** Can a user deny performing an action, and the system can't prove otherwise?

Check for:
- Critical actions not logged (auth events, data access, admin operations)
- Logs that can be tampered with (no WORM/append-only, no integrity)
- No audit trail for sensitive operations
- Logs missing user identity, timestamp, or action details

### I — Information Disclosure
**Question:** Can data leak to unauthorized parties at this boundary?

Check for:
- Sensitive data in responses without auth checks
- Error messages revealing stack traces, internal structure, or secrets
- Data exposure in logs, metrics, or debug output
- PII stored/transmitted without encryption
- API responses returning more data than needed (over-posting)

### D — Denial of Service
**Question:** Can this component be overwhelmed or made unavailable?

Check for:
- No rate limiting on expensive endpoints (AI/LLM calls, DB queries, file processing)
- Unbounded resource consumption (no limits on request size, upload size, query depth)
- No circuit breakers on external service calls
- Expensive operations without caching or queuing
- Resource exhaustion vectors (memory, file handles, connections)

### E — Elevation of Privilege
**Question:** Can a user gain capabilities beyond their authorized level?

Check for:
- Missing authorization checks on privileged operations
- IDOR/BOLA (sequential IDs, no ownership verification)
- Role checks missing or bypassable
- Admin functionality accessible to regular users
- Privilege escalation via parameter manipulation

## ASTRIDE — AI Agent-Specific Threats (7th Category)

### A — AI Agent-Specific Attacks

**Prompt Injection:**
- Direct: user input contains instructions that override system prompts
- Indirect: untrusted data (web pages, tool outputs, documents) contains injections
- Via tool results: tool output poisons the agent's context window

**Unsafe Tool Invocation:**
- Agent can call tools with side effects (delete, send, write) without confirmation
- No tool allowlist or allowlist bypassable
- Tool parameters not validated before execution
- Agent can access tools outside its intended scope

**Context/Memory Misuse:**
- Sensitive data (PII, secrets) sent to LLM context without sanitization
- Agent memory can be poisoned by crafted inputs
- Conversation history leaks across user sessions
- Context window used as a data exfiltration channel

**Model Impersonation:**
- Untrusted or unverified LLM endpoints (no API key validation, open proxies)
- Model responses trusted without verification (especially for code/commands)
- No guardrails on model output before execution

**Output Manipulation:**
- LLM output used directly in SQL queries, shell commands, or eval without validation
- Model output treated as trusted code (exec, eval, subprocess with model output)
- No sandboxing of agent actions (filesystem, network, system calls)
