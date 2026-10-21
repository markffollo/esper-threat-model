# Esper

> *"Enhance. Stop. Move left. Enhance. Stop. Pull back.* — the Esper machine, Blade Runner (1982)

STRIDE threat modeling for vibe-coded applications. Named after the Esper machine in Blade Runner — the photo analysis device that discovers hidden details invisible to the naked eye.

## What it does

Scan a codebase built with AI tools (Cursor, Bolt, Lovable, v0, Claude Code) and get:

1. **Architecture discovery → Data Flow Diagram** — components, data flows, trust boundaries rendered as a visual HTML diagram
2. **STRIDE assessment** — every component × trust boundary evaluated against the 6 STRIDE categories, plus a 7th "A" category (ASTRIDE) for AI/agentic threats
3. **DREAD severity ranking** — each finding scored 0–10 on 5 dimensions, ranked Critical/High/Medium/Low
4. **Actionable remediation** — file:line evidence, concrete code fixes, and multi-step attack path tracing

## Why

Vibe-coded apps ship fast but skip security. Existing tools (appsec-advisor, SecureVibes, STRIDE-GPT) run on Claude — which refuses to describe real attack paths, water down exploit scenarios, and bail mid-analysis on exactly the threat categories that matter most. Esper runs on non-refusing models (GLM/DeepSeek via OpenRouter) and is conversational, not one-shot.

## Install (Hermes Agent skill)

```bash
# Copy the skill directory into your Hermes skills folder
cp -r skill/ ~/.hermes/skills/security/threat-modeling/
```

Or use `skill_manage` to install it.

## Usage

In a Hermes session:

> "Run the threat-modeling skill on /path/to/my/vibe-coded-app"

The skill will:
1. Run `scripts/scan_codebase.py` to discover the architecture
2. Generate a DFD using the `architecture-diagram` skill
3. Ask you to confirm the diagram before proceeding
4. Apply STRIDE + ASTRIDE per trust boundary
5. Score findings with DREAD
6. Output `threat-model.md` + `threat-model.yaml`

## Structure

```
skill/
├── SKILL.md                        # Main skill (4-phase workflow)
├── references/
│   ├── stride.md                   # STRIDE + ASTRIDE category definitions
│   ├── dread.md                    # DREAD scoring rubric (0–10 per dimension)
│   └── vibe-code-patterns.md      # 10 common vibe-code security failures
├── templates/
│   ├── threat-model.md            # Report template
│   └── threat-model.yaml          # Machine-readable output
└── scripts/
    └── scan_codebase.py           # Codebase scanner (11 languages)
```

## Supported languages

Python, JavaScript, TypeScript, Go, Ruby, Java, PHP, C#, Rust, Kotlin, Swift

## Requirements

- [Hermes Agent](https://github.com/NousResearch/hermes-agent)
- The `architecture-diagram` skill (ships with Hermes)
- An OpenRouter API key with GLM-5.3 or DeepSeek V3 (recommended models)

## License

MIT
