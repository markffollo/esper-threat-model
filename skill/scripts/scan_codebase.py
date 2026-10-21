#!/usr/bin/env python3
"""Codebase scanner for threat modeling.

Walks a codebase directory and identifies components, data flows,
trust boundaries, auth mechanisms, secrets, and AI/agentic patterns.
Outputs structured JSON for the threat modeling skill to consume.

Usage: python3 scan_codebase.py /path/to/project [--output components.json]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# --- File extensions to scan
SCAN_EXTENSIONS = {
    # Python
    ".py", ".pyw",
    # JS/TS
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    # Go
    ".go",
    # Ruby
    ".rb",
    # Java/Kotlin
    ".java", ".kt", ".kts",
    # PHP
    ".php",
    # C#/Rust
    ".cs", ".rs",
    # Config
    ".yaml", ".yml", ".toml", ".json", ".env", ".ini", ".cfg",
    # Web
    ".html", ".vue", ".svelte",
    # Docker
    ".dockerfile",
    # Shell
    ".sh", ".bash",
}

# Directories to skip
SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "__pycache__",
    ".next", ".nuxt", "dist", "build", ".output", ".svelte-kit",
    "vendor", ".idea", ".vscode", "target", ".gradle", ".mvn",
    "coverage", ".nyc_output", ".turbo", ".parcel-cache",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

# --- Pattern definitions

# API routes / entry points
ROUTE_PATTERNS = [
    # Python - FastAPI/Flask/Starlette/Django
    (re.compile(r'@(?:app|router)\.(get|post|put|patch|delete|head|options|api_route)\s*\(([^)]+)'), "python", "api_route"),
    (re.compile(r'@(?:bp|blueprint)\.(get|post|put|patch|delete)\s*\(([^)]+)'), "python", "api_route"),
    (re.compile(r'path\(\s*["\']([^"\']+)'), "python", "api_route"),
    # JS/TS - Express/Next/Hono/NestJS
    (re.compile(r'\.(?:get|post|put|patch|delete|use)\s*\(\s*["\']([^"\']+)'), "javascript", "api_route"),
    (re.compile(r'(?:router|app)\.(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)'), "javascript", "api_route"),
    (re.compile(r'(?:export\s+)?(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)'), "javascript", "api_route"),  # Next.js app router
    # Go - net/http/gin/echo
    (re.compile(r'(?:http\.)?HandleFunc\s*\(\s*["\']([^"\']+)'), "go", "api_route"),
    (re.compile(r'(?:r|router|e|g)\.(?:GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\']([^"\']+)'), "go", "api_route"),
    # Ruby - Rails/Sinatra
    (re.compile(r'(?:get|post|put|patch|delete)\s+["\']([^"\']+)'), "ruby", "api_route"),
    # Java - Spring
    (re.compile(r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(([^)]+)'), "java", "api_route"),
    # PHP - Laravel
    (re.compile(r'Route::(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)'), "php", "api_route"),
]

# Database connections
DB_PATTERNS = [
    # Connection strings
    (re.compile(r'(?:mongodb|postgres|postgresql|mysql|redis|amqp|sqlite)://[^"\'\s]+'), None, "db_connection_string"),
    # Python ORMs/clients
    (re.compile(r'import\s+(sqlalchemy|psycopg2|pymongo|redis|sqlite3|aiomysql|asyncpg|motor)'), "python", "db_import"),
    (re.compile(r'(?:create_engine|sessionmaker|AsyncSession|MongoClient|Redis)\s*\('), "python", "db_init"),
    # JS/TS ORMs/clients
    (re.compile(r'(?:require|import)\s+.*(?:mongoose|pg|prisma|@prisma/client|redis|ioredis|sequelize|knex|mongodb|drizzle-orm)'), "javascript", "db_import"),
    (re.compile(r'new\s+(?:PrismaClient|MongoClient|Redis|Knex|Sequelize)\s*\('), "javascript", "db_init"),
    # Go
    (re.compile(r'"(?:database/sql|gorm\.io|go\.mongodb\.org)"'), "go", "db_import"),
    # Ruby
    (re.compile(r'(?:establish_connection|ActiveRecord::Base|Mongo::Client)'), "ruby", "db_init"),
    # Java
    (re.compile(r'@(?:Repository|Entity|Table)'), "java", "db_entity"),
]

# External services / API calls
EXTERNAL_PATTERNS = [
    # HTTP clients
    (re.compile(r'(?:import|require).*\b(?:requests|httpx|aiohttp|urllib3|fetch|axios|got|node-fetch|undici|superagent)\b'), None, "http_client"),
    # Cloud SDKs
    (re.compile(r'(?:import|require).*\b(?:boto3|aws-sdk|@aws-sdk|google-cloud|@google-cloud|azure-sdk|@azure)\b'), None, "cloud_sdk"),
    # Supabase/Firebase
    (re.compile(r'(?:import|require).*\b(?:@supabase/supabase-js|firebase|admin)\b'), None, "baas"),
    # Stripe/payment
    (re.compile(r'(?:import|require).*\b(?:stripe|@stripe)\b'), None, "payment"),
]

# LLM / AI patterns
LLM_PATTERNS = [
    (re.compile(r'(?:import|require).*\b(?:openai|anthropic|google\.generativeai|cohere|mistralai|groq)\b'), None, "llm_import"),
    (re.compile(r'(?:import|require).*\b(?:langchain|langgraph|llamaindex|crewai|autogen|haystack|semantic_kernel|phi)\b'), None, "agent_framework"),
    (re.compile(r'(?:ChatCompletion|chat\.completions|messages\.create|generativeModel|generateContent)'), None, "llm_call"),
    (re.compile(r'(?:sk-[a-zA-Z0-9]{20,}|ANTHROPIC_API_KEY|OPENAI_API_KEY)'), None, "llm_api_key"),
    (re.compile(r'\b(?:system_prompt|system_message|tools?)\s*[=:]', re.IGNORECASE), None, "agent_tool"),
    (re.compile(r'function_call|tool_call|function_definition|tools=\['), None, "agent_tool_def"),
]

# Auth patterns
AUTH_PATTERNS = [
    (re.compile(r'(?:import|require).*\b(?:jwt|jsonwebtoken|jose|pyjwt|python-jose|authlib)\b'), None, "jwt"),
    (re.compile(r'(?:import|require).*\b(?:passport|oauth2|authlib|next-auth|@auth|lucia|better-auth)\b'), None, "oauth"),
    (re.compile(r'(?:import|require).*\b(?:express-session|flask-session|connect-session|cookie-session|express-cookie)\b'), None, "session"),
    (re.compile(r'(?:Bearer|Authorization|x-api-key|api_key|apikey)', re.IGNORECASE), None, "auth_header"),
    (re.compile(r'(?:verify_token|decode_token|get_current_user|require_auth|@login_required|check_auth|authenticate)'), None, "auth_func"),
    (re.compile(r'(?:Depends|Security|Header)\s*\(\s*(?:get_current_user|verify_token|check_auth)'), None, "auth_decorator"),
]

# Secret patterns
SECRET_PATTERNS = [
    (re.compile(r'(?:sk-[a-zA-Z0-9]{20,})'), None, "openai_key"),
    (re.compile(r'(?:AKIA[A-Z0-9]{16})'), None, "aws_key"),
    (re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{36})'), None, "github_pat"),
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{3,}["\']', re.IGNORECASE), None, "hardcoded_password"),
    (re.compile(r'(?:secret|api_key|apikey|access_token|private_key)\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE), None, "hardcoded_secret"),
    (re.compile(r'(?:-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----)'), None, "private_key"),
]

# CORS patterns
CORS_PATTERNS = [
    (re.compile(r'allow_origins\s*[=:]\s*\[["\']\*["\']'), None, "cors_wildcard"),
    (re.compile(r'origin\s*[=:]\s*["\']\*["\']'), None, "cors_wildcard"),
    (re.compile(r'Access-Control-Allow-Origin.*\*'), None, "cors_wildcard"),
    (re.compile(r'allow_credentials\s*[=:]\s*True'), None, "cors_credentials"),
]

# Debug patterns
DEBUG_PATTERNS = [
    (re.compile(r'(?:DEBUG|debug)\s*[=:]\s*(?:True|true|TRUE|1)'), None, "debug_enabled"),
    (re.compile(r'app\.(?:run|listen)\s*\(.*(?:debug|debug=True|debug=true)'), None, "debug_mode"),
    (re.compile(r'/docs|/redoc|/swagger'), None, "api_docs_exposed"),
]

# Rate limiting patterns (to detect ABSENCE — note if found)
RATE_LIMIT_PATTERNS = [
    (re.compile(r'(?:slowapi|@rate_limit|RateLimiter|limiter|throttle|express-rate-limit|@Limiter|rateLimit)'), None, "rate_limit_present"),
]

# Eval/exec patterns (dangerous sinks)
DANGEROUS_SINK_PATTERNS = [
    (re.compile(r'\b(?:eval|exec)\s*\('), None, "eval_exec"),
    (re.compile(r'subprocess\.\w+\s*\(.*shell\s*=\s*(?:True|true)'), None, "shell_exec"),
    (re.compile(r'(?:cursor|execute)\s*\(\s*f["\']'), None, "sql_fstring"),
    (re.compile(r'\.execute\s*\(\s*.*\+'), None, "sql_concat"),
]

ALL_PATTERN_GROUPS = [
    ("routes", ROUTE_PATTERNS),
    ("databases", DB_PATTERNS),
    ("external_services", EXTERNAL_PATTERNS),
    ("llm_ai", LLM_PATTERNS),
    ("auth", AUTH_PATTERNS),
    ("secrets", SECRET_PATTERNS),
    ("cors", CORS_PATTERNS),
    ("debug", DEBUG_PATTERNS),
    ("rate_limiting", RATE_LIMIT_PATTERNS),
    ("dangerous_sinks", DANGEROUS_SINK_PATTERNS),
]


def scan_file(filepath: Path) -> dict:
    """Scan a single file and return findings."""
    results = {}
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return results

    lines = content.split("\n")
    for group_name, patterns in ALL_PATTERN_GROUPS:
        group_results = []
        for regex, lang, ptype in patterns:
            for i, line in enumerate(lines, 1):
                m = regex.search(line)
                if m:
                    group_results.append({
                        "file": str(filepath),
                        "line": i,
                        "type": ptype,
                        "match": m.group(0)[:200],
                        "language": lang or filepath.suffix.lstrip("."),
                        "context": line.strip()[:300],
                    })
        if group_results:
            results[group_name] = group_results

    return results


def classify_component(findings: dict, filepath: Path) -> str:
    """Classify a component based on what was found in its files."""
    if "routes" in findings:
        return "api_backend"
    if "databases" in findings:
        return "database"
    if "llm_ai" in findings:
        return "ai_llm"
    if "external_services" in findings:
        return "external_service"
    if filepath.suffix in (".html", ".vue", ".svelte", ".css"):
        return "frontend"
    if filepath.suffix in (".yaml", ".yml", ".toml", ".env"):
        return "config"
    return "unknown"


def scan_codebase(root: str) -> dict:
    """Scan the entire codebase and return structured results."""
    root_path = Path(root).resolve()
    all_findings = {}
    file_findings = []
    languages = set()
    is_agentic = False
    has_llm = False
    has_agent_framework = False

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Skip excluded directories
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]

        for filename in filenames:
            filepath = Path(dirpath) / filename
            ext = filepath.suffix.lower()
            if not ext and filename.lower() not in ("dockerfile", "makefile", "procfile"):
                continue
            if ext not in SCAN_EXTENSIONS and filename.lower() not in ("dockerfile", "makefile", "procfile"):
                continue

            if ext in (".py",):
                languages.add("python")
            elif ext in (".js", ".jsx", ".mjs", ".cjs"):
                languages.add("javascript")
            elif ext in (".ts", ".tsx"):
                languages.add("typescript")
            elif ext in (".go",):
                languages.add("go")
            elif ext in (".rb",):
                languages.add("ruby")
            elif ext in (".java",):
                languages.add("java")
            elif ext in (".php",):
                languages.add("php")

            file_result = scan_file(filepath)
            if file_result:
                for group, items in file_result.items():
                    if group not in all_findings:
                        all_findings[group] = []
                    all_findings[group].extend(items)

                    if group == "llm_ai":
                        for item in items:
                            if item["type"] in ("llm_import", "llm_call", "llm_api_key"):
                                has_llm = True
                            if item["type"] == "agent_framework":
                                has_agent_framework = True
                            if item["type"] in ("agent_tool", "agent_tool_def"):
                                has_agent_framework = True

                comp_type = classify_component(file_result, filepath)
                file_findings.append({
                    "file": str(filepath),
                    "component_type": comp_type,
                    "findings": list(file_result.keys()),
                })

    is_agentic = has_llm or has_agent_framework or any(
        item["type"] in ("agent_tool", "agent_tool_def", "function_call", "tool_call")
        for item in all_findings.get("llm_ai", [])
    )

    # Build components list
    components = []
    comp_map = {}
    for ff in file_findings:
        ctype = ff["component_type"]
        if ctype not in comp_map:
            comp_map[ctype] = {"name": ctype, "type": ctype, "files": [], "finding_types": set()}
        comp_map[ctype]["files"].append(ff["file"])
        for g in ff["findings"]:
            comp_map[ctype]["finding_types"].add(g)

    for ctype, data in comp_map.items():
        data["finding_types"] = list(data["finding_types"])
        data["file_count"] = len(data["files"])
        data["files"] = data["files"][:20]  # cap
        components.append(data)

    # Build trust boundaries
    trust_boundaries = []
    if any(c["type"] == "frontend" for c in components):
        trust_boundaries.append("Internet → Frontend")
    if any(c["type"] == "api_backend" for c in components):
        trust_boundaries.append("Frontend → API")
    if any(c["type"] == "database" for c in components):
        trust_boundaries.append("API → Database")
    if any(c["type"] == "external_service" for c in components):
        trust_boundaries.append("API → External Service")
    if has_llm or is_agentic:
        trust_boundaries.append("API → LLM/AI Provider")

    # Build data flows (inferred)
    data_flows = []
    comp_types = set(c["type"] for c in components)
    if "frontend" in comp_types and "api_backend" in comp_types:
        data_flows.append({"from": "frontend", "to": "api_backend", "data_type": "user_requests", "protocol": "https", "trust_boundary": "Internet → Frontend → API"})
    if "api_backend" in comp_types and "database" in comp_types:
        data_flows.append({"from": "api_backend", "to": "database", "data_type": "queries_data", "protocol": "tcp", "trust_boundary": "API → Database"})
    if "api_backend" in comp_types and "external_service" in comp_types:
        data_flows.append({"from": "api_backend", "to": "external_service", "data_type": "api_calls", "protocol": "https", "trust_boundary": "API → External Service"})
    if ("api_backend" in comp_types or "ai_llm" in comp_types) and (has_llm or is_agentic):
        data_flows.append({"from": "api_backend", "to": "llm_provider", "data_type": "prompts_responses", "protocol": "https", "trust_boundary": "API → LLM/AI Provider"})

    # Rate limiting status
    has_rate_limiting = bool(all_findings.get("rate_limiting"))

    # Count findings
    finding_counts = {k: len(v) for k, v in all_findings.items()}

    return {
        "project_root": str(root_path),
        "languages": sorted(languages),
        "is_agentic": is_agentic,
        "has_llm": has_llm,
        "has_agent_framework": has_agent_framework,
        "has_rate_limiting": has_rate_limiting,
        "components": components,
        "data_flows": data_flows,
        "trust_boundaries": trust_boundaries,
        "raw_findings": all_findings,
        "finding_counts": finding_counts,
        "total_findings": sum(finding_counts.values()),
    }


def main():
    parser = argparse.ArgumentParser(description="Scan codebase for threat modeling")
    parser.add_argument("path", help="Path to the codebase root directory")
    parser.add_argument("--output", "-o", default="components.json", help="Output JSON file path")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a directory", file=sys.stderr)
        sys.exit(1)

    result = scan_codebase(args.path)

    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Scanned: {args.path}")
    print(f"Languages: {', '.join(result['languages'])}")
    print(f"Agentic: {result['is_agentic']}")
    print(f"Components found: {len(result['components'])}")
    print(f"Trust boundaries: {len(result['trust_boundaries'])}")
    print(f"Data flows: {len(result['data_flows'])}")
    print(f"Total raw findings: {result['total_findings']}")
    for group, count in sorted(result["finding_counts"].items()):
        print(f"  {group}: {count}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
