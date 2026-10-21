# Vibe-Code Security Failure Patterns

Common security failures in AI-assisted code generation. These are the
patterns that vibe-coded apps get wrong repeatedly — check each one
against the codebase. These complement (not replace) STRIDE analysis.

## 1. Hardcoded Secrets
**Pattern:** API keys, database passwords, tokens hardcoded in source
code or committed `.env` files.
**Where to look:** source files, config files, `.env`, `.env.local`,
docker-compose.yml, any file with `key`, `secret`, `password`, `token`.
**Evidence:** grep for `sk-`, `AKIA`, `password`, `secret`, `api_key`,
`Bearer`, `mongodb://`, `postgres://` with actual values (not env vars).

## 2. Missing Authentication on Endpoints
**Pattern:** API endpoints with no auth check — especially AI/agent
endpoints, which are often added quickly without auth middleware.
**Where to look:** route definitions (FastAPI `@app.get`, Express
`app.get`, Flask `@app.route`), check if auth middleware/decorator is
applied.
**Evidence:** routes without auth decorators, no `Depends(get_current_user)`,
no `req.user` check, no `@login_required`.

## 3. CORS Wide Open
**Pattern:** `Access-Control-Allow-Origin: *` with credentials enabled,
or CORS configured to allow all origins in development and never
tightened for production.
**Where to look:** CORS configuration, `app.add_middleware(CORSMiddleware, ...)`,
`app.use(cors())`, `@CrossOrigin`.
**Evidence:** `allow_origins=["*"]`, `origin: '*'`,
`allow_credentials=True` with wildcard origin.

## 4. Debug/Dev Routes Exposed
**Pattern:** Debug endpoints, admin panels, Swagger/OpenAPI docs, or
development tools left enabled in production.
**Where to look:** debug mode flags, `/docs`, `/redoc`, `/swagger`,
`/admin`, `debug=True`, `app.debug`.
**Evidence:** `DEBUG = True` in production config, `/docs` endpoint
enabled, `/admin` route without auth, Django `DEBUG = True`.

## 5. Unvalidated LLM Output in Dangerous Sinks
**Pattern:** LLM-generated output used directly in SQL queries, shell
commands, `eval()`, or file operations without any validation or
sanitization.
**Where to look:** anywhere `openai.ChatCompletion`, `anthropic.messages`,
`client.chat.completions` output is used — trace where the response text
goes.
**Evidence:** `eval(llm_response)`, `cursor.execute(f"SELECT ... {llm_output}")`,
`subprocess.call(llm_output, shell=True)`, `os.system(llm_output)`.

## 6. Secrets in Client-Side Code
**Pattern:** API keys, tokens, or credentials embedded in frontend
JavaScript, React components, or mobile app bundles.
**Where to look:** `.js`, `.jsx`, `.ts`, `.tsx` files,
`process.env.NEXT_PUBLIC_`, `VITE_`, any `const API_KEY` in frontend.
**Evidence:** `const apiKey = "sk-..."` in `.js`/`.jsx` files,
`NEXT_PUBLIC_API_KEY` with a real key, hardcoded keys in HTML.

## 7. No Rate Limiting
**Pattern:** Expensive endpoints (AI/LLM calls, database queries, file
processing) with no rate limiting — enables cost abuse and DoS.
**Where to look:** middleware setup, API route handlers — check for
`slowapi`, `@rate_limit`, `RateLimiter`, `throttle`, `express-rate-limit`.
**Evidence:** no rate limiting middleware, LLM endpoints without
limits, no `@limiter.limit()` decorators.

## 8. Insecure Direct Object References (IDOR)
**Pattern:** Sequential or predictable object IDs with no authorization
check — user can access other users' data by changing the ID.
**Where to look:** routes with path parameters (`/users/{id}`,
`/orders/{id}`), check if ownership is verified before returning data.
**Evidence:** `User.query.get(id)` without `id == current_user.id` check,
`/api/users/1` returns data regardless of who's authenticated, no
`WHERE user_id = ?` in queries.

## 9. No Input Validation on API Endpoints
**Pattern:** User input accepted without schema validation, type
checking, or sanitization — common when endpoints are generated
quickly.
**Where to look:** request handlers — check if Pydantic models, Zod
schemas, Joi validators, or manual validation are used.
**Evidence:** `request.json()` used directly without validation,
`req.body` without schema, `@app.post` without a request model,
no `pydantic.BaseModel` for inputs.

## 10. Insecure File Handling
**Pattern:** User-uploaded files stored without validation, served
from the same origin, or with predictable paths.
**Where to look:** file upload handlers, `request.files`, `multipart`,
`FormData`, storage paths.
**Evidence:** no file type validation, files stored in web-root,
user-controlled filenames used directly, no size limits.
