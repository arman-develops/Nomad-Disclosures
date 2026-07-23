# Case Study: Authorized Security Assessment of Flipkart's Home Services Platform
**Researcher:** Arman  
**Program:** Flipkart Bug Bounty — HackerOne (Launched April 2025)  
**Scope:** `flipkart.com` and associated subdomains  
**Engagement Type:** Authorized bug bounty — black-box, unauthenticated and guest-authenticated surface  
**Duration:** Multi-session reconnaissance and analysis  
**Status:** Findings documented; CORS report submission in progress

---

## Executive Summary

This engagement focused on Flipkart's home services web platform and its underlying microservice infrastructure, accessible via several subdomains: `homeservice.flipkart.com`, `wooster.flipkart.com`, and `hubsystem.flipkart.com`. Through systematic black-box reconnaissance — including JavaScript bundle analysis, API endpoint enumeration, and CORS origin probing — two confirmed vulnerabilities were identified, and three additional attack surfaces were characterized through negative testing, producing thorough non-exploitability documentation.

The most significant confirmed finding is a CORS misconfiguration with credential exposure across two backend subdomains, which could allow a malicious third-party site to silently make credentialed API calls on behalf of an authenticated user. A secondary finding — an unauthenticated cart endpoint leaking session artifacts — was also confirmed and characterized.

---

## Engagement Scope and Methodology

### Target Overview

Flipkart's home services platform (`homeservice.flipkart.com`) provides consumers with access to repair, cleaning, and maintenance service bookings. The platform is backed by a microservice architecture, with API traffic handled by internal services exposed on separate subdomains. The system uses a layered authentication model:

- **Guest tokens** issued by `generate_token` (no credentials required)
- **Authenticated tokens** issued via `login/ultra` (OAuth/SSO code exchange) or `login/jeeves` (username/password for internal/partner accounts)
- **JWT-based session validation** enforced by an Envoy-fronted service mesh (identified via `server: istio-envoy` response headers)

The portal does not support public account registration; accounts appear to be provisioned out-of-band, consistent with a B2B or internal-partner-facing deployment model.

### Methodology

Reconnaissance proceeded in four phases:

1. **JavaScript bundle analysis** — Deobfuscation and structural analysis of `bundle.js` to extract API endpoint maps, authentication flow logic, session configuration, and client-side routing tables.
2. **Unauthenticated endpoint enumeration** — Systematic probing of extracted API endpoints without session tokens to identify access control gaps.
3. **Guest token scoping** — Calling `generate_token` to obtain a legitimately issued guest `access_token`, then replaying it against the full endpoint inventory to determine its effective scope.
4. **CORS origin probing** — Testing `Access-Control-Allow-Origin` header behavior across subdomains with attacker-controlled `Origin` values, with `withCredentials` mode to assess credential exposure.

All testing was performed within the rules of engagement of the Flipkart HackerOne program. No user data was accessed or extracted. No authentication bypass was attempted beyond testing legitimately issued tokens against their intended scope.

---

## Findings

### Finding 1 — CORS Misconfiguration with Credential Reflection (High Severity)

**Affected Hosts:** `wooster.flipkart.com`, `hubsystem.flipkart.com`  
**Status:** Confirmed  
**CVSS Estimate:** 8.1 (High) — Network / Low Complexity / No Privileges Required / User Interaction Required

#### Description

Both `wooster.flipkart.com` and `hubsystem.flipkart.com` reflect arbitrary `Origin` header values in `Access-Control-Allow-Origin` responses, combined with `Access-Control-Allow-Credentials: true`. This combination violates the CORS specification's requirement that wildcard or reflected origins must not be paired with credential allowance.

#### Technical Detail

A request with an attacker-controlled origin:

```
GET /[endpoint] HTTP/1.1
Host: wooster.flipkart.com
Origin: https://attacker-controlled.com
Cookie: [session cookies]
```

Returns:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker-controlled.com
Access-Control-Allow-Credentials: true
```

This means a malicious page at `https://attacker-controlled.com` can issue cross-origin requests to these endpoints from a victim's browser, and the browser will include the victim's session cookies — and expose the response body to the attacker's JavaScript.

#### Business Impact

An attacker who can direct an authenticated Flipkart user to a malicious page (via phishing, a compromised ad, or an open redirect) can silently exfiltrate data from any API endpoint reachable on these subdomains — including booking history, saved addresses, payment method metadata, and support incident details — without the user's knowledge or any visible interaction.

#### Scope Note

`homeservice.flipkart.com` was spot-checked and does not exhibit this behavior; the misconfiguration is isolated to the two backend subdomains named above.

---

### Finding 2 — Unauthenticated Cart Endpoint Exposes Session Artifacts (Medium Severity)

**Affected Host:** `homeservice.flipkart.com`  
**Endpoint:** `GET /cart`  
**Status:** Confirmed  
**CVSS Estimate:** 5.3 (Medium) — Network / Low Complexity / No Privileges Required / No User Interaction

#### Description

The `/cart` endpoint returns a valid JSON response, including a `cart_id` and `total_amount`, without requiring any authentication token. All other user-tied endpoints correctly enforce session requirements.

#### Technical Detail

Unauthenticated request:

```
GET /cart HTTP/1.1
Host: homeservice.flipkart.com
```

Response (200 OK):

```json
{
  "cart_id": "[value]",
  "total_amount": 0,
  "line_items": []
}
```

Contrast with authenticated endpoints such as `/profile`, `/bookings`, `/addresses`, which correctly return:

```json
{"code": "SESSION_NOT_SET", "message": "Failed : JWT key does not exists"}
```

#### Business Impact

The immediate impact is limited — the endpoint returns no user PII and the cart contents are empty for unauthenticated sessions. However, the `cart_id` is a server-issued session artifact that may have value in CSRF or cart-fixation attack chains, depending on how the checkout flow consumes it. The finding also represents an inconsistency in authentication enforcement across the API surface, which warrants remediation for defense-in-depth.

---

## Negative Findings (Tested and Not Exploitable)

The following attack surfaces were systematically tested and found not to be exploitable. These are included to demonstrate thoroughness and to provide a clear record of what was characterized during the engagement.

### Guest Token Privilege Escalation — Not Exploitable

Guest tokens issued by `generate_token` were tested against all authenticated API endpoints (`/profile`, `/bookings`, `/addresses`, `/incidents`, `/checkout/*`, `/v1/app/home_screen`). All returned `401 SESSION_NOT_SET`. Guest tokens are correctly scoped to anonymous browsing only and cannot access user data.

### Stored XSS / SSTI via Form Submission — Unconfirmed

Payloads were submitted via `POST /send-user-collection` (a seller inquiry form). Out-of-band callback infrastructure (webhook listener) was deployed to detect blind execution. No callbacks were received across the testing window. Assessed as either: sanitized server-side, not rendered in any downstream execution context, or rendered in a context not reachable from the test environment. Not reported.

### JSON Injection on Form Inputs — Impact Undemonstrated

Form fields on the submission surface accepted unsanitized JSON-like input without server-side rejection. No demonstrable impact was established — the input appeared to be treated as an opaque string rather than parsed. Not reported pending further characterization.

### Token Prediction / Device ID Manipulation — Mitigated

The `X-DEVICE-ID` header value used in token generation is attacker-controllable client-side, but the resulting token is bound by server-side JWT signature validation. Manipulation of the device ID produced tokens with different claims but no elevated privileges. The attack surface is mitigated by cryptographic validation; no exploitable path was found.

---

## Architecture Intelligence (Recon Output)

The following was determined through bundle analysis and response header inspection, and may be useful context for the client's internal security team:

- **Service mesh:** Istio/Envoy (identified via `server: istio-envoy`, `x-envoy-upstream-service-time` headers)
- **Backend language:** Java (inferred from response structure and internal service naming conventions)
- **Internal service names:** "Jeeves" (authentication/login microservice), "Wooster" (API gateway / internal service hub — name consistent with `wooster.flipkart.com`)
- **Token architecture:** Dual-path authentication — OAuth/SSO (`login/ultra`) for consumer platform, credential-based (`login/jeeves`) for internal/partner accounts; guest flow via `generate_token`
- **Firebase:** Present in the frontend bundle, assessed as FCM (push notification infrastructure) rather than a Firebase database integration. No Firestore or Realtime Database SDK calls were identified; no Firebase misconfiguration testing was warranted.
- **Frontend routing:** React-based SPA with 28 identified client-side routes, consistent with a full-featured consumer booking application

---

## Observations on Program Quality

Flipkart's HackerOne program demonstrates above-average operational maturity:

- **6-hour average time to first response** — among the fastest in the industry for a program of this scale
- **91% response efficiency** — consistently engages with incoming reports
- **Managed by HackerOne** with collaboration and retesting enabled

This engagement was conducted with confidence in the program's ability to triage findings appropriately and engage with the researcher in good faith.

---

## Recommendations

| Priority | Recommendation |
|---|---|
| High | Restrict `Access-Control-Allow-Origin` on `wooster.flipkart.com` and `hubsystem.flipkart.com` to an explicit allowlist of trusted origins. Do not pair reflected or wildcard origins with `Access-Control-Allow-Credentials: true`. |
| Medium | Enforce authentication on `GET /cart` or, if a guest cart is an intentional product feature, ensure the `cart_id` cannot be used to fixate or escalate a session during checkout. |
| Low | Conduct a full audit of API endpoints for authentication enforcement consistency, using the endpoint inventory identified in this assessment as a baseline. |
| Informational | Review `POST /send-user-collection` for output encoding if submitted values are rendered anywhere in internal tooling or admin dashboards. |

---

## About the Researcher

Independent security researcher and CS graduate based in Nairobi, Kenya, specializing in web application security assessments and responsible disclosure. This engagement is part of an active portfolio of authorized bug bounty and vulnerability disclosure work across multiple programs. Previous engagements include confirmed critical-severity findings in authentication and access control across several platforms.

All work conducted under authorized programs with strict adherence to responsible disclosure principles. No user data is accessed, exfiltrated, or retained during assessments.

---

*This case study is produced for portfolio purposes. Sensitive technical details such as specific payload values, full response bodies containing system internals, and unreported findings have been omitted or generalized in accordance with responsible disclosure norms.*
