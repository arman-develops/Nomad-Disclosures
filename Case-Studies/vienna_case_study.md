# Case Study: City of Vienna Digital Infrastructure
## Independent Application Security Assessment

**Researcher:** Arman  
**Engagement Type:** Authorized Bug Bounty (Bugcrowd Managed Program)  
**Assessment Period:** February 2026  
**Target Scope:** wien.gv.at and associated infrastructure  
**Program Status:** Active — City of Vienna Managed Bug Bounty  

---

## Executive Overview

The City of Vienna operates one of Europe's most extensive municipal digital infrastructures, serving over 1.9 million residents through a network of web applications, citizen portals, and internal government systems. As part of an authorized bug bounty engagement, an independent security assessment was conducted across the primary `wien.gv.at` domain and three associated infrastructure domains.

The assessment revealed multiple information disclosure vulnerabilities across the authentication and API layers. While the organization's core security posture was found to be mature — with proper cryptographic controls, mutual TLS enforcement, and well-configured security headers — several issues were identified that reduce defense-in-depth and could aid an attacker in reconnaissance or further exploitation.

This case study documents the methodology, findings, and lessons drawn from the engagement, with the goal of helping organizations understand how information disclosure vulnerabilities — often dismissed as low severity — form the foundation of higher-impact attack chains.

---

## Organizational Context

| **Attribute** | **Detail** |
|---------------|------------|
| Organization | City of Vienna (Stadt Wien) |
| Sector | Government / Public Administration |
| Infrastructure Scale | 1,700+ subdomains across primary domain |
| Authentication Stack | SAML 2.0 (Shibboleth), Azure AD, OIDC |
| Technology Stack | ASP.NET, Liferay CMS, WordPress, Apache |
| Regulatory Context | GDPR, Austrian Data Protection Act (DSG) |
| Engagement Channel | Bugcrowd Managed Bug Bounty Program |

---

## Scope and Methodology

### Scope

The engagement covered the following domains:

- `wien.gv.at` — Primary municipal portal
- `magwien.gv.at` — Internal administration infrastructure
- `gesundheitsverbund.at` — Vienna Healthcare Group
- `akhwien.at` — General Hospital Vienna (AKH)

### Methodology

The assessment followed a structured approach adapted from industry-standard frameworks including OWASP WSTG and the Bugcrowd Vulnerability Rating Taxonomy.

```
Phase 1: Reconnaissance
    └── Subdomain enumeration
    └── Technology fingerprinting
    └── Attack surface mapping

Phase 2: Authentication Analysis
    └── SAML flow interception and analysis
    └── Azure AD integration testing
    └── Session management review

Phase 3: API Security Testing
    └── Endpoint enumeration
    └── Input validation testing
    └── Error message analysis

Phase 4: Infrastructure Testing
    └── Subdomain takeover verification
    └── CVE validation
    └── Header and configuration review

Phase 5: Documentation
    └── Finding validation
    └── Impact analysis
    └── Report writing
```

### Tools Used

- **Subdomain Enumeration:** subfinder, httpx
- **HTTP Analysis:** Burp Suite, curl
- **DNS Analysis:** dig, custom shell scripts
- **SAML Analysis:** Python (base64, lxml), manual inspection
- **Fuzzing:** ffuf, manual parameter testing

---

## Reconnaissance Findings

### Attack Surface

Subdomain enumeration revealed a large but well-managed attack surface:

| **Domain** | **Found** | **Resolved** | **Public-Facing** |
|------------|-----------|--------------|-------------------|
| wien.gv.at | 1,700 | 897 | ~78 |
| magwien.gv.at | 375 | 68 | ~9 |
| gesundheitsverbund.at | 142 | 96 | ~20 |
| akhwien.at | 112 | 45 | ~12 |

The majority of subdomains either redirected to the main portal, returned 404s, or were protected behind authentication. No dangling DNS records or subdomain takeover vulnerabilities were identified across eight verified Azure Front Door CNAME records.

### Technology Fingerprinting

The infrastructure runs a heterogeneous stack:

- **Authentication:** Shibboleth SP (SAML 2.0), Azure AD (OIDC), Custom IdP (`stdportal-idp`)
- **CMS:** Liferay Portal, WordPress
- **Backend:** ASP.NET WebForms, .NET Web API, Apache 2.4.37
- **CDN/Edge:** Azure Front Door
- **Internal API:** Custom REST API on `stp.wien.gv.at:4543` (mTLS protected)

---

## Authentication Architecture

A significant portion of the assessment focused on the SAML 2.0 authentication infrastructure, which serves as the single sign-on backbone across multiple citizen-facing portals.

### SAML Flow

The primary authentication flow was mapped as follows:

```
Citizen Portal                  Identity Provider              Service Provider
(mitgestalten.wien.gv.at)      (mein.wien.gv.at/stdportal-idp)  (shib.wien.gv.at)
        |                               |                               |
        |--- AuthnRequest (signed) ---->|                               |
        |                               |                               |
        |                               |--- SAML Response (signed) --->|
        |                               |                               |
        |<-- Session established -------|------------------------------>|
```

**AuthnRequest (decoded):**
```xml
<samlp:AuthnRequest
  AssertionConsumerServiceURL='https://mitgestalten.wien.gv.at/auth/vienna_citizen/callback'
  Destination='https://mein.wien.gv.at/stdportal-idp/extern.wien.gv.at/profile/SAML2/Redirect/SSO'
  Version='2.0'>
  <saml:Issuer>CitizenLabWien</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate='true'
    Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'/>
</samlp:AuthnRequest>
```

### SAML Attack Surface Tested

The following attacks were attempted against the SAML implementation:

| **Attack** | **Result** | **Notes** |
|------------|------------|-----------|
| Unsigned assertion submission | ❌ Rejected | Signature validation enforced |
| XML Signature Wrapping (XSW) | ❌ Rejected | Properly implemented |
| Signature stripping | ❌ Rejected | Required by SP |
| Assertion replay | ❌ Rejected | InResponseTo validated |
| XXE in SAML XML | ❌ Rejected | Parser hardened |
| Attribute manipulation | ❌ Rejected | Signature covers attributes |
| Cross-service assertion replay | ❌ Rejected | Audience restriction enforced |

The SAML implementation was found to be **cryptographically sound**, using RSA-SHA256 signatures and proper assertion validation. No authentication bypass was achieved.

---

## Validated Vulnerabilities

### Finding 1: Internal IP Address Disclosure in SAML Responses

**Severity:** P5 — Informational  
**Category:** Server Security Misconfiguration > Fingerprinting/Banner Disclosure  
**CWE:** CWE-200 — Exposure of Sensitive Information  
**Status:** Accepted by Triage

#### Technical Detail

SAML authentication responses transmitted during the citizen login flow included the internal IP address of the authentication server embedded in two XML attributes:

```xml
<saml2:SubjectConfirmationData
  Address="10.106.223.30"
  InResponseTo="_bf333de1-7c3d-4663-a4a8-877b5bab7502"
  NotOnOrAfter="2026-02-09T00:16:53.858Z"
  Recipient="https://mitgestalten.wien.gv.at/auth/vienna_citizen/callback" />

<saml2:SubjectLocality Address="10.106.223.30" />
```

#### Impact Analysis

In isolation, this finding has limited direct exploitability. An external attacker cannot reach `10.106.223.30` from the public internet. However, it becomes a **critical component of a server-side request forgery (SSRF) attack chain:**

```
Attacker discovers internal IP via SAML disclosure
        +
Attacker identifies SSRF vulnerability on any wien.gv.at property
        =
Attacker routes requests to internal network using server as proxy
```

Without the SSRF primitive, this finding remains informational. The value lies in establishing that the internal subnet `10.106.x.x` hosts authentication services.

#### Lesson

Information disclosure findings must be framed in terms of their **combinatorial potential**, not their standalone impact. Triage handlers ask: *"As an attacker, I could..."* — the answer must be a concrete next step, not a theoretical risk.

---

### Finding 2: API Authorization Token Disclosure in Error Responses

**Severity:** P5 — Informational  
**Category:** Server Security Misconfiguration > Fingerprinting/Banner Disclosure  
**CWE:** CWE-209 — Error Message Containing Sensitive Information  
**Status:** Accepted by Triage

#### Technical Detail

When the registration endpoint receives malformed input, the error response includes the complete outbound request details — including the authorization header used to communicate with the backend API:

**Trigger Request:**
```http
PUT /broker/public/api/Account/RegisterAccount?branding= HTTP/1.1
Host: mein.wien.gv.at
Content-Type: application/json

{"authId":1,"eMail":"test@example.com","passwort":"Test123$","userName":"#"}
```

**Response (404):**
```json
{
  "response": {
    "requestMessage": {
      "requestUri": "https://stp.wien.gv.at:4543/restapi/v1/otfu/#",
      "headers": [{
        "key": "API-Authorization",
        "value": ["eVkI9XW9qUy2Ss_HYE6DVwBSfo-Iy62UGO74EXp4EfkA"]
      }]
    }
  }
}
```

#### Compensating Control

Direct access to the backend API was attempted and blocked by mutual TLS:

```http
HTTP/1.1 403 Access Denied
Content-Type: text/html

Error: Access is Denied. Client SSL Certificate Required.
```

The mTLS requirement prevents immediate exploitation of the exposed token. However, this is a **defense-in-depth failure** — if mTLS is misconfigured or bypassed (e.g., via SSRF), the token provides ready-made credentials for internal API access.

#### Lesson

When a compensating control blocks exploitation, document it explicitly. It demonstrates thorough testing, justifies the lower severity, and shows reviewers exactly why the risk is contained — while preserving the finding's validity.

---

### Finding 3: Internal Infrastructure Disclosure via Verbose Error Messages

**Severity:** P5 — Informational  
**Category:** Server Security Misconfiguration > Fingerprinting/Banner Disclosure  
**CWE:** CWE-209 — Error Message Containing Sensitive Information  
**Status:** Accepted by Triage

#### Technical Detail

Multiple error conditions on the registration endpoint returned detailed technical information revealing internal system architecture:

**Exposed Data Points:**

| **Data** | **Value** | **Source** |
|----------|-----------|------------|
| Internal hostname | `lxwhale1.host.magwien.gv.at` | 404 error body |
| Backend API endpoint | `https://stp.wien.gv.at:4543/restapi/v1/otfu/` | 404 error body |
| Internal domain | `magwien.gv.at` | Error URL |
| Backend runtime | `.NET (System.Guid)` | 500 error body |
| API field names | `datensatz` | Validation error |

**Example (hostname and endpoint disclosure):**
```json
{
  "content": "Error: 404 Not Found. Sorry, the requested URL
  'http://stp.wien.gv.at:4543, lxwhale1.host.magwien.gv.at/restapi/v1/otfu/'
  caused an error: Not found: '/v1/otfu/'"
}
```

**Example (implementation detail disclosure):**
```json
{
  "message": "Error converting value \"01084b67-0862-437a332-90af-073293da5b0f\"
  to type 'System.Guid'. Path 'datensatz', line 1, position 54."
}
```

#### Collective Impact

Individually, each error message is low value. Collectively, they provide an attacker with:

1. The internal hostname of the backend server
2. The exact API endpoint structure
3. The authorization token to authenticate against it (Finding 2)
4. The internal network segment hosting it (Finding 1)

This is a **reconnaissance package** — everything needed to target the internal API if a request forgery primitive is found.

---

### Finding 4: Example Metadata Warning in Production Shibboleth Configuration

**Severity:** P5 — Informational  
**Category:** Server Security Misconfiguration > Fingerprinting/Banner Disclosure  
**CWE:** CWE-1188 — Insecure Default Initialization  
**Status:** Accepted by Triage

#### Technical Detail

The Shibboleth service provider metadata, publicly accessible at `https://shib.wien.gv.at/Shibboleth.sso/Metadata`, contained a comment from the default example configuration:

```xml
<!--
This is example metadata only. Do *NOT* supply it as is without review,
and do *NOT* provide it in real time to your partners.
-->
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="https://shib.wien.gv.at/shibboleth">
```

The presence of this comment in production suggests the metadata file may have been deployed from default templates without full review.

---

## Security Controls Assessment

A key output of any honest security assessment is acknowledging what the organization is doing well. The following controls were found to be properly implemented:

### Authentication and Cryptography
✅ SAML responses signed with RSA-SHA256  
✅ Signature validation enforced on all assertions  
✅ Audience restriction properly configured  
✅ InResponseTo correlation validated (replay prevention)  
✅ Backend API protected by mutual TLS  

### Infrastructure
✅ No subdomain takeover vulnerabilities (8 Azure Front Door CNAMEs verified)  
✅ Internal portals properly restricted (Azure AD, OIDC)  
✅ Apache CVEs not exploitable in current configuration  
✅ Liferay JSON-WS API properly restricted (403)  
✅ ViewState MAC validation enabled on ASP.NET applications  

### Security Headers
✅ HSTS (max-age=31536000, includeSubdomains)  
✅ X-Content-Type-Options: nosniff  
✅ X-XSS-Protection: 1; mode=block  
✅ Content-Security-Policy implemented  

### Access Controls
✅ Debug endpoints disabled (trace.axd, elmah.axd)  
✅ Configuration files not exposed  
✅ Custom error pages enabled on most applications  

---

## The Attack Chain Concept

The most important insight from this engagement is the relationship between individually low-severity findings and their collective potential.

### What Was Found (Each Finding in Isolation)

```
Finding 1: Internal IP address in SAML response     → P5
Finding 2: API token in error response              → P5
Finding 3: Internal hostname and endpoint in errors → P5
Finding 4: Default metadata comment                 → P5
```

### What They Enable Together

```
Step 1  [Finding 3] → Identify internal API endpoint
                      stp.wien.gv.at:4543/restapi/v1/

Step 2  [Finding 2] → Obtain authorization token for that API
                      API-Authorization: eVkI9XW9qUy2Ss_...

Step 3  [Finding 1] → Confirm internal network segment
                      10.106.x.x subnet hosts auth services

Step 4  [Unknown]   → Find SSRF on any wien.gv.at property

Step 5  [Combined]  → Route authenticated requests to internal API
                      through the SSRF vector using the leaked token
                      → Potential: Internal data access, auth bypass
                      → Severity: Critical
```

### The Gap

This chain was not completed during the assessment. No SSRF vulnerability was identified on the tested applications. Without the SSRF primitive, the chain cannot be closed and the findings remain informational.

**This is the core lesson:** information disclosure findings are latent vulnerabilities. Their severity is determined by what else an attacker can find alongside them.

---

## Triage Outcome and Reflection

All four findings were accepted by the Bugcrowd triage team and classified as **P5 — Informational** under the category **Server Security Misconfiguration > Fingerprinting/Banner Disclosure**.

The triage handler noted:

> *"Each submission should aim to answer the question 'as an attacker, I could...'"*

The findings were accepted as valid but classified as acceptable risk for the organization given the absence of a demonstrated exploit path.

### What This Means in Practice

The findings were not wrong — they were incomplete. The difference between P5 and P3 in this context was not the *existence* of the vulnerabilities but the *demonstrated impact*:

| **Submission Quality** | **Likely Outcome** |
|------------------------|-------------------|
| "Internal IP is disclosed" | P5 Informational |
| "Internal IP is disclosed, combined with exposed API token, an attacker with SSRF access could reach the internal API authenticated" | P3 Medium |
| "Internal IP is disclosed. I found SSRF on X endpoint. I used it to reach the internal API with the leaked token and retrieved [data]" | P1/P2 Critical/High |

The gap is impact demonstration, not finding identification.

---

## Recommendations

The following recommendations were provided to the City of Vienna:

### Immediate (30 Days)
1. **Remove internal IP addresses from SAML responses** — Strip the `Address` attribute from `SubjectConfirmationData` and `SubjectLocality` elements, or replace with public-facing values
2. **Sanitize error responses** — Remove authorization headers and internal endpoint details from public error messages. Log detailed errors server-side only

### Short-Term (60 Days)
3. **Implement generic API error responses** — Replace verbose .NET error messages with user-friendly generic messages
4. **Review Shibboleth metadata** — Remove example configuration comments and conduct a full metadata security review

### Strategic (90+ Days)
5. **Conduct SSRF audit** — Given the exposed internal infrastructure details, test all URL-accepting parameters across the estate for SSRF vulnerability
6. **Implement error message scanning** — Add automated checks to CI/CD pipeline to detect sensitive information in error responses before deployment

---

## Key Takeaways for Security Teams

### 1. Information Disclosure is a Force Multiplier
A single piece of leaked information is rarely exploitable. A collection of leaked information — internal IPs, hostnames, API endpoints, authorization tokens — becomes a reconnaissance package that dramatically reduces the effort required for a targeted attack.

### 2. Defense-in-Depth Gaps Are Still Gaps
The backend API was properly protected by mutual TLS. This prevented immediate exploitation of the leaked token. However, if mTLS is ever misconfigured, removed, or bypassed via SSRF, the token exposure immediately becomes critical. Compensating controls do not eliminate risk — they defer it.

### 3. Error Messages Are a Free Recon Tool
Every verbose error message is a gift to an attacker. Internal hostnames, endpoint paths, field names, data types, and framework versions — all of these reduce the time and effort required to map an attack surface. Generic error messages are one of the cheapest security improvements an organization can make.

### 4. Chaining Matters More Than Finding
Security researchers and internal teams should think in terms of attack chains, not individual findings. A P5 finding combined with another P5 finding and a P4 finding can constitute a P1 attack chain. Vulnerability management programs should account for this.

---

## About This Research

This assessment was conducted as part of an ongoing independent application security research practice focused on responsible disclosure and helping organizations understand real-world security risks.

All testing was conducted:
- Within the authorized scope of the City of Vienna's Bugcrowd managed bug bounty program
- Using accounts created specifically for testing purposes
- Without accessing, modifying, or exfiltrating any user data
- In accordance with responsible disclosure principles

Findings were submitted through the Bugcrowd platform and triaged by the program's security team.

---

*Published as part of an independent security research case study series.*  
*Organization details shared with explicit program authorization via Bugcrowd's public bug bounty platform.*
