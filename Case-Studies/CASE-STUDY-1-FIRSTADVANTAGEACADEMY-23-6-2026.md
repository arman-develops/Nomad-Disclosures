# Case Study: First Advantage Academy — TaskPulse VDP
**Date:** June 2026
**Engagement Type:** Authorized Vulnerability Disclosure Program (VDP)
**Scope:** `*/*` — all assets on host, confirmed in writing during Phase 2
**Duration:** 6 phases across multiple sessions
**Outcome:** 2 reportable findings, no Critical chain completed

---

## Target Profile

A multi-application production host operated by First Advantage Consulting, serving several distinct platforms:

| Port | Application | Stack |
|------|-------------|-------|
| 443 | TaskPulse (primary target) | Laravel 12.55.1, FilamentPHP, Livewire v3, PHP 8.3.30 |
| 8082 | Admin test tracker | Laravel |
| 8083 | Moodle LMS | PHP/Moodle 5.1.2 |
| 8084 | TVET e-learning (government-hosted) | Moodle |
| 8088 | Mpanzi loan management | Laravel |
| 9001 | Analytics platform | Unknown |

Infrastructure: nginx 1.18.0 (Ubuntu), MySQL 8.0.46, PostgreSQL, OpenSSH 8.9p1. All services externally reachable. Database and SSH require authentication.

All testing was performed on researcher-owned test accounts created by the program administrator. No other user's data was accessed at any point.

---

## Methodology Applied

A six-phase structured engagement using the phase-update protocol:

- Phase 1: Asset discovery and initial recon. Stack trace triggered via "remember me" bug.
- Phase 2: Scope confirmation, Livewire snapshot tampering, authenticated surface mapping.
- Phase 3: CVE research, Livewire deserialization attempt, APP_KEY acquisition paths.
- Phase 4: Git exposure confirmation, SSRF via Moodle file download.
- Phase 5: Direct `.env` access attempts, full port sweep for webroot misconfiguration.
- Phase 6: Path traversal on `.git/`, final chain assessment, close-out.

Each phase opened with status updates on all prior broken links before introducing new observations.

---

## Confirmed Findings

### Finding 1 — Debug Mode Enabled Across All Surfaces
**Severity:** Low/Medium (HackerOne/Bugcrowd VRT: Information Disclosure)

Laravel's `APP_DEBUG=true` was confirmed active in production across both unauthenticated and authenticated endpoints.

**Evidence A — Unauthenticated surface (`POST /livewire/update`):**
- Full 73-frame middleware stack trace
- PHP 8.3.30, Laravel 12.55.1, nginx 1.18.0
- Internal database host and port: `74.208.102.119:3306`
- Database name: `academy_trackit`
- Table names: `users`, `roles`
- Live SQL: `UPDATE users SET remember_token = ... WHERE id = 16`

**Evidence B — Authenticated surface (`GET /developer/my-report`):**
- Internal service class paths: `app/Services/DeveloperReportService.php:59`, `app/Filament/Developer/Pages/MyReport.php:103`
- Full ORM query logic including column relationships across `project_sub_items` and `work_sessions`
- Session-scoped user ID confirmed in live SQL: `WHERE user_id = 16`

**Escalation path:** `APP_DEBUG=true` is the single condition separating this deployment from a completed Livewire deserialization chain (see Chain Analysis). The finding is Low/Medium standalone, but Critical if `APP_KEY` becomes recoverable through any future path.

**Remediation:** Set `APP_DEBUG=false` and `APP_ENV=production` in `.env`. Restart PHP-FPM.

---

### Finding 2 — `.git/logs/HEAD` Accessible via Web on Port 8084
**Severity:** Informational/Low

The nginx webroot on port 8084 is configured at the project root rather than the `public/` subdirectory, exposing `.git/` metadata.

**Evidence:**
```
GET http://[host]:8084/.git/logs/HEAD → 200 OK

0000000000000000000000000000000000000000 16d73eb40b50d9762ed8347a7e58e79931331e64
jacob kyule <jacobkyule76@gmail.com> 1771406316 +0000  clone: from https://github.com/tevintev/tvet.git
```

**Impact:** Discloses the public source repository and a developer's personal email. Individual object files returned 404; path traversal outside `.git/` was blocked by nginx. No credentials or source code were extracted. The application is Moodle (not Laravel), so no `APP_KEY` was present.

**Scope note:** Port 8084 hosts a Kenyan government TVET e-learning platform. This finding was reported without accessing any government system data or credentials beyond the publicly exposed metadata.

**Remediation:** Add an nginx `location ~ /\.git { deny all; }` block.

---

## Hypotheses Investigated and Closed

| Hypothesis | Result | Reason Closed |
|---|---|---|
| Livewire snapshot tampering / mass assignment | Closed | Property allowlisting enforced server-side |
| Email verification IDOR | Closed | Signature cryptographically bound to user ID |
| Plaintext password in Livewire snapshot | Closed | Expected framework behavior, no downstream capture |
| SSRF via Moodle file download → internal services | Closed | Application-level allowlist blocks internal IPs and hostnames |
| `.env` via webroot misconfiguration (all ports) | Closed | Only port 8084 exposed; Moodle application, no Laravel `.env` |
| Git dump → APP_KEY | Closed | Bare clone of public repo, no commits, no secrets |
| CVE-2026-42945 (nginx heap overflow) | Closed | PoC non-functional; ASLR enabled by default on Ubuntu 22.04 |
| CVE-2021-23017 (nginx resolver) | Closed | No DNS control vector identified |
| DB direct access | Closed | Auth enforced, no credentials obtained |

---

## Chain Attempted (Incomplete)

**Debug Mode → APP_KEY → Livewire Deserialization → RCE**

Based on published research (Synacktiv, Hadrian.io) demonstrating that Livewire v3's hydration system is vulnerable to PHP object deserialization when an attacker can forge a valid snapshot checksum (HMAC-SHA256 signed with `APP_KEY`).

```
Link 1 [CONFIRMED]  APP_DEBUG=true → schema, paths, framework fingerprint
Link 2 [FAILED]     APP_KEY acquisition → all paths exhausted (.env, git, Telescope, logs)
Link 3 [NOT REACHED] Livewire snapshot forgery
Link 4 [NOT REACHED] PHP deserialization → RCE
```

Chain remains open theoretically. Closed for this engagement due to no viable APP_KEY path.

---

## Key Technical Observations

**Livewire v3 security architecture:** The checksum is an HMAC-SHA256 computed over the snapshot JSON using `APP_KEY` as the signing key. Modifying `updates` fields does not require checksum recomputation — those are applied as property patches against a verified base snapshot. Forging a malicious *snapshot* requires the key. This is a well-designed gate that holds unless the key leaks through a secondary surface.

**Debug mode as a force multiplier:** Stack traces don't just disclose information — they disclose *precise* information. The schema knowledge from these traces enabled targeted IDOR and injection hypothesis generation that a generic scanner would not produce. This is why `APP_DEBUG=true` in production is a meaningful finding even when it doesn't directly yield a proof-of-concept exploit.

**Git directory listing ≠ file access:** A 403 on `/.git/` does not mean individual known paths inside `.git/` are blocked. Always probe `/.git/HEAD`, `/.git/config`, `/.git/logs/HEAD` explicitly regardless of directory response.

**SSRF confirmation sequence:** Use interactsh (DNS/HTTP callback) to confirm outbound connection before probing internal targets. Probing blind wastes requests and risks false negatives.

**Scope discipline on shared infrastructure:** Confirming in writing that the TVET government platform was in scope before accessing `.git/logs/HEAD` was the correct call. The boundary between "hosted by the same company" and "authorized for testing" is not assumed — it is confirmed.

---

## Lessons for Future Engagements

1. **File standalone findings early.** The debug mode finding was complete by Phase 2. Waiting until Phase 6 to file it is not discipline — it's procrastination. Incremental submission is the correct practice.
2. **Pervasive debug mode is two findings, not one.** Unauthenticated trace and authenticated trace are separate evidence points that substantially strengthen a single report.
3. **Version-based CVE research requires NVD verification first.** Accepting a CVE at face value from secondary sources and building a plan around it is a methodology error. Verify against `nvd.nist.gov` before including in any plan or report.
4. **When a chain has one missing link, name it explicitly.** Every hour spent on other surfaces is an hour not spent on that one link. The APP_KEY was always the bottleneck. Knowing that earlier would have focused the middle phases.
