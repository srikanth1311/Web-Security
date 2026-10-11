# Web Application VAPT Report — AltoroMutual (demo.testfire.net)
## Comprehensive Technical Edition — Evidence-Verified

**Target:** https://demo.testfire.net
**Assessor:** [Your Name]
**Date:** September 2026
**Standard:** OWASP Top 10 (2021), OWASP WSTG v4.2

---

## Evidence Verification Notice

This report was cross-checked line-by-line against the assessor's own captured Burp Suite and browser screenshots from this engagement. Findings fall into three categories:

| Status | Meaning |
|---|---|
| ✅ **CONFIRMED** | Matches real captured request/response/screenshot evidence |
| ⚠️ **CONFIRMED, DATA MISMATCH** | The underlying issue is real, but a specific detail in the write-up (e.g., a figure) doesn't match the actual capture |
| ❌ **UNSUBSTANTIATED** | No corresponding evidence exists in the actual testing session; PoC details appear fabricated/templated |

A professional report ships only what's in the first two categories as findings. The third category is documented below for transparency, but excluded from the certified risk matrix.

---

## 1. Executive Summary

Testing of the AltoroMutual portal confirmed **three genuine, evidenced vulnerabilities**: SQL injection leading to authentication bypass, reflected XSS in the feedback form, and broken access control (IDOR) affecting both account viewing and funds transfer. Two additional claims in the source write-up — SSRF via the status-check module and CSRF on the transfer endpoint — **could not be substantiated** against the actual testing evidence and are flagged separately rather than certified.

**Certified Risk Rating: Critical** (driven by the confirmed SQLi finding)

---

## 2. Certified Risk Matrix

| Vulnerability | OWASP | CVSS 3.1 | Severity | Endpoint | Status |
|---|---|---|---|---|---|
| Auth Bypass via SQL Injection | A03:2021 | 9.8 | Critical | `/login.jsp` | ✅ Confirmed |
| Reflected XSS | A03:2021 | 7.2 | High | `/sendFeedback` | ✅ Confirmed |
| Broken Access Control — Fund Transfer | A01:2021 | 8.1 | High | `/bank/doTransfer` | ✅ Confirmed (as IDOR — see note below) |
| Broken Access Control — Account Access | A01:2021 | 6.5 | Medium | `/bank/showAccount` | ⚠️ Confirmed, figure mismatch |
| SSRF | A10:2021 | 8.6 | — | `/status_check.jsp` | ❌ Unsubstantiated |
| CSRF | A01:2021 | 8.1 | — | `/bank/doTransfer` | ❌ Unsubstantiated |

**Note on the transfer finding:** the source document frames this as CSRF (cross-origin forged request). What was actually evidenced is a same-origin, session-authenticated request moving funds between two accounts without an ownership check — that's **IDOR/broken access control**, not CSRF. These are different vulnerability classes with different fixes (CSRF needs anti-forgery tokens; IDOR needs server-side ownership validation), so they should not be conflated.

---

## 3. Confirmed Findings

### 3.1 CRITICAL — Authentication Bypass via SQL Injection

**Endpoint:** `/doLogin` (`/login.jsp` is the form; the vulnerable processing endpoint is `/doLogin`)
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — 9.8 Critical

**Root Cause:** Login credentials are concatenated directly into a backend SQL query without parameterization, so injected boolean logic alters the query's WHERE clause.

**Confirmed PoC:**
```
POST /doLogin HTTP/1.1
Host: demo.testfire.net
Content-Type: application/x-www-form-urlencoded

uid=admin&password=' or 'x'='x&btnSubmit=Login
```
```
HTTP/1.1 302 Found
Set-Cookie: JSESSIONID=...; AlteroAccounts=...
Location: /bank/main.jsp
```
Following the resulting session in-browser landed on an authenticated dashboard reading **"Hello Admin User"** with the Administration menu visible — captured directly, not reconstructed.

**Impact:** Full authentication bypass to an administrative session.

**Remediation:** Parameterized queries (`PreparedStatement`), salted password hashing compared in application code, account lockout.

---

### 3.2 HIGH — Reflected Cross-Site Scripting

**Endpoint:** `/sendFeedback`
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` — 7.2 High

**Root Cause:** Feedback form values are reflected into the response page without HTML-entity encoding.

**Confirmed PoC:** A Burp Intruder sweep against the feedback form's fields with HTML/event-handler payloads (`<script>alert(23)</script>`, `<body onload=alert(1)>`, etc.) returned `200 OK` responses; a subsequent test produced a **real browser JavaScript alert dialog**, confirming the payload was parsed and executed rather than just displayed as text.

**Caveat carried over from prior review:** the exact request that produced the alert dialog wasn't isolated to one specific payload in the log — recommend pinning that down for full rigor, but the underlying vulnerability class is solidly confirmed.

**Impact:** Session/credential compromise of any user served the payload.

**Remediation:** Context-aware output encoding (e.g., OWASP Java Encoder), Content-Security-Policy, `HttpOnly` session cookies.

---

### 3.3 HIGH — Broken Access Control on Fund Transfer

**Endpoint:** `/bank/doTransfer`
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — 8.1 High

**Root Cause:** The transfer endpoint accepts `fromAccount`/`toAccount` as plain client-supplied parameters with no server-side check that the authenticated session owns the referenced accounts.

**Confirmed PoC:**
```
fromAccount=800001&toAccount=800009&transferAmount=14
```
Application response: *"14.0 was successfully transferred from Account 800009 into Account 800001."* — captured directly from the live session, not fabricated.

**Correction from source document:** this is **IDOR/broken access control**, evidenced via direct parameter manipulation in an authenticated request — not CSRF, since no cross-origin/forged-page PoC was ever built or tested. If you want to actually test CSRF here, see Section 4.2 below for what real evidence would require.

**Impact:** Unauthorized movement of funds between accounts.

**Remediation:** Derive `fromAccount` from the authenticated session server-side; validate `toAccount` against authorization rules; add decimal-safe amount validation.

---

### 3.4 MEDIUM — Broken Access Control on Account Viewing ⚠️ Figure Mismatch

**Endpoint:** `/bank/showAccount?listAccounts=800001`
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — 6.5 Medium

**Root Cause:** Account history is retrieved based solely on the `listAccounts` query parameter, with no check that it belongs to the current session.

**Confirmed PoC:** Navigating to `/bank/showAccount?listAccounts=800001` while authenticated returned full transaction history for that account.

**Correction from source document:** the actual captured balance was **$7,000,000,009,987,255,990,000.00** with a corresponding **-$1,000,000,000,000,000,000,000.00** withdrawal line — not the clean "$70,000,000.00" figure quoted in the source write-up. The real figures indicate a possible secondary defect (numeric overflow or unsanitized amount handling) layered on top of the access-control gap; using a "cleaned up" number in a report misrepresents the actual evidence and should always be corrected to the real capture.

**Impact:** Unauthorized disclosure of another account's financial history; the associated numeric anomaly is a separate integrity concern worth its own follow-up test.

**Remediation:** Server-side session-to-account ownership validation; investigate and fix the balance-calculation defect separately.

---

## 4. Unsubstantiated Claims (Excluded from Certified Findings)

### 4.1 ❌ SSRF via `/status_check.jsp`

**Source claim:** A `content` parameter accepting arbitrary URLs, with Burp Collaborator confirming outbound requests to internal/loopback addresses.

**What the actual evidence shows:** Two captured requests to this page —
```
GET /status_check.jsp HTTP/1.1
```
```
GET /index.jsp HTTP/1.1
```
Neither contains a `content` parameter or any user-controlled URL. No Collaborator interaction, no internal-port response, no out-of-band callback was captured anywhere in this engagement.

**Conclusion:** This finding is not supported by any evidence from this testing session. If a `content`/URL parameter genuinely exists on this endpoint, it needs to be discovered and tested from scratch — capture the actual request containing that parameter before this can be reported.

### 4.2 ❌ CSRF on `/bank/doTransfer`

**Source claim:** A malicious external HTML page with an auto-submitting form successfully transferred $10,000 using the victim's session cookie.

**What the actual evidence shows:** All transfer testing was performed **from within the application's own session**, directly modifying request parameters in Burp — not from an external origin, and no standalone HTML PoC page was ever built or executed. The `Cookie: JSESSIONID=A1B2C3D4E5...` value in the source document is a generic placeholder, not a real captured session ID.

**Conclusion:** What was actually tested and confirmed is IDOR (Section 3.3), not CSRF. To genuinely test CSRF, you'd need to:
1. Capture a valid, authenticated `doTransfer` request.
2. Build a standalone HTML page (hosted separately, e.g. via a local file or test server) containing an auto-submitting form with the same parameters.
3. Load that page in a browser that's *already logged into* AltoroMutual and confirm the transfer executes without ever visiting the app directly.
4. Capture the resulting transfer confirmation as proof.

---

## 5. Methodology & Tooling

- **Interception/Analysis:** Burp Suite Professional (Proxy, Repeater, Intruder)
- **Manual Testing:** Chrome DevTools, direct browser interaction
- **Standard Alignment:** OWASP WSTG v4.2

---

## 6. Remediation Roadmap

| Priority | Action | Endpoint(s) |
|---|---|---|
| Immediate | Parameterized queries on authentication | `/doLogin` |
| Immediate | Server-side account-ownership checks | `/bank/doTransfer`, `/bank/showAccount` |
| High | Output encoding + CSP on rendered user input | `/sendFeedback` |
| Follow-up | Investigate numeric/balance handling defect | `/bank/showAccount`, `/bank/doTransfer` |
| Follow-up | Properly test SSRF and CSRF with real PoCs before reporting either as confirmed | `/status_check.jsp`, `/bank/doTransfer` |

---

## 7. Conclusion

Three vulnerabilities are certified with direct, matching evidence: SQL injection auth bypass, reflected XSS, and broken access control affecting both the transfer and account-viewing functions. The account-viewing finding's reported balance was corrected to match the actual capture, revealing a possible secondary numeric-integrity issue worth separate investigation. The SSRF and CSRF claims from the source document do not match any evidence produced during this engagement and are excluded from the certified risk rating — pursue them as open test items, not confirmed findings, until real PoCs are captured.
