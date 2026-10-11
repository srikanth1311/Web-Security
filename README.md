# Web Application VAPT — Vulnerability Assessment & Penetration Test

**Type:** Web Application Security Assessment
**Tooling:** Burp Suite, manual testing
**Report:** [`VAPT_Report.pdf`](./VAPT_Report.pdf) | [`VAPT_Verified.md`](./VAPT_Verified.md)

---

## Summary

This assessment targeted a web application and identified multiple vulnerabilities across authentication, input validation, and access control layers — including SQL injection on the admin login, stored/reflected XSS, HTML injection, parameter tampering, IDOR, and a security misconfiguration. Each finding below includes before/after evidence captured via Burp Suite and manual verification.

---

## Findings

| # | Vulnerability | Area | Evidence |
|---|---|---|---|
| 1 | SQL Injection — admin login bypass | Authentication | `screenshots/sql-injection-admin-login-before.png`, `-after.png`, `-success.png` |
| 2 | Security Misconfiguration | Server/App config | `screenshots/security-misconfig-before.png`, `-after.png`, `-after-output.png` |
| 3 | Parameter Tampering | Input validation | `screenshots/parameter-intercept.png`, `parameter-tampering.png`, `parameter-tampering-success.png` |
| 4 | Cross-Site Scripting (XSS) | Input validation | `screenshots/xss.png`, `xss-burp.png` |
| 5 | HTML Injection | Input validation | `screenshots/html-injection.png`, `html-injection-burp.png` |
| 6 | Insecure Direct Object Reference (IDOR) | Access control | `screenshots/idor-before.png` |

---

## Methodology

1. **Reconnaissance** — mapped application endpoints, input fields, and parameters using Burp Suite's proxy/spider.
2. **Authentication Testing** — tested the admin login form for SQL injection using crafted payloads; confirmed bypass.
3. **Input Validation Testing** — tested all user-input fields for reflected/stored XSS and HTML injection.
4. **Parameter Manipulation** — intercepted and modified request parameters in Burp Suite to test for tampering vulnerabilities.
5. **Access Control Testing** — tested for IDOR by modifying object/user identifiers in requests.
6. **Configuration Review** — identified a security misconfiguration and verified its impact.

---

## Disclaimer

This assessment was performed in an authorized testing environment. All screenshots and findings are documented for educational/portfolio purposes only. Do not run any of these techniques against applications you do not own or have explicit written authorization to test.

## Files

- `VAPT_Report.pdf` — full formatted report
- `VAPT_Verified.md` — verified findings notes
- `screenshots/` — evidence for each finding (before/after/success states)
