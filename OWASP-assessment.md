# OWASP Top 10 Security Assessment Report

## Incident Management REST API

## 1. Introduction

This document provides a comprehensive security evaluation of the **Incident Management REST API**, developed using **Flask**, **Flask-RESTful**, **SQLAlchemy ORM**, and **PostgreSQL**, in alignment with the **OWASP Top 10 (2021)** categories.

The assessment includes:

* **Automated security tests via Postman Collections**
* **Manual security verification via code review**
* **Database inspection and environment configuration checks**
* **Categorization of findings per OWASP Top 10 standard**

---

## 2. API Summary

### Core Endpoints

| Method | Path                     | Description                                                     |
| ------ | ------------------------ | --------------------------------------------------------------- |
| POST   | `/auth/login`            | Authenticate user, get token                                    |
| POST   | `/auth/register`         | Create new account (admin-only, controlled via env credentials) |
| GET    | `/incidents`             | List all incidents                                              |
| POST   | `/incidents`             | Create a new incident                                           |
| GET    | `/incidents/<id>`        | Retrieve incident details                                       |
| PATCH  | `/incidents/<id>/status` | Update incident status                                          |

### Security Features Implemented

* Token-based authentication (Bearer token)
* Password hashing (`generate_password_hash`)
* Environment-based secrets (`.env`)
* Input validation (severity, title length, IP address)
* ORM preventing SQL injection
* Expiring tokens & cleanup
* Size-limited requests
* Strict JSON-only requests

---

## 3. OWASP Top 10 2021 Evaluation Summary

| Category                                           | Status     | Verified By      | Notes                                       |
| -------------------------------------------------- | ---------- | ---------------- | ------------------------------------------- |
| **A01 – Broken Access Control**                    | ✔ PASS     | Postman + Manual | All protected endpoints require valid token |
| **A02 – Cryptographic Failures**                   | ✔ PASS     | Manual           | Passwords hashed, no plaintext secrets      |
| **A03 – Injection**                                | ✔ PASS     | Postman + Manual | SQLi attempts fail; ORM safe                |
| **A04 – Insecure Design**                          | 🟡 Partial | Manual           | No RBAC or rate limiting yet                |
| **A05 – Security Misconfiguration**                | ✔ PASS     | Postman + Manual | Invalid JSON → 400; no stack traces         |
| **A06 – Vulnerable Components**                    | 🟡 Partial | Manual           | Requirements pinned; recommend pip-audit    |
| **A07 – Identification & Authentication Failures** | ✔ PASS     | Postman + Manual | Strong password policy, no enumeration      |
| **A08 – Software & Data Integrity Failures**       | N/A        | Manual           | No plugins/remote code loading              |
| **A09 – Security Logging & Monitoring Failures**   | 🟡 Partial | Manual           | Logging not implemented yet                 |
| **A10 – SSRF**                                     | N/A        | Manual           | API does not fetch external URLs            |

---

## 4. Detailed Assessment per Category

## A01 – Broken Access Control

### ✔ **Status: PASS**

### What was tested

1. Calling `/incidents` with:

   * **No Authorization header** → Response: `401 Unauthorized`
   * **Invalid token** → Response: `401 Unauthorized`
   * **Expired token** → Response: `401 Unauthorized`
2. Token extraction verified manually through:

   * `require_auth()` logic

### Evidence (Postman Response Example)

```
{
  "message": "Missing or invalid Authorization header."
}
```

### Assessment

* ✔ All protected endpoints enforce token checks
* ✔ No incident data can be accessed anonymously
* ✔ No privilege escalation issues found

---

## A02 – Cryptographic Failures

### ✔ **Status: PASS (Manual Verification)**

### Verified

* Passwords stored using:

  ```
  generate_password_hash(password)
  ```

  → Uses PBKDF2 hashing (OWASP-compliant)
* Tokens are random UUID4 hex strings stored server-side
* Environment variables used:

  * `SECRET_KEY`
  * `INITIAL_ADMIN_PASSWORD`
  * `DATABASE_URL`

### Production Recommendation

> Deploy behind HTTPS (TLS) to avoid MITM attacks.

---

## A03 – Injection

### ✔ **Status: PASS**

### SQL Injection Test Examples

**Login with SQLi username:**

```json
{
  "username": "admin' OR '1'='1",
  "password": "anything"
}
```

→ Response: `401 Invalid credentials`

**Incident title with SQLi payload:**

```json
"title": "DROP TABLE incidents; --"
```

→ Stored as text, not executed.

### Why it’s safe

* SQLAlchemy uses parameterized queries
* No dynamic SQL
* Input validation eliminates malformed data
* No eval/exec used

---

## A04 – Insecure Design

### 🟡 **Status: PARTIAL**

### Strengths

* Strong password policy (uppercase, lowercase, digit, special char)
* Token expiration enforced
* Strict JSON parsing
* Input validation for:

  * Title length
  * Severity enum
  * Source IP

### Limitations (Future Enhancements)

* ❌ No rate limiting (brute force)
* ❌ No multi-role RBAC
* ❌ No audit log history for incident modifications
* ❌ No session anomaly detection

These are normal limitations for a student project.

---

## A05 – Security Misconfiguration

### ✔ **Status: PASS**

### Tests performed

* Invalid JSON → `400 Bad Request`
* Wrong content type → `400`
* Disabled debug mode in production (`FLASK_DEBUG=0`)
* File upload limit (1MB) enforced via:

  ```
  MAX_CONTENT_LENGTH_BYTES
  ```
* No framework internals leaked in error messages

### Example Evidence

```
{
  "error": "Invalid JSON"
}
```

---

## A06 – Vulnerable and Outdated Components

### 🟡 **Status: PARTIAL**

### Verified:

* All dependencies are pinned in `requirements.txt`
* No deprecated libraries identified manually

### Recommendation:

```
pip install pip-audit
pip-audit
```

or
Enable **GitHub Dependabot** for ongoing monitoring.

---

## A07 – Identification & Authentication Failures

### ✔ **Status: PASS**

### Tests performed

* Wrong password → `401`
* Weak password in registration → `400`
* Password mismatch → `400`
* SQLi-like login → `401`
* Tokens stored with expiration → validated correctly

### Manual checks

* No username enumeration:

  * Wrong username and wrong password return the same error message.

### Password hashing: verified

Stored in DB as:

```
pbkdf2:sha256$<salt>$<hash>
```

---

## A08 – Software and Data Integrity Failures

### ✔ **Status: NOT APPLICABLE**

The API does **not**:

* Load external code/plugins
* Execute remote templates
* Rely on CDNs
* Perform background updates

Therefore, A08 is out of scope for this system.

---

## A09 – Security Logging and Monitoring Failures

### 🟡 **Status: PARTIAL**

### Current status

* No structured application-level logging yet
* No SIEM integration
* No monitoring of:

  * Failed logins
  * Token misuse
  * Suspicious incident creation patterns

### Recommendation for future

* Add Python logging module
* Store logs in rotating files
* Forward logs to ELK/Splunk/Graylog

---

## A10 – SSRF (Server-Side Request Forgery)

### ✔ **Status: NOT APPLICABLE**

The API does not:

* Fetch external URLs
* Parse user-provided URLs
* Connect to user-defined resources

SSRF cannot be triggered by design.

---

## 5. Improvement Points

### 1. Rate limiting

To prevent brute-force attacks:

```
Flask-Limiter
```

### 2. Role-Based Access Control (RBAC)

* Admin: manage users
* Analyst: create/view incidents

### 3. Logging

* Failed logins
* Suspicious requests
* Changes to incidents
* Token expirations

### 4. API monitoring

* IP-based alerts
* Request anomaly detection
* Abuse filters

---

## 6. Final Evaluation

| Category          | Result                  |
| ----------------- | ----------------------- |
| Fully Covered     | A01, A02, A03, A05, A07 |
| Partially Covered | A04, A06, A09           |
| Not Applicable    | A08, A10                |

**Conclusion:**

> The Incident Management API demonstrates strong implementation against most OWASP Top 10 risks.
> It is secure by design for the scope of this academic project, with clear upgrade paths for production-level hardening.

---

## 7. Appendix

### Included Postman Collections

* `soc-incidents-api.postman_collection` — Functional testing
* `soc-incidents-api-owasp-tests.postman_collection` — Security tests