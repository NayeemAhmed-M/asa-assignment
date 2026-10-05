# Security Analysis: Prioritized Findings

## 1. Overview & Threat Model Context

**VulnTracker** is a multi-tenant vulnerability management and scan tracking platform. It processes, correlates, and tracks security vulnerabilities across client systems and infrastructure.

In this business context, VulnTracker is a **Tier-1 Crown Jewel target**:
- **Compromise of Data**: A breach exposes zero-day vulnerabilities, unpatched CVEs, internal network topologies, and system credentials of all monitored clients—providing attackers an attacker's blueprint to compromise downstream organizations.
- **Compromise of Integrity**: Tampering with scan records allows malicious actors to hide known exploits or mark active breaches as "resolved".
- **Compromise of Confidentiality**: Exposing share links or allowing horizontal tenant traversal (IDOR) breaks tenant isolation and violates regulatory mandates (SOC 2, ISO 27001, GDPR, HIPAA).

This document prioritizes findings discovered across **Static Application Security Testing (SAST)**, **Software Composition Analysis (SCA)**, **Container Scanning**, **Infrastructure-as-Code (IaC) Scanning**, and **Manual Security Architecture Review**.

---

## 2. Prioritized Findings Table

| ID | Finding Title | Scan Type | Detection Source | Assessed Severity & Justification | Location | Component | Business Impact in VulnTracker Context |
|---|---|---|---|---|---|---|---|
| **FINDING-01** | SQL Injection via String Interpolation in Search | SAST / Manual | Bandit (`B608`) & Manual Review | **CRITICAL**<br>Bandit flagged this as Medium, but because the attacker input is directly formatted into SQLite queries without sanitization or parameterization, full database extraction is trivial. | `app/database.py:22-27` | Starter Code | **Total Database Compromise:** Allows unauthenticated/authenticated attackers to dump user credentials, bcrypt password hashes, private vulnerability scans, and API keys via `UNION SELECT` or boolean blind injection. |
| **FINDING-02** | Authentication Bypass via Permissive JWT `"none"` Algorithm | SAST / Manual **CRITICAL**<br>Bandit missed this finding. Specifying `"none"` in `jwt.decode(..., algorithms=[ALGORITHM, "none"])` allows attackers to sign arbitrary tokens with no cryptographic key. | `app/auth.py:38` | Starter Code | **Complete Account Takeover:** An external attacker can craft a JWT header with `{"alg": "none"}` and payload `{"sub": "admin"}` without knowing `SECRET_KEY`, gaining full administrative control over all customer vulnerability records. |
| **FINDING-03** | Insecure Direct Object Reference (IDOR) on Scan Retrieval | Business Logic | Manual Review (Invisible to SAST) | **HIGH**<br>`GET /scans/{scan_id}` authenticates the user but completely fails to verify tenancy or ownership (`scan.owner_id == current_user.id`). | `app/main.py:220-230` | Starter Code | **Cross-Tenant Data Exposure:** Any low-privileged customer can enumerate integer IDs (`/scans/1`, `/scans/2`) to read all other customers' confidential vulnerability scans, system flaw descriptions, and remediation notes. |
| **FINDING-04** | Plaintext Password Exposure in Application Logs | SAST | **HIGH**<br>`logger.info` and `logger.warning` write plain text passwords from login attempts directly to application logs during both successful and failed logins. | `app/main.py:153, 157-160` | Starter Code | **Credential Leakage in Monitoring Systems:** Anyone with access to log aggregators (Datadog, Splunk, CloudWatch, stdout) can harvest customer passwords in cleartext. Violates PCI-DSS 3.2, GDPR, and ISO 27001 compliance. |
| **FINDING-05** | Host Header Poisoning in Shared Report Link Generation | Web Security | Manual Review | **HIGH**<br>The shared report URL is dynamically generated using the untrusted `Host` HTTP request header without whitelist validation: `request.headers.get('host')`. | `app/main.py:325` | New Feature (Task 1) | **Phishing & Token Interception:** An attacker spoofing the `Host` header (e.g. `Host: evil-attacker.com`) during automated workflows or cache poisoning generates links pointing to malicious infrastructure, capturing external stakeholder clicks and tokens. |
| **FINDING-06** | Insecure Cross-Origin Resource Sharing (CORS) Configuration | Web Security | Manual Review | **HIGH**<br>Reflects arbitrary request `Origin` headers while granting `Access-Control-Allow-Credentials: true` and wildcard allowed headers. | `app/main.py:30-39` | Starter Code | **Cross-Origin Data Exfiltration:** Malicious websites visited by an authenticated user in another browser tab can issue authenticated cross-origin fetch requests to VulnTracker and steal sensitive scan reports and user details. |
| **FINDING-07** | Hardcoded Secrets and Default Master Credentials in Version Control | SAST / Secrets | Bandit (`B105`) & Secret Scan | **HIGH**<br>`SECRET_KEY`, `DB_PASSWORD`, and `ADMIN_API_KEY` are hardcoded in static configuration files committed to git. | `app/config.py:3, 9, 12` | Starter Code | **Persistent Lateral Movement:** Anyone with read access to the git repository (contractors, CI runners, compromised developer laptops) possesses perpetual administrative API keys and the ability to forge valid JWT authentication tokens. |
| **FINDING-08** | Missing Brute-Force Protection on Password-Protected Share Links | Auth / Rate Limiting | Manual Review | **MEDIUM**<br>`GET /share/{token}` performs bcrypt comparison on user-supplied passwords with no attempt throttling or rate limiting. | `app/main.py:331-352` | New Feature (Task 1) | **Password Guessing on Public Share Links:** Because share links are publicly accessible endpoints, attackers who guess or intercept a token can run automated dictionary attacks against the password. |
| **FINDING-10** | Known Critical & High Vulnerabilities in Pinned Dependencies | SCA | pip-audit (`reports/sca.pip-audit.json`) | **HIGH**<br>53 vulnerabilities detected across 8 Python packages, including CVEs in `cryptography`, `urllib3`, `certifi`, and `jinja2`. | `requirements.txt` | Starter Code | **Supply Chain Vulnerability:** Outdated dependencies permit denial of service, memory corruption, and remote compromise through known exploits in widely published CVE databases. |
| **FINDING-11** | Container Image Vulnerabilities in Base OS Packages | Container Scan | Trivy (`reports/container.trivy.json`) | **MEDIUM**<br>Multiple upstream Debian 12 CVEs identified in standard system shared libraries (glibc, libssl, libexpat). | `Dockerfile` | Deployment (Task 4) | **Container Escape / Local Exploit Vector:** While mitigated by non-root execution (`USER appuser`), base image vulnerabilities pose risk if a remote code execution vulnerability is chained with a kernel/system library privilege escalation exploit. |
| **FINDING-12** | Read-Only Root Filesystem Disabled in Kubernetes Deployment | IaC Misconfig | Trivy (`reports/iac.trivy.json` - `KSV014`) | **LOW** (Documented Trade-off)<br>`readOnlyRootFilesystem: false` in Helm `deployment.yaml`. Trivy flags this as HIGH policy violation. | `helm/vulntracker/templates/deployment.yaml` | Deployment (Task 4) | **Container Persistence Risk:** If an attacker gains shell execution inside the pod, they can modify container binaries or drop malware unless persistent storage (`/data`) is mounted and the root filesystem is made immutable. |

---

## 4. Remediation Prioritization Strategy

Remediation is planned in three phases:

1. **Immediate Code Fixes (Task 3 - Critical / High Priority)**:
   - Fix **FINDING-01**: Refactor `search_scans_by_query` to use SQLAlchemy parameterized queries.
   - Fix **FINDING-02**: Remove `"none"` algorithm from `auth.py` and enforce strict HS256 validation.
   - Fix **FINDING-03**: Enforce tenancy/owner authorization checks in `get_scan` (`GET /scans/{scan_id}`).
   - Fix **FINDING-04**: Redact plaintext passwords from all logging in `app/main.py`.
   - Fix **FINDING-05 (Task 1 Code)**: Validate `Host` header or source base URL from trusted configuration rather than blindly reflecting client headers.
   - Fix **FINDING-06**: Restrict CORS origins to trusted domains rather than reflecting arbitrary incoming origins with credentials.

2. **Supply Chain & Infrastructure Fixes (Tasks 4 & Follow-up)**:
   - Upgrade dependencies in `requirements.txt` to eliminate known SCA CVEs.


