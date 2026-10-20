# NotesApp risk assessment

## Risk scoring method

Risk = likelihood × impact, using ordinal scores from 1 to 5. Multiplication supports prioritization, not a numerical probability or expected financial loss. Related threats and attack chains are not added together.

| Score | Likelihood in the stated deployment | Impact if the scenario succeeds |
|---|---|---|
| 1 | Exceptional prerequisites; largely theoretical | Negligible, readily reversible effect |
| 2 | Several uncommon conditions or user-dependent steps | Limited effect on one noncritical function |
| 3 | Credible but needs privilege, access, victim behavior or uncertain capacity | Material effect on a limited set of records or accountability |
| 4 | Straightforward for an ordinary authenticated actor | Broad grade disclosure/tampering or service-wide interruption |
| 5 | Directly exposed, low-complexity path without an account | Administrative, credential-wide or runtime/host compromise |

Bands: 1–4 Low; 5–9 Moderate; 10–16 High; 17–25 Critical. These scales and bands are assessment choices, not values prescribed by the assignment.

## STRIDE register and ratings

S = Spoofing; T = Tampering; R = Repudiation; I = Information disclosure; D = Denial of service; E = Elevation of privilege. A threat may affect multiple categories. Same-role access to another user's resources is described explicitly; an E label here includes exceeding the intended authorization scope, not necessarily changing the stored role.

| Threat | STRIDE | Scope | L | I | Risk | Level |
|---|---|---|---:|---:|---:|---|
| TH01 | S T E | 1–4 | 5 | 5 | 25 | Critical |
| TH02 | S E | 4, 9, 13, 17, 21, 25, 29, 33, 37 | 5 | 5 | 25 | Critical |
| TH03 | S I | 13–16 | 5 | 4 | 20 | Critical |
| TH04 | I | 13–16 | 4 | 4 | 16 | High |
| TH05 | I E | 17–20, 25–28 | 4 | 4 | 16 | High |
| TH06 | T E | 21–24 | 4 | 4 | 16 | High |
| TH07 | T I | 21–22 → 11–12 / 19–20 | 3 | 4 | 12 | High |
| TH08 | T E | 7–8, 21–24, 33–40 | 3 | 4 | 12 | High |
| TH09 | S T I | TB1; HTTP deployment | 3 | 5 | 15 | High |
| TH10 | I | PostgreSQL; image backups / deployment context | 3 | 5 | 15 | High |
| TH11 | R | 1–4, 7–40; audit context | 4 | 3 | 12 | High |
| TH12 | D | 1–44; resource usage | 3 | 4 | 12 | High |
| TH13 | T D E | 37–40, especially 38 | 3 | 5 | 15 | High |
| TH14 | E | 38; Docker deployment context | 3 | 5 | 15 | High |
| TH15 | T I | 21–22, 25–28; spreadsheet use | 2 | 4 | 8 | Moderate |
| TH16 | T | 21–24 | 4 | 3 | 12 | High |
| TH17 | S I | 4, 7–8, 12–16 | 3 | 4 | 12 | High |

### TH01

Concatenated login SQL allows attacker-controlled credentials to change query logic and potentially authenticate as another user.

**Evidence:** `web/app.py:143–177` (`login`).

**Likelihood 5:** Unauthenticated input reaches SQL directly; the source is available. **Impact 5:** An administrative identity enables broad account and grade operations.

**Mitigation:** Load the user using a bound username parameter, verify a stored password hash with a suitable password-hashing API outside SQL, migrate existing plaintext passwords, return generic failures and use least-privilege DB access. Hashing and rate limiting do not replace parameterization.

### TH02

The published Flask signing secret permits creation of accepted session data, including a privileged role.

**Evidence:** `web/app.py:32–35,121–126` (`SECRET_KEY`, `login_required`); `docker-compose.yml:28`.

**Likelihood 5:** The configured secret is present in the supplied source; no prior account is required. **Impact 5:** A forged administrator session exposes all administrative actions.

**Mitigation:** Replace and rotate `SECRET_KEY` outside Git, remove the development-key fallback, fail startup if the secret is missing, invalidate old signatures across all workers, and check active users and current roles against trusted server-side records. Session and JWT signing keys are separate from `COMMENT_KEY`; rotating authentication keys does not require replacing the comment-encryption key.

### TH03

The API accepts unsigned JWTs and a weak published HMAC key, allowing a forged Bearer identity to pass its authentication check.

**Evidence:** `web/app.py:69–117,205–227` (`make_jwt`, `verify_jwt`, `current_identity`, `api_notes`); `docker-compose.yml:27`.

**Likelihood 5:** An unsigned-token branch accepts a payload without verifying a signature. **Impact 4:** All grade records may be disclosed through the API; this path does not authenticate browser admin pages.

**Mitigation:** Use a maintained JWT library, pin the allowed signed algorithm, protect and rotate `JWT_SECRET`, require valid `exp`, `iss`, `aud` and user identity claims, and resolve an active current user. If an Authorization header is present, validate Bearer credentials and return 401 on failure without falling back to a cookie; use session authentication only when that header is absent. Enforce note ownership separately under TH04.

### TH04

A logged-in student can request another student’s note because the API selects by record ID without checking ownership.

**Evidence:** `web/app.py:205–227` (`api_notes`).

**Likelihood 4:** A normal authenticated student can change the requested note ID; no owner condition appears in the query. This matches the scale's authenticated-actor definition, rather than its unauthenticated score of 5. **Impact 4:** Grades and private comments across students can be disclosed.

**Mitigation:** Scope queries to the current student; define explicit teacher/admin policies and test the permission matrix.

### TH05

A teacher can view or export classes assigned to other teachers because class ownership does not restrict the queries.

**Evidence:** `web/app.py:230–251,282–314` (`teacher`, `export_csv`); `README.md:3–5`.

**Likelihood 4:** An ordinary teacher account can use the normal page or export endpoint. **Impact 4:** Bulk disclosure extends beyond the teacher’s assigned classes.

**Mitigation:** Filter classes and exports by the authenticated teacher ID; reject unauthorized class IDs.

### TH06

A teacher can create or update grades in another teacher’s class when the route checks the teacher role but not class ownership.

**Evidence:** `web/app.py:254–279` (`grades`).

**Likelihood 4:** Teacher credentials and a chosen record/class ID are sufficient prerequisites in the code. **Impact 4:** Unauthorized changes undermine academic records across classes.

**Mitigation:** Verify class ownership and enrollment in the write transaction; constrain updates by both record and authorized class.

### TH07

An actor allowed to write a comment can store active HTML/script that is rendered without escaping to another user.

**Evidence:** `web/templates/dashboard.html:15`; `web/templates/teacher.html:47`.

**Likelihood 3:** Requires comment-write access and a victim viewing the stored content. **Impact 4:** Script can alter displayed data and act in the victim browser; HttpOnly does not stop same-origin actions.

**Mitigation:** Restore autoescaping; if rich text is necessary apply a strict sanitizer, and add CSP as defense in depth.

### TH08

Missing CSRF validation can allow unwanted state changes when a victim browser sends a session cookie with an attacker-induced request.

**Evidence:** `web/app.py:180–183,254–279,332–349,370–387` (`logout`, `grades`, `admin_ping`, `admin_users`).

**Likelihood 3:** Requires a logged-in victim and a request context where browser cookie rules permit the cookie. **Impact 4:** Teacher or admin actions could be induced; ping consequences may chain to TH13.

**Mitigation:** Add server-validated CSRF tokens to mutations, use POST logout, check origins and set SameSite explicitly.

### TH09

On an accessible untrusted network, plaintext HTTP can expose credentials/session cookies and allow response or request modification.

**Evidence:** `docker-compose.yml:29–30`; `web/app.py:400–402` (HTTP development server).

**Likelihood 3:** Requires network positioning that permits interception or modification; the HTTP configuration alone does not demonstrate such an attack. **Impact 5:** A stolen privileged session can compromise administrative operations.

**Mitigation:** Deploy HTTPS, enable Secure cookies, retain Flask's HttpOnly protection, choose SameSite explicitly, and restrict development bindings to loopback.

### TH10

Plaintext passwords and the image's baked password backup remain exposed to someone with the necessary database, image or filesystem access. Current comments are encrypted with AES-GCM before storage and decrypted by Flask for outputs. A database-only read without `COMMENT_KEY` does not directly reveal their plaintext; key access or application-runtime compromise can still reveal them. Seed SQL contains example plaintext comments that startup migration converts.

**Evidence:** `db/init.sql:6–11,34–41`; `web/Dockerfile:16–22`; `web/comment_crypto.py:6–30`; `web/migrate_comments.py:7–43`; `docker-compose.yml:11–12,22`.

**Likelihood 3:** Requires database, image, backup or filesystem access; published database settings broaden exposure if reachable. **Impact 5:** Remaining password and backup disclosure can enable account compromise and subsequent access to private records. The score reflects these residual credential risks, not an assertion that encrypted comments remain plaintext.

**Mitigation:** Migrate passwords to Argon2id or another suitable password KDF, remove baked secrets/backups and restrict DB access. Retain AES-GCM with fresh nonces, protect and preserve the separately managed encryption key, and keep startup migration. Encryption does not replace the authorization fixes in TH04–TH06 or safe rendering/export in TH07/TH15.

### TH11

Incomplete, locally writable audit records leave insufficient evidence to attribute or reconstruct reads and administrative changes.

**Evidence:** `web/app.py:40–46,172–176,278,347` (`log` and its call sites); `web/Dockerfile:20–22`.

**Likelihood 4:** Normal sensitive operations omit key audit fields; code can silently ignore logging failures. **Impact 3:** Disputes and incident reconstruction become difficult even when data is still available.

**Mitigation:** Record actor, action, target, outcome and time; capture protected change history, centralize append-only logs, and alert on failures.

### TH12

Unbounded result sets, no application rate limiting and growing logs may exhaust database, worker or disk resources.

**Evidence:** `web/app.py:40–46,230–251,282–314` (`log`, `teacher`, `export_csv`); `docker-compose.yml` (no resource quotas).

**Likelihood 3:** Repeated traffic is possible, but practical thresholds depend on host resources and middleware. **Impact 4:** Service-wide unavailability could block grade access and updates.

**Mitigation:** Add rate limits, pagination, request-size limits, timeouts, log rotation and container quotas; validate with a bounded authorized load test.

### TH13

The administrator-controlled host string is concatenated into a shell command, enabling command execution beyond the intended ping function.

**Evidence:** `web/app.py:332–349` (`admin_ping`); `web/Dockerfile:24`.

**Likelihood 3:** Requires an administrator session, possibly obtained through TH01 or TH02. **Impact 5:** Commands run with the web process privileges and can damage the service or lead to TH14.

**Mitigation:** Avoid shell=True, validate destinations, use fixed executable arguments, restrict egress, and run the process with minimal privileges.

### TH14

Code execution in a root web container may allow control of the Docker Engine through the mounted socket and modification of bind-mounted project files.

**Evidence:** `docker-compose.yml:37–38`; `web/Dockerfile:24` (no `USER` directive).

**Likelihood 3:** Requires code execution and usable socket permissions; root alone is not a container escape. **Impact 5:** Compromise can extend to the Docker Engine host and other workloads.

**Mitigation:** Remove the Docker socket and broad host mount, use a non-root user and read-only filesystem, drop capabilities and isolate the runtime.

### TH15

An attacker-written comment exported as CSV may be treated as a formula by a spreadsheet application.

**Evidence:** `web/app.py:282–314` (`export_csv`); [OWASP CSV Injection](https://community.owasp.org/attacks/CSV_Injection).

**Likelihood 2:** Requires a writable comment, teacher download and spreadsheet behavior/settings that evaluate the cell. **Impact 4:** Spreadsheet content or accessible information may be affected; exfiltration depends on application controls.

**Mitigation:** Export untrusted cells as explicit text using a tested spreadsheet-safe policy; quoting CSV alone does not neutralize formulas.

### TH16

The grade route does not enforce a business grade range or verify that the selected user is an enrolled student in the class.

**Evidence:** `web/app.py:254–279` (`grades`); `db/init.sql:20–32`.

**Likelihood 4:** A teacher can submit values directly; foreign keys do not enforce role, enrollment or grade policy. **Impact 3:** False academic records or out-of-policy grades can be stored.

**Mitigation:** Agree the allowed grade range, validate role/enrollment and numeric input, then enforce appropriate database constraints.

### TH17

Issued JWTs lack expiry and copied tokens can still be used at the API after logout clears the browser session.

**Evidence:** `web/app.py:69–117,169–171,180–183,205–227` (`make_jwt`, `current_identity`, `logout`, `api_notes`).

**Likelihood 3:** Requires a previously copied token; logout does not implement token revocation. **Impact 4:** Grade access may persist beyond the intended session.

**Mitigation:** Require expiry and issuer/audience validation, short lifetimes and a revocation/version mechanism; revoke on logout when policy requires it.
