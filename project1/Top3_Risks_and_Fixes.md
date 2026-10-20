# NotesApp top three risks and fixes

## The three highest priority risks

TH01 and TH02 score 25, followed by TH03 at 20. TH04 now scores 16 because its direct exploitation requires an authenticated user, matching likelihood 4 in the scale. Its missing ownership check remains an urgent independent defect after JWT verification is repaired. Related threat and attack-chain scores are not added together.

### Priority 1 TH01 Login SQL injection

**Risk 25 = 5 × 5.** Unauthenticated credential input is concatenated into a SQL query. A changed query may produce another user's identity and administrative access.

**Evidence:** `web/app.py:143–177` (`login`).

**Fix:** query the user by a bound username parameter, then verify the stored password hash with a suitable password-hashing API outside SQL. Migrate existing plaintext passwords, restrict database privileges and return generic client-facing failures while keeping diagnostics in protected server logs. Hashing and rate limiting complement parameterization; neither replaces it. See [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).

**Acceptance checks:** valid credentials work; an unauthenticated client submitting incorrect credentials, quotes or SQL-like strings is rejected without creating an authenticated session or exposing database errors. Review query construction as well as responses. Define separately how a failed login affects an existing authenticated session.

### Priority 2 TH02 Published session signing secret

**Risk 25 = 5 × 5.** The application trusts session identity and role fields signed with a secret distributed in the project configuration. Anyone knowing that secret may create accepted session data without possessing a user's password.

**Evidence:** `web/app.py:32–35,121–126` (`SECRET_KEY`, `login_required`); `docker-compose.yml:28`.

**Fix:** supply a strong deployment-specific `SECRET_KEY` through protected configuration, remove the development fallback and fail startup if it is absent. Rotate the exposed key across every worker and reject old signatures. Resolve active-account status and current roles from trusted server-side records, and enforce authorization at each operation. Use HTTPS and Secure cookies, retain HttpOnly and explicitly choose SameSite.

`SECRET_KEY` protects sessions, `JWT_SECRET` protects API tokens and `COMMENT_KEY` protects stored comments. Manage them separately; rotating authentication keys must not accidentally replace the key needed to read existing comments.

**Acceptance checks:** new legitimate sessions work; old-key signatures and modified cookie data fail; deleted/disabled accounts and role changes take effect on protected endpoints. Missing session-secret configuration fails startup instead of using a development key. Check the repository, image and logs for leaked replacement secrets without publishing them.

### Priority 3 TH03 Forged API tokens

**Risk 20 = 5 × 4.** The custom verifier accepts `alg: none` and uses a published weak HMAC key. A forged Bearer token can pass the API identity gate. This is not evidence that browser-only teacher/admin routes accept that token.

**Evidence:** `web/app.py:69–117,205–227` (`make_jwt`, `verify_jwt`, `current_identity`, `api_notes`); `docker-compose.yml:27`.

**Fix:** use a maintained library, allow only the selected signed algorithm, protect and rotate `JWT_SECRET`, require valid `exp`, `iss`, `aud` and user identity claims, and resolve an active current user. Required claims must be present as well as valid. Independently scope note queries to the acting user's permissions under TH04. See [JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html).

**Acceptance checks:**

- Unsigned, wrong-key, malformed, empty and expired tokens return 401. Missing required claims and wrong issuer/audience values are rejected.
- Missing or inactive users are rejected; invalid credentials do not produce server errors or disclose grades.
- Invalid Bearer + valid cookie returns 401; cookie-only authentication without Authorization works; valid Bearer without a cookie works.
- If valid credentials identify different users, Bearer determines the acting identity and that user's note permissions apply.
- A student can read an owned note, but another student's note returns 404 through both Bearer and cookie-only paths. This check also covers TH04.
