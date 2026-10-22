# NOTESAPP PASSWORD AUDIT — pair: Liu Yunfei, Ziqian YU

## Lab 1

### FINDING 1 — login over plain HTTP

- **Exposed:** `username=alice&password=alicepw` (before-screenshot: the `POST /login` line)
- **Who reads it:** Anyone sniffing traffic on the local network or gateway
- **Severity:** High because credentials are transmitted in plaintext without encryption, allowing attackers to easily intercept passwords
- **Fix:** Enforce HTTPS (TLS encryption) using a reverse proxy like Nginx
- **FIX VERIFIED — re-captured under HTTPS:** password readable? No (after-screenshot)

### FINDING 2 — certificate trust

- **GitHub issued by:** Sectigo Public Server Authentication CA DV E36
- **Yours issued by:** localhost
- **Trust yours lacks:** A valid chain of trust backed by a trusted Root Certificate Authority
- **Verdict (encrypted vs trusted):** The connection is encrypted (secure from eavesdropping), but untrusted (no valid CA chain), which triggers browser warnings

**STATE:** NotesApp now served over HTTPS (self-signed, for the lab). ✅

## Lab 2

### FINDING 1 — stored passwords (unsalted MD5)

- **Cracked:** 4/6 in 0.103334 ms, public wordlist
- **Held out & why:** marie and raj were absent from the wordlist; the username+pw bonus then recovered marie (5/6), leaving raj's long random password.
- **Severity:** High because a leaked table allows rapid offline recovery of common passwords.
- **Fix:** Use Argon2id with a unique random salt per password and suitable memory/time costs.

### FINDING 2 — the fix, measured

- **MD5:** 3,724,595 guesses/sec → 321,805,008,000 / day
- **Argon2:** 39.3 guesses/sec → 3,395,520 / day
- Argon2 is ~94,800× slower per guess.
- **Verdict:** MD5 enables rapid offline cracking; Argon2 makes each guess much costlier, so attackers may give up when a strong password exceeds their budget, but common passwords remain crackable.

**STATE:** NotesApp now stores passwords with Argon2 (alice migrated on login). ✅
