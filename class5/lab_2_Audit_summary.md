# NOTESAPP PASSWORD AUDIT — pair: Liu Yunfei (2023905324)

## FINDING 1 — stored passwords (unsalted MD5)

- **Cracked:** 4/6 in 0.103334 ms, public wordlist
- **Held out & why:** marie and raj were absent from the wordlist; the username+pw bonus then recovered marie (5/6), leaving raj's long random password.
- **Severity:** High because a leaked table allows rapid offline recovery of common passwords.
- **Fix:** Use Argon2id with a unique random salt per password and suitable memory/time costs.

## FINDING 2 — the fix, measured

- **MD5:** 3,724,595 guesses/sec   → 321,805,008,000 / day
- **Argon2:** 39.3 guesses/sec   → 3,395,520 / day
- Argon2 is ~94,800× slower per guess.
- **Verdict:** MD5 enables rapid offline cracking; Argon2 makes each guess much costlier, so attackers may give up when a strong password exceeds their budget, but common passwords remain crackable.

**STATE:** NotesApp now stores passwords with Argon2 (alice migrated on login).  ✅
