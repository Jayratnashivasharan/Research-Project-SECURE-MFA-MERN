# SecureMERN — AI-Guarded MFA Authentication

A MERN application demonstrating multi-factor authentication strengthened by an AI-based risk engine.

## Run it
1. Install Node.js 18+ and have MongoDB running locally.
2. `cp server/.env.example server/.env`
3. `npm run install-all`
4. `npm run seed`
5. In one terminal: `npm run server`. In another: `npm run client`.
6. Open http://localhost:5173

Demo logins (password `Demo@1234`): `admin@example.com` (admin), `user@example.com`.
Tests: `npm test` (risk engine). Build: `npm run build`.

## What "AI" means here
The risk engine (`server/riskEngine.js`) is a transparent, weighted logistic-regression-style
scorer over behavioral features: unrecognized device, new IP, recent failed attempts, odd-hour
login, and rapid IP change ("impossible travel" proxy). It is documented honestly as a
rule-weighted statistical model, not a deep neural network, in keeping with academic integrity
expectations — see the comments in riskEngine.js.

## How security is enhanced
1. Password login (bcrypt-hashed) always happens first.
2. Every attempt is scored 0–1 by the risk engine against the user's own history.
3. Score ≥ 0.75 → login blocked outright. Score 0.4–0.75, or MFA already enabled → a second
   factor (TOTP code or backup code) is required. Below that → normal login.
4. TOTP enrollment uses `speakeasy` + QR code (Google Authenticator / Authy compatible), with
   8 single-use backup codes generated on activation.
5. JWT access tokens are short-lived (15 min) with a 7-day refresh token; auth and general API
   routes are rate-limited; passwords are bcrypt-hashed; helmet + CORS are applied.

## Status
IMPLEMENTED: registration/login, bcrypt hashing, JWT access+refresh, TOTP MFA with QR enrollment
and backup codes, weighted-logistic AI risk engine with 4 passing unit tests, per-user security
activity log, admin security overview dashboard, rate limiting, helmet, input validation.
NOT BUILT: email/SMS OTP delivery (interfaces described in the paper, not wired to a provider),
WebAuthn, password reset flow, Docker, and a persisted device-fingerprint beyond a browser-stored ID.
