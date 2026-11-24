# Privacy Monitor — Deployment, Security & Backup Recovery Guide

Privacy Monitor is a self-service progressive web application (React + Vite + TypeScript + Express + Node `node:sqlite`) designed to run in **zero-additional-cost mode** without mandatory paid APIs, SMTP servers, or external billing accounts.

---

## 1. Runtime Prerequisites

- **Node.js 22.12+** (built-in `node:sqlite` and native Web Crypto / `crypto` support; tested on Node 22).
- **npm** (or Bun lockfile compatible dependencies).
- Persistent writable storage directory for runtime state (`instance/` by default, or `PRIVACY_INSTANCE_DIR`).
- **HTTPS termination** in production (via reverse proxy such as Cloud Run, Nginx, Caddy, or Cloudflare) so WebAuthn Passkeys, Service Workers (PWA), and `navigator.mediaDevices.getUserMedia` camera access operate in a secure context.

---

## 2. Build & Start Commands

```bash
# Install dependencies
npm install

# Run automated TypeScript verification & integration test suite
npm run lint
npm test

# Build frontend assets & PWA manifest/service worker into dist/
npm run build

# Start production Express server on port 3000 (serves API + dist/)
NODE_ENV=production npm start
```

For clean production distribution (excludes databases, keys, secrets, Python artifacts, and test fixtures):

```bash
npm run package:prod
# Outputs: release/privacy-monitor-prod.zip
```

---

## 3. Environment Variables

### Core Host Configuration

| Variable | Required? | Purpose | Zero-Cost Default |
| --- | --- | --- | --- |
| `PORT` | Optional | Listening port | `3000` |
| `NODE_ENV` | Recommended (`production`) | Enables HSTS, strict production guards, static `dist/` serving | `development` |
| `APP_URL` / `PUBLIC_BASE_URL` | Required in prod for WebAuthn / OAuth | Canonical HTTPS origin (e.g. `https://privacy.example.com`) | Auto-detected from request host locally |
| `SESSION_SECRET` | Recommended in prod | HMAC signing key for sessions & reviewer tokens | Securely auto-generated to `instance/session.secret` |
| `EVIDENCE_KEY` | Recommended for portable vaults | 32-byte encryption key (`hex`, `base64`, or passphrase) for AES-256-GCM blobs | Auto-generated to `instance/encryption.key` |
| `REVIEWER_PASSCODE` | Recommended in prod | Initial / environment-locked Trusted Reviewer Console passcode | Claimable once via UI if unset |
| `REVIEWER_BOOTSTRAP_TOKEN` | Recommended in prod if claiming via UI | Server token guarding first-run reviewer passcode claim | Not required unless set |

### Free OSINT & AI Enhancers (Zero Paid Subscriptions)

| Variable | Cost | Effect When Set / Unset |
| --- | --- | --- |
| `GEMINI_API_KEY` | Free tier / AI Studio key | Enables advisory plain-language explanations, takedown drafting, Image Studio, and opt-in 1:1 visual screening. All core scanning, vault encryption, and reporting continue if unset. |
| `URLHAUS_AUTH_KEY` | Free (`auth.abuse.ch`) | Enables URLhaus malicious URL & domain lookup. Marked unavailable honestly if unset. |
| `GITHUB_TOKEN` | Free GitHub PAT | Raises GitHub REST search quota from 10 req/min to 30 req/min. Works unauthenticated when unset. |
| `NVD_API_KEY` | Free NIST NVD key | Raises NVD CVE v2.0 rate limit from 5 req/30s to 50 req/30s. Works unauthenticated when unset. |

The following free OSINT providers require **no API key**:
- **HIBP Pwned Passwords Range API** (k-anonymity SHA-1 5-char prefix)
- **crt.sh Certificate Transparency**
- **IANA RDAP & Cloudflare DNS-over-HTTPS** (SPF / DMARC / DNS)
- **CISA Known Exploited Vulnerabilities (KEV)**
- **Gravatar Profile Hash**, **StopForumSpam**, **Hacker News (Algolia)**, **Wikipedia REST**

### Optional External / Paid Integrations (Disabled by Default)

| Variable | Type | Behavior When Unset |
| --- | --- | --- |
| `BRAVE_API_KEY` | Paid-tier Web Search | Provider explicitly reported as unavailable/skipped — never treated as clean. |
| `HIBP_API_KEY` | Paid HIBP v3 Email API | Provider explicitly reported as unavailable/skipped — never treated as clean. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_FROM` | Optional SMTP relay | Verification tokens are shown via the preview fallback UI for single-host / zero-cost operation. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Optional Google OIDC | `/api/auth/google/status` reports `{ configured: false }`; password, PIN, recovery code, and WebAuthn passkeys remain fully functional. |

---

## 4. Google OAuth Callback Setup (Optional)

If enabling optional Google OpenID Connect sign-in:
1. Create an OAuth 2.0 Web Application client in Google Cloud Console.
2. Add Authorized Redirect URI: `<PUBLIC_BASE_URL>/api/auth/google/callback`.
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `APP_URL` / `PUBLIC_BASE_URL`.
4. Note that Privacy Monitor preserves biometric enrollment consent: Google Sign-In links to or authenticates existing enrolled accounts.

---

## 5. Key Management, Encrypted Backup & Disaster Recovery

Privacy Monitor encrypts all uploaded selfies, monitoring photos, Image Studio files, and case evidence at rest using **AES-256-GCM** with `EVIDENCE_KEY` (or `instance/encryption.key`).

**Critical Rule:** Encrypted database backups (`.pmbackup`) deliberately exclude host secrets and encryption keys (`encryption.key`, `session.secret`, `.env`) so compromised archives cannot decrypt stored blobs alone.

### Backup Procedure
1. Preserve **`EVIDENCE_KEY`** (or back up `instance/encryption.key`) in a separate password manager or KMS secret store.
2. Open **Reviewer Audit Console -> Encrypted Database Backup & Restore**.
3. Enter a 12+ character passphrase and click **Export Backup**.
   - Creates a `VACUUM INTO` atomic SQLite snapshot encrypted with **AES-256-GCM** + **scrypt** key derivation and verifies SQLite integrity.

### Verification & Restoration Procedure
1. Restore `EVIDENCE_KEY` / `instance/encryption.key` on the target server first so stored encrypted photos and case evidence decrypt cleanly.
2. Open **Reviewer Audit Console** on the target instance, select the `.pmbackup` archive, enter the backup passphrase, and click **Verify** (runs AEAD decryption + SHA-256 check + SQLite `PRAGMA integrity_check`).
3. Click **Restore** to atomically replace the live SQLite database from the verified snapshot.

---

## 6. Known Operational & Architectural Boundaries

- **Face Screening vs. Neural Biometrics:** Camera check captures a 3-frame local sequence + optional opt-in Gemini 1:1 visual comparison + mandatory human Trusted Reviewer sign-off. Dedicated DeepFace/ArcFace neural embeddings, certified biometric liveness, forensic deepfake detectors, and automatic open-web reverse-image uploads are not integrated in this build.
- **Passkeys (WebAuthn):** Bound to the Relying Party ID (`RP ID`) matching the active hostname (`localhost` or your deployed domain). Moving domains requires registering a new passkey for the new hostname.
- **SQLite Concurrency:** Uses WAL mode and single-process Node `node:sqlite`. Designed for single-node deployments rather than multi-container horizontal replicas sharing one disk file.
