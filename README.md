# Shomei Auth

Shomei is a fully-featured, self-hosted OpenID Connect (OIDC) identity provider built with Node.js and React. Similar to commercial identity providers like Auth0 or Clerk, Shomei acts as a centralized authentication server that allows you to manage user identities and securely authorize third-party applications.

## 🌿 The Nature of Shomei
Shomei's frontend embraces a soothing, grounded nature aesthetic. We believe authentication shouldn't be a jarring or frustrating experience. Our UI incorporates subtle CSS animations (like swaying vines), earthy tones, and a playful slithering snake animation that gently alerts users when they make a mistake. 

## 🏗️ Architecture
Shomei is built as a microservice architecture orchestrated by Docker Compose:

1. **PostgreSQL (`shomei_postgres`)**: The source of truth for Users, Clients, Refresh Tokens, and OTP Codes.
2. **Redis (`shomei_redis`)**: An in-memory data store used for two critical components:
   * **Rate Limiting**: To prevent brute-force attacks and DDOS attempts.
   * **Shortcodes**: OIDC authorization codes are extremely short-lived (5 minutes). Storing them in Redis leverages automatic TTL expiration, which prevents your database from bloating over time.
3. **Backend (`shomei_backend`)**: A Node.js Express API handling OIDC logic, OTP generation, and token signing.
4. **Frontend (`shomei_frontend`)**: A modern React SPA (Single Page Application) built with Vite and served via Nginx.

## 🛡️ Security Features
* **PKCE (Proof Key for Code Exchange)**: Protects the token exchange flow from code injection attacks, a critical defense for SPAs and mobile apps.
* **Two-Tiered Rate Limiting**: Uses Redis to limit requests by both IP address (preventing botnet spam) and by specific email (preventing targeted brute force attacks).
* **Bcrypt Hashing**: All passwords and client secrets are cryptographically salted and hashed.
* **Refresh Tokens**: Access tokens are short-lived. Shomei issues secure refresh tokens that can be monitored and revoked at any time.

## 🚀 Getting Started

### Prerequisites
* Docker and Docker Compose
* A Resend API Key (for email verification)
* Node.js (for local Drizzle commands)

### Installation
1. Clone the repository and navigate into it.
2. Create your `.env` file:
   ```env
   # Ensure you set up DATABASE_URL, RESEND_KEY, and PUBLIC_KEY / PRIVATE_KEY
   ```
3. Push the database schema to your Postgres instance:
   ```bash
   npm run generate
   npx drizzle-kit push
   ```
4. Build and start the Shomei services:
   ```bash
   docker-compose up --build -d
   ```

   Run maintanence.sh to work out everything

   added fix for server

Shomei will now be running on `http://localhost:3000` (Frontend) and `http://localhost:3371` (Backend).
