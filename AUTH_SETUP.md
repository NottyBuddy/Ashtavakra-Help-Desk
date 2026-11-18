# Secure sign-in deployment — IndiFrame Agent Help Desk

This is an authentication extension to the existing portal, not a separate portal. The original approved scripts, product information, SOPs and other modules remain in the existing `index.html`.

## What is included

- Cloudflare Pages Functions API in `functions/api/[[path]].js`
- D1 schema in `migrations/0001_auth.sql`
- Session enforcement for all portal pages in `functions/_middleware.js`
- Same-site sign-in and forced password change page in `login.html`
- Team Lead account management console in `admin.html`
- Cloudflare Pages/D1 config template in `wrangler.toml`

## Role and password policy

- Exactly one Team Lead administrator is bootstrapped through a one-time setup endpoint.
- Team Lead creates agent records; new records remain pending until explicitly approved.
- There is no public self-registration.
- When Team Lead approves an agent, the backend sets the configured temporary agent password and marks the account as requiring a password change.
- Team Lead can disable an agent or reset an approved agent's password. Disabling/resetting revokes existing sessions.
- Admin and agent passwords are separate. The Team Lead chooses their own password during initial setup.
- Passwords are stored as PBKDF2-HMAC-SHA256 hashes with unique salts. Session tokens are random and only their hashes are stored in D1.
- API role checks are server-side; hiding admin controls in the browser is not treated as security.

## Required Cloudflare setup

Cloudflare account access is required for the following account-level steps. These actions cannot be completed from the GitHub repository alone.

1. Create a **D1 database** named `indiframe-agent-help-desk`.
2. In the D1 SQL console, run the complete contents of `migrations/0001_auth.sql`.
3. Copy the database ID into `wrangler.toml`, replacing `REPLACE_WITH_CLOUDFLARE_D1_DATABASE_ID`.
4. Create a **Cloudflare Pages** project connected to this GitHub repository. For the initial test, select branch `feature/secure-auth-cloudflare`. Set the build command to blank / none and the build output directory to `/`.
5. In Pages → Settings → Functions → D1 database bindings, add binding name `DB` and select the database created in step 1.
6. In Pages → Settings → Environment variables and secrets, add these as **secrets** for Production (and Preview if testing there):
   - `ADMIN_SETUP_TOKEN`: a one-time, high-entropy setup token. Generate it privately; never commit or share it.
   - `AGENT_INITIAL_PASSWORD`: set to the exact temporary password supplied by the Team Lead for all newly approved agents. This value is used only server-side to create the salted password hash. Never put it in frontend JavaScript or Git.
7. Deploy the branch and confirm `https://YOUR-PAGES-DOMAIN/api/health` returns an `ok: true` response.
8. Initialize the Team Lead exactly once by POSTing JSON to `/api/setup/admin`:
   ```json
   {
     "setupToken": "YOUR_ONE_TIME_SETUP_TOKEN",
     "name": "Team Lead name",
     "email": "teamlead@company-domain",
     "password": "A unique strong Team Lead password"
   }
   ```
   Use a private API client over HTTPS. Do not put the setup token or Team Lead password in the website source, GitHub, or a shared chat. The Team Lead password must be unique and at least 12 characters.
9. After the first Team Lead account is successfully created, remove the `ADMIN_SETUP_TOKEN` secret from Cloudflare and redeploy. The setup endpoint will then be disabled.
10. Sign in at `/login.html`. The Team Lead can add agent names and approved company work emails from the Team Lead Console. New records are pending; click **Approve** only after checking the work email. Give the temporary password to the agent through the company's approved private channel.
11. After testing, merge the branch into `main` and point the Cloudflare Pages production deployment at `main`.

## Important hosting note

The existing GitHub Pages address only serves static files and cannot run these secure server-side functions. The login system is active only on the Cloudflare Pages deployment after the D1 binding and secrets are configured. The GitHub repository remains the source code and the portal remains one website/domain. Do not continue using the public GitHub Pages URL for confidential internal content once the protected deployment is live.

## API endpoints

- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/change-password`
- `POST /api/auth/logout`
- `GET /api/admin/agents`
- `POST /api/admin/agents`
- `PATCH /api/admin/agents/:id`
- `POST /api/admin/agents/reset-password`

The admin setup endpoint is `POST /api/setup/admin` and should be used once only.


## AI Assist (Workers AI)

The portal AI Assist uses a server-side Cloudflare Workers AI binding. The repository Wrangler configuration declares `[ai] binding = "AI"`; verify that the production Pages environment has a Workers AI binding named `AI` and redeploy after binding changes. The AI endpoint requires an approved portal session, limits question/context size, applies a per-user/IP request limit using the existing D1 login-attempts table, and instructs the model to answer only from supplied approved portal excerpts. Workers AI inference consumes account usage and may incur charges under the current plan. Do not send customer personal data or confidential customer records in prompts.
