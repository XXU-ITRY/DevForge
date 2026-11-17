<div align="center">

# DevForge

**Build Together. Code Better.**

A lightweight, self-hostable developer collaboration platform — teams, projects, channels, file sharing, and Git insights in one place.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/XXU-ITRY/DevForge/)

[Features](#features) · [Quick Start](#quick-start) · [Architecture](#architecture) · [Development](#local-development) · [Deployment](#deployment) · [Configuration](#configuration) · [Security](#security) · [License](#license)

</div>

---

## Overview

DevForge is a single-file Cloudflare Worker that serves both the SPA frontend and the JSON API. It uses **D1** for persistence, **R2** (optional) for file storage, and **Workers Builds** for zero-config CI/CD. Every push to `main` runs database migrations and deploys the Worker automatically — no manual `wrangler` commands required after the initial setup.

**Key principles:**

- **One file, zero build step.** `worker.js` contains the HTML, CSS, JavaScript, and API.
- **Bilingual by design.** English and Persian (فارسی) with full RTL support.
- **Self-hosted, no vendor lock-in.** Deploy on your own Cloudflare account; connect your own GitHub repos.
- **Automatic resource provisioning.** D1 is created on first deploy; R2 is optional.

---

## Features

| Category | Capabilities |
| --- | --- |
| **Authentication** | JWT (HS256) via Web Crypto, PBKDF2 password hashing, session persistence |
| **Teams** | Create teams, invite-by-ownership model, member roles |
| **Projects** | Per-team projects with optional Git repository binding |
| **Messaging** | Real-time polling channels, message history, file attachments |
| **Files** | Upload/download via R2 (optional binding) |
| **Git Integration** | Recent commits from GitHub (public or private with token) |
| **Notifications** | In-app activity feed |
| **UI/UX** | Dark/light theme, Vazirmatn font, SVG icons, responsive layout |
| **i18n** | English (default) and Persian with instant RTL/LTR switching |

---

## Quick Start

### Option A — One-click deploy (recommended)

Click the **Deploy to Cloudflare** button above. Cloudflare will:

1. Clone this repository into your GitHub account.
2. Read `wrangler.toml` and provision a D1 database named `devforge-db`.
3. Run `npm run deploy` (which applies migrations and deploys the Worker).
4. Provide a live `*.workers.dev` URL.

No terminal, no `wrangler login`, no manual database creation.

### Option B — Connect an existing repository to Workers Builds

1. Push this repository to GitHub.
2. In the Cloudflare dashboard, go to **Workers & Pages → Create application → GitHub**.
3. Select the repository.
4. Cloudflare detects the `deploy` script in `package.json` and pre-populates:
   - **Build command:** `npm run build` (or blank)
   - **Deploy command:** `npm run deploy`
5. Select **Save and Deploy**.

Workers Builds will apply D1 migrations and deploy the Worker on every push to `main`[reference:5][reference:6].

### Option C — Local development

```bash
npm install
npx wrangler d1 migrations apply DB --local
npm run dev
# open http://localhost:8787
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Cloudflare Workers                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │                  worker.js                        │  │
│  │  ┌────────────┐  ┌─────────────┐  ┌───────────┐  │  │
│  │  │   HTML     │  │    CSS      │  │    JS     │  │  │
│  │  │  (SPA)     │  │  (themes)   │  │  (client) │  │  │
│  │  └────────────┘  └─────────────┘  └───────────┘  │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │              API router                     │  │  │
│  │  │  /api/auth  /api/teams  /api/channels  ...  │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│         ┌────────────────┼────────────────┐             │
│         ▼                ▼                ▼             │
│      ┌──────┐       ┌─────────┐      ┌──────┐          │
│      │  D1  │       │   R2    │      │GitHub│          │
│      │ (SQL)│       │ (files) │      │ API  │          │
│      └──────┘       └─────────┘      └──────┘          │
└─────────────────────────────────────────────────────────┘
```

**Data model:** `users` · `teams` · `team_members` · `projects` · `channels` · `messages` · `notifications`

**Auth flow:** `POST /api/auth/register` → PBKDF2 hash → JWT signed with `JWT_SECRET` → stored in `localStorage`. Every subsequent request sends `Authorization: Bearer <token>`.

---

## Local Development

### Prerequisites

- Node.js 20+
- A Cloudflare account (free tier is sufficient)

### Steps

```bash
git clone https://github.com/YOUR_USERNAME/devforge.git
cd devforge
npm install

# Apply migrations locally (uses a SQLite file under .wrangler/)
npx wrangler d1 migrations apply DB --local

# Start the dev server
npm run dev
```

Open `http://localhost:8787`. The dev server uses a local SQLite database; changes to `worker.js` hot-reload automatically.

### Testing the API

```bash
# Register
curl -X POST http://localhost:8787/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","username":"dev","password":"secret123"}'

# Login (returns token)
curl -X POST http://localhost:8787/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"dev@example.com","password":"secret123"}'
```

---

## Deployment

### How Workers Builds handles D1 migrations

Cloudflare Workers Builds **does not apply D1 migrations automatically**[reference:7][reference:8]. DevForge solves this by defining a custom `deploy` script:

```json
"deploy": "wrangler d1 migrations apply DB --remote && wrangler deploy"
```

Because this script exists in `package.json`, Workers Builds detects it and uses it as the deploy command[reference:9]. The result: every push to `main` runs migrations **before** deploying the Worker.

### Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `JWT_SECRET` | Yes | Secret used to sign JWTs. Set a long random string. |
| `GITHUB_TOKEN` | No | Personal access token for private GitHub repos. |
| `BUCKET` (R2 binding) | No | Enables file upload/download. |

Set secrets via the dashboard or Wrangler:

```bash
wrangler secret put JWT_SECRET
```

### R2 (optional)

Uncomment the `[[r2_buckets]]` block in `wrangler.toml`. On the next deploy, Cloudflare provisions the bucket named `devforge-files` automatically[reference:10].

---

## Configuration Reference

### Switching language

Open **Settings → Language** and select English or فارسی. The choice is stored in `localStorage` **and** persisted server-side (`users.lang`), so it follows the user across devices.

### Switching theme

**Settings → Theme** toggles between dark and light. Stored in `localStorage` and `users.theme`.

### Adding a Git repository to a project

When creating a project, enter the repository path as `owner/repo` (GitHub). DevForge fetches the latest 20 commits via the GitHub API. For private repositories, add a `GITHUB_TOKEN` secret.

---

## Security

- **Passwords** are hashed with PBKDF2 (100,000 iterations, SHA-256, random 16-byte salt) using Web Crypto — no external crypto libraries.
- **JWTs** are signed with HS256 and verified on every API request.
- **Authorization** is enforced per team: every `/teams/:id` route checks `team_members` before returning data.
- **CORS** is permissive by default (`*`). For production, restrict it in `worker.js`:
  ```js
  const cors = { 'Access-Control-Allow-Origin': 'https://your-domain.com' };
  ```
- **Secrets** (`JWT_SECRET`, `GITHUB_TOKEN`) are never committed. Use `wrangler secret put` or the dashboard.

---

## Project Structure

```
devforge/
├── worker.js                 # Entire application (HTML + CSS + JS + API)
├── wrangler.toml             # Cloudflare configuration (D1, vars, optional R2)
├── package.json              # Scripts: build, deploy, dev
├── migrations/
│   └── 0001_init.sql         # Initial schema
├── .env.example              # Template for local secrets
└── README.md
```

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-feature`.
3. Commit your changes: `git commit -m 'Add my feature'`.
4. Push: `git push origin feature/my-feature`.
5. Open a Pull Request.

Please keep changes focused and test locally with `npm run dev` before submitting.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**DevForge** — Because context-switching is a bug, not a feature.

</div>
