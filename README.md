# SafeSite Guard

SafeSite Guard is a browser-extension security checker that sends page URLs to a backend API, which then applies Google Safe Browsing, TLS, domain-age, and heuristic checks before returning a verdict.

## Project structure

- `backend/` — Express API that performs security checks.
- `extension/` — Chrome/Chromium extension UI and monitoring logic.
- `docker-compose.yml` — Docker Compose setup for the backend service.

## Requirements

- Node.js 20+
- npm
- Docker + Docker Compose (optional, for container deployment)
- A Google Safe Browsing API key

## 1. Configure the backend

From the project root:

```bash
cp backend/.env.example backend/.env
```

Then edit `backend/.env` and set a real value for `GOOGLE_SAFE_BROWSING_KEY`.

Example:

```env
PORT=3000
GOOGLE_SAFE_BROWSING_KEY=your_real_key_here
```

## 2. Run locally

```bash
npm install --prefix backend
npm --prefix backend run dev
```

Verify the backend health endpoint:

```bash
curl http://localhost:3000/health
```

Expected output:

```json
{ "status": "ok" }
```

## 3. Load the extension in Chrome

1. Open `chrome://extensions`.
2. Turn on Developer mode.
3. Click Load unpacked.
4. Select the `extension/` folder.
5. Open the extension settings page and set the backend URL to `http://localhost:3000`.

The extension checks the backend URL from `chrome.storage.local`, so you can change it later without editing code.

## 4. Deploy the backend with Docker

```bash
docker compose up --build -d
```

Then test:

```bash
curl http://localhost:3000/health
```

## 5. Deploy the backend to a cloud provider

Use any Node.js hosting provider such as Render, Railway, Fly.io, or Azure App Service.

Set these environment variables:

- `PORT`
- `GOOGLE_SAFE_BROWSING_KEY`

Build command:

```bash
npm install --omit=dev
```

Start command:

```bash
node server.js
```

Then open the extension settings page and change the backend URL to your deployed URL, for example:

```text
https://safesiteguard-backend.onrender.com
```

## 6. Production improvements to consider

- Add real user authentication and role-based access control to the backend.
- Put the API behind HTTPS and a reverse proxy.
- Add audit logging and rate limiting.
- Limit which external domains are checked and how often.
- Add automated tests for the risk engine and the extension flows.
- Add a proper CI pipeline with linting and smoke tests.

## 7. Troubleshooting

- If `GOOGLE_SAFE_BROWSING_KEY` is missing, the backend still starts but reports a low-confidence result.
- If the extension cannot reach the backend, confirm the backend URL in the extension options page.
- If the browser blocks the request, verify that the backend responds with CORS headers and that the URL is reachable from the browser.
