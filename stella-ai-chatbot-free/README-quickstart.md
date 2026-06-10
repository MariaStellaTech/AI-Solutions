# Stella AI Chatbot Free - Quick Start

## 1) Install

```bash
npm install
```

## 2) Create `.env`

Copy `.env.example` to `.env`, then set at least:

```env
NODE_ENV=production
PORT=8080
APP_SECRET=your-strong-secret
ADMIN_USER=your_admin
ADMIN_PASS=your_password
INSTALL_TOKEN=your_install_token
DATA_ENCRYPTION_KEY=your-strong-encryption-key
REQUIRE_WIDGET_CALLER_HEADERS=true
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

## 3) Start App

```bash
npm start
```

## 4) Run Installer

Open:

```text
http://localhost:PORT/install
```

Then open admin:

```text
http://localhost:PORT/admin
```

## 5) Configure in Admin

Go to:

```text
/admin/settings
```

Set:
- Chatbot name/avatar
- Welcome and no-match messages
- Categories
- Widget domain policy (`restricted` recommended)
- Allowed widget domains

## 6) Embed Widget

Copy embed code from `/admin/settings`, or use:

```html
<script src="https://YOUR_CHATBOT_DOMAIN/widget.js" data-api-base="https://YOUR_CHATBOT_DOMAIN"></script>
```

## 7) Go-Live Checklist

- Use HTTPS
- Use strong non-default secrets
- Keep `INSTALL_MAINTENANCE_MODE=false`
- Keep `widgetDomainPolicy=restricted`
- Set explicit `CORS_ORIGINS`

## Common Notes

- If `npm start` is blocked, you still have default `.env` values.
- If `/install` redirects to `/admin`, app is already installed.
- For reinstall: set `INSTALL_MAINTENANCE_MODE=true`, restart, run installer, then set it back to `false`.
