# Stella AI Chatbot Free

Self-hosted FAQ chatbot for websites.

This package includes:
- Admin panel (`/admin`)
- Widget script (`/widget.js`)
- JSON storage in `data/`
- Free features: FAQ, fuzzy matching, categories, lead capture, logs

## Requirements

- Node.js 18 or newer
- npm
- Single server/process deployment is recommended

## Quick Start

1. Open terminal in this folder.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Copy environment file:
   ```bash
   copy .env.example .env
   ```
4. Edit `.env` with secure values.
5. Start server:
   ```bash
   npm start
   ```
   If startup is blocked, update the `.env` values shown in the error and run again.
6. Open installer:
   - `http://localhost:PORT/install`
7. Open admin:
   - `http://localhost:PORT/admin`

## Environment Configuration

Set these values before going live:

```env
NODE_ENV=production
PORT=8080
APP_SECRET=your-strong-random-secret
ADMIN_USER=your_admin_username
ADMIN_PASS=your_strong_password
INSTALL_TOKEN=your_install_token
DATA_ENCRYPTION_KEY=your-strong-random-encryption-key
TRUST_PROXY=false
CSP_RELAXED=false
REQUIRE_WIDGET_CALLER_HEADERS=true
INSTALL_MAINTENANCE_MODE=false
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### Variable Notes

- `PORT`: app port (many cloud hosts set this automatically)
- `APP_SECRET`: signing key for admin and widget tokens
- `ADMIN_USER` / `ADMIN_PASS`: admin login credentials
- `INSTALL_TOKEN`: installer authorization token
- `DATA_ENCRYPTION_KEY`: encrypts sensitive lead data at rest
- `TRUST_PROXY`: set `true` only behind a trusted reverse proxy
- `CORS_ORIGINS`: allowed browser origins
- `REQUIRE_WIDGET_CALLER_HEADERS`: when `true` (recommended), widget API access requires `Origin`/`Referer` headers for non-local requests
- `INSTALL_MAINTENANCE_MODE`: set `true` only to intentionally reopen installer

## Installer Behavior

- First setup is at `/install`.
- After install, `/` and `/install` redirect to `/admin` (unless maintenance mode is enabled).
- To reinstall:
  1. set `INSTALL_MAINTENANCE_MODE=true`
  2. restart server
  3. open `/install`
  4. set `INSTALL_MAINTENANCE_MODE=false` after completion
- In production mode, installer actions require a valid `INSTALL_TOKEN`.

## Storage

Free edition uses JSON storage files in `data/`:
- `settings.json`
- `categories.json`
- `faqs.json`
- `sessions.json`
- `messages.json`
- `leads.json`
- `install.lock`

## Admin Pages

- `/admin` - Overview (stats and analytics)
- `/admin/settings` - chatbot and widget settings
- `/admin/faqs` - FAQ management
- `/admin/logs` - sessions, messages, leads

## Settings Overview

### Core Identity
- Chatbot name
- Avatar upload and shape
- Live preview toggle

### Messaging & Engagement
- Welcome and no-match messages
- Fuzzy match enable + threshold
- Lead capture enable + prompt

### Widget Appearance
- Widget visibility and position
- Widget size and animation
- Brand color and panel background
- Category display behavior

### System & Performance
- Admin page size
- Log retention days
- Auto cleanup
- Enforce HTTPS
- Enforce Admin CSRF

### Categories
- Add/manage categories
- Delete categories from Settings
- Category delete safety:
  - If category has FAQs and no duplicate category exists, delete is blocked
  - If duplicate categories exist with same normalized name, FAQs are auto-merged and duplicate can be deleted
- Select up to 3 recommended categories

### Embed Code & Domain Lock
- API base URL
- Widget domain policy (`restricted` recommended)
- Allowed widget domains (one per line)

## FAQ Management

- Add FAQ with category, keyword, question, and answer
- Edit and delete support
- Pagination support
- Mobile-friendly card layout
- File import supports `.txt`, `.csv`, `.csb`, `.docx`
- Delimiter import supports manual delimiter and auto-detection (`,`, `:`, `;`, `|`, tab) when left blank
- Import category handling modes:
  - Create missing categories from file
  - Always use selected category
- Import duplicate keyword handling:
  - Skip duplicate
  - Auto-suffix keyword
- Category names from import are normalized to prevent duplicate lookalike categories

## Logs

- Session list
- Session-specific chat messages
- Leads (name/email/session)
- Filters and pagination

## Embed in Frontend Website

Use embed code from `/admin/settings`, or:

```html
<script src="https://YOUR_CHATBOT_DOMAIN/widget.js" data-api-base="https://YOUR_CHATBOT_DOMAIN"></script>
```

## Go-Live Checklist

1. Set strong non-default values for:
   - `APP_SECRET`
   - `ADMIN_USER`
   - `ADMIN_PASS`
   - `INSTALL_TOKEN`
   - `DATA_ENCRYPTION_KEY`
2. Set `NODE_ENV=production`.
3. Use HTTPS.
4. Set widget domain policy to `restricted`.
5. Configure allowed widget domains.
6. Set strict `CORS_ORIGINS` (no `*`).
7. Keep `INSTALL_MAINTENANCE_MODE=false`.
8. Back up `data/` regularly.

## Notes

- This is the Free edition.
- Best for small websites and single-instance deployments.
- For larger/advanced usage, use Pro edition.
- Keep `.env` private and never expose it publicly.
