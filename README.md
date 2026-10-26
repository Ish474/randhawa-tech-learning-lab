# Randhawa's Tech Learning Lab

Randhawa's Tech Learning Lab is a Flask + SQLite learning platform with browser-based rooms, saved progress, fighting-style learning games, learner accounts, and a master-admin role.

## Run Locally

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Set the required environment variables before the first run:

```bash
export NULLSPACE_SECRET_KEY="replace-with-a-long-random-value"
export MASTER_ADMIN_EMAIL="admin@example.com"
export MASTER_ADMIN_PASSWORD="replace-with-a-strong-password"
python3 app.py
```

Open `http://127.0.0.1:5000`.

The first configured admin account is created on startup. New learners verify their email with a six-digit OTP before registration. Progress, quest XP, and OTP records are stored in `instance/nullspace.sqlite3`.

## Deploy On Render

Connect this repository to Render and choose **New Blueprint**. Render will read `render.yaml`, install Gunicorn, enable HTTPS, and mount persistent storage for the SQLite database and media. Set the values marked `sync: false` in the Render dashboard. Keep `OTP_DEV_MODE=0` in production.

## OTP Delivery

Set the `OTP_SMTP_*` variables for email delivery. Set `OTP_DEV_MODE=1` only for local testing; it displays the generated code in the response and browser instead of sending it. Never enable that mode on a public deployment.

## Course Management

Sign in as the master admin and open **Admin console**. Courses and modules are stored in SQLite, so an admin can create, edit, publish, unpublish, or delete them. Module edits include the lesson explanation, example code, practice task, checkpoint content, answer choices, hint, and game mode.

Use **Generate fresh questions** on a course to create content-aware, module-specific questions from the title, explanation, code, task, steps, and answer choices. It works locally by default; setting `OPENAI_API_KEY` enables richer AI-generated variants on the server without exposing the key to browsers.

Available game modes are **Duel**, **Boss battle**, **Speed race**, and **Base defense**. Correct answers damage the opponent and advance to the next round; incorrect answers show the explanation, damage the player, and then advance automatically.

## Security and Ownership

Mutating API requests require a session-bound CSRF token. Authentication and API routes have rate limits, passwords require upper/lowercase letters plus a digit, new accounts require email OTP verification, uploads are limited to approved image/video MIME types and 25 MB, and responses include security headers. Enable `NULLSPACE_COOKIE_SECURE=1` behind HTTPS.

The configured master admin controls site identity, copyright, logo, approved media, courses, modules, publishing, and game modes from **Admin console**. Arbitrary code/file uploads are intentionally not allowed because that would turn the admin panel into a remote-code-execution surface.

The terminal and fighting games are intentionally simulated in the browser. For public use, deploy behind HTTPS with Gunicorn or another production WSGI server, configure SMTP, use database backups, move rate limiting to Redis/proxy infrastructure, add audit logs and upload malware scanning, and never expose development OTP codes.
