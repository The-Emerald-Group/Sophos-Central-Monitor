# 🛡️ Sophos Central Monitor

A lightweight, self-hosted Docker application that polls the **Sophos Central Partner API**, displays a live security alert dashboard, and sends **end-of-day email summaries** for newly registered endpoints.

---

## Features

- **Live alert dashboard** — real-time view of all security alerts across all managed tenants, with card and table views
- **Severity filtering** — filter by Critical, High, Medium, or Low with colour-coded indicators
- **Partner account support** — automatically enumerates all managed tenants via the Sophos Partner API
- **New device detection** — tracks endpoints registered today and accumulates them throughout the day
- **End-of-day email summary** — sends a formatted HTML email at a configurable time (default 23:00) listing all new devices registered that day
- **Multi-platform Docker image** — supports `linux/amd64` and `linux/arm64`
- **Persistent data** — alert data survives container restarts via a mounted Docker volume

---

## Screenshots

The dashboard auto-refreshes every 30 seconds and groups alerts by tenant, sorted with critical alerts first.

---

## Quick Start

### 1. Pull from Docker Hub

```bash
docker pull samuelstreets/sophos-central-monitor:latest
```

### 2. Run with Docker Compose

Copy the example below into a `docker-compose.yml` file, fill in your credentials, then run:

```bash
docker compose up -d
```

The dashboard will be available at **http://localhost:8083**.

---

## Configuration

All configuration is done via environment variables.

### Required

| Variable | Description |
|---|---|
| `SOPHOS_CLIENT_ID` | Your Sophos Central API client ID |
| `SOPHOS_CLIENT_SECRET` | Your Sophos Central API client secret |

### Email (optional but recommended)

| Variable | Default | Description |
|---|---|---|
| `SMTP_SERVER` | — | SMTP server hostname or IP |
| `SMTP_PORT` | `25` | SMTP port |
| `SMTP_USER` | — | SMTP username (leave blank for unauthenticated relay) |
| `SMTP_PASS` | — | SMTP password |
| `EMAIL_FROM` | — | Sender address |
| `EMAIL_TO` | — | Recipient address for daily summaries |

### Polling & Scheduling

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL` | `300` | How often to poll the Sophos API, in seconds |
| `EOD_HOUR` | `23` | Hour (0–23, server local time) at which the end-of-day summary email is sent |

---

## docker-compose.yml

```yaml
services:
  sophos-monitor:
    image: samuelstreets/sophos-central-monitor:latest
    container_name: sophos-monitor
    ports:
      - "8083:8080"
    volumes:
      - sophos_data:/sophos_data
    environment:
      - SOPHOS_CLIENT_ID=YOUR_CLIENT_ID_HERE
      - SOPHOS_CLIENT_SECRET=YOUR_CLIENT_SECRET_HERE
      - SMTP_SERVER=your.smtp.server.ip
      - SMTP_PORT=25
      - SMTP_USER=your_smtp_user
      - SMTP_PASS=your_smtp_password
      - EMAIL_FROM=alerts@yourdomain.com
      - EMAIL_TO=reports@yourdomain.com
      - POLL_INTERVAL=300
      - EOD_HOUR=23
      - PYTHONUNBUFFERED=1
    restart: always

volumes:
  sophos_data:
```

> **Note:** If you want to build the image locally instead of pulling from Docker Hub, replace `image:` with `build: .` and ensure the `Dockerfile`, `app.py`, and `index.html` are in the same directory.

---

## Obtaining Sophos API Credentials

1. Log in to **Sophos Central**.
2. Navigate to **Global Settings → API Credentials Management**.
3. Click **Add Credential**, give it a name, and set the role to **Partner Super Admin** (or appropriate partner role).
4. Copy the **Client ID** and **Client Secret** and set them as environment variables.

> The application uses the `client_credentials` OAuth2 flow. Credentials are never stored — a fresh token is obtained on each poll cycle.

---

## How It Works

1. **Auth** — obtains a short-lived OAuth2 token from `id.sophos.com`.
2. **Who Am I** — determines whether the account is a partner or a single tenant.
3. **Tenant enumeration** — for partner accounts, fetches all managed tenants with pagination.
4. **Per-tenant polling** — for each tenant, fetches all security alerts and all endpoints.
5. **New device detection** — checks each endpoint's registration timestamp; devices registered today are accumulated in memory.
6. **Dashboard update** — writes sorted alert data to `/sophos_data/data.json`, which the web UI reads every 30 seconds.
7. **EOD email** — a background scheduler thread fires once per day at `EOD_HOUR`. If any new devices were detected, a formatted HTML email is sent and the list is cleared for the next day.

---


## Health Check

The compose file includes a built-in health check that verifies the HTTP server is responding every 60 seconds:

```yaml
healthcheck:
  test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/data.json')"]
  interval: 60s
  timeout: 10s
  retries: 3
  start_period: 15s
```

---

## License

MIT — feel free to fork and adapt for your own MSP tooling.
