import os, requests, json, time, threading, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SOPHOS_CLIENT_ID     = os.environ.get("SOPHOS_CLIENT_ID")
SOPHOS_CLIENT_SECRET = os.environ.get("SOPHOS_CLIENT_SECRET")
POLL_INTERVAL        = int(os.environ.get("POLL_INTERVAL", 300))

SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT   = int(os.environ.get("SMTP_PORT", 25))
SMTP_USER   = os.environ.get("SMTP_USER")
SMTP_PASS   = os.environ.get("SMTP_PASS")
EMAIL_FROM  = os.environ.get("EMAIL_FROM")
EMAIL_TO    = os.environ.get("EMAIL_TO")

DATA_DIR   = "/sophos_data"
os.makedirs(DATA_DIR, exist_ok=True)
DATA_FILE  = f"{DATA_DIR}/data.json"
STATE_FILE = f"{DATA_DIR}/known_endpoints.json"

AUTH_URL        = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL      = "https://api.central.sophos.com/whoami/v1"
PARTNER_API_URL = "https://api.central.sophos.com"
SEV_ORDER       = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def log(m): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {m}", flush=True)


def write_data(payload):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def get_token():
    try:
        r = requests.post(AUTH_URL, data={
            "grant_type":    "client_credentials",
            "client_id":     SOPHOS_CLIENT_ID,
            "client_secret": SOPHOS_CLIENT_SECRET,
            "scope":         "token"
        }, timeout=15)
        r.raise_for_status()
        return r.json().get("access_token")
    except Exception as e:
        log(f"!! Auth failed: {e}")
        return None


def get_whoami(token):
    try:
        r = requests.get(WHOAMI_URL,
                         headers={"Authorization": f"Bearer {token}"},
                         timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log(f"!! Whoami failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Partner: list ALL managed tenants (integer page-based pagination)
# ---------------------------------------------------------------------------
def get_partner_tenants(token, partner_id):
    tenants  = []
    page_num = 1
    hdrs = {
        "Authorization": f"Bearer {token}",
        "X-Partner-ID":  partner_id,
        "Accept":        "application/json"
    }
    while True:
        try:
            r = requests.get(
                f"{PARTNER_API_URL}/partner/v1/tenants",
                headers=hdrs,
                params={"pageSize": 100, "page": page_num},
                timeout=30
            )
            r.raise_for_status()
            d     = r.json()
            items = d.get("items", [])
            tenants.extend(items)
            log(f"  Tenant page {page_num}: got {len(items)} tenant(s) (total so far: {len(tenants)})")

            pages     = d.get("pages", {})
            current   = pages.get("current", page_num)
            total_pgs = pages.get("total", 1)

            if current >= total_pgs or not items:
                break
            page_num += 1

        except Exception as e:
            log(f"!! Error fetching tenant page {page_num}: {e}")
            break

    log(f"  Total tenants fetched: {len(tenants)}")
    return tenants


# ---------------------------------------------------------------------------
# Fetch security alerts for a single tenant (dashboard)
# ---------------------------------------------------------------------------
def fetch_alerts_for_tenant(token, tenant_id, tenant_url):
    alerts, page_key = [], None
    hdrs = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID":   tenant_id,
        "Accept":        "application/json"
    }
    url = f"{tenant_url}/common/v1/alerts"
    while True:
        params = {"pageSize": 100}
        if page_key:
            params["pageFromKey"] = page_key
        try:
            r = requests.get(url, headers=hdrs, params=params, timeout=30)
            r.raise_for_status()
            d = r.json()
            alerts.extend(d.get("items", []))
            page_key = d.get("pages", {}).get("nextKey")
            if not page_key:
                break
        except Exception as e:
            log(f"!! Alerts fetch error for tenant {tenant_id}: {e}")
            break
    return alerts


# ---------------------------------------------------------------------------
# Fetch all endpoints for a single tenant (new device detection)
# ---------------------------------------------------------------------------
def fetch_endpoints_for_tenant(token, tenant_id, tenant_url):
    endpoints, page_key = [], None
    hdrs = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID":   tenant_id,
        "Accept":        "application/json"
    }
    url = f"{tenant_url}/endpoint/v1/endpoints"
    while True:
        params = {"pageSize": 500}
        if page_key:
            params["pageFromKey"] = page_key
        try:
            r = requests.get(url, headers=hdrs, params=params, timeout=30)
            r.raise_for_status()
            d = r.json()
            endpoints.extend(d.get("items", []))
            page_key = d.get("pages", {}).get("nextKey")
            if not page_key:
                break
        except Exception as e:
            log(f"!! Endpoints fetch error for tenant {tenant_id}: {e}")
            break
    return endpoints


# ---------------------------------------------------------------------------
# Parse a raw Sophos alert into a clean dict
# ---------------------------------------------------------------------------
def parse_alert(a, tenant_name=""):
    sev = (a.get("severity") or "low").lower()
    if sev not in SEV_ORDER:
        sev = "low"

    raised_raw  = a.get("raisedAt") or a.get("when") or ""
    raised_disp = ""
    raised_ts   = 0
    if raised_raw:
        try:
            dt          = datetime.fromisoformat(raised_raw.replace("Z", "+00:00"))
            raised_disp = dt.strftime("%d %b %Y  %H:%M")
            raised_ts   = dt.timestamp()
        except Exception:
            raised_disp = raised_raw[:16]

    device = (a.get("managedAgent") or {}).get("name") or a.get("location") or ""

    return {
        "id":          a.get("id", ""),
        "tenant":      tenant_name,
        "description": a.get("description") or a.get("category") or "Unknown alert",
        "severity":    sev,
        "category":    a.get("category") or "Uncategorised",
        "type":        a.get("type") or "",
        "device":      device,
        "product":     a.get("product") or "",
        "raised":      raised_disp,
        "raised_ts":   raised_ts
    }


# ---------------------------------------------------------------------------
# Email: new device alert
# ---------------------------------------------------------------------------
def send_new_device_email(new_devices):
    if not SMTP_SERVER or not EMAIL_TO:
        log("-- SMTP not configured, skipping email.")
        return False

    count  = len(new_devices)
    plural = "s" if count > 1 else ""
    subject = f"New Sophos Endpoint{plural} Detected — {count} Machine{plural} Registered"

    table_rows = ""
    for d in new_devices:
        table_rows += f"""
        <tr>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;font-weight:bold;color:#222;">{d['hostname']}</td>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;color:#666;">{d['os']}</td>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;color:#666;">{d['tenant']}</td>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;color:#666;">{d['group']}</td>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;color:#00A1E4;">{d['registered']}</td>
        </tr>"""

    html = f"""
    <html>
      <body style="font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f4f5f7;margin:0;padding:30px 10px;">
        <div style="max-width:700px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 4px 15px rgba(0,0,0,0.05);">
          <div style="background:#0073CF;color:#fff;padding:20px;text-align:center;">
            <h2 style="margin:0;font-size:22px;letter-spacing:1px;">&#x1F4BB; NEW ENDPOINT{plural.upper()} DETECTED</h2>
          </div>
          <div style="padding:30px;">
            <p style="font-size:16px;color:#444;line-height:1.5;margin-top:0;">
              The Sophos Central monitor has detected <b>{count} new endpoint{plural}</b> registered since
              the last harvest. Please review these machines to confirm they are authorised.
            </p>
            <table style="width:100%;border-collapse:collapse;margin-top:20px;margin-bottom:25px;
                          background:#f9f9f9;border-radius:6px;overflow:hidden;text-align:left;">
              <tr style="background:#eaeaea;">
                <th style="padding:12px 15px;color:#444;font-size:14px;">Hostname</th>
                <th style="padding:12px 15px;color:#444;font-size:14px;">OS</th>
                <th style="padding:12px 15px;color:#444;font-size:14px;">Tenant</th>
                <th style="padding:12px 15px;color:#444;font-size:14px;">Group</th>
                <th style="padding:12px 15px;color:#444;font-size:14px;">Registered</th>
              </tr>
              {table_rows}
            </table>
            <h3 style="color:#222;font-size:16px;margin-bottom:10px;border-bottom:2px solid #0073CF;
                       display:inline-block;padding-bottom:5px;">Recommended Actions</h3>
            <ul style="color:#555;line-height:1.6;padding-left:20px;font-size:14px;">
              <li style="margin-bottom:6px;"><b>Verify ownership:</b> Confirm the device belongs to a known user or department.</li>
              <li style="margin-bottom:6px;"><b>Check group assignment:</b> Ensure the device is in the correct policy group.</li>
              <li style="margin-bottom:6px;"><b>Review in Sophos Central:</b> Confirm tamper protection and policies are applied.</li>
              <li style="margin-bottom:6px;"><b>Investigate unknowns:</b> Unrecognised devices should be isolated immediately.</li>
            </ul>
          </div>
          <div style="background:#f1f1f1;padding:15px;text-align:center;color:#888;font-size:12px;border-top:1px solid #eaeaea;">
            <strong>Emerald IT</strong> &bull; Automated Sophos Central Monitoring
          </div>
        </div>
      </body>
    </html>"""

    msg = MIMEMultipart("alternative")
    msg["From"]    = EMAIL_FROM
    msg["To"]      = EMAIL_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(html, "html"))

    for attempt in range(1, 4):
        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            log(f"*** EMAIL SENT: {subject} ***")
            try: server.quit()
            except Exception: pass
            return True
        except Exception as e:
            log(f"!! Email attempt {attempt} failed: {e}")
            time.sleep(5)
    return False


# ---------------------------------------------------------------------------
# Main harvest loop
# ---------------------------------------------------------------------------
def harvest():
    # Load known endpoint IDs from disk
    known_ids = set()
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                known_ids = set(json.load(f))
            log(f"Loaded {len(known_ids)} known endpoint IDs.")
        except Exception:
            pass

    first_run = len(known_ids) == 0

    while True:
        log(">>> Harvesting Sophos Central...")

        token = get_token()
        if not token:
            write_data({"timestamp": datetime.now().strftime("%H:%M:%S"),
                        "total": 0, "counts": {}, "alerts": [], "tenants_polled": 0,
                        "error": "Auth failed — check SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET."})
            time.sleep(POLL_INTERVAL)
            continue

        whoami = get_whoami(token)
        if not whoami:
            write_data({"timestamp": datetime.now().strftime("%H:%M:%S"),
                        "total": 0, "counts": {}, "alerts": [], "tenants_polled": 0,
                        "error": "Could not reach Sophos API."})
            time.sleep(POLL_INTERVAL)
            continue

        id_type = whoami.get("idType")
        log(f"  Account type: {id_type}")

        # Build tenant list
        tenant_list = []

        if id_type == "partner":
            partner_id = whoami["id"]
            log(f"  Partner ID: {partner_id} — fetching managed tenants...")
            tenants = get_partner_tenants(token, partner_id)
            for t in tenants:
                t_url = t.get("apiHost") or t.get("dataRegion") or PARTNER_API_URL
                if isinstance(t_url, dict):
                    t_url = t_url.get("dataRegion", PARTNER_API_URL)
                tenant_list.append({
                    "id":   t.get("id"),
                    "name": t.get("showAs") or t.get("name") or t.get("id"),
                    "url":  t_url
                })

        elif id_type == "tenant":
            tenant_list.append({
                "id":   whoami["id"],
                "name": "",
                "url":  whoami.get("apiHosts", {}).get("dataRegion", PARTNER_API_URL)
            })

        else:
            write_data({"timestamp": datetime.now().strftime("%H:%M:%S"),
                        "total": 0, "counts": {}, "alerts": [], "tenants_polled": 0,
                        "error": f"Unrecognised account type: '{id_type}'."})
            time.sleep(POLL_INTERVAL)
            continue

        # ── Per-tenant: fetch alerts + endpoints ─────────────────────────────
        all_alerts  = []
        new_devices = []
        current_ids = set()

        for t in tenant_list:
            t_id, t_name, t_url = t["id"], t["name"], t["url"]
            log(f"  Polling: {t_name or t_id}")

            # Security alerts → dashboard
            raw_alerts = fetch_alerts_for_tenant(token, t_id, t_url)
            for a in raw_alerts:
                all_alerts.append(parse_alert(a, tenant_name=t_name))

            # Endpoints → new device email
            raw_endpoints = fetch_endpoints_for_tenant(token, t_id, t_url)
            log(f"    {len(raw_alerts)} alert(s), {len(raw_endpoints)} endpoint(s)")

            for ep in raw_endpoints:
                ep_id = ep.get("id")
                if not ep_id:
                    continue
                current_ids.add(ep_id)

                if ep_id not in known_ids and not first_run:
                    hostname = ep.get("hostname") or ep.get("name") or "Unknown"
                    os_info  = ep.get("os", {})
                    os_name  = f"{os_info.get('name', '')} {os_info.get('majorVersion', '')}".strip() or "Unknown OS"
                    group    = (ep.get("group") or {}).get("name", "Ungrouped")

                    reg_raw  = ep.get("assignedAt") or ep.get("registeredAt") or ""
                    reg_disp = ""
                    if reg_raw:
                        try:
                            reg_disp = datetime.fromisoformat(
                                reg_raw.replace("Z", "+00:00")
                            ).strftime("%d %b %Y %H:%M")
                        except Exception:
                            reg_disp = reg_raw[:16]

                    new_devices.append({
                        "hostname":   hostname,
                        "os":         os_name,
                        "tenant":     t_name or "—",
                        "group":      group,
                        "registered": reg_disp
                    })

        # ── New device email ──────────────────────────────────────────────────
        if first_run:
            log(f"First run — seeding {len(current_ids)} known endpoints. No email sent.")
            first_run = False
        elif new_devices:
            log(f">>> {len(new_devices)} new device(s) found — sending email...")
            send_new_device_email(new_devices)
        else:
            log("  No new devices detected.")

        # Persist known endpoint IDs
        known_ids = current_ids
        with open(STATE_FILE, "w") as f:
            json.dump(list(known_ids), f)

        # ── Sort alerts and write dashboard ───────────────────────────────────
        all_alerts.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), -x["raised_ts"]))

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in all_alerts:
            counts[a["severity"] if a["severity"] in counts else "low"] += 1

        write_data({
            "timestamp":      datetime.now().strftime("%H:%M:%S"),
            "total":          len(all_alerts),
            "tenants_polled": len(tenant_list),
            "counts":         counts,
            "alerts":         all_alerts,
            "error":          None
        })

        log(f"*** Done — {len(all_alerts)} alert(s), {len(new_devices)} new device(s), "
            f"{len(tenant_list)} tenant(s). {counts}")
        time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send("/app/index.html", "text/html")
        elif path == "/data.json":
            self._send(DATA_FILE, "application/json")
        else:
            self.send_response(404)
            self.end_headers()

    def _send(self, fp, ct):
        try:
            data = open(fp, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Cache-Control", "no-store,no-cache,must-revalidate,max-age=0")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_response(503)
            self.end_headers()


if __name__ == "__main__":
    if not os.path.exists(DATA_FILE):
        write_data({"timestamp": "N/A", "total": 0, "counts": {}, "alerts": [],
                    "tenants_polled": 0,
                    "error": "Starting up — first harvest in progress..."})
    threading.Thread(target=harvest, daemon=True).start()
    log("Sophos Alerts Monitor running on :8080")
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
