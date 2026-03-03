import os, requests, json, time, threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

SOPHOS_CLIENT_ID     = os.environ.get("SOPHOS_CLIENT_ID")
SOPHOS_CLIENT_SECRET = os.environ.get("SOPHOS_CLIENT_SECRET")
POLL_INTERVAL        = int(os.environ.get("POLL_INTERVAL", 300))

DATA_DIR  = "/sophos_data"
os.makedirs(DATA_DIR, exist_ok=True)
DATA_FILE = f"{DATA_DIR}/data.json"

AUTH_URL   = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
SEV_ORDER  = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def log(m): print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {m}", flush=True)


def write_data(payload):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def get_token():
    try:
        r = requests.post(AUTH_URL, data={
            "grant_type": "client_credentials",
            "client_id": SOPHOS_CLIENT_ID,
            "client_secret": SOPHOS_CLIENT_SECRET,
            "scope": "token"
        }, timeout=15)
        r.raise_for_status()
        return r.json().get("access_token")
    except Exception as e:
        log(f"!! Auth failed: {e}")
        return None


def get_whoami(token):
    try:
        r = requests.get(WHOAMI_URL, headers={"Authorization": f"Bearer {token}"}, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log(f"!! Whoami failed: {e}")
        return None


def fetch_alerts(token, tenant_id, base_url):
    alerts, page_key = [], None
    hdrs = {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_id, "Accept": "application/json"}
    url  = f"{base_url}/common/v1/alerts"
    while True:
        params = {"pageSize": 100}
        if page_key: params["pageFromKey"] = page_key
        try:
            r = requests.get(url, headers=hdrs, params=params, timeout=30)
            r.raise_for_status()
            d = r.json()
            alerts.extend(d.get("items", []))
            page_key = d.get("pages", {}).get("nextKey")
            if not page_key: break
        except Exception as e:
            log(f"!! Alerts page error: {e}"); break
    return alerts


def harvest():
    while True:
        log(">>> Harvesting Sophos Central alerts...")
        token = get_token()
        if not token:
            write_data({"timestamp": datetime.now().strftime("%H:%M:%S"), "total": 0,
                        "counts": {}, "alerts": [], "error": "Auth failed — check CLIENT_ID / CLIENT_SECRET."})
            time.sleep(POLL_INTERVAL); continue

        whoami = get_whoami(token)
        if not whoami or whoami.get("idType") != "tenant":
            write_data({"timestamp": datetime.now().strftime("%H:%M:%S"), "total": 0,
                        "counts": {}, "alerts": [], "error": "Invalid credential type — must be a Tenant API key."})
            time.sleep(POLL_INTERVAL); continue

        tenant_id  = whoami["id"]
        tenant_url = whoami.get("apiHosts", {}).get("dataRegion", "https://api.central.sophos.com")
        raw        = fetch_alerts(token, tenant_id, tenant_url)
        log(f"  Got {len(raw)} alert(s).")

        counts    = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        processed = []

        for a in raw:
            sev = (a.get("severity") or "low").lower()
            counts[sev if sev in counts else "low"] += 1

            raised_raw, raised_disp, raised_ts = a.get("raisedAt") or a.get("when") or "", "", 0
            if raised_raw:
                try:
                    dt = datetime.fromisoformat(raised_raw.replace("Z", "+00:00"))
                    raised_disp = dt.strftime("%d %b %Y  %H:%M")
                    raised_ts   = dt.timestamp()
                except Exception:
                    raised_disp = raised_raw[:16]

            device = (a.get("managedAgent") or {}).get("name") or a.get("location") or ""

            processed.append({
                "id":          a.get("id", ""),
                "description": a.get("description") or a.get("category") or "Unknown alert",
                "severity":    sev,
                "category":    a.get("category") or "Uncategorised",
                "type":        a.get("type") or "",
                "device":      device,
                "product":     a.get("product") or "",
                "raised":      raised_disp,
                "raised_ts":   raised_ts
            })

        processed.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), -x["raised_ts"]))

        write_data({"timestamp": datetime.now().strftime("%H:%M:%S"),
                    "total": len(processed), "counts": counts,
                    "alerts": processed, "error": None})
        log(f"*** Done — {len(processed)} alert(s). {counts}")
        time.sleep(POLL_INTERVAL)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send("/app/index.html", "text/html")
        elif path == "/data.json":
            self._send(DATA_FILE, "application/json")
        else:
            self.send_response(404); self.end_headers()

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
            self.send_response(503); self.end_headers()


if __name__ == "__main__":
    if not os.path.exists(DATA_FILE):
        write_data({"timestamp": "N/A", "total": 0, "counts": {}, "alerts": [],
                    "error": "Starting up — first harvest in progress..."})
    threading.Thread(target=harvest, daemon=True).start()
    log("Sophos Alerts Monitor running on :8080")
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 25))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
EMAIL_FROM = os.environ.get("EMAIL_FROM")
EMAIL_TO = os.environ.get("EMAIL_TO")

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", 300))

# --- PERSISTENT STORAGE ---
DATA_DIR = "/sophos_data"
os.makedirs(DATA_DIR, exist_ok=True)
STATE_FILE = f"{DATA_DIR}/known_endpoints.json"
DATA_FILE = f"{DATA_DIR}/data.json"

SOPHOS_AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
SOPHOS_API_URL = "https://api.central.sophos.com"


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# --- SOPHOS AUTH ---
def get_sophos_token():
    try:
        res = requests.post(SOPHOS_AUTH_URL, data={
            "grant_type": "client_credentials",
            "client_id": SOPHOS_CLIENT_ID,
            "client_secret": SOPHOS_CLIENT_SECRET,
            "scope": "token"
        }, timeout=15)
        res.raise_for_status()
        return res.json().get("access_token")
    except Exception as e:
        log(f"!! Sophos auth failed: {e}")
        return None


def get_whoami(token):
    try:
        res = requests.get(f"{SOPHOS_API_URL}/whoami/v1", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }, timeout=15)
        res.raise_for_status()
        return res.json()
    except Exception as e:
        log(f"!! Sophos whoami failed: {e}")
        return None


def fetch_all_endpoints(token, tenant_id, tenant_url):
    """Fetch every endpoint from Sophos Central, handling pagination."""
    endpoints = []
    page_key = None
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": tenant_id,
        "Accept": "application/json"
    }
    base = f"{tenant_url}/endpoint/v1/endpoints"

    while True:
        params = {"pageSize": 500}
        if page_key:
            params["pageFromKey"] = page_key
        try:
            res = requests.get(base, headers=headers, params=params, timeout=30)
            res.raise_for_status()
            data = res.json()
            endpoints.extend(data.get("items", []))
            next_key = data.get("pages", {}).get("nextKey")
            if not next_key:
                break
            page_key = next_key
        except Exception as e:
            log(f"!! Error fetching endpoints page: {e}")
            break

    return endpoints


# --- EMAIL ---
def send_new_device_alert(new_devices):
    if not SMTP_SERVER or not EMAIL_TO:
        log("-- SMTP not configured, skipping email.")
        return False

    count = len(new_devices)
    s_plural = "s" if count > 1 else ""
    subject = f"🆕 {count} New Sophos Endpoint{s_plural} Detected"

    table_rows = ""
    for d in new_devices:
        registered = d.get("registered", "Unknown")
        os_name = d.get("os", "Unknown OS")
        group = d.get("group", "Ungrouped")
        assigned_user = d.get("user", "—")
        table_rows += f"""
        <tr>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;font-weight:bold;color:#222;">{d['name']}</td>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;color:#666;">{os_name}</td>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;color:#666;">{group}</td>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;color:#666;">{assigned_user}</td>
          <td style="padding:10px 15px;border-bottom:1px solid #eaeaea;color:#00A1E4;">{registered}</td>
        </tr>
        """

    html_body = f"""
    <html>
      <body style="font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background-color:#f4f5f7;margin:0;padding:30px 10px;">
        <div style="max-width:700px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 4px 15px rgba(0,0,0,0.05);">
          <div style="background-color:#0073CF;color:#ffffff;padding:20px;text-align:center;">
            <h2 style="margin:0;font-size:22px;letter-spacing:1px;">🆕 NEW ENDPOINT{s_plural.upper()} DETECTED</h2>
          </div>
          <div style="padding:30px;">
            <p style="font-size:16px;color:#444;line-height:1.5;margin-top:0;">
              The Sophos Central monitor has detected <b>{count} new endpoint{s_plural}</b> registered since the last harvest. Please review these devices to confirm they are authorised.
            </p>
            <table style="width:100%;border-collapse:collapse;margin-top:20px;margin-bottom:25px;background-color:#f9f9f9;border-radius:6px;overflow:hidden;text-align:left;">
              <tr style="background-color:#eaeaea;">
                <th style="padding:12px 15px;color:#444;font-size:14px;">Hostname</th>
                <th style="padding:12px 15px;color:#444;font-size:14px;">OS</th>
                <th style="padding:12px 15px;color:#444;font-size:14px;">Group</th>
                <th style="padding:12px 15px;color:#444;font-size:14px;">User</th>
                <th style="padding:12px 15px;color:#444;font-size:14px;">Registered</th>
              </tr>
              {table_rows}
            </table>
            <h3 style="color:#222;font-size:16px;margin-bottom:10px;border-bottom:2px solid #0073CF;display:inline-block;padding-bottom:5px;">Recommended Actions</h3>
            <ul style="color:#555;line-height:1.6;padding-left:20px;font-size:14px;">
              <li style="margin-bottom:6px;"><b>Verify ownership:</b> Confirm the device belongs to a known user or department.</li>
              <li style="margin-bottom:6px;"><b>Check group assignment:</b> Ensure the device has been placed in the correct policy group.</li>
              <li style="margin-bottom:6px;"><b>Review in Sophos Central:</b> Log in to confirm tamper protection and policies are applied.</li>
              <li style="margin-bottom:6px;"><b>Investigate unknowns:</b> Unrecognised devices should be isolated and investigated immediately.</li>
            </ul>
          </div>
          <div style="background-color:#f1f1f1;padding:15px;text-align:center;color:#888;font-size:12px;border-top:1px solid #eaeaea;">
            <strong>Emerald IT</strong> • Automated Sophos Central Monitoring
          </div>
        </div>
      </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

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


# --- HARVEST LOOP ---
def harvest_data():
    # Load known endpoints from disk
    known_ids = set()
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                known_ids = set(json.load(f))
            log(f"Loaded {len(known_ids)} known endpoint IDs from state file.")
        except Exception:
            pass

    first_run = len(known_ids) == 0

    while True:
        log(">>> Starting Sophos Central Harvest...")

        token = get_sophos_token()
        if not token:
            log("!! Could not obtain token, retrying next interval.")
            time.sleep(POLL_INTERVAL)
            continue

        whoami = get_whoami(token)
        if not whoami:
            log("!! Could not get tenant info, retrying next interval.")
            time.sleep(POLL_INTERVAL)
            continue

        id_type = whoami.get("idType")
        tenant_id = whoami.get("id")

        # Resolve tenant API URL
        if id_type == "tenant":
            tenant_url = whoami.get("apiHosts", {}).get("dataRegion", SOPHOS_API_URL)
        elif id_type == "partner":
            # For partners: iterate sub-tenants (advanced use)
            log("!! Partner accounts are not yet supported — please use a tenant credential.")
            time.sleep(POLL_INTERVAL)
            continue
        else:
            log(f"!! Unrecognised idType: {id_type}")
            time.sleep(POLL_INTERVAL)
            continue

        endpoints = fetch_all_endpoints(token, tenant_id, tenant_url)
        log(f"Fetched {len(endpoints)} total endpoints from Sophos Central.")

        current_ids = set()
        all_device_data = []
        new_devices = []

        for ep in endpoints:
            ep_id = ep.get("id")
            if not ep_id:
                continue
            current_ids.add(ep_id)

            hostname = ep.get("hostname") or ep.get("name") or "Unknown"
            os_info = ep.get("os", {})
            os_name = f"{os_info.get('name', '')} {os_info.get('majorVersion', '')}".strip() or "Unknown OS"
            group = ep.get("group", {}).get("name", "Ungrouped") if isinstance(ep.get("group"), dict) else "Ungrouped"
            
            assigned_user = "—"
            if ep.get("associatedPerson"):
                p = ep["associatedPerson"]
                assigned_user = p.get("name") or p.get("viaLogin") or "—"

            health = ep.get("health", {}).get("overall", "unknown")
            registered_raw = ep.get("assignedAt") or ep.get("registeredAt") or ""
            registered_display = ""
            if registered_raw:
                try:
                    dt = datetime.fromisoformat(registered_raw.replace("Z", "+00:00"))
                    registered_display = dt.strftime("%d %b %Y %H:%M")
                except Exception:
                    registered_display = registered_raw[:16]

            device_record = {
                "id": ep_id,
                "name": hostname,
                "os": os_name,
                "group": group,
                "user": assigned_user,
                "health": health,
                "registered": registered_display,
                "type": ep.get("type", "unknown")
            }
            all_device_data.append(device_record)

            if ep_id not in known_ids:
                new_devices.append(device_record)

        if first_run:
            log(f"First run — seeding state with {len(current_ids)} endpoints. No alert will be sent.")
            first_run = False
        elif new_devices:
            log(f">>> {len(new_devices)} new endpoint(s) detected! Sending alert...")
            send_new_device_alert(new_devices)
        else:
            log("No new endpoints detected this harvest.")

        # Update known IDs state
        known_ids = current_ids
        with open(STATE_FILE, "w") as f:
            json.dump(list(known_ids), f)

        # Write dashboard data
        now_str = datetime.now().strftime("%H:%M:%S")
        dashboard = {
            "timestamp": now_str,
            "total": len(all_device_data),
            "new_this_harvest": len(new_devices) if not first_run else 0,
            "devices": sorted(all_device_data, key=lambda x: x["name"].lower())
        }
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(dashboard, f, indent=4)

        log(f"*** HARVEST COMPLETE: {len(all_device_data)} endpoints tracked. ***")
        time.sleep(POLL_INTERVAL)


# --- HTTP SERVER ---
class MyHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.path = "/index.html"
            return SimpleHTTPRequestHandler.do_GET(self)
        if self.path.startswith("/data.json"):
            try:
                with open(DATA_FILE, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(content)
            except Exception:
                self.send_response(503)
                self.end_headers()
            return
        SimpleHTTPRequestHandler.do_GET(self)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Access-Control-Allow-Origin", "*")
        SimpleHTTPRequestHandler.end_headers(self)


if __name__ == "__main__":
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump({"timestamp": "N/A", "total": 0, "new_this_harvest": 0, "devices": []}, f)
    threading.Thread(target=harvest_data, daemon=True).start()
    log("Sophos Central Monitor started on port 8080")
    HTTPServer(("0.0.0.0", 8080), MyHandler).serve_forever()
