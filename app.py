import os, requests, json, time, threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SOPHOS_CLIENT_ID     = os.environ.get("SOPHOS_CLIENT_ID")
SOPHOS_CLIENT_SECRET = os.environ.get("SOPHOS_CLIENT_SECRET")
POLL_INTERVAL        = int(os.environ.get("POLL_INTERVAL", 300))

DATA_DIR  = "/sophos_data"
os.makedirs(DATA_DIR, exist_ok=True)
DATA_FILE = f"{DATA_DIR}/data.json"

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
# Partner: list all managed tenants
# ---------------------------------------------------------------------------
def get_partner_tenants(token, partner_id):
    tenants, page_key = [], None
    hdrs = {
        "Authorization": f"Bearer {token}",
        "X-Partner-ID":  partner_id,
        "Accept":        "application/json"
    }
    while True:
        params = {"pageSize": 100}
        if page_key:
            params["pageFromKey"] = page_key
        try:
            r = requests.get(f"{PARTNER_API_URL}/partner/v1/tenants",
                             headers=hdrs, params=params, timeout=30)
            r.raise_for_status()
            d = r.json()
            tenants.extend(d.get("items", []))
            page_key = d.get("pages", {}).get("nextKey")
            if not page_key:
                break
        except Exception as e:
            log(f"!! Error listing tenants: {e}")
            break
    return tenants


# ---------------------------------------------------------------------------
# Alerts for a single tenant
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
# Main harvest loop
# ---------------------------------------------------------------------------
def harvest():
    while True:
        log(">>> Harvesting Sophos Central alerts...")

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
                        "error": "Could not reach Sophos API — check credentials."})
            time.sleep(POLL_INTERVAL)
            continue

        id_type = whoami.get("idType")
        log(f"  Account type: {id_type}")

        all_processed  = []
        tenants_polled = 0

        # ── PARTNER: enumerate sub-tenants ───────────────────────────────────
        if id_type == "partner":
            partner_id = whoami["id"]
            log(f"  Partner ID: {partner_id} — fetching managed tenants...")
            tenants = get_partner_tenants(token, partner_id)
            log(f"  Found {len(tenants)} managed tenant(s).")

            for tenant in tenants:
                t_id   = tenant.get("id")
                t_name = tenant.get("showAs") or tenant.get("name") or t_id
                t_url  = tenant.get("apiHost") or tenant.get("dataRegion") or PARTNER_API_URL
                if isinstance(t_url, dict):
                    t_url = t_url.get("dataRegion", PARTNER_API_URL)

                log(f"    Polling: {t_name}")
                raw = fetch_alerts_for_tenant(token, t_id, t_url)
                log(f"      -> {len(raw)} alert(s)")
                tenants_polled += 1
                for a in raw:
                    all_processed.append(parse_alert(a, tenant_name=t_name))

        # ── TENANT: query directly ───────────────────────────────────────────
        elif id_type == "tenant":
            tenant_id  = whoami["id"]
            tenant_url = whoami.get("apiHosts", {}).get("dataRegion", PARTNER_API_URL)
            raw = fetch_alerts_for_tenant(token, tenant_id, tenant_url)
            tenants_polled = 1
            for a in raw:
                all_processed.append(parse_alert(a))

        else:
            write_data({"timestamp": datetime.now().strftime("%H:%M:%S"),
                        "total": 0, "counts": {}, "alerts": [], "tenants_polled": 0,
                        "error": f"Unrecognised account type: '{id_type}'."})
            time.sleep(POLL_INTERVAL)
            continue

        # ── Sort & count ─────────────────────────────────────────────────────
        all_processed.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), -x["raised_ts"]))

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in all_processed:
            counts[a["severity"] if a["severity"] in counts else "low"] += 1

        write_data({
            "timestamp":      datetime.now().strftime("%H:%M:%S"),
            "total":          len(all_processed),
            "tenants_polled": tenants_polled,
            "counts":         counts,
            "alerts":         all_processed,
            "error":          None
        })

        log(f"*** Done — {len(all_processed)} alert(s) across {tenants_polled} tenant(s). {counts}")
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
