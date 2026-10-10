"""
CyberSentry end-to-end proof. Run it with the API up and read the output aloud --
it walks the whole pipeline and asserts the safety properties that matter.

    python -m uvicorn main:app --port 8000     # terminal 1
    python smoke_test.py                       # terminal 2
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = os.getenv("CYBERSENTRY_API", "http://127.0.0.1:8000")
DB = Path(os.getenv("CYBERSENTRY_DB") or Path(__file__).with_name("cybersentry.db"))
PASS, FAIL = "  [PASS]", "  [FAIL]"
failures: list[str] = []


def call(path: str, token: str | None = None, form: dict | None = None, post: bool = False,
         text: str | None = None):
    headers: dict[str, str] = {}
    body: bytes | None = None
    method = "GET"
    if text is not None:
        body, method = text.encode(), "POST"
        headers["Content-Type"] = "text/plain"
    elif form is not None:
        body = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        method = "POST"
    elif post:
        body, method = b"", "POST"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach {BASE} -- is the API running?  ({e.reason})")


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"{PASS if condition else FAIL} {label}{'  |  ' + detail if detail else ''}")
    if not condition:
        failures.append(label)


def token_for(username: str) -> str:
    status, body = call("/api/auth/login", form={"username": username, "password": "cybersentry"})
    if status != 200:
        sys.exit(f"Could not sign in as {username}: {body}")
    return body["access_token"]


print("\n-- 1. Service and authentication ----------------------------------------")
status, health = call("/health")
check("API is up", status == 200, f"agent: {health.get('agent')} | "
                                 f"{health.get('rules')} rules | {health.get('playbooks')} playbooks")
admin, analyst = token_for("admin"), token_for("analyst")
check("admin and analyst can sign in", bool(admin and analyst))
check("a wrong password is rejected",
      call("/api/auth/login", form={"username": "admin", "password": "wrong"})[0] == 401)
check("an unauthenticated read is rejected", call("/api/events")[0] == 401)
check("an analyst cannot launch a simulation",
      call("/api/simulate/S1", token=analyst, post=True)[0] == 403)

print("\n-- 2. Detect -> investigate -> respond, on all five scenarios -------------")
incidents = []
for key in ("S1", "S2", "S3", "S4", "S5"):
    status, body = call(f"/api/simulate/{key}", token=admin, post=True)
    found = body.get("incidents", [])
    check(f"{key} is detected and handled", status == 200 and len(found) == 1,
          (f"{found[0]['rule_id']} | {found[0]['severity']} | risk {found[0]['risk_score']} | "
           f"detect {found[0]['detect_ms']}ms | respond {found[0]['respond_ms']}ms | "
           f"{found[0]['actions']} actions") if found else "no incident raised")
    incidents += found

print("\n-- 2b. Real log ingestion (OpenSSH syslog format) ---------------------")
# Same shape as real sshd lines in /var/log/auth.log and the Loghub dataset.
ssh_log = "\n".join(
    [f"Dec 10 08:24:{n:02d} LabSZ sshd[24361]: Failed password for invalid user admin "
     f"from 5.188.10.180 port 36279 ssh2" for n in range(12)]
    + ["Dec 10 08:25:01 LabSZ sshd[24363]: Connection closed by 5.188.10.180 [preauth]",
       "this line is not syslog and is skipped"])
check("ingesting needs the admin role",
      call("/api/ingest/ssh", token=analyst, text=ssh_log)[0] == 403)
status, ingested = call("/api/ingest/ssh", token=admin, text=ssh_log)
found = ingested.get("incidents", [])
check("real SSH lines are parsed and the brute force is detected",
      status == 200 and ingested["events"] == 13 and len(found) == 1
      and found[0]["rule_id"] == "R1_BRUTE_FORCE" and found[0]["severity"] == "high",
      f"{ingested.get('by_type')} | " + (found[0]["title"] if found else "no incident raised"))
status, detail = call(f"/api/incidents/{found[0]['incident_id']}", token=admin) if found else (0, {})
report = detail.get("report") or {}
check("the report describes the real attacker, not a scripted story",
      "5.188.10.180" in report.get("summary", "") and "j.martinez" not in json.dumps(report),
      report.get("summary", "")[:90])
incidents += found

print("\n-- 3. The agent explained itself ----------------------------------------")
for inc in incidents:
    status, detail = call(f"/api/incidents/{inc['incident_id']}", token=admin)
    report = detail.get("report") or {}
    complete = all(report.get(k) for k in
                   ("summary", "root_cause", "attack_chain", "mitre",
                    "affected_assets", "recommended_actions"))
    check(f"incident #{inc['incident_id']} has a complete report", status == 200 and complete,
          f"{len(detail.get('events', []))} events correlated | {len(report.get('trace', []))} "
          f"tool calls | {', '.join(m['id'] for m in report.get('mitre', []))}")

print("\n-- 4. The guard-rail: the AI proposes, policy disposes ------------------")
status, pending = call("/api/actions/pending", token=admin)
status, metrics = call("/api/metrics", token=admin)
every_held_is_high = all(a["risk"] == "high" for a in pending)
check("every action held for approval is high risk", bool(pending) and every_held_is_high,
      f"{len(pending)} held | " + ", ".join(sorted({a["playbook"] for a in pending})))
check("low and medium risk contained themselves automatically",
      metrics["actions_auto_executed"] > 0,
      f"{metrics['actions_auto_executed']} of {metrics['actions_total']} actions "
      f"({metrics['auto_containment_pct']}%)")

held = pending[0]
check("an analyst may NOT approve a high-risk action",
      call(f"/api/actions/{held['id']}/approve", token=analyst, post=True)[0] == 403,
      f"{held['playbook']} -> {held['target']}")
status, approved = call(f"/api/actions/{held['id']}/approve", token=admin, post=True)
check("an admin may approve it, and it then executes",
      status == 200 and approved["status"] == "executed",
      f"{approved.get('result')} | by {approved.get('decided_by')}")
check("the same action cannot be approved twice",
      call(f"/api/actions/{held['id']}/approve", token=admin, post=True)[0] == 409)
status, undone = call(f"/api/actions/{held['id']}/rollback", token=admin, post=True)
check("every executed action can be rolled back",
      status == 200 and undone["status"] == "rolled_back", undone.get("result", ""))

print("\n-- 5. The audit trail is tamper-evident ---------------------------------")
status, verified = call("/api/audit/verify", token=admin)
check("the hash chain verifies", verified["ok"], f"{verified['entries']} entries")
con = sqlite3.connect(DB)
row = con.execute("SELECT seq, detail FROM audit ORDER BY seq LIMIT 1 OFFSET 2").fetchone()
con.execute("UPDATE audit SET detail='(silently edited)' WHERE seq=?", (row[0],))
con.commit()
status, broken = call("/api/audit/verify", token=admin)
check("editing one past entry is detected", broken["ok"] is False,
      f"chain breaks at entry {broken.get('broken_at')}")
con.execute("UPDATE audit SET detail=? WHERE seq=?", (row[1], row[0]))
con.commit()
con.close()
status, restored = call("/api/audit/verify", token=admin)
check("restoring the entry repairs the chain", restored["ok"], "tamper test left no trace")

print("\n-- Evaluation metrics ---------------------------------------------------")
status, m = call("/api/metrics", token=admin)
for label, value in [
    ("Events ingested", m["events_ingested"]),
    ("Incidents raised", f"{m['incidents']}  {m['incidents_by_severity']}"),
    ("Mean time to detect", f"{m['mttd_ms']} ms"),
    ("Mean time to respond", f"{m['mttr_ms']} ms"),
    ("Noise reduction", f"{m['noise_reduction_pct']} %"),
    ("Actions auto-contained", f"{m['actions_auto_executed']} / {m['actions_total']}  "
                               f"({m['auto_containment_pct']} %)"),
    ("Actions held for a human", m["actions_pending_approval"]),
    ("Rollbacks performed", m["actions_rolled_back"]),
]:
    print(f"  {label:<26} {value}")

print()
if failures:
    print(f"FAILED -- {len(failures)} check(s): " + "; ".join(failures))
    sys.exit(1)
print("All checks passed.")
