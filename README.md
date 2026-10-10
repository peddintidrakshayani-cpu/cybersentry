# CyberSentry — Detect. Explain. Respond.

AI-powered autonomous security incident response. Hackathon problem **TH2-PS-GAI-006**.

```
INGEST ──▶ DETECT ──▶ INVESTIGATE ──▶ RESPOND ──▶ AUDIT
 logs      5 rules +   agent with       8 playbooks   append-only
           correlation autonomous      + human        hash-chained
                       tool use        approval       trail
```

**The safety story, in one line:** the agent may only *propose* from eight whitelisted
playbooks. Low- and medium-risk actions contain themselves automatically; **high-risk
actions wait for a named human**. The AI never executes anything, and every action has
an undo step.

---

## Two pieces, one console

| Piece | What it is | Why it exists |
|---|---|---|
| [`demo.html`](demo.html) | The SOC console. One self-contained file — vanilla JS, hand-written CSS, no build step. **Live** when served by the backend; falls back to an in-page simulation when opened as a file. | **This is what you present.** Live, it shows real data; offline, it cannot fail on stage. |
| [`backend/`](backend/) | A real FastAPI service: SQLite, JWT with roles, the five detection rules, the investigation agent, the guard-railed response engine, the hash-chained audit trail. | **This is what you show judges who ask "is it real?"** Open `/docs`, run the smoke test. |

**Live mode** — open <http://127.0.0.1:8000/> with the backend running. The console
detects the API and every number, event, incident, approval and audit row comes from it
(top bar: *connected to API*). It has no fake background traffic, adds a **Real logs**
card (fetch Loghub, or upload your own `auth.log`), and polls every 3 s, so logs ingested
with curl show up on their own.

**Offline mode** — double-click `demo.html`, or the API is unreachable. The backend is
simulated in-page with a scripted agent (top bar: *standalone*), so a demo never
depends on a server.

---

## Run the console

Start the backend (below) and open <http://127.0.0.1:8000/> for live mode. For the
offline version, double-click `demo.html`, or open the published copy:
<https://claude.ai/artifact/5LPx6yzTrDUMrNENFPt3LP>

Sign in with the pre-filled credentials (`admin` / `cybersentry`), then either click a
single attack button or **▶ Run end-to-end** to play the whole flow hands-free.

## Run the backend

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --port 8000      # or: start.bat
```

- Swagger UI: <http://127.0.0.1:8000/docs>
- Health: <http://127.0.0.1:8000/health>
- Logins: `admin` / `cybersentry` (full control) and `analyst` / `cybersentry` (cannot
  approve high-risk actions, cannot launch simulations)

### Prove it works

```bash
python smoke_test.py      # second terminal; API started with CYBERSENTRY_STREAM=off
```

Nineteen checks across the whole pipeline: auth and role enforcement, all five attack
scenarios detected and handled, report completeness, the approval guard-rail, rollback,
and a tamper test that edits a past audit row and shows the chain detect it. It prints
the evaluation metrics at the end.

### API surface

| Method | Path | Role |
|---|---|---|
| POST | `/api/auth/login` | — |
| GET | `/api/events` | any |
| GET | `/api/incidents` · `/api/incidents/{id}` | any |
| POST | `/api/incidents/{id}/resolve` | any |
| POST | `/api/simulate/{S1..S5}` | admin |
| GET | `/api/ingest/sources` · `/api/stream` | any |
| POST | `/api/stream/start` · `/api/stream/stop` | admin |
| POST | `/api/ingest/source/{name}` · `/api/ingest/ssh` | admin |
| GET | `/api/actions/pending` | any |
| POST | `/api/actions/{id}/approve` · `/reject` | any (high risk: admin only) |
| POST | `/api/actions/{id}/rollback` | any |
| GET | `/api/audit` · `/api/audit/verify` | any |
| GET | `/api/metrics` · `/health` | any / — |
| WS | `/ws` | — |

### Real logs

Besides the five scripted scenarios, the backend ingests real OpenSSH syslog lines
(`/var/log/auth.log` format). Real lines carry no attack label; the same rules have to
find the attacks, and the report is built from the actual events and lookups.

```bash
B=http://127.0.0.1:8000
TOKEN=$(curl -s -X POST $B/api/auth/login -d 'username=admin&password=cybersentry' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 1. Let the server fetch a real public dataset (allow-listed sources only)
curl -X POST $B/api/ingest/source/loghub-openssh -H "Authorization: Bearer $TOKEN"

# 2. Or upload any sshd log yourself — e.g. your own machine's auth log
sudo cat /var/log/auth.log | curl -X POST $B/api/ingest/ssh \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/plain" --data-binary @-
```

Two extra rules apply to real SSH logs: `R6_USER_ENUM` (one IP trying 5+ account names
that do not exist, medium) and `R7_SSH_PROBE` (5+ addresses connecting without ever
attempting a login, low). The Loghub file (2,000 lines from an internet-facing server)
raises 11 incidents: 6 brute force (high), 4 username enumeration (medium), 1 probing (low).

An open incident suppresses repeats of the same attack (same correlation key). **Resolve**
it (button on the incident, or `POST /api/incidents/{id}/resolve`) and the next
occurrence raises a fresh incident. Set `CYBERSENTRY_DB` to use a different database file.

**Live stream.** To keep events flowing continuously (instead of one batch), start the
stream from the console's *Real logs* card, or with the API:

```bash
curl -X POST "$B/api/stream/start?source=replay&rate=2" -H "Authorization: Bearer $TOKEN"
curl -X POST "$B/api/stream/stop" -H "Authorization: Bearer $TOKEN"
```

- `replay` re-sends the real Loghub lines one by one, stamped with their arrival time
  (event source `ssh-replay`), and loops at the end.
- `tail` follows a real, growing log file: start the server with
  `CYBERSENTRY_TAIL=/var/log/auth.log` (the path is server config, never a request field).
- Detection runs every 5 s over the newest 400 events. The stream **starts with the
  server** (replay, 3 lines/s): set `CYBERSENTRY_STREAM=off` to disable it (required for
  `smoke_test.py`), `tail` to follow a file, and `CYBERSENTRY_STREAM_RATE` for the speed.
- An event counts as hostile when a scenario labelled it or an incident cites it as
  evidence; an attacker's protocol chatter (disconnects, PAM notes) is not counted.

**Live threat intel.** For real (public) IPs, `check_ip_reputation` asks two free,
keyless sources: [GreyNoise Community](https://api.greynoise.io/v3/community/8.8.8.8)
(is this IP attacking the internet right now?) and the
[blocklist.de SSH list](https://lists.blocklist.de/lists/ssh.txt) (reported in the last
48 h). Note the Loghub data is years old, so its IPs mostly come back "not observed";
today's attackers come back `malicious`. Set `CYBERSENTRY_INTEL=off` to run fully
offline, or `GREYNOISE_API_KEY` for a higher rate limit. The scripted scenarios keep
their fixed intel because they use reserved documentation addresses.

---

## The five scenarios

| ID | Scenario | Rule | MITRE ATT&CK |
|---|---|---|---|
| S1 | Brute force → successful login | `R1_BRUTE_FORCE` | T1110.003, T1078.004 |
| S2 | Impossible travel | `R2_IMPOSSIBLE_TRAVEL` | T1078, T1114.003 |
| S3 | Phishing → malware → C2 beacon | `R3_MALWARE_CHAIN` | T1566.001, T1059.001, T1547.001, T1071.001 |
| S4 | Privilege escalation to Domain Admin | `R4_PRIV_ESC` | T1136.002, T1098 |
| S5 | Off-hours data exfiltration | `R5_EXFIL` | T1005, T1560.001, T1048 |

The rules are given raw events with no scenario label and have to correlate them
themselves — `R1` genuinely counts failed logins per source IP and looks for a
subsequent success.

## The agent

`GET /health` reports which analyzer is active.

- **With `ANTHROPIC_API_KEY` set and `pip install anthropic`** — Claude runs a real
  tool-use loop over five read-only tools (`search_events`, `check_ip_reputation`,
  `check_domain_reputation`, `get_user_history`, `get_asset_info`), decides for itself
  what to look up, and submits a structured report via a `submit_report` tool.
- **Without a key** — a deterministic analyzer calls the same read-only tools and
  returns the same report shape, so a demo never depends on the network.

Either way the agent's output is a *recommendation*. `plan_response()` drops anything
not in `PLAYBOOKS`, and `AUTO_EXECUTE` decides what runs without a human.

Prompt-injection posture: log text reaches the agent strictly as data, the tools are
read-only, and the only verbs the agent can emit are playbook names.

## Measured on this machine

From `smoke_test.py` on a clean database:

| Metric | Value |
|---|---|
| Mean time to detect | **92 ms** |
| Mean time to respond (detect → contained) | **161 ms** |
| Noise reduction | **91.5 %** of events never reach an analyst |
| Auto-contained actions | **14 of 20 (70 %)** |
| Actions held for a human | **5** (every one of them high-risk) |
| Audit chain | 39 entries, verified; tampering detected at the edited row |

## Not built

Honest list, for the "future work" slide: there is
no Postgres/Alembic path yet; no Docker, CI, or deployment; no pytest suite (the smoke
test covers the same ground end-to-end); IP reputation is live for real logs, but the
asset and user-baseline lookups are still local fixtures.
