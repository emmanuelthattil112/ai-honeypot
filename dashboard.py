#!/usr/bin/env python3
"""
Honeypot dashboard. Reads what analyze.py writes and shows it as a web page.
Runs on 127.0.0.1 only, so it's reachable through an SSH tunnel, not the open internet.
"""
import json
import os
import re
from collections import Counter

from flask import Flask, render_template_string

BASE = os.path.dirname(os.path.abspath(__file__))
PROFILES_FILE = os.path.join(BASE, "attacker_profiles.jsonl")
STATS_FILE = os.path.join(BASE, "stats.json")
MAX_FEED = 200

TECHNIQUES = {
    "T1110": "Brute Force", "T1110.001": "Password Guessing", "T1110.003": "Password Spraying",
    "T1078": "Valid Accounts", "T1078.001": "Default Accounts",
    "T1082": "System Information Discovery", "T1033": "System Owner/User Discovery",
    "T1057": "Process Discovery", "T1083": "File and Directory Discovery",
    "T1016": "System Network Configuration Discovery", "T1087": "Account Discovery",
    "T1018": "Remote System Discovery", "T1046": "Network Service Discovery",
    "T1049": "System Network Connections Discovery",
    "T1059": "Command and Scripting Interpreter", "T1059.004": "Unix Shell",
    "T1105": "Ingress Tool Transfer", "T1098": "Account Manipulation",
    "T1098.004": "SSH Authorized Keys", "T1136": "Create Account",
    "T1053": "Scheduled Task/Job", "T1053.003": "Cron",
    "T1543": "Create or Modify System Process", "T1496": "Resource Hijacking",
    "T1070": "Indicator Removal", "T1070.003": "Clear Command History",
    "T1222": "File Permissions Modification", "T1222.002": "Linux File Permissions",
    "T1027": "Obfuscated Files or Information", "T1140": "Deobfuscate/Decode",
    "T1562": "Impair Defenses", "T1021.004": "Remote Services: SSH",
    "T1071": "Application Layer Protocol", "T1571": "Non-Standard Port",
}
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

app = Flask(__name__)


def load_profiles():
    profiles = []
    if os.path.exists(PROFILES_FILE):
        with open(PROFILES_FILE) as f:
            for line in f:
                if line.strip():
                    try:
                        profiles.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return profiles


def split_summary(text):
    """Separate the prose from the trailing 'ATT&CK: ...' line."""
    body, techs = [], []
    for line in (text or "").splitlines():
        if line.strip().upper().startswith("ATT&CK"):
            techs += TECH_RE.findall(line)
        elif line.strip():
            body.append(line.strip())
    return " ".join(body), techs


def attack_time(p):
    """Real attack time from Cowrie's timestamp, falling back to processing time."""
    ts = p.get("session_start") or ""
    if len(ts) >= 19:
        return ts[:10] + " " + ts[11:19] + " UTC"
    return p.get("time", "")


def top(counter, n=8):
    return sorted(counter.items(), key=lambda kv: -kv[1])[:n]


@app.route("/")
def dashboard():
    stats = {}
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE) as f:
                stats = json.load(f)
        except json.JSONDecodeError:
            pass

    profiles = load_profiles()
    tech_count = Counter()
    downloads = {}
    groups = {}
    for p in profiles:
        p["body"], p["techs"] = split_summary(p.get("summary"))
        p["when"] = attack_time(p)
        tech_count.update(set(p["techs"]))
        if p.get("source") in ("claude", "repeat"):
            g = groups.setdefault(p["body"], {"count": 0, "ips": set()})
            g["count"] += 1
            g["ips"].add(p.get("src_ip"))
    for p in profiles:
        g = groups.get(p["body"])
        p["seen"] = g["count"] if g else 1
        p["seen_ips"] = len(g["ips"]) if g else 1
        for d in p.get("downloads") or []:
            key = d.get("sha256") or d.get("url")
            if key and key not in downloads:
                downloads[key] = {**d, "seen": p.get("time"), "ip": p.get("src_ip")}

    profiles.sort(key=lambda p: p.get("session_start") or "")
    repeat_count = sum(1 for p in profiles if p.get("source") == "repeat")
    tech_rows = [(t, TECHNIQUES.get(t, ""), c) for t, c in tech_count.most_common(10)]
    tech_max = tech_rows[0][2] if tech_rows else 1

    return render_template_string(
        PAGE,
        s=stats,
        unique_ips=len(stats.get("ips", {})),
        feed=list(reversed(profiles))[:MAX_FEED],
        total_profiles=len(profiles),
        repeat_count=repeat_count,
        tech_rows=tech_rows,
        tech_max=tech_max,
        downloads=list(downloads.values())[-20:][::-1],
        top_users=top(stats.get("usernames", {})),
        top_pass=top(stats.get("passwords", {})),
        top_ips=top(stats.get("ips", {})),
        top_cmds=top(stats.get("commands", {})),
    )


PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honeypot</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,800&family=Work+Sans:wght@400;500;600&family=IBM+Plex+Mono&display=swap" rel="stylesheet">
<style>
  :root {
    --comb: #2b1e12;      /* dark comb brown */
    --cell: #3a2918;      /* raised panel */
    --wax: #f2e4c4;       /* main text */
    --dim: #b39c74;       /* secondary text */
    --honey: #e8a82e;     /* accent */
    --sting: #d8613c;     /* downloads / danger */
    --line: #54402a;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--comb); color: var(--wax);
    font: 400 15px/1.55 "Work Sans", system-ui, sans-serif;
  }
  a { color: var(--honey); }
  a:focus-visible, input:focus-visible { outline: 2px solid var(--honey); outline-offset: 2px; }
  .wrap { max-width: 1240px; margin: 0 auto; padding: 32px 24px 64px; }

  header { padding-bottom: 28px; border-bottom: 1px solid var(--line); margin-bottom: 28px; }
  h1 {
    font-family: "Fraunces", Georgia, serif; font-weight: 800;
    font-size: clamp(34px, 5.5vw, 64px); line-height: 1.05; margin: 0 0 14px;
    letter-spacing: -0.01em;
  }
  h1 .n { color: var(--honey); font-variant-numeric: tabular-nums; }
  .sub { color: var(--dim); margin: 0; }
  .sub b { color: var(--wax); font-weight: 600; }

  .grid { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 32px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }

  h2 { font-family: "Fraunces", Georgia, serif; font-weight: 600; font-size: 21px; margin: 0 0 12px; }
  section + section { margin-top: 32px; }

  .toggle { display: block; font-size: 13px; color: var(--dim); margin: -6px 0 16px; cursor: pointer; }
  .toggle input { accent-color: var(--honey); margin-right: 6px; }
  .search {
    width: 100%; padding: 10px 12px; margin-bottom: 16px;
    background: var(--cell); color: var(--wax); border: 1px solid var(--line); border-radius: 6px;
    font: inherit;
  }
  .session { background: var(--cell); border-radius: 8px; padding: 16px 18px; margin-bottom: 12px; }
  .session.repeat { background: transparent; border: 1px dashed var(--line); }
  .meta { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 13px; color: var(--dim); margin-bottom: 8px; }
  .meta .ip { color: var(--wax); font-weight: 600; }
  .tag { font-size: 12px; padding: 1px 8px; border-radius: 999px; background: var(--line); color: var(--wax); }
  .tag.claude { background: var(--honey); color: var(--comb); }
  .tag.skipped, .tag.error { background: var(--sting); color: var(--comb); }
  .creds { font-family: "IBM Plex Mono", monospace; font-size: 13px; color: var(--honey); }
  pre {
    font: 13px/1.5 "IBM Plex Mono", monospace; background: var(--comb); color: var(--wax);
    padding: 10px 12px; border-radius: 6px; margin: 8px 0; overflow-x: auto; white-space: pre-wrap; word-break: break-all;
  }
  .summary { margin: 8px 0 0; max-width: 72ch; }
  .techs { margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; }
  .techs a { font-size: 12px; text-decoration: none; border: 1px solid var(--honey); border-radius: 4px; padding: 1px 6px; }

  .bars div { margin-bottom: 10px; font-size: 13px; }
  .bars .label { display: flex; justify-content: space-between; gap: 8px; }
  .bars .track { height: 8px; background: var(--cell); border-radius: 4px; margin-top: 4px; }
  .bars .fill { height: 100%; background: var(--honey); border-radius: 4px; }

  ol.top { margin: 0; padding-left: 22px; font-size: 13px; }
  ol.top li { margin-bottom: 4px; }
  ol.top li span.v {
    font-family: "IBM Plex Mono", monospace; display: inline-block; max-width: 230px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom;
  }
  ol.top li span.c { color: var(--dim); float: right; }

  .dl { font-size: 13px; border-left: 3px solid var(--sting); padding: 6px 0 6px 10px; margin-bottom: 10px; word-break: break-all; }
  .dl .when { color: var(--dim); }
  .empty { color: var(--dim); font-style: italic; }
  footer { color: var(--dim); font-size: 13px; margin-top: 40px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1><span class="n">{{ "{:,}".format(s.get("login_attempts", 0)) }}</span> login attempts.
        <span class="n">{{ "{:,}".format(s.get("successful_logins", 0)) }}</span> got in.</h1>
    <p class="sub">
      <b>{{ "{:,}".format(s.get("sessions", 0)) }}</b> connections from <b>{{ "{:,}".format(unique_ips) }}</b> unique IPs.
      <b>{{ s.get("sessions_with_activity", 0) }}</b> sessions ran commands.
      Claude profiled <b>{{ s.get("claude_calls", 0) }}</b> new playbooks and recognized <b>{{ s.get("repeats", 0) }}</b> repeats.
    </p>
  </header>

  <div class="grid">
    <main>
      <h2>Attacker sessions</h2>
      <input class="search" id="q" type="search" placeholder="Filter by IP, password, command, or technique" aria-label="Filter sessions">
      <label class="toggle"><input type="checkbox" id="showRepeats"> Show {{ repeat_count }} repeat sessions</label>
      {% if not feed %}
        <p class="empty">No one has run commands yet. Sessions show up here once analyze.py profiles an attacker.</p>
      {% endif %}
      {% for p in feed %}
      <article class="session {{ 'repeat' if p.source == 'repeat' else '' }}">
        <div class="meta">
          <span>{{ p.when }}</span>
          <a class="ip" href="https://www.abuseipdb.com/check/{{ p.src_ip }}" target="_blank" rel="noopener">{{ p.src_ip }}</a>
          <span class="tag {{ p.source }}">{{ {'claude':'new playbook','repeat':'repeat','skipped':'not analyzed','error':'error'}.get(p.source, p.source) }}</span>
          {% if p.source == 'claude' and p.seen > 1 %}<span>Seen {{ p.seen }} times from {{ p.seen_ips }} IP{{ 's' if p.seen_ips != 1 else '' }}</span>{% endif %}
        </div>
        {% if p.credentials %}<div class="creds">Logged in as {{ p.credentials | join(", ") }}</div>{% endif %}
        {% if p.commands %}<pre>{{ p.commands | join("\n") }}</pre>{% endif %}
        {% for d in p.downloads or [] %}<div class="dl">Downloaded {{ d.url }}</div>{% endfor %}
        <p class="summary">{{ p.body }}</p>
        {% if p.techs %}
        <div class="techs">
          {% for t in p.techs %}<a href="https://attack.mitre.org/techniques/{{ t | replace('.', '/') }}/" target="_blank" rel="noopener">{{ t }}</a>{% endfor %}
        </div>
        {% endif %}
      </article>
      {% endfor %}
      {% if total_profiles > feed|length %}<p class="empty">Showing the latest {{ feed|length }} of {{ total_profiles }}.</p>{% endif %}
    </main>

    <aside>
      <section>
        <h2>ATT&amp;CK techniques seen</h2>
        {% if tech_rows %}
        <div class="bars">
          {% for t, name, c in tech_rows %}
          <div>
            <div class="label"><span><a href="https://attack.mitre.org/techniques/{{ t | replace('.', '/') }}/" target="_blank" rel="noopener">{{ t }}</a> {{ name }}</span><span>{{ c }}</span></div>
            <div class="track"><div class="fill" style="width: {{ (100 * c / tech_max) | round(0) }}%"></div></div>
          </div>
          {% endfor %}
        </div>
        {% else %}<p class="empty">None tagged yet.</p>{% endif %}
      </section>

      <section>
        <h2>Files attackers tried to download</h2>
        {% for d in downloads %}
          <div class="dl">
            {{ d.url or "unknown URL" }}<br>
            <span class="when">{{ d.seen }} from {{ d.ip }}</span>
            {% if d.sha256 %}<br><a href="https://www.virustotal.com/gui/file/{{ d.sha256 }}" target="_blank" rel="noopener">Check on VirusTotal</a>{% endif %}
          </div>
        {% else %}<p class="empty">No downloads yet.</p>{% endfor %}
      </section>

      {% for title, rows in [("Top passwords", top_pass), ("Top usernames", top_users), ("Top attacker IPs", top_ips), ("Top commands", top_cmds)] %}
      <section>
        <h2>{{ title }}</h2>
        {% if rows %}
        <ol class="top">
          {% for v, c in rows %}<li><span class="v" title="{{ v }}">{{ v }}</span><span class="c">{{ c }}</span></li>{% endfor %}
        </ol>
        {% else %}<p class="empty">Nothing yet.</p>{% endif %}
      </section>
      {% endfor %}
    </aside>
  </div>

  <footer>Refreshes every minute while the filter box is empty. Attacker text is displayed as plain text, never run.</footer>
</div>
<script>
  const q = document.getElementById("q");
  const rep = document.getElementById("showRepeats");
  const cards = [...document.querySelectorAll(".session")];
  rep.checked = sessionStorage.getItem("showRepeats") === "1";
  function apply() {
    const term = q.value.toLowerCase();
    cards.forEach(c => {
      const isRepeat = c.classList.contains("repeat");
      const matches = !term || c.textContent.toLowerCase().includes(term);
      c.hidden = !matches || (isRepeat && !rep.checked && !term);
    });
  }
  q.addEventListener("input", apply);
  rep.addEventListener("change", () => { sessionStorage.setItem("showRepeats", rep.checked ? "1" : "0"); apply(); });
  apply();
  setInterval(() => { if (!q.value && document.activeElement !== q) location.reload(); }, 60000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    # 127.0.0.1 = only reachable from the server itself (use an SSH tunnel to view it)
    app.run(host="127.0.0.1", port=5000)
