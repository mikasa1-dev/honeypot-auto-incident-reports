import json
import time
from collections import Counter
from flask import Flask, jsonify, render_template_string, Response
import alert_helper

LOGFILE = "honeypot_log.jsonl"
THRESHOLD = 5
WINDOW = 60

app = Flask(__name__)


def read_events():
    events = []
    try:
        with open(LOGFILE) as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return events


def live_alerts(events):
    """IPs with THRESHOLD+ attempts in the last WINDOW seconds."""
    now = time.time()
    recent = Counter()
    for e in events:
        try:
            t = time.mktime(time.strptime(e["time"], "%Y-%m-%d %H:%M:%S"))
        except (KeyError, ValueError):
            continue
        if now - t <= WINDOW:
            recent[e["ip"]] += 1
    return [{"ip": ip, "count": c} for ip, c in recent.items() if c >= THRESHOLD]


PAGE = """
<!doctype html>
<html><head><title>Honeypot Dashboard</title>
<style>
 body{font-family:sans-serif;background:#111;color:#eee;margin:0;padding:20px}
 #banner{padding:20px;border-radius:8px;font-size:20px;margin-bottom:20px;background:#1e5e2f}
 #banner.attack{background:#b00020;animation:flash 1s infinite}
 @keyframes flash{50%{background:#ff3b3b}}
 .box{background:#1c1c1c;border-radius:8px;padding:15px;margin-bottom:20px}
 table{width:100%;border-collapse:collapse}
 td,th{text-align:left;padding:6px;border-bottom:1px solid #333}
 a.btn{display:inline-block;background:#2563eb;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none}
 .HIGH{color:#ff5c5c}.MEDIUM{color:#ffb020}.LOW{color:#6fcf97}
</style></head><body>
<h1>Honeypot Dashboard</h1>
<div id="banner">All quiet. Waiting for attackers...</div>
<div class="box"><a class="btn" href="/report">Download incident report</a></div>
<div class="box"><h3>Incidents</h3><div id="incidents">None yet</div></div>
<div class="box"><h3>Live attempts</h3><table id="events"></table></div>
<script>
function cell(tr, text, cls){var td=document.createElement('td');td.textContent=text;if(cls)td.className=cls;tr.appendChild(td);}
async function refresh(){
  var d = await (await fetch('/api/data')).json();
  var b = document.getElementById('banner');
  if(d.alerts.length){
    b.className='attack';
    b.textContent='ATTACK DETECTED from '+d.alerts.map(function(a){return a.ip+' ('+a.count+' tries)';}).join(', ');
  } else { b.className=''; b.textContent='All quiet. Waiting for attackers...'; }
  var inc=document.getElementById('incidents'); inc.textContent='';
  if(!d.incidents.length){inc.textContent='None yet';}
  d.incidents.forEach(function(i){
    var div=document.createElement('div'); div.style.marginBottom='14px';
    var h=document.createElement('div');
    var sev=document.createElement('span'); sev.className=i.severity; sev.textContent=i.severity;
    h.appendChild(sev);
    h.appendChild(document.createTextNode(' | '+i.name+' | '+i.mitre+' | '+i.ip+' | '+i.attempts+' attempts'));
    div.appendChild(h);
    var ul=document.createElement('ul');
    i.steps.forEach(function(s){var li=document.createElement('li');li.textContent=s;ul.appendChild(li);});
    div.appendChild(ul); inc.appendChild(div);
  });
  var e=document.getElementById('events'); e.textContent='';
  d.events.forEach(function(x){var tr=document.createElement('tr');cell(tr,x.time);cell(tr,x.ip);cell(tr,x.username);e.appendChild(tr);});
}
setInterval(refresh,2000); refresh();
</script></body></html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/data")
def data():
    events = read_events()
    findings = alert_helper.analyze(events) if events else []
    incidents = [{
        "ip": f["ip"], "attempts": f["attempts"], "name": f["name"],
        "mitre": f["mitre"], "severity": f["severity"], "steps": f["steps"],
    } for f in findings]
    recent = [{"time": e.get("time", ""), "ip": e.get("ip", ""), "username": e.get("username", "")}
              for e in events[-30:]][::-1]
    return jsonify(alerts=live_alerts(events), incidents=incidents, events=recent)


@app.route("/report")
def report():
    events = read_events()
    if not events:
        return Response("No events yet.", mimetype="text/plain")
    text = alert_helper.write_report(alert_helper.analyze(events))
    return Response(text, mimetype="text/markdown",
                    headers={"Content-Disposition": "attachment; filename=incident_report.md"})


if __name__ == "__main__":
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(host="127.0.0.1", port=5000)
