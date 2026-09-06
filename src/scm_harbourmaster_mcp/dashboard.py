"""SCM MCP Live Interaction Feed.

Provides a real-time colour-coded dashboard of MCP tool calls served at
/dashboard (HTML) and /dashboard/feed (JSON, polled every 3 s).

Wire-up in server.py:
    from .dashboard import register_dashboard, instrument_server
    instrument_server(mcp)
    register_dashboard(mcp)
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

# ── Event store ──────────────────────────────────────────────────────────────

_FEED: deque[dict[str, Any]] = deque(maxlen=200)
_FEED_LOCK = threading.Lock()
_EVENT_ID = 0


def _next_id() -> int:
    global _EVENT_ID
    with _FEED_LOCK:
        _EVENT_ID += 1
        return _EVENT_ID


def _category(tool: str) -> tuple[str, str]:
    """Return (icon, label) for a tool name."""
    t = tool.lower()
    if any(k in t for k in ("bpa", "ncsc", "audit", "dspt", "iso27001", "nist", "decrypt_policy")):
        return "🛡️", "Compliance"
    if any(
        k in t
        for k in (
            "backup",
            "config_backup",
            "restore",
            "config_diff",
            "config_version",
            "config_rollback",
        )
    ):
        return "💾", "Config"
    if any(k in t for k in ("commit", "push_track", "config_push")):
        return "🚀", "Deploy"
    if any(k in t for k in ("asbuilt", "hld")):
        return "📄", "AS-BUILT"
    if any(k in t for k in ("incident", "posture")):
        return "🚨", "Incidents"
    if any(k in t for k in ("cert", "tls_profile")):
        return "🔒", "Certs"
    if any(k in t for k in ("sdwan", "sd_wan", "wan")):
        return "🌐", "SD-WAN"
    if any(k in t for k in ("adnsr", "ngfw", "aiops")):
        return "⚙️", "NGFW"
    if any(k in t for k in ("address", "service", "tag", "edl", "object")):
        return "📦", "Objects"
    if any(k in t for k in ("security_rule", "nat", "decryption_rule", "url_category")):
        return "🔐", "Policy"
    if any(k in t for k in ("zone", "ike", "ipsec", "remote_network", "dns_security")):
        return "🌍", "Network"
    if any(k in t for k in ("folder", "snippet", "device", "mssp", "tenant")):
        return "🏢", "MSSP"
    if any(k in t for k in ("mobile", "gp_session", "ztna", "browser", "airs")):
        return "📱", "Access"
    if any(k in t for k in ("licence", "spn", "check_update", "tenant_dashboard", "restart")):
        return "📊", "Ops"
    if any(k in t for k in ("dlp", "casb")):
        return "🗂️", "DLP"
    return "⚡", "General"


def _node(arguments: dict[str, Any]) -> str:
    """Extract tenant/folder node label from tool arguments."""
    tenant = str(arguments.get("tenant_id") or "").strip()
    folder = str(arguments.get("folder") or "").strip()
    if tenant and folder:
        return f"{tenant[:12]}·{folder[:12]}"
    if tenant:
        return tenant[:20]
    if folder:
        return folder[:20]
    return "default"


def record_start(tool: str, arguments: dict[str, Any]) -> int:
    """Record a tool call start. Returns event ID for later update."""
    eid = _next_id()
    icon, cat = _category(tool)
    event: dict[str, Any] = {
        "id": eid,
        "tool": tool,
        "icon": icon,
        "category": cat,
        "node": _node(arguments),
        "start_ts": time.time(),
        "duration": None,
        "status": "running",
    }
    with _FEED_LOCK:
        _FEED.appendleft(event)
    return eid


def record_end(eid: int, status: str = "ok") -> None:
    """Update a running event with its final duration and status."""
    with _FEED_LOCK:
        for ev in _FEED:
            if ev["id"] == eid:
                ev["duration"] = round(time.time() - ev["start_ts"], 2)
                ev["status"] = status
                break


def get_feed_snapshot() -> list[dict[str, Any]]:
    with _FEED_LOCK:
        return list(_FEED)


# ── Instrumentation ──────────────────────────────────────────────────────────


def instrument_server(mcp: Any) -> None:
    """Wrap FastMCP.call_tool to log and record every tool call.

    Adds structured log entries (tool_call_start / tool_call_end) at INFO
    level via structlog — zero impact on the MCP protocol; errors propagate
    unchanged and the result is a transparent pass-through.
    """
    import structlog as _structlog

    _log = _structlog.get_logger("scm_mcp.tool_calls")
    original = mcp.call_tool

    async def _instrumented(name: str, arguments: dict[str, Any]) -> Any:
        args = arguments or {}
        _icon, _cat = _category(name)
        node = _node(args)
        # Log safe argument keys (no values — may contain secrets)
        arg_keys = sorted(args.keys())
        eid = record_start(name, args)
        _log.info(
            "tool_call_start",
            tool=name,
            category=_cat,
            node=node,
            arg_keys=arg_keys,
            event_id=eid,
        )
        t0 = time.perf_counter()
        try:
            result = await original(name, args)
            duration = round(time.perf_counter() - t0, 3)
            record_end(eid, "ok")
            _log.info(
                "tool_call_end",
                tool=name,
                category=_cat,
                node=node,
                status="ok",
                duration_s=duration,
                event_id=eid,
            )
            return result
        except Exception as exc:
            duration = round(time.perf_counter() - t0, 3)
            record_end(eid, "error")
            _log.warning(
                "tool_call_error",
                tool=name,
                category=_cat,
                node=node,
                status="error",
                duration_s=duration,
                error=str(exc)[:200],
                event_id=eid,
            )
            raise

    mcp.call_tool = _instrumented


# ── HTTP routes ──────────────────────────────────────────────────────────────

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SCM MCP · Live Feed</title>
<style>
  :root{
    --bg:#0d1117;--surface:#161b22;--border:#30363d;
    --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
    --green:#3fb950;--amber:#d29922;--red:#f85149;
    --running:#58a6ff;--pulse:#3fb950;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
       font-size:13px;min-height:100vh}
  header{background:var(--surface);border-bottom:1px solid var(--border);
         padding:12px 20px;display:flex;align-items:center;gap:12px;
         position:sticky;top:0;z-index:10}
  .logo{font-size:15px;font-weight:700;letter-spacing:.3px;color:var(--text)}
  .logo span{color:var(--accent)}
  .pulse-wrap{display:flex;align-items:center;gap:6px;margin-left:auto}
  .pulse{width:8px;height:8px;border-radius:50%;background:var(--pulse);
         animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}
                   50%{opacity:.4;transform:scale(.8)}}
  .live-label{font-size:11px;font-weight:600;color:var(--pulse);text-transform:uppercase;
              letter-spacing:1px}
  .stats{display:flex;gap:16px;font-size:11px;color:var(--muted)}
  .stats b{color:var(--text)}
  .refresh-note{font-size:11px;color:var(--muted)}
  #countdown{color:var(--accent);font-weight:600}

  .feed{padding:12px 16px;display:flex;flex-direction:column;gap:6px;max-width:1200px;margin:0 auto}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
        padding:10px 14px;display:grid;
        grid-template-columns:28px 1fr auto auto auto;
        align-items:center;gap:10px;transition:border-color .2s}
  .card.running{border-color:var(--running);animation:border-pulse 1.5s infinite}
  @keyframes border-pulse{0%,100%{border-color:var(--running)}50%{border-color:var(--border)}}
  .card.ok{border-color:var(--border)}
  .card.error{border-color:var(--red)}
  .icon{font-size:16px;text-align:center}
  .main{min-width:0}
  .tool-name{font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;
             text-overflow:ellipsis;color:var(--text)}
  .meta{font-size:11px;color:var(--muted);margin-top:2px;display:flex;gap:8px}
  .cat-badge{background:#21262d;border:1px solid var(--border);border-radius:10px;
             padding:1px 7px;font-size:10px;font-weight:600;color:var(--muted);
             text-transform:uppercase;letter-spacing:.4px}
  .node-badge{background:#0d2137;border:1px solid #1f6feb;border-radius:10px;
              padding:1px 7px;font-size:10px;color:#58a6ff;max-width:140px;
              white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .dur{min-width:60px;text-align:right}
  .dur-bar-wrap{height:4px;background:#21262d;border-radius:2px;
                width:60px;margin-top:4px}
  .dur-bar{height:4px;border-radius:2px;transition:width .4s}
  .dur-val{font-size:11px;color:var(--muted)}
  .dur-val.green{color:var(--green)}
  .dur-val.amber{color:var(--amber)}
  .dur-val.red{color:var(--red)}
  .dur-val.running-txt{color:var(--running)}
  .status{width:52px;text-align:center}
  .badge{border-radius:10px;padding:2px 8px;font-size:10px;font-weight:700;
         text-transform:uppercase;letter-spacing:.4px}
  .badge.ok{background:#0d3321;color:var(--green);border:1px solid #238636}
  .badge.error{background:#2d1b1b;color:var(--red);border:1px solid #f85149}
  .badge.running{background:#0d2137;color:var(--running);border:1px solid #1f6feb}
  .ts{font-size:11px;color:var(--muted);white-space:nowrap;min-width:52px;text-align:right}
  .empty{text-align:center;padding:60px 20px;color:var(--muted)}
  .empty .icon-big{font-size:40px;margin-bottom:12px}

  .top-bar{background:var(--surface);border-bottom:1px solid var(--border);
           padding:8px 20px;display:flex;gap:20px;font-size:11px;color:var(--muted)}
  .top-stat{display:flex;align-items:center;gap:5px}
  .dot{width:7px;height:7px;border-radius:50%}
  .dot.green{background:var(--green)}
  .dot.amber{background:var(--amber)}
  .dot.red{background:var(--red)}
  .dot.blue{background:var(--running)}
</style>
</head>
<body>
<header>
  <div class="logo">SCM MCP <span>·</span> Live Interaction Feed</div>
  <div class="stats">
    <div>Total: <b id="stat-total">0</b></div>
    <div><span style="color:var(--green)">●</span> OK: <b id="stat-ok">0</b></div>
    <div><span style="color:var(--red)">●</span> Error: <b id="stat-err">0</b></div>
    <div><span style="color:var(--running)">●</span> Running: <b id="stat-run">0</b></div>
  </div>
  <div class="pulse-wrap">
    <div class="pulse"></div>
    <div class="live-label">LIVE</div>
    <div class="refresh-note" style="margin-left:10px">refresh in <span id="countdown">3</span>s</div>
  </div>
</header>
<div class="top-bar">
  <div class="top-stat"><div class="dot green"></div>&lt;5 s fast</div>
  <div class="top-stat"><div class="dot amber"></div>5–15 s normal</div>
  <div class="top-stat"><div class="dot red"></div>&gt;15 s slow</div>
  <div class="top-stat" style="margin-left:auto;color:var(--muted)">
    Showing last 50 calls — <span id="total-seen">0</span> total recorded
  </div>
</div>
<div class="feed" id="feed"><div class="empty"><div class="icon-big">⚡</div>
  Waiting for tool calls…<br><small>Make a request via Claude or the MCP CLI to see the live feed.</small>
</div></div>

<script>
const feed = document.getElementById('feed');
let countdown = 3;
let countdownTimer;

function relativeTime(ts){
  const diff = (Date.now()/1000) - ts;
  if(diff < 5) return 'just now';
  if(diff < 60) return Math.floor(diff)+'s ago';
  if(diff < 3600) return Math.floor(diff/60)+'m ago';
  return Math.floor(diff/3600)+'h ago';
}

function durColor(d){
  if(d===null) return 'running-txt';
  if(d<5) return 'green';
  if(d<15) return 'amber';
  return 'red';
}
function durBarColor(d){
  if(d===null) return 'var(--running)';
  if(d<5) return 'var(--green)';
  if(d<15) return 'var(--amber)';
  return 'var(--red)';
}
function durBarWidth(d){
  if(d===null) return '100';
  // scale: 0s=0%, 30s=100%
  return Math.min(100, Math.round(d/30*100));
}

function renderCard(ev){
  const dur = ev.duration;
  const durLabel = dur===null ? '<span class="dur-val running-txt">⏳ …</span>'
    : `<span class="dur-val ${durColor(dur)}">${dur.toFixed(1)}s</span>`;
  const barW = durBarWidth(dur);
  const barColor = durBarColor(dur);
  const statusBadge = ev.status==='running'
    ? '<span class="badge running">●&nbsp;LIVE</span>'
    : ev.status==='ok'
    ? '<span class="badge ok">✓&nbsp;OK</span>'
    : '<span class="badge error">✗&nbsp;ERR</span>';
  return `<div class="card ${ev.status}" data-id="${ev.id}">
    <div class="icon">${ev.icon}</div>
    <div class="main">
      <div class="tool-name">${ev.tool}</div>
      <div class="meta">
        <span class="cat-badge">${ev.category}</span>
        <span class="node-badge">${ev.node}</span>
      </div>
    </div>
    <div class="dur">
      ${durLabel}
      <div class="dur-bar-wrap">
        <div class="dur-bar" style="width:${barW}%;background:${barColor}"></div>
      </div>
    </div>
    <div class="status">${statusBadge}</div>
    <div class="ts">${relativeTime(ev.start_ts)}</div>
  </div>`;
}

function updateStats(events){
  const total = events.length;
  const ok = events.filter(e=>e.status==='ok').length;
  const err = events.filter(e=>e.status==='error').length;
  const run = events.filter(e=>e.status==='running').length;
  document.getElementById('stat-total').textContent=total;
  document.getElementById('stat-ok').textContent=ok;
  document.getElementById('stat-err').textContent=err;
  document.getElementById('stat-run').textContent=run;
  document.getElementById('total-seen').textContent=total;
}

async function refresh(){
  try{
    const resp = await fetch('/dashboard/feed');
    if(!resp.ok) return;
    const events = await resp.json();
    updateStats(events);
    const shown = events.slice(0,50);
    if(shown.length===0){
      feed.innerHTML='<div class="empty"><div class="icon-big">⚡</div>Waiting for tool calls…<br><small>Make a request via Claude or the MCP CLI to see the live feed.</small></div>';
      return;
    }
    feed.innerHTML = shown.map(renderCard).join('');
  } catch(e){
    // silently ignore network errors during refresh
  }
}

// Countdown timer
function startCountdown(){
  clearInterval(countdownTimer);
  countdown=3;
  document.getElementById('countdown').textContent=countdown;
  countdownTimer=setInterval(()=>{
    countdown--;
    if(countdown<=0){
      countdown=3;
      refresh();
    }
    document.getElementById('countdown').textContent=countdown;
  },1000);
}

// Relative timestamps refresh every second
setInterval(()=>{
  document.querySelectorAll('.ts').forEach((el,i)=>{
    // We can't easily get ts from rendered HTML, so the full refresh handles it
  });
},1000);

refresh();
startCountdown();
</script>
</body>
</html>"""


def register_dashboard(mcp: Any) -> None:
    """Register /dashboard and /dashboard/feed routes on the FastMCP server."""
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, JSONResponse

    @mcp.custom_route("/dashboard", methods=["GET"])  # type: ignore[untyped-decorator]
    async def dashboard_page(request: Request) -> HTMLResponse:
        return HTMLResponse(_HTML)

    @mcp.custom_route("/dashboard/feed", methods=["GET"])  # type: ignore[untyped-decorator]
    async def dashboard_feed(request: Request) -> JSONResponse:
        events = get_feed_snapshot()
        # Serialise: convert any non-JSON-safe values
        safe = []
        for ev in events:
            safe.append(
                {
                    "id": ev["id"],
                    "tool": ev["tool"],
                    "icon": ev["icon"],
                    "category": ev["category"],
                    "node": ev["node"],
                    "start_ts": ev["start_ts"],
                    "duration": ev["duration"],
                    "status": ev["status"],
                }
            )
        return JSONResponse(safe, headers={"Cache-Control": "no-store"})
