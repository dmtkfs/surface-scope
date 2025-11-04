#!/usr/bin/env python3

# surface_scope.py: Attack-surface & exposure mapping CLI.

import argparse
import json
import os
import platform
import random
import socket
import html
import subprocess
import ssl
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional

# Type alias for module return
ModuleResult = Tuple[str, str, str, Dict[str, Any]]

REPORTS_DIR = Path("surface-scope-reports")
REPORTS_DIR.mkdir(exist_ok=True)

VERSION = "0.2.2"

# ---------------------
# Utility helpers
# ---------------------
def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

def report_filename(prefix: str = "report") -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return REPORTS_DIR / f"{prefix}-{ts}.txt"

def env_header() -> str:
    return (
        f"Host: {socket.gethostname()}\n"
        f"OS: {platform.system()} {platform.release()} ({platform.version()})\n"
        f"Python: {platform.python_version()}\n"
        f"User: {os.getenv('USERNAME') or os.getenv('USER') or 'unknown'}\n"
    )

def build_risk_summary(combined_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Derive quick metrics from the contexts for the 'Risk Summary' section and HTML."""
    summary = {
        "grade_counts": {"LOW": 0, "MED": 0, "HIGH ⚠": 0},
        "cloud_flag_counts": {},
        "top_flags": [],  # first 5 flags
    }
    grade_ctx = combined_ctx.get("modules", {}).get("grade", {}).get("ctx", {})
    probes = grade_ctx.get("probes", {})
    for _, info in probes.items():
        g = info.get("grade", "LOW")
        if g not in summary["grade_counts"]:
            summary["grade_counts"][g] = 0
        summary["grade_counts"][g] += 1

    cloud_ctx = combined_ctx.get("modules", {}).get("cloud", {}).get("ctx", {})
    flags = cloud_ctx.get("flags", [])
    for f in flags:
        t = f.get("type", "flag")
        summary["cloud_flag_counts"][t] = summary["cloud_flag_counts"].get(t, 0) + 1
    summary["top_flags"] = flags[:5]
    return summary

def render_risk_summary_text(rs: Dict[str, Any]) -> str:
    lines = ["[Risk Summary]"]
    gc = rs["grade_counts"]
    lines.append(f"• Grades: LOW={gc.get('LOW',0)}, MED={gc.get('MED',0)}, HIGH ⚠={gc.get('HIGH ⚠',0)}")
    if rs["cloud_flag_counts"]:
        lines.append("• Cloud Flags:")
        for k, v in rs["cloud_flag_counts"].items():
            lines.append(f"  - {k}: {v}")
    if rs["top_flags"]:
        lines.append("• Top Flags:")
        for f in rs["top_flags"]:
            ident = f.get("id") or f.get("name") or "item"
            lines.append(f"  - {f['type']}: {ident} ({f.get('detail','')})")
    return "\n".join(lines)

def write_html_report(path: Path, full_text: str, rs: Dict[str, Any], ctx: Dict[str, Any]) -> None:
    """Single-file HTML with lightweight styling."""
    grade_counts = rs["grade_counts"]
    flag_counts = rs["cloud_flag_counts"]
    top_flags = rs["top_flags"]

    # escape text report so it shows verbatim
    escaped = html.escape(full_text)

    # HTML template
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SurfaceScope Report</title>
<style>
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }}
  h1 {{ margin: 0 0 8px; }}
  .meta {{ color:#555; margin-bottom:16px; }}
  .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin:12px 0 18px; }}
  .card {{ border:1px solid #ddd; border-radius:12px; padding:12px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid #ccc; font-size:12px; }}
  pre {{ background:#f7f7f8; border:1px solid #eee; border-radius:8px; padding:12px; overflow:auto; }}
  .muted {{ color:#666; }}
</style>
</head>
<body>
  <h1>SurfaceScope Report</h1>
  <div class="meta muted">
    Policy: {html.escape(str(ctx.get('policy')))} · Ports: {html.escape(','.join(map(str, ctx.get('ports',[]))))} · Demo: {html.escape(str(ctx.get('demo')))}
  </div>

  <div class="grid">
    <div class="card">
      <div><span class="badge">LOW</span></div>
      <div style="font-size:28px; font-weight:700;">{grade_counts.get('LOW',0)}</div>
      <div class="muted">Assets graded LOW</div>
    </div>
    <div class="card">
      <div><span class="badge">MED</span></div>
      <div style="font-size:28px; font-weight:700;">{grade_counts.get('MED',0)}</div>
      <div class="muted">Assets graded MED</div>
    </div>
    <div class="card">
      <div><span class="badge">HIGH ⚠</span></div>
      <div style="font-size:28px; font-weight:700;">{grade_counts.get('HIGH ⚠',0)}</div>
      <div class="muted">Assets graded HIGH</div>
    </div>
    <div class="card">
      <div><span class="badge">Cloud Flags</span></div>
      <div style="font-size:28px; font-weight:700;">{sum(flag_counts.values())}</div>
      <div class="muted">Total flags detected</div>
    </div>
  </div>

  <div class="card">
    <div style="font-weight:600; margin-bottom:6px;">Top Flags</div>
    <ul>
      {"".join(f"<li>{html.escape(f.get('type','flag'))}: {html.escape(str(f.get('id') or f.get('name') or 'item'))} — {html.escape(f.get('detail',''))}</li>" for f in top_flags) or "<li class='muted'>None</li>"}
    </ul>
  </div>

  <h2>Full Text Report</h2>
  <pre>{escaped}</pre>
</body></html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_doc, encoding="utf-8")

def pretty_table(headers: List[str], rows: List[List[str]], pad: int = 2) -> str:
    col_widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            col_widths[i] = max(col_widths[i], len(str(c)))
    sep = "  "
    header_line = sep.join(h.ljust(col_widths[i] + pad) for i, h in enumerate(headers))
    lines = [header_line, "-" * len(header_line)]
    for r in rows:
        lines.append(sep.join(str(c).ljust(col_widths[i] + pad) for i, c in enumerate(r)))
    return "\n".join(lines)

def safe_tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """Lightweight TCP connect probe. Returns True if connect succeeds, False otherwise."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def get_http_headers(host: str, port: int = 80, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Minimal HTTP/1.0 probe using raw sockets to fetch status code and selected headers.
    Returns: {"status": int|None, "server": str|None, "x_powered_by": str|None}
    """
    out = {"status": None, "server": None, "x_powered_by": None}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: SurfaceScope/{VERSION}\r\n\r\n"
            s.sendall(req.encode("ascii", errors="ignore"))
            data = s.recv(4096).decode("latin-1", errors="ignore")
        head = data.split("\r\n\r\n", 1)[0].split("\r\n")
        if head:
            # status line like: HTTP/1.1 200 OK
            parts = head[0].split()
            if len(parts) >= 2 and parts[1].isdigit():
                out["status"] = int(parts[1])
        for line in head[1:]:
            k, _, v = line.partition(":")
            if not v:
                continue
            k_low = k.strip().lower()
            v = v.strip()
            if k_low == "server":
                out["server"] = v
            elif k_low == "x-powered-by":
                out["x_powered_by"] = v
    except Exception:
        pass
    return out

def get_https_headers(host: str, port: int = 443, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Minimal HTTPS probe: TLS handshake + plain GET, capture status + headers.
    Assumes SNI via server_hostname.
    Returns: {"status": int|None, "server": str|None, "x_powered_by": str|None}
    """
    out = {"status": None, "server": None, "x_powered_by": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.settimeout(timeout)
                req = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: SurfaceScope/{VERSION}\r\n\r\n"
                ssock.sendall(req.encode("ascii", errors="ignore"))
                data = ssock.recv(4096).decode("latin-1", errors="ignore")
        head = data.split("\r\n\r\n", 1)[0].split("\r\n")
        if head:
            parts = head[0].split()
            if len(parts) >= 2 and parts[1].isdigit():
                out["status"] = int(parts[1])
        for line in head[1:]:
            k, _, v = line.partition(":")
            if not v:
                continue
            k_low = k.strip().lower()
            v = v.strip()
            if k_low == "server":
                out["server"] = v
            elif k_low == "x-powered-by":
                out["x_powered_by"] = v
    except Exception:
        pass
    return out

def load_policy_config(policy: str, policy_json: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    """
    Returns (policy_label, cfg_dict) where cfg_dict has:
      - high_any: set[int]
      - med_num_open: int
    If policy_json is provided, overrides builtin thresholds.
    """
    builtin = {
        "minimal":  {"high_any": {22, 3389, 445},         "med_num_open": 3},
        "balanced": {"high_any": {22, 3389, 445},         "med_num_open": 2},
        "paranoid": {"high_any": {22, 3389, 445, 21, 23}, "med_num_open": 1},
    }
    label = (policy or "balanced").lower()
    cfg = dict(builtin.get(label, builtin["balanced"]))  # copy

    if policy_json:
        p = Path(policy_json)
        if not p.exists():
            raise FileNotFoundError(f"policy json not found: {policy_json}")
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        high_any = data.get("high_any", list(cfg["high_any"]))
        cfg["high_any"] = set(int(x) for x in high_any)
        if "med_num_open" in data:
            cfg["med_num_open"] = int(data["med_num_open"])
        label = f"custom({p.name})"
    return label, cfg

# ---------------------
# Module placeholders
# ---------------------
def discover(domain: str, limit: int = 100, demo: bool = False) -> ModuleResult:
    """
    Shadow Asset Discovery.
    Returns (status, reason, text_block, context)
    """
    ctx = {"domain": domain, "discovered": []}

    if demo:
        demo_hosts = [
            {"host": f"api.{domain}",              "type": "A",     "addr": "10.0.0.3",        "note": "resolved"},
            {"host": f"staging.{domain}",          "type": "A",     "addr": None,              "note": "NXDOMAIN"},
            {"host": f"dev-{domain.split('.')[0]}.github.io", "type": "CNAME", "addr": "github.io", "note": "dangling"},
            {"host": f"rdp.{domain}",              "type": "A",     "addr": "203.0.113.7",     "note": "resolved"},
            {"host": f"smb.{domain}",              "type": "A",     "addr": "203.0.113.8",     "note": "resolved"},
            {"host": f"vpn.{domain}",              "type": "A",     "addr": "198.51.100.5",    "note": "resolved"},
            {"host": f"old-backup.{domain}",       "type": "CNAME", "addr": "s3-website.amazonaws.com", "note": "possible public site"},
        ]
        ctx["discovered"] = demo_hosts[:limit]
        lines = ["[Shadow Discovery]", domain]
        for d in ctx["discovered"]:
            addr = d["addr"] or "—"
            note = f" [{d['note']}]" if d.get("note") else ""
            if d["type"] == "CNAME":
                lines.append(f"• Found: {d['host']} (CNAME {addr}){note}")
            else:
                lines.append(f"• Found: {d['host']} (A {addr}){note}")
        return ("OK", "demo results generated", "\n".join(lines), ctx)

    # Placeholder logic with nslookup CNAME hinting
    text_lines = [f"[Shadow Discovery] {domain}"]
    try:
        try:
            ip = socket.gethostbyname(domain)
            text_lines.append(f"• Apex resolves: {domain} (A {ip})")
            ctx["discovered"].append({"host": domain, "type": "A", "addr": ip, "note": "resolved"})
        except Exception:
            text_lines.append(f"• Apex: {domain} (could not resolve)")

        common = ["www", "api", "dev", "staging", "test"]
        for s in common[: min(limit, len(common))]:
            fqdn = f"{s}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                cname_target = None
                try:
                    p = subprocess.run(["nslookup", fqdn], capture_output=True, text=True, timeout=2)
                    out = p.stdout + p.stderr
                    for line in out.splitlines():
                        line = line.strip()
                        if "canonical name" in line.lower():
                            parts = line.split("=")
                            if len(parts) > 1:
                                cname_target = parts[1].strip().rstrip(".")
                                break
                except Exception:
                    pass
                ctx["discovered"].append({"host": fqdn, "type": "A", "addr": ip, "note": "resolved", "cname": cname_target})
                if cname_target:
                    text_lines.append(f"• Found: {fqdn} (A {ip}) [CNAME → {cname_target}]")
                else:
                    text_lines.append(f"• Found: {fqdn} (A {ip})")
            except Exception:
                cname_target = None
                try:
                    p = subprocess.run(["nslookup", fqdn], capture_output=True, text=True, timeout=2)
                    out = p.stdout + p.stderr
                    for line in out.splitlines():
                        line = line.strip()
                        if "canonical name" in line.lower():
                            parts = line.split("=")
                            if len(parts) > 1:
                                cname_target = parts[1].strip().rstrip(".")
                                break
                except Exception:
                    pass

                if cname_target:
                    dangling = any(x in cname_target.lower() for x in ("github.io", "s3.amazonaws.com", "amazonaws.com", "azurewebsites.net", "herokuapp.com"))
                    note = "dangling" if dangling else "CNAME"
                    ctx["discovered"].append({"host": fqdn, "type": "CNAME", "addr": cname_target, "note": note})
                    text_lines.append(f"• Found: {fqdn} (CNAME → {cname_target}) [{note}]")
                else:
                    ctx["discovered"].append({"host": fqdn, "type": "A", "addr": None, "note": "NXDOMAIN"})
                    text_lines.append(f"• Found: {fqdn} (NXDOMAIN)")

        return ("OK", "placeholder discovery completed", "\n".join(text_lines), ctx)
    except Exception as e:
        return ("ERROR", str(e), "\n".join(text_lines), ctx)

def grade(
    targets: List[Dict[str, Any]],
    ports: List[int],
    timeout: float = 1.0,
    demo: bool = False,
    policy: str = "balanced",
    demo_seed: Optional[int] = None,
    policy_cfg: Optional[Dict[str, Any]] = None,
) -> ModuleResult:
    """
    Exposure Grading.
    - policy: minimal | balanced | paranoid (tunes grading)
    """
    # Policy rules
    if policy_cfg:
        cfg = {
            "high_any": set(int(x) for x in policy_cfg.get("high_any", [])),
            "med_num_open": int(policy_cfg.get("med_num_open", 2)),
        }
        policy = policy or "custom"
    else:
        policy = (policy or "balanced").lower()
        rules = {
            "minimal":  {"high_any": {22, 3389, 445},         "med_num_open": 3},
            "balanced": {"high_any": {22, 3389, 445},         "med_num_open": 2},
            "paranoid": {"high_any": {22, 3389, 445, 21, 23}, "med_num_open": 1},
        }
        cfg = rules.get(policy, rules["balanced"])

    ctx: Dict[str, Any] = {"targets": targets, "probes": {}, "policy": policy}

    if demo:
        if demo_seed is not None:
            random.seed(demo_seed)

        demo_targets = targets[:] if targets else [
            {"host": "api.example.com"},
            {"host": "staging.example.com"},
            {"host": "rdp.example.com"},
            {"host": "smb.example.com"},
            {"host": "vpn.example.com"},
            {"host": "old-backup.example.com"},
        ]

        def demo_open_ports_for(host: str) -> List[int]:
            h = host.lower()
            if "staging" in h:
                return [22, 80, 3389]
            if "rdp" in h:
                return [3389]
            if "smb" in h:
                return [445]
            if "vpn" in h:
                return [80, 443]
            if "old-backup" in h or "backup" in h:
                return [80]
            if "dev-" in h or "github.io" in h:
                return [80]
            if "api" in h or "www" in h:
                return [80, 443]
            return [80]

        rows = []
        for t in demo_targets:
            host = t["host"]
            open_ports = demo_open_ports_for(host)
            grade_str = "LOW"
            if any(p in cfg["high_any"] for p in open_ports) and (80 in open_ports or 443 in open_ports or len(open_ports) > 1):
                grade_str = "HIGH ⚠"
            elif len(open_ports) >= cfg["med_num_open"]:
                grade_str = "MED"
            rows.append([host, ", ".join(str(p) for p in open_ports), grade_str])
            ctx["probes"][host] = {"open_ports": open_ports, "grade": grade_str}

            # HTTP/HTTPS banner sniff
            if 80 in open_ports:
                ctx["probes"][host]["http"] = get_http_headers(host, 80, timeout=timeout)
            if 443 in open_ports:
                ctx["probes"][host]["https"] = get_https_headers(host, 443, timeout=timeout)

        text = "[Exposure Grading]\n" + pretty_table(["Host", "Ports", "Grade"], rows)

        # Service banners section
        banner_lines = []
        for host, info in ctx["probes"].items():
            if "http" in info and (info["http"].get("status") is not None or info["http"].get("server")):
                s = info["http"]
                banner_lines.append(f"{host} (http) -> status={s.get('status')}  Server={s.get('server') or '—'}")
            if "https" in info and (info["https"].get("status") is not None or info["https"].get("server")):
                s = info["https"]
                banner_lines.append(f"{host} (https) -> status={s.get('status')}  Server={s.get('server') or '—'}")
        if banner_lines:
            text = text + "\n\n[Service Banners]\n" + "\n".join(banner_lines)

        return ("OK", "demo grading produced", text, ctx)

    # Real probe (minimal)
    rows = []
    try:
        for t in targets:
            host = t.get("host")
            open_ports = []
            for p in ports:
                if safe_tcp_connect(host, p, timeout=timeout):
                    open_ports.append(p)
            grade_str = "LOW"
            if any(p in cfg["high_any"] for p in open_ports) and (80 in open_ports or 443 in open_ports or len(open_ports) > 1):
                grade_str = "HIGH ⚠"
            elif len(open_ports) >= cfg["med_num_open"]:
                grade_str = "MED"
            rows.append([host, ", ".join(str(p) for p in open_ports) or "none", grade_str])
            ctx["probes"][host] = {"open_ports": open_ports, "grade": grade_str}

            # HTTP/HTTPS banner sniff
            if 80 in open_ports:
                ctx["probes"][host]["http"] = get_http_headers(host, 80, timeout=timeout)
            if 443 in open_ports:
                ctx["probes"][host]["https"] = get_https_headers(host, 443, timeout=timeout)

        text = "[Exposure Grading]\n" + pretty_table(["Host", "Ports", "Grade"], rows)

        # Service banners section
        banner_lines = []
        for host, info in ctx["probes"].items():
            if "http" in info and (info["http"].get("status") is not None or info["http"].get("server")):
                s = info["http"]
                banner_lines.append(f"{host} (http) -> status={s.get('status')}  Server={s.get('server') or '—'}")
            if "https" in info and (info["https"].get("status") is not None or info["https"].get("server")):
                s = info["https"]
                banner_lines.append(f"{host} (https) -> status={s.get('status')}  Server={s.get('server') or '—'}")
        if banner_lines:
            text = text + "\n\n[Service Banners]\n" + "\n".join(banner_lines)

        return ("OK", "grading completed", text, ctx)
    except Exception as e:
        return ("ERROR", str(e), "[Exposure Grading] failed", ctx)

def cloud_summary(json_path: Optional[str] = None, demo: bool = False) -> ModuleResult:
    """
    Cloud Footprint Summary placeholder.
    Expects a path to a JSON export (IaC / cli) or operates in demo mode.
    Returns counts and flagged risky items in context.
    """
    ctx: Dict[str, Any] = {"resources": {}, "flags": []}
    if demo:
        ctx["resources"] = {"buckets": 12, "public_buckets": 4, "instances": 7, "iam_roles": 11}
        ctx["flags"] = [
            {"type": "open_sg", "id": "sg-02ab...", "detail": "0.0.0.0/0 -> 22"},
            {"type": "open_sg", "id": "sg-0bad...", "detail": "0.0.0.0/0 -> 3389"},
            {"type": "public_bucket", "name": "example-public-bucket", "detail": "LIST/READ allowed"},
            {"type": "public_bucket", "name": "legacy-static-site", "detail": "Website hosting enabled"},
            {"type": "iam_overpriv", "name": "PowerUserRole", "detail": "wildcards in policy"},
        ]
        lines = ["[Cloud Footprint Summary]"]
        lines.append(f"Buckets: {ctx['resources']['buckets']} ({ctx['resources']['public_buckets']} public)")
        lines.append(f"Instances: {ctx['resources']['instances']}")
        lines.append(f"IAM Roles: {ctx['resources']['iam_roles']}")
        lines.append("Flags:")
        for f in ctx["flags"]:
            lines.append(f"⚠ {f['type']}: {f.get('id') or f.get('name')} ({f['detail']})")
        return ("OK", "demo cloud summary", "\n".join(lines), ctx)

    # Minimal parsing
    try:
        if not json_path:
            return ("WARN", "no cloud json provided", "[Cloud Footprint Summary] no input", ctx)
        p = Path(json_path)
        if not p.exists():
            return ("ERROR", f"json not found: {json_path}", "", ctx)
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        # Trivial example: expect top-level keys like 's3', 'ec2', 'iam'
        buckets = data.get("s3", [])
        instances = data.get("ec2", [])
        iam = data.get("iam", [])
        ctx["resources"] = {
            "buckets": len(buckets),
            "public_buckets": sum(1 for b in buckets if b.get("acl", "").lower() in ("public-read", "public")),
            "instances": len(instances),
            "iam_roles": len(iam),
        }
        # Flags: simplistic checks
        flags = []
        for b in buckets:
            if b.get("policy_allows_public", False) or b.get("acl", "").lower() in ("public-read", "public"):
                flags.append({"type": "public_bucket", "name": b.get("name"), "detail": "public read/list"})
        for sg in data.get("security_groups", []):
            for rule in sg.get("ingress", []):
                if rule.get("cidr") == "0.0.0.0/0" and rule.get("port") in (22, 3389):
                    flags.append({"type": "open_sg", "id": sg.get("id"), "detail": f"0.0.0.0/0 -> {rule.get('port')}"})
        ctx["flags"] = flags

        lines = ["[Cloud Footprint Summary]"]
        lines.append(f"Buckets: {ctx['resources']['buckets']} ({ctx['resources']['public_buckets']} public)")
        lines.append(f"Instances: {ctx['resources']['instances']}")
        lines.append(f"IAM Roles: {ctx['resources']['iam_roles']}")
        if flags:
            lines.append("Flags:")
            for f in flags:
                lines.append(f"⚠ {f['type']}: {f.get('id') or f.get('name')} ({f['detail']})")
        else:
            lines.append("No immediate flags detected.")
        return ("OK", "cloud summary parsed", "\n".join(lines), ctx)
    except Exception as e:
        return ("ERROR", str(e), "[Cloud Footprint Summary] failed", ctx)

# ---------------------
# High-level run
# ---------------------
def run_all(
    domain: Optional[str],
    cloud_json: Optional[str],
    out: Optional[str],
    ports: List[int],
    timeout: float,
    limit: int,
    demo: bool,
    targets_override: Optional[List[Dict[str, Any]]] = None,
    policy: str = "balanced",
    demo_seed: Optional[int] = None,
    json_out: Optional[str] = None,
    policy_json: Optional[str] = None,
    html_out: Optional[str] = None,
    no_write: bool = False,
    quiet: bool = False,
) -> ModuleResult:
    """
    Orchestrates discover -> grade -> cloud_summary and writes a combined report file.
    Returns (status, reason, FULL_REPORT_TEXT, context).
    """
    # Policy (may be overridden by custom file)
    policy_label, policy_cfg = load_policy_config(policy, policy_json)

    # Demo default domain
    effective_domain = domain
    demo_note = ""
    if demo and not domain:
        effective_domain = "example.com"
        demo_note = " (auto: example.com)"

    if demo_seed is not None:
        random.seed(demo_seed)

    combined_ctx: Dict[str, Any] = {
        "modules": {},
        "effective_domain": effective_domain,
        "demo": demo,
        "policy": policy_label,   # label not raw input
        "ports": ports,
        "timeout": timeout,
        "limit": limit,
        "seed": demo_seed,
        "version": VERSION,
    }

    report_lines = []
    header = (
        "SurfaceScope Report\n"
        f"Generated: {timestamp()}\n"
        f"Command: run\n"
        f"Demo mode: {demo}\n"
        f"{env_header()}"
    )
    report_lines.append(header)

    d_status, g_status, c_status = "SKIP", "SKIP", "SKIP"

    # 1) Discover
    if effective_domain:
        d_status, d_reason, d_text, d_ctx = discover(effective_domain, limit=limit, demo=demo)
        if demo_note:
            d_text = d_text + f"\n\n[Note] Demo discovery used domain{demo_note}"
        combined_ctx["modules"]["discover"] = {"status": d_status, "reason": d_reason, "ctx": d_ctx}
        report_lines.append(d_text)
        report_lines.append("\n")
    else:
        report_lines.append("[Shadow Discovery] Skipped (no domain provided)\n")

    # 2) Grade
    targets = []
    if targets_override:
        targets = targets_override
    else:
        disc_ctx = combined_ctx.get("modules", {}).get("discover", {}).get("ctx")
        if disc_ctx:
            for d in disc_ctx.get("discovered", []):
                targets.append({"host": d["host"]})
        if not targets and effective_domain and not demo:
            targets = [{"host": effective_domain}]

    g_status, g_reason, g_text, g_ctx = grade(
        targets, ports=ports, timeout=timeout, demo=demo,
        policy=policy_label, demo_seed=demo_seed, policy_cfg=policy_cfg
    )
    combined_ctx["modules"]["grade"] = {"status": g_status, "reason": g_reason, "ctx": g_ctx}
    report_lines.append(g_text)
    report_lines.append("\n")

    # 3) Cloud summary
    c_status, c_reason, c_text, c_ctx = cloud_summary(cloud_json, demo=demo)
    combined_ctx["modules"]["cloud"] = {"status": c_status, "reason": c_reason, "ctx": c_ctx}
    report_lines.append(c_text)
    report_lines.append("\n")

    # 4) Explanations
    report_lines.extend([
        "[What this means]",
        "• Low: Few open services detected; lower immediate exposure surface.",
        f"• Med: Multiple services exposed; threshold policy='{policy_label}'.",
        "• High ⚠: RDP/SSH/SMB exposed alongside web or multiple services; prioritize firewalling, MFA, patching.",
        "",
        "[Next checks]",
        "• Validate which hosts are truly internet-facing (vs VPN-only).",
        "• Cloud: review bucket ACLs, SGs, and IAM wildcards; remove public access; enforce least privilege.",
        "",
    ])

    # 5) Risk summary
    rs = build_risk_summary(combined_ctx)
    rs_text = render_risk_summary_text(rs)
    report_lines.append(rs_text)
    report_lines.append("")

    # 6) Footer + write files
    out_path = Path(out) if out else report_filename("surface-scope")
    full_report_text = "\n".join(report_lines) + (
        f"Report written to: {out_path}\n"
        f"Modules: discover={d_status}, grade={g_status}, cloud={c_status}\n"
    )

    # Write TXT
    if not no_write:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(full_report_text, encoding="utf-8")

    # Optional machine-readable JSON
    if json_out and not no_write:
        jpath = Path(json_out)
        jpath.parent.mkdir(parents=True, exist_ok=True)
        dump_ctx = dict(combined_ctx)
        dump_ctx["report_path"] = str(out_path)
        with jpath.open("w", encoding="utf-8") as fh:
            json.dump(dump_ctx, fh, indent=2)
        if not quiet:
            print(f"\nJSON written to: {jpath}")

    # Optional HTML report
    if html_out and not no_write:
        hpath = Path(html_out)
        write_html_report(hpath, full_report_text, rs, combined_ctx)
        if not quiet:
            print(f"HTML written to: {hpath}")

    return ("OK", "run completed", full_report_text, combined_ctx)

# ---------------------
# CLI wiring
# ---------------------
def parse_ports(s: str) -> List[int]:
    if not s:
        return [22, 80, 443, 445, 3389]
    return [int(p.strip()) for p in s.split(",") if p.strip()]

def load_targets_json(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    # Expect list of {"host": "..."}; allow legacy list of strings
    if isinstance(data, list) and data and isinstance(data[0], str):
        return [{"host": h} for h in data]
    return data

def selftest() -> bool:
    try:
        # Tiny sanity: Ensure helpers and a demo run do not crash
        _, _, _, _ = discover("example.com", demo=True)
        txt = pretty_table(["A","B"], [["x","y"]])
        assert "A" in txt and "x" in txt
        # run_all dry run
        ports = parse_ports("22,80,443,445,3389")
        status, reason, text, ctx = run_all(
            domain=None, cloud_json=None, out=None, ports=ports, timeout=1.0, limit=5, demo=True,
            targets_override=None, policy="balanced", demo_seed=42,
            json_out=None, policy_json=None, html_out=None, no_write=True, quiet=True
        )
        assert status == "OK" and "SurfaceScope Report" in text
        return True
    except Exception:
        return False

def main():
    ap = argparse.ArgumentParser(prog="surface-scope", description="SurfaceScope — attack-surface & exposure mapping")
    sub = ap.add_subparsers(dest="cmd", required=False)

    # discover
    dsc = sub.add_parser("discover", help="Discover shadow assets via DNS and simple heuristics")
    dsc.add_argument("--domain", "-d", required=True)
    dsc.add_argument("--limit", type=int, default=100)
    dsc.add_argument("--demo", action="store_true", help="Demo mode (fabricated results)")
    dsc.add_argument("--out", help="Write module output to file")
    dsc.add_argument("--no-write", action="store_true", help="Dry run: do not write any files")

    # grade
    grd = sub.add_parser("grade", help="Probe discovered hosts and compute exposure scores")
    grd.add_argument("--targets", help="JSON file with targets (list of {\"host\":\"...\"})")
    grd.add_argument("--ports", default="22,80,443,445,3389")
    grd.add_argument("--timeout", type=float, default=1.0)
    grd.add_argument("--demo", action="store_true")
    grd.add_argument("--out", help="Write module output to file")
    grd.add_argument("--no-write", action="store_true", help="Dry run: do not write any files")

    # cloud
    cld = sub.add_parser("cloud", help="Summarize offline IaC or AWS JSON assets")
    cld.add_argument("--cloud-json", required=False)
    cld.add_argument("--demo", action="store_true")
    cld.add_argument("--out", help="Write module output to file")
    cld.add_argument("--no-write", action="store_true", help="Dry run: do not write any files")

    # run
    runp = sub.add_parser("run", help="Run all modules and export a combined report")
    runp.add_argument("--domain", "-d", required=False)
    runp.add_argument("--cloud-json", required=False)
    runp.add_argument("--targets", help='JSON file with targets (list of {"host":"..."})')
    runp.add_argument("--ports", default="22,80,443,445,3389")
    runp.add_argument("--timeout", type=float, default=1.0)
    runp.add_argument("--limit", type=int, default=100)
    runp.add_argument("--out", help="Write combined report to path (default: surface-scope-reports/...)")
    runp.add_argument("--json-out", help="Also write machine-readable JSON with results/context")
    runp.add_argument("--policy", choices=["minimal", "balanced", "paranoid"], default="balanced")
    runp.add_argument("--demo", action="store_true")
    runp.add_argument("--demo-seed", type=int, help="Deterministic demo seed")
    runp.add_argument("--policy-json", help="Path to custom policy JSON (overrides --policy thresholds)")
    runp.add_argument("--html-out", help="Also write a single-file HTML report")
    runp.add_argument("--quiet", action="store_true", help="Reduce console output (still prints the report body)")
    runp.add_argument("--no-write", action="store_true", help="Dry run: do not write any files")

    # scan (alias of run)
    scan = sub.add_parser("scan", help="Alias of 'run' — execute all modules")
    scan.add_argument("--domain", "-d", required=False)
    scan.add_argument("--cloud-json", required=False)
    scan.add_argument("--targets", help='JSON file with targets (list of {"host":"..."})')
    scan.add_argument("--ports", default="22,80,443,445,3389")
    scan.add_argument("--timeout", type=float, default=1.0)
    scan.add_argument("--limit", type=int, default=100)
    scan.add_argument("--out", help="Write combined report to path (default: surface-scope-reports/...)")
    scan.add_argument("--json-out", help="Also write machine-readable JSON with results/context")
    scan.add_argument("--policy", choices=["minimal", "balanced", "paranoid"], default="balanced")
    scan.add_argument("--demo", action="store_true")
    scan.add_argument("--demo-seed", type=int, help="Deterministic demo seed")
    scan.add_argument("--policy-json", help="Path to custom policy JSON (overrides --policy thresholds)")
    scan.add_argument("--html-out", help="Also write a single-file HTML report")
    scan.add_argument("--quiet", action="store_true", help="Reduce console output (still prints the report body)")
    scan.add_argument("--no-write", action="store_true", help="Dry run: do not write any files")

    # selftest
    sub.add_parser("selftest", help="Run a minimal self test")

    args = ap.parse_args()

    # default: demo run
    if not args.cmd:
        ports = parse_ports("22,80,443,445,3389")
        _, _, text, _ = run_all(
            domain=None, cloud_json=None, out=None, ports=ports, timeout=1.0, limit=100, demo=True,
            targets_override=None, policy="balanced", demo_seed=1337, json_out=None,
            policy_json=None, html_out=None, no_write=True, quiet=False
        )
        print(text)
        return

    if args.cmd == "selftest":
        ok = selftest()
        print("Selftest OK" if ok else "Selftest FAILED")
        return

    if args.cmd == "discover":
        status, reason, text, ctx = discover(args.domain, limit=args.limit, demo=args.demo)
        print(text)
        if getattr(args, "out", None) and not getattr(args, "no_write", False):
            p = Path(args.out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        if getattr(args, "no_write", False):
            print("[DRY-RUN] --no-write set: no files were written.")
        return

    if args.cmd == "grade":
        targets = []
        if args.targets:
            targets = load_targets_json(args.targets)
        else:
            print("No --targets provided; nothing to grade.")
            return
        ports = parse_ports(args.ports)
        status, reason, text, ctx = grade(targets, ports=ports, timeout=args.timeout, demo=args.demo)
        print(text)
        if getattr(args, "out", None) and not getattr(args, "no_write", False):
            Path(args.out).write_text(text, encoding="utf-8")
        if getattr(args, "no_write", False):
            print("[DRY-RUN] --no-write set: no files were written.")
        return

    if args.cmd == "cloud":
        status, reason, text, ctx = cloud_summary(getattr(args, "cloud_json", None), demo=args.demo)
        print(text)
        if getattr(args, "out", None) and not getattr(args, "no_write", False):
            Path(args.out).write_text(text, encoding="utf-8")
        if getattr(args, "no_write", False):
            print("[DRY-RUN] --no-write set: no files were written.")
        return

    if args.cmd == "run":
        ports = parse_ports(args.ports)
        targets_override = None
        if getattr(args, "targets", None):
            try:
                targets_override = load_targets_json(args.targets)
            except FileNotFoundError:
                print(f"[WARN] Targets file not found: {args.targets}. Continuing without explicit targets.")
        _, _, text, _ = run_all(
            args.domain, args.cloud_json, args.out, ports, args.timeout, args.limit, args.demo,
            targets_override=targets_override, policy=args.policy, demo_seed=args.demo_seed,
            json_out=args.json_out, policy_json=args.policy_json, html_out=args.html_out,
            no_write=getattr(args, "no_write", False), quiet=getattr(args, "quiet", False)
        )
        print(text if not getattr(args, "quiet", False) else "", end="")
        if getattr(args, "no_write", False):
            print("[DRY-RUN] --no-write set: no files were written.")
        return

    if args.cmd == "scan":  # alias
        ports = parse_ports(args.ports)
        targets_override = None
        if getattr(args, "targets", None):
            try:
                targets_override = load_targets_json(args.targets)
            except FileNotFoundError:
                print(f"[WARN] Targets file not found: {args.targets}. Continuing without explicit targets.")
        _, _, text, _ = run_all(
            args.domain, args.cloud_json, args.out, ports, args.timeout, args.limit, args.demo,
            targets_override=targets_override, policy=args.policy, demo_seed=args.demo_seed,
            json_out=args.json_out, policy_json=args.policy_json, html_out=args.html_out,
            no_write=getattr(args, "no_write", False), quiet=getattr(args, "quiet", False)
        )
        print(text if not getattr(args, "quiet", False) else "", end="")
        if getattr(args, "no_write", False):
            print("[DRY-RUN] --no-write set: no files were written.")
        return

if __name__ == "__main__":
    main()
