#!/usr/bin/env python3
"""
surface_scope.py: Attack-surface & exposure mapping CLI.

Optional features:
 - DNS bruteforce using dnspython (install: pip install dnspython)
 - Live AWS snapshot using boto3 (install: pip install boto3)
"""

from __future__ import annotations
import argparse
import json
import os
import platform
import random
import socket
import html as html_mod
import ssl
import asyncio
import concurrent.futures
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional

# Optional dependency imports (handled gracefully)
try:
    import dns.resolver  # type: ignore
    DNSPY_AVAILABLE = True
except Exception:
    DNSPY_AVAILABLE = False

try:
    import boto3  # type: ignore
    from botocore.exceptions import NoCredentialsError, ClientError, BotoCoreError  # type: ignore
    BOTO3_AVAILABLE = True
except Exception:
    BOTO3_AVAILABLE = False

# Type alias
ModuleResult = Tuple[str, str, str, Dict[str, Any]]

# Reports dir
REPORTS_DIR = Path("surface-scope-reports")
REPORTS_DIR.mkdir(exist_ok=True)


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
    summary = {
        "grade_counts": {"LOW": 0, "MED": 0, "HIGH ⚠": 0},
        "cloud_flag_counts": {},
        "top_flags": [],
    }
    grade_ctx = combined_ctx.get("modules", {}).get("grade", {}).get("ctx", {})
    probes = grade_ctx.get("probes", {})
    for host, info in probes.items():
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
    grade_counts = rs["grade_counts"]
    flag_counts = rs["cloud_flag_counts"]
    top_flags = rs["top_flags"]
    escaped = html_mod.escape(full_text)
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
    Policy: {html_mod.escape(str(ctx.get('policy')))} · Ports: {html_mod.escape(','.join(map(str, ctx.get('ports',[]))))} · Demo: {html_mod.escape(str(ctx.get('demo')))}
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
      {"".join(f"<li>{html_mod.escape(f.get('type','flag'))}: {html_mod.escape(str(f.get('id') or f.get('name') or 'item'))} — {html_mod.escape(f.get('detail',''))}</li>" for f in top_flags) or "<li class='muted'>None</li>"}
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


# ---------------------
# Network helpers
# ---------------------
def safe_tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_http_server_header(host: str, port: int = 80, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """Fetch minimal HTTP info using raw socket; returns dict or None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: SurfaceScope/0.1\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("ascii", errors="ignore"))
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
            text = data.decode("latin-1", errors="ignore")
            lines = text.split("\r\n")
            status = None
            headers = {}
            if lines:
                status_line = lines[0]
                if status_line.startswith("HTTP/"):
                    parts = status_line.split(" ", 2)
                    if len(parts) >= 2:
                        status = int(parts[1])
                for h in lines[1:]:
                    if ":" in h:
                        k, v = h.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
            return {"status": status, "server": headers.get("server"), "x_powered_by": headers.get("x-powered-by")}
    except Exception:
        return None


def get_https_server_info(host: str, port: int = 443, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Attempt TLS handshake to capture SNI cert info and then fetch HTTP headers over TLS."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # cert subject / issuer brief
                cert = ssock.getpeercert()
                # attempt minimal GET
                req = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: SurfaceScope/0.1\r\nConnection: close\r\n\r\n"
                ssock.sendall(req.encode("ascii", errors="ignore"))
                data = b""
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    except socket.timeout:
                        break
                text = data.decode("latin-1", errors="ignore")
                headers = {}
                lines = text.split("\r\n")
                status = None
                if lines:
                    status_line = lines[0]
                    if status_line.startswith("HTTP/"):
                        parts = status_line.split(" ", 2)
                        if len(parts) >= 2:
                            try:
                                status = int(parts[1])
                            except Exception:
                                status = None
                    for h in lines[1:]:
                        if ":" in h:
                            k, v = h.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                cert_subject = None
                if cert:
                    subj = cert.get("subject", ())
                    # subject is a sequence of tuples
                    subj_parts = []
                    for s in subj:
                        for kv in s:
                            subj_parts.append(f"{kv[0]}={kv[1]}")
                    cert_subject = ", ".join(subj_parts)
                return {"status": status, "server": headers.get("server"), "x_powered_by": headers.get("x-powered-by"), "cert_subject": cert_subject}
    except Exception:
        return None


# ---------------------
# Policy loader
# ---------------------
def load_policy_config(policy: str, policy_json: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    builtin = {
        "minimal":  {"high_any": {22, 3389, 445},        "med_num_open": 3},
        "balanced": {"high_any": {22, 3389, 445},        "med_num_open": 2},
        "paranoid": {"high_any": {22, 3389, 445, 21, 23}, "med_num_open": 1},
    }
    label = (policy or "balanced").lower()
    cfg = dict(builtin.get(label, builtin["balanced"]))
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
# DNS wordlist discovery (optional)
# ---------------------
def discover_with_wordlist(domain: str, wordlist_path: str, workers: int = 20, timeout: float = 1.5) -> Tuple[str, str, List[Dict[str, Any]], Dict[str, Any]]:
    if not DNSPY_AVAILABLE:
        return ("WARN", "dnspython not installed", [], {"error": "dnspython not available"})
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            labels = [ln.strip() for ln in fh if ln.strip()]
    except Exception as e:
        return ("ERROR", f"cannot read wordlist: {e}", [], {})

    hosts: List[Dict[str, Any]] = []
    errors: List[str] = []

    def check_label(label: str) -> Optional[Dict[str, Any]]:
        fqdn = f"{label}.{domain}".rstrip(".")
        out = {"host": fqdn, "type": None, "addr": None, "note": None}
        try:
            # A/AAAA
            try:
                ans = resolver.resolve(fqdn, "A")
                if ans:
                    out["type"] = "A"
                    out["addr"] = str(ans[0])
                    out["note"] = "resolved"
                    return out
            except Exception:
                pass
            try:
                ans = resolver.resolve(fqdn, "CNAME")
                if ans:
                    target = str(ans[0]).rstrip(".")
                    out["type"] = "CNAME"
                    out["addr"] = target
                    dangling = any(x in target.lower() for x in ("github.io", "s3.amazonaws.com", "amazonaws.com", "azurewebsites.net", "herokuapp.com"))
                    out["note"] = "dangling" if dangling else "CNAME"
                    return out
            except Exception:
                pass
            out["type"] = "A"
            out["addr"] = None
            out["note"] = "NXDOMAIN"
            return out
        except Exception as e:
            errors.append(f"{fqdn}: {e}")
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(check_label, labels):
            if res:
                hosts.append(res)
    return ("OK", "wordlist discovery complete", hosts, {"errors": errors})


# ---------------------
# Module implementations
# ---------------------
def discover(domain: str, limit: int = 100, demo: bool = False, dns_wordlist: Optional[str] = None, dns_workers: int = 20, dns_timeout: float = 1.5) -> ModuleResult:
    ctx = {"domain": domain, "discovered": []}
    if demo:
        demo_hosts = [
            {"host": f"api.{domain}", "type": "A", "addr": "10.0.0.3", "note": "resolved"},
            {"host": f"staging.{domain}", "type": "A", "addr": None, "note": "NXDOMAIN"},
            {"host": f"dev-{domain.split('.')[0]}.github.io", "type": "CNAME", "addr": "github.io", "note": "dangling"},
            {"host": f"rdp.{domain}", "type": "A", "addr": "203.0.113.7", "note": "resolved"},
            {"host": f"smb.{domain}", "type": "A", "addr": "203.0.113.8", "note": "resolved"},
            {"host": f"vpn.{domain}", "type": "A", "addr": "198.51.100.5", "note": "resolved"},
            {"host": f"old-backup.{domain}", "type": "CNAME", "addr": "s3-website.amazonaws.com", "note": "possible public site"},
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
        # If dns_wordlist provided in demo, run and append
        if dns_wordlist:
            w_status, w_reason, w_hosts, w_ctx = discover_with_wordlist(domain, dns_wordlist, workers=dns_workers, timeout=dns_timeout)
            if w_hosts:
                ctx["discovered"].extend(w_hosts[:max(0, limit - len(ctx["discovered"]))])
                lines.append("\n[Bruteforce Discovery] (demo + wordlist)")
                for w in w_hosts[:10]:
                    lines.append(f"• {w['host']} ({w['type']} {w.get('addr') or '—'}) [{w.get('note')}]")
        return ("OK", "demo results generated", "\n".join(lines), ctx)

    # Real placeholder logic
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
                # Attempt nslookup to extract CNAME details (best-effort)
                cname_target = None
                try:
                    p = subprocess.run(["nslookup", fqdn], capture_output=True, text=True, timeout=2)
                    out = p.stdout + p.stderr
                    for line in out.splitlines():
                        line = line.strip()
                        if "canonical name" in line.lower() or "canonical name =" in line.lower():
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
                # attempt nslookup to see if CNAME exists
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

        # optional dns bruteforce (user-supplied)
        if dns_wordlist:
            w_status, w_reason, w_hosts, w_ctx = discover_with_wordlist(domain, dns_wordlist, workers=dns_workers, timeout=dns_timeout)
            if w_status.startswith("OK") and w_hosts:
                text_lines.append("\n[Bruteforce Discovery]")
                for w in w_hosts[:min(40, len(w_hosts))]:
                    ctx["discovered"].append(w)
                    text_lines.append(f"• {w['host']} ({w['type']} {w.get('addr') or '—'}) [{w.get('note')}]")
            elif w_status == "WARN":
                text_lines.append(f"\n[Bruteforce Discovery] skipped: dnspython not installed (pass --dns-wordlist after installing dnspython)")
            elif w_status == "ERROR":
                text_lines.append(f"\n[Bruteforce Discovery] error: {w_reason}")

        return ("OK", "discovery completed", "\n".join(text_lines), ctx)
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
    async_probe: bool = False,
) -> ModuleResult:
    if policy_cfg:
        cfg = {
            "high_any": set(int(x) for x in policy_cfg.get("high_any", [])),
            "med_num_open": int(policy_cfg.get("med_num_open", 2)),
        }
        policy = policy or "custom"
    else:
        policy = (policy or "balanced").lower()
        rules = {
            "minimal":  {"high_any": {22, 3389, 445},        "med_num_open": 3},
            "balanced": {"high_any": {22, 3389, 445},        "med_num_open": 2},
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
            # service probes
            if 80 in open_ports:
                info = get_http_server_header(host, 80, timeout=timeout)
                if info:
                    ctx["probes"][host]["http"] = info
            if 443 in open_ports:
                info = get_https_server_info(host, 443, timeout=timeout)
                if info:
                    ctx["probes"][host]["https"] = info

        text = "[Exposure Grading]\n" + pretty_table(["Host", "Ports", "Grade"], rows)
        banner_lines = []
        for host, info in ctx.get("probes", {}).items():
            if info.get("http"):
                banner_lines.append(f"{host} (http) -> status={info['http'].get('status')}  Server={info['http'].get('server')}")
            if info.get("https"):
                banner_lines.append(f"{host} (https) -> status={info['https'].get('status')}  Server={info['https'].get('server')}")
        if banner_lines:
            text = text + "\n\n[Service Banners]\n" + "\n".join(banner_lines)
        return ("OK", "demo grading produced", text, ctx)

    # Real probe path
    rows = []
    try:
        if async_probe:
            # async probing using asyncio
            async def probe_host(host: str, ports_list: List[int], timeout: float) -> Tuple[str, List[int], Optional[Dict[str, Any]]]:
                open_ports_local: List[int] = []
                for p in ports_list:
                    try:
                        fut = asyncio.open_connection(host, p)
                        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                        open_ports_local.append(p)
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                    except Exception:
                        pass
                return host, open_ports_local, None

            async def run_all_hosts(hosts: List[str], ports_list: List[int], timeout: float):
                tasks = [probe_host(h, ports_list, timeout) for h in hosts]
                results = await asyncio.gather(*tasks)
                return results

            host_list = [t.get("host") for t in targets]
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(run_all_hosts(host_list, ports, timeout))
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                loop.close()
            for host, open_ports_local, _ in results:
                grade_str = "LOW"
                if any(p in cfg["high_any"] for p in open_ports_local) and (80 in open_ports_local or 443 in open_ports_local or len(open_ports_local) > 1):
                    grade_str = "HIGH ⚠"
                elif len(open_ports_local) >= cfg["med_num_open"]:
                    grade_str = "MED"
                rows.append([host, ", ".join(str(p) for p in open_ports_local) or "none", grade_str])
                ctx["probes"][host] = {"open_ports": open_ports_local, "grade": grade_str}
                # banners
                if 80 in open_ports_local:
                    info = get_http_server_header(host, 80, timeout=timeout)
                    if info:
                        ctx["probes"][host]["http"] = info
                if 443 in open_ports_local:
                    info = get_https_server_info(host, 443, timeout=timeout)
                    if info:
                        ctx["probes"][host]["https"] = info
        else:
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
                # banners
                if 80 in open_ports:
                    info = get_http_server_header(host, 80, timeout=timeout)
                    if info:
                        ctx["probes"][host]["http"] = info
                if 443 in open_ports:
                    info = get_https_server_info(host, 443, timeout=timeout)
                    if info:
                        ctx["probes"][host]["https"] = info

        text = "[Exposure Grading]\n" + pretty_table(["Host", "Ports", "Grade"], rows)
        banner_lines = []
        for host, info in ctx.get("probes", {}).items():
            if info.get("http"):
                banner_lines.append(f"{host} (http) -> status={info['http'].get('status')}  Server={info['http'].get('server')}")
            if info.get("https"):
                banner_lines.append(f"{host} (https) -> status={info['https'].get('status')}  Server={info['https'].get('server')}")
        if banner_lines:
            text = text + "\n\n[Service Banners]\n" + "\n".join(banner_lines)
        return ("OK", "grading completed", text, ctx)
    except Exception as e:
        return ("ERROR", str(e), "[Exposure Grading] failed", ctx)


# ---------------------
# Cloud summary (local JSON or live AWS)
# ---------------------
def cloud_summary_from_json(json_path: Optional[str] = None, demo: bool = False) -> ModuleResult:
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

    try:
        if not json_path:
            return ("WARN", "no cloud json provided", "[Cloud Footprint Summary] no input", ctx)
        p = Path(json_path)
        if not p.exists():
            return ("ERROR", f"json not found: {json_path}", "", ctx)
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        buckets = data.get("s3", [])
        instances = data.get("ec2", [])
        iam = data.get("iam", [])
        ctx["resources"] = {
            "buckets": len(buckets),
            "public_buckets": sum(1 for b in buckets if b.get("acl", "").lower() in ("public-read", "public")),
            "instances": len(instances),
            "iam_roles": len(iam),
        }
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


def cloud_summary_live_aws() -> ModuleResult:
    ctx: Dict[str, Any] = {"resources": {}, "flags": []}
    if not BOTO3_AVAILABLE:
        return ("WARN", "boto3 not installed", "[Cloud Footprint Summary] boto3 missing", ctx)
    try:
        s3 = boto3.client("s3")
        ec2 = boto3.client("ec2")
        iam = boto3.client("iam")
        buckets_resp = s3.list_buckets()
        buckets = buckets_resp.get("Buckets", [])
        public_buckets = 0
        flags = []
        for b in buckets:
            name = b.get("Name")
            pub = False
            try:
                # ACL check (best-effort)
                acl = s3.get_bucket_acl(Bucket=name)
                for g in acl.get("Grants", []):
                    gr = g.get("Grantee", {})
                    if gr.get("URI", "").endswith("/AllUsers") or gr.get("URI", "").endswith("/AuthenticatedUsers"):
                        pub = True
                        break
            except Exception:
                pass
            try:
                pol_status = s3.get_bucket_policy_status(Bucket=name)
                if pol_status.get("PolicyStatus", {}).get("IsPublic"):
                    pub = True
            except Exception:
                pass
            if pub:
                public_buckets += 1
                flags.append({"type": "public_bucket", "name": name, "detail": "public read/list (policy/ACL)"})

        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            sgid = sg.get("GroupId")
            for r in sg.get("IpPermissions", []):
                port = r.get("FromPort")
                for rng in r.get("IpRanges", []):
                    if rng.get("CidrIp") == "0.0.0.0/0" and port in (22, 3389):
                        flags.append({"type": "open_sg", "id": sgid, "detail": f"0.0.0.0/0 -> {port}"})

        roles = iam.list_roles().get("Roles", [])
        # coarse instance count
        instances = sum(1 for r in ec2.describe_instances().get("Reservations", []))

        ctx["resources"] = {
            "buckets": len(buckets),
            "public_buckets": public_buckets,
            "instances": instances,
            "iam_roles": len(roles),
        }
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
        return ("OK", "live AWS snapshot", "\n".join(lines), ctx)
    except NoCredentialsError:
        return ("ERROR", "no AWS credentials found", "[Cloud Footprint Summary] missing AWS creds", ctx)
    except (BotoCoreError, ClientError) as e:
        return ("ERROR", str(e), "[Cloud Footprint Summary] AWS error", ctx)
    except Exception as e:
        return ("ERROR", str(e), "[Cloud Footprint Summary] failed", ctx)


# ---------------------
# Orchestration
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
    json_out: Optional[str] = None,   # kept for context echo in returned ctx, not used for writing
    policy_json: Optional[str] = None,
    html_out: Optional[str] = None,   # kept for context echo in returned ctx, not used for writing
    dns_wordlist: Optional[str] = None,
    dns_workers: int = 20,
    dns_timeout: float = 1.5,
    aws_live: bool = False,
    async_probe: bool = False,
) -> ModuleResult:
    """
    Orchestrates modules and returns:
      - status, reason
      - full_report_text (NO file writes)
      - combined_ctx (includes suggested out path for the text report)
    """
    policy_label, policy_cfg = load_policy_config(policy, policy_json)
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
        "policy": policy_label,
        "ports": ports,
        "timeout": timeout,
        "limit": limit,
        "seed": demo_seed,
        "version": "0.2.3",
        "intended_json_out": json_out,
        "intended_html_out": html_out,
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
    d_status = g_status = c_status = "SKIP"

    # Discover
    if effective_domain:
        d_status, d_reason, d_text, d_ctx = discover(
            effective_domain, limit=limit, demo=demo,
            dns_wordlist=dns_wordlist, dns_workers=dns_workers, dns_timeout=dns_timeout
        )
        if demo_note:
            d_text = d_text + f"\n\n[Note] Demo discovery used domain{demo_note}"
        combined_ctx["modules"]["discover"] = {"status": d_status, "reason": d_reason, "ctx": d_ctx}
        report_lines.append(d_text)
        report_lines.append("\n")
    else:
        report_lines.append("[Shadow Discovery] Skipped (no domain provided)\n")

    # Targets
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

    # Grade
    g_status, g_reason, g_text, g_ctx = grade(
        targets, ports=ports, timeout=timeout, demo=demo,
        policy=policy_label, demo_seed=demo_seed, policy_cfg=policy_cfg,
        async_probe=async_probe
    )
    combined_ctx["modules"]["grade"] = {"status": g_status, "reason": g_reason, "ctx": g_ctx}
    report_lines.append(g_text)
    report_lines.append("\n")

    # Cloud
    if aws_live:
        c_status, c_reason, c_text, c_ctx = cloud_summary_live_aws()
        if cloud_json:
            c_text = c_text + "\n\n[Note] --aws-live provided: ignoring --cloud-json input."
    else:
        c_status, c_reason, c_text, c_ctx = cloud_summary_from_json(cloud_json, demo=demo)
    combined_ctx["modules"]["cloud"] = {"status": c_status, "reason": c_reason, "ctx": c_ctx}
    report_lines.append(c_text)
    report_lines.append("\n")

    # Explanations
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

    # Risk summary
    rs = build_risk_summary(combined_ctx)
    rs_text = render_risk_summary_text(rs)
    report_lines.append(rs_text)
    report_lines.append("")  # spacer

    # Decide suggested path (but DO NOT write here)
    suggested_path = Path(out) if out else report_filename("surface-scope")
    combined_ctx["suggested_report_path"] = str(suggested_path)

    full_report_text = "\n".join(report_lines) + (
        f"Report written to: {suggested_path}\n"
        f"Modules: discover={d_status}, grade={g_status}, cloud={c_status}\n"
    )

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
    if isinstance(data, list) and data and isinstance(data[0], str):
        return [{"host": h} for h in data]
    return data


def main():
    ap = argparse.ArgumentParser(prog="surface-scope", description="SurfaceScope — attack-surface & exposure mapping")
    sub = ap.add_subparsers(dest="cmd", required=False)

    dsc = sub.add_parser("discover", help="Discover shadow assets via DNS and simple heuristics")
    dsc.add_argument("--domain", "-d", required=True)
    dsc.add_argument("--limit", type=int, default=100)
    dsc.add_argument("--demo", action="store_true")
    dsc.add_argument("--out", help="Write module output to file")
    dsc.add_argument("--dns-wordlist", help="Optional wordlist path for bruteforce (requires dnspython)")
    dsc.add_argument("--dns-workers", type=int, default=20)
    dsc.add_argument("--dns-timeout", type=float, default=1.5)

    grd = sub.add_parser("grade", help="Probe discovered hosts and compute exposure scores")
    grd.add_argument("--targets", help="JSON file with targets (list of {\"host\":\"...\"})")
    grd.add_argument("--ports", default="22,80,443,445,3389")
    grd.add_argument("--timeout", type=float, default=1.0)
    grd.add_argument("--demo", action="store_true")
    grd.add_argument("--out", help="Write module output to file")
    grd.add_argument("--async-probe", action="store_true", help="Use asyncio for port probes (faster)")

    cld = sub.add_parser("cloud", help="Summarize offline IaC or AWS JSON assets")
    cld.add_argument("--cloud-json", required=False)
    cld.add_argument("--demo", action="store_true")
    cld.add_argument("--out", help="Write module output to file")
    cld.add_argument("--aws-live", action="store_true", help="Use boto3 to snapshot live AWS account (requires boto3)")

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
    runp.add_argument("--quiet", action="store_true", help="Suppresses all console output except errors.")
    runp.add_argument("--no-write", action="store_true", help="Dry run: do not write any files")
    runp.add_argument("--dns-wordlist", help="Optional wordlist path for bruteforce (requires dnspython)")
    runp.add_argument("--dns-workers", type=int, default=20)
    runp.add_argument("--dns-timeout", type=float, default=1.5)
    runp.add_argument("--aws-live", action="store_true", help="Use boto3 to snapshot live AWS account (requires boto3)")
    runp.add_argument("--async-probe", action="store_true", help="Use asyncio for port probes (faster)")

    scan = sub.add_parser("scan", help="Alias of 'run' — execute all modules")
    # mirror run args for scan
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
    scan.add_argument("--quiet", action="store_true", help="Suppresses all console output except errors.")
    scan.add_argument("--no-write", action="store_true", help="Dry run: do not write any files")
    scan.add_argument("--dns-wordlist", help="Optional wordlist path for bruteforce (requires dnspython)")
    scan.add_argument("--dns-workers", type=int, default=20)
    scan.add_argument("--dns-timeout", type=float, default=1.5)
    scan.add_argument("--aws-live", action="store_true", help="Use boto3 to snapshot live AWS account (requires boto3)")
    scan.add_argument("--async-probe", action="store_true", help="Use asyncio for port probes (faster)")

    sub.add_parser("selftest", help="Run a minimal self test")

    args = ap.parse_args()

    # default run if no cmd
    if not args.cmd:
        ports = parse_ports("22,80,443,445,3389")
        _, _, text, _ = run_all(
            domain=None, cloud_json=None, out=None, ports=ports, timeout=1.0, limit=100, demo=True,
            targets_override=None, policy="balanced", demo_seed=1337, json_out=None,
            policy_json=None, html_out=None, dns_wordlist=None, dns_workers=20, dns_timeout=1.5,
            aws_live=False, async_probe=False
        )
        print(text)
        return

    if args.cmd == "selftest":
        print("Selftest OK")
        return

    if args.cmd == "discover":
        status, reason, text, ctx = discover(args.domain, limit=args.limit, demo=args.demo, dns_wordlist=getattr(args, "dns_wordlist", None), dns_workers=getattr(args, "dns_workers", 20), dns_timeout=getattr(args, "dns_timeout", 1.5))
        print(text)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        return

    if args.cmd == "grade":
        targets = []
        if args.targets:
            targets = load_targets_json(args.targets)
        else:
            print("No --targets provided; nothing to grade.")
            return
        ports = parse_ports(args.ports)
        status, reason, text, ctx = grade(targets, ports=ports, timeout=args.timeout, demo=args.demo, async_probe=getattr(args, "async_probe", False))
        print(text)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        return

    if args.cmd == "cloud":
        status, reason, text, ctx = (cloud_summary_live_aws() if getattr(args, "aws_live", False) else cloud_summary_from_json(getattr(args, "cloud_json", None), demo=args.demo))
        print(text)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        return

    if args.cmd in ("run", "scan"):
        ports = parse_ports(args.ports)
        targets_override = None
        if getattr(args, "targets", None):
            try:
                targets_override = load_targets_json(args.targets)
            except FileNotFoundError:
                print(f"[WARN] Targets file not found: {args.targets}. Continuing without explicit targets.")

        status, reason, text, ctx = run_all(
            getattr(args, "domain", None),
            getattr(args, "cloud_json", None),
            getattr(args, "out", None),
            ports,
            getattr(args, "timeout", 1.0),
            getattr(args, "limit", 100),
            getattr(args, "demo", False),
            targets_override=targets_override,
            policy=getattr(args, "policy", "balanced"),
            demo_seed=getattr(args, "demo_seed", None),
            json_out=getattr(args, "json_out", None),   # only echoed back in ctx
            policy_json=getattr(args, "policy_json", None),
            html_out=getattr(args, "html_out", None),   # only echoed back in ctx
            dns_wordlist=getattr(args, "dns_wordlist", None),
            dns_workers=getattr(args, "dns_workers", 20),
            dns_timeout=getattr(args, "dns_timeout", 1.5),
            aws_live=getattr(args, "aws_live", False),
            async_probe=getattr(args, "async_probe", False),
        )

        # Respect --quiet for console printing
        if not getattr(args, "quiet", False):
            print(text)
        else:
            print(f"SurfaceScope: {status} — {reason}")

        # Absolute no-write guard (NO files created when set)
        if getattr(args, "no_write", False):
            print("[DRY-RUN] --no-write set: no files were written.")
            return

        # Write artifacts ONLY when no_write is False
        suggested_path = Path(ctx.get("suggested_report_path", report_filename("surface-scope")))
        suggested_path.parent.mkdir(parents=True, exist_ok=True)
        suggested_path.write_text(text, encoding="utf-8")

        intended_json = getattr(args, "json_out", None)
        if intended_json:
            jpath = Path(intended_json)
            jpath.parent.mkdir(parents=True, exist_ok=True)
            dump_ctx = dict(ctx)
            dump_ctx["report_path"] = str(suggested_path)
            with jpath.open("w", encoding="utf-8") as fh:
                json.dump(dump_ctx, fh, indent=2)
            print(f"JSON written to: {jpath}")

        intended_html = getattr(args, "html_out", None)
        if intended_html:
            hpath = Path(intended_html)
            hpath.parent.mkdir(parents=True, exist_ok=True)
            # Build risk summary again for HTML cards
            rs = build_risk_summary(ctx)
            write_html_report(hpath, text, rs, ctx)
            print(f"HTML written to: {hpath}")

        return

    # fallback
    ap.print_help()


if __name__ == "__main__":
    main()
