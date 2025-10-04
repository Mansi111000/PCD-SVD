from __future__ import annotations
from typing import Dict, Any, Iterable, List, Tuple
from pathlib import Path
import re, json
from markupsafe import escape

from .cfg import CFG, cfg_to_mermaid
from .utils import FindingSet

TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "templates" / "premium_report.html"

# ---------- Finding helpers ----------

def _iter_issues(fset: Any) -> Iterable[Any]:
    if fset is None:
        return []
    if hasattr(fset, "by_severity"):
        try:
            return list(fset.by_severity())
        except Exception:
            pass
    issues = getattr(fset, "issues", None)
    if isinstance(issues, list):
        return issues
    try:
        return list(fset)
    except Exception:
        return []

# ---------- Source rendering ----------

_UNSAFE_FUNCS = re.compile(r"\b(strcpy|strcat|gets|scanf|system|memcpy|printf)\b")

def _render_code_with_lines(source: str) -> str:
    src = (source or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: List[str] = []
    for i, line in enumerate(src, start=1):
        esc = escape(line)
        esc = _UNSAFE_FUNCS.sub(
            r"<mark class='px-1 rounded bg-red-700 text-white'>\1</mark>", str(esc)
        )
        out.append(
            f"<div class='line' id='L{i}'>"
            f"<span class='ln'>{i:>4}</span>"
            f"<span class='lc'>{esc}</span>"
            f"</div>"
        )
    return "\n".join(out)

# ---------- Line mapping ----------

_TOKEN_RE = re.compile(r"[A-Za-z_]\w+")

def _function_bounds(lines: List[str], fname: str) -> Tuple[int, int] | None:
    pat = re.compile(rf"\b{re.escape(fname)}\s*\(")
    start_idx = None
    for i, ln in enumerate(lines):
        if pat.search(ln):
            start_idx = i
            break
    if start_idx is None:
        return None
    depth = 0
    started = False
    for j in range(start_idx, len(lines)):
        depth += lines[j].count("{")
        if depth > 0:
            started = True
        depth -= lines[j].count("}")
        if started and depth == 0:
            return (start_idx + 1, j + 1)
    return None

def _scan_for_tokens(lines: List[str], tokens: List[str], bounds: Tuple[int,int] | None) -> int | None:
    rng = range(len(lines))
    if bounds:
        lo, hi = bounds
        rng = range(lo-1, hi)
    toks = [t for t in tokens if t]
    if not toks:
        return None
    for i in rng:
        ln = lines[i]
        if any(t in ln for t in toks):
            return i+1
    for i in range(len(lines)):
        if any(t in lines[i] for t in toks):
            return i+1
    return None

def _guess_issue_line(issue: Any, source: str, fname: str | None) -> int | None:
    ev = getattr(issue, "evidence", None) or {}
    if isinstance(ev, dict) and "line" in ev:
        try:
            ln = int(ev["line"])
            if ln > 0:
                return ln
        except Exception:
            pass
    text = (source or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    bounds = _function_bounds(lines, fname) if fname else None

    tokens: List[str] = []
    if isinstance(ev, dict):
        call = ev.get("call"); expr = ev.get("expr"); reads = ev.get("reads")
        if call:
            m = re.match(r"\s*([A-Za-z_]\w*)\s*\(", call)
            tokens.append(m.group(1) if m else call[:32])
        if expr:
            tokens += _TOKEN_RE.findall(expr)
        if isinstance(reads, (list, tuple)):
            tokens += [str(x) for x in reads]
    msg = getattr(issue, "message", "") or ""
    tokens += _TOKEN_RE.findall(msg)
    for sink in ("strcpy","strcat","gets","scanf","system","memcpy","printf"):
        if sink in msg.lower():
            tokens.append(sink)

    return _scan_for_tokens(lines, tokens, bounds)

# ---------- Findings table ----------

def _sev_badge_class(sev: str) -> str:
    s = (sev or "").lower()
    if s.startswith("h"): return "sev-high"
    if s.startswith("m"): return "sev-med"
    if s.startswith("l"): return "sev-low"
    return "bg-gray-600 text-white"

def _build_rows(findings: Dict[str, FindingSet], source: str) -> tuple[str, Dict[str,int]]:
    rows: List[str] = []
    sev_counts = {"High":0, "Medium":0, "Low":0}
    for fname, fset in (findings or {}).items():
        for it in _iter_issues(fset):
            sev = getattr(it, "severity", "") or ""
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            badge = _sev_badge_class(sev)
            kind = escape(getattr(it, "kind", "") or "")
            msg  = escape(getattr(it, "message", "") or "")
            cwe  = escape(getattr(it, "cwe", "") or "") or "-"
            ev   = getattr(it, "evidence", None) or {}
            fix_btn = "<span class='text-gray-500 text-xs'>—</span>"
            if isinstance(ev, dict) and ev.get("fix"):
                fx = str(ev["fix"])
                fix_btn = f"<button class='btn text-xs copy-fix' data-fix='{escape(fx)}'>Copy Fix</button>"
            fn   = escape(fname)
            line = _guess_issue_line(it, source, fname) or 1
            rows.append(f"""
<tr class="border-b border-white/10 hover:bg-white/5 row-enter" data-line="{line}" data-sev="{escape(sev)}">
  <td class="p-2"><span class="px-2 py-0.5 rounded {badge}">{escape(sev)}</span></td>
  <td class="p-2">{kind}</td>
  <td class="p-2 msg-link underline decoration-dotted cursor-pointer">{msg}</td>
  <td class="p-2">{cwe}</td>
  <td class="p-2">{fn}</td>
  <td class="p-2">{fix_btn}</td>
</tr>""")
    tbody_html = "\n".join(rows) if rows else "<tr><td class='p-3 text-gray-400' colspan='6'>No issues found</td></tr>"
    return tbody_html, sev_counts

# ---------- Counters ----------

def _set_counter(html: str, label_text: str, value: int) -> str:
    pattern = re.compile(
        rf"(<div[^>]*class=\"[^\"]*text-xs[^\"]*\"[^>]*>\s*{re.escape(label_text)}\s*</div>\s*"
        rf"<div[^>]*class=\"[^\"]*text-2xl[^\"]*\"[^>]*data-counter=\")(\d+)(\"[^>]*>)([^<]*)(</div>)",
        re.I | re.S
    )
    def repl(m): return f"{m.group(1)}{value}{m.group(3)}{value}{m.group(5)}"
    return pattern.sub(repl, html, count=1)

# ---------- CFG payload (hardened) ----------

def _sanitize_mermaid(txt: str) -> str:
    if not txt:
        return ""
    # Make Mermaid/browser-safe
    return (
        txt.replace("\r", "")                       # remove CRs
           .replace("`", "'")                       # avoid back-ticks breaking <script> parsing
           .replace("</script>", "<\\/script>")     # never close our script tag
           .strip()
    )

def _build_mermaid_payload(cfgs: Dict[str, CFG]) -> str:
    """
    Build JSON array expected by the premium template:
      [ { "name": "main", "diagram": "flowchart TD\\nA-->B" }, ... ]
    Always returns a valid diagram string per function so the UI can render.
    """
    arr = []
    for name, cfg in (cfgs or {}).items():
        diagram = None
        try:
            d = cfg_to_mermaid(cfg)
            d = _sanitize_mermaid(d)
            # Ensure Mermaid sees a chart directive
            if not d.lower().startswith(("flowchart", "graph")):
                d = "flowchart TD\n" + d
            diagram = d
        except Exception:
            pass

    # Fallback so the UI never shows “No CFG available.”
        if not diagram:
            diagram = f"flowchart TD\nS((start))-->N[\"{name}\"]"

        arr.append({"name": name, "diagram": diagram})

    return json.dumps(arr)

# ---------- Main ----------

def make_report_html(
    source: str,
    cfgs: Dict[str, CFG],
    facts,
    findings: Dict[str, FindingSet],
    filename: str | None = None,
    metrics: Dict[str, Any] | None = None,
    summaries: Dict[str, dict] | None = None,
) -> str:
    if not TEMPLATE_PATH.exists():
        body = escape("premium_report.html not found at " + str(TEMPLATE_PATH))
        return f"<!doctype html><html><body style='background:#0b1020;color:#eee;font-family:system-ui;padding:24px'>{body}</body></html>"

    html = TEMPLATE_PATH.read_text(encoding="utf-8")

    # Findings rows
    rows_html, _sev_counts = _build_rows(findings, source)
    html = re.sub(
        r'(<tbody\s+id=["\']tbody["\']\s*>)(.*?)(</tbody>)',
        rf"\1{rows_html}\3",
        html,
        flags=re.S | re.I
    )

    # Code viewer (exact injection, no left padding)
    code_html = _render_code_with_lines(source or "")
    html = re.sub(
        r'(<pre\s+id=["\']code["\'][^>]*>)(.*?)(</pre>)',
        rf"\1{code_html}\3",
        html,
        flags=re.S | re.I
    )

    # Counters
    loc = len((source or "").splitlines())
    fcount = len(cfgs or {})
    icount = sum(len(list(_iter_issues(fs))) for fs in (findings or {}).values())
    html = _set_counter(html, "LOC", loc)
    html = _set_counter(html, "Functions", fcount)
    html = _set_counter(html, "Issues", icount)

    # Embed Mermaid JSON (unescaped block the template reads)
    mmd_json = _build_mermaid_payload(cfgs)
    html = html.replace(
        "</body>",
        f'<script id="cfg-mermaid" type="application/json">{mmd_json}</script>\n</body>'
    )

    return html
