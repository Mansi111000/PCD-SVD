from __future__ import annotations
from typing import Dict, Any, List, Tuple, Iterable
from markupsafe import escape
import json, re

from .cfg import CFG, cfg_to_mermaid, cfg_block_details
from .utils import FindingSet

TAILWIND = "https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"
MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs"

UNSAFE_FUNCS = re.compile(r'\b(strcpy|strcat|gets|scanf|system|memcpy)\b')

def _iter_issues(fset: Any) -> Iterable[Any]:
    if fset is None: return []
    if hasattr(fset, "by_severity"):
        try: return list(fset.by_severity())
        except Exception: pass
    issues = getattr(fset, "issues", None)
    if isinstance(issues, list): return issues
    try: return list(fset)
    except Exception: return []

def _count_issues(findings: Dict[str, Any]) -> int:
    return sum(len(list(_iter_issues(fs))) for fs in findings.values())

def _compute_metrics_default(source: str, cfgs: Dict[str, CFG], findings: Dict[str, Any]) -> Dict[str, Any]:
    loc = len((source or "").splitlines())
    fn = len(cfgs)
    nodes = sum(len(cfg.blocks) for cfg in cfgs.values())
    edges = sum(len(b.succ) for cfg in cfgs.values() for b in cfg.blocks.values())
    issues = _count_issues(findings)
    return {"loc": loc, "functions": fn, "cfg_nodes": nodes, "cfg_edges": edges, "issues": issues, "analysis_ms": None}

def _sev_badge(sev: str) -> str:
    s = (sev or "").lower()
    if s.startswith("h"): return "bg-red-600"
    if s.startswith("m"): return "bg-yellow-600"
    if s.startswith("l"): return "bg-green-600"
    return "bg-gray-600"

def _stat(label: str, value: Any) -> str:
    v = escape(str(value)) if value is not None else "—"
    return f"<div class='card rounded-xl p-3 text-center'><div class='text-xs text-gray-400'>{escape(label)}</div><div class='text-xl font-semibold'>{v}</div></div>"

def _render_source_with_anchors_and_highlights(source: str) -> Tuple[str, Dict[int, int]]:
    lines = (source or "").replace("\r\n","\n").replace("\r","\n").split("\n")
    rendered: List[str] = []
    for i, raw in enumerate(lines, start=1):
        esc = escape(raw)
        esc = UNSAFE_FUNCS.sub(r"<mark class='px-1 rounded bg-red-700 text-white'>\1</mark>", str(esc))
        rendered.append(f"<span id='L{i}' class='code-line block'><a class='line-no' href='#L{i}'>{i:>4}</a> {esc}</span>")
    return "\n".join(rendered), {}

def _finding_rows(findings: Dict[str, Any]) -> List[dict]:
    out = []
    for fname, fset in findings.items():
        for it in _iter_issues(fset):
            out.append({
                "function": fname,
                "severity": getattr(it,"severity",""),
                "kind": getattr(it,"kind",""),
                "message": getattr(it,"message",""),
                "cwe": getattr(it,"cwe","") or "",
                "evidence": getattr(it,"evidence",{}) or {},
            })
    return out

def _guess_line_for_issue(issue: dict, source: str) -> int | None:
    ev = issue.get("evidence") or {}
    if "line" in ev:
        try:
            ln = int(ev["line"])
            return ln if ln > 0 else None
        except Exception:
            pass
    snippet = ev.get("call") or ev.get("expr") or issue.get("message","")
    if not snippet:
        return None
    src = (source or "").replace("\r\n","\n").replace("\r","\n").split("\n")
    token = snippet.split("(")[0][:40]
    for i, line in enumerate(src, start=1):
        if token and token in line:
            return i
    return None

def _render_summaries_card(summaries: Dict[str, dict]) -> str:
    if not summaries: return ""
    rows = []
    for fname, sm in summaries.items():
        pnn = ", ".join(sm.get("params_nonnull", [])) or "—"
        tr  = "Yes" if sm.get("taints_return") else "No"
        mrz = "Yes" if sm.get("may_return_zero") else "No"
        rows.append(f"""
        <tr class='border-b border-gray-700'>
          <td class='p-2 font-mono'>{escape(fname)}</td>
          <td class='p-2'>{escape(pnn)}</td>
          <td class='p-2'>{escape(tr)}</td>
          <td class='p-2'>{escape(mrz)}</td>
        </tr>
        """)
    return f"""
    <section class='card rounded-2xl p-4 shadow'>
      <h2 class='text-xl font-semibold mb-2'>Function Summaries</h2>
      <div class='table-wrap'>
        <table class='min-w-full text-sm'>
          <thead>
            <tr class='text-left border-b border-gray-700'>
              <th class='p-2'>Function</th>
              <th class='p-2'>Params required non-null</th>
              <th class='p-2'>Taints return</th>
              <th class='p-2'>May return 0</th>
            </tr>
          </thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    """

def make_report_html(
    source: str,
    cfgs: Dict[str, CFG],
    facts,
    findings: Dict[str, Any],
    filename: str | None = None,
    metrics: Dict[str, Any] | None = None,
    summaries: Dict[str, dict] | None = None,
) -> str:

    diagrams = {fname: cfg_to_mermaid(cfg) for fname, cfg in cfgs.items()}
    details  = {fname: cfg_block_details(cfg) for fname, cfg in cfgs.items()}
    base     = _compute_metrics_default(source, cfgs, findings)
    m        = base if metrics is None else {**base, **metrics}

    finding_list = _finding_rows(findings)
    payload = {
        "file": filename or "<input>",
        "metrics": m,
        "findings": finding_list
    }
    findings_json = json.dumps(payload)

    rows = []
    for item in finding_list:
        ln = _guess_line_for_issue(item, source)
        anchor = f"#L{ln}" if ln else "#source"
        fix = (item.get("evidence") or {}).get("fix")
        fix_cell = (f"<button class='px-2 py-1 rounded bg-emerald-600 text-white text-xs' "
                    f"data-fix='{escape(fix)}' onclick='copyFix(this)'>Copy Fix</button>") if fix else "<span class='text-gray-400'>—</span>"
        rows.append(f"""
<tr class='border-b border-gray-700 hover:bg-gray-800'>
  <td class='p-2'><span class='px-2 py-0.5 rounded text-white {_sev_badge(item.get("severity",""))}'>{escape(item.get("severity",""))}</span></td>
  <td class='p-2'>{escape(item.get("kind",""))}</td>
  <td class='p-2'><a class='underline text-indigo-300 hover:text-indigo-100' href='{anchor}'>{escape(item.get("message",""))}</a></td>
  <td class='p-2'>{escape(item.get("cwe","") or "-")}</td>
  <td class='p-2'>{escape(item.get("function",""))}</td>
  <td class='p-2'>{fix_cell}</td>
</tr>""")
    issues_html = "\n".join(rows) or "<tr><td colspan=6 class='p-3'>No issues found</td></tr>"

    tabs, panels = [], []
    for i, (fname, dia) in enumerate(diagrams.items()):
        tab_id, graph_id, mmd_id = f"tab{i}", f"graph-tab{i}", f"mmd-tab{i}"
        active_cls = "is-active" if i == 0 else ""
        tabs.append(f"<button type='button' onclick=\"showPanel('{tab_id}',this)\" class='tab-btn {active_cls}'>{escape(fname)}</button>")

        detail_list = []
        for bid, lines in details.get(fname, []):
            esc_lines = "<br/>".join(escape(l) for l in lines) or "&mdash;"
            detail_list.append(f"<div class='p-2 rounded bg-gray-900 mb-2'><div class='font-semibold text-sm mb-1'>{escape(bid)}</div><div class='text-xs text-gray-300'>{esc_lines}</div></div>")

        dia_script = (dia or "").replace("</script>", "<\\/script>")
        panels.append(
            f"<div id='{tab_id}' class='panel {'' if i==0 else 'hidden'}' data-rendered='0'>"
            f"  <script type='text/plain' class='mmd' id='{mmd_id}'>{dia_script}</script>"
            f"  <div id='{graph_id}' class='p-2 rounded bg-white overflow-auto min-h-[120px]'></div>"
            f"  <div class='mt-3'><div class='text-sm text-gray-300 mb-1'>CFG Details</div>{''.join(detail_list)}</div>"
            f"</div>"
        )
    cfg_tabs_html = "".join(tabs)
    cfg_panels_html = "".join(panels)

    source_html, _ = _render_source_with_anchors_and_highlights(source or "")

    title = f"Static Vulnerability Detector — {escape(filename or '<input>')}"
    return f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>{title}</title>
  <link rel='stylesheet' href='{TAILWIND}'/>
  <style>
    body {{ background:#0f172a; }}
    .card {{ background:#111827; color:#e5e7eb; }}
    .panel.hidden {{ display:none; }}
    .table-wrap {{ overflow:auto; }}
    code {{ white-space: pre; }}
    .tab-btn {{ padding:.375rem .75rem; border-radius:.5rem; margin-right:.5rem; background:#e5e7eb; color:#111827; transition: background .15s, color .15s; }}
    .tab-btn:hover, .tab-btn.is-active {{ background:#4f46e5; color:#fff; }}
    .code-line {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace; }}
    .line-no {{ display:inline-block; width:3rem; color:#9ca3af; text-decoration:none; }}
    mark {{ background:#b91c1c; color:#fff; }}
  </style>
</head>
<body class='min-h-screen'>
  <div class='max-w-7xl mx-auto p-4 sm:p-6 space-y-6'>

    <header class='flex items-center justify-between flex-wrap gap-3'>
      <h1 class='text-2xl font-bold text-white'>Static Vulnerability Detector</h1>
      <div class='text-gray-300 text-sm'>{escape(filename or '<input>')}</div>
    </header>

    <!-- Export buttons: work in server mode (POST) and in file:// mode (JS fallback) -->
    <section class='flex items-center gap-2'>
      <form id='export-json-form' method='post' action='/export/json' target='_blank' style='display:none'>
        <input type='hidden' name='data' value=''/>
      </form>
      <form id='export-pdf-form' method='post' action='/export/pdf' target='_blank' style='display:none'>
        <input type='hidden' name='data' value=''/>
      </form>
      <button id='btn-json' class='px-3 py-2 rounded bg-gray-700 text-white text-sm'>Export JSON</button>
      <button id='btn-pdf'  class='px-3 py-2 rounded bg-gray-700 text-white text-sm'>Export PDF</button>
    </section>

    <!-- Metrics -->
    <section class='grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3'>
      {_stat('LOC', m.get('loc'))}
      {_stat('Functions', m.get('functions'))}
      {_stat('CFG Nodes', m.get('cfg_nodes'))}
      {_stat('CFG Edges', m.get('cfg_edges'))}
      {_stat('Issues', m.get('issues'))}
      {_stat('Time (ms)', m.get('analysis_ms') if m.get('analysis_ms') is not None else '—')}
    </section>

    <!-- Findings -->
    <section class='card rounded-2xl p-4 shadow'>
      <h2 class='text-xl font-semibold mb-2'>Findings</h2>
      <div class='table-wrap'>
        <table class='min-w-full text-sm'>
          <thead>
            <tr class='text-left border-b border-gray-700'>
              <th class='p-2'>Severity</th><th class='p-2'>Type</th><th class='p-2'>Message</th>
              <th class='p-2'>CWE</th><th class='p-2'>Function</th><th class='p-2'>Quick Fix</th>
            </tr>
          </thead>
          <tbody>{issues_html}</tbody>
        </table>
      </div>
    </section>

    <!-- Function Summaries -->
    { _render_summaries_card(summaries or {}) }

    <!-- CFG -->
    <section class='card rounded-2xl p-4 shadow'>
      <h2 class='text-xl font-semibold mb-2'>CFG (per function)</h2>
      <div class='mb-3 flex flex-wrap items-center gap-2'>{cfg_tabs_html}</div>
      {cfg_panels_html}
    </section>

    <!-- Source -->
    <section id='source' class='card rounded-2xl p-4 shadow'>
      <h2 class='text-xl font-semibold mb-2'>Source</h2>
      <div class='bg-black text-green-200 p-3 rounded overflow-auto text-xs sm:text-sm'>
        {source_html}
      </div>
    </section>

    <footer class='text-gray-400 text-xs text-center'>Generated by SVD</footer>
  </div>

  <!-- Payload for export -->
  <script>
    window.__SVD_PAYLOAD__ = {findings_json};
  </script>

  <script type="module">
    import mermaid from '{MERMAID}';
    mermaid.initialize({{ startOnLoad: false, theme: 'default' }});

    async function renderMermaidInto(panelId) {{
      const panel = document.getElementById(panelId);
      if (!panel || panel.dataset.rendered === '1') return;
      const mmd = panel.querySelector('script.mmd');
      const target = panel.querySelector('#graph-' + panelId);
      if (!mmd || !target) return;
      const def = mmd.textContent || mmd.innerText || "";
      try {{
        const {{ svg }} = await mermaid.render('svg-' + panelId, def);
        target.innerHTML = svg;
        panel.dataset.rendered = '1';
      }} catch (e) {{
        target.innerHTML = "<div style='padding:.5rem;color:#b91c1c;'>Mermaid render error: " + (e?.message || e) + "</div>";
      }}
    }}

    window.showPanel = (id, btn) => {{
      document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
      const el = document.getElementById(id);
      el.classList.remove('hidden');
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('is-active'));
      if (btn) btn.classList.add('is-active');
      renderMermaidInto(id);
    }}

    window.copyFix = (btn) => {{
      const txt = btn?.dataset?.fix;
      if (!txt || txt === 'None') return;
      navigator.clipboard.writeText(txt).then(() => {{
        btn.textContent = 'Copied!';
        setTimeout(() => (btn.textContent = 'Copy Fix'), 1200);
      }});
    }}

    // Export buttons: server mode (POST) or file:// fallback
    const payload = window.__SVD_PAYLOAD__;
    const btnJson = document.getElementById('btn-json');
    const btnPdf  = document.getElementById('btn-pdf');

    btnJson.addEventListener('click', () => {{
      if (location.protocol === 'file:') {{
        const blob = new Blob([JSON.stringify(payload, null, 2)], {{type:'application/json'}});
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'svd-report.json';
        a.click();
        URL.revokeObjectURL(a.href);
      }} else {{
        const f = document.getElementById('export-json-form');
        f.elements['data'].value = JSON.stringify(payload);
        f.submit();
      }}
    }});

    btnPdf.addEventListener('click', () => {{
      if (location.protocol === 'file:') {{
        // Simple and reliable: use browser "Print to PDF"
        window.print();
      }} else {{
        const f = document.getElementById('export-pdf-form');
        f.elements['data'].value = JSON.stringify(payload);
        f.submit();
      }}
    }});

    // Render first CFG on page load
    window.addEventListener('DOMContentLoaded', () => {{
      const first = document.querySelector('.panel:not(.hidden)');
      if (first) renderMermaidInto(first.id);
    }});
  </script>
</body>
</html>
"""
