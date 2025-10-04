from __future__ import annotations
from typing import Dict, Any
from markupsafe import escape
from .cfg import CFG, cfg_to_mermaid, cfg_block_details
from .utils import FindingSet

TAILWIND = "https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css"
MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs"

def _count_issues(findings: Dict[str, FindingSet]) -> int:
    total = 0
    for _, fset in findings.items():
        if hasattr(fset, "by_severity"):
            total += len(list(fset.by_severity()))
        else:
            try:
                total += len(list(fset))
            except Exception:
                pass
    return total

def _compute_metrics_default(source: str, cfgs: Dict[str, CFG], findings: Dict[str, FindingSet]) -> Dict[str, Any]:
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
    return f"""
    <div class='card rounded-xl p-3 text-center'>
      <div class='text-xs text-gray-400'>{escape(label)}</div>
      <div class='text-xl font-semibold'>{v}</div>
    </div>
    """

def make_report_html(
    source: str,
    cfgs: Dict[str, CFG],
    facts,
    findings: Dict[str, FindingSet],
    filename: str | None = None,
    metrics: Dict[str, Any] | None = None,
) -> str:
    diagrams = {fname: cfg_to_mermaid(cfg) for fname, cfg in cfgs.items()}
    details = {fname: cfg_block_details(cfg) for fname, cfg in cfgs.items()}

    base = _compute_metrics_default(source, cfgs, findings)
    m = base if metrics is None else {**base, **metrics}

    # Findings table
    rows = []
    for fname, fset in findings.items():
        items = fset.by_severity() if hasattr(fset, "by_severity") else list(fset)
        for it in items:
            ev = getattr(it, "evidence", {}) or {}
            fix = ev.get("fix")
            fix_cell = (
                f"<button class='px-2 py-1 rounded bg-emerald-600 text-white text-xs' "
                f"data-fix='{escape(fix)}' onclick='copyFix(this)'>Copy Fix</button>"
            ) if fix else "<span class='text-gray-400'>—</span>"
            rows.append(f"""
<tr class='border-b border-gray-700 hover:bg-gray-800'>
  <td class='p-2'><span class='px-2 py-0.5 rounded text-white {_sev_badge(getattr(it,'severity',''))}'>{escape(getattr(it,'severity',''))}</span></td>
  <td class='p-2'>{escape(getattr(it,'kind',''))}</td>
  <td class='p-2'>{escape(getattr(it,'message',''))}</td>
  <td class='p-2'>{escape(getattr(it,'cwe','') or '-')}</td>
  <td class='p-2'>{escape(fname)}</td>
  <td class='p-2'>{fix_cell}</td>
</tr>""")
    issues_html = "\n".join(rows) or "<tr><td colspan=6 class='p-3'>No issues found</td></tr>"
    code_html = escape(source or "")

    # Build CFG tabs & panels (each panel has a raw <script type="text/plain"> + a render target)
    tabs, panels = [], []
    for i, (fname, dia) in enumerate(diagrams.items()):
        tab_id = f"tab{i}"
        graph_id = f"graph-{tab_id}"
        mmd_id = f"mmd-{tab_id}"
        active_cls = "is-active" if i == 0 else ""
        tabs.append(
            f"<button type='button' onclick=\"showPanel('{tab_id}',this)\" class='tab-btn {active_cls}'>{escape(fname)}</button>"
        )

        # details for the block listing
        detail_list = []
        for bid, lines in details.get(fname, []):
            esc_lines = "<br/>".join(escape(l) for l in lines) or "&mdash;"
            detail_list.append(
                f"<div class='p-2 rounded bg-gray-900 mb-2'>"
                f"<div class='font-semibold text-sm mb-1'>{escape(bid)}</div>"
                f"<div class='text-xs text-gray-300'>{esc_lines}</div></div>"
            )

        # IMPORTANT: Mermaid raw text is stored in a plain script tag, NOT auto-processed.
        dia_script = dia.replace("</script>", "<\\/script>")  # super safety
        panels.append(
            f"<div id='{tab_id}' class='panel {'' if i==0 else 'hidden'}' data-rendered='{'0' if i!=0 else '0'}'>"
            f"  <script type='text/plain' class='mmd' id='{mmd_id}'>{dia_script}</script>"
            f"  <div id='{graph_id}' class='p-2 rounded bg-white overflow-auto min-h-[120px]'></div>"
            f"  <div class='mt-3'>"
            f"    <div class='text-sm text-gray-300 mb-1'>CFG Details</div>"
            f"    {''.join(detail_list)}"
            f"  </div>"
            f"</div>"
        )

    cfg_tabs_html = "".join(tabs)
    cfg_panels_html = "".join(panels)

    title = f"Static Vulnerability Detector — {escape(filename or '<input>')}"
    return f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8'/>
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>{title}</title>
  <link rel='stylesheet' href='{TAILWIND}'/>
  <style>
    body {{ background: #0f172a; }}
    .card {{ background:#111827; color:#e5e7eb; }}
    .panel.hidden {{ display:none; }}
    .table-wrap {{ overflow:auto; }}
    code {{ white-space: pre; }}
    /* Tabs */
    .tab-btn {{
      padding:.375rem .75rem; border-radius:.5rem; margin-right:.5rem;
      background:#e5e7eb; color:#111827; transition: background .15s, color .15s;
    }}
    .tab-btn:hover, .tab-btn.is-active {{ background:#4f46e5; color:#fff; }}
  </style>
</head>
<body class='min-h-screen'>
  <div class='max-w-7xl mx-auto p-4 sm:p-6 space-y-6'>

    <header class='flex items-center justify-between flex-wrap gap-3'>
      <h1 class='text-2xl font-bold text-white'>Static Vulnerability Detector</h1>
      <div class='text-gray-300 text-sm'>{escape(filename or '<input>')}</div>
    </header>

    <section class='grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3'>
      {_stat('LOC', m.get('loc'))}
      {_stat('Functions', m.get('functions'))}
      {_stat('CFG Nodes', m.get('cfg_nodes'))}
      {_stat('CFG Edges', m.get('cfg_edges'))}
      {_stat('Issues', m.get('issues'))}
      {_stat('Time (ms)', m.get('analysis_ms') if m.get('analysis_ms') is not None else '—')}
    </section>

    <section class='card rounded-2xl p-4 shadow'>
      <h2 class='text-xl font-semibold mb-2'>Findings</h2>
      <div class='table-wrap'>
        <table class='min-w-full text-sm'>
          <thead>
            <tr class='text-left border-b border-gray-700'>
              <th class='p-2'>Severity</th>
              <th class='p-2'>Type</th>
              <th class='p-2'>Message</th>
              <th class='p-2'>CWE</th>
              <th class='p-2'>Function</th>
              <th class='p-2'>Quick Fix</th>
            </tr>
          </thead>
          <tbody>
            {issues_html}
          </tbody>
        </table>
      </div>
    </section>

    <section class='card rounded-2xl p-4 shadow'>
      <h2 class='text-xl font-semibold mb-2'>CFG (per function)</h2>
      <div class='mb-3 flex flex-wrap items-center gap-2'>{cfg_tabs_html}</div>
      {cfg_panels_html}
    </section>

    <section class='card rounded-2xl p-4 shadow'>
      <h2 class='text-xl font-semibold mb-2'>Source</h2>
      <pre class='bg-black text-green-200 p-3 rounded overflow-auto text-xs sm:text-sm'><code>{code_html}</code></pre>
    </section>

    <footer class='text-gray-400 text-xs text-center'>Generated by SVD</footer>
  </div>

  <script type="module">
    import mermaid from '{MERMAID}';
    // No auto-processing. We render on demand for the visible tab.
    mermaid.initialize({{ startOnLoad: false, theme: 'default' }});

    async function renderMermaidInto(panelId) {{
      const panel = document.getElementById(panelId);
      if (!panel) return;
      if (panel.dataset.rendered === '1') return; // already rendered

      const mmdEl = panel.querySelector('script.mmd');
      const graphEl = panel.querySelector('#graph-' + panelId);

      if (!mmdEl || !graphEl) return;
      const def = mmdEl.textContent || mmdEl.innerText || "";

      try {{
        const { '{' } svg { '}' } = await mermaid.render('svg-' + panelId, def);
        graphEl.innerHTML = svg;
        panel.dataset.rendered = '1';
      }} catch (e) {{
        graphEl.innerHTML = "<div style='padding:.5rem;color:#b91c1c;'>Mermaid render error: " + (e?.message || e) + "</div>";
      }}
    }}

    window.showPanel = function(id, btn) {{
      // switch visibility
      document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
      const el = document.getElementById(id);
      el.classList.remove('hidden');

      // tabs active state
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('is-active'));
      if (btn) btn.classList.add('is-active');

      // render if not rendered yet
      renderMermaidInto(id);
    }}

    window.copyFix = function(btn) {{
      const txt = btn?.dataset?.fix;
      if (!txt || txt === 'None') return;
      navigator.clipboard.writeText(txt).then(() => {{
        btn.textContent = 'Copied!';
        setTimeout(() => (btn.textContent = 'Copy Fix'), 1200);
      }});
    }}

    // Render the first visible tab on load
    window.addEventListener('DOMContentLoaded', () => {{
      const first = document.querySelector('.panel:not(.hidden)');
      if (first) renderMermaidInto(first.id);
    }});
  </script>
</body>
</html>
"""
