from __future__ import annotations
import argparse, pathlib, json, time
from typing import Any, Dict, List

from .core.parser_frontend import parse_c_to_unit, strip_preprocessor_lines
from .core.ir import lower_unit_to_ir  # your IR lowering
from .core.cfg import build_cfgs_for_unit
from .core.report import make_report_html
from .core.rules import run_rules  # your main rules pass
from .core.rules_post import attach_quick_fixes, detect_injection_like, compute_function_summaries

# ------------------- PDF (lightweight) -------------------
def _write_pdf(pdf_path: str, filename: str, metrics: Dict[str, Any], findings: Dict[str, Any]) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
    except Exception as e:
        raise SystemExit(
            "PDF export requires 'reportlab'. Install it with:\n"
            "  pip install reportlab\n"
            f"(import error: {e})"
        )

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    flow = []
    flow.append(Paragraph(f"Static Vulnerability Detector — {filename}", styles["Title"]))
    flow.append(Spacer(1, 8))

    # metrics
    mrows = [["Metric", "Value"]]
    for k in ("loc", "functions", "cfg_nodes", "cfg_edges", "issues", "analysis_ms"):
        mrows.append([k, str(metrics.get(k, "—"))])
    t = Table(mrows, hAlign="LEFT")
    t.setStyle(TableStyle([("GRID", (0,0), (-1,-1), 0.25, colors.grey)]))
    flow.append(t)
    flow.append(Spacer(1, 12))

    # findings
    frows = [["Severity","Type","Message","CWE","Function"]]
    from .core.report import _iter_issues  # safe iterator
    total = 0
    for fn, fs in findings.items():
        for it in _iter_issues(fs):
            frows.append([
                getattr(it,"severity",""),
                getattr(it,"kind",""),
                getattr(it,"message",""),
                getattr(it,"cwe","") or "",
                fn
            ])
            total += 1
    if total == 0:
        flow.append(Paragraph("No issues found.", styles["Normal"]))
    else:
        tf = Table(frows, hAlign="LEFT", colWidths=[70,100,250,60,80])
        tf.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
            ("BACKGROUND", (0,0), (-1,0), colors.lightgrey)
        ]))
        flow.append(tf)

    doc.build(flow)

# ------------------- JSON export helper -------------------
def _findings_to_json(filename: str, metrics: Dict[str, Any], findings: Dict[str, Any]) -> Dict[str, Any]:
    from .core.report import _iter_issues
    items: List[dict] = []
    for fn, fs in findings.items():
        for it in _iter_issues(fs):
            items.append({
                "function": fn,
                "severity": getattr(it,"severity",""),
                "kind": getattr(it,"kind",""),
                "message": getattr(it,"message",""),
                "cwe": getattr(it,"cwe","") or "",
                "evidence": getattr(it,"evidence",{}) or {},
            })
    return {"file": filename, "metrics": metrics, "findings": items}

# ------------------- pipeline -------------------
def analyze_file(path: str, out_html: str, use_strip: bool, json_out: str | None, pdf_out: str | None) -> None:
    p = pathlib.Path(path)
    text = p.read_text(encoding="utf-8", errors="ignore")
    if use_strip:
        text = strip_preprocessor_lines(text)

    # Parse → IR → CFG
    unit = parse_c_to_unit(text, filename=str(p))
    ir = lower_unit_to_ir(unit)
    cfgs = build_cfgs_for_unit(ir)

    # Run rules (this is the bit that populates findings!)
    t0 = time.perf_counter()
    findings = run_rules(cfgs, facts={})           # your rules.py pass
    attach_quick_fixes(findings)                   # post: quick fixes
    detect_injection_like(ir, findings)            # post: format-string/system()
    summaries = compute_function_summaries(ir)     # for the summaries card
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    # Minimal metrics for the dashboard
    metrics = {
        "loc": len(text.splitlines()),
        "functions": len(cfgs),
        "cfg_nodes": sum(len(c.blocks) for c in cfgs.values()),
        "cfg_edges": sum(len(b.succ) for c in cfgs.values() for b in c.blocks.values()),
        "issues": sum(len(getattr(fs, "issues", [])) for fs in findings.values()),
        "analysis_ms": elapsed_ms,
    }

    # HTML
    html = make_report_html(text, cfgs, facts={}, findings=findings, filename=str(p),
                            metrics=metrics, summaries=summaries)
    pathlib.Path(out_html).write_text(html, encoding="utf-8")
    print(f"Report written to {out_html}")

    # JSON export
    if json_out:
        payload = _findings_to_json(str(p), metrics, findings)
        pathlib.Path(json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"JSON written to {json_out}")

    # PDF export (summary PDF)
    if pdf_out:
        _write_pdf(pdf_out, str(p), metrics, findings)
        print(f"PDF written to {pdf_out}")

# ------------------- CLI -------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="C source file (.c or preprocessed .i)")
    ap.add_argument("-o","-O","--out-html", dest="out_html", default="report.html")
    ap.add_argument("--strip", action="store_true", help="Strip #includes/comments for pycparser demo")
    ap.add_argument("--json-out", dest="json_out", default=None, help="Also write findings JSON")
    ap.add_argument("--pdf-out", dest="pdf_out", default=None, help="Also write a summary PDF")
    args = ap.parse_args()
    analyze_file(args.file, args.out_html, use_strip=args.strip, json_out=args.json_out, pdf_out=args.pdf_out)

if __name__ == "__main__":
    main()
