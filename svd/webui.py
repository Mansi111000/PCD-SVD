from __future__ import annotations
from flask import Flask, request, render_template
from flask import Response, send_file
import json, time, io

from .core.parser_frontend import parse_c_to_unit, strip_preprocessor_lines
from .core.ir import lower_unit_to_ir
from .core.cfg import build_cfgs_for_unit
from .core.report import make_report_html
from .core.rules import run_rules
from .core.rules_post import attach_quick_fixes, detect_injection_like, compute_function_summaries

app = Flask(__name__, template_folder="templates", static_folder="static")

@app.get("/")
def index():
    sample = """#include <stdio.h>
#include <string.h>
int f(int n){
  int a[10]; int i, sum;
  for(i=0;i<=10;i++) sum += a[i];
  int *p = 0;
  return *p + (100/n);
}
int main(int argc, char** argv){
  char dst[8];
  char *src = argv[1];
  strcpy(dst, src);
  printf("%s\\n", dst);
  return f(argc-1);
}
"""
    return render_template("editor.html", sample=sample)

@app.post("/analyze")
def analyze():
    code = (request.form.get("code") or "").replace("\r\n","\n").replace("\r","\n")
    cleaned = strip_preprocessor_lines(code)
    unit = parse_c_to_unit(cleaned)
    ir = lower_unit_to_ir(unit)
    cfgs = build_cfgs_for_unit(ir)

    t0 = time.perf_counter()
    findings = run_rules(cfgs, facts={})
    attach_quick_fixes(findings)
    detect_injection_like(ir, findings)
    summaries = compute_function_summaries(ir)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    metrics = {
        "loc": len(code.splitlines()),
        "functions": len(cfgs),
        "cfg_nodes": sum(len(c.blocks) for c in cfgs.values()),
        "cfg_edges": sum(len(b.succ) for c in cfgs.values() for b in c.blocks.values()),
        "issues": sum(len(getattr(fs, "issues", [])) for fs in findings.values()),
        "analysis_ms": elapsed_ms,
    }

    html = make_report_html(code, cfgs, facts={}, findings=findings, filename="<input>",
                            metrics=metrics, summaries=summaries)
    return html

# ---------- Export endpoints (server mode) ----------

@app.post("/export/json")
def export_json():
    data = request.form.get("data") or "{}"
    # Validate JSON
    try:
        parsed = json.loads(data)
    except Exception:
        parsed = {"error":"invalid JSON payload"}
        data = json.dumps(parsed)
    return Response(
        data,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=svd-report.json"}
    )

@app.post("/export/pdf")
def export_pdf():
    # build a minimal PDF summary from the posted JSON payload
    data = request.form.get("data") or "{}"
    try:
        payload = json.loads(data)
    except Exception:
        payload = {"file":"<unknown>", "metrics":{}, "findings":[]}

    buf = io.BytesIO()
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
    except Exception as e:
        # Give a friendly message if reportlab isn't installed on the server
        return Response(
            f"reportlab not installed ({e}). Install with: pip install reportlab\n",
            mimetype="text/plain"
        )

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    flow = []
    flow.append(Paragraph(f"Static Vulnerability Detector — {payload.get('file','<input>')}", styles["Title"]))
    flow.append(Spacer(1, 8))
    m = payload.get("metrics", {}) or {}
    mrows = [["Metric","Value"]] + [[k, str(m.get(k,"—"))] for k in ("loc","functions","cfg_nodes","cfg_edges","issues","analysis_ms")]
    t = Table(mrows, hAlign="LEFT")
    t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.25,colors.grey)]))
    flow.append(t)
    flow.append(Spacer(1,12))
    frows = [["Severity","Type","Message","CWE","Function"]]
    for it in payload.get("findings", []):
        frows.append([it.get("severity",""), it.get("kind",""), it.get("message",""), it.get("cwe",""), it.get("function","")])
    if len(frows) == 1:
        flow.append(Paragraph("No issues found.", styles["Normal"]))
    else:
        tf = Table(frows, hAlign="LEFT", colWidths=[70,100,250,60,80])
        tf.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.25,colors.grey),
                                ("BACKGROUND",(0,0),(-1,0),colors.lightgrey)]))
        flow.append(tf)

    doc.build(flow)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name="svd-report.pdf")

if __name__ == "__main__":
    app.run(debug=False)
