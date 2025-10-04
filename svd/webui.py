from __future__ import annotations
from flask import Flask, render_template, request, make_response
import time
from svd.core.parser_frontend import parse_c_to_unit
from svd.core.ir import lower_unit_to_ir as lower_to_ir
from svd.core.cfg import build_cfgs_for_unit
from svd.core.rules import analyze_unit
from svd.core.report import make_report_html
from svd.core.rules_post import attach_quick_fixes, detect_injection_like

app = Flask(__name__)

@app.get('/')
def home():
    sample = "#include <stdio.h>\nint main(){char dst[8]; char *src=\"hello world\"; strcpy(dst, src);}\n"
    return render_template('editor.html', sample=sample)

@app.post('/analyze')
def analyze():
    code = request.form.get('code','')
    t0 = time.perf_counter()
    unit = parse_c_to_unit(code)
    ir = lower_to_ir(unit)
    cfgs = build_cfgs_for_unit(ir)
    facts, findings = analyze_unit(ir)

    attach_quick_fixes(findings)
    detect_injection_like(ir, findings)

    t1 = time.perf_counter()
    metrics = {"analysis_ms": int((t1 - t0) * 1000)}
    html = make_report_html(code, cfgs, facts, findings, filename='<input>', metrics=metrics)
    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp

if __name__ == '__main__':
    app.run(debug=False)
