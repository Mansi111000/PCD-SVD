from __future__ import annotations
import argparse, time, pathlib
from svd.core.parser_frontend import parse_c_to_unit
from svd.core.ir import lower_unit_to_ir as lower_to_ir   # alias for compatibility
from svd.core.cfg import build_cfgs_for_unit
from svd.core.rules import analyze_unit
from svd.core.report import make_report_html
from svd.core.rules_post import attach_quick_fixes, detect_injection_like

def analyze_file(path: str, out_html: str, use_strip: bool = False):
    src = pathlib.Path(path).read_text(encoding='utf-8', errors='ignore')
    t0 = time.perf_counter()
    unit = parse_c_to_unit(src, filename=path)
    ir = lower_to_ir(unit)
    cfgs = build_cfgs_for_unit(ir)
    facts, findings = analyze_unit(ir)

    # Add-ons
    attach_quick_fixes(findings)
    detect_injection_like(ir, findings)

    t1 = time.perf_counter()
    metrics = {"analysis_ms": int((t1 - t0) * 1000)}
    html = make_report_html(src, cfgs, facts, findings, filename=path, metrics=metrics)
    if not isinstance(html, str):
        raise TypeError(f"make_report_html must return str, got {type(html)}")
    pathlib.Path(out_html).write_text(html, encoding='utf-8')
    print(f"Report written to {out_html}")

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    a = sub.add_parser('analyze', help='Analyze a C file and produce HTML report')
    a.add_argument('file')
    a.add_argument('-o', '--out-html', default='report.html')
    a.add_argument('--strip', action='store_true', help='(compat) ignore preprocess lines/comments')
    args = p.parse_args()

    if args.cmd == 'analyze':
        analyze_file(args.file, args.out_html, use_strip=args.strip)

if __name__ == '__main__':
    main()
