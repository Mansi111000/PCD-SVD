from __future__ import annotations
from typing import Dict
import re

from .utils import Issue, FindingSet

UNSAFE = {"strcpy","strcat","gets","scanf","system","memcpy"}

def _ensure_fs(d: Dict[str, FindingSet], fn: str) -> FindingSet:
    fs = d.get(fn)
    if not isinstance(fs, FindingSet):
        fs = FindingSet()
        d[fn] = fs
    return fs

def attach_quick_fixes(findings: Dict[str, FindingSet]) -> None:
    for fn, fs in list(findings.items()):
        if not isinstance(fs, FindingSet):
            continue
        for it in fs.issues:
            msg = (it.message or "").lower()
            fix = None
            if "strcpy" in msg:
                fix = "Use strncpy(dst, src, sizeof(dst)-1); dst[sizeof(dst)-1] = '\\0';"
            elif "strcat" in msg:
                fix = "Use strncat(dst, src, sizeof(dst)-strlen(dst)-1);"
            elif "gets" in msg:
                fix = "Use fgets(buf, sizeof(buf), stdin) instead of gets()."
            elif "division by zero" in msg or "div by zero" in msg:
                fix = "Guard: if (n == 0) return /*error*/;"

            if fix:
                ev = getattr(it, "evidence", {}) or {}
                ev["fix"] = fix
                try:
                    it.evidence = ev
                except Exception:
                    # if Issue is frozen, reconstruct (unlikely in your repo, but safe)
                    new_it = Issue(kind=it.kind, message=it.message, severity=it.severity,
                                   cwe=it.cwe, function=it.function, node_id=getattr(it,"node_id",None),
                                   evidence=ev)
                    fs.add(new_it)

def detect_injection_like(ir_unit, findings: Dict[str, FindingSet]) -> None:
    try:
        funcs = ir_unit.functions
    except Exception:
        return

    printf_call = re.compile(r"\bprintf\s*\(([^)]*)\)")
    system_call = re.compile(r"\bsystem\s*\(([^)]*)\)")

    for func in funcs:
        fs = _ensure_fs(findings, func.name)
        for s in getattr(func, "body", []):
            text = ""
            a = getattr(s, "args", None)
            if isinstance(a, dict):
                text = " ".join(str(v) for v in a.values() if v is not None)
            text = str(getattr(s, "text", text))

            m = printf_call.search(text)
            if m:
                fs.add(Issue(
                    kind="Format String Risk",
                    message="printf() with non-literal format",
                    severity="Medium",
                    cwe="CWE-134",
                    function=func.name,
                    node_id=getattr(s, "sid", None),
                    evidence={"call": f"printf({m.group(1)})",
                              "fix": "Use printf(\"%s\", user_input) or validate the format."}
                ))

            m2 = system_call.search(text)
            if m2:
                fs.add(Issue(
                    kind="Command Injection Risk",
                    message="system() called with untrusted input",
                    severity="High",
                    cwe="CWE-78",
                    function=func.name,
                    node_id=getattr(s, "sid", None),
                    evidence={"call": f"system({m2.group(1)})",
                              "fix": "Avoid system(); use execv with fixed argv or sanitize input."}
                ))

def compute_function_summaries(ir_unit) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for f in getattr(ir_unit, "functions", []):
        may_return_zero = any("return 0" in str(getattr(s, "text", "")) for s in getattr(f, "body", []))
        taints_return = any(("return" in str(getattr(s, "op",""))) and ("argv" in str(getattr(s, "args",""))) for s in getattr(f, "body", []))
        out[f.name] = {
            "params_nonnull": [],  # could be filled from guards if you add them
            "taints_return": bool(taints_return),
            "may_return_zero": bool(may_return_zero),
        }
    return out

# ---- Compat alias so older code importing postprocess_findings keeps working ----
def postprocess_findings(ir_unit, findings: Dict[str, FindingSet]) -> None:
    attach_quick_fixes(findings)
    detect_injection_like(ir_unit, findings)
