# svd/core/rules_post.py
from __future__ import annotations
from typing import Dict, Optional, Iterable
from dataclasses import replace, is_dataclass
from dataclasses import FrozenInstanceError
from .utils import Issue, FindingSet

# ----------------- Helpers -----------------

def _ensure_fset(findings: Dict[str, FindingSet], fn: str) -> FindingSet:
    """
    Guarantee a FindingSet exists for function `fn`.
    IMPORTANT: FindingSet requires 'issues' positional arg in this project,
    so we always construct with FindingSet(issues=[]).
    """
    if fn in findings and isinstance(findings[fn], FindingSet):
        return findings[fn]
    fs = FindingSet(issues=[])
    findings[fn] = fs
    return fs

def _add(
    findings: Dict[str, FindingSet],
    fn: str,
    severity: str,
    kind: str,
    cwe: str,
    message: str,
    evidence: Optional[dict] = None,
) -> None:
    """
    Add a new Issue to findings[fn]. Creates the FindingSet if needed.
    """
    fset = _ensure_fset(findings, fn)
    issue = Issue(
        kind=kind,
        message=message,
        severity=severity,
        cwe=cwe,
        function=fn,
        node_id=None,
        evidence=evidence or {},
    )
    # Many FindingSet implementations provide 'add', but to be safe:
    try:
        fset.add(issue)
    except Exception:
        # Fallback: if FindingSet is simple container, append to internal list
        try:
            # assume fset has attribute 'issues' (dataclass wrapper)
            fset.issues.append(issue)
        except Exception:
            # last resort: replace with a new FindingSet
            findings[fn] = FindingSet(issues=list(_iter_findingset(fset)) + [issue])

def _iter_findingset(fset: FindingSet) -> Iterable[Issue]:
    """
    Safely iterate the issues of a FindingSet (compatible with multiple shapes).
    """
    if hasattr(fset, "by_severity"):
        try:
            for item in fset.by_severity():
                yield item
            return
        except Exception:
            pass
    # try to treat as iterable
    try:
        for item in list(fset):
            yield item
        return
    except Exception:
        pass
    # try attribute 'issues'
    try:
        for item in getattr(fset, "issues", []):
            yield item
        return
    except Exception:
        return

# ----------------- Quick-fix attachment -----------------

def attach_quick_fixes(findings: Dict[str, FindingSet]) -> None:
    """
    Walk existing findings and attach suggested quick fixes where applicable.
    This mutates Issue.evidence when possible; if Issue is frozen, we replace
    it with a new Issue instance that contains updated evidence.
    """
    for fn, fset in list(findings.items()):
        # Collect new list of issues after applying fixes (for replacement if needed)
        replaced = False
        new_issues = []
        for it in list(_iter_findingset(fset)):
            ev = dict(getattr(it, "evidence", {}) or {})
            call_sig = ev.get("call", "") or ""

            # Basic heuristics for quick fixes
            fix_text = None
            if call_sig.startswith("strcpy("):
                fix_text = "strncpy(dst, src, sizeof(dst)-1); dst[sizeof(dst)-1] = '\\0';"
            elif call_sig.startswith("strcat("):
                fix_text = "strncat(dst, src, sizeof(dst)-strlen(dst)-1);"
            elif call_sig.startswith("memcpy("):
                fix_text = "memcpy(dst, src, len); /* ensure len <= sizeof(dst) */"
            elif call_sig.startswith("scanf(") and "%s" in call_sig:
                fix_text = 'scanf("%15s", buf); /* add width to avoid overflow */'
            elif call_sig.startswith("gets("):
                fix_text = "fgets(buf, sizeof(buf), stdin); /* avoid gets() */"

            if fix_text:
                ev["fix"] = fix_text

                # Try to set evidence in-place (works if Issue not frozen)
                try:
                    setattr(it, "evidence", ev)
                    new_issues.append(it)
                except FrozenInstanceError:
                    # If Issue is frozen dataclass, reconstruct a new Issue with same fields
                    if is_dataclass(it):
                        try:
                            # build kwargs from attributes that Issue is expected to have
                            kwargs = {
                                "kind": getattr(it, "kind", None),
                                "message": getattr(it, "message", None),
                                "severity": getattr(it, "severity", None),
                                "cwe": getattr(it, "cwe", None),
                                "function": getattr(it, "function", fn),
                                "node_id": getattr(it, "node_id", None),
                                "evidence": ev,
                            }
                            new_issue = Issue(**kwargs)
                            new_issues.append(new_issue)
                            replaced = True
                        except Exception:
                            # if reconstruction fails, fall back to keeping original issue
                            new_issues.append(it)
                    else:
                        # not a dataclass but frozen: can't set — keep original
                        new_issues.append(it)
                except Exception:
                    # any other error while setting, keep original
                    new_issues.append(it)
            else:
                # no fix applicable; keep original
                new_issues.append(it)

        # If we replaced/updated issues, make sure findings[fn] contains the updated FindingSet
        if replaced:
            findings[fn] = FindingSet(issues=new_issues)

# ----------------- Injection/format detectors -----------------

def detect_injection_like(ir_unit, findings: Dict[str, FindingSet]) -> None:
    """
    Heuristic detectors for:
      - printf(non-literal) -> Format string risk (CWE-134)
      - system(tainted) -> Command injection (CWE-78)
    This is intentionally minimal and conservative.
    """
    for func in getattr(ir_unit, "functions", []):
        fname = getattr(func, "name", "<unknown>")
        for s in getattr(func, "body", []):
            if getattr(s, "op", "") != "call":
                continue
            func_name = s.args.get("func") if isinstance(getattr(s, "args", None), dict) else None
            args = s.args.get("args", []) if isinstance(getattr(s, "args", None), dict) else []
            # format-string check: first arg is not a string literal
            if func_name == "printf" and args:
                first = args[0]
                if not (isinstance(first, str) and (first.startswith('"') or first.startswith("'"))):
                    _add(
                        findings,
                        fname,
                        "Medium",
                        "Format string risk",
                        "CWE-134",
                        f"printf called with non-literal first argument: {first}",
                        {"call": f"printf({', '.join(args)})"},
                    )
            # command injection: system called with non-constant/tainted arg
            if func_name == "system" and args:
                _add(
                    findings,
                    fname,
                    "High",
                    "Command Injection risk",
                    "CWE-78",
                    f"system invoked with possibly user-controlled data: {args[0]}",
                    {"call": f"system({', '.join(args)})"},
                )

# ----------------- Exported entrypoint -----------------

def postprocess_findings(ir_unit, findings: Dict[str, FindingSet]) -> None:
    """
    Run all post-processing steps: detection augmentation & quick-fix attachment.
    Call this after your main rule pass so the UI/HTML rendering sees the final findings.
    """
    # 1) Detect additional patterns like injections
    try:
        detect_injection_like(ir_unit, findings)
    except Exception:
        # keep post-processing resilient; don't crash analyzer if this fails
        pass

    # 2) Attach quick fixes where applicable
    try:
        attach_quick_fixes(findings)
    except Exception:
        pass
