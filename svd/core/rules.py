from __future__ import annotations
from typing import Dict
from collections import defaultdict

from .cfg import CFG, build_cfgs_for_unit
from .ir import IRStmt, IRUnit
from .utils import Issue, FindingSet
from .dataflow import Facts, _reads

# Attempt to find a dataflow driver with any common name
_analyze_df = None
try:
    from .dataflow import analyze_dataflow as _analyze_df
except Exception:
    pass
if _analyze_df is None:
    try:
        from .dataflow import run_dataflow as _analyze_df
    except Exception:
        pass
if _analyze_df is None:
    try:
        from .dataflow import compute_facts as _analyze_df
    except Exception:
        pass

UNSAFE_SINKS = {"strcpy","strcat","gets","scanf","memcpy","system"}

def run_rules(cfgs: Dict[str, CFG], facts: Dict[str, Facts]) -> Dict[str, FindingSet]:
    out: Dict[str, FindingSet] = {}
    for fname, cfg in cfgs.items():
        fnd = FindingSet(issues=[])
        fx = facts.get(fname) if facts else None
        for bid, block in cfg.blocks.items():
            def_in = fx.defined_in.get(bid, set()) if fx else set()
            taint_in = fx.taint_in.get(bid, set()) if fx else set()
            for s in block.stmts:
                reads = _reads(s)

                # 1) Uninitialized variable use
                undef = [v for v in reads if v not in def_in and not v.isdigit()]
                if undef:
                    fnd.add(Issue(
                        kind="Uninitialized Variable",
                        message=f"Use of {', '.join(undef)} may be uninitialized",
                        severity="High",
                        cwe="CWE-457",
                        function=fname,
                        node_id=bid,
                        evidence={"stmt": s.op, "sid": s.sid, "reads": list(reads)}
                    ))

                # 2) Division by zero heuristic
                if s.op == "assign":
                    rhs = s.args.get("rhs", "")
                    if "/" in rhs:
                        parts = rhs.split("/")
                        if len(parts) == 2:
                            denom = parts[1].strip()
                            if denom == "0" or denom in reads:
                                fnd.add(Issue(
                                    kind="Division by Zero",
                                    message=f"Possible division by zero in '{rhs}'",
                                    severity="Medium",
                                    cwe="CWE-369",
                                    function=fname,
                                    node_id=bid,
                                    evidence={"stmt": s.op, "sid": s.sid, "expr": rhs}
                                ))

                # 3) Null deref heuristic
                rhs = s.args.get("rhs", "")
                if ("*" in rhs or "->" in rhs) and any(tok in {"p","ptr","ptr1","ptr2"} for tok in reads):
                    fnd.add(Issue(
                        kind="Null Dereference",
                        message="Pointer may be null before dereference",
                        severity="High",
                        cwe="CWE-476",
                        function=fname,
                        node_id=bid,
                        evidence={"sid": s.sid, "reads": list(reads)}
                    ))

                # 4) Unsafe sinks (API misuse)
                if s.op == "call" and s.args.get("func") in UNSAFE_SINKS:
                    func = s.args.get("func")
                    args = s.args.get("args", [])
                    fnd.add(Issue(
                        kind="Unsafe Library Call",
                        message=f"Call to {func} may cause overflow or command injection",
                        severity="High" if func in {"strcpy","gets","system"} else "Medium",
                        cwe="CWE-120" if func in {"strcpy","gets","strcat","memcpy"} else "CWE-78",
                        function=fname,
                        node_id=bid,
                        evidence={"sid": s.sid, "call": f"{func}({', '.join(args)})"}
                    ))

                # 5) Tainted arg to sink
                if s.op == "call" and s.args.get("func") in UNSAFE_SINKS and taint_in:
                    tainted = [a for a in reads if a in taint_in]
                    if tainted:
                        fnd.add(Issue(
                            kind="Tainted Data to Sink",
                            message=f"Tainted input {', '.join(tainted)} reaches {s.args.get('func')}",
                            severity="High",
                            cwe="CWE-20",
                            function=fname,
                            node_id=bid,
                            evidence={"sid": s.sid, "tainted": tainted}
                        ))
        out[fname] = fnd
    return out

def analyze_unit(unit_or_ir: IRUnit):
    """Build CFGs, run data-flow if available, then apply rules. Returns (facts, findings)."""
    cfgs = build_cfgs_for_unit(unit_or_ir)
    if _analyze_df is not None:
        try:
            facts = _analyze_df(unit_or_ir, cfgs)  # prefer (unit, cfgs)
        except TypeError:
            try:
                facts = _analyze_df(unit_or_ir)
            except Exception:
                facts = {}
    else:
        facts = {}
    findings = run_rules(cfgs, facts)
    return facts, findings
