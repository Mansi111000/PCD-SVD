from __future__ import annotations
from typing import Dict
from collections import defaultdict

from .cfg import CFG
from .utils import Issue, FindingSet
from .dataflow import _reads  # Facts is optional; we only care about _reads

UNSAFE_SINKS = {"strcpy","strcat","gets","scanf","memcpy","system"}

def run_rules(cfgs: Dict[str, CFG], facts: Dict[str, object] | None = None) -> Dict[str, FindingSet]:
    """
    Very small rules pass that:
      - flags uninitialized var reads (uses facts.defined_in if provided)
      - division-by-zero heuristic
      - null deref heuristic
      - unsafe library calls
      - tainted-to-sink if facts.taint_in is provided
    """
    out: Dict[str, FindingSet] = {}
    facts = facts or {}

    for fname, cfg in cfgs.items():
        fset = FindingSet()
        fx = facts.get(fname) if isinstance(facts, dict) else None

        for bid, block in cfg.blocks.items():
            defined = set()
            tainted = set()
            try:
                defined = set(getattr(fx, "defined_in", {}).get(bid, set()))
                tainted = set(getattr(fx, "taint_in", {}).get(bid, set()))
            except Exception:
                pass

            for s in block.stmts:
                reads = list(_reads(s))

                # 1) Uninitialized variable use
                undef = [v for v in reads if v not in defined and not v.isdigit()]
                if undef:
                    fset.add(Issue(
                        kind="Uninitialized Variable",
                        message=f"Use of {', '.join(undef)} may be uninitialized",
                        severity="High",
                        cwe="CWE-457",
                        function=fname,
                        node_id=bid,
                        evidence={"sid": getattr(s,"sid",None), "reads": reads}
                    ))

                # 2) Division by zero heuristic: look for "a / b"
                if getattr(s, "op", "") == "assign":
                    rhs = (getattr(s, "args", {}) or {}).get("rhs", "")
                    if isinstance(rhs, str) and "/" in rhs:
                        parts = rhs.split("/")
                        if len(parts) == 2:
                            denom = parts[1].strip()
                            if denom == "0" or denom in reads:
                                fset.add(Issue(
                                    kind="Division by Zero",
                                    message=f"Possible division by zero in '{rhs}'",
                                    severity="Medium",
                                    cwe="CWE-369",
                                    function=fname,
                                    node_id=bid,
                                    evidence={"sid": getattr(s,"sid",None), "expr": rhs}
                                ))

                # 3) Null deref heuristic
                rhs = (getattr(s, "args", {}) or {}).get("rhs", "")
                if isinstance(rhs, str) and ("*" in rhs or "->" in rhs):
                    if any(tok in {"p","ptr","ptr1","ptr2"} for tok in reads):
                        fset.add(Issue(
                            kind="Null Dereference",
                            message="Pointer may be null before dereference",
                            severity="High",
                            cwe="CWE-476",
                            function=fname,
                            node_id=bid,
                            evidence={"sid": getattr(s,"sid",None), "reads": reads}
                        ))

                # 4) Unsafe sinks
                if getattr(s, "op", "") == "call":
                    func = (getattr(s, "args", {}) or {}).get("func")
                    args = (getattr(s, "args", {}) or {}).get("args", [])
                    if func in UNSAFE_SINKS:
                        fset.add(Issue(
                            kind="Unsafe Library Call",
                            message=f"Call to {func} may cause overflow or command injection",
                            severity="High" if func in {"strcpy","gets","system"} else "Medium",
                            cwe="CWE-120" if func in {"strcpy","gets","strcat","memcpy"} else "CWE-78",
                            function=fname,
                            node_id=bid,
                            evidence={"sid": getattr(s,"sid",None), "call": f"{func}({', '.join(args)})"}
                        ))
                        # 5) Taint to sink (if facts present)
                        try:
                            if tainted:
                                tainted_args = [a for a in reads if a in tainted]
                                if tainted_args:
                                    fset.add(Issue(
                                        kind="Tainted Data to Sink",
                                        message=f"Tainted input {', '.join(tainted_args)} reaches {func}",
                                        severity="High",
                                        cwe="CWE-20",
                                        function=fname,
                                        node_id=bid,
                                        evidence={"sid": getattr(s,"sid",None), "tainted": tainted_args}
                                    ))
                        except Exception:
                            pass

        out[fname] = fset
    return out
