from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Set, Iterable

# --- Dataflow facts (very small / demo-friendly) -----------------------------------

@dataclass
class Facts:
    """
    Minimal dataflow container used by rules.py.
    - defined_in[block_id] = set of vars defined before/within the block (very coarse).
    - taint_in[block_id]   = set of vars considered tainted at block entry (optional).
    """
    defined_in: Dict[str, Set[str]] = field(default_factory=dict)
    taint_in: Dict[str, Set[str]] = field(default_factory=dict)

# --- IR read-extraction helper -----------------------------------------------------

def _reads(stmt) -> Iterable[str]:
    """
    Best-effort extraction of variable names read by an IR statement.
    Works with simple IRs used in this project (stmt.op + stmt.args dict).
    Falls back to scanning strings present in stmt.args.
    """
    out: Set[str] = set()
    try:
        # expected layout: stmt.op (str) and stmt.args (dict)
        args = getattr(stmt, "args", {}) or {}
        def _scan_val(v):
            if v is None:
                return
            if isinstance(v, str):
                # crude tokenization
                for tok in v.replace("->", " ").replace("*", " ").replace("(", " ").replace(")", " ").replace(",", " ").split():
                    # ignore obvious operators/ints
                    if tok.isdigit():
                        continue
                    if tok in {"=", "+", "-", "/", "*", "%", "==", "!=", "<", "<=", ">", ">=", "&&", "||"}:
                        continue
                    out.add(tok)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    _scan_val(x)
            elif isinstance(v, dict):
                for x in v.values():
                    _scan_val(x)

        for v in args.values():
            _scan_val(v)

        # Some IRs store a direct 'reads' field
        r = args.get("reads")
        if isinstance(r, (list, set, tuple)):
            for x in r:
                if isinstance(x, str):
                    out.add(x)

    except Exception:
        pass
    return out
