from __future__ import annotations
from typing import Dict, Set
from dataclasses import dataclass
from .cfg import CFG
from .ir import IRStmt

@dataclass
class Facts:
    defined_in: Dict[str, Set[str]]  # block id -> vars definitely defined on entry
    taint_in: Dict[str, Set[str]]    # block id -> tainted vars on entry
    intervals: Dict[str, Dict[str, tuple[int|None,int|None]]]  # block -> var -> (lo,hi)


def _reads(stmt: IRStmt) -> Set[str]:
    txt = ""  # crude parse: collect identifiers tokens used on RHS
    if stmt.op == "assign":
        txt = stmt.args.get("rhs", "")
    elif stmt.op == "call":
        txt = ",".join(stmt.args.get("args", []))
    elif stmt.op == "return":
        txt = stmt.args.get("expr", "")
    elif stmt.op in ("if", "loop"):
        txt = stmt.args.get("cond", "")
    out: Set[str] = set()
    for tok in txt.replace("[", " ").replace("]", " ").replace("(", " ").replace(")", " ").replace(","," ").replace("*"," ").split():
        if tok and tok[0].isalpha():
            out.add(tok)
    return out


def _writes(stmt: IRStmt) -> Set[str]:
    if stmt.op == "assign":
        lhs = stmt.args.get("lhs", "")
        # treat a[i] as a write to a
        return {lhs.split("[")[0]}
    return set()


def run_all_analyses(cfgs: Dict[str, CFG]) -> Dict[str, Facts]:
    facts: Dict[str, Facts] = {}
    for fname, cfg in cfgs.items():
        facts[fname] = _analyze_function(cfg)
    return facts


def _analyze_function(cfg: CFG) -> Facts:
    defined_in: Dict[str, Set[str]] = {bid: set() for bid in cfg.blocks}
    taint_in: Dict[str, Set[str]] = {bid: set() for bid in cfg.blocks}
    intervals: Dict[str, Dict[str, tuple[int|None,int|None]]] = {bid: {} for bid in cfg.blocks}

    changed = True
    while changed:
        changed = False
        for bid, block in cfg.blocks.items():
            # IN sets are union of predecessors' OUT
            preds = block.pred
            in_def = set().union(*(defined_in[p] for p in preds)) if preds else set()
            in_taint = set().union(*(taint_in[p] for p in preds)) if preds else set()

            cur_def = set(in_def)
            cur_taint = set(in_taint)

            # very light interval: none for now (kept for UI completeness)
            intervals[bid] = intervals.get(bid, {})

            for s in block.stmts:
                # taint sources
                if s.op == "call" and s.args.get("func") in {"gets","fgets","scanf"}:
                    # mark args as tainted sinks won't be here; args 1+ are outputs
                    # Simple rule: any identifier appearing is tainted
                    for v in _reads(s):
                        cur_taint.add(v)
                # reads may report uninitialized elsewhere
                for w in _writes(s):
                    cur_def.add(w)
                # taint propagation: assignment copies taint
                if s.op == "assign":
                    lhs = s.args.get("lhs", "").split("[")[0]
                    rhs_ids = _reads(s)
                    if any(r in cur_taint for r in rhs_ids):
                        cur_taint.add(lhs)

            if cur_def != defined_in[bid] or cur_taint != taint_in[bid]:
                defined_in[bid] = cur_def
                taint_in[bid] = cur_taint
                changed = True

    return Facts(defined_in=defined_in, taint_in=taint_in, intervals=intervals)