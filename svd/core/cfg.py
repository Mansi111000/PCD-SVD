from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Tuple
from .ir import IRFunction, IRUnit, IRStmt

@dataclass
class BasicBlock:
    id: str
    stmts: List[IRStmt]
    succ: List[str] = field(default_factory=list)
    pred: List[str] = field(default_factory=list)

@dataclass
class CFG:
    func: IRFunction
    blocks: Dict[str, BasicBlock]
    entry: str

# ---------------- CFG construction (structured, simple) ----------------

def build_cfg(func: IRFunction) -> CFG:
    blocks: Dict[str, BasicBlock] = {}
    counter = 0

    def new_block() -> BasicBlock:
        nonlocal counter
        counter += 1
        bid = f"B{counter}"
        bb = BasicBlock(id=bid, stmts=[])
        blocks[bid] = bb
        return bb

    current = new_block()
    stack: List[tuple[str, BasicBlock, BasicBlock | None]] = []  # (kind, start, else)

    for s in func.body:
        op = getattr(s, "op", "")
        if op in ("if", "loop"):
            current.stmts.append(s)
            then_bb = new_block()
            current.succ.append(then_bb.id)
            then_bb.pred.append(current.id)
            stack.append((op, current, None))
            current = then_bb
        elif op == "else":
            kind, start_bb, _ = stack.pop()
            else_bb = new_block()
            start_bb.succ.append(else_bb.id)
            else_bb.pred.append(start_bb.id)
            stack.append((kind, start_bb, else_bb))
            current = else_bb
        elif op in ("endif", "endloop"):
            kind, start_bb, else_bb = stack.pop()
            join = new_block()
            current.succ.append(join.id)
            join.pred.append(current.id)
            if else_bb:
                else_bb.succ.append(join.id)
                join.pred.append(else_bb.id)
            else:
                start_bb.succ.append(join.id)
                join.pred.append(start_bb.id)
            current = join
        else:
            current.stmts.append(s)

    entry = "B1"
    return CFG(func=func, blocks=blocks, entry=entry)

def build_cfgs_for_unit(unit: IRUnit) -> Dict[str, CFG]:
    return {f.name: build_cfg(f) for f in unit.functions}

# ---------------- Human-readable stmt lines & details ----------------

def _stmt_line(s: IRStmt) -> str:
    op = getattr(s, "op", "")
    sid = getattr(s, "sid", "")
    args = getattr(s, "args", {}) or {}
    if op == "assign":
        return f"{sid}: {args.get('lhs','')} = {args.get('rhs','')}"
    if op == "call":
        fn = args.get("func", "")
        argv = args.get("args", [])
        return f"{sid}: call {fn}({', '.join(argv)})"
    if op == "return":
        return f"{sid}: return {args.get('expr','')}"
    if op == "if":
        return f"{sid}: if ({args.get('cond','')})"
    if op == "else":
        return f"{sid}: else"
    if op == "endif":
        return f"{sid}: endif"
    if op == "loop":
        return f"{sid}: loop ({args.get('cond','')})"
    if op == "endloop":
        return f"{sid}: endloop"
    return f"{sid}: {op}"

def cfg_block_details(cfg: CFG) -> List[Tuple[str, List[str]]]:
    details: List[Tuple[str, List[str]]] = []
    for bid, b in cfg.blocks.items():
        details.append((bid, [_stmt_line(s) for s in b.stmts]))
    details.sort(key=lambda x: int(x[0][1:]) if x[0].startswith('B') else 0)
    return details

# ---------------- Mermaid output (bulletproof) ----------------
# Nodes only show the block id (B1, B2, ...) to avoid parser gotchas.

def cfg_to_mermaid(cfg: CFG) -> str:
    lines = ["flowchart TD"]
    for bid in cfg.blocks.keys():
        lines.append(f'{bid}["{bid}"]')   # rectangle node with simple id label
    for bid, b in cfg.blocks.items():
        for t in b.succ:
            lines.append(f"{bid} --> {t}")
    return "\n".join(lines)
