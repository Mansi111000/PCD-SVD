from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pycparser import c_ast
from .parser_frontend import Unit

@dataclass
class IRStmt:
    op: str
    args: dict
    sid: int

@dataclass
class IRFunction:
    name: str
    params: List[str]
    body: List[IRStmt]
    arrays: Dict[str, int]  # decl name -> size if constant

@dataclass
class IRUnit:
    functions: List[IRFunction]


class IRBuilder(c_ast.NodeVisitor):
    def __init__(self):
        self.funcs: List[IRFunction] = []
        self.cur_body: List[IRStmt] | None = None
        self.cur_arrays: Dict[str,int] | None = None
        self.sid = 0

    def new_sid(self):
        self.sid += 1
        return self.sid

    def visit_FuncDef(self, node: c_ast.FuncDef):
        name = node.decl.name
        params = []
        if isinstance(node.decl.type, c_ast.FuncDecl) and node.decl.type.args:
            for p in node.decl.type.args.params:
                if isinstance(p, c_ast.Decl):
                    params.append(p.name)
        self.cur_body = []
        self.cur_arrays = {}
        self.visit(node.body)
        self.funcs.append(IRFunction(name=name, params=params, body=self.cur_body or [], arrays=self.cur_arrays or {}))
        self.cur_body = None
        self.cur_arrays = None

    # Collect array sizes from declarations like: int a[10];
    def visit_Decl(self, node: c_ast.Decl):
        if isinstance(node.type, c_ast.ArrayDecl) and self.cur_arrays is not None:
            try:
                sz = int(node.type.dim.value) if node.type.dim is not None else None
                if sz is not None:
                    self.cur_arrays[node.name] = sz
            except Exception:
                pass
        # Also record declaration as a definitional stmt (init)
        if node.init is not None and self.cur_body is not None:
            self.cur_body.append(IRStmt(op="assign", args={"lhs": node.name, "rhs": self.expr_to_str(node.init)}, sid=self.new_sid()))

    def visit_Assignment(self, node: c_ast.Assignment):
        if self.cur_body is None: return
        lhs = self.expr_to_str(node.lvalue)
        rhs = self.expr_to_str(node.rvalue)
        self.cur_body.append(IRStmt(op="assign", args={"lhs": lhs, "rhs": rhs}, sid=self.new_sid()))

    def visit_FuncCall(self, node: c_ast.FuncCall):
        if self.cur_body is None: return
        name = node.name.name if isinstance(node.name, c_ast.ID) else str(node.name)
        args = []
        if node.args:
            for a in node.args.exprs:
                args.append(self.expr_to_str(a))
        self.cur_body.append(IRStmt(op="call", args={"func": name, "args": args}, sid=self.new_sid()))

    def visit_Return(self, node: c_ast.Return):
        if self.cur_body is None: return
        expr = self.expr_to_str(node.expr) if node.expr is not None else None
        self.cur_body.append(IRStmt(op="return", args={"expr": expr}, sid=self.new_sid()))

    def visit_If(self, node: c_ast.If):
        # Represent as branch
        cond = self.expr_to_str(node.cond)
        self.cur_body.append(IRStmt(op="if", args={"cond": cond}, sid=self.new_sid()))
        self.visit(node.iftrue)
        if node.iffalse:
            self.cur_body.append(IRStmt(op="else", args={}, sid=self.new_sid()))
            self.visit(node.iffalse)
        self.cur_body.append(IRStmt(op="endif", args={}, sid=self.new_sid()))

    def visit_While(self, node: c_ast.While):
        cond = self.expr_to_str(node.cond)
        self.cur_body.append(IRStmt(op="loop", args={"cond": cond}, sid=self.new_sid()))
        self.visit(node.stmt)
        self.cur_body.append(IRStmt(op="endloop", args={}, sid=self.new_sid()))

    def visit_For(self, node: c_ast.For):
        # Simplify: record a loop with synthetic condition text
        cond = self.expr_to_str(node.cond) if node.cond is not None else "true"
        self.cur_body.append(IRStmt(op="loop", args={"cond": cond}, sid=self.new_sid()))
        if node.stmt: self.visit(node.stmt)
        self.cur_body.append(IRStmt(op="endloop", args={}, sid=self.new_sid()))

    def generic_visit(self, node):
        for c in node: self.visit(c)

    def expr_to_str(self, node) -> str:
        # Best-effort source-ish strings for expressions
        if node is None:
            return ""
        if isinstance(node, c_ast.Constant):
            return node.value
        if isinstance(node, c_ast.ID):
            return node.name
        if isinstance(node, c_ast.BinaryOp):
            return f"{self.expr_to_str(node.left)} {node.op} {self.expr_to_str(node.right)}"
        if isinstance(node, c_ast.UnaryOp):
            return f"{node.op}{self.expr_to_str(node.expr)}"
        if isinstance(node, c_ast.ArrayRef):
            return f"{self.expr_to_str(node.name)}[{self.expr_to_str(node.subscript)}]"
        if isinstance(node, c_ast.Cast):
            return self.expr_to_str(node.expr)
        if isinstance(node, c_ast.TernaryOp):
            return f"({self.expr_to_str(node.cond)} ? {self.expr_to_str(node.iftrue)} : {self.expr_to_str(node.iffalse)})"
        return str(node)


def lower_unit_to_ir(unit: Unit) -> IRUnit:
    b = IRBuilder()
    b.visit(unit.ast)
    return IRUnit(functions=b.funcs)

def lower_to_ir(unit):
    return lower_unit_to_ir(unit)