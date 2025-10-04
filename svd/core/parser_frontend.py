from __future__ import annotations
from pycparser import c_parser, c_ast
import re

class Unit:
    def __init__(self, ast: c_ast.FileAST, text: str, filename: str | None = None):
        self.ast = ast
        self.text = text
        self.filename = filename or "<input>"

# Regexes for preprocessing
_CPP_LINE       = re.compile(r"^\s*#.*$", re.M)        # #include, #define, #ifdef, ...
_BLOCK_COMMENT  = re.compile(r"/\*.*?\*/", re.S)       # /* ... */
_LINE_COMMENT   = re.compile(r"//.*?$", re.M)          # // ...
_TRIM_TAIL_WS   = re.compile(r"[ \t]+\n")              # trailing spaces before newline

def _normalize_line_endings(text: str) -> str:
    """Convert CRLF/CR to LF so the lexer never sees raw '\r' characters."""
    # First collapse CRLF to LF, then any stray CR to LF
    return text.replace("\r\n", "\n").replace("\r", "\n")

def _preprocess_for_pycparser(text: str) -> str:
    """
    Make code friendly to pycparser without a real C preprocessor:
      1) normalize Windows line endings to LF
      2) remove preprocessor lines (#include, #define, etc.)
      3) remove /* block */ comments
      4) remove // line comments
      5) trim trailing whitespace
    """
    cleaned = _normalize_line_endings(text)
    cleaned = _CPP_LINE.sub("", cleaned)
    cleaned = _BLOCK_COMMENT.sub("", cleaned)
    cleaned = _LINE_COMMENT.sub("", cleaned)
    cleaned = _TRIM_TAIL_WS.sub("\n", cleaned)
    return cleaned

def parse_c_to_unit(text: str, filename: str | None = None) -> Unit:
    parser = c_parser.CParser()
    cleaned = _preprocess_for_pycparser(text)
    ast = parser.parse(cleaned, filename=filename or "<input>")
    return Unit(ast=ast, text=text, filename=filename)
