from __future__ import annotations
from pycparser import c_parser, c_ast
import re

# --------------------------------------------------------------------------------------
# Public data structure (unchanged)
# --------------------------------------------------------------------------------------
class Unit:
    def __init__(self, ast: c_ast.FileAST, text: str, filename: str | None = None):
        self.ast = ast
        self.text = text
        self.filename = filename or "<input>"

# --------------------------------------------------------------------------------------
# Lightweight "preprocessor" helpers so pycparser won't choke on raw student code
# --------------------------------------------------------------------------------------

# Regexes for cleaning
_CPP_LINE       = re.compile(r"^\s*#.*$", re.M)        # #include, #define, #ifdef, ...
_BLOCK_COMMENT  = re.compile(r"/\*.*?\*/", re.S)       # /* ... */
_LINE_COMMENT   = re.compile(r"//.*?$", re.M)          # // ...
_TRIM_TAIL_WS   = re.compile(r"[ \t]+\n")              # trailing spaces before newline

def _normalize_line_endings(text: str) -> str:
    """Convert CRLF/CR to LF so the lexer never sees raw '\r' characters."""
    return text.replace("\r\n", "\n").replace("\r", "\n")

def strip_preprocessor_lines(text: str) -> str:
    """
    PUBLIC: Make raw C friendlier for pycparser by:
      1) Normalizing CRLF/CR to LF (Windows safety).
      2) Removing /* ... */ block comments.
      3) Removing // line comments.
      4) Removing preprocessor lines starting with '#'.
      5) Trimming trailing whitespace at EOL.

    Note: This is a heuristic cleaner for demos/assignments. For full C,
    prefer a real preprocessor (e.g., `gcc -E`).
    """
    if not text:
        return ""
    s = _normalize_line_endings(text)
    # Remove preprocessor lines (#include/#define/etc.)
    s = _CPP_LINE.sub("", s)
    # Remove comments
    s = _BLOCK_COMMENT.sub("", s)
    s = _LINE_COMMENT.sub("", s)
    # Trim trailing spaces
    s = _TRIM_TAIL_WS.sub("\n", s)
    return s

def _preprocess_for_pycparser(text: str) -> str:
    """
    Internal hook used by parse_c_to_unit(). Currently identical to
    strip_preprocessor_lines(), but kept separate in case you later want
    a different pipeline for CLI vs. web UI.
    """
    return strip_preprocessor_lines(text)

# --------------------------------------------------------------------------------------
# Frontend entrypoint (unchanged call-site API)
# --------------------------------------------------------------------------------------
def parse_c_to_unit(text: str, filename: str | None = None) -> Unit:
    """
    Parse C into a pycparser AST after performing a minimal preprocessing
    (see _preprocess_for_pycparser). Returns a Unit wrapper.
    """
    parser = c_parser.CParser()
    cleaned = _preprocess_for_pycparser(text or "")
    ast = parser.parse(cleaned, filename=filename or "<input>")
    return Unit(ast=ast, text=text, filename=filename)
