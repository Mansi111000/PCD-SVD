from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class Issue:
    kind: str
    message: str
    severity: str
    cwe: str | None
    function: str | None
    node_id: str | None  # CFG node id for highlighting
    evidence: dict[str, Any]

@dataclass
class FindingSet:
    issues: list[Issue]

    def add(self, issue: Issue):
        self.issues.append(issue)

    def by_severity(self):
        order = {"High":0, "Medium":1, "Low":2}
        return sorted(self.issues, key=lambda x: order.get(x.severity, 3))