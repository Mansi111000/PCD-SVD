from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class Issue:
    kind: str
    message: str
    severity: str
    cwe: str
    function: str
    node_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FindingSet:
    issues: List[Issue] = field(default_factory=list)

    def add(self, issue: Issue) -> None:
        self.issues.append(issue)

    def by_severity(self) -> List[Issue]:
        order = {"High":0, "Medium":1, "Low":2}
        return sorted(self.issues, key=lambda x: order.get((x.severity or "Medium"), 1))
