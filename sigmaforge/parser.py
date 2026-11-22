"""Load and validate Sigma-like YAML rules."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import uuid
import yaml

VALID_STATUSES={"stable","test","experimental","deprecated"}
VALID_LEVELS={"informational","low","medium","high","critical"}

@dataclass
class RuleDocument:
    path: Path
    data: dict
    errors: list[str]
    warnings: list[str]

    @property
    def rule_id(self): return str(self.data.get("id",""))
    @property
    def title(self): return str(self.data.get("title",""))
    @property
    def detection(self): return self.data.get("detection",{})
    @property
    def condition(self): return str(self.detection.get("condition",""))

def load_rule(path: str | Path) -> RuleDocument:
    path=Path(path)
    try:
        data=yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return RuleDocument(path,{},[f"YAML parse error: {exc}"],[])
    errors=[]; warnings=[]
    if not isinstance(data,dict):
        return RuleDocument(path,{},["rule root must be a YAML mapping"],[])
    for field in ("title","id","status","description","logsource","detection","level"):
        if field not in data:
            errors.append(f"missing required field: {field}")
    if data.get("id"):
        try: uuid.UUID(str(data["id"]))
        except (ValueError,TypeError,AttributeError): errors.append("id must be a UUID")
    if data.get("status") not in VALID_STATUSES:
        errors.append(f"status must be one of: {', '.join(sorted(VALID_STATUSES))}")
    if data.get("level") not in VALID_LEVELS:
        errors.append(f"level must be one of: {', '.join(sorted(VALID_LEVELS))}")
    if not isinstance(data.get("logsource"),dict):
        errors.append("logsource must be a mapping")
    if not isinstance(data.get("detection"),dict):
        errors.append("detection must be a mapping")
    else:
        detection=data["detection"]
        condition=detection.get("condition")
        selectors={k for k,v in detection.items() if k!="condition" and isinstance(v,(dict,list))}
        if not isinstance(condition,str) or not condition.strip():
            errors.append("detection.condition must be a non-empty string")
        else:
            from .condition import parse_condition, select_names
            try:
                tree=parse_condition(condition)
                select_names(tree,selectors)
            except ValueError as exc:
                errors.append(f"invalid condition: {exc}")
        if not selectors:
            errors.append("detection must contain at least one selector")
    if not isinstance(data.get("tags",[]),list):
        errors.append("tags must be a list")
    if not data.get("falsepositives"):
        warnings.append("falsepositives guidance is missing")
    if not data.get("tags"):
        warnings.append("ATT&CK or classification tags are missing")
    if not data.get("author"):
        warnings.append("author metadata is missing")
    return RuleDocument(path,data,errors,warnings)

def discover_rules(root: str | Path) -> list[Path]:
    path=Path(root)
    if path.is_file(): return [path]
    if not path.exists(): raise FileNotFoundError(path)
    return sorted(p for p in path.rglob("*.yml") if p.is_file()) + sorted(p for p in path.rglob("*.yaml") if p.is_file())

def validate_paths(root: str | Path) -> list[RuleDocument]:
    documents=[load_rule(path) for path in discover_rules(root)]
    seen={}
    for document in documents:
        rule_id=document.rule_id
        if not rule_id:
            continue
        if rule_id in seen:
            document.errors.append(f"duplicate rule id also used by {seen[rule_id]}")
        else:
            seen[rule_id]=document.path
    return documents
