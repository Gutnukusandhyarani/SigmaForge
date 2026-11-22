"""Export simple SigmaForge rules to the SentinelOps JSON rule-pack contract."""
from __future__ import annotations
from pathlib import Path
import json
from .parser import validate_paths

def export_sentinelops(root: str | Path) -> list[dict]:
    documents=validate_paths(root)
    result=[]
    for doc in documents:
        if doc.errors:
            raise ValueError(f"{doc.path}: "+"; ".join(doc.errors))
        detection=doc.detection
        selectors=[(k,v) for k,v in detection.items() if k!="condition"]
        tree_condition=doc.condition.strip()
        if tree_condition not in {name for name,_ in selectors} or len(selectors)!=1:
            raise ValueError(f"{doc.path}: SentinelOps export requires one selector referenced directly by condition")
        selector=selectors[0][1]
        if not isinstance(selector,dict):
            raise ValueError(f"{doc.path}: SentinelOps export supports mapping selectors only")
        conditions=[]
        for field_expr,value in selector.items():
            parts=field_expr.split("|")
            field=parts[0]
            mods=parts[1:]
            if mods==["exists"]:
                conditions.append({"field":field,"operator":"exists","value":True})
            elif not mods:
                conditions.append({"field":field,"operator":"equals","value":value})
            elif mods==["contains"]:
                conditions.append({"field":field,"operator":"contains","value":value})
            else:
                raise ValueError(f"{doc.path}: SentinelOps export does not support modifier {mods}")
        tags=[str(t) for t in doc.data.get("tags",[])]
        level=doc.data.get("level","medium")
        result.append({
            "id":doc.rule_id,"title":doc.title,"level":level,
            "description":doc.data.get("description",""),
            "tags":tags,"conditions":conditions
        })
    return result

def write_export(root,output):
    rules=export_sentinelops(root)
    path=Path(output); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(rules,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    return len(rules)
