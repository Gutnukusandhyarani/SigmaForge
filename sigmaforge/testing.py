"""Regression test runner for event fixtures."""
from __future__ import annotations
from pathlib import Path
import json
from .parser import validate_paths
from .matcher import match_rule

def run_cases(rules_root,cases_path):
    docs=validate_paths(rules_root)
    invalid=[d for d in docs if d.errors]
    if invalid:
        raise ValueError("invalid rules: "+"; ".join(f"{d.path}: {d.errors}" for d in invalid))
    rules=[d.data for d in docs]
    cases=json.loads(Path(cases_path).read_text(encoding="utf-8"))
    results=[]
    for case in cases:
        event=case["event"]; expected=set(case.get("expect",[]))
        matched=set()
        for rule in rules:
            if match_rule(rule,event): matched.add(str(rule["id"]))
        results.append({"name":case.get("name","unnamed"),"expected":sorted(expected),
                        "matched":sorted(matched),"pass":matched==expected})
    return results
