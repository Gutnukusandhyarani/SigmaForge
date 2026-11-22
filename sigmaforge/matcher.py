"""Evaluate supported Sigma-like selector semantics against normalized JSON events."""
from __future__ import annotations
import fnmatch
import re
from .condition import parse_condition,select_names

def get_field(event: dict, name: str):
    current=event
    for segment in name.split("."):
        if isinstance(current,dict):
            current=current.get(segment)
        else:
            return None
    return current

def _scalar_match(actual, expected, modifier, all_values=False):
    if isinstance(actual,list):
        outcomes=[_scalar_match(v,expected,modifier,False) for v in actual]
        return all(outcomes) if all_values else any(outcomes)
    if actual is None:
        return False
    candidates=expected if isinstance(expected,list) else [expected]
    def one(wanted):
        a=str(actual); b=str(wanted)
        if modifier in ("contains","all"):
            return b.casefold() in a.casefold()
        if modifier=="startswith": return a.casefold().startswith(b.casefold())
        if modifier=="endswith": return a.casefold().endswith(b.casefold())
        if modifier=="re":
            try: return re.search(b,a,re.I) is not None
            except re.error: return False
        return a.casefold()==b.casefold()
    if modifier=="all":
        return all(one(x) for x in candidates)
    return any(one(x) for x in candidates)

def match_selector(selector, event):
    if isinstance(selector,list):
        return any(match_selector(item,event) for item in selector)
    if not isinstance(selector,dict):
        # Sigma keyword selectors are represented by a list of terms.
        if isinstance(selector,str):
            message=str(event.get("message",""))
            return selector.casefold() in message.casefold()
        return False
    for field_expr,expected in selector.items():
        parts=field_expr.split("|")
        field=parts[0]
        modifiers=parts[1:]
        if "exists" in modifiers:
            actual=get_field(event,field)
            exists=actual is not None and actual!=""
            if bool(expected) != exists: return False
            continue
        modifier=next((m for m in modifiers if m in {"contains","startswith","endswith","re","all"}),"equals")
        actual=get_field(event,field)
        if not _scalar_match(actual,expected,modifier):
            return False
    return True

def evaluate_tree(tree, detection, event):
    op=tree[0]
    if op=="selector":
        return match_selector(detection[tree[1]],event)
    if op=="of_expanded":
        threshold=tree[1]
        names=tree[2]
        count=sum(1 for name in names if match_selector(detection[name],event))
        return count==len(names) if threshold=="all" else count>=int(threshold)
    if op=="not": return not evaluate_tree(tree[1],detection,event)
    if op=="and": return evaluate_tree(tree[1],detection,event) and evaluate_tree(tree[2],detection,event)
    if op=="or": return evaluate_tree(tree[1],detection,event) or evaluate_tree(tree[2],detection,event)
    raise ValueError(f"unsupported condition node: {op}")

def match_rule(rule: dict, event: dict) -> bool:
    detection=rule.get("detection",{})
    names={k for k in detection if k!="condition" and isinstance(detection[k],(dict,list))}
    tree=select_names(parse_condition(detection["condition"]),names)
    return evaluate_tree(tree,detection,event)
