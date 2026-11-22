"""Compile the supported detection subset to common SIEM query dialects."""
from __future__ import annotations
from .condition import parse_condition,select_names
from .parser import RuleDocument

DEFAULT_FIELDS={
    "event_id":{"splunk":"EventCode","sentinel":"EventID","elastic":"event.code"},
    "host":{"splunk":"host","sentinel":"Computer","elastic":"host.name"},
    "source_ip":{"splunk":"src_ip","sentinel":"IpAddress","elastic":"source.ip"},
    "user":{"splunk":"user","sentinel":"TargetUserName","elastic":"user.name"},
    "action":{"splunk":"action","sentinel":"Action","elastic":"event.action"},
    "process":{"splunk":"process_name","sentinel":"NewProcessName","elastic":"process.name"},
    "message":{"splunk":"Message","sentinel":"Message","elastic":"message"},
    "product":{"splunk":"product","sentinel":"Product","elastic":"event.provider"},
}

def _quote(value):
    return "'"+str(value).replace("\\","\\\\").replace("'","\\'")+"'"

def _field_condition(field_expr,expected,backend,field_map):
    parts=field_expr.split("|"); field=parts[0]
    modifiers=parts[1:]
    if modifiers==["exists"]:
        name=field_map.get(field,{}).get(backend,field)
        return {"splunk":f'{name}=*',"sentinel":f'isnotempty({name})',"elastic":f'{name}:*'}[backend]
    modifier=next((m for m in modifiers if m in {"contains","startswith","endswith","re"}),"equals")
    name=field_map.get(field,{}).get(backend,field)
    values=expected if isinstance(expected,list) else [expected]
    if backend=="splunk":
        if modifier=="re": raise ValueError("regular-expression modifier is not exported to Splunk in this build")
        def term(v):
            escaped=str(v).replace('"','\\"')
            value=f"*{v}*" if modifier=="contains" else f"{v}*" if modifier=="startswith" else f"*{v}" if modifier=="endswith" else str(v)
            return f'{name}="{value.replace(chr(34), chr(92)+chr(34))}"'
        return "("+" OR ".join(term(v) for v in values)+")" if len(values)>1 else term(values[0])
    if backend=="sentinel":
        op={"equals":"==","contains":"contains","startswith":"startswith","endswith":"endswith"}.get(modifier)
        if op is None: raise ValueError(f"{modifier} is not exported to Sentinel KQL in this build")
        terms=[f'{name} {op} {_quote(v)}' for v in values]
        if modifier in ("contains","startswith","endswith"): return "("+" or ".join(terms)+")"
        return "("+" or ".join(terms)+")" if len(terms)>1 else terms[0]
    if backend=="elastic":
        if modifier=="re": raise ValueError("regular-expression modifier is not exported to Elastic query syntax")
        def term(v):
            val=str(v).replace(" ","\\ ")
            if modifier=="contains": val=f"*{val}*"
            elif modifier=="startswith": val=f"{val}*"
            elif modifier=="endswith": val=f"*{val}"
            return f"{name}:{val}"
        return "("+" OR ".join(term(v) for v in values)+")" if len(values)>1 else term(values[0])
    raise ValueError(f"unknown backend: {backend}")

def _selector_query(selector,backend,field_map):
    if isinstance(selector,list):
        return "("+" OR ".join(_selector_query(s,backend,field_map) for s in selector)+")"
    if not isinstance(selector,dict):
        raise ValueError("keyword-style/list selector export is not supported")
    pieces=[_field_condition(k,v,backend,field_map) for k,v in selector.items()]
    if not pieces: raise ValueError("empty selector")
    joiner=" AND " if backend=="splunk" else " and " if backend=="sentinel" else " AND "
    return "("+joiner.join(pieces)+")" if len(pieces)>1 else pieces[0]

def _tree_query(tree,detection,backend,field_map):
    op=tree[0]
    if op=="selector": return _selector_query(detection[tree[1]],backend,field_map)
    if op=="of_expanded":
        names=tree[2]
        if tree[1]!="1":
            raise ValueError("only '1 of' is currently compiled; 'all of' and numeric thresholds need rule-specific expansion")
        return "("+" OR ".join(_selector_query(detection[n],backend,field_map) for n in names)+")"
    if op=="not":
        inner=_tree_query(tree[1],detection,backend,field_map)
        return f"NOT ({inner})" if backend!="sentinel" else f"not({inner})"
    left=_tree_query(tree[1],detection,backend,field_map)
    right=_tree_query(tree[2],detection,backend,field_map)
    join={"splunk":" AND " if op=="and" else " OR ",
          "sentinel":" and " if op=="and" else " or ",
          "elastic":" AND " if op=="and" else " OR "}[backend]
    return f"({left}{join}{right})"

def compile_rule(document: RuleDocument,backend: str,field_map=None) -> str:
    if document.errors:
        raise ValueError("cannot compile invalid rule: "+"; ".join(document.errors))
    if backend not in {"splunk","sentinel","elastic"}:
        raise ValueError("backend must be splunk, sentinel or elastic")
    fields=field_map or DEFAULT_FIELDS
    detection=document.data["detection"]
    names={k for k in detection if k!="condition" and isinstance(detection[k],(dict,list))}
    tree=select_names(parse_condition(detection["condition"]),names)
    query=_tree_query(tree,detection,backend,fields)
    if backend=="splunk":
        return f"index=* {query}"
    if backend=="sentinel":
        source=document.data.get("logsource",{})
        tables={"windows":"SecurityEvent","linux":"Syslog"}
        table=tables.get(str(source.get("product","")).lower(),"CommonSecurityLog")
        return f"{table}\n| where {query}"
    return query
