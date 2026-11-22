"""Generate a simple ATT&CK-tag coverage report from rule metadata."""
from collections import Counter,defaultdict
from pathlib import Path
from .parser import validate_paths

def build_coverage(root):
    documents=validate_paths(root)
    techniques=Counter(); tactic_counts=Counter(); rules_without=[]
    for doc in documents:
        tags=[str(t).lower() for t in doc.data.get("tags",[])]
        found=[t for t in tags if t.startswith("attack.t")]
        if not found: rules_without.append(doc.title or str(doc.path))
        for tag in found: techniques[tag]+=1
        for tag in tags:
            if tag.startswith("attack.") and not tag.startswith("attack.t"):
                tactic_counts[tag]+=1
    lines=["# ATT&CK Coverage Report","",
           f"- Rules analyzed: **{len(documents)}**",
           f"- Unique technique/sub-technique tags: **{len(techniques)}**",
           f"- Rules without ATT&CK technique tags: **{len(rules_without)}**","",
           "## Technique tags",""]
    if techniques:
        lines += ["| Technique tag | Rule count |","|---|---:|"]+[f"| `{tag}` | {count} |" for tag,count in sorted(techniques.items())]
    else: lines.append("No `attack.t*` tags found.")
    lines += ["","## Tactic tags",""]
    if tactic_counts:
        lines += ["| Tactic tag | Rule count |","|---|---:|"]+[f"| `{tag}` | {count} |" for tag,count in sorted(tactic_counts.items())]
    else: lines.append("No `attack.*` tactic tags found.")
    lines += ["","## Rules needing ATT&CK mapping",""]
    lines += [f"- {title}" for title in rules_without] if rules_without else ["All rules have at least one technique tag."]
    return "\n".join(lines)+"\n"
