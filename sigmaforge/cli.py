"""SigmaForge CLI."""
import argparse
import json
from pathlib import Path
from .parser import validate_paths,load_rule
from .compiler import compile_rule
from .testing import run_cases
from .coverage import build_coverage
from .exporter import write_export

def cmd_validate(root):
    docs=validate_paths(root); errors=0; warnings=0
    for doc in docs:
        rel=str(doc.path)
        if doc.errors:
            errors+=len(doc.errors)
            for e in doc.errors: print(f"ERROR {rel}: {e}")
        else: print(f"OK    {rel}")
        for w in doc.warnings:
            warnings+=1; print(f"WARN  {rel}: {w}")
    print(f"\nValidated {len(docs)} rule(s): {errors} error(s), {warnings} warning(s).")
    return 1 if errors else 0

def main():
    parser=argparse.ArgumentParser(prog="sigmaforge",description="Detection-as-code workbench")
    sub=parser.add_subparsers(dest="command",required=True)
    validate=sub.add_parser("validate"); validate.add_argument("--rules",default="rules")
    test=sub.add_parser("test"); test.add_argument("--rules",default="rules"); test.add_argument("--cases",default="tests/cases.json")
    test.add_argument("--events",help="optional raw JSONL event file for exploratory evaluation")
    compile_p=sub.add_parser("compile"); compile_p.add_argument("rule"); compile_p.add_argument("--backend",choices=["splunk","sentinel","elastic"],required=True)
    compile_p.add_argument("--field-map",help="optional JSON field map keyed by normalized field name")
    coverage=sub.add_parser("coverage"); coverage.add_argument("--rules",default="rules"); coverage.add_argument("--output",default="reports/attack-coverage.md")
    export=sub.add_parser("export"); export.add_argument("--rules",default="rules"); export.add_argument("--format",choices=["sentinelops"],required=True); export.add_argument("--output",default="exports/sentinelops-rules.json")
    web=sub.add_parser("serve",help="start the local rule-explorer dashboard")
    web.add_argument("--host",default="127.0.0.1"); web.add_argument("--port",type=int,default=8788)
    web.add_argument("--rules",default="rules"); web.add_argument("--cases",default="tests/cases.json")
    args=parser.parse_args()
    if args.command=="validate":
        raise SystemExit(cmd_validate(args.rules))
    if args.command=="serve":
        from .server import serve
        serve(args.host,args.port,args.rules,args.cases)
    if args.command=="test":
        results=run_cases(args.rules,args.cases)
        for r in results:
            print(("PASS" if r["pass"] else "FAIL")+f"  {r['name']}  expected={r['expected']} matched={r['matched']}")
        passed=sum(r["pass"] for r in results)
        print(f"\n{passed}/{len(results)} regression cases passed.")
        if args.events:
            from .matcher import match_rule
            from .parser import validate_paths
            docs=validate_paths(args.rules)
            for line_no,line in enumerate(Path(args.events).read_text(encoding="utf-8").splitlines(),1):
                if not line.strip(): continue
                event=json.loads(line)
                hits=[d.title for d in docs if not d.errors and match_rule(d.data,event)]
                print(f"event line {line_no}: {hits or 'no rule match'}")
        raise SystemExit(0 if passed==len(results) else 1)
    if args.command=="compile":
        doc=load_rule(args.rule)
        if doc.errors: raise SystemExit("Invalid rule: "+"; ".join(doc.errors))
        field_map=json.loads(Path(args.field_map).read_text(encoding="utf-8")) if args.field_map else None
        print(compile_rule(doc,args.backend,field_map))
    if args.command=="coverage":
        report=build_coverage(args.rules); path=Path(args.output); path.parent.mkdir(parents=True,exist_ok=True); path.write_text(report,encoding="utf-8")
        print(f"Wrote {path}")
    if args.command=="export":
        count=write_export(args.rules,args.output); print(f"Exported {count} rule(s) to {args.output}")
