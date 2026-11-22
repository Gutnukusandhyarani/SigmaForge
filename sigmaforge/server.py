"""Local-only rule explorer API and static dashboard."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse,parse_qs
import json
from .parser import validate_paths
from .compiler import compile_rule
from .testing import run_cases
from .coverage import build_coverage

WEB_DIR=Path(__file__).resolve().parent.parent/"web"

def _summary(rules_root,cases_path):
    docs=validate_paths(rules_root)
    valid=sum(not d.errors for d in docs)
    warnings=sum(len(d.warnings) for d in docs)
    levels={}
    techniques={}
    for doc in docs:
        level=str(doc.data.get("level","unknown"))
        levels[level]=levels.get(level,0)+1
        for tag in doc.data.get("tags",[]):
            lower=str(tag).lower()
            if lower.startswith("attack.t"):
                techniques[lower]=techniques.get(lower,0)+1
    try:
        cases=run_cases(rules_root,cases_path)
        passed=sum(1 for item in cases if item["pass"])
        tests={"total":len(cases),"passed":passed,"failed":len(cases)-passed}
    except Exception as exc:
        tests={"total":0,"passed":0,"failed":0,"error":str(exc)}
    return {"rules":len(docs),"valid":valid,"invalid":len(docs)-valid,
            "warnings":warnings,"levels":levels,"techniques":techniques,"tests":tests}

class Handler(BaseHTTPRequestHandler):
    rules_root="rules"
    cases_path="tests/cases.json"
    def _send(self,payload,status=200,ctype="application/json; charset=utf-8"):
        if ctype.startswith("application/json"):
            body=json.dumps(payload,ensure_ascii=False).encode("utf-8")
        else: body=payload
        self.send_response(status); self.send_header("Content-Type",ctype)
        self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store")
        self.end_headers(); self.wfile.write(body)
    def _static(self,name):
        path=(WEB_DIR/name).resolve()
        if WEB_DIR.resolve() not in path.parents or not path.is_file():
            return self._send("not found",404,"text/plain; charset=utf-8")
        content="text/html; charset=utf-8" if path.suffix==".html" else "text/css; charset=utf-8" if path.suffix==".css" else "application/javascript; charset=utf-8"
        self._send(path.read_bytes(),200,content)
    def do_GET(self):
        parsed=urlparse(self.path); params=parse_qs(parsed.query)
        if parsed.path=="/": return self._static("index.html")
        if parsed.path in ("/app.js","/styles.css"): return self._static(parsed.path.lstrip("/"))
        try:
            if parsed.path=="/api/overview":
                return self._send(_summary(self.rules_root,self.cases_path))
            if parsed.path=="/api/rules":
                docs=validate_paths(self.rules_root)
                result=[]
                for doc in docs:
                    result.append({"id":doc.rule_id,"title":doc.title,"status":doc.data.get("status","unknown"),
                        "level":doc.data.get("level","unknown"),"description":doc.data.get("description",""),
                        "tags":doc.data.get("tags",[]),"path":str(doc.path),
                        "errors":doc.errors,"warnings":doc.warnings,
                        "logsource":doc.data.get("logsource",{})})
                return self._send(result)
            if parsed.path=="/api/tests":
                return self._send(run_cases(self.rules_root,self.cases_path))
            if parsed.path=="/api/compile":
                rule_id=params.get("id",[""])[0]
                backend=params.get("backend",["splunk"])[0]
                if backend not in {"splunk", "sentinel", "elastic"}:
                    return self._send({"error":"unsupported backend"}, 400)
                if len(rule_id) > 64:
                    return self._send({"error":"invalid rule id"}, 400)
                docs=validate_paths(self.rules_root)
                doc=next((item for item in docs if item.rule_id==rule_id),None)
                if doc is None: return self._send({"error":"rule not found"},404)
                query=compile_rule(doc,backend)
                return self._send({"id":rule_id,"backend":backend,"query":query})
            if parsed.path=="/api/health":
                return self._send({"status":"ok","product":"SigmaForge"})
            return self._send({"error":"not found"},404)
        except Exception as exc:
            return self._send({"error":str(exc)},400)
    def log_message(self,fmt,*args):
        super().log_message(fmt,*args)

def serve(host="127.0.0.1",port=8788,rules_root="rules",cases_path="tests/cases.json"):
    # SigmaForge exposes read-only rule metadata, regression results and query compilation.
    # It has no write endpoints, but public hosting should still be limited to this app.
    if not host or len(host) > 255:
        raise ValueError("A valid bind host is required.")
    if not Path(rules_root).exists(): raise FileNotFoundError(rules_root)
    Handler.rules_root=rules_root; Handler.cases_path=cases_path
    server=ThreadingHTTPServer((host,port),Handler)
    print(f"SigmaForge Studio: http://{host}:{port}  (Ctrl+C to stop)")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStopping SigmaForge Studio.")
    finally: server.server_close()
