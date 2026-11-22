let rules=[],selected=null,queryText="";
const $=id=>document.getElementById(id);
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function get(path){const r=await fetch(path,{cache:"no-store"});if(!r.ok)throw new Error(`HTTP ${r.status}`);return r.json();}
function level(v){const x=String(v||"low").toLowerCase();return `<span class="pill level-${esc(x)}">${esc(x)}</span>`;}
async function refresh(){
  try{
    const [overview,ruleData,tests]=await Promise.all([get("/api/overview"),get("/api/rules"),get("/api/tests")]);
    rules=ruleData;
    $("total").textContent=overview.rules;
    $("valid").textContent=overview.valid;
    $("techniques").textContent=Object.keys(overview.techniques||{}).length;
    const t=overview.tests||{};
    $("passrate").textContent=t.total?`${Math.round(t.passed/t.total*100)}%`:"—";
    $("testsub").textContent=`${t.passed||0}/${t.total||0} regression cases passed`;
    $("rule-count").textContent=`${rules.length} rules`;
    $("test-count").textContent=`${tests.length} cases`;
    $("test-list").innerHTML=tests.map(t=>`<div class="test-row"><span>${esc(t.name)}</span><b class="${t.pass?"pass":"fail"}">${t.pass?"PASS":"FAIL"}</b></div>`).join("")||`<div class="empty">No regression cases found.</div>`;
    renderRules();
    if(selected){const same=rules.find(r=>r.id===selected.id);if(same)selectRule(same,false);}
  }catch(e){$("rule-list").innerHTML=`<div class="empty">Unable to load rule data: ${esc(e.message)}</div>`;}
}
function renderRules(){
  const q=$("search").value.toLowerCase();
  const list=rules.filter(r=>`${r.title} ${r.id} ${(r.tags||[]).join(" ")}`.toLowerCase().includes(q));
  $("rule-list").innerHTML=list.map(r=>`<button class="rule ${selected&&selected.id===r.id?"selected":""}" onclick="pickRule('${esc(r.id)}')">
    <div class="rule-title">${esc(r.title)}</div><div class="rule-meta">${level(r.level)}<span class="rule-id">${esc(r.id.slice(0,8))}</span><span class="${r.errors.length?"invalid":"valid"}">${r.errors.length?"INVALID":"VALID"}</span></div></button>`).join("")||`<div class="empty">No rules match your search.</div>`;
}
function pickRule(id){const rule=rules.find(r=>r.id===id);if(rule)selectRule(rule,true);}
async function selectRule(rule,compile=true){
  selected=rule;$("detail-title").textContent=rule.title;
  const tags=(rule.tags||[]).map(t=>`<span class="tech">${esc(t)}</span>`).join("");
  $("detail").innerHTML=`<p class="description">${esc(rule.description)}</p>
    <div class="meta-grid"><div class="meta-box"><small>Rule status</small><span>${esc(rule.status)}</span></div>
    <div class="meta-box"><small>Severity</small><span>${level(rule.level)}</span></div>
    <div class="meta-box"><small>Log source</small><span>${esc(JSON.stringify(rule.logsource))}</span></div>
    <div class="meta-box"><small>Validation</small><span class="${rule.errors.length?"invalid":"valid"}">${rule.errors.length?esc(rule.errors.join("; ")):"No validation errors"}</span></div></div>
    <div class="rule-id">${esc(rule.id)} · ${esc(rule.path)}</div><div class="tags">${tags}</div>
    ${rule.warnings.length?`<p class="description">Warnings: ${esc(rule.warnings.join("; "))}</p>`:""}`;
  renderRules(); if(compile)await compileSelected();
}
async function compileSelected(){
  if(!selected)return;
  $("query").textContent="Compiling…";
  try{const backend=$("backend").value;const result=await get(`/api/compile?id=${encodeURIComponent(selected.id)}&backend=${backend}`);$("query").textContent=result.query||result.error;}
  catch(e){$("query").textContent=`Compilation failed: ${e.message}`;}
}
async function copyQuery(){try{await navigator.clipboard.writeText($("query").textContent);$("query").dataset.copied="true";}catch(e){alert("Clipboard unavailable in this browser context.");}}
$("backend").addEventListener("change",compileSelected);
refresh();
