"use strict";
const flow={id:null,data:null,saved:null,draft:null,run:null,timer:null,dirty:false,busy:false,running:false,expanded:new Set(),categoryFilter:""};
const labels={pass:"조건 충족",fail:"조건 불일치",not_found:"경로 없음",unavailable:"접근 불가",inconclusive:"판단 보류",blocked:"선택 제외",manual_review:"코드 검토"};
const technicalCategories=new Set(["xss","sqli","path_traversal","open_redirect","command_injection","ssrf","template_injection","insecure_deserialization","xxe","file_upload","csrf","sensitive_data_exposure","security_misconfiguration","other_technical"]);
const categoryLabels={xss:"XSS",sqli:"SQL 인젝션",path_traversal:"경로 탐색",open_redirect:"오픈 리다이렉트",command_injection:"명령어 삽입",ssrf:"서버 측 요청 위조",template_injection:"템플릿 삽입",insecure_deserialization:"안전하지 않은 역직렬화",xxe:"XML 외부 개체",file_upload:"파일 업로드",csrf:"사이트 간 요청 위조",sensitive_data_exposure:"민감 정보 노출",security_misconfiguration:"보안 설정 오류",other_technical:"기타 기술 취약점",dependency_advisory:"취약 패키지 공지",manual_review:"수동 검토",manual:"수동 검토",uncategorized:"미분류"};
const scenarioCategory=item=>typeof item.category==="string"&&item.category.trim()?item.category.trim():"uncategorized";
const categoryLabel=category=>Object.prototype.hasOwnProperty.call(categoryLabels,category)?categoryLabels[category]:category.replaceAll("_"," ");
const scriptLabel=item=>item.script_mode==="offline"?"오프라인 검토 Python 스크립트 ↓":item.script_mode==="live_request"||item.script_mode==="live_get"||item.request?"선택 요청 Python 스크립트 ↓":"오프라인 검토 Python 스크립트 ↓";
const requestLabel=item=>{const request=item.request;if(!request)return "";
  const name=request.input_name||item.scenario?.input_name;
  const input=name?`${request.input_location==="body"?"JSON 본문":"쿼리"} ${name}`:"입력 없음";
  return `${request.method} ${request.path||item.scenario?.path||request.url} · ${input} · ${request.count||1}회 요청 · 후보 HTTP ${item.http_status??"응답 없음"}`;};
function focusCategoryAction(category,action){
  for(const button of document.querySelectorAll(".scenario-category-actions button")){
    if(button.dataset.category===category&&button.dataset.action===action){button.focus();break;}
  }
}
const resultLabel=item=>technicalCategories.has(item.scenario?.category)&&item.status==="fail"?"취약 동작 관찰":technicalCategories.has(item.scenario?.category)&&item.status==="pass"?"취약 동작 미관찰":labels[item.status]||item.status;
const clone=v=>JSON.parse(JSON.stringify(v));
function flowError(message){const box=$("#workflow-error");box.textContent=message||"";box.hidden=!message;}
function workflowStep(step){
  if(!state.result)return;
  for(const name of ["source","scenarios","runtime","remediation","report"])$("#workflow-"+name).hidden=name!==step;
  document.querySelectorAll("[data-workflow-step]").forEach(b=>b.classList.toggle("active",b.dataset.workflowStep===step));
  flowError("");$("#results").scrollIntoView({block:"start",behavior:"smooth"});
}
async function loadWorkflow(id){
  clearTimeout(flow.timer);
  flow.id=id;flow.data=await api(`/api/jobs/${id}/workflow`);flow.saved=clone(flow.data.selection);flow.draft=clone(flow.saved);flow.run=null;flow.dirty=false;flow.running=false;flow.expanded=new Set();flow.categoryFilter="";
  $("#runtime-summary").replaceChildren();$("#runtime-results").replaceChildren();$("#runtime-progress").hidden=true;
  $("#target-base-url").value=flow.draft.target_base_url;
  drawSelection();drawHistory();drawAudit();drawRemediation();drawReport();workflowStep("source");
  if(flow.data.runs.length)await openRun(flow.data.runs[0].id);
}
function drawSelection(){
  if(!flow.data)return;
  const scenarios=flow.data.scenarios,endpoints=flow.data.endpoint_options;
  const chosen=new Set(flow.draft.scenario_ids),allowed=new Set(flow.draft.endpoint_ids);
  const scenarioList=$("#scenario-list"),endpointList=$("#selection-endpoints"),scenarioScroll=scenarioList.scrollTop;
  scenarioList.replaceChildren();endpointList.replaceChildren();
  const groups=new Map();
  for(const item of scenarios){const category=scenarioCategory(item);if(!groups.has(category))groups.set(category,[]);groups.get(category).push(item);}
  const categoryFilter=$("#scenario-category-filter");
  if(flow.categoryFilter&&!groups.has(flow.categoryFilter))flow.categoryFilter="";
  categoryFilter.replaceChildren();const allOption=el("option","",`전체 카테고리 (${scenarios.length}개)`);allOption.value="";categoryFilter.append(allOption);
  for(const [category,items] of groups){const option=el("option","",`${categoryLabel(category)} (${items.length}개)`);option.value=category;categoryFilter.append(option);}
  categoryFilter.value=flow.categoryFilter;
  for(const [category,items] of groups){
    if(flow.categoryFilter&&category!==flow.categoryFilter)continue;
    const group=el("section","scenario-category"),heading=el("div","scenario-category-heading");
    group.setAttribute("aria-label",`${categoryLabel(category)} 시나리오`);
    const title=el("h5","",categoryLabel(category)),count=el("span","scenario-category-count",`${items.filter(item=>chosen.has(item.id)).length}/${items.length}개 선택`);
    const actions=el("div","scenario-category-actions"),selectAll=el("button","secondary","모두 선택"),clearAll=el("button","secondary","모두 해제");
    selectAll.type="button";clearAll.type="button";
    selectAll.dataset.category=category;selectAll.dataset.action="select";
    clearAll.dataset.category=category;clearAll.dataset.action="clear";
    selectAll.setAttribute("aria-label",`${categoryLabel(category)} 시나리오 모두 선택`);
    clearAll.setAttribute("aria-label",`${categoryLabel(category)} 시나리오 모두 해제`);
    selectAll.disabled=items.every(item=>chosen.has(item.id));clearAll.disabled=items.every(item=>!chosen.has(item.id));
    selectAll.addEventListener("click",()=>{for(const item of items)chosen.add(item.id);flow.draft.scenario_ids=[...chosen];flow.dirty=true;drawSelection();focusCategoryAction(category,"clear");});
    clearAll.addEventListener("click",()=>{for(const item of items)chosen.delete(item.id);flow.draft.scenario_ids=[...chosen];flow.dirty=true;drawSelection();focusCategoryAction(category,"select");});
    actions.append(selectAll,clearAll);heading.append(title,count,actions);group.append(heading);
    for(const item of items){
    const effective=item.endpoint_ids.every(id=>allowed.has(id));
    const container=el("div",`scenario-pick${chosen.has(item.id)&&!effective?" blocked":""}`);
    const row=el("label",`pick-row${chosen.has(item.id)&&!effective?" blocked":""}`),check=el("input");
    check.type="checkbox";check.checked=chosen.has(item.id);check.setAttribute("aria-label",item.title);
    check.addEventListener("change",()=>{if(check.checked)chosen.add(item.id);else chosen.delete(item.id);flow.draft.scenario_ids=[...chosen];flow.dirty=true;drawSelection();});
    const copy=el("span","pick-copy");copy.append(el("strong","",item.title),el("small","",`${item.method} ${item.path}`),el("small","",item.description));
    copy.append(el("em","",item.automatable?(effective?`기준·후보 ${item.method} 운영 검증`:chosen.has(item.id)?"엔드포인트 제외로 실행 차단":"선택 시 엔드포인트도 허용 필요"):"자동 요청 없음 · 오프라인 검토"));
    row.append(check,copy);container.append(row);
    const detail=el("details","scenario-detail");detail.open=flow.expanded.has(item.id);
    detail.addEventListener("toggle",()=>{if(detail.open)flow.expanded.add(item.id);else flow.expanded.delete(item.id);});
    detail.append(el("summary","","시나리오 근거와 검증 방법 자세히"));
    const explanation=el("div","scenario-explanation");
    const explainRows=[
      ["위험 가설",item.risk_hypothesis||item.description],
      ["코드에서 발견한 단서",item.source_trigger],
      ["검증 시 확인할 결과",item.verification_expectation||item.expected],
      ["자동 검증 범위와 이유",item.automation_rationale],
      ["아직 확정할 수 없는 점",item.uncertainty],
    ];
    for(const [heading,value] of explainRows){if(!value)continue;
      const block=el("section","scenario-explanation-block");block.append(el("h5","",heading),el("p","",value));explanation.append(block);}
    if(item.review_steps?.length){const block=el("section","scenario-explanation-block");block.append(el("h5","","확인 순서"));
      const steps=el("ol");for(const step of item.review_steps)steps.append(el("li","",step));block.append(steps);explanation.append(block);}
    if(item.source_evidence?.length){const block=el("section","scenario-explanation-block");block.append(el("h5","","소스 근거"));
      const locations=el("ul","scenario-evidence");for(const evidence of item.source_evidence){
        const entry=el("li");const open=el("button","source-location",`${evidence.file}:${evidence.line}${evidence.symbol?` · ${evidence.symbol}`:""}`);
        open.type="button";open.addEventListener("click",()=>openSource(evidence.file));entry.append(open);locations.append(entry);}
      block.append(locations);explanation.append(block);}
    if(item.disabled_reason)explanation.append(el("p","scenario-boundary",`자동 요청 제외: ${item.disabled_reason}`));
    detail.append(explanation);container.append(detail);group.append(container);
    }
    scenarioList.append(group);
  }
  if(!scenarios.length)scenarioList.append(el("p","empty-message","생성된 시나리오가 없습니다."));
  scenarioList.scrollTop=scenarioScroll;
  for(const item of endpoints){
    const row=el("label","pick-row endpoint-pick"),check=el("input");check.type="checkbox";check.checked=allowed.has(item.id);
    check.setAttribute("aria-label",`${item.method} ${item.path} 허용`);
    check.addEventListener("change",()=>{if(check.checked)allowed.add(item.id);else allowed.delete(item.id);flow.draft.endpoint_ids=[...allowed];flow.dirty=true;drawSelection();});
    const copy=el("span","pick-copy");copy.append(el("strong","",`${item.method} ${item.path}`),
      el("small","",item.scenario_ids.length?`${item.scenario_ids.length}개 연결 · ${item.automatable?"선택한 메서드·경로로 검증 가능":"자동 요청 없음"}`:"연결된 시나리오 없음"));
    if(item.disabled_reason)copy.append(el("em","",item.disabled_reason));row.append(check,copy);endpointList.append(row);
  }
  const selected=scenarios.filter(s=>chosen.has(s.id)),effective=selected.filter(s=>s.endpoint_ids.every(id=>allowed.has(id)));
  const auto=effective.filter(s=>s.automatable).length;
  $("#selection-summary").textContent=`선택 ${selected.length}개 · 자동 요청 후보 ${auto}개 · 오프라인 검토 ${effective.length-auto}개 · 엔드포인트 제외 ${selected.length-effective.length}개`;
  $("#scenario-count").textContent=`${scenarios.length}개`;$("#selection-endpoint-count").textContent=`${endpoints.length}개`;
  const audited=flow.data.dependency_audit;
  $("#scenario-audit-summary").textContent=audited?
    `OSV ${audited.status==="completed"?"조회 완료":audited.status==="partial"?"일부 미확인":"조회 실패"} · 공지 검토 시나리오 ${scenarios.filter(s=>s.category==="dependency_advisory").length}개`:
    "조회 버튼을 누르면 고정된 PyPI·npm·Maven·Packagist 이름과 버전이 OSV로 전송됩니다. 공지는 수동 검토 후보입니다.";
  $("#selection-revision").textContent=`저장 버전 ${flow.saved.revision}`;
  $("#selection-dirty").textContent=flow.dirty?"저장되지 않은 변경":"선택 범위 저장됨";
  $("#save-selection").disabled=flow.busy||!flow.dirty;$("#save-target").disabled=flow.busy||!flow.dirty;
  $("#run-validation").disabled=flow.busy||flow.running||flow.dirty||!selected.length;
  $("#run-readiness").textContent=flow.dirty?"선택과 서버 주소를 저장한 뒤 실행하세요.":
    selected.length?`저장된 ${selected.length}개 시나리오 중 ${auto}개가 자동 요청 후보입니다. 선택한 HTTP 메서드는 서버 상태를 바꿀 수 있으므로 테스트 환경과 요청 범위를 확인하세요.`:"시나리오를 먼저 선택하세요.";
  $("#save-message").textContent=flow.dirty?"선택 범위를 저장해야 운영 검증에 적용됩니다.":"저장한 선택 범위가 운영 검증에 적용됩니다.";
}
async function saveFlow(){
  if(!flow.data||flow.busy)return;
  flow.draft.target_base_url=$("#target-base-url").value.trim();flow.busy=true;drawSelection();
  try{const value=await api(`/api/jobs/${flow.id}/selection`,{method:"PUT",body:JSON.stringify(flow.draft)});
    flow.saved=clone(value);flow.draft=clone(value);flow.dirty=false;flowError("");toast("점검 범위를 저장했습니다.");}
  catch(error){flowError(error.message);}finally{flow.busy=false;drawSelection();drawReport();}
}
function drawHistory(){
  const box=$("#run-history");box.replaceChildren();const empty=el("option","","점검 이력 선택");empty.value="";box.append(empty);
  for(const run of flow.data.runs){const option=el("option","",`${time(run.created_at)} · ${run.state}`);option.value=run.id;box.append(option);}
}
function drawProgress(run){
  $("#runtime-progress").hidden=!["queued","running"].includes(run.state);
  $("#runtime-progress-label").textContent=run.stage;$("#runtime-progress-value").textContent=`${run.progress}%`;
  $("#runtime-progress-bar").value=run.progress;$("#runtime-progress-message").textContent=run.message;
}
async function openRun(id){
  if(!id)return;clearTimeout(flow.timer);
  const run=await api(`/api/jobs/${flow.id}/runs/${id}`);flow.run=run;$("#run-history").value=id;drawProgress(run);
  const entry=flow.data.runs.find(item=>item.id===id);if(entry){entry.state=run.state;drawHistory();$("#run-history").value=id;}
  flow.running=["queued","running"].includes(run.state);drawSelection();
  if(run.state==="completed"){drawRun();return;}
  if(["failed","interrupted"].includes(run.state)){flowError(run.message);return;}
  clearTimeout(flow.timer);flow.timer=setTimeout(()=>openRun(id).catch(e=>flowError(e.message)),1200);
}
async function executeFlow(){
  if(flow.busy||flow.running||flow.dirty||!flow.saved.scenario_ids.length)return;flow.busy=true;drawSelection();flowError("");
  try{const run=await api(`/api/jobs/${flow.id}/runs`,{method:"POST",body:JSON.stringify({selection_revision:flow.saved.revision})});
    flow.data.runs.unshift(run);flow.running=true;flow.run=null;$("#runtime-summary").replaceChildren();$("#runtime-results").replaceChildren();drawRemediation();drawReport();drawHistory();await openRun(run.id);}
  catch(error){flowError(error.message);}finally{flow.busy=false;drawSelection();}
}
function drawRun(){
  const run=flow.run;if(!run?.results)return;
  const summary=$("#runtime-summary"),list=$("#runtime-results");summary.replaceChildren();list.replaceChildren();
  const scriptGeneration=run.script_generation;
  if(scriptGeneration?.status==="completed")summary.append(el("p","script-generation-note","Python 점검 스크립트: AI가 시나리오에 맞춰 코드를 작성했고 앱이 문법·실행 범위를 검사했습니다. 오프라인 검토 항목은 운영 서버로 자동 요청하지 않았습니다."));
  else if(scriptGeneration?.status==="failed")summary.append(el("p","script-generation-note failed",`Python 재검증 스크립트 생성 실패: ${scriptGeneration.message||"모델 응답 또는 코드 검증 오류"}. 운영 관찰 결과는 그대로 저장됐습니다.`));
  for(const [kind,count] of Object.entries(run.counts||{}))if(count){
    const matching=run.results.filter(item=>item.status===kind);
    const label=matching.length&&matching.every(item=>technicalCategories.has(item.scenario?.category))&&["fail","pass"].includes(kind)?
      resultLabel(matching[0]):labels[kind]||kind;
    summary.append(el("span",`status-badge ${kind}`,`${label} ${count}`));
  }
  for(const item of run.results){
    const card=el("article","run-row");card.append(el("strong","",item.scenario.title),
      el("span",`status-badge ${item.status}`,resultLabel(item)),el("p","",item.summary));
    if(item.request)card.append(el("small","",requestLabel(item)));
    if(item.script_available){const script=el("a","secondary scenario-script",scriptLabel(item));
      script.href=`/api/jobs/${flow.id}/runs/${run.id}/download/script?scenario_id=${encodeURIComponent(item.scenario.id)}`;
      card.append(script);}
    else if(item.status==="manual_review")card.append(el("small","","자동 요청은 없었으며 검증된 오프라인 스크립트도 제공되지 않았습니다."));
    else if(item.status==="blocked")card.append(el("small","","선택 범위에서 제외되어 요청 스크립트를 생성하지 않았습니다."));
    if(item.evidence?.baseline&&item.evidence?.candidate){const details=el("details");details.append(el("summary","","기준값·후보값 응답"));
      for(const [label,record] of [["기준값",item.evidence.baseline],["후보값",item.evidence.candidate]]){
        details.append(el("p","",`${label}: HTTP ${record.status_code??"응답 없음"}${record.error?` · ${record.error}`:""}`));
        for(const [key,value] of Object.entries(record.headers||{}))if(value)details.append(el("p","",`${label} ${key}: ${value}`));}
      card.append(details);}
    else if(item.evidence?.headers){const details=el("details");details.append(el("summary","","관찰한 응답 헤더"));
      for(const [key,value] of Object.entries(item.evidence.headers))details.append(el("p","",`${key}: ${value||"없음"}`));card.append(details);}
    list.append(card);
  }
  drawRemediation();drawReport();
}
function diffViewer(patch){
  const wrapper=el("section","patch-preview");
  const file=patch.file||"파일 위치 확인 필요";
  wrapper.append(el("h5","",`${file}${patch.start_line?`:${patch.start_line}`:""}`));
  if(patch.applicability){const label={review_required:"AI가 분석 시점 소스를 기준으로 제안한 수정 · 적용 전 검토 필요",manual_review:"AI 수정안의 위치 또는 안전성을 확인하지 못함"}[patch.applicability]||patch.applicability;
    wrapper.append(el("p","patch-applicability",label));}
  if(!patch.diff){wrapper.append(el("p","patch-reason",patch.reason||"수정 위치를 확정할 근거가 없어 자동 diff를 만들지 않았습니다."));return wrapper;}
  wrapper.append(el("p","diff-legend","왼쪽: 원본 줄 · 오른쪽: 수정 줄 · 빨강: 삭제 · 초록: 추가"));
  const grid=el("div","diff-view");grid.setAttribute("role","table");grid.setAttribute("aria-label",`${file} 수정 제안`);
  const header=el("div","diff-line diff-header");header.setAttribute("role","row");
  for(const name of ["원본","수정","변경 내용"]){const cell=el("span",name==="변경 내용"?"diff-code":"diff-number",name);cell.setAttribute("role","columnheader");header.append(cell);}grid.append(header);
  let oldLine=Number(patch.start_line)||1,newLine=Number(patch.start_line)||1;
  const lines=patch.diff.split(/\r?\n/);if(lines.at(-1)==="")lines.pop();
  for(const line of lines){
    const hunk=/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if(hunk){oldLine=Number(hunk[1]);newLine=Number(hunk[2]);}
    const kind=hunk||line.startsWith("@@")?"hunk":line.startsWith("--- ")||line.startsWith("+++ ")||line.startsWith("diff ")||line.startsWith("\\ No newline")?"meta":line.startsWith("-")?"removed":line.startsWith("+")?"added":"context";
    const row=el("div",`diff-line ${kind}`);row.setAttribute("role","row");
    const before=el("span","diff-number",kind==="removed"||kind==="context"?String(oldLine):"");
    const after=el("span","diff-number",kind==="added"||kind==="context"?String(newLine):"");
    const code=el("span","diff-code",line||" ");
    before.setAttribute("role","cell");after.setAttribute("role","cell");code.setAttribute("role","cell");
    row.append(before,after,code);grid.append(row);
    if(kind==="removed"||kind==="context")oldLine++;
    if(kind==="added"||kind==="context")newLine++;
  }
  wrapper.append(grid);
  if(patch.reason)wrapper.append(el("p","patch-reason",patch.reason));
  return wrapper;
}
function drawRemediation(){
  const box=$("#remediation-list");box.replaceChildren();
  if(!flow.run?.results){box.append(el("p","empty-message","운영 검증 뒤 조치방안을 볼 수 있습니다."));return;}
  const actionable=flow.run.results.filter(item=>!['pass','blocked'].includes(item.status));
  if(!actionable.length){box.append(el("p","empty-message","이번 점검에서 조치 또는 추가 코드 검토가 필요한 항목이 없습니다."));return;}
  for(const item of actionable){
    const card=el("article","remediation-card");card.append(el("span",`status-badge ${item.status}`,resultLabel(item)),
      el("h4","",item.scenario.title),el("p","",item.remediation.summary),
      el("p","source-locations",(item.scenario.source_evidence||[]).map(e=>`${e.file}:${e.line}`).join(" · ")));
    const steps=el("ol");for(const text of item.remediation.steps||[])steps.append(el("li","",text));card.append(steps);
    const patches=Array.isArray(item.patches)?item.patches:item.patch?[item.patch]:item.remediation.patch?[item.remediation.patch]:[];
    if(patches.length){for(const patch of patches)card.append(diffViewer(patch));}
    else if(item.remediation.code_suggestion){const details=el("details");details.append(el("summary","","코드 수정 예시 · 위치 검토 필요"),
      el("small","",item.remediation.code_suggestion.file),el("pre","",item.remediation.code_suggestion.content));card.append(details);}
    else card.append(el("p","patch-reason","이 항목은 수정 위치가 확정되지 않아 diff가 없습니다. 위 코드 근거와 확인 순서를 먼저 검토하세요."));
    if(item.script_available){const script=el("a","secondary scenario-script",scriptLabel(item));
      script.href=`/api/jobs/${flow.id}/runs/${flow.run.id}/download/script?scenario_id=${encodeURIComponent(item.scenario.id)}`;card.append(script);}
    box.append(card);
  }
}
function drawReport(){
  const overview=$("#report-overview"),downloads=$("#report-downloads"),scope=$("#report-scope");
  overview.replaceChildren();downloads.replaceChildren();scope.replaceChildren();if(!flow.data)return;
  overview.append(el("p","",`소스 분석 ${state.result?.counts?.total??0}개 경로 · 저장된 시나리오 ${flow.saved.scenario_ids.length}개 · 대상 ${flow.saved.target_base_url}`));
  const source=el("a","secondary","소스 분석 JSON ↓");source.href=`/api/jobs/${flow.id}/download/json`;downloads.append(source);
  if(flow.run?.results){
    for(const [kind,label] of [["json","운영 결과 JSON ↓"],["report","통합 보고서 ↓"],["script","선택 시나리오 Python 스크립트 ↓"],["policy","적용 범위 ↓"]]){
      if(kind==="script"&&!flow.run.results.some(item=>item.script_available))continue;
      const link=el("a","secondary",label);link.href=`/api/jobs/${flow.id}/runs/${flow.run.id}/download/${kind}`;downloads.append(link);}
    if(flow.run.script_generation?.status==="completed")scope.append(el("p","script-generation-note","AI가 선택한 시나리오의 Python 점검 코드를 작성했고 앱이 검증했습니다. 내려받은 파일을 직접 실행할 때는 OpenShell 정책이 적용되지 않으며 요청 메서드에 따라 서버 상태가 바뀔 수 있습니다."));
    else if(flow.run.script_generation?.status==="failed")scope.append(el("p","script-generation-note failed",`AI 판정 코드 생성 실패: ${flow.run.script_generation.message||"모델 응답 또는 코드 검증 오류"}. Python 스크립트 다운로드는 제공되지 않습니다.`));
    const actualRequests=[...new Set(flow.run.results.filter(item=>item.request).map(item=>`${item.request.method||item.scenario?.method||"?"} ${item.request.path||item.scenario?.path||"?"}`))];
    scope.append(el("h4","","실제 허용한 요청"),el("p","",`${flow.run.target_base_url} · ${actualRequests.join(", ")||"요청 없음"}`),
      el("p","",`점검 ID ${flow.run.id} · 선택 버전 ${flow.run.selection.revision} · 임시 정책 ${flow.run.scope.policy_applied?"적용":"요청 없음"} · 복원 ${flow.run.scope.policy_restored?"확인":"기록 없음"}`));
  }else scope.append(el("p","","운영 검증 후 실제 허용 경로, 응답 결과와 조치방안이 저장됩니다."));
}
function drawAudit(){
  const box=$("#audit-results");box.replaceChildren();const data=flow.data?.dependency_audit;
  if(!data){box.append(el("p","subtle","아직 조회하지 않았습니다."));return;}
  const state={completed:"조회 완료",partial:"일부 미확인",failed:"조회 실패"}[data.status]||data.status;
  box.append(el("p","",`${state} · ${data.message}`));
  for(const row of data.packages||[]){const item=el("p","",`${row.name}==${row.version} · ${row.status==="advisories_found"?"공지 있음":row.status==="no_known_advisories"?"조회된 알려진 공지 없음 (안전성 보증 아님)":"미확인"} · ${(row.source_files||[]).join(", ")}`);
    for(const advisory of row.advisories||[]){const link=el("a","audit-link",advisory.id);link.href=advisory.url;link.target="_blank";link.rel="noopener noreferrer";item.append(" ",link);}box.append(item);}
  if(data.unresolved?.length)box.append(el("p","subtle",`${data.unresolved.length}개 항목은 조회하지 않았습니다.`));
}
async function auditFlow(){
  const buttons=[$("#audit-package"),$("#audit-scenarios")];
  const labels=buttons.map(button=>button.textContent);buttons.forEach(button=>{button.disabled=true;button.textContent="조회 중…";});
  try{flow.data.dependency_audit=await api(`/api/jobs/${flow.id}/dependency-audit`,{method:"POST"});
    const refreshed=await api(`/api/jobs/${flow.id}/workflow`);
    flow.data.scenarios=refreshed.scenarios;flow.data.endpoint_options=refreshed.endpoint_options;
    const available=new Set(refreshed.scenarios.map(s=>s.id));
    const retained=flow.draft.scenario_ids.filter(id=>available.has(id));
    if(retained.length!==flow.draft.scenario_ids.length){flow.draft.scenario_ids=retained;flow.dirty=true;}
    if(flow.run?.results)flow.run.dependency_audit=flow.data.dependency_audit;
    drawSelection();drawAudit();drawReport();toast("패키지 공지 조회를 기록했습니다.");}
  catch(error){flowError(error.message);}finally{buttons.forEach((button,index)=>{button.disabled=false;button.textContent=labels[index];});}
}
document.querySelectorAll("[data-workflow-step]").forEach(button=>button.addEventListener("click",()=>workflowStep(button.dataset.workflowStep)));
$("#select-automatic").addEventListener("click",()=>{flow.draft.scenario_ids=flow.data.scenarios.filter(s=>s.automatable).map(s=>s.id);
  flow.draft.endpoint_ids=[...new Set(flow.data.scenarios.filter(s=>s.automatable).flatMap(s=>s.endpoint_ids))];flow.dirty=true;drawSelection();});
$("#clear-scenarios").addEventListener("click",()=>{flow.draft.scenario_ids=[];flow.dirty=true;drawSelection();});
$("#scenario-category-filter").addEventListener("change",event=>{flow.categoryFilter=event.target.value;drawSelection();$("#scenario-list").scrollTop=0;});
$("#target-base-url").addEventListener("input",()=>{flow.draft.target_base_url=$("#target-base-url").value;flow.dirty=true;drawSelection();});
$("#save-selection").addEventListener("click",saveFlow);$("#save-target").addEventListener("click",saveFlow);
$("#run-validation").addEventListener("click",executeFlow);
$("#run-history").addEventListener("change",event=>openRun(event.target.value).catch(e=>flowError(e.message)));
$("#audit-package").addEventListener("click",auditFlow);
$("#audit-scenarios").addEventListener("click",auditFlow);
