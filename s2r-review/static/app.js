"use strict";
const $ = selector => document.querySelector(selector);
const state = {config: null, result: null, selected: null, activeJob: null, polling: null};
const authLabels = {authenticated: "인증 검사 발견", role_check_detected: "역할 검사 발견", ownership_check_detected: "소유권 검사 발견", needs_review: "인증 여부 확인 필요", no_auth_dependency_detected: "인증 의존성 미발견"};
const jobLabels = {queued: "대기", running: "진행 중", completed: "완료", failed: "실패", interrupted: "중단"};
const stageLabels = {snapshot: "소스 범위 확인", boundary: "접근 경계 검증", snapshot_upload: "소스 연결 준비", manifest_upload: "소스 목록 전달", analyzing: "엔드포인트·취약점 분석", saving: "결과 저장", completed: "분석 완료", queued: "분석 준비"};
function el(tag, className, text) { const node = document.createElement(tag); if(className) node.className = className; if(text !== undefined) node.textContent = text; return node; }
function time(value) { return new Date(value).toLocaleString("ko-KR", {month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"}); }
async function api(path, options = {}) {
  const headers = {Accept:"application/json"};
  if(options.method) { headers["Content-Type"] = "application/json"; headers["X-S2R-Token"] = state.config?.token || ""; }
  const response = await fetch(path, {...options, headers});
  const result = await response.json();
  if(!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "요청을 처리하지 못했습니다.");
  return result;
}
let toastTimer;
function toast(message) { $("#toast").textContent = message; $("#toast").hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $("#toast").hidden = true; }, 4000); }
function projectPath() { const project = state.config.projects.find(row => row.id === $("#project-select").value); $("#project-path").textContent = project?.path || ""; $("#project-path").title = project?.path || ""; }
async function loadConfig(selected) {
  state.config = await api("/api/config");
  $("#project-select").replaceChildren(...state.config.projects.map(project => { const option = el("option", "", project.name); option.value = project.id; return option; }));
  if(selected) $("#project-select").value = selected;
  projectPath();
}
function screen(name) {
  $("#analysis-screen").hidden = name !== "analysis"; $("#history-screen").hidden = name !== "history";
  $("#nav-analysis").classList.toggle("active", name === "analysis"); $("#nav-history").classList.toggle("active", name === "history");
  $("#top-title").textContent = name === "analysis" ? "소스 분석" : "분석 이력";
  if(name === "history") loadHistory();
}
function busy(value) { $("#run-analysis").disabled = value; $("#choose-folder").disabled = value; $("#project-select").disabled = value; }
function showProgress(job) {
  $("#progress-panel").hidden = false;
  $("#progress-label").textContent = stageLabels[job.stage] || "분석 상태";
  $("#progress-value").textContent = `${job.progress}%`;
  $("#progress").value = job.progress;
  $("#progress-message").textContent = job.message;
}
async function pollJob(id) {
  try {
    const job = await api(`/api/jobs/${id}`);
    if(state.activeJob !== id) return;
    showProgress(job);
    if(job.state === "completed") {
      state.activeJob = null; busy(false);
      await openResult(id);
      toast(job.message);
    } else if(["failed", "interrupted"].includes(job.state)) {
      state.activeJob = null; busy(false);
      $("#error-panel").textContent = job.message; $("#error-panel").hidden = false;
    } else { state.polling = setTimeout(() => pollJob(id), 1200); }
  } catch(error) {
    busy(false); state.activeJob = null;
    $("#error-panel").textContent = `상태 확인 연결이 끊겼습니다. 분석 이력에서 결과를 확인하세요. ${error.message}`; $("#error-panel").hidden = false;
  }
}
async function runAnalysis() {
  busy(true); $("#error-panel").hidden = true; $("#results").hidden = true; $("#empty-state").hidden = true;
  try {
    const job = await api("/api/jobs", {method:"POST", body:JSON.stringify({project_id:$("#project-select").value, ai:true})});
    state.activeJob = job.id; showProgress(job); pollJob(job.id);
  } catch(error) { busy(false); $("#error-panel").textContent = error.message; $("#error-panel").hidden = false; }
}
async function openResult(id) {
  const result = await api(`/api/jobs/${id}/result`);
  state.result = result; state.selected = result.endpoints[0]?.id;
  $("#empty-state").hidden = true; $("#results").hidden = false; $("#error-panel").hidden = true;
  $("#result-title").textContent = `${result.project.name} 분석 결과`;
  $("#result-meta").textContent = `${time(result.created_at)} · 소스 ${result.source_hash.slice(0,12)} · ${result.counts.files}개 파일`;
  $("#count-total").textContent = result.counts.total; $("#count-default").textContent = result.counts.unconditional; $("#count-conditional").textContent = result.counts.conditional;
  $("#boundary-result").textContent = result.boundary.passed ? "확인 완료" : "확인 실패";
  $("#source-unchanged").textContent = result.source_unchanged ? "분석 전후 원본 내용 동일" : "분석 중 원본 변경 감지";
  $("#download-json").href = `/api/jobs/${id}/download/json`; $("#download-report").href = `/api/jobs/${id}/download/report`;
  const aiAnalysis = result.analysis_mode === "ai";
  const legacyExplanation = !aiAnalysis && result.ai.status === "completed";
  $("#ai-state").textContent = aiAnalysis ? "AI 엔드포인트·시나리오" : legacyExplanation ? "기존 기록 · AI 설명" : result.ai.status === "failed" ? "기존 기록 · AI 설명 실패" : "규칙 기반 분석";
  $("#project-summary").textContent = result.ai.project_summary || (result.ai.status === "failed" ? `${result.ai.message} (${result.ai.error})` : aiAnalysis ? "AI가 제안한 엔드포인트와 취약점 시나리오의 코드 근거를 확인하세요." : "규칙 기반 분석 결과입니다. 엔드포인트와 시나리오의 코드 근거를 확인하세요.");
  $("#analysis-note").textContent = aiAnalysis ? "AI가 식별한 경로와 취약점 가설은 소스 근거에 연결된 후보입니다. 실제 배포 환경의 동작을 확인한 결과가 아닙니다." : "소스 분석 결과는 실제 배포 환경의 동작을 확인한 결과가 아닙니다.";
  $("#ai-notes").replaceChildren(...(result.ai.review_notes || []).map(note => el("li", "", note)));
  $("#ai-notes-box").hidden = !(result.ai.review_notes || []).length;
  $("#endpoint-search").value = ""; $("#method-filter").value = "";
  renderScope(); renderManifests(); resultTab("endpoints"); renderEndpoints(); screen("analysis");
  try { await loadWorkflow(id); } catch(error) { $("#workflow-error").textContent=error.message; $("#workflow-error").hidden=false; }
}
function resultTab(name) {
  for(const item of ["endpoints", "scope", "dependencies"]) $(`#${item}-tab`).hidden = name !== item;
  document.querySelectorAll("[data-result-tab]").forEach(button => button.classList.toggle("active", button.dataset.resultTab === name));
}
function renderEndpoints() {
  if(!state.result) return;
  const query = $("#endpoint-search").value.toLowerCase(), method = $("#method-filter").value;
  const endpoints = state.result.endpoints.filter(row => (!method || row.method === method) && `${row.path} ${row.handler.symbol} ${row.framework || ""}`.toLowerCase().includes(query));
  if(!endpoints.some(row => row.id === state.selected)) state.selected = endpoints[0]?.id;
  $("#visible-count").textContent = `${endpoints.length}개 표시`;
  $("#endpoint-list").replaceChildren();
  for(const endpoint of endpoints) {
    const row = el("button", `endpoint-row${state.selected === endpoint.id ? " active" : ""}`);
    row.setAttribute("aria-label", `${endpoint.method} ${endpoint.path}`);
    row.setAttribute("aria-pressed", String(state.selected === endpoint.id));
    const line = el("div", "route-line"); line.append(el("span", `method ${endpoint.method}`, endpoint.method), el("code", "", endpoint.path));
    row.append(line, el("small", "", `${endpoint.framework || state.result.framework} · ${endpoint.handler.symbol} · ${authLabels[endpoint.auth] || endpoint.auth}`));
    if(endpoint.conditions.length) row.append(el("span", "conditional-label", "조건부 등록 · 실행 설정 확인 필요"));
    row.addEventListener("click", () => { state.selected = endpoint.id; renderEndpoints(); });
    $("#endpoint-list").append(row);
  }
  if(!endpoints.length) $("#endpoint-list").append(el("p", "empty-message", "일치하는 엔드포인트가 없습니다."));
  renderDetail(state.result.endpoints.find(row => row.id === state.selected));
}
function section(title) { const box = el("section", "detail-section"); box.append(el("h4", "", title)); return box; }
function pairs(items) { const list = el("dl", "meta-pairs"); for(const [key, value] of items) list.append(el("dt", "", key), el("dd", "", value)); return list; }
function renderDetail(endpoint) {
  const target = $("#endpoint-detail"); target.replaceChildren();
  if(!endpoint) { target.append(el("p", "empty-message", "엔드포인트를 선택하세요.")); return; }
  target.append(el("span", `method ${endpoint.method}`, endpoint.method), el("h3", "", endpoint.path));
  const summary = (state.result.ai.endpoints || []).find(row => row.id === endpoint.id)?.summary;
  target.append(el("p", "description", summary || `${endpoint.handler.symbol} 함수의 코드 근거를 확인하세요. 실행 환경의 동작은 아직 확인하지 않았습니다.`));
  target.append(pairs([
    ["프레임워크", endpoint.framework || state.result.framework],
    ["처리 함수", `${endpoint.handler.symbol}()`], ["코드 위치", `${endpoint.handler.file}:${endpoint.handler.line}`],
    ["인증·권한", authLabels[endpoint.auth] || endpoint.auth],
    ["등록 조건", endpoint.conditions.join(" 그리고 ") || "코드상 조건 없음"],
    ["기본값 추정", endpoint.conditions.length ? (endpoint.default_enabled === false ? "설정 클래스 기본값 기준 비활성" : "확인 필요") : "해당 없음"],
    ["실행 상태", "미확인 · 웹사이트 요청 없음"],
    ["상태 변경", endpoint.effects.database_write_detected ? "DB 쓰기 호출 발견" : endpoint.effects.session_change_detected ? "세션 변경 호출 발견" : endpoint.effects.assessment === "no_write_detected" ? "쓰기 호출 미발견 · 안전성 확정 아님" : "상태 변경 여부 확인 필요"]
  ]));
  const inputs = section("입력값과 제약 조건");
  const table = el("table", "param-table"), head = el("tr"); for(const label of ["위치", "이름 / 형식", "제약"]) head.append(el("th", "", label)); table.append(head);
  for(const input of endpoint.inputs) {
    const rows = input.fields ? input.fields.map(field => ({...field, in:"body"})) : [input];
    for(const field of rows) { const row = el("tr"); row.append(el("td", "", field.in), el("td", "", `${field.name} : ${field.type}`), el("td", "", [field.required ? "필수" : "선택", ...Object.entries(field.constraints || {}).map(([k,v]) => `${k}=${v}`)].join(" · "))); table.append(row); }
  }
  inputs.append(endpoint.inputs.length ? table : el("p", "subtle", "추출된 요청 파라미터 없음. 인증 헤더는 의존성 근거를 확인하세요.")); target.append(inputs);
  const guards = section("권한 검사 근거");
  if(!endpoint.guards.length) guards.append(el("p", "subtle", "표시된 코드에서 권한 검사 근거가 확인되지 않았습니다. 실제 인증 경계는 별도 확인이 필요합니다."));
  else {
    const chips = el("div", "detail-chips");
    for(const guard of endpoint.guards) chips.append(el("span", "", `${guard.kind} · ${guard.symbol}:${guard.line}`));
    guards.append(chips, el("p", "subtle", "검사 코드가 존재한다는 근거입니다. 올바르게 적용된다는 완전한 증명은 아닙니다."));
  }
  target.append(guards);
  const chain = section("엔드포인트 코드 근거");
  for(const evidence of endpoint.call_chain) {
    const details = el("details", "evidence");
    const summaryNode = el("summary", "", `${evidence.symbol}() · ${evidence.reason}`);
    summaryNode.append(el("small", "", `${evidence.file}:${evidence.line}`));
    details.append(summaryNode, el("pre", "", evidence.snippet));
    const open = el("button", "", "분석 시점 파일 전체 보기 ↗"); open.addEventListener("click", () => openSource(evidence.file)); details.append(open); chain.append(details);
  }
  target.append(chain);
}
async function openSource(file) {
  try {
    const result = await api(`/api/jobs/${state.result.id}/source?file=${encodeURIComponent(file)}`);
    $("#source-title").textContent = file;
    $("#source-content").textContent = result.content.split("\n").map((line,index) => `${String(index + 1).padStart(4)}  ${line}`).join("\n");
    $("#source-dialog").showModal();
  } catch(error) { toast(error.message); }
}
function renderScope() {
  const result = state.result, target = $("#scope-tab"); target.replaceChildren(el("h3", "", "실제 실행 경계"));
  const mounted = result.scope?.originals_mounted === true;
  target.append(pairs([["샌드박스", result.sandbox], ["입력 쓰기 차단", String(result.boundary.input_write_denied)], ["범위 밖 읽기 차단", String(result.boundary.outside_read_denied)], ["출력 쓰기 허용", String(result.boundary.output_write_allowed)], ["원본 접근", mounted ? "선별한 원본 파일을 각각 읽기 전용 마운트 · OpenShell은 /source만 허용" : "호스트가 읽기 전용 복사본 준비 · 분석 프로세스에는 원본 미마운트"], ["소스 SHA-256", result.source_hash], ["해시 범위", result.source_hash_scope]]));
  if(mounted) target.append(pairs([["허용 파일 읽기", String(result.boundary.source_read_allowed)], ["정책 밖 경로 읽기 차단", String(result.boundary.source_unselected_read_denied)], ["원본 쓰기 차단", String(result.boundary.source_write_denied)]]));
  const syntax = result.analysis_mode === "ai" ? result.ai?.syntax_assist : null;
  if(syntax) {
    const statusLabels = {completed:"수집 완료", partial:"일부 수집", failed:"수집 실패", unavailable:"사용 불가", skipped:"건너뜀", disabled:"비활성", parser_unavailable:"구문 파서 없음", no_supported_files:"해당 언어 파일 없음", no_visible_facts:"표시된 구조 단서 없음", no_visible_python_facts:"표시된 Python 구조 단서 없음"};
    const count = value => Number.isSafeInteger(value) && value >= 0 ? `${value}개` : "기록 없음";
    target.append(el("h3", "", "AI 분석의 구문 구조 보조"));
    target.append(el("p", "subtle", "Python AST와 Tree-sitter 구문 트리에서 함수·라우트 선언 등의 구조 단서를 뽑아 AI 분석에 참고시켰습니다. 엔드포인트와 취약점 시나리오는 AI가 소스와 단서를 함께 읽고 제안합니다."));
    for(const [key, label] of [["python_ast", "Python AST"], ["tree_sitter", "Tree-sitter 구문 트리"]]) {
      const item = syntax[key]; if(!item) continue;
      target.append(el("h4", "", label));
      target.append(pairs([
        ["수집 상태", statusLabels[item.status] || String(item.status || "기록 없음")],
        ["파일 처리", `파싱 ${count(item.files_parsed)} · 실패 ${count(item.files_failed)} · 건너뜀 ${count(item.files_skipped)}${item.files_limited ? ` · 처리 한도 ${count(item.files_limited)}` : ""}`],
        ["구조 단서", `모델 입력에 포함 ${count(item.facts_included)} · 제외 ${count(item.facts_omitted)}`]
      ]));
      if(Array.isArray(item.diagnostics) && item.diagnostics.length) {
        const details = el("details", "file-card"); details.append(el("summary", "", `${label} 확인 사항 ${item.diagnostics.length}건`));
        const notes = el("ul", "");
        for(const diagnostic of item.diagnostics.slice(0, 10)) {
          notes.append(el("li", "", typeof diagnostic === "string" ? diagnostic : [diagnostic.file, diagnostic.message || diagnostic.reason].filter(Boolean).join(" · ")));
        }
        if(item.diagnostics.length > 10) notes.append(el("li", "", `나머지 ${item.diagnostics.length - 10}건은 결과 JSON에서 확인하세요.`));
        details.append(notes); target.append(details);
      }
    }
    target.append(el("p", "subtle", "이 수치는 선택·파싱한 파일의 구조 단서 수집 기록입니다. 전체 프로젝트 커버리지나 라우트 등록·취약점 존재의 증명이 아닙니다. 파싱 실패 또는 입력 길이 제한으로 빠진 단서가 있을 수 있습니다."));
  }
  target.append(el("h3", "", "분석의 한계"));
  const limits = el("ul"); result.limitations.forEach(item => limits.append(el("li", "", item))); target.append(limits);
  target.append(el("h3", "", `확인 사항 ${result.diagnostics.length}건`));
  const notes = el("ul"); result.diagnostics.forEach(item => notes.append(el("li", "", `${item.file || ""}${item.line ? ":" + item.line : ""} ${item.message}`))); target.append(notes);
  if(result.skipped_files.length) { target.append(el("h3", "", "제외된 파일")); const skipped = el("ul"); result.skipped_files.forEach(item => skipped.append(el("li", "", `${item.file} · ${item.reason}`))); target.append(skipped); }
}
function renderManifests() {
  const target = $("#dependencies-tab"); target.replaceChildren(el("h3", "", "패키지 선언 파일"), el("p", "", "선택된 소스에서 읽은 파일입니다. 최신 CVE 데이터 조회와 실제 영향 판단은 이번 분석에 포함되지 않았습니다."));
  for(const item of state.result.manifests) { const box = el("details", "file-card"); box.append(el("summary", "", item.file), el("pre", "", item.content)); target.append(box); }
}
async function loadHistory() {
  try {
    const result = await api("/api/jobs"); $("#history-list").replaceChildren();
    if(!result.items.length) $("#history-list").append(el("p", "empty-message", "아직 분석 이력이 없습니다."));
    for(const job of result.items) {
      const row = el("button", "history-card"), info = el("div");
      info.append(el("strong", "", job.project.name), el("p", "", `${time(job.created_at)} · ${job.counts ? job.counts.total + "개 엔드포인트" : job.message}`));
      const label = job.state === "completed" && job.ai_status === "failed" ? "기존 기록 · AI 설명 실패" : jobLabels[job.state] || job.state;
      row.append(info, el("span", "", `${label} ↗`));
      row.addEventListener("click", async () => {
        if(job.state === "completed") { $("#progress-panel").hidden = true; try { await openResult(job.id); } catch(error) { toast(error.message); } }
        else if(["running", "queued"].includes(job.state)) { screen("analysis"); state.activeJob = job.id; clearTimeout(state.polling); busy(true); pollJob(job.id); }
        else toast(job.message);
      }); $("#history-list").append(row);
    }
  } catch(error) { toast(error.message); }
}
$("#project-select").addEventListener("change", projectPath);
$("#run-analysis").addEventListener("click", runAnalysis);
$("#choose-folder").addEventListener("click", async () => {
  $("#choose-folder").disabled = true;
  try { const result = await api("/api/projects/select", {method:"POST"}); if(result.project) await loadConfig(result.project.id); }
  catch(error) { toast(error.message); } finally { $("#choose-folder").disabled = false; }
});
$("#nav-analysis").addEventListener("click", () => screen("analysis")); $("#nav-history").addEventListener("click", () => screen("history"));
$("#refresh-history").addEventListener("click", loadHistory);
$("#scope-info").addEventListener("click", () => $("#scope-dialog").showModal());
document.querySelectorAll("[data-close]").forEach(button => button.addEventListener("click", () => document.getElementById(button.dataset.close).close()));
document.querySelectorAll("[data-result-tab]").forEach(button => button.addEventListener("click", () => resultTab(button.dataset.resultTab)));
$("#endpoint-search").addEventListener("input", renderEndpoints); $("#method-filter").addEventListener("change", renderEndpoints);
(async () => {
  try {
    await loadConfig();
    const history = await api("/api/jobs");
    const running = history.items.find(job => ["queued", "running"].includes(job.state));
    if(running) { state.activeJob = running.id; $("#empty-state").hidden = true; busy(true); pollJob(running.id); }
    else { const latest = history.items.find(job => job.state === "completed"); if(latest) await openResult(latest.id); }
  } catch(error) { $("#error-panel").textContent = error.message; $("#error-panel").hidden = false; }
})();
