/* TechLab Registry catalog UI. API-supplied text is rendered as text, never HTML. */
(function () {
  'use strict';

  var details = {
    1: { icon: '>_', description: '반복되는 개발 작업을 간결한 명령 흐름으로 정리하는 팀 공용 CLI.', note: '일상적인 프로젝트 작업을 빠르게 시작하세요.' },
    2: { icon: '{}', description: '서비스 이벤트와 상태 정보를 애플리케이션에 연결하는 개발자 SDK.', note: '서비스 코드에 자연스럽게 연결할 수 있습니다.' },
    3: { icon: '//', description: '구조화된 입력 데이터를 일관된 형식으로 읽고 변환하는 파서 라이브러리.', note: '데이터 처리 파이프라인을 단순하게 유지하세요.' },
    4: { icon: '◈', description: '대시보드와 내부 도구에서 함께 쓰는 인터페이스 테마 자산.', note: '일관된 화면을 빠르게 구성하세요.' },
    5: { icon: '≡', description: '애플리케이션의 이벤트를 읽기 쉬운 형식으로 기록하는 로깅 라이브러리.', note: '실행 흐름을 명확하게 살펴보세요.' },
    6: { icon: '▦', description: '개발부터 릴리스까지 반복되는 빌드 단계를 정리하는 CLI 도구.', note: '팀의 빌드 과정을 한눈에 관리하세요.' }
  };
  var categoryNames = { cli: 'CLI', sdk: 'SDK', library: '라이브러리', asset: '디자인 자산' };
  var state = { q: new URLSearchParams(window.location.search).get('q') || '', category: '', requestId: 0 };
  var grid = document.getElementById('package-grid');
  var search = document.getElementById('search-input');
  var summary = document.getElementById('result-summary');
  var previewLink = document.getElementById('preview-link');
  var emptyState = document.getElementById('empty-state');
  var errorState = document.getElementById('error-state');
  var dialog = document.getElementById('package-dialog');

  function textNode(tag, className, value) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value;
    return node;
  }

  function updatePreviewLink() {
    var query = search.value.trim();
    previewLink.href = '/search/preview' + (query ? '?q=' + encodeURIComponent(query) : '');
  }

  function updateUrl() {
    var url = new URL(window.location.href);
    if (state.q) url.searchParams.set('q', state.q);
    else url.searchParams.delete('q');
    window.history.replaceState({}, '', url.pathname + url.search + url.hash);
  }

  function setCategory(category) {
    state.category = category;
    document.querySelectorAll('.filter-chip').forEach(function (button) {
      var active = button.dataset.category === category;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
  }

  function showLoading() {
    emptyState.hidden = true;
    errorState.hidden = true;
    grid.hidden = false;
    grid.replaceChildren();
    for (var i = 0; i < 3; i += 1) grid.appendChild(textNode('div', 'loading-card', ''));
    summary.textContent = '패키지를 불러오는 중입니다.';
  }

  function openDetails(item) {
    var meta = details[item.id] || { icon: '▦', description: '개발자를 위한 패키지 리소스입니다.', note: '카탈로그에서 패키지 정보를 확인하세요.' };
    document.getElementById('dialog-icon').textContent = meta.icon;
    document.getElementById('dialog-category').textContent = categoryNames[item.category] || item.category;
    document.getElementById('dialog-title').textContent = item.name;
    document.getElementById('dialog-description').textContent = meta.description + ' ' + meta.note;
    document.getElementById('dialog-version').textContent = 'v' + item.version;
    document.getElementById('dialog-command').textContent = 'GET /api/products?q=' + encodeURIComponent(item.name);
    document.getElementById('copy-command').textContent = '복사';
    dialog.showModal();
  }

  function createCard(item) {
    var meta = details[item.id] || { icon: '▦', description: '개발자를 위한 패키지 리소스입니다.' };
    var article = textNode('article', 'package-card', '');
    var top = textNode('div', 'package-card-top', '');
    var icon = textNode('span', 'package-icon ' + (categoryNames[item.category] ? item.category : ''), meta.icon);
    icon.setAttribute('aria-hidden', 'true');
    top.appendChild(icon);
    top.appendChild(textNode('span', 'version-tag', 'v' + item.version));
    article.appendChild(top);
    article.appendChild(textNode('div', 'package-category', categoryNames[item.category] || item.category));
    article.appendChild(textNode('h3', '', item.name));
    article.appendChild(textNode('p', '', meta.description));
    var bottom = textNode('div', 'package-card-bottom', '');
    bottom.appendChild(textNode('span', '', '공개 패키지'));
    var action = textNode('button', '', '자세히 보기 →');
    action.type = 'button';
    action.setAttribute('aria-label', item.name + ' 자세히 보기');
    action.addEventListener('click', function () { openDetails(item); });
    bottom.appendChild(action);
    article.appendChild(bottom);
    return article;
  }

  function render(items) {
    grid.replaceChildren();
    errorState.hidden = true;
    if (!items.length) {
      grid.hidden = true;
      emptyState.hidden = false;
      summary.textContent = '검색 결과 0개';
      return;
    }
    grid.hidden = false;
    emptyState.hidden = true;
    items.sort(function (a, b) { return a.name.localeCompare(b.name, 'ko'); });
    items.forEach(function (item) { grid.appendChild(createCard(item)); });
    summary.textContent = '검색 결과 ' + items.length + '개 패키지';
  }

  async function loadCatalog() {
    var requestId = ++state.requestId;
    var params = new URLSearchParams();
    if (state.q) params.set('q', state.q);
    if (state.category) params.set('category', state.category);
    showLoading();
    try {
      var url = '/api/products' + (params.toString() ? '?' + params.toString() : '');
      var response = await fetch(url, { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error('Catalog request failed');
      var payload = await response.json();
      if (requestId !== state.requestId) return;
      render(Array.isArray(payload.items) ? payload.items : []);
    } catch (_error) {
      if (requestId !== state.requestId) return;
      grid.hidden = true;
      emptyState.hidden = true;
      errorState.hidden = false;
      summary.textContent = '카탈로그를 불러오지 못했습니다.';
    }
  }

  async function loadTotal() {
    try {
      var response = await fetch('/api/products', { headers: { Accept: 'application/json' } });
      if (!response.ok) return;
      var payload = await response.json();
      if (!Array.isArray(payload.items)) return;
      document.getElementById('metric-packages').textContent = String(payload.items.length).padStart(2, '0');
      document.getElementById('all-count').textContent = String(payload.items.length);
    } catch (_error) { /* The catalog request shows its own error state. */ }
  }

  async function loadHealth() {
    var status = document.getElementById('service-status');
    try {
      var response = await fetch('/health');
      if (!response.ok) throw new Error('Service unavailable');
      status.lastElementChild.textContent = '서비스 정상';
    } catch (_error) {
      status.classList.add('offline');
      status.lastElementChild.textContent = '연결 확인 필요';
    }
  }

  search.value = state.q;
  updatePreviewLink();
  search.addEventListener('input', updatePreviewLink);
  document.getElementById('search-form').addEventListener('submit', function (event) {
    event.preventDefault();
    state.q = search.value.trim();
    updateUrl();
    updatePreviewLink();
    loadCatalog();
  });
  document.querySelectorAll('.filter-chip').forEach(function (button) {
    button.addEventListener('click', function () {
      setCategory(button.dataset.category);
      loadCatalog();
    });
  });
  document.getElementById('clear-filters').addEventListener('click', function () {
    search.value = '';
    state.q = '';
    setCategory('');
    updateUrl();
    updatePreviewLink();
    loadCatalog();
  });
  document.getElementById('retry-load').addEventListener('click', loadCatalog);
  document.getElementById('dialog-close').addEventListener('click', function () { dialog.close(); });
  dialog.addEventListener('click', function (event) { if (event.target === dialog) dialog.close(); });
  document.getElementById('copy-command').addEventListener('click', async function () {
    var button = this;
    try {
      await navigator.clipboard.writeText(document.getElementById('dialog-command').textContent);
      button.textContent = '복사됨';
      window.setTimeout(function () { button.textContent = '복사'; }, 1800);
    } catch (_error) { button.textContent = '선택하여 복사'; }
  });

  loadTotal();
  loadCatalog();
  loadHealth();
}());
