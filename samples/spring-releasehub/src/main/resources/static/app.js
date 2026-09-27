const searchInput = document.querySelector('#search');
const releaseList = document.querySelector('#release-grid');
const message = document.querySelector('#catalog-message');
const filters = [...document.querySelectorAll('.filter')];
const previewLink = document.querySelector('#preview-link');
const documentDialog = document.querySelector('#document-dialog');
const releaseDialog = document.querySelector('#release-dialog');
let releases = [];
let selectedChannel = 'all';
let requestSerial = 0;

const channelNames = {
  'Developer tools': '개발 도구',
  SDK: 'SDK',
  Infrastructure: '인프라',
  'Design system': '디자인 시스템',
};

function formatDate(value) {
  const [year, month, day] = (value || '').split('-');
  return year && month && day ? `${year}.${month}.${day}` : value;
}

function monthLabel(value) {
  const [year, month] = (value || '').split('-');
  return year && month ? `${year}년 ${Number(month)}월` : '날짜 미상';
}

function showRelease(item) {
  document.querySelector('#detail-channel').textContent = channelNames[item.channel] || item.channel;
  document.querySelector('#detail-name').textContent = item.name;
  const date = document.querySelector('#detail-date');
  date.dateTime = item.shippedOn;
  date.textContent = formatDate(item.shippedOn);
  document.querySelector('#detail-version').textContent = `버전 ${item.version}`;
  document.querySelector('#detail-summary').textContent = item.summary;
  releaseDialog.showModal();
}

function makeRow(item) {
  const row = document.createElement('article');
  row.className = 'release-row';
  const date = document.createElement('time');
  date.className = 'release-date';
  date.dateTime = item.shippedOn;
  date.textContent = formatDate(item.shippedOn).slice(5);

  const body = document.createElement('div');
  body.className = 'release-body';
  const meta = document.createElement('div');
  meta.className = 'release-meta';
  const channel = document.createElement('span');
  channel.textContent = channelNames[item.channel] || item.channel;
  const separator = document.createElement('span');
  separator.className = 'meta-separator';
  separator.textContent = '/';
  const version = document.createElement('span');
  version.className = 'release-version';
  version.textContent = `v${item.version}`;
  meta.append(channel, separator, version);

  const title = document.createElement('button');
  title.className = 'release-title';
  title.type = 'button';
  title.setAttribute('aria-label', `${item.name} 릴리스 상세 보기`);
  const name = document.createElement('span');
  name.textContent = item.name;
  const arrow = document.createElement('span');
  arrow.setAttribute('aria-hidden', 'true');
  arrow.textContent = '↗';
  title.append(name, arrow);
  title.addEventListener('click', () => showRelease(item));

  const summary = document.createElement('p');
  summary.className = 'release-summary';
  summary.textContent = item.summary;
  body.append(meta, title, summary);
  row.append(date, body);
  return row;
}

function render() {
  const visible = selectedChannel === 'all'
    ? releases : releases.filter(item => item.channel === selectedChannel);
  const content = document.createDocumentFragment();
  let currentMonth = '';
  for (const item of visible) {
    const month = monthLabel(item.shippedOn);
    if (month !== currentMonth) {
      const heading = document.createElement('div');
      heading.className = 'month-heading';
      heading.textContent = month;
      content.append(heading);
      currentMonth = month;
    }
    content.append(makeRow(item));
  }
  releaseList.replaceChildren(content);
  document.querySelector('#result-count').textContent = `${visible.length}개의 업데이트`;
  message.hidden = visible.length > 0;
  if (!visible.length) message.textContent = '검색 조건에 맞는 릴리스가 없습니다.';
}

async function loadReleases() {
  const serial = ++requestSerial;
  const query = searchInput.value.trim();
  previewLink.href = `/search/preview?q=${encodeURIComponent(query)}`;
  try {
    const response = await fetch(`/api/releases?q=${encodeURIComponent(query)}`);
    if (!response.ok) throw new Error('Catalog request failed');
    const data = await response.json();
    if (serial !== requestSerial) return;
    releases = Array.isArray(data.items) ? data.items : [];
    render();
  } catch {
    if (serial !== requestSerial) return;
    releaseList.replaceChildren();
    document.querySelector('#result-count').textContent = '결과 없음';
    message.hidden = false;
    message.textContent = '카탈로그를 불러오지 못했습니다. 검색어를 확인하고 다시 시도하세요.';
  }
}

let searchTimer;
searchInput.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadReleases, 180);
});
document.addEventListener('keydown', event => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault();
    searchInput.focus();
  }
});
filters.forEach(button => button.addEventListener('click', () => {
  selectedChannel = button.dataset.channel;
  filters.forEach(item => {
    const active = item === button;
    item.classList.toggle('active', active);
    item.setAttribute('aria-pressed', String(active));
  });
  render();
}));

document.querySelectorAll('[data-document]').forEach(button => button.addEventListener('click', async () => {
  document.querySelector('#document-title').textContent = button.querySelector('span').textContent;
  document.querySelector('#document-body').textContent = '문서를 불러오는 중…';
  documentDialog.showModal();
  try {
    const response = await fetch(`/api/documents?name=${encodeURIComponent(button.dataset.document)}`);
    if (!response.ok) throw new Error('Document unavailable');
    document.querySelector('#document-body').textContent = await response.text();
  } catch {
    document.querySelector('#document-body').textContent = '문서를 불러오지 못했습니다.';
  }
}));

document.querySelector('#close-dialog').addEventListener('click', () => documentDialog.close());
document.querySelector('#close-release-dialog').addEventListener('click', () => releaseDialog.close());
for (const dialog of [documentDialog, releaseDialog]) {
  dialog.addEventListener('click', event => { if (event.target === dialog) dialog.close(); });
}

fetch('/api/summary').then(response => response.json()).then(summary => {
  document.querySelector('#release-count').textContent = String(summary.releaseCount).padStart(2, '0');
  document.querySelector('#filter-all-count').textContent = String(summary.releaseCount).padStart(2, '0');
  document.querySelector('#channel-count').textContent = String(summary.channels).padStart(2, '0');
  document.querySelector('#latest-version').textContent = summary.latestVersion;
  document.querySelector('#latest-product').textContent = summary.latestProduct;
}).catch(() => {});
loadReleases();
