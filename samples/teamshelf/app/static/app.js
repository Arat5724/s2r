"use strict";

const $ = (selector) => document.querySelector(selector);
const state = {token: null, user: null, category: "", products: [], view: "catalog"};
const currency = (value) => new Intl.NumberFormat("ko-KR").format(value) + "원";
const statusLabels = {pending: "승인 대기", approved: "승인 완료", rejected: "반려", cancelled: "취소"};
const illustrations = {
  keyboard: '<g transform="rotate(-12 80 60)"><rect x="11" y="34" width="140" height="60" rx="7" fill="#b9c4ac"/><rect x="8" y="27" width="140" height="60" rx="7" fill="#f9f9ed"/><path d="M19 40h118M19 51h118M19 62h118M28 32v36M41 32v36M54 32v36M67 32v36M80 32v36M93 32v36M106 32v36M119 32v36" stroke="#c7d0bb" stroke-width="3"/><rect x="43" y="72" width="65" height="7" rx="2" fill="#dbe1cd"/></g>',
  notebook: '<g transform="rotate(12 80 60)"><rect x="47" y="12" width="73" height="96" rx="3" fill="#b2ba99"/><path d="M45 10h70v92H45z" fill="#d1d7b8"/><path d="M50 10v92" stroke="#a3ad88" stroke-width="4"/><rect x="64" y="28" width="33" height="17" rx="1" fill="#eef0dc"/><path d="M70 34h20m-20 5h12" stroke="#a5b08d"/></g>',
  headphones: '<path d="M42 70V47a38 38 0 0 1 76 0v23" fill="none" stroke="#738a7f" stroke-width="14"/><path d="M44 46a36 36 0 0 1 72 0" fill="none" stroke="#b5c6bb" stroke-width="7"/><rect x="29" y="56" width="27" height="42" rx="12" fill="#91a99b"/><rect x="104" y="56" width="27" height="42" rx="12" fill="#91a99b"/><rect x="44" y="59" width="12" height="35" rx="6" fill="#536c60"/><rect x="104" y="59" width="12" height="35" rx="6" fill="#536c60"/>',
  mug: '<ellipse cx="79" cy="101" rx="42" ry="6" fill="#d2bfa5"/><path d="M108 39h9c27 0 27 39 0 39h-9" fill="none" stroke="#cfa16a" stroke-width="11"/><path d="M40 30h70v56c0 22-70 22-70 0z" fill="#e4b982"/><ellipse cx="75" cy="30" rx="35" ry="10" fill="#f4d3a3"/><ellipse cx="75" cy="31" rx="28" ry="6" fill="#aa7950"/>',
  stand: '<path d="M63 43h37l13 48H50z" fill="#9ca99d"/><path d="M50 89h65l13 11H35z" fill="#c9d0c2"/><g transform="rotate(-10 80 40)"><path d="M23 14h118v55H23z" fill="#b9c5b7"/><rect x="28" y="18" width="109" height="45" rx="2" fill="#3c5145"/><rect x="34" y="23" width="97" height="35" rx="1" fill="#cedacc"/><path d="M13 69h140l-9 7H20z" fill="#e4e9dc"/></g>',
  tray: '<g transform="rotate(-13 80 60)"><rect x="13" y="36" width="137" height="53" rx="21" fill="#b0a17d"/><rect x="13" y="30" width="137" height="52" rx="21" fill="#d7cba7"/><rect x="24" y="40" width="115" height="31" rx="13" fill="#bfb28d"/><path d="M41 51h75" stroke="#738765" stroke-width="7" stroke-linecap="round"/><path d="M49 63h70" stroke="#f0e9d0" stroke-width="5" stroke-linecap="round"/></g>'
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, options = {}) {
  const headers = {Accept: "application/json", ...(options.body ? {"Content-Type": "application/json"} : {})};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(path, {...options, headers});
  const data = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    if (response.status === 401 && state.token) { state.token = null; state.user = null; updateAccount(); }
    throw new Error(typeof data?.detail === "string" ? data.detail : "입력 내용을 확인해 주세요.");
  }
  return data;
}

let toastTimer;
function toast(message) {
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $("#toast").hidden = true; }, 3500);
}

function updateAccount() {
  $("#user-name").textContent = state.user?.name || "게스트";
  $("#user-role").textContent = state.user ? (state.user.role === "admin" ? "워크스페이스 관리자" : "팀 멤버") : "둘러보는 중";
  $("#avatar").textContent = state.user?.name.slice(0, 1) || "G";
  $("#login-button").textContent = state.user ? "로그아웃 →" : "로그인 →";
  $("#account-button").setAttribute("aria-label", state.user ? "로그아웃" : "로그인");
  $("#admin-nav").hidden = state.user?.role !== "admin";
}

let productRequest = 0;
async function loadProducts() {
  const request = ++productRequest;
  try {
    const params = new URLSearchParams({q: $("#search").value});
    if (state.category) params.set("category", state.category);
    const result = await api(`/api/products?${params}`);
    if (request !== productRequest) return;
    state.products = result.items;
    $("#product-count").textContent = `${result.items.length}개의 비품`;
    $("#products").replaceChildren();
    if (!result.items.length) $("#products").append(el("p", "empty-state", "검색 결과가 없습니다."));
    for (const product of result.items) {
      const card = el("article", "product-card");
      const art = el("div", `product-art ${product.icon}`);
      // Only these developer-owned SVG literals enter innerHTML; API text uses textContent.
      art.innerHTML = `<svg viewBox="0 0 160 120" aria-hidden="true">${illustrations[product.icon] || ""}</svg>`;
      art.append(el("span", "category-pill", product.category));
      const info = el("div", "product-info");
      info.append(el("h2", "", product.name), el("p", "", product.description));
      const bottom = el("div", "product-bottom");
      const button = el("button", "request-button", "신청하기 ↗");
      button.addEventListener("click", () => openOrder(product.id));
      bottom.append(el("span", "", currency(product.price)), button);
      info.append(bottom); card.append(art, info); $("#products").append(card);
    }
  } catch (error) { toast(error.message); }
}

async function openOrder(id) {
  if (!state.user) { $("#login-error").textContent = "신청하려면 먼저 로그인해 주세요."; $("#login-dialog").showModal(); return; }
  try {
    const product = await api(`/api/products/${id}`);
    $("#order-form").reset();
    $("#order-form").elements.product_id.value = product.id;
    $("#order-title").textContent = product.name;
    $("#order-description").textContent = `${product.description} · ${currency(product.price)}`;
    $("#order-error").textContent = "";
    $("#order-dialog").showModal();
  } catch (error) { toast(error.message); }
}

async function loadOrders(admin = false) {
  const target = admin ? $("#admin-content") : $("#orders-content");
  target.replaceChildren(el("div", "empty-state", "신청 내역을 불러오는 중…"));
  if (!state.user) { target.replaceChildren(el("div", "empty-state", "로그인하면 신청 내역을 확인할 수 있습니다.")); return; }
  try {
    const result = await api(admin ? "/api/admin/orders" : "/api/orders");
    const list = el("div", "order-list");
    for (const order of result.items) {
      const row = el("article", "order-row"), main = el("div", "order-main");
      main.append(el("strong", "", order.product_name), el("small", "", `#${order.id} · ${order.quantity}개 · ${currency(order.unit_price * order.quantity)}${admin ? ` · ${order.requester}` : ""}`));
      if (order.note) main.append(el("small", "order-note", order.note));
      row.append(main, el("span", `badge ${order.status}`, statusLabels[order.status]));
      if (order.status === "pending") {
        const actions = el("div", "row-actions");
        for (const [action, label] of admin ? [["approved", "승인"], ["rejected", "반려"]] : [["cancel", "취소"]]) {
          const button = el("button", "", label);
          button.addEventListener("click", async () => {
            button.disabled = true;
            try {
              await api(admin ? `/api/admin/orders/${order.id}/status` : `/api/orders/${order.id}/cancel`,
                admin ? {method: "PATCH", body: JSON.stringify({status: action})} : {method: "POST"});
              await loadOrders(admin); toast("신청 상태가 변경되었습니다.");
            } catch (error) { toast(error.message); button.disabled = false; }
          });
          actions.append(button);
        }
        row.append(actions);
      }
      list.append(row);
    }
    target.replaceChildren(result.items.length ? list : el("div", "empty-state", "아직 신청 내역이 없습니다."));
  } catch (error) { target.replaceChildren(el("div", "empty-state", error.message)); }
}

function showView(view) {
  state.view = view;
  for (const name of ["catalog", "orders", "admin"]) $(`#${name}-view`).hidden = name !== view;
  document.querySelectorAll("[data-view]").forEach(button => button.classList.toggle("active", button.dataset.view === view));
  $("#breadcrumb").textContent = {catalog: "비품 둘러보기", orders: "내 신청 내역", admin: "승인 관리"}[view];
  if (view !== "catalog") loadOrders(view === "admin");
}

async function accountAction() {
  if (!state.user) { $("#login-error").textContent = ""; $("#login-dialog").showModal(); return; }
  try { await api("/api/auth/logout", {method: "POST"}); }
  catch (error) { toast(error.message); return; }
  state.token = null; state.user = null; updateAccount();
  // Clear authenticated data when signing out; tokens live only in this page's memory.
  $("#orders-content").replaceChildren(); $("#admin-content").replaceChildren();
  showView("catalog"); toast("로그아웃했습니다.");
}

$("#login-button").addEventListener("click", accountAction);
$("#account-button").addEventListener("click", accountAction);
document.querySelectorAll("[data-close]").forEach(button => button.addEventListener("click", () => document.getElementById(button.dataset.close).close()));
document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => showView(button.dataset.view)));
document.querySelectorAll("[data-category]").forEach(button => button.addEventListener("click", () => {
  state.category = button.dataset.category;
  document.querySelectorAll("[data-category]").forEach(tab => tab.classList.toggle("active", tab === button));
  loadProducts();
}));
let searchTimer;
$("#search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(loadProducts, 180); });

$("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget, button = form.querySelector('[type="submit"]'); button.disabled = true;
  try {
    const result = await api("/api/auth/login", {method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(form)))});
    state.token = result.access_token; state.user = result.user; form.reset();
    updateAccount(); $("#login-dialog").close(); showView(state.view); toast(`${result.user.name}님, 반가워요.`);
  } catch (error) { $("#login-error").textContent = error.message; }
  finally { button.disabled = false; }
});

$("#order-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget, button = form.querySelector('[type="submit"]'); button.disabled = true;
  const data = new FormData(form);
  try {
    await api("/api/orders", {method: "POST", body: JSON.stringify({product_id: Number(data.get("product_id")), quantity: Number(data.get("quantity")), note: data.get("note")})});
    $("#order-dialog").close(); toast("비품 신청이 접수되었습니다."); showView("orders");
  } catch (error) { $("#order-error").textContent = error.message; }
  finally { button.disabled = false; }
});

api("/api/meta").then(meta => { $("#build-info").textContent = `${meta.revision} · ${meta.profile} · 샘플 데이터`; }).catch(error => toast(error.message));
loadProducts();
