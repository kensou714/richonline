"use strict";
const path = location.pathname;
const isCatalog = path === "/catalog/" || path === "/catalog";
for (const link of document.querySelectorAll(".site-header nav a")) {
  if (new URL(link.href).pathname === (isCatalog ? "/catalog/" : path)) link.setAttribute("aria-current", "page");
}
if (isCatalog) {
  document.querySelector("#home").hidden = true;
  document.querySelector("#catalog-page").hidden = false;
  document.title = "游戏资料 · 大富翁 Online";
  const failed = () => {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.textContent = "游戏资料暂时无法加载，请稍后刷新页面。";
    row.append(cell); document.querySelector("#card-list").replaceChildren(row);
  };
  const data = document.createElement("script");
  data.src = "/catalog/catalog.js";
  data.onerror = failed;
  data.onload = () => {
    const app = document.createElement("script");
    app.src = "/catalog/app.js"; app.onerror = failed;
    document.head.append(app);
  };
  document.head.append(data);
}
const pages = {
  "/register": { action: "register", title: "注册游戏账号", description: "创建一个账号，就能登录游戏。", button: "注册账号", rules: ["账号为 4～20 位英文字母、数字或下划线，区分大小写。", "密码为 8～32 位英文字母、数字或常用半角符号。请不要使用其他网站的密码。"] },
  "/password": { action: "password", title: "修改登录密码", description: "使用原密码验证账号，设置新的密码。", button: "确认修改", rules: ["修改成功后，下次登录游戏请使用新密码。", "本功能需要原密码，不能用来找回遗忘的密码。"] },
  "/claim": { action: "claim", title: "领取 10,000 代币", description: "先查询余额，再为你的角色领取代币。", button: "验证账号并查询余额", rules: ["代币余额低于 10,000 时，每次可以领取 10,000。", "余额达到或超过 10,000 时不可领取；不是补齐至 10,000。", "无需付费，无需审核。到账后请重新登录游戏刷新余额。"] }
};
const page = pages[path];
if (page) {
  document.querySelector("#home").hidden = true;
  document.querySelector("#account-page").hidden = false;
  document.title = `${page.title} · 大富翁 Online`;
  document.querySelector("#page-title").textContent = page.title;
  document.querySelector("#page-description").textContent = page.description;
  for (const text of page.rules) { const p = document.createElement("p"); p.textContent = text; document.querySelector("#rules").append(p); }
  const form = document.querySelector("#account-form");
  const username = document.querySelector("#username");
  const password = document.querySelector("#password");
  const next = document.querySelector("#new-password");
  const confirmation = document.querySelector("#confirm-password");
  const submit = document.querySelector("#submit");
  const refresh = document.querySelector("#refresh-balance");
  const select = document.querySelector("#role");
  const notice = document.querySelector("#notice");
  let token = null, loaded = false, busy = false, operationId = null;
  submit.textContent = page.button;
  if (page.action === "register") {
    username.minLength = 4; username.maxLength = 20; username.pattern = "[A-Za-z0-9_]{4,20}";
    document.querySelector("#username-help").textContent = "4～20 位英文字母、数字或下划线，区分大小写。";
    password.autocomplete = "new-password"; password.minLength = 8; password.maxLength = 32;
  }
  if (page.action !== "claim") {
    document.querySelector("#confirm-field").hidden = false; confirmation.required = true;
  }
  if (page.action === "password") {
    document.querySelector("#new-password-field").hidden = false; next.required = true;
    document.querySelector("#password-label").textContent = "原密码";
  }
  function report(text, error = false) {
    notice.textContent = text; notice.hidden = false; notice.classList.toggle("error", error);
  }
  function resetRole() {
    loaded = false; operationId = null; select.replaceChildren();
    document.querySelector("#role-field").hidden = true; refresh.hidden = true;
    submit.textContent = page.button;
  }
  username.addEventListener("input", resetRole); password.addEventListener("input", resetRole);
  select.addEventListener("change", () => { operationId = null; });
  async function send(action, body) {
    if (!token) {
      const response = await fetch("/api/token", { cache: "no-store", credentials: "same-origin" });
      if (!response.ok) throw new Error("页面服务暂不可用，请稍后重试。");
      token = (await response.json()).token;
    }
    const response = await fetch(`/api/${action}`, {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": token }, body: JSON.stringify(body)
    });
    const result = await response.json();
    if (!response.ok) { if (response.status === 403) token = null; throw new Error(result.error || "请求未完成，请稍后重试。"); }
    return result;
  }
  async function query() {
    const result = await send("account", { username: username.value, password: password.value });
    select.replaceChildren();
    for (const role of result.roles) {
      const option = document.createElement("option"); option.value = role.role_id;
      option.textContent = `${role.name} · ${Number(role.coins).toLocaleString("zh-CN")} 代币`;
      select.append(option);
    }
    loaded = result.roles.length > 0; operationId = null;
    document.querySelector("#role-field").hidden = !loaded; refresh.hidden = !loaded;
    submit.textContent = loaded ? "领取 10,000 代币" : page.button;
    report(loaded ? "请选择领取角色。提交时会再次核对最新余额。" : "本账号暂无可领取的角色。");
  }
  async function perform(forceQuery = false) {
    if (busy || !form.reportValidity()) return;
    if (page.action !== "claim" && confirmation.value !== (page.action === "password" ? next.value : password.value)) {
      report("两次输入的密码不一致。", true); confirmation.focus(); return;
    }
    busy = true; submit.disabled = true; refresh.disabled = true;
    // 请求期间锁定身份字段，避免响应回来时误关联到已修改的账号。
    for (const input of form.querySelectorAll("input, select")) input.disabled = true;
    notice.hidden = true;
    try {
      if (page.action === "claim" && (!loaded || forceQuery)) { await query(); return; }
      const payload = { username: username.value, password: password.value };
      if (page.action === "password") payload.newPassword = next.value;
      if (page.action === "claim") {
        operationId ||= crypto.randomUUID().replaceAll("-", "");
        payload.roleId = Number(select.value); payload.operationId = operationId;
      }
      const result = await send(page.action, payload);
      password.value = ""; next.value = ""; confirmation.value = "";
      if (page.action === "claim") {
        resetRole(); report(`已领取 10,000 代币。发放后余额为 ${Number(result.balance).toLocaleString("zh-CN")}。请重新登录游戏刷新余额。`);
      } else report(page.action === "register" ? "注册成功！现在可以使用此账号登录游戏。" : "密码修改成功！下次登录请使用新密码。");
    } catch (error) {
      report(error instanceof TypeError ? "网络响应中断，结果暂不确定。请在本页重试，系统会沿用相同申请编号。" : error.message, true);
    } finally {
      busy = false; submit.disabled = false; refresh.disabled = false;
      for (const input of form.querySelectorAll("input, select")) input.disabled = false;
    }
  }
  form.addEventListener("submit", event => { event.preventDefault(); void perform(); });
  refresh.addEventListener("click", () => { void perform(true); });
}
