"use strict";

const state = { csrf: null, initialized: false, page: null, role: null, username: null, pages: [] };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const UKEY_AGENT_ORIGIN = "http://127.0.0.1:18088";

function rotateLeft(value, count) {
  const bits = count & 31;
  return ((value << bits) | (value >>> ((32 - bits) & 31))) >>> 0;
}

function add32(...values) {
  let result = 0;
  for (const value of values) result = (result + (value >>> 0)) >>> 0;
  return result;
}

function sm3(bytes) {
  const length = bytes.length;
  const total = Math.ceil((length + 1 + 8) / 64) * 64;
  const padded = new Uint8Array(total);
  padded.set(bytes);
  padded[length] = 0x80;
  let bitLength = BigInt(length) * 8n;
  for (let index = 0; index < 8; index += 1) {
    padded[total - 1 - index] = Number(bitLength & 0xffn);
    bitLength >>= 8n;
  }

  const hash = new Uint32Array([
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
  ]);
  const words = new Uint32Array(68);
  const expanded = new Uint32Array(64);
  const p0 = (value) => (value ^ rotateLeft(value, 9) ^ rotateLeft(value, 17)) >>> 0;
  const p1 = (value) => (value ^ rotateLeft(value, 15) ^ rotateLeft(value, 23)) >>> 0;

  for (let offset = 0; offset < total; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      const pos = offset + index * 4;
      words[index] = (
        (padded[pos] << 24) | (padded[pos + 1] << 16) |
        (padded[pos + 2] << 8) | padded[pos + 3]
      ) >>> 0;
    }
    for (let index = 16; index < 68; index += 1) {
      words[index] = (
        p1(words[index - 16] ^ words[index - 9] ^ rotateLeft(words[index - 3], 15)) ^
        rotateLeft(words[index - 13], 7) ^ words[index - 6]
      ) >>> 0;
    }
    for (let index = 0; index < 64; index += 1) {
      expanded[index] = (words[index] ^ words[index + 4]) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = hash;
    for (let index = 0; index < 64; index += 1) {
      const first = index < 16;
      const ff = first ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c));
      const gg = first ? (e ^ f ^ g) : ((e & f) | ((~e) & g));
      const ss1 = rotateLeft(add32(rotateLeft(a, 12), e, rotateLeft(first ? 0x79cc4519 : 0x7a879d8a, index)), 7);
      const ss2 = (ss1 ^ rotateLeft(a, 12)) >>> 0;
      const tt1 = add32(ff, d, ss2, expanded[index]);
      const tt2 = add32(gg, h, ss1, words[index]);
      d = c; c = rotateLeft(b, 9); b = a; a = tt1;
      h = g; g = rotateLeft(f, 19); f = e; e = p0(tt2);
    }
    [a, b, c, d, e, f, g, h].forEach((value, index) => { hash[index] ^= value; });
  }

  const output = new Uint8Array(32);
  hash.forEach((value, index) => {
    output[index * 4] = value >>> 24;
    output[index * 4 + 1] = value >>> 16;
    output[index * 4 + 2] = value >>> 8;
    output[index * 4 + 3] = value;
  });
  return output;
}

function base64Bytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesBase64(value) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function validateAdminPassword(password) {
  if (password.length < 10 || password.length > 128) {
    throw new Error("管理员密码长度必须为 10–128 个字符");
  }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]
    .filter((pattern) => pattern.test(password)).length;
  if (classes < 3) throw new Error("管理员密码需包含大写、小写、数字、符号中的至少三类");
}

function hashPassword(password, saltBase64) {
  const passwordBytes = new TextEncoder().encode(password);
  const salt = base64Bytes(saltBase64);
  if (salt.length !== 8) throw new Error("服务器返回的账户口令盐值长度无效");
  const input = new Uint8Array(passwordBytes.length + salt.length);
  input.set(passwordBytes);
  input.set(salt, passwordBytes.length);
  const digest = sm3(input);
  passwordBytes.fill(0);
  input.fill(0);
  return bytesBase64(digest);
}

async function passwordHashForUser(username, password) {
  const response = await api(`/api/auth/password-salt?username=${encodeURIComponent(username)}`);
  return { hash_base64: hashPassword(password, response.salt_base64) };
}

async function newPasswordMaterial(username, password, initialize = false) {
  validateAdminPassword(password);
  const path = initialize
    ? "/api/auth/initialize-password-salt"
    : `/api/administrators/${encodeURIComponent(username)}/password-salt`;
  const response = await api(path, {
    method: "POST",
    body: initialize ? JSON.stringify({ username }) : "{}",
  });
  return {
    ticket_id: response.ticket_id,
    hash_base64: hashPassword(password, response.salt_base64),
  };
}

async function currentPasswordHash(password) {
  if (!state.username) throw new Error("当前管理会话缺少用户名");
  return passwordHashForUser(state.username, password);
}

function notice(message, error = false) {
  const host = $("#notice");
  host.innerHTML = "";
  const item = document.createElement("div");
  item.className = `notice${error ? " error" : ""}`;
  item.textContent = message;
  host.append(item);
  setTimeout(() => item.remove(), 4500);
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.csrf && !["GET", "HEAD"].includes((options.method || "GET").toUpperCase())) {
    headers["X-CSRF-Token"] = state.csrf;
  }
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data.detail || data.error?.message || `请求失败（${response.status}）`;
    throw new Error(message);
  }
  return data;
}

async function fileBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function formJson(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function showAuthTab(tab) {
  $$("[data-auth-tab]").forEach((button) => {
    const active = button.dataset.authTab === tab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  $$("[data-auth-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.authPanel !== tab;
  });
}

function showUKeyAgentDialog() {
  const dialog = $("#ukey-agent-dialog");
  if (!dialog.open) dialog.showModal();
}

function unavailableError(message) {
  const error = new Error(message);
  error.ukeyAgentUnavailable = true;
  return error;
}

function openUKeyBridge() {
  const width = 380;
  const height = 330;
  const left = Math.max(0, Math.round((window.screenX || 0) + (window.outerWidth - width) / 2));
  const top = Math.max(0, Math.round((window.screenY || 0) + (window.outerHeight - height) / 2));
  return window.open(
    `${UKEY_AGENT_ORIGIN}/bridge/pin`,
    "cryptokit-ukey-pin",
    `popup=yes,width=${width},height=${height},left=${left},top=${top},resizable=no,scrollbars=no`
  );
}

function signWithUKeyBridge(popup, challenge, username) {
  return new Promise((resolve, reject) => {
    let requestSent = false;
    let bridgeReady = false;
    let timer = null;

    function finish(error, result) {
      window.clearInterval(closeWatcher);
      window.clearTimeout(timer);
      window.removeEventListener("message", onMessage);
      if (error) reject(error); else resolve(result);
    }

    function onMessage(event) {
      const data = event.data;
      if (event.source !== popup || !data || data.source !== "cryptokit-ukey-bridge") return;
      if (data.type === "ready" && !requestSent) {
        bridgeReady = true;
        requestSent = true;
        window.clearTimeout(timer);
        timer = window.setTimeout(() => finish(new Error("UKey 签名等待超时")), 120000);
        popup.postMessage({
          source: "cryptokit-soft-hsm",
          type: "sign",
          channel_id: challenge.challenge_id,
          username,
          challenge_base64url: challenge.challenge_base64url,
          user_id: challenge.sm2_user_id,
        }, UKEY_AGENT_ORIGIN);
      } else if (data.type === "result" && data.channel_id === challenge.challenge_id) {
        finish(null, data.result);
      } else if (data.type === "cancel" && (!data.channel_id || data.channel_id === challenge.challenge_id)) {
        finish(new Error("已取消 UKey 登录"));
      }
    }

    const closeWatcher = window.setInterval(() => {
      if (popup.closed) {
        finish(bridgeReady ? new Error("已取消 UKey 登录") : unavailableError("未检测到本机 UKey 插件"));
      }
    }, 350);
    window.addEventListener("message", onMessage);
    timer = window.setTimeout(
      () => finish(unavailableError("未检测到本机 UKey 插件，请先启动或下载安装")),
      5000
    );
  });
}

async function copyText(text) {
  const value = String(text ?? "");
  if (window.isSecureContext && typeof navigator.clipboard?.writeText === "function") {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_) {
      // Continue with the HTTP-compatible fallback below.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.readOnly = true;
  textarea.setAttribute("aria-hidden", "true");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.opacity = "0";
  document.body.append(textarea);

  let copied = false;
  try {
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, value.length);
    copied = typeof document.execCommand === "function" && document.execCommand("copy");
  } catch (_) {
    copied = false;
  } finally {
    textarea.remove();
  }

  if (!copied) {
    window.prompt("浏览器禁止自动访问剪贴板，请手动复制公钥 Base64：", value);
  }
  return copied;
}

function showMode(mode) {
  $("#initialize-view").hidden = mode !== "initialize";
  $("#login-view").hidden = mode !== "login";
  $("#app-view").hidden = mode !== "app";
  $("#nav").hidden = mode !== "app";
  $("#logout").hidden = mode !== "app";
  $("#page-title").textContent = mode === "initialize" ? "初始化" : mode === "login" ? "管理员登录" : "运行概览";
}

function setService(ok, text) {
  $("#service-dot").className = `dot ${ok ? "ok" : "error"}`;
  $("#service-label").textContent = text;
}

function applyAccess(session) {
  state.csrf = session.csrf;
  state.role = session.role;
  state.username = session.username;
  state.pages = session.pages || [];
  $$("#nav button").forEach((button) => {
    button.hidden = !state.pages.includes(button.dataset.page);
  });
  const first = state.pages[0];
  if (first) switchPage(first);
}

function switchPage(page) {
  if (state.pages.length && !state.pages.includes(page)) return;
  state.page = page;
  $$(".page").forEach((item) => { item.hidden = item.id !== `page-${page}`; });
  $$("#nav button").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
  const titles = { administrators: "管理员管理", dashboard: "运行概览", service: "服务管理", keys: "密码服务与密钥", device: "设备信息", sessions: "会话管理", testing: "密码自检", maintenance: "备份与恢复", audit: "审计日志" };
  $("#page-title").textContent = titles[page];
  if (page === "administrators") loadAdministrators();
  if (page === "dashboard") loadDashboard();
  if (page === "service") loadService();
  if (page === "keys") {
    loadKeys();
    if (typeof loadKeks === "function") loadKeks();
  }
  if (page === "device") loadDevice();
  if (page === "maintenance" && typeof loadBackups === "function") loadBackups();
  if (page === "audit") loadAudit();
}

async function loadDashboard() {
  const data = await api("/api/status");
  $("#metric-status").textContent = data.daemon.status === "running" ? "正常" : "异常";
  $("#metric-keys").textContent = data.daemon.keys;
  $("#metric-sessions").textContent = data.daemon.active_sessions;
  $("#metric-requests").textContent = data.daemon.total_requests;
  $("#device-heading").textContent = data.device.device_name;
  $("#summary-vendor").textContent = data.device.vendor;
  $("#summary-serial").textContent = data.device.serial;
  setService(true, "密码服务运行正常");
}

function actionButton(label, className, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `mini ${className || ""}`;
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function formatDateTime(timestamp) {
  return timestamp ? new Date(timestamp * 1000).toLocaleString() : "—";
}

function formatDuration(seconds) {
  let remaining = Math.max(0, Number(seconds) || 0);
  const days = Math.floor(remaining / 86400);
  remaining %= 86400;
  const hours = Math.floor(remaining / 3600);
  remaining %= 3600;
  const minutes = Math.floor(remaining / 60);
  const parts = [];
  if (days) parts.push(`${days} 天`);
  if (hours || days) parts.push(`${hours} 小时`);
  parts.push(`${minutes} 分钟`);
  return parts.join(" ");
}

async function loadService() {
  const service = await api("/api/service");
  const running = service.running && service.daemon_available;
  const stateText = service.running ? (service.daemon_available ? "运行中" : "进程异常") : "已停止";
  $("#service-state").textContent = stateText;
  $("#service-address").textContent = service.address;
  $("#service-uptime").textContent = service.running ? formatDuration(service.uptime_seconds) : "—";
  $("#service-requests").textContent = service.total_requests ?? "—";
  $("#service-host").textContent = service.listen_host;
  $("#service-port").textContent = service.port;
  $("#service-started-at").textContent = formatDateTime(service.started_at);
  $("#service-stopped-at").textContent = formatDateTime(service.stopped_at);
  $("#service-pid").textContent = service.pid ?? "—";
  $("#service-sessions").textContent = service.active_sessions ?? "—";
  $("#service-keys").textContent = service.keys ?? "—";
  $("#service-description").textContent = service.description || service.supervisor_state;
  const badge = $("#service-state-badge");
  badge.textContent = stateText;
  badge.className = `status ${running ? "ok" : service.running ? "warn" : "off"}`;
  const error = service.daemon_error || service.spawn_error;
  $("#service-error").hidden = !error;
  $("#service-error").textContent = error ? `服务诊断：${error}` : "";
  $("#start-service").disabled = service.running;
  $("#stop-service").disabled = !service.running;
  setService(running, running ? "密码服务运行正常" : service.running ? "密码服务进程异常" : "密码服务已停止（Web 正常）");
}

function openServiceDialog(action) {
  const settings = {
    start: { title: "启动密码服务", confirmation: "START SERVICE", copy: "启动同一容器内的 sdfxd 密码服务进程。" },
    stop: { title: "停止密码服务", confirmation: "STOP SERVICE", copy: "停止会断开全部 SDF 连接与活动会话。Web 管理端会保持在线，可稍后重新启动服务。" },
    restart: { title: "重启密码服务", confirmation: "RESTART SERVICE", copy: "重启会中断全部 SDF 连接与活动会话，并重置本次启动的请求计数。持久化数据不受影响。" },
  };
  const config = settings[action];
  const form = $("#service-form");
  form.reset();
  form.elements.action.value = action;
  form.elements.confirmation.placeholder = config.confirmation;
  form.elements.confirmation.pattern = config.confirmation;
  $("#service-dialog-title").textContent = config.title;
  $("#service-dialog-copy").textContent = `${config.copy} 请输入 ${config.confirmation} 确认。`;
  $("#service-submit").textContent = config.title;
  $("#service-submit").className = `button ${action === "start" ? "primary" : action === "restart" ? "warning" : "danger"}`;
  $("#service-dialog").showModal();
}

function lifecycleBadge(item) {
  const badge = document.createElement("span");
  const status = item.expiry_status || "permanent";
  badge.className = `status ${status === "expired" ? "expired" : status === "warning" ? "warn" : status === "valid" ? "ok" : "off"}`;
  badge.textContent = status === "permanent" ? "长期有效" :
    status === "expired" ? `已到期 ${Math.abs(item.remaining_days || 0)} 天` :
    status === "warning" ? `剩余 ${item.remaining_days} 天` :
    `${formatDateTime(item.expires_at)}（${item.remaining_days} 天）`;
  return badge;
}

function openValidityDialog(item, keyType = item.type) {
  const form = $("#validity-form");
  form.algorithm.value = item.algorithm || "SM4";
  form.key_type.value = keyType;
  form.index.value = item.index;
  form.validity_days.value = item.validity_days ?? 0;
  $("#validity-dialog").showModal();
}

async function loadKeys() {
  const rows = $("#key-rows");
  rows.innerHTML = '<tr><td colspan="9">正在读取…</td></tr>';
  try {
    const keys = await api("/api/keys");
    rows.innerHTML = "";
    if (!keys.length) rows.innerHTML = '<tr><td colspan="9">尚未生成内部密钥</td></tr>';
    const expiring = keys.filter((key) => ["warning", "expired"].includes(key.expiry_status));
    const summary = $("#key-expiry-summary");
    summary.hidden = expiring.length === 0;
    summary.textContent = expiring.length ? `密钥到期告警：${expiring.filter((key) => key.expiry_status === "expired").length} 个已到期，${expiring.filter((key) => key.expiry_status === "warning").length} 个将在 30 天内到期。到期不会自动停用。` : "";
    for (const key of keys) {
      const tr = document.createElement("tr");
      const purpose = key.type === "sign" ? "签名" : key.type === "enc" ? "加密" : key.purpose;
      const algorithmQuery = `?algorithm=${encodeURIComponent(key.algorithm)}`;
      [purpose, key.index, `${key.algorithm}-${key.bits}`].forEach((value) => {
        const td = document.createElement("td"); td.textContent = value; tr.append(td);
      });
      const statusCell = document.createElement("td");
      const statusBadge = document.createElement("span");
      statusBadge.className = `status ${key.enabled ? "ok" : "off"}`;
      statusBadge.textContent = key.enabled ? "启用" : "停用";
      statusCell.append(statusBadge); tr.append(statusCell);
      const integrityCell = document.createElement("td");
      const integrityBadge = document.createElement("span");
      integrityBadge.className = `status ${key.integrity === false ? "off" : "ok"}`;
      integrityBadge.textContent = key.integrity === false ? "异常" : "已保护";
      integrityCell.append(integrityBadge); tr.append(integrityCell);
      const created = document.createElement("td");
      created.textContent = formatDateTime(key.lifecycle_created_at || key.created_at); tr.append(created);
      const validity = document.createElement("td"); validity.append(lifecycleBadge(key)); tr.append(validity);
      const fingerprint = document.createElement("td");
      fingerprint.className = "fingerprint"; fingerprint.title = key.fingerprint;
      fingerprint.textContent = key.fingerprint; tr.append(fingerprint);
      const actions = document.createElement("td"); actions.className = "actions";
      actions.append(actionButton("校验", "", async () => {
        try {
          const result = await api(`/api/keys/${key.type}/${key.index}/verify${algorithmQuery}`, { method: "POST", body: "{}" });
          notice(result.valid ? "HMAC-SM3 完整性校验通过" : "完整性校验失败", !result.valid);
          await loadKeys();
        } catch (error) { notice(error.message, true); }
      }));
      actions.append(actionButton("改索引", "", () => {
        const form = $("#reindex-form"); form.algorithm.value = key.algorithm; form.key_type.value = key.type;
        form.old_index.value = key.index; form.new_index.value = key.index;
        $("#reindex-dialog").showModal();
      }));
      actions.append(actionButton("有效期", "", () => openValidityDialog(key)));
      actions.append(actionButton(key.enabled ? "停用" : "启用", "", async () => {
        try { await api(`/api/keys/${key.type}/${key.index}/${key.enabled ? "disable" : "enable"}${algorithmQuery}`, { method: "POST", body: "{}" }); await loadKeys(); }
        catch (error) { notice(error.message, true); }
      }));
      actions.append(actionButton("导出公钥", "", async () => {
        try {
          const result = await api(`/api/keys/${key.type}/${key.index}/public${algorithmQuery}`);
          const copied = await copyText(result.data);
          notice(copied ? "公钥 Base64 已复制" : "已显示公钥 Base64，请手动复制");
        }
        catch (error) { notice(error.message, true); }
      }));
      actions.append(actionButton("改口令", "", () => {
        const form = $("#password-form"); form.algorithm.value = key.algorithm; form.key_type.value = key.type; form.index.value = key.index; $("#password-dialog").showModal();
      }));
      actions.append(actionButton("删除", "delete", () => {
        const form = $("#delete-form"); form.algorithm.value = key.algorithm; form.key_type.value = key.type; form.index.value = key.index; $("#delete-dialog").showModal();
      }));
      tr.append(actions); rows.append(tr);
    }
  } catch (error) { rows.innerHTML = ""; notice(error.message, true); }
}
async function loadDevice() {
  try {
    const device = await api("/api/device");
    const form = $("#device-form");
    form.vendor.value = device.vendor;
    form.device_name.value = device.device_name;
    form.serial.value = device.serial;
  } catch (error) { notice(error.message, true); }
}

async function loadAudit() {
  try {
    const filterParams = auditFilterParams();
    const [events, settings, options] = await Promise.all([
      api(`/api/audit?${filterParams}`), api("/api/audit/settings"), api("/api/audit/options"),
    ]);
    const settingsForm = $("#audit-settings-form");
    settingsForm.retention_days.value = settings.retention_days;
    settingsForm.display_level.value = settings.display_level;
    populateAuditSelect("categories", options.category || []);
    populateAuditSelect("results", options.result || []);
    const rows = $("#audit-rows");
    rows.innerHTML = "";
    if (!events.length) rows.innerHTML = '<tr><td colspan="12">当前筛选条件下暂无审计事件</td></tr>';
    for (const event of events) {
      const tr = document.createElement("tr");
      [
        new Date(event.occurred_at * 1000).toLocaleString(),
        event.level, event.category, event.username, event.action, event.target,
        event.result, event.remote_addr, event.request_id || "—", event.method || "—",
        event.path || "—", event.details || "—",
      ].forEach((value) => {
        const td = document.createElement("td");
        td.textContent = value;
        tr.append(td);
      });
      rows.append(tr);
    }
  } catch (error) { notice(error.message, true); }
}

function populateAuditSelect(name, values) {
  const select = $(`#audit-filter-form [name="${name}"]`);
  const selected = new Set([...select.selectedOptions].map((option) => option.value));
  select.innerHTML = "";
  for (const value of values) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    option.selected = selected.has(value);
    select.append(option);
  }
}

function auditFilterParams() {
  const form = $("#audit-filter-form");
  const params = new URLSearchParams();
  for (const name of ["levels", "categories", "results"]) {
    const values = [...form.elements[name].selectedOptions].map((option) => option.value);
    if (values.length) params.set(name, values.join(","));
  }
  for (const name of ["username", "action", "target", "remote_addr", "request_id", "method", "path", "keyword", "limit", "order"]) {
    const value = form.elements[name].value.trim();
    if (value) params.set(name, value);
  }
  for (const name of ["start_at", "end_at"]) {
    const value = form.elements[name].value;
    if (value) params.set(name, String(Math.floor(new Date(value).getTime() / 1000)));
  }
  return params;
}

$("#initialize-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  const password = data.password;
  form.password.value = "";
  try {
    data.password = await newPasswordMaterial(data.username.trim(), password, true);
    await api("/api/initialize", { method: "POST", body: JSON.stringify(data) });
    form.reset();
    showMode("login");
    notice("初始化完成，请登录");
  } catch (error) { notice(error.message, true); }
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const form = event.currentTarget;
  const data = formJson(form);
  const password = data.password;
  form.password.value = "";

  try {
    data.password = await passwordHashForUser(data.username.trim(), password);
    const result = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(data),
    });

    form.reset();
    showMode("app");
    applyAccess(result);
  } catch (error) {
    notice(error.message, true);
  }
});

$("#logout").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST", body: "{}" }); } catch (_) {}
  state.csrf = null;
  state.username = null;
  showMode("login");
});

$("#device-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    await api("/api/device", { method: "PATCH", body: JSON.stringify(formJson(form)) });
    notice("设备信息已保存");
    await loadDashboard();
  } catch (error) { notice(error.message, true); }
});

$("#open-key-dialog").addEventListener("click", () => $("#key-dialog").showModal());
$("#key-form [name=algorithm]").addEventListener("change", (event) => {
  const bits = $("#key-form [name=bits]");
  const rsa = event.currentTarget.value === "RSA";
  bits.value = rsa ? "2048" : "256";
  bits.min = rsa ? "1024" : "256";
  bits.max = rsa ? "2048" : "256";
});
$$("[data-close]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));

$("#key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  data.index = Number(data.index);
  data.bits = Number(data.bits);
  data.validity_days = Number(data.validity_days);
  try {
    await api("/api/keys", { method: "POST", body: JSON.stringify(data) });
    $("#key-dialog").close();
    form.reset();
    notice("内部密钥已生成");
    await loadKeys();
  } catch (error) { notice(error.message, true); }
});

$$("[data-auth-tab]").forEach((button) => {
  button.addEventListener("click", () => showAuthTab(button.dataset.authTab));
});

$("#ukey-login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $("button[type=submit]", form);
  const username = form.username.value.trim();
  const password = form.password.value;
  form.password.value = "";
  const popup = openUKeyBridge();
  if (!popup) {
    showUKeyAgentDialog();
    notice("浏览器未能打开 UKey PIN 窗口，请允许本站弹出窗口", true);
    return;
  }
  button.disabled = true;
  button.textContent = "正在验证 UKey…";
  try {
    const passwordHash = await passwordHashForUser(username, password);
    const challenge = await api("/api/auth/ukey/challenge", {
      method: "POST",
      body: JSON.stringify({ username, password: passwordHash }),
    });
    const signed = await signWithUKeyBridge(popup, challenge, username);
    const result = await api("/api/auth/ukey/verify", {
      method: "POST",
      body: JSON.stringify({
        username,
        challenge_id: challenge.challenge_id,
        signature_base64url: signed.signature_base64url,
        digest_base64url: signed.digest_base64url,
        certificate_base64: signed.certificate_base64,
      }),
    });
    form.reset();
    showMode("app");
    applyAccess(result);
  } catch (error) {
    if (error.ukeyAgentUnavailable) showUKeyAgentDialog();
    notice(error.message, true);
  } finally {
    if (!popup.closed) popup.close();
    button.disabled = false;
    button.textContent = "使用 UKey 登录";
  }
});

$("#retry-ukey-agent").addEventListener("click", () => {
  $("#ukey-agent-dialog").close();
  $("#ukey-login-form").requestSubmit();
});

$("#validity-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  const body = JSON.stringify({ validity_days: Number(data.validity_days) });
  const path = data.key_type === "kek"
    ? `/api/keks/${data.index}/validity`
    : `/api/keys/${data.key_type}/${data.index}/validity?algorithm=${encodeURIComponent(data.algorithm)}`;
  try {
    await api(path, { method: "PUT", body });
    $("#validity-dialog").close();
    notice("密钥有效期已更新");
    if (data.key_type === "kek" && typeof loadKeks === "function") await loadKeks();
    else await loadKeys();
  } catch (error) { notice(error.message, true); }
});

$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  try {
    await api("/api/keys/" + data.key_type + "/" + data.index + "/password?algorithm=" + encodeURIComponent(data.algorithm), {
      method: "POST",
      body: JSON.stringify({ old_password: data.old_password, new_password: data.new_password }),
    });
    $("#password-dialog").close();
    form.reset();
    notice("密钥口令已修改");
  } catch (error) { notice(error.message, true); }
});

$("#delete-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  const password = data.password;
  form.password.value = "";
  try {
    data.password = await currentPasswordHash(password);
    await api(`/api/keys/${data.key_type}/${data.index}?algorithm=${encodeURIComponent(data.algorithm)}`, {
      method: "DELETE",
      body: JSON.stringify({ password: data.password, confirmation: data.confirmation }),
    });
    $("#delete-dialog").close();
    form.reset();
    notice("内部密钥已删除");
    await loadKeys();
  } catch (error) { notice(error.message, true); }
});

async function loadAdministrators() {
  const rows = $("#admin-rows");
  rows.innerHTML = '<tr><td colspan="7">正在读取…</td></tr>';
  try {
    const users = await api("/api/administrators"); rows.innerHTML = "";
    for (const user of users) {
      const tr = document.createElement("tr");
      [user.username, user.role_label, user.enabled ? "启用" : "停用", user.login_mode_label, user.ukey_auth?.enabled ? "已启用" : user.ukey_auth ? "已配置/停用" : "未配置", new Date(user.created_at * 1000).toLocaleString()].forEach((value) => {
        const td = document.createElement("td"); td.textContent = value; tr.append(td);
      });
      const actions = document.createElement("td"); actions.className = "actions";
      actions.append(actionButton("配置", "", () => {
        const form = $("#admin-edit-form"); form.username.value = user.username;
        form.role.value = user.role; form.login_mode.value = user.login_mode;
        form.password.value = ""; form.enabled.checked = user.enabled;
        $("#admin-edit-dialog").showModal();
      }));
      actions.append(actionButton("UKey", "", () => {
        const form = $("#admin-ukey-form");
        form.reset();
        form.username.value = user.username;
        form.enabled.checked = user.ukey_auth?.enabled ?? true;
        $("#admin-ukey-account").textContent = `管理员：${user.username}`;
        const cert = user.ukey_auth?.validation?.user_certificate;
        $("#admin-ukey-summary").textContent = cert
          ? `主题：${cert.subject}\n颁发者：${cert.issuer}\n序列号：${cert.serial_number}\n有效期：${cert.not_before} ～ ${cert.not_after}\nSHA-256：${cert.sha256_fingerprint}`
          : "尚未配置";
        $("#remove-admin-ukey").hidden = !user.ukey_auth;
        $("#admin-ukey-dialog").showModal();
      }));
      actions.append(actionButton("删除", "delete", () => {
        const form = $("#admin-delete-form"); form.username.value = user.username;
        $("#admin-delete-dialog").showModal();
      }));
      tr.append(actions); rows.append(tr);
    }
  } catch (error) { rows.innerHTML = ""; notice(error.message, true); }
}

$("#open-admin-dialog").addEventListener("click", () => $("#admin-dialog").showModal());
$("#admin-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formJson(form);
  const password = data.password; form.password.value = "";
  try { data.password = await newPasswordMaterial(data.username.trim(), password); await api("/api/administrators", { method: "POST", body: JSON.stringify(data) }); $("#admin-dialog").close(); form.reset(); notice("管理员已创建"); await loadAdministrators(); }
  catch (error) { notice(error.message, true); }
});
$("#admin-edit-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formJson(form);
  const body = { role: data.role, login_mode: data.login_mode, enabled: form.enabled.checked };
  const password = data.password; form.password.value = "";
  try { if (password) body.password = await newPasswordMaterial(data.username, password); await api(`/api/administrators/${encodeURIComponent(data.username)}`, { method: "PATCH", body: JSON.stringify(body) }); $("#admin-edit-dialog").close(); form.reset(); notice("管理员配置已保存"); await loadAdministrators(); }
  catch (error) { notice(error.message, true); }
});
$("#admin-delete-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formJson(form);
  const password = data.password; form.password.value = "";
  try { const passwordHash = await currentPasswordHash(password); await api(`/api/administrators/${encodeURIComponent(data.username)}`, { method: "DELETE", body: JSON.stringify({ password: passwordHash, confirmation: data.confirmation }) }); $("#admin-delete-dialog").close(); form.reset(); notice("管理员已删除"); await loadAdministrators(); }
  catch (error) { notice(error.message, true); }
});
$("#reindex-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formJson(form);
  try { await api(`/api/keys/${data.key_type}/${data.old_index}/reindex?algorithm=${encodeURIComponent(data.algorithm)}`, { method: "POST", body: JSON.stringify({ new_index: Number(data.new_index) }) }); $("#reindex-dialog").close(); form.reset(); notice("密钥索引已修改并重新计算完整性值"); await loadKeys(); }
  catch (error) { notice(error.message, true); }
});
$("#run-selftest").addEventListener("click", async () => {
  const output = $("#selftest-output");
  output.textContent = "正在执行…";
  try {
    const result = await api("/api/crypto/selftest", { method: "POST", body: "{}" });
    output.textContent = "总体: " + result.status + "\n" +
      "随机数: " + result.random.status + " (" + result.random.bytes + " 字节)\n" +
      "SM3: " + result.sm3.status + " (" + result.sm3.vector + " 已知向量)\n" +
      "SM4: " + result.sm4.status + " (" + result.sm4.mode + " 回环)\n" +
      "SM2: " + result.sm2.status + " (临时密钥签名验签)\n" +
      "RSA: " + result.rsa.status + " (" + result.rsa.bits + " 位临时密钥私钥/公钥回环)\n" +
      "耗时: " + result.elapsed_ms + " ms";
  } catch (error) {
    output.textContent = error.message;
    notice(error.message, true);
  }
});

$("#run-random").addEventListener("click", async () => {
  const output = $("#random-output");
  output.textContent = "正在执行…";
  try {
    const result = await api(`/api/crypto/random?length=${Number($("#random-length").value)}`, { method: "POST", body: "{}" });
    output.textContent = `长度: ${result.length} 字节\n耗时: ${result.elapsed_ms} ms\n\n${result.hex}`;
  } catch (error) {
    output.textContent = error.message;
    notice(error.message, true);
  }
});

$("#audit-settings-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = formJson(form);
  try {
    await api("/api/audit/settings", { method: "PATCH", body: JSON.stringify({
      retention_days: Number(data.retention_days), display_level: data.display_level,
    }) });
    notice("审计日志配置已保存"); await loadAudit();
  } catch (error) { notice(error.message, true); }
});
$("#refresh-audit").addEventListener("click", loadAudit);
$("#audit-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault(); await loadAudit();
});

$("#admin-ukey-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const userCertificate = form.user_certificate.files[0];
  const caCertificate = form.ca_certificate.files[0];
  if (!userCertificate || !caCertificate) {
    notice("请选择用户签名证书和 CA 证书", true);
    return;
  }
  try {
    const result = await api(`/api/administrators/${encodeURIComponent(form.username.value)}/ukey`, {
      method: "PUT",
      body: JSON.stringify({
        enabled: form.enabled.checked,
        user_certificate_base64: await fileBase64(userCertificate),
        ca_certificate_base64: await fileBase64(caCertificate),
      }),
    });
    const cert = result.validation.user_certificate;
    $("#admin-ukey-summary").textContent = `主题：${cert.subject}\n颁发者：${cert.issuer}\n序列号：${cert.serial_number}\n有效期：${cert.not_before} ～ ${cert.not_after}\nSHA-256：${cert.sha256_fingerprint}`;
    $("#remove-admin-ukey").hidden = false;
    notice("UKey 证书链校验通过，身份鉴别配置已保存");
    await loadAdministrators();
  } catch (error) {
    notice(error.message, true);
  }
});

$("#remove-admin-ukey").addEventListener("click", async () => {
  const form = $("#admin-ukey-form");
  if (!window.confirm(`确认移除管理员 ${form.username.value} 的 UKey 身份鉴别配置？`)) return;
  try {
    await api(`/api/administrators/${encodeURIComponent(form.username.value)}/ukey`, { method: "DELETE", body: "{}" });
    $("#admin-ukey-dialog").close();
    notice("UKey 身份鉴别配置已移除");
    await loadAdministrators();
  } catch (error) { notice(error.message, true); }
});
$("#audit-filter-form").addEventListener("reset", () => setTimeout(loadAudit, 0));
$("#audit-export-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const params = auditFilterParams();
  params.set("format", form.elements.format.value);
  params.set("limit", form.elements.limit.value);
  params.set("order", form.elements.order.value);
  params.set("include_header", form.elements.include_header.checked ? "true" : "false");
  const fields = [...form.querySelectorAll('input[name="fields"]:checked')].map((item) => item.value);
  if (!fields.length) { notice("请至少选择一个导出字段", true); return; }
  params.set("fields", fields.join(","));
  window.location.assign(`/api/audit/export?${params}`);
});
$("#refresh-service").addEventListener("click", async () => {
  try { await loadService(); } catch (error) { notice(error.message, true); }
});
$("#start-service").addEventListener("click", () => openServiceDialog("start"));
$("#stop-service").addEventListener("click", () => openServiceDialog("stop"));
$("#restart-service").addEventListener("click", () => openServiceDialog("restart"));
$("#service-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  const submit = $("#service-submit");
  submit.disabled = true;
  try {
    await api(`/api/service/${data.action}`, {
      method: "POST",
      body: JSON.stringify({ confirmation: data.confirmation }),
    });
    $("#service-dialog").close();
    form.reset();
    notice(data.action === "start" ? "密码服务已启动" : data.action === "stop" ? "密码服务已停止，Web 管理端仍保持在线" : "密码服务已重启");
    await loadService();
  } catch (error) {
    notice(error.message, true);
  } finally {
    submit.disabled = false;
  }
});
$$("#nav button").forEach((button) => button.addEventListener("click", () => switchPage(button.dataset.page)));

(async function bootstrap() {
  try {
    const health = await api("/api/health");
    state.initialized = health.initialized;
    const daemonRunning = health.daemon?.running && health.daemon?.daemon_available;
    setService(daemonRunning, daemonRunning ? "密码服务运行正常" : "密码服务已停止（Web 正常）");
    if (!health.initialized) {
      showMode("initialize");
      return;
    }
    try {
      const session = await api("/api/auth/session");
      showMode("app");
      applyAccess(session);
    } catch (_) {
      showMode("login");
    }
  } catch (error) {
    setService(false, "密码服务不可用");
    showMode("login");
    notice(error.message, true);
  }
})();
