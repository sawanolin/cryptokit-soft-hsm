"use strict";

async function loadKeks() {
  const rows = $("#kek-rows");
  if (!rows) return;
  rows.innerHTML = '<tr><td colspan="7">正在读取…</td></tr>';
  try {
    const keks = await api("/api/keks");
    rows.innerHTML = "";
    if (!keks.length) {
      rows.innerHTML = '<tr><td colspan="7">尚未生成对称密钥</td></tr>';
      return;
    }
    for (const kek of keks) {
      const tr = document.createElement("tr");
      ["会话密钥封装", kek.index, `${kek.algorithm}-${kek.bits}`].forEach((value) => {
        const td = document.createElement("td");
        td.textContent = value;
        tr.append(td);
      });

      const statusCell = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `status ${kek.enabled ? "ok" : "off"}`;
      badge.textContent = kek.enabled ? "启用" : "停用";
      statusCell.append(badge);
      tr.append(statusCell);

      const integrityCell = document.createElement("td");
      const integrityBadge = document.createElement("span");
      integrityBadge.className = `status ${kek.integrity === false ? "off" : "ok"}`;
      integrityBadge.textContent = kek.integrity === false ? "异常" : "已保护";
      integrityCell.append(integrityBadge);
      tr.append(integrityCell);

      const fingerprint = document.createElement("td");
      fingerprint.className = "fingerprint";
      fingerprint.title = kek.fingerprint;
      fingerprint.textContent = kek.fingerprint;
      tr.append(fingerprint);

      const actions = document.createElement("td");
      actions.className = "actions";
      actions.append(actionButton("校验", "", async () => {
        try {
          const result = await api(`/api/keks/${kek.index}/verify`, {
            method: "POST",
            body: "{}",
          });
          notice(result.valid ? "HMAC-SM3 完整性校验通过" : "完整性校验失败", !result.valid);
        } catch (error) {
          notice(error.message, true);
        }
      }));
      actions.append(actionButton(kek.enabled ? "停用" : "启用", "", async () => {
        try {
          await api(`/api/keks/${kek.index}/${kek.enabled ? "disable" : "enable"}`, {
            method: "POST",
            body: "{}",
          });
          await loadKeks();
        } catch (error) {
          notice(error.message, true);
        }
      }));
      actions.append(actionButton("删除", "delete", () => {
        const form = $("#kek-delete-form");
        form.index.value = kek.index;
        $("#kek-delete-dialog").showModal();
      }));
      tr.append(actions);
      rows.append(tr);
    }
  } catch (error) {
    rows.innerHTML = "";
    notice(error.message, true);
  }
}

$("#open-kek-dialog").addEventListener("click", () => $("#kek-dialog").showModal());

$("#kek-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  data.index = Number(data.index);
  try {
    await api("/api/keks", { method: "POST", body: JSON.stringify(data) });
    $("#kek-dialog").close();
    form.reset();
    notice("对称密钥已生成");
    await loadKeks();
  } catch (error) {
    notice(error.message, true);
  }
});

$("#kek-delete-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  try {
    await api(`/api/keks/${data.index}`, {
      method: "DELETE",
      body: JSON.stringify({
        password: data.password,
        confirmation: data.confirmation,
      }),
    });
    $("#kek-delete-dialog").close();
    form.reset();
    notice("对称密钥已删除");
    await loadKeks();
  } catch (error) {
    notice(error.message, true);
  }
});
