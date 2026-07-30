"use strict";

async function loadSessions() {
  const rows = $("#session-rows");
  rows.innerHTML = '<tr><td colspan="6">正在读取…</td></tr>';
  try {
    const sessions = await api("/api/sessions");
    rows.innerHTML = "";
    if (!sessions.length) {
      rows.innerHTML = '<tr><td colspan="6">当前没有活动 SDF 会话</td></tr>';
      return;
    }
    for (const session of sessions) {
      const row = document.createElement("tr");
      [
        session.session_id,
        session.device_id,
        new Date(session.created_at * 1000).toLocaleString(),
        new Date(session.last_access * 1000).toLocaleString(),
      ].forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.append(cell);
      });
      const statusCell = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `status ${session.active ? "ok" : "off"}`;
      badge.textContent = session.active ? "活动" : "关闭";
      statusCell.append(badge);
      row.append(statusCell);

      const actions = document.createElement("td");
      const terminate = actionButton("终止", "delete", () => {
        const form = $("#session-form");
        form.session_id.value = session.session_id;
        $("#session-dialog").showModal();
      });
      actions.append(terminate);
      row.append(actions);
      rows.append(row);
    }
  } catch (error) {
    rows.innerHTML = "";
    notice(error.message, true);
  }
}

$('[data-page="sessions"]').addEventListener("click", () => {
  $("#page-title").textContent = "会话管理";
  loadSessions();
});

$("#refresh-sessions").addEventListener("click", loadSessions);

$("#session-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const form = event.currentTarget;
  const data = formJson(form);

  try {
    await api(`/api/sessions/${data.session_id}`, {
      method: "DELETE",
      body: JSON.stringify({
        password: data.password,
        confirmation: data.confirmation,
      }),
    });

    $("#session-dialog").close();
    form.reset();
    notice("SDF 会话已终止");
    await loadSessions();
  } catch (error) {
    notice(error.message, true);
  }
});
