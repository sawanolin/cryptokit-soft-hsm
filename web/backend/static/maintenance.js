"use strict";

function humanSize(bytes) {
  const units = ["B", "KiB", "MiB", "GiB"];
  let value = Number(bytes);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function newBackupId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function loadBackups() {
  const rows = $("#backup-rows");
  if (!rows) return;
  rows.innerHTML = '<tr><td colspan="4">正在读取…</td></tr>';
  try {
    const backups = await api("/api/backups");
    rows.innerHTML = "";
    if (!backups.length) {
      rows.innerHTML = '<tr><td colspan="4">尚未创建备份</td></tr>';
      return;
    }
    backups.sort((a, b) => b.created_at - a.created_at);
    for (const backup of backups) {
      const tr = document.createElement("tr");
      [
        backup.id,
        new Date(backup.created_at * 1000).toLocaleString(),
        humanSize(backup.size),
      ].forEach((value) => {
        const td = document.createElement("td");
        td.textContent = value;
        if (value === backup.id) td.className = "fingerprint";
        tr.append(td);
      });
      const actions = document.createElement("td");
      actions.className = "actions";
      actions.append(actionButton("下载", "", () => {
        window.location.assign(`/api/backups/${backup.id}/download`);
      }));
      actions.append(actionButton("恢复", "", () => {
        const form = $("#backup-restore-form");
        form.backup_id.value = backup.id;
        $("#backup-restore-dialog").showModal();
      }));
      actions.append(actionButton("删除", "delete", () => {
        const form = $("#backup-delete-form");
        form.backup_id.value = backup.id;
        $("#backup-delete-dialog").showModal();
      }));
      tr.append(actions);
      rows.append(tr);
    }
  } catch (error) {
    rows.innerHTML = "";
    notice(error.message, true);
  }
}

$("#create-backup").addEventListener("click", async () => {
  try {
    await api("/api/backups", { method: "POST", body: "{}" });
    notice("设备备份已创建");
    await loadBackups();
  } catch (error) {
    notice(error.message, true);
  }
});

$("#backup-upload").addEventListener("change", async (event) => {
  const input = event.currentTarget;
  const file = input.files[0];
  if (!file) return;
  const backupId = newBackupId();
  try {
    const response = await fetch(`/api/backups/upload?backup_id=${backupId}`, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-CSRF-Token": state.csrf,
      },
      body: file,
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(result.detail || result.error?.message || `上传失败（${response.status}）`);
    }
    notice("备份已上传；恢复时将由密码服务校验格式");
    await loadBackups();
  } catch (error) {
    notice(error.message, true);
  } finally {
    input.value = "";
  }
});

$("#backup-restore-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  const password = data.password;
  form.password.value = "";
  try {
    data.password = await currentPasswordHash(password);
    await api("/api/backups/restore", {
      method: "POST",
      body: JSON.stringify(data),
    });
    $("#backup-restore-dialog").close();
    form.reset();
    state.csrf = null;
    state.username = null;
    showMode("login");
    notice("备份恢复完成，请使用恢复后的管理员凭据重新登录");
  } catch (error) {
    notice(error.message, true);
  }
});

$("#backup-delete-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  const password = data.password;
  form.password.value = "";
  try {
    const passwordHash = await currentPasswordHash(password);
    await api(`/api/backups/${data.backup_id}`, {
      method: "DELETE",
      body: JSON.stringify({
        password: passwordHash,
        confirmation: data.confirmation,
      }),
    });
    $("#backup-delete-dialog").close();
    form.reset();
    notice("备份已删除");
    await loadBackups();
  } catch (error) {
    notice(error.message, true);
  }
});

$("#open-reset-dialog").addEventListener("click", () => $("#reset-dialog").showModal());

$("#reset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formJson(form);
  const password = data.password;
  form.password.value = "";
  try {
    data.password = await currentPasswordHash(password);
    await api("/api/device/reset", {
      method: "POST",
      body: JSON.stringify(data),
    });
    $("#reset-dialog").close();
    form.reset();
    state.csrf = null;
    state.username = null;
    showMode("initialize");
    notice("设备已经完全重置，需要重新初始化");
  } catch (error) {
    notice(error.message, true);
  }
});
