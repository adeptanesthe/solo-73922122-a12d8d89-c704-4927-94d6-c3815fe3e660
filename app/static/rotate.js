/* HTTPS 证书轮换页逻辑（原生 JS，无构建步骤）。 */

const state = {
  current: null,
  samples: [],
  busy: false,
};

function $(id) {
  return document.getElementById(id);
}

function clearMessages() {
  $("error-banner").hidden = true;
  $("success-banner").hidden = true;
}

function showError(message) {
  const banner = $("error-banner");
  banner.textContent = message;
  banner.hidden = false;
  $("success-banner").hidden = true;
  banner.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function showSuccess(message) {
  const banner = $("success-banner");
  banner.textContent = message;
  banner.hidden = false;
  $("error-banner").hidden = true;
}

function formatApiError(data) {
  if (data && Array.isArray(data.errors) && data.errors.length > 0) {
    return data.errors.join("\n");
  }
  if (data && typeof data.detail === "string") {
    return data.detail;
  }
  if (data && Array.isArray(data.detail)) {
    return data.detail
      .map((item) => {
        const loc = (item.loc || []).filter((p) => p !== "body").join(" → ");
        return `${loc}: ${item.msg}`;
      })
      .join("\n");
  }
  return "未知错误";
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = { detail: `响应不是 JSON（HTTP ${response.status}）` };
  }
  if (!response.ok) {
    const error = new Error(formatApiError(data));
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function formatFingerprint(hex) {
  if (!hex) return "";
  return hex
    .toUpperCase()
    .match(/(.{2})/g)
    .join(":");
}

// --------------------------------------------------------------------------- //
// 当前活动证书
// --------------------------------------------------------------------------- //
function stateItem(label, value, options = {}) {
  const item = document.createElement("div");
  item.className = "state-item";

  const labelEl = document.createElement("div");
  labelEl.className = "state-label";
  labelEl.textContent = label;
  item.appendChild(labelEl);

  const valueEl = document.createElement(options.code ? "code" : "div");
  valueEl.className = `state-value${options.code ? " fingerprint" : ""}`;
  valueEl.textContent = value;
  item.appendChild(valueEl);
  return item;
}

function renderState(data) {
  state.current = data;
  const grid = $("current-state");
  grid.innerHTML = "";

  grid.appendChild(stateItem("工作进程", data.worker || "—"));
  grid.appendChild(stateItem("活动版本", String(data.version)));
  grid.appendChild(
    stateItem(
      "握手证书 SHA-256",
      data.fingerprint_display || formatFingerprint(data.fingerprint_sha256),
      { code: true }
    )
  );
  grid.appendChild(stateItem("证书主题", data.subject || "—", { code: true }));
  grid.appendChild(
    stateItem(
      "DNS SAN",
      Array.isArray(data.san_dns) && data.san_dns.length
        ? data.san_dns.join(", ")
        : "—"
    )
  );
  grid.appendChild(
    stateItem(
      "有效期",
      `${data.not_before || "—"} → ${data.not_after || "—"}`
    )
  );
  grid.appendChild(stateItem("启用来源", data.origin || "—"));
  grid.appendChild(stateItem("启用时间", data.activated_at || "—"));

  const expectedInput = $("expected-version");
  expectedInput.value = String(data.version);
}

async function loadState(clear = true) {
  if (clear) {
    clearMessages();
  }
  try {
    const data = await fetchJson("/api/rotate/state", { cache: "no-store" });
    renderState(data);
  } catch (err) {
    showError(`读取当前证书失败：${err.message}`);
  }
}

// --------------------------------------------------------------------------- //
// 本地样例
// --------------------------------------------------------------------------- //
async function loadSamples() {
  try {
    const data = await fetchJson("/api/rotate/samples", { cache: "no-store" });
    state.samples = data.samples || [];
  } catch (err) {
    showError(`载入本地轮换样例失败：${err.message}`);
  }
}

async function loadSample(sampleKey) {
  if (state.samples.length === 0) {
    await loadSamples();
  }
  if (!state.current) {
    await loadState(false);
  }
  const sample = state.samples.find((item) => item.key === sampleKey);
  if (!sample) {
    showError(`未找到样例 ${sampleKey}`);
    return;
  }
  $("cert-pem").value = sample.cert_pem;
  $("key-pem").value = sample.key_pem;
  $("cert-file").value = "";
  $("key-file").value = "";
  $("sample-note").textContent = `${sample.label} · 指纹 ${sample.fingerprint_display}（${sample.note}）`;
  if (state.current) {
    $("expected-version").value = String(state.current.version);
  }
  clearMessages();
}

function wireFileInput(fileInputId, textareaId) {
  $(fileInputId).addEventListener("change", async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    try {
      $(textareaId).value = await file.text();
      $("sample-note").textContent = `已读取文件：${file.name}`;
      clearMessages();
    } catch (err) {
      showError(`读取文件失败：${err.message}`);
    }
  });
}

// --------------------------------------------------------------------------- //
// 原子启用
// --------------------------------------------------------------------------- //
async function activate(event) {
  event.preventDefault();
  clearMessages();

  const certPem = $("cert-pem").value;
  const keyPem = $("key-pem").value;
  const expectedRaw = $("expected-version").value;

  if (!certPem.trim()) {
    showError("请上传或粘贴证书 PEM");
    return;
  }
  if (!keyPem.trim()) {
    showError("请上传或粘贴未加密 RSA 私钥 PEM");
    return;
  }
  if (expectedRaw.trim() === "" || !Number.isInteger(Number(expectedRaw))) {
    showError("预期当前版本必须是整数");
    return;
  }

  const payload = {
    cert_pem: certPem,
    key_pem: keyPem,
    expected_version: Number(expectedRaw),
  };

  const button = $("btn-activate");
  state.busy = true;
  button.disabled = true;
  button.textContent = "校验中…";
  try {
    const result = await fetchJson("/api/rotate/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    showSuccess(result.message || `已启用版本 ${result.version}`);
    $("sample-note").textContent = `新活动版本 ${result.version} · 握手指纹 ${result.fingerprint_display}`;
    await loadState(false);
    await probe();
  } catch (err) {
    showError(err.message);
    if (err.status === 409) {
      await loadState(false);
    }
  } finally {
    state.busy = false;
    button.disabled = false;
    button.textContent = "校验并原子启用（版本 +1）";
  }
}

// --------------------------------------------------------------------------- //
// 双进程握手探测
// --------------------------------------------------------------------------- //
function probeCell(text, className) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = text == null ? "—" : String(text);
  return cell;
}

function renderProbe(data) {
  const rows = $("probe-rows");
  rows.innerHTML = "";
  const targets = data.targets || [];
  const okCount = targets.filter((item) => item.ok).length;

  $("probe-summary").textContent =
    `探测时间 ${data.probed_at || "—"}：${okCount}/${targets.length} 个进程握手成功。`;

  targets.forEach((target) => {
    const tr = document.createElement("tr");

    const nameCell = document.createElement("td");
    const name = document.createElement("strong");
    name.textContent = target.name || "—";
    nameCell.appendChild(name);
    if (target.worker) {
      const worker = document.createElement("div");
      worker.className = "hint";
      worker.textContent = `进程自报：${target.worker}`;
      nameCell.appendChild(worker);
    }
    tr.appendChild(nameCell);

    tr.appendChild(probeCell(target.display_url || target.url, "url-cell"));

    if (target.ok) {
      const fpCell = document.createElement("td");
      const fp = document.createElement("code");
      fp.className = "fingerprint";
      fp.textContent =
        target.fingerprint_display || formatFingerprint(target.fingerprint_sha256);
      fpCell.appendChild(fp);
      tr.appendChild(fpCell);
    } else {
      const fpCell = document.createElement("td");
      fpCell.className = "error-cell";
      fpCell.textContent = "握手失败";
      tr.appendChild(fpCell);
    }

    tr.appendChild(
      probeCell(
        target.ok ? target.version : "—",
        "version-cell"
      )
    );

    const statusCell = document.createElement("td");
    if (target.ok) {
      const line = document.createElement("div");
      line.textContent = `${target.tls_version || "TLS"} · 握手成功`;
      statusCell.appendChild(line);
      if (target.state_matches_handshake === false) {
        const warn = document.createElement("div");
        warn.className = "error-cell";
        warn.textContent = "警告：握手指纹与进程报告不一致";
        statusCell.appendChild(warn);
      } else {
        const ok = document.createElement("div");
        ok.className = "ok-cell";
        ok.textContent = "握手指纹与活动版本一致";
        statusCell.appendChild(ok);
      }
    } else {
      statusCell.className = "error-cell";
      statusCell.textContent = target.error || "探测失败";
    }
    tr.appendChild(statusCell);

    tr.appendChild(probeCell(`${target.elapsed_ms ?? "—"} ms`, "hint"));
    rows.appendChild(tr);
  });
}

async function probe() {
  const button = $("btn-probe");
  button.disabled = true;
  button.textContent = "探测中…";
  try {
    const data = await fetchJson("/api/rotate/probe", { cache: "no-store" });
    renderProbe(data);
  } catch (err) {
    showError(`探测两个工作进程失败：${err.message}`);
  } finally {
    button.disabled = false;
    button.textContent = "重新探测两个进程";
  }
}

// --------------------------------------------------------------------------- //
// 初始化
// --------------------------------------------------------------------------- //
document.addEventListener("DOMContentLoaded", async () => {
  $("rotate-form").addEventListener("submit", activate);
  $("btn-probe").addEventListener("click", probe);
  document.querySelectorAll("[data-sample]").forEach((button) => {
    button.addEventListener("click", () => loadSample(button.dataset.sample));
  });
  wireFileInput("cert-file", "cert-pem");
  wireFileInput("key-file", "key-pem");

  await loadState();
  await loadSamples();
  await probe();
});
