/* 防火墙规则变更核对工具前端逻辑（原生 JS，无构建步骤）。 */

const MAX_RULES = 20;

const state = {
  old_rules: [],
  new_rules: [],
};

const emptyRule = () => ({
  src_cidr: "",
  dst_cidr: "",
  port_low: 0,
  port_high: 65535,
  action: "deny",
});

// --------------------------------------------------------------------------- //
// 规则表渲染
// --------------------------------------------------------------------------- //
function renderTable(key) {
  const tbody = document.getElementById(`tbody-${key}`);
  tbody.innerHTML = "";

  if (state[key].length === 0) {
    const tr = document.createElement("tr");
    tr.className = "empty-row";
    tr.innerHTML = '<td colspan="7">暂无规则，点击右上角“添加规则”或载入示例</td>';
    tbody.appendChild(tr);
    return;
  }

  state[key].forEach((rule, idx) => {
    const tr = document.createElement("tr");

    tr.appendChild(textTd(String(idx + 1)));
    tr.appendChild(inputTd(key, rule, idx, "src_cidr", "text", "10.0.0.0/8"));
    tr.appendChild(inputTd(key, rule, idx, "dst_cidr", "text", "192.168.0.0/16"));
    tr.appendChild(inputTd(key, rule, idx, "port_low", "number", "0-65535"));
    tr.appendChild(inputTd(key, rule, idx, "port_high", "number", "0-65535"));
    tr.appendChild(actionTd(key, rule, idx));

    const opsTd = document.createElement("td");
    const up = smallButton("↑", () => moveRule(key, idx, -1), idx === 0);
    const down = smallButton("↓", () => moveRule(key, idx, 1), idx === state[key].length - 1);
    const del = smallButton("删除", () => removeRule(key, idx), false);
    opsTd.append(up, down, del);
    tr.appendChild(opsTd);

    tbody.appendChild(tr);
  });
}

function textTd(text) {
  const cell = document.createElement("td");
  cell.textContent = text;
  return cell;
}

function inputTd(key, rule, idx, field, type, placeholder) {
  const cell = document.createElement("td");
  const input = document.createElement("input");
  input.type = type;
  input.placeholder = placeholder || "";
  input.value = rule[field];
  if (type === "number") {
    input.min = 0;
    input.max = 65535;
  }
  input.addEventListener("input", () => {
    state[key][idx][field] = type === "number" ? normalizePort(input.value) : input.value.trim();
  });
  cell.appendChild(input);
  return cell;
}

function actionTd(key, rule, idx) {
  const cell = document.createElement("td");
  const select = document.createElement("select");
  for (const value of ["allow", "deny"]) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = value === "allow" ? "允许 allow" : "拒绝 deny";
    select.appendChild(opt);
  }
  select.value = rule.action;
  select.addEventListener("change", () => {
    state[key][idx].action = select.value;
  });
  cell.appendChild(select);
  return cell;
}

function normalizePort(value) {
  if (value === "") return "";
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : value;
}

function smallButton(text, onClick, disabled) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn btn-small btn-move";
  btn.textContent = text;
  btn.disabled = !!disabled;
  btn.addEventListener("click", onClick);
  return btn;
}

function addRule(key) {
  if (state[key].length >= MAX_RULES) {
    showError(`每份规则表最多 ${MAX_RULES} 条规则`);
    return;
  }
  state[key].push(emptyRule());
  renderAll();
}

function removeRule(key, idx) {
  state[key].splice(idx, 1);
  renderAll();
}

function moveRule(key, idx, delta) {
  const target = idx + delta;
  if (target < 0 || target >= state[key].length) return;
  const list = state[key];
  [list[idx], list[target]] = [list[target], list[idx]];
  renderAll();
}

function renderAll() {
  renderTable("old_rules");
  renderTable("new_rules");
}

// --------------------------------------------------------------------------- //
// 结果渲染
// --------------------------------------------------------------------------- //
function fmtCount(n) {
  return n.toLocaleString("en-US");
}

function renderResults(data) {
  const results = document.getElementById("results");
  results.hidden = false;

  const s = data.stats;
  document.getElementById("results-summary").innerHTML = `
    <span class="stat">空间切分：<b>${fmtCount(s.grid_cells)}</b> 个基本单元
      （源段 ${s.src_segments} × 目标段 ${s.dst_segments} × 端口段 ${s.port_segments}）</span>
    <span class="stat">新增放行区域：<b style="color:var(--allow)">${s.allowed_region_count}</b> 个，
      覆盖连接 <b>${fmtCount(s.allowed_connection_count)}</b> 条</span>
    <span class="stat">新增阻断区域：<b style="color:var(--block)">${s.blocked_region_count}</b> 个，
      覆盖连接 <b>${fmtCount(s.blocked_connection_count)}</b> 条</span>`;

  renderRegionList("allowed-regions", data.newly_allowed, "allow");
  renderRegionList("blocked-regions", data.newly_blocked, "block");
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderRegionList(elementId, regions, kind) {
  const el = document.getElementById(elementId);
  el.innerHTML = "";
  if (regions.length === 0) {
    const div = document.createElement("div");
    div.className = "no-change";
    div.textContent = kind === "allow" ? "无新增放行连接。" : "无新增阻断连接。";
    el.appendChild(div);
    return;
  }
  regions.forEach((region) => el.appendChild(regionCard(region, kind)));
}

function regionCard(region, kind) {
  const card = document.createElement("div");
  card.className = `region-card ${kind}`;

  const head = document.createElement("div");
  head.className = "region-head";
  head.innerHTML = `
    <span class="region-id">区域 #${region.id}（${kind === "allow" ? "新增放行" : "新增阻断"}）</span>
    <span class="region-meta">该区域共包含 ${fmtCount(region.connection_count)} 条连接
      （源 IP 数 × 目标 IP 数 × 端口数）</span>`;
  card.appendChild(head);

  const grid = document.createElement("div");
  grid.className = "segment-grid";
  grid.appendChild(segmentBox("源地址段（互不重叠）", region.src_segment, true));
  grid.appendChild(segmentBox("目标地址段（互不重叠）", region.dst_segment, true));
  grid.appendChild(segmentBox("TCP 目标端口段（闭区间）", region.port_segment, false));
  card.appendChild(grid);

  const sample = document.createElement("div");
  sample.className = "sample-line";
  sample.innerHTML = `示例连接：<code>${escapeHtml(region.sample_connection.label)}</code>`;
  card.appendChild(sample);

  const hits = document.createElement("div");
  hits.className = "hit-grid";
  hits.appendChild(hitBox("旧规则侧命中", region.old_side));
  hits.appendChild(hitBox("新规则侧命中", region.new_side));
  card.appendChild(hits);

  return card;
}

function segmentBox(label, segment, isIp) {
  const box = document.createElement("div");
  box.className = "segment-box";
  const lab = document.createElement("div");
  lab.className = "seg-label";
  lab.textContent = label;
  box.appendChild(lab);

  const value = document.createElement("div");
  value.className = "seg-value";
  value.textContent = segment.label;
  box.appendChild(value);

  if (isIp && segment.cidrs && segment.cidrs.length > 1) {
    const ul = document.createElement("ul");
    ul.className = "cidr-list";
    segment.cidrs.forEach((cidr) => {
      const li = document.createElement("li");
      li.textContent = cidr;
      ul.appendChild(li);
    });
    box.appendChild(ul);
  }
  return box;
}

function hitBox(sideLabel, hit) {
  const box = document.createElement("div");
  const cls = hit.kind === "default_deny" ? "default" : hit.rule.action;
  box.className = `hit-box ${cls}`;

  const side = document.createElement("div");
  side.className = "hit-side";
  side.textContent = sideLabel;
  box.appendChild(side);

  const body = document.createElement("code");
  body.textContent = hit.label;
  box.appendChild(body);
  return box;
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// --------------------------------------------------------------------------- //
// 交互与 API 调用
// --------------------------------------------------------------------------- //
function showError(message) {
  const banner = document.getElementById("error-banner");
  banner.textContent = message;
  banner.hidden = false;
}

function clearError() {
  document.getElementById("error-banner").hidden = true;
}

function validateBeforeSubmit() {
  for (const key of ["old_rules", "new_rules"]) {
    if (state[key].length === 0) {
      return `${key === "old_rules" ? "旧" : "新"}规则表不能为空（允许只写默认拒绝规则）`;
    }
    for (let i = 0; i < state[key].length; i += 1) {
      const r = state[key][i];
      if (!r.src_cidr || !r.dst_cidr) {
        return `${key === "old_rules" ? "旧" : "新"}规则表第 ${i + 1} 条：源/目标 CIDR 不能为空`;
      }
      if (r.port_low === "" || r.port_high === "") {
        return `${key === "old_rules" ? "旧" : "新"}规则表第 ${i + 1} 条：端口不能为空`;
      }
      if (Number(r.port_low) > Number(r.port_high)) {
        return `${key === "old_rules" ? "旧" : "新"}规则表第 ${i + 1} 条：端口下限不能大于上限`;
      }
    }
  }
  return null;
}

async function analyze() {
  clearError();
  const validationError = validateBeforeSubmit();
  if (validationError) {
    showError(validationError);
    return;
  }

  const payload = {
    old_rules: state.old_rules.map(normalizeRule),
    new_rules: state.new_rules.map(normalizeRule),
  };

  try {
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showError(formatApiError(data));
      return;
    }
    renderResults(data);
  } catch (err) {
    showError(`请求失败：${err.message}`);
  }
}

function normalizeRule(r) {
  return {
    src_cidr: r.src_cidr,
    dst_cidr: r.dst_cidr,
    port_low: Number(r.port_low),
    port_high: Number(r.port_high),
    action: r.action,
  };
}

function formatApiError(data) {
  if (typeof data.detail === "string") return data.detail;
  if (Array.isArray(data.detail)) {
    return data.detail
      .map((e) => {
        const loc = (e.loc || []).filter((p) => p !== "body").join(" → ");
        return `${loc}: ${e.msg}`;
      })
      .join("\n");
  }
  return "未知错误";
}

async function loadExample() {
  clearError();
  const resp = await fetch("/api/example");
  const data = await resp.json();
  state.old_rules = data.old_rules.map(clone);
  state.new_rules = data.new_rules.map(clone);
  renderAll();
}

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function clearAll() {
  state.old_rules = [];
  state.new_rules = [];
  document.getElementById("results").hidden = true;
  clearError();
  renderAll();
}

// --------------------------------------------------------------------------- //
// 初始化
// --------------------------------------------------------------------------- //
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-add]").forEach((btn) => {
    btn.addEventListener("click", () => addRule(btn.dataset.add));
  });
  document.getElementById("btn-example").addEventListener("click", loadExample);
  document.getElementById("btn-clear").addEventListener("click", clearAll);
  document.getElementById("btn-analyze").addEventListener("click", analyze);
  loadExample();
});
