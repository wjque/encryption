// ============================================================
// vault/ui.js —— 保险库界面交互
// ============================================================
(function () {
  "use strict";
  const V = window.VAULT;
  const S = V.SYNC;
  const $ = (id) => document.getElementById(id);
  const AUTO_LOCK_MS = 5 * 60 * 1000; // 闲置 5 分钟自动锁定
  let autoLockTimer = null;
  let pendingConflictContent = null; // 冲突时保存远端内容

  // ---- 工具 ----
  function fmtTime(ts) {
    if (!ts) return "";
    const d = new Date(ts);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  }
  function fmtRelative(ts) {
    if (!ts) return "从未";
    const diff = Date.now() - ts;
    if (diff < 60_000) return "刚刚";
    if (diff < 3_600_000) return `${Math.floor(diff/60_000)} 分钟前`;
    if (diff < 86_400_000) return `${Math.floor(diff/3_600_000)} 小时前`;
    return `${Math.floor(diff/86_400_000)} 天前`;
  }
  function strengthMeter(password) {
    if (!password) return { html: "", cls: "" };
    const pool = guessPool(password);
    const bits = Math.round(password.length * Math.log2(pool || 94));
    const s = V.strengthLabel(bits);
    const pct = Math.min(100, (bits / 128) * 100);
    return {
      cls: s.cls,
      html: `<span class="bar"><span class="fill" style="width:${pct}%"></span></span>${bits} 位熵 · ${s.label}`,
    };
  }
  function guessPool(pw) {
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 20;
    return pool || 26;
  }
  function setStatus(id, msg, kind) {
    const el = $(id);
    if (!el) return;
    el.textContent = msg;
    el.className = "status" + (kind ? " " + kind : "");
  }
  function renderMeter(meterId, password) {
    const el = $(meterId);
    if (!el) return;
    const m = strengthMeter(password);
    el.innerHTML = m.html;
    el.className = "meter " + m.cls;
  }

  // ============ 启动：决定显示哪个门 ============
  function initGate() {
    if (V.exists()) {
      $("gate-setup").hidden = true;
      $("gate-unlock").hidden = false;
      $("unlock-pw").focus();
    } else {
      $("gate-setup").hidden = false;
      $("gate-unlock").hidden = true;
      $("setup-pw1").focus();
    }
  }

  // ============ 设置主密码 ============
  $("setup-show").addEventListener("change", (e) => {
    const t = e.target.checked ? "text" : "password";
    $("setup-pw1").type = t;
    $("setup-pw2").type = t;
  });
  $("setup-pw1").addEventListener("input", () => renderMeter("setup-meter", $("setup-pw1").value));
  $("setup-btn").addEventListener("click", async () => {
    const p1 = $("setup-pw1").value, p2 = $("setup-pw2").value;
    if (p1.length < 12) return setStatus("setup-status", "❌ 主密码至少 12 个字符", "err");
    if (p1 !== p2) return setStatus("setup-status", "❌ 两次输入不一致", "err");
    setStatus("setup-status", "正在创建保险库…", "");
    $("setup-btn").disabled = true;
    try {
      await V.setup(p1);
      enterApp({ initialPull: false });
    } catch (e) {
      setStatus("setup-status", "❌ " + e.message, "err");
    } finally {
      $("setup-btn").disabled = false;
    }
  });

  // ============ 解锁 ============
  $("unlock-show").addEventListener("change", (e) => {
    $("unlock-pw").type = e.target.checked ? "text" : "password";
  });
  $("unlock-btn").addEventListener("click", async () => {
    setStatus("unlock-status", "正在解锁…（派生密钥）", "");
    $("unlock-btn").disabled = true;
    try {
      await V.unlock($("unlock-pw").value);
      $("unlock-pw").value = "";
      enterApp({ initialPull: true });
    } catch (e) {
      setStatus("unlock-status", "❌ " + e.message, "err");
    } finally {
      $("unlock-btn").disabled = false;
    }
  });
  $("unlock-pw").addEventListener("keydown", (e) => { if (e.key === "Enter") $("unlock-btn").click(); });
  $("reset-link").addEventListener("click", (e) => {
    e.preventDefault();
    if (confirm("确定重置？将清除本浏览器中的所有保险库数据，且不可恢复。")) {
      V.reset();
      location.reload();
    }
  });

  // ============ 进入主界面 ============
  async function enterApp(opts = {}) {
    $("gate").hidden = true;
    $("app").hidden = false;
    renderEntries();
    scheduleAutoLock();
    renderSyncBadge();
    // 解锁时若已配置同步，先尝试拉一次
    if (opts.initialPull && S.isReady()) {
      const r = await S.pull();
      if (r.status === "remote-newer") {
        // 首次拉取到远端更新 → 直接应用（本地是同一账号的历史副本）
        try {
          V.applyRemoteVault(r.content);
          S.applyRemoteEtag(r.etag);
          renderEntries($("search").value);
        } catch (e) {
          // 远端 vault 格式异常，或主密码与远端不匹配（视为冲突）
          console.warn("初次拉取失败：", e);
        }
      }
    }
  }
  function exitApp() {
    V.lock();
    $("app").hidden = true;
    $("gate").hidden = false;
    initGate();
    setStatus("unlock-status", "", "");
  }

  // ============ 自动锁定 ============
  function scheduleAutoLock() {
    clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(() => {
      if (V.isUnlocked()) {
        exitApp();
        setStatus("unlock-status", "⏱ 已因闲置自动锁定", "");
      }
    }, AUTO_LOCK_MS);
  }
  ["click", "keydown", "mousemove"].forEach(ev =>
    document.addEventListener(ev, () => { if (V.isUnlocked()) scheduleAutoLock(); })
  );

  // ============ 条目列表 ============
  function renderEntries(filter = "") {
    const box = $("entries");
    const entries = V.listEntries();
    const f = filter.trim().toLowerCase();
    const shown = f
      ? entries.filter(e => e.name.toLowerCase().includes(f) || (e.username || "").toLowerCase().includes(f))
      : entries;
    box.innerHTML = "";
    $("empty-hint").hidden = shown.length > 0;
    for (const e of shown) {
      const div = document.createElement("div");
      div.className = "entry";
      div.dataset.id = e.id;
      div.innerHTML = `
        <div class="entry-head">
          <span class="entry-name"></span>
          <span class="entry-user"></span>
          <span class="entry-actions">
            <button class="reveal">显示</button>
            <button class="copy">复制</button>
            <button class="edit">编辑</button>
            <button class="del danger-text">删除</button>
          </span>
        </div>
        <div class="pw-display" hidden><code></code> <span class="meta"></span></div>`;
      div.querySelector(".entry-name").textContent = e.name;
      div.querySelector(".entry-user").textContent = e.username || "";
      div.querySelector(".entry-user").hidden = !e.username;
      const pwBox = div.querySelector(".pw-display");
      const codeEl = div.querySelector("code");
      const metaEl = div.querySelector(".meta");
      const revealBtn = div.querySelector(".reveal");
      let revealed = false;

      revealBtn.addEventListener("click", async () => {
        if (!revealed) {
          try {
            codeEl.textContent = await V.decryptPassword(e.id);
            pwBox.hidden = false;
            revealed = true;
            revealBtn.textContent = "隐藏";
            metaEl.textContent = e.gen ? `生成 ${e.gen.length} 位` : `更新 ${fmtTime(e.updated)}`;
          } catch (err) { alert("解密失败：" + err.message); }
        } else {
          codeEl.textContent = "";
          pwBox.hidden = true;
          revealed = false;
          revealBtn.textContent = "显示";
        }
      });
      div.querySelector(".copy").addEventListener("click", async () => {
        try {
          const pw = await V.decryptPassword(e.id);
          await navigator.clipboard.writeText(pw);
          const b = div.querySelector(".copy");
          const old = b.textContent;
          b.textContent = "已复制✓";
          setTimeout(() => (b.textContent = old), 1200);
          setTimeout(() => { navigator.clipboard.writeText("").catch(() => {}); }, 30000);
        } catch (err) { alert("复制失败：" + err.message); }
      });
      div.querySelector(".edit").addEventListener("click", () => openEntryDialog(e.id));
      div.querySelector(".del").addEventListener("click", () => {
        if (confirm(`删除「${e.name}」？此操作不可撤销。`)) {
          V.deleteEntry(e.id);
          renderEntries($("search").value);
        }
      });
      box.appendChild(div);
    }
  }
  $("search").addEventListener("input", (e) => renderEntries(e.target.value));

  // ============ 添加/编辑条目对话框 ============
  let editingId = null;
  $("add-btn").addEventListener("click", () => openEntryDialog(null));

  function openEntryDialog(id) {
    editingId = id;
    const dlg = $("entry-dialog");
    if (id) {
      const e = V.listEntries().find(x => x.id === id);
      $("entry-title").textContent = "编辑条目";
      $("e-name").value = e.name;
      $("e-user").value = e.username || "";
      $("e-pw").value = "";
      $("e-pw").placeholder = "留空则不修改密码";
      if (e.gen) {
        $("g-len").value = e.gen.length;
        $("g-sym").checked = e.gen.symbol !== false;
      }
    } else {
      $("entry-title").textContent = "添加条目";
      $("entry-form").reset();
      $("e-pw").placeholder = "手动输入或生成";
    }
    renderMeter("e-meter", $("e-pw").value);
    dlg.showModal();
    $("e-name").focus();
  }
  $("e-pw").addEventListener("input", () => renderMeter("e-meter", $("e-pw").value));
  $("e-gen").addEventListener("click", () => {
    const pw = V.generate({
      length: parseInt($("g-len").value, 10) || 20,
      upper: $("g-upper").checked, lower: $("g-lower").checked,
      digit: $("g-digit").checked, symbol: $("g-sym").checked,
      avoidAmbiguous: $("g-amb").checked,
    });
    $("e-pw").value = pw;
    renderMeter("e-meter", pw);
  });
  $("e-copy").addEventListener("click", () => {
    if ($("e-pw").value) navigator.clipboard.writeText($("e-pw").value);
  });
  $("e-cancel").addEventListener("click", () => $("entry-dialog").close());
  $("entry-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const name = $("e-name").value.trim();
    const username = $("e-user").value.trim();
    const pw = $("e-pw").value;
    if (!name) return;
    try {
      if (editingId) {
        await V.updateEntry(editingId, {
          name, username,
          password: pw === "" ? null : pw,
          gen: { length: parseInt($("g-len").value,10)||20, symbol: $("g-sym").checked },
        });
      } else {
        if (!pw) { alert("请输入或生成密码"); return; }
        await V.addEntry({ name, username, password: pw, gen: { length: parseInt($("g-len").value,10)||20, symbol: $("g-sym").checked } });
      }
      $("entry-dialog").close();
      renderEntries($("search").value);
    } catch (err) { alert(err.message); }
  });

  // ============ 锁定 ============
  $("lock-btn").addEventListener("click", exitApp);

  // ============ 设置菜单 ============
  $("menu-btn").addEventListener("click", () => $("menu-dialog").showModal());
  $("m-close").addEventListener("click", () => $("menu-dialog").close());

  $("m-change").addEventListener("click", () => {
    $("menu-dialog").close();
    $("change-form").reset();
    setStatus("c-status", "", "");
    $("change-dialog").showModal();
  });
  $("c-cancel").addEventListener("click", () => $("change-dialog").close());
  $("change-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const old = $("c-old").value, n1 = $("c-new1").value, n2 = $("c-new2").value;
    if (n1.length < 12) return setStatus("c-status", "❌ 新主密码至少 12 个字符", "err");
    if (n1 !== n2) return setStatus("c-status", "❌ 两次新密码不一致", "err");
    setStatus("c-status", "正在重新加密所有条目…", "");
    try {
      await V.changeMaster(old, n1);
      $("change-dialog").close();
      alert("主密码已修改，所有条目已用新密码重新加密。");
    } catch (err) {
      setStatus("c-status", "❌ " + err.message, "err");
    }
  });

  $("m-export").addEventListener("click", () => {
    const data = V.exportVault();
    const blob = new Blob([data], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `vault-backup-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    $("menu-dialog").close();
  });
  $("m-import-file").addEventListener("change", (ev) => {
    const file = ev.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        V.importVault(reader.result);
        alert("导入成功。请用导入文件的主密码解锁。");
        $("menu-dialog").close();
        exitApp();
      } catch (err) { alert("导入失败：" + err.message); }
    };
    reader.readAsText(file);
  });
  $("m-reset").addEventListener("click", () => {
    if (confirm("确定重置？将清除本浏览器中的所有保险库数据，且不可恢复。")) {
      V.reset();
      location.reload();
    }
  });

  // ============================================================
  // 云同步 UI
  // ============================================================

  // ---- 状态徽章 ----
  function renderSyncBadge(status) {
    const el = $("sync-badge");
    if (!S.isConfigured()) { el.hidden = true; return; }
    el.hidden = false;
    let text, cls;
    switch (status) {
      case "syncing": text = "⟳ 同步中…"; cls = "syncing"; break;
      case "pending": text = "· 待同步"; cls = "pending"; break;
      case "conflict": text = "⚠ 冲突，点击处理"; cls = "err"; break;
      case "error": text = "⚠ 同步失败"; cls = "err"; break;
      case "ok":
      default:
        text = `✓ 已同步 ${fmtRelative(S.getLastSyncAt())}`;
        cls = "ok";
    }
    el.textContent = "☁ " + text;
    el.className = "sync-badge " + cls;
  }
  S.onStatus((status, detail) => {
    renderSyncBadge(status);
    if (status === "conflict") {
      // 由 pushNow 触发的冲突需要 UI 打开对话框
      // 但我们不知道远端内容——重新拉取一次拿到内容
      handleConflictFromPush();
    }
  });

  async function handleConflictFromPush() {
    // 强制清 etag 拿到最新内容
    const meta = S.getMeta();
    if (!meta) return;
    try {
      // 直接调 pull() 会因为 etag 匹配返回 unchanged；先清 etag
      // 这里用一个技巧：调用 fetchOnly 绕过 etag 缓存
      // 注意 fetchOnly 需要明文 token；此处走 pull() 后从其返回处理
      const r = await S.pull();
      if (r.status === "remote-newer") {
        pendingConflictContent = { content: r.content, etag: r.etag };
        $("conflict-dialog").showModal();
      }
    } catch {}
  }

  // 徽章点击 → 打开同步设置或冲突对话框
  $("sync-badge").addEventListener("click", () => {
    if ($("sync-badge").classList.contains("err")) {
      // 若是冲突状态，尝试触发冲突处理；否则打开设置
      if (pendingConflictContent) {
        $("conflict-dialog").showModal();
      } else {
        openSyncDialog();
      }
    } else {
      openSyncDialog();
    }
  });

  // ---- 同步设置对话框 ----
  $("m-sync").addEventListener("click", () => {
    $("menu-dialog").close();
    openSyncDialog();
  });

  function openSyncDialog() {
    const on = S.isConfigured();
    $("sync-off").hidden = on;
    $("sync-on").hidden = !on;
    setStatus("sync-off-status", "", "");
    setStatus("sync-on-status", "", "");
    if (on) {
      const meta = S.getMeta();
      $("sync-info-gistid").textContent = meta.gistId;
      $("sync-info-time").textContent = fmtRelative(meta.lastSyncAt);
    } else {
      $("sync-token").value = "";
      $("sync-gistid").value = "";
    }
    $("sync-dialog").showModal();
  }
  $("sync-cancel").addEventListener("click", () => $("sync-dialog").close());
  $("sync-close-on").addEventListener("click", () => $("sync-dialog").close());

  $("sync-enable").addEventListener("click", async () => {
    const token = $("sync-token").value.trim();
    const gistId = $("sync-gistid").value.trim();
    if (!token) return setStatus("sync-off-status", "❌ 请填入 Personal Access Token", "err");
    setStatus("sync-off-status", "正在校验并连接 GitHub…", "");
    $("sync-enable").disabled = true;
    try {
      const key = V.getMasterKey();
      if (!key) throw new Error("保险库未解锁");
      const encryptedJson = V.exportVault();
      const r = await S.enable(key, token, gistId || null, encryptedJson);
      setStatus("sync-off-status", `✓ 已启用，Gist ID: ${r.gistId}`, "ok");
      renderSyncBadge("ok");
      // 若填了已有 gistId，提示用户可能需要拉取远端
      if (gistId) {
        const pull = await S.pull();
        if (pull.status === "remote-newer") {
          if (confirm("远端 Gist 有内容，是否用远端覆盖本地？（选否则用本地覆盖远端）")) {
            V.applyRemoteVault(pull.content);
            S.applyRemoteEtag(pull.etag);
            renderEntries($("search").value);
          } else {
            await S.forcePush(V.exportVault());
          }
        }
      }
      setTimeout(() => {
        $("sync-dialog").close();
        openSyncDialog(); // 切到"已启用"视图
      }, 800);
    } catch (e) {
      setStatus("sync-off-status", "❌ " + e.message, "err");
    } finally {
      $("sync-enable").disabled = false;
    }
  });

  $("sync-pull").addEventListener("click", async () => {
    setStatus("sync-on-status", "正在拉取…", "");
    const r = await S.pull();
    if (r.status === "unchanged") {
      setStatus("sync-on-status", "✓ 已是最新", "ok");
    } else if (r.status === "remote-newer") {
      pendingConflictContent = { content: r.content, etag: r.etag };
      if (confirm("远端有更新，是否覆盖本地？")) {
        try {
          V.applyRemoteVault(r.content);
          S.applyRemoteEtag(r.etag);
          renderEntries($("search").value);
          setStatus("sync-on-status", "✓ 已从远端更新本地", "ok");
          pendingConflictContent = null;
        } catch (e) {
          setStatus("sync-on-status", "❌ " + e.message, "err");
        }
      } else {
        setStatus("sync-on-status", "已保留本地版本（下次推送需强制）", "");
      }
    } else if (r.status === "error") {
      setStatus("sync-on-status", "❌ " + r.error, "err");
    }
    $("sync-info-time").textContent = fmtRelative(S.getLastSyncAt());
  });

  $("sync-push").addEventListener("click", async () => {
    setStatus("sync-on-status", "正在推送…", "");
    const r = await S.pushNow(() => V.exportVault());
    if (r.status === "ok") {
      setStatus("sync-on-status", "✓ 已推送", "ok");
    } else if (r.status === "conflict") {
      pendingConflictContent = { content: r.remote, etag: r.remoteEtag };
      setStatus("sync-on-status", "⚠ 冲突，请选择处理方式", "err");
      $("sync-dialog").close();
      $("conflict-dialog").showModal();
    } else if (r.status === "error") {
      setStatus("sync-on-status", "❌ " + r.error, "err");
    }
    $("sync-info-time").textContent = fmtRelative(S.getLastSyncAt());
  });

  $("sync-disable").addEventListener("click", () => {
    if (!confirm("关闭同步会清除本地保存的 Token 与 Gist ID。GitHub 上的 Gist 不会被删除。")) return;
    S.disable();
    renderSyncBadge();
    $("sync-dialog").close();
  });

  // ---- 冲突对话框 ----
  $("cf-pull").addEventListener("click", async () => {
    if (!pendingConflictContent) return;
    try {
      V.applyRemoteVault(pendingConflictContent.content);
      S.applyRemoteEtag(pendingConflictContent.etag);
      renderEntries($("search").value);
      pendingConflictContent = null;
      $("conflict-dialog").close();
    } catch (e) {
      alert("覆盖本地失败：" + e.message);
    }
  });
  $("cf-push").addEventListener("click", async () => {
    const r = await S.forcePush(V.exportVault());
    if (r.status === "ok") {
      pendingConflictContent = null;
      $("conflict-dialog").close();
    } else if (r.status === "error") {
      alert("强制推送失败：" + r.error);
    }
  });
  $("cf-later").addEventListener("click", () => {
    $("conflict-dialog").close();
  });

  // ============================================================
  // 从 Gist 恢复
  // ============================================================
  $("restore-link").addEventListener("click", (e) => {
    e.preventDefault();
    $("restore-form").reset();
    setStatus("r-status", "", "");
    $("restore-dialog").showModal();
  });
  $("r-cancel").addEventListener("click", () => $("restore-dialog").close());
  $("r-go").addEventListener("click", async () => {
    const token = $("r-token").value.trim();
    const gistId = $("r-gistid").value.trim();
    const master = $("r-master").value;
    if (!token || !gistId || !master)
      return setStatus("r-status", "❌ 请填写全部字段", "err");
    setStatus("r-status", "正在从 GitHub 拉取…", "");
    $("r-go").disabled = true;
    try {
      const r = await S.fetchOnly(token, gistId);
      // 写入 localStorage 作为当前 vault
      V.applyRemoteVault(r.content);
      // 尝试用主密码解锁
      setStatus("r-status", "正在派生密钥并解锁…", "");
      await V.unlock(master);
      const key = V.getMasterKey();
      // 用主密钥加密 PAT，写入 sync 元数据
      await S.completeRestore(key, token, gistId, r.etag);
      $("restore-dialog").close();
      $("r-token").value = ""; $("r-master").value = "";
      enterApp({ initialPull: false });
    } catch (e) {
      setStatus("r-status", "❌ " + e.message, "err");
      // 恢复失败：如果已经写了本地 vault，回滚
      if (V.exists() && !V.isUnlocked()) V.reset();
    } finally {
      $("r-go").disabled = false;
    }
  });

  // ============ 启动 ============
  initGate();
})();
