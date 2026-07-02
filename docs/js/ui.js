// ============================================================
// ui.js —— DOM 绑定、tab 切换、按钮事件、输出渲染
// 对应 rsa.py 的 CLI 子命令：gen / encrypt / decrypt / sign / verify
// ============================================================
(function (global) {
  "use strict";
  const RSA = global.RSA;
  const $ = (id) => document.getElementById(id);

  function setStatus(id, msg, kind) {
    const el = $(id);
    el.textContent = msg;
    el.className = "status" + (kind ? " " + kind : "");
  }
  function setBusy(btn, busy, label) {
    btn.disabled = busy;
    if (busy) btn.dataset.label = btn.textContent;
    btn.textContent = busy ? "处理中…" : (label || btn.dataset.label || btn.textContent);
  }

  // ---- tab 切换 ----
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      $("tab-" + tab.dataset.tab).classList.add("active");
    });
  });

  // ---- 复制 / 下载 代理（事件委托）----
  document.addEventListener("click", (ev) => {
    const copyBtn = ev.target.closest("button.copy");
    if (copyBtn) {
      const text = $(copyBtn.dataset.copy).value;
      navigator.clipboard.writeText(text).then(
        () => flash(copyBtn, "已复制"),
        () => flash(copyBtn, "失败")
      );
      return;
    }
    const dlBtn = ev.target.closest("button.download");
    if (dlBtn) {
      const text = $(dlBtn.dataset.dl).value;
      const blob = new Blob([text], { type: "application/octet-stream" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = dlBtn.dataset.dlName || "download.txt";
      a.click();
      URL.revokeObjectURL(a.href);
    }
  });
  function flash(btn, msg) {
    const old = btn.textContent;
    btn.textContent = msg;
    setTimeout(() => (btn.textContent = old), 1000);
  }

  // ---- 文件加载密钥（4 个 keyfile input 共用模式）----
  function wireKeyFile(inputId, targetId) {
    $(inputId).addEventListener("change", (ev) => {
      const file = ev.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => ($(targetId).value = reader.result);
      reader.readAsText(file);
    });
  }
  wireKeyFile("enc-keyfile", "enc-key");
  wireKeyFile("dec-keyfile", "dec-key");
  wireKeyFile("sign-keyfile", "sign-key");
  wireKeyFile("verify-keyfile", "verify-key");

  // ---- 解析密钥 JSON，附带友好报错 ----
  function parseKey(textareaId, statusId, requirePrivate) {
    const text = $(textareaId).value.trim();
    if (!text) throw new Error("请粘贴或加载密钥 JSON");
    let obj;
    try { obj = JSON.parse(text); }
    catch { throw new Error("密钥 JSON 格式错误"); }
    const key = RSA.keyFromJSON(obj);
    if (requirePrivate && !(key instanceof RSA.RSAPrivateKey))
      throw new Error("此处需要私钥 JSON（含 d/p/q 字段）");
    return key;
  }

  // ============ 生成密钥 ============
  $("gen-btn").addEventListener("click", async () => {
    const btn = $("gen-btn");
    const bits = parseInt($("gen-bits").value, 10);
    const e = BigInt($("gen-e").value);
    setStatus("gen-status", `正在生成 ${bits} 位密钥对…`, "busy");
    setBusy(btn, true);
    try {
      // 让 UI 先刷新再执行重计算
      await new Promise((r) => setTimeout(r, 20));
      const priv = await RSA.generateKeyPair(bits, e);
      $("gen-priv").value = RSA.keyToJSON(priv);
      $("gen-pub").value = RSA.keyToJSON(priv.public());
      setStatus("gen-status", `✅ 已生成 ${bits} 位密钥对（n=${priv.bits} 位）`, "ok");
    } catch (err) {
      setStatus("gen-status", "❌ " + err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  // ============ 加密 ============
  $("enc-btn").addEventListener("click", async () => {
    const btn = $("enc-btn");
    setStatus("enc-status", "加密中…", "busy");
    setBusy(btn, true);
    try {
      const key = parseKey("enc-key", "enc-status", false);
      const mode = $("enc-mode").value;
      const padding = $("enc-padding").value;
      const hash = $("enc-hash").value;
      if (padding === "oaep" && mode !== "public") {
        throw new Error("OAEP 仅用于 public 模式（公钥加密）");
      }
      // 私钥加密需私钥；公钥加密可用公钥或私钥(取其 e)
      const useKey = (mode === "private")
        ? (key instanceof RSA.RSAPrivateKey ? key : (() => { throw new Error("private 模式需要私钥"); })())
        : key;
      const plaintext = RSA.utf8ToBytes($("enc-text").value);
      await new Promise((r) => setTimeout(r, 20));
      const ct = await RSA.encrypt(plaintext, useKey, mode, padding, hash);
      $("enc-out").value = RSA.bytesToBase64(ct);
      // 公钥从私钥派生；若输入即公钥则原样输出
      const pub = (useKey instanceof RSA.RSAPrivateKey) ? useKey.public() : useKey;
      $("enc-pub").value = RSA.keyToJSON(pub);
      const padDesc = padding === "none" ? "教科书RSA" : `OAEP/${hash}`;
      setStatus("enc-status",
        `✅ 加密完成 · mode=${mode} (${mode === "private" ? "私钥 d" : "公钥 e"}) · ${padDesc} · 密文 ${ct.length} 字节`, "ok");
    } catch (err) {
      setStatus("enc-status", "❌ " + err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  // OAEP 选项联动：选 OAEP 时自动切到 public 模式
  $("enc-padding").addEventListener("change", (ev) => {
    if (ev.target.value === "oaep") $("enc-mode").value = "public";
  });
  $("enc-mode").addEventListener("change", (ev) => {
    if (ev.target.value === "private" && $("enc-padding").value === "oaep")
      $("enc-padding").value = "none";
  });

  // ============ 解密 ============
  $("dec-btn").addEventListener("click", async () => {
    const btn = $("dec-btn");
    setStatus("dec-status", "解密中…", "busy");
    setBusy(btn, true);
    try {
      const key = parseKey("dec-key", "dec-status", false);
      const mode = $("dec-mode").value;
      const padding = $("dec-padding").value;
      const hash = $("dec-hash").value;
      if (mode === "public" && !(key instanceof RSA.RSAPrivateKey))
        throw new Error("public 模式的密文需用私钥解密");
      const ct = RSA.base64ToBytes($("dec-cipher").value);
      await new Promise((r) => setTimeout(r, 20));
      const pt = await RSA.decrypt(ct, key, mode, padding, hash);
      try {
        $("dec-out").value = RSA.bytesToUtf8(pt);
      } catch {
        $("dec-out").value = RSA.bytesToBase64(pt) + "  (非 UTF-8，以 base64 显示)";
      }
      setStatus("dec-status", `✅ 解密完成 · 明文 ${pt.length} 字节`, "ok");
    } catch (err) {
      setStatus("dec-status", "❌ " + err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  // ============ 签名 ============
  $("sign-btn").addEventListener("click", async () => {
    const btn = $("sign-btn");
    setStatus("sign-status", "签名中…", "busy");
    setBusy(btn, true);
    try {
      const priv = parseKey("sign-key", "sign-status", true);
      const hash = $("sign-hash").value;
      const saltEl = $("sign-salt");
      const saltLen = saltEl.value === "" ? null : parseInt(saltEl.value, 10);
      const msg = RSA.utf8ToBytes($("sign-text").value);
      await new Promise((r) => setTimeout(r, 20));
      const sig = await RSA.pssSign(msg, priv, hash, saltLen);
      $("sign-out").value = RSA.bytesToBase64(sig);
      setStatus("sign-status",
        `✅ 签名完成 · PSS/${hash} · salt=${saltLen === null ? "hLen" : saltLen} · 签名 ${sig.length} 字节`, "ok");
    } catch (err) {
      setStatus("sign-status", "❌ " + err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });

  // ============ 验签 ============
  $("verify-btn").addEventListener("click", async () => {
    const btn = $("verify-btn");
    setStatus("verify-status", "验签中…", "busy");
    setBusy(btn, true);
    try {
      const key = parseKey("verify-key", "verify-status", false);
      const pub = (key instanceof RSA.RSAPrivateKey) ? key.public() : key;
      const hash = $("verify-hash").value;
      const saltEl = $("verify-salt");
      const saltLen = saltEl.value === "" ? null : parseInt(saltEl.value, 10);
      const msg = RSA.utf8ToBytes($("verify-text").value);
      const sig = RSA.base64ToBytes($("verify-sig").value);
      await new Promise((r) => setTimeout(r, 20));
      const ok = await RSA.pssVerify(msg, sig, pub, hash, saltLen);
      setStatus("verify-status",
        ok ? "✅ 验签通过：签名有效" : "❌ 验签失败：签名与消息不匹配",
        ok ? "ok" : "err");
    } catch (err) {
      setStatus("verify-status", "❌ " + err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  });
})(window);
