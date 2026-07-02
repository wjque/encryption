// ============================================================
// vault/sync.js —— GitHub Gist 云同步
//
// 存储布局（localStorage["rsa-vault-sync"]）：
//   {
//     provider: "gist",
//     gistId: "abc123...",
//     tokenCt: { nonce, ct },     // PAT 用主密钥 AES-GCM 加密
//     lastEtag: '"...","...",     // 用于冲突检测的乐观锁
//     lastSyncAt: 1735776000000,
//   }
//
// 安全模型：
//   - PAT 绝不明文存盘，用当前主密钥加密后放 localStorage
//   - Gist 内容是密文（vault 本身），GitHub 看不到明文
//   - 使用 fine-grained PAT，仅需 Gists 读写权限（最小权限）
// ============================================================
(function (global) {
  "use strict";
  const VAULT = (global.VAULT = global.VAULT || {});

  const SYNC_KEY = "rsa-vault-sync";
  const API = "https://api.github.com";
  const FILE = "vault.json";
  const PUSH_DEBOUNCE_MS = 3000;

  // --- 内存状态 ---
  let syncState = null;      // 从 localStorage 读入的元数据
  let plainToken = null;     // 解锁后从 tokenCt 解出的 PAT，仅内存
  let pushTimer = null;
  let pushInFlight = false;
  let statusListener = null; // (status, detail) => void

  // ---------- 存取 ----------
  function readSync() {
    try {
      const s = localStorage.getItem(SYNC_KEY);
      return s ? JSON.parse(s) : null;
    } catch { return null; }
  }
  function writeSync(obj) {
    if (obj) localStorage.setItem(SYNC_KEY, JSON.stringify(obj));
    else localStorage.removeItem(SYNC_KEY);
  }

  function isConfigured() { return readSync() !== null; }
  function getMeta() { return readSync(); }
  function getLastSyncAt() { return syncState?.lastSyncAt || 0; }

  // ---------- 状态回调 ----------
  function onStatus(fn) { statusListener = fn; }
  function emit(status, detail) {
    if (statusListener) statusListener(status, detail);
  }

  // ---------- GitHub API ----------
  async function ghRequest(token, path, init = {}) {
    const headers = {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(init.headers || {}),
    };
    if (init.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
    const r = await fetch(API + path, { ...init, headers });
    return r;
  }

  async function ghJson(token, path, init) {
    const r = await ghRequest(token, path, init);
    if (r.status === 401) throw new Error("GitHub token 无效或已过期");
    if (r.status === 403) throw new Error("权限不足或触发速率限制");
    if (r.status === 404) throw new Error("Gist 不存在或无访问权限");
    if (!r.ok) {
      let msg;
      try { msg = (await r.json()).message; } catch { msg = r.statusText; }
      throw new Error(`GitHub ${r.status}: ${msg}`);
    }
    return { data: await r.json(), etag: r.headers.get("etag") };
  }

  // 校验 token（同时探测权限）
  async function validateToken(token) {
    const r = await ghRequest(token, "/user");
    if (r.status === 401) throw new Error("Token 无效");
    if (!r.ok) throw new Error(`GitHub ${r.status}`);
    const user = await r.json();
    return { login: user.login };
  }

  // 检查当前存的 token 是否仍有效，并顺便探测能否访问当前 Gist
  //   { ok: true, login }                        全绿
  //   { ok: false, reason: "no-sync" }           未配置同步
  //   { ok: false, reason: "no-token" }          有配置但内存里没 token（未 attach）
  //   { ok: false, reason: "token-invalid" }     token 过期/被吊销
  //   { ok: false, reason: "gist-forbidden" }    token 有效但访问不了当前 Gist
  //   { ok: false, reason: "network", error }    网络问题
  async function checkTokenHealth() {
    if (!syncState) return { ok: false, reason: "no-sync" };
    if (!plainToken) return { ok: false, reason: "no-token" };
    try {
      const u = await ghRequest(plainToken, "/user");
      if (u.status === 401) return { ok: false, reason: "token-invalid" };
      if (!u.ok) return { ok: false, reason: "network", error: `GitHub ${u.status}` };
      const user = await u.json();
      const g = await ghRequest(plainToken, `/gists/${syncState.gistId}`);
      if (g.status === 401) return { ok: false, reason: "token-invalid" };
      if (g.status === 403 || g.status === 404) return { ok: false, reason: "gist-forbidden" };
      if (!g.ok) return { ok: false, reason: "network", error: `GitHub ${g.status}` };
      return { ok: true, login: user.login };
    } catch (e) {
      return { ok: false, reason: "network", error: e.message };
    }
  }

  // 更换 token：仅当新 token 有效且能访问当前 Gist 时才落盘
  // masterKey: 当前主密钥，用于加密新 token
  // 返回：{ login } —— 新 token 所属的 GitHub 用户名
  async function replaceToken(masterKey, newToken) {
    if (!syncState) throw new Error("同步未启用");
    if (!newToken) throw new Error("请输入新的 Token");
    // 验 token 有效
    const u = await ghRequest(newToken, "/user");
    if (u.status === 401) throw new Error("新 Token 无效");
    if (!u.ok) throw new Error(`GitHub ${u.status}：无法验证 Token`);
    const user = await u.json();
    // 验能读当前 Gist
    const g = await ghRequest(newToken, `/gists/${syncState.gistId}`);
    if (g.status === 401) throw new Error("新 Token 无效");
    if (g.status === 403) throw new Error("新 Token 权限不足（需要 Gists: Read and write）");
    if (g.status === 404) throw new Error("新 Token 无法访问当前 Gist（可能不属于同一 GitHub 账号）");
    if (!g.ok) throw new Error(`GitHub ${g.status}：无法访问当前 Gist`);
    const gistData = await g.json();

    // 都通过 → 更新内存 + 落盘（用主密钥加密）
    plainToken = newToken;
    syncState.tokenCt = await encryptToken(masterKey, newToken);
    syncState.lastEtag = g.headers.get("etag") || syncState.lastEtag;
    writeSync(syncState);
    emit("ok");
    return { login: user.login, updatedAt: gistData.updated_at };
  }

  // 创建新 Gist
  async function createGist(token, content) {
    const { data, etag } = await ghJson(token, "/gists", {
      method: "POST",
      body: JSON.stringify({
        description: "Encrypted password vault (AES-256-GCM)",
        public: false,
        files: { [FILE]: { content } },
      }),
    });
    return { id: data.id, etag };
  }

  // 拉取 Gist 内容；ifNoneMatch 命中时返回 unchanged
  async function fetchGist(token, gistId, ifNoneMatch) {
    const headers = ifNoneMatch ? { "If-None-Match": ifNoneMatch } : {};
    const r = await ghRequest(token, `/gists/${gistId}`, { headers });
    if (r.status === 304) return { unchanged: true };
    if (r.status === 401) throw new Error("Token 无效或已过期");
    if (r.status === 404) throw new Error("Gist 不存在或无访问权限");
    if (!r.ok) throw new Error(`GitHub ${r.status}`);
    const data = await r.json();
    const file = data.files[FILE];
    if (!file) throw new Error(`Gist 中未找到 ${FILE}`);
    return {
      content: file.content,
      etag: r.headers.get("etag"),
      updatedAt: data.updated_at,
    };
  }

  // 推送新内容
  async function pushGist(token, gistId, content) {
    // 说明：Gists API 对 PATCH 不严格遵循 If-Match（不同版本表现不一），
    // 因此不依赖服务端条件请求；改为 push 前先 GET etag，比对上次记忆的 etag，
    // 若变了则视为冲突。乐观锁在客户端完成。
    const { data, etag } = await ghJson(token, `/gists/${gistId}`, {
      method: "PATCH",
      body: JSON.stringify({ files: { [FILE]: { content } } }),
    });
    return { etag, updatedAt: data.updated_at };
  }

  // ---------- PAT 的对称加密（用主密钥）----------
  async function encryptToken(masterKey, token) {
    return VAULT.encryptStr(masterKey, token);
  }
  async function decryptToken(masterKey, tokenCt) {
    return VAULT.decryptStr(masterKey, tokenCt.nonce, tokenCt.ct);
  }

  // ---------- 生命周期 ----------
  // 解锁后调用：解密 PAT 到内存
  async function attach(masterKey) {
    syncState = readSync();
    if (!syncState) { plainToken = null; return; }
    try {
      plainToken = await decryptToken(masterKey, syncState.tokenCt);
    } catch {
      // 主密钥变了但 sync 元数据未及时更新（极端情况），标记为需要重新配置
      plainToken = null;
      emit("error", "无法解密同步凭证，请在设置中重新配置");
    }
  }

  // 锁定时调用：清除内存令牌
  function detach() {
    plainToken = null;
    syncState = null;
    if (pushTimer) { clearTimeout(pushTimer); pushTimer = null; }
  }

  function isReady() { return plainToken !== null && syncState !== null; }

  // ---------- 启用同步 ----------
  // masterKey: 当前主密钥，用于加密 PAT
  // token:     GitHub PAT
  // gistId:    留空则创建新 Gist；填入则复用已有 Gist
  // encryptedVaultJson: 当前保险库的加密 JSON（首次上传用）
  async function enable(masterKey, token, gistId, encryptedVaultJson) {
    await validateToken(token);   // 先验 token
    let id = gistId, etag;
    if (id) {
      // 已有 Gist：先拉一次确认可读，同时拿 etag
      const existing = await fetchGist(token, id);
      etag = existing.etag;
      // 不覆盖已有内容；由调用方决定后续是否 push
    } else {
      const created = await createGist(token, encryptedVaultJson);
      id = created.id;
      etag = created.etag;
    }
    const tokenCt = await encryptToken(masterKey, token);
    syncState = {
      provider: "gist",
      gistId: id,
      tokenCt,
      lastEtag: etag || null,
      lastSyncAt: Date.now(),
    };
    plainToken = token;
    writeSync(syncState);
    return { gistId: id };
  }

  // 关闭同步（保留 Gist 本身在 GitHub 上，仅清理本地元数据）
  function disable() {
    detach();
    writeSync(null);
  }

  // 删除远端 Gist（需要已解锁，plainToken 在内存中）
  async function deleteRemoteGist() {
    if (!isReady()) throw new Error("同步未启用或未解锁，无法删除云端 Gist");
    const r = await ghRequest(plainToken, `/gists/${syncState.gistId}`, { method: "DELETE" });
    if (r.status === 204 || r.status === 200) return true;
    if (r.status === 404) return true;  // 已不存在，视为成功
    if (r.status === 401) throw new Error("Token 无效，无法删除远端 Gist");
    if (r.status === 403) throw new Error("Token 权限不足，无法删除该 Gist");
    throw new Error(`GitHub ${r.status}：删除 Gist 失败`);
  }

  // ---------- 拉取远端并对比 ----------
  // 返回：
  //   { status: "unchanged" }              远端与本地记忆一致
  //   { status: "remote-newer", content, etag }  远端有新内容
  //   { status: "no-sync" }                未配置
  //   { status: "error", error }
  async function pull() {
    if (!isReady()) return { status: "no-sync" };
    try {
      emit("syncing");
      const r = await fetchGist(plainToken, syncState.gistId, syncState.lastEtag);
      if (r.unchanged) {
        emit("ok");
        return { status: "unchanged" };
      }
      // etag 变了 → 远端有新内容
      return { status: "remote-newer", content: r.content, etag: r.etag };
    } catch (e) {
      emit("error", e.message);
      return { status: "error", error: e.message };
    }
  }

  // 应用远端拉回的内容（调用方在冲突对话框里确认后调用）
  function applyRemoteEtag(etag) {
    if (!syncState) return;
    syncState.lastEtag = etag;
    syncState.lastSyncAt = Date.now();
    writeSync(syncState);
    emit("ok");
  }

  // ---------- 推送 ----------
  // 立即推送（跳过防抖）
  async function pushNow(contentProvider) {
    if (!isReady()) return { status: "no-sync" };
    if (pushInFlight) return { status: "in-flight" };
    pushInFlight = true;
    emit("syncing");
    try {
      // 冲突检测：push 前先 GET etag，比对上次记忆的 etag
      const head = await fetchGist(plainToken, syncState.gistId, syncState.lastEtag);
      if (!head.unchanged) {
        // 远端已被别处更新，交给调用方处理冲突
        pushInFlight = false;
        emit("conflict");
        return { status: "conflict", remote: head.content, remoteEtag: head.etag };
      }
      const content = contentProvider();
      const r = await pushGist(plainToken, syncState.gistId, content);
      syncState.lastEtag = r.etag || syncState.lastEtag;
      syncState.lastSyncAt = Date.now();
      writeSync(syncState);
      emit("ok");
      return { status: "ok" };
    } catch (e) {
      emit("error", e.message);
      return { status: "error", error: e.message };
    } finally {
      pushInFlight = false;
    }
  }

  // 强制推送（用户选择"本地覆盖远端"）
  async function forcePush(content) {
    if (!isReady()) return { status: "no-sync" };
    pushInFlight = true;
    emit("syncing");
    try {
      const r = await pushGist(plainToken, syncState.gistId, content);
      syncState.lastEtag = r.etag || syncState.lastEtag;
      syncState.lastSyncAt = Date.now();
      writeSync(syncState);
      emit("ok");
      return { status: "ok" };
    } catch (e) {
      emit("error", e.message);
      return { status: "error", error: e.message };
    } finally {
      pushInFlight = false;
    }
  }

  // 防抖推送：3 秒后触发；期间的重复调用只延后
  function schedulePush(contentProvider) {
    if (!isReady()) return;
    if (pushTimer) clearTimeout(pushTimer);
    emit("pending");
    pushTimer = setTimeout(() => {
      pushTimer = null;
      pushNow(contentProvider);
    }, PUSH_DEBOUNCE_MS);
  }

  // 修改主密码后调用：用新密钥重新加密 PAT
  async function rekey(newMasterKey) {
    if (!syncState || !plainToken) return;
    syncState.tokenCt = await encryptToken(newMasterKey, plainToken);
    writeSync(syncState);
  }

  // 恢复流程用：只拉，不写本地 sync 元数据（尚未确定主密码）
  async function fetchOnly(token, gistId) {
    await validateToken(token);
    const r = await fetchGist(token, gistId);
    return { content: r.content, etag: r.etag };
  }

  // 恢复流程收尾：主密码已确认后，写入 sync 元数据
  async function completeRestore(masterKey, token, gistId, etag) {
    const tokenCt = await encryptToken(masterKey, token);
    syncState = {
      provider: "gist",
      gistId,
      tokenCt,
      lastEtag: etag || null,
      lastSyncAt: Date.now(),
    };
    plainToken = token;
    writeSync(syncState);
  }

  // ============================================================
  // 配对加密（QR 码用）
  //
  // 生成端：pin(4 位)+ token + gistId → PBKDF2 派生临时密钥 → AES-GCM 加密
  //         → base64url 编码为 URL fragment 内容
  // 扫码端：解 base64url → 用 pin 派生密钥 → 解密还原 {token, gistId}
  //
  // 生命周期：
  //   - 每次「添加新设备」重新生成 PIN 与盐/nonce → QR 每次不同
  //   - PIN 只在生成端屏幕上显示 30 秒，倒计时结束 UI 关闭
  //   - 扫码端拿到 payload 也需 PIN 才能解 → 偷拍 QR 无用
  // ============================================================
  const PAIR_KDF_ITER = 200_000;    // 配对场景低于 vault 主 KDF 即可，PIN 只有 4 位数字

  // base64url（无填充，URL 安全）
  function b64u(bytes) {
    return VAULT.b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function unb64u(str) {
    const s = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
    return VAULT.unb64(s);
  }

  // 用 PIN 派生一次性 AES-GCM 密钥
  async function derivePinKey(pin, salt) {
    const baseKey = await crypto.subtle.importKey(
      "raw", VAULT.utf8(pin), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PAIR_KDF_ITER, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false, ["encrypt", "decrypt"]);
  }

  // 生成配对 payload：返回 { pin, fragment }
  //   - pin: 4 位数字字符串（UI 显示给用户）
  //   - fragment: 放到 URL 的 #pair=... 后面的 base64url 字符串
  async function createPairPayload() {
    if (!isReady()) throw new Error("同步未启用，无法生成配对码");
    // 生成 4 位随机 PIN（0000-9999），用 crypto.getRandomValues 拒绝采样保证均匀
    const buf = new Uint32Array(1);
    let n;
    const limit = 0x100000000 - (0x100000000 % 10000);
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    const pin = String(buf[0] % 10000).padStart(4, "0");

    const salt = VAULT.randomBytes(16);
    const nonce = VAULT.randomBytes(12);
    const key = await derivePinKey(pin, salt);
    const plain = VAULT.utf8(JSON.stringify({
      v: 1,
      token: plainToken,
      gistId: syncState.gistId,
    }));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce }, key, plain));

    // 打包：[1 字节版本 | 16 字节盐 | 12 字节 nonce | ct...]
    const out = new Uint8Array(1 + salt.length + nonce.length + ct.length);
    out[0] = 1;
    out.set(salt, 1);
    out.set(nonce, 1 + salt.length);
    out.set(ct, 1 + salt.length + nonce.length);
    return { pin, fragment: b64u(out) };
  }

  // 扫码端：用 fragment + pin 解出 {token, gistId}
  async function decodePairPayload(fragment, pin) {
    let raw;
    try { raw = unb64u(fragment); }
    catch { throw new Error("配对码格式错误"); }
    if (raw.length < 1 + 16 + 12 + 16) throw new Error("配对码长度不足");
    if (raw[0] !== 1) throw new Error("配对码版本不支持");
    const salt = raw.slice(1, 17);
    const nonce = raw.slice(17, 29);
    const ct = raw.slice(29);
    const key = await derivePinKey(pin, salt);
    let plain;
    try {
      plain = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce }, key, ct));
    } catch {
      throw new Error("PIN 错误或配对码已损坏");
    }
    const obj = JSON.parse(VAULT.fromUtf8(plain));
    if (!obj.token || !obj.gistId) throw new Error("配对码内容不完整");
    return { token: obj.token, gistId: obj.gistId };
  }

  Object.assign(VAULT, {
    SYNC: {
      isConfigured, getMeta, getLastSyncAt,
      onStatus,
      attach, detach, isReady,
      enable, disable, rekey, deleteRemoteGist,
      pull, applyRemoteEtag,
      pushNow, forcePush, schedulePush,
      fetchOnly, completeRestore,
      validateToken, fetchGist,
      checkTokenHealth, replaceToken,
      createPairPayload, decodePairPayload,
    },
  });
})(window);
