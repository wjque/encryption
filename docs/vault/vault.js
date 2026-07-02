// ============================================================
// vault/vault.js —— 保险库数据模型
//
// 存储布局（localStorage["rsa-vault"]）：
//   {
//     version: 1,
//     kdf: { salt, iterations },
//     verifier: { nonce, ct },          // 用于校验主密码
//     entries: [ { id, name, username, ct:{nonce,ct}, created, updated, gen } ]
//   }
//
// 仅存密文与公开参数；主密码永不落盘，密钥仅按需派生、驻留内存。
// ============================================================
(function (global) {
  "use strict";
  const VAULT = (global.VAULT || {});
  const STORE_KEY = "rsa-vault";
  const VERSION = 1;
  const C = VAULT; // crypto 命名空间别名

  let state = null;    // { meta, entries, key }  解锁后含派生密钥
  let key = null;      // 当前派生的 AES-GCM 密钥（仅内存）

  // 触发防抖同步：所有会改变 vault 内容的操作在结尾调用它
  function triggerSync() {
    if (VAULT.SYNC && VAULT.SYNC.isReady()) {
      VAULT.SYNC.schedulePush(exportVault);
    }
  }

  // 获取当前主密钥（供 sync 层加密 PAT / 恢复流程等使用）
  function getMasterKey() { return key; }

  // --- 原始读写 ---
  function readRaw() {
    try {
      const s = localStorage.getItem(STORE_KEY);
      return s ? JSON.parse(s) : null;
    } catch { return null; }
  }
  function writeRaw(obj) {
    localStorage.setItem(STORE_KEY, JSON.stringify(obj));
  }
  function exists() { return readRaw() !== null; }

  // --- 初始化新保险库（首次设置主密码）---
  async function setup(masterPassword, iterations = C.KDF.iterations) {
    if (exists()) throw new Error("保险库已存在；请先解锁或重置");
    const salt = C.randomBytes(16);
    key = await C.deriveKey(masterPassword, salt, iterations);
    const verifier = await C.makeVerifier(key);
    const vault = {
      version: VERSION,
      kdf: { salt: C.b64(salt), iterations },
      verifier,
      entries: [],
    };
    writeRaw(vault);
    state = vault;
    return vault;
  }

  // --- 解锁：校验主密码，派生并驻留密钥 ---
  async function unlock(masterPassword) {
    const vault = readRaw();
    if (!vault) throw new Error("尚未创建保险库");
    const salt = C.unb64(vault.kdf.salt);
    const candidate = await C.deriveKey(masterPassword, salt, vault.kdf.iterations);
    if (!(await C.checkVerifier(candidate, vault.verifier)))
      throw new Error("主密码错误");
    key = candidate;
    state = vault;
    if (VAULT.SYNC) await VAULT.SYNC.attach(key);
    return vault;
  }

  // --- 锁定：丢弃密钥与内存状态 ---
  function lock() {
    key = null;
    state = null;
    if (VAULT.SYNC) VAULT.SYNC.detach();
  }
  function isUnlocked() { return key !== null; }

  // --- 条目列表（明文 name/username，密文密码）---
  function listEntries() {
    if (!state) return [];
    return state.entries.map(e => ({
      id: e.id, name: e.name, username: e.username,
      created: e.created, updated: e.updated, gen: e.gen,
    }));
  }

  // --- 添加条目 ---
  async function addEntry({ name, username, password, gen }) {
    requireUnlocked();
    if (!name || !password) throw new Error("站点名和密码不能为空");
    const enc = await C.encryptStr(key, password);
    const now = Date.now();
    const entry = {
      id: crypto.randomUUID(),
      name: name.trim(),
      username: (username || "").trim(),
      ct: enc,
      gen: gen || null,
      created: now, updated: now,
    };
    state.entries.push(entry);
    persist();
    triggerSync();
    return entry.id;
  }

  // --- 更新条目 ---
  async function updateEntry(id, { name, username, password, gen }) {
    requireUnlocked();
    const e = state.entries.find(x => x.id === id);
    if (!e) throw new Error("条目不存在");
    if (name !== undefined) e.name = name.trim();
    if (username !== undefined) e.username = (username || "").trim();
    if (password !== undefined && password !== null) {
      e.ct = await C.encryptStr(key, password);
    }
    if (gen !== undefined) e.gen = gen || null;
    e.updated = Date.now();
    persist();
    triggerSync();
  }

  // --- 解密单条密码（按需）---
  async function decryptPassword(id) {
    requireUnlocked();
    const e = state.entries.find(x => x.id === id);
    if (!e) throw new Error("条目不存在");
    return C.decryptStr(key, e.ct.nonce, e.ct.ct);
  }

  // --- 删除条目 ---
  function deleteEntry(id) {
    requireUnlocked();
    const i = state.entries.findIndex(x => x.id === id);
    if (i < 0) throw new Error("条目不存在");
    const [removed] = state.entries.splice(i, 1);
    persist();
    triggerSync();
    return removed;
  }

  // --- 修改主密码：用旧密钥解密所有密码，用新密钥重新加密 ---
  async function changeMaster(oldPassword, newPassword, iterations = C.KDF.iterations) {
    requireUnlocked();
    // 校验旧密码（再次验证，防误操作）
    const vault = readRaw();
    const oldSalt = C.unb64(vault.kdf.salt);
    const oldCheck = await C.deriveKey(oldPassword, oldSalt, vault.kdf.iterations);
    if (!(await C.checkVerifier(oldCheck, vault.verifier)))
      throw new Error("旧主密码错误");

    // 用新主密码派生新密钥
    const newSalt = C.randomBytes(16);
    const newKey = await C.deriveKey(newPassword, newSalt, iterations);
    const newEntries = [];
    for (const e of state.entries) {
      const plain = await C.decryptStr(key, e.ct.nonce, e.ct.ct);
      newEntries.push({ ...e, ct: await C.encryptStr(newKey, plain) });
    }
    const newVault = {
      version: VERSION,
      kdf: { salt: C.b64(newSalt), iterations },
      verifier: await C.makeVerifier(newKey),
      entries: newEntries,
    };
    writeRaw(newVault);
    key = newKey;
    state = newVault;
    // 修改主密码后，需用新密钥重新加密 sync 层保存的 PAT
    if (VAULT.SYNC) await VAULT.SYNC.rekey(newKey);
    triggerSync();
  }

  // --- 导出（加密的完整备份，仍是密文）---
  function exportVault() {
    const v = readRaw();
    if (!v) throw new Error("无保险库可导出");
    return JSON.stringify(v, null, 2);
  }

  // --- 导入 ---
  function importVault(jsonStr) {
    let obj;
    try { obj = JSON.parse(jsonStr); }
    catch { throw new Error("导入文件不是有效 JSON"); }
    if (!obj.version || !obj.kdf || !obj.verifier || !Array.isArray(obj.entries))
      throw new Error("导入文件格式不正确");
    writeRaw(obj);
    // 导入的 vault 主密码可能与当前不同，旧 sync 元数据里的 PAT 用旧主密钥加密
    // 已无法解密，故清空。用户可重新配置同步。
    if (VAULT.SYNC) VAULT.SYNC.disable();
    lock(); // 导入后需重新解锁
  }

  // --- 用远端拉回的 vault JSON 覆盖本地（用于同步冲突/恢复）---
  // 调用方需保证 jsonStr 是本主密码可解密的 vault
  function applyRemoteVault(jsonStr) {
    let obj;
    try { obj = JSON.parse(jsonStr); }
    catch { throw new Error("远端数据不是有效 JSON"); }
    if (!obj.version || !obj.kdf || !obj.verifier || !Array.isArray(obj.entries))
      throw new Error("远端数据格式不正确");
    writeRaw(obj);
    state = obj;
  }

  // --- 重置（彻底删除保险库）---
  // opts.deleteRemote: 是否同时删除远端 Gist（需当前处于已解锁状态才可行）
  // 返回 { remoteDeleted: boolean, remoteError?: string }
  async function reset(opts = {}) {
    let remoteDeleted = false, remoteError;
    if (opts.deleteRemote && VAULT.SYNC && VAULT.SYNC.isReady()) {
      try {
        await VAULT.SYNC.deleteRemoteGist();
        remoteDeleted = true;
      } catch (e) {
        remoteError = e.message;
      }
    }
    localStorage.removeItem(STORE_KEY);
    if (VAULT.SYNC) VAULT.SYNC.disable();
    lock();
    return { remoteDeleted, remoteError };
  }

  // --- 内部：要求已解锁 ---
  function requireUnlocked() {
    if (!key || !state) throw new Error("保险库未解锁");
  }
  function persist() { writeRaw(state); }

  Object.assign(VAULT, {
    STORE_KEY, VERSION,
    setup, unlock, lock, isUnlocked, getMasterKey,
    listEntries, addEntry, updateEntry, decryptPassword, deleteEntry,
    changeMaster, exportVault, importVault, applyRemoteVault, reset, exists,
  });
})(window);
