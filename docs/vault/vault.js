// ============================================================
// vault/vault.js —— 保险库数据模型
//
// 存储布局（localStorage["rsa-vault"]）：
//   {
//     version: 2,
//     kdf: { salt, iterations },
//     verifier: { nonce, ct },
//     entries: [
//       { id, meta:{nonce,ct}, secret:{nonce,ct}, created, updated }
//     ]
//   }
//
// meta 加密保存 { name, username, gen }；secret 单独保存密码。
// 解锁后只缓存 meta，密码仍按需解密。
// ============================================================
(function (global) {
  "use strict";
  const VAULT = (global.VAULT || {});
  const STORE_KEY = "rsa-vault";
  const VERSION = 2;
  const C = VAULT;

  let state = null;
  let key = null;
  let metaCache = new Map();

  function triggerSync() {
    if (VAULT.SYNC && VAULT.SYNC.isReady()) {
      VAULT.SYNC.schedulePush(exportVault);
    }
  }

  function getMasterKey() { return key; }

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

  function validateVault(obj, label = "保险库") {
    if (!obj || obj.version !== VERSION || !obj.kdf || !obj.verifier || !Array.isArray(obj.entries)) {
      throw new Error(`${label}格式不正确或版本不支持`);
    }
    for (const e of obj.entries) {
      if (!e.id || !e.meta || !e.secret) {
        throw new Error(`${label}条目格式不正确`);
      }
    }
  }

  function normalizeMeta(meta) {
    return {
      name: String(meta.name || "").trim(),
      username: String(meta.username || "").trim(),
      gen: meta.gen || null,
    };
  }

  async function encryptMeta(masterKey, meta) {
    return C.encryptStr(masterKey, JSON.stringify(normalizeMeta(meta)));
  }

  async function decryptMeta(masterKey, entry) {
    const raw = await C.decryptStr(masterKey, entry.meta.nonce, entry.meta.ct);
    const meta = normalizeMeta(JSON.parse(raw));
    if (!meta.name) throw new Error("条目名称为空");
    return meta;
  }

  async function hydrateMetaCache(vault) {
    const next = new Map();
    for (const e of vault.entries) {
      next.set(e.id, await decryptMeta(key, e));
    }
    metaCache = next;
  }

  async function setup(masterPassword, iterations = C.KDF.iterations) {
    if (exists()) throw new Error("保险库已存在");
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
    metaCache = new Map();
    return vault;
  }

  async function unlock(masterPassword) {
    const vault = readRaw();
    if (!vault) throw new Error("尚未创建保险库");
    validateVault(vault);
    const salt = C.unb64(vault.kdf.salt);
    const candidate = await C.deriveKey(masterPassword, salt, vault.kdf.iterations);
    if (!(await C.checkVerifier(candidate, vault.verifier))) {
      throw new Error("主密码错误");
    }
    key = candidate;
    state = vault;
    try {
      await hydrateMetaCache(vault);
    } catch {
      key = null;
      state = null;
      metaCache = new Map();
      throw new Error("保险库数据解密失败");
    }
    if (VAULT.SYNC) await VAULT.SYNC.attach(key);
    return vault;
  }

  function lock() {
    key = null;
    state = null;
    metaCache = new Map();
    if (VAULT.SYNC) VAULT.SYNC.detach();
  }

  function isUnlocked() { return key !== null; }

  function listEntries() {
    if (!state) return [];
    return state.entries.map(e => {
      const meta = metaCache.get(e.id) || { name: "", username: "", gen: null };
      return {
        id: e.id,
        name: meta.name,
        username: meta.username,
        gen: meta.gen,
        created: e.created,
        updated: e.updated,
      };
    });
  }

  async function addEntry({ name, username, password, gen }) {
    requireUnlocked();
    const meta = normalizeMeta({ name, username, gen });
    if (!meta.name || !password) throw new Error("站点名和密码不能为空");
    const now = Date.now();
    const entry = {
      id: crypto.randomUUID(),
      meta: await encryptMeta(key, meta),
      secret: await C.encryptStr(key, password),
      created: now,
      updated: now,
    };
    state.entries.push(entry);
    metaCache.set(entry.id, meta);
    persist();
    triggerSync();
    return entry.id;
  }

  async function updateEntry(id, { name, username, password, gen }) {
    requireUnlocked();
    const e = state.entries.find(x => x.id === id);
    if (!e) throw new Error("条目不存在");
    const current = metaCache.get(id) || await decryptMeta(key, e);
    const nextMeta = normalizeMeta({
      name: name !== undefined ? name : current.name,
      username: username !== undefined ? username : current.username,
      gen: gen !== undefined ? gen : current.gen,
    });
    if (!nextMeta.name) throw new Error("站点名不能为空");
    e.meta = await encryptMeta(key, nextMeta);
    if (password !== undefined && password !== null) {
      e.secret = await C.encryptStr(key, password);
    }
    e.updated = Date.now();
    metaCache.set(id, nextMeta);
    persist();
    triggerSync();
  }

  async function decryptPassword(id) {
    requireUnlocked();
    const e = state.entries.find(x => x.id === id);
    if (!e) throw new Error("条目不存在");
    return C.decryptStr(key, e.secret.nonce, e.secret.ct);
  }

  function deleteEntry(id) {
    requireUnlocked();
    const i = state.entries.findIndex(x => x.id === id);
    if (i < 0) throw new Error("条目不存在");
    const [removed] = state.entries.splice(i, 1);
    metaCache.delete(id);
    persist();
    triggerSync();
    return removed;
  }

  async function changeMaster(oldPassword, newPassword, iterations = C.KDF.iterations) {
    requireUnlocked();
    const vault = readRaw();
    validateVault(vault);
    const oldSalt = C.unb64(vault.kdf.salt);
    const oldCheck = await C.deriveKey(oldPassword, oldSalt, vault.kdf.iterations);
    if (!(await C.checkVerifier(oldCheck, vault.verifier))) {
      throw new Error("旧主密码错误");
    }

    const newSalt = C.randomBytes(16);
    const newKey = await C.deriveKey(newPassword, newSalt, iterations);
    const newEntries = [];
    const newMetaCache = new Map();
    for (const e of state.entries) {
      const meta = metaCache.get(e.id) || await decryptMeta(key, e);
      const plain = await C.decryptStr(key, e.secret.nonce, e.secret.ct);
      newEntries.push({
        ...e,
        meta: await encryptMeta(newKey, meta),
        secret: await C.encryptStr(newKey, plain),
      });
      newMetaCache.set(e.id, meta);
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
    metaCache = newMetaCache;
    if (VAULT.SYNC) await VAULT.SYNC.rekey(newKey);
    triggerSync();
  }

  function exportVault() {
    const v = readRaw();
    if (!v) throw new Error("无保险库可导出");
    return JSON.stringify(v, null, 2);
  }

  function importVault(jsonStr) {
    let obj;
    try { obj = JSON.parse(jsonStr); }
    catch { throw new Error("导入文件不是有效 JSON"); }
    validateVault(obj, "导入文件");
    writeRaw(obj);
    if (VAULT.SYNC) VAULT.SYNC.disable();
    lock();
  }

  async function applyRemoteVault(jsonStr) {
    let obj;
    try { obj = JSON.parse(jsonStr); }
    catch { throw new Error("远端数据不是有效 JSON"); }
    validateVault(obj, "远端数据");
    writeRaw(obj);
    if (key) {
      state = obj;
      await hydrateMetaCache(obj);
    } else {
      state = null;
      metaCache = new Map();
    }
  }

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
