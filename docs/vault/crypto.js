// ============================================================
// vault/crypto.js —— 密码派生 + 对称加解密（WebCrypto 原生）
//
// 安全模型：
//   主密码 ──PBKDF2(SHA-256, 600k)──> AES-256-GCM 密钥
//   密钥 extractable=false，不可导出，仅驻留内存；锁定即丢弃。
//   每条站点密码用独立随机 nonce + AES-GCM 加密（密文含认证标签）。
//
// 无任何第三方依赖、无网络请求。
// ============================================================
(function (global) {
  "use strict";
  const VAULT = (global.VAULT = global.VAULT || {});

  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: false });

  const KDF = { algorithm: "PBKDF2", hash: "SHA-256", iterations: 600000 };
  const MAGIC = enc.encode("VAULT_OK_v1"); // 用于验证主密码是否正确

  // --- base64 <-> Uint8Array ---
  function b64(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }
  function unb64(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function utf8(s) { return enc.encode(s); }
  function fromUtf8(b) { return dec.decode(b); }

  // --- 随机盐 / nonce ---
  function randomBytes(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
  }

  // --- 由主密码派生 AES-GCM 密钥（不可导出）---
  async function deriveKey(password, salt, iterations = KDF.iterations) {
    const baseKey = await crypto.subtle.importKey(
      "raw", utf8(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: KDF.hash },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,            // extractable: false —— 密钥无法被导出
      ["encrypt", "decrypt"]);
  }

  // --- 加密字节：返回 {nonce, ct}（ct 含 16 字节 GCM 认证标签）---
  async function encrypt(key, data) {
    const nonce = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data);
    return { nonce, ct: new Uint8Array(ct) };
  }

  // --- 解密字节；密文被篡改或密钥错误时抛错（GCM 认证失败）---
  async function decrypt(key, nonce, ct) {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
    return new Uint8Array(pt);
  }

  // --- 加密字符串 ---
  async function encryptStr(key, str) {
    const { nonce, ct } = await encrypt(key, utf8(str));
    return { nonce: b64(nonce), ct: b64(ct) };
  }
  async function decryptStr(key, nonceB64, ctB64) {
    const pt = await decrypt(key, unb64(nonceB64), unb64(ctB64));
    return fromUtf8(pt);
  }

  // --- 生成验证器：加密 MAGIC，用于解锁时校验主密码 ---
  async function makeVerifier(key) {
    return encryptStr(key, MAGIC_STR());
  }
  function MAGIC_STR() { return "VAULT_OK_v1"; }

  // --- 校验主密码：尝试解密验证器；失败则密码错误 ---
  // 通过「解密不抛错 + 明文==MAGIC」双重确认
  async function checkVerifier(key, verifier) {
    try {
      const pt = await decryptStr(key, verifier.nonce, verifier.ct);
      return pt === MAGIC_STR();
    } catch { return false; }
  }

  Object.assign(VAULT, {
    KDF, b64, unb64, utf8, fromUtf8, randomBytes,
    deriveKey, encrypt, decrypt, encryptStr, decryptStr,
    makeVerifier, checkVerifier,
  });
})(window);
