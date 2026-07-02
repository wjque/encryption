// ============================================================
// crypto.js —— 分块加解密 + 高层 encrypt/decrypt 接口
// 对应 rsa.py 第三节「分块加解密」+ 第五节「高层加解密接口」
// 教科书模式（padding="none"）：4 字节长度前缀 + 右填充至整块的帧格式
// OAEP 由 padding.js 提供，本文件按 padding 参数分发
// ============================================================
(function (global) {
  "use strict";
  const RSA = (global.RSA = global.RSA || {});

  function byteLen(n) { return Math.ceil(RSA.bitLength(n) / 8); }

  // 明文每块的最多字节数，保证块整数 < n
  function blockSize(n) {
    const sz = Math.floor((RSA.bitLength(n) - 1) / 8);
    return sz >= 1 ? sz : 1;
  }

  // 拼接 Uint8Array
  function concat(arr) {
    let total = 0;
    for (const a of arr) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arr) { out.set(a, off); off += a.length; }
    return out;
  }

  // --- 教科书加密：用指数 exp 对 data 加密 ---
  function _encryptBytes(data, exp, n) {
    const k = byteLen(n);
    const blk = blockSize(n);
    // 前 4 字节记录原始长度（大端）
    const lenBytes = new Uint8Array(4);
    let L = data.length;
    lenBytes[0] = (L >>> 24) & 0xff; lenBytes[1] = (L >>> 16) & 0xff;
    lenBytes[2] = (L >>> 8) & 0xff; lenBytes[3] = L & 0xff;
    let framed = concat([lenBytes, data]);
    // 右填充到 blk 整数倍（JS % 对负数返回负数，故用 (blk - x%blk) % blk）
    const pad = (blk - (framed.length % blk)) % blk;
    if (pad) framed = concat([framed, new Uint8Array(pad)]);
    const out = [];
    for (let i = 0; i < framed.length; i += blk) {
      const m = RSA.bytesToBigInt(framed.subarray(i, i + blk));
      const c = RSA.modPow(m, exp, n);
      out.push(RSA.bigIntToBytes(c, k));
    }
    return concat(out);
  }

  // --- 教科书解密 ---
  function _decryptBytes(data, exp, n) {
    const k = byteLen(n);
    const blk = blockSize(n);
    if (data.length === 0 || data.length % k !== 0)
      throw new Error("密文长度与密钥不匹配");
    const out = [];
    for (let i = 0; i < data.length; i += k) {
      const c = RSA.bytesToBigInt(data.subarray(i, i + k));
      const m = RSA.modPow(c, exp, n);
      out.push(RSA.bigIntToBytes(m, blk));
    }
    const framed = concat(out);
    const length = (framed[0] << 24) | (framed[1] << 16) | (framed[2] << 8) | framed[3];
    if (length > framed.length - 4) throw new Error("解密失败：长度字段非法");
    return framed.subarray(4, 4 + length);
  }

  // --- 高层加密 ---
  // mode="public": 公钥 e 加密；mode="private": 私钥 d 加密
  // padding="none"/"oaep"(仅 public)；hashName 用于 OAEP
  async function encrypt(plaintext, key, mode, padding = "none", hashName = "sha256") {
    let exp, n;
    if (mode === "public") { exp = key.e; n = key.n; }
    else if (mode === "private") {
      if (!(key instanceof RSA.RSAPrivateKey)) throw new Error("私钥加密需要 RSAPrivateKey");
      exp = key.d; n = key.n;
    } else throw new Error("未知 mode: " + mode);

    if (padding === "none") return _encryptBytes(plaintext, exp, n);
    if (padding === "oaep") {
      if (mode !== "public") throw new Error("OAEP 仅用于公钥加密；私钥运算请用 sign(PSS)");
      return RSA.oaepEncrypt(plaintext, n, exp, hashName);
    }
    throw new Error("未知 padding: " + padding);
  }

  // --- 高层解密 ---
  async function decrypt(ciphertext, key, mode, padding = "none", hashName = "sha256") {
    let exp, n;
    if (mode === "public") {
      if (!(key instanceof RSA.RSAPrivateKey)) throw new Error("公钥加密的密文需用 RSAPrivateKey 解密");
      exp = key.d; n = key.n;
    } else if (mode === "private") { exp = key.e; n = key.n; }
    else throw new Error("未知 mode: " + mode);

    if (padding === "none") return _decryptBytes(ciphertext, exp, n);
    if (padding === "oaep") {
      if (mode !== "public") throw new Error("OAEP 仅用于公钥加密的密文");
      return RSA.oaepDecrypt(ciphertext, n, exp, hashName);
    }
    throw new Error("未知 padding: " + padding);
  }

  Object.assign(RSA, {
    byteLen, blockSize, concat,
    _encryptBytes, _decryptBytes,
    encrypt, decrypt,
  });
})(window);
