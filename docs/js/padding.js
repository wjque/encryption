// ============================================================
// padding.js —— OAEP（加密填充）+ PSS（签名）
// 对应 rsa.py 第四节「标准填充：OAEP 与 PSS」，符合 RFC 8017 (PKCS#1 v2.2)
// 浏览器用 crypto.subtle.digest（异步），故本模块全为 async。
// ============================================================
(function (global) {
  "use strict";
  const RSA = (global.RSA = global.RSA || {});

  // WebCrypto 仅支持 SHA-1/256/384/512（规范不含 SHA-224），故网页版不含 sha224。
  const HASHES = ["sha1", "sha256", "sha384", "sha512"];
  const HASH_SIZE = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };
  // WebCrypto 需要规范名（SHA-256），用户/API 使用小写名以与 Python 版一致
  const WEBCRYPTO_NAME = {
    sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512",
  };

  // 异步哈希：返回 Uint8Array
  async function hash(name, data) {
    if (!HASHES.includes(name)) throw new Error("不支持的哈希: " + name);
    const buf = await crypto.subtle.digest(WEBCRYPTO_NAME[name], data);
    return new Uint8Array(buf);
  }
  function hashSize(name) { return HASH_SIZE[name]; }

  // 等长字节异或
  function xorBytes(a, b) {
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  // MGF1（异步）
  async function mgf1(seed, length, name) {
    const out = [];
    let counter = 0;
    let total = 0;
    while (total < length) {
      const ctr = new Uint8Array(4);
      ctr[0] = (counter >>> 24) & 0xff; ctr[1] = (counter >>> 16) & 0xff;
      ctr[2] = (counter >>> 8) & 0xff; ctr[3] = counter & 0xff;
      const h = await hash(name, RSA.concat([seed, ctr]));
      out.push(h);
      total += h.length;
      counter++;
    }
    const full = RSA.concat(out);
    return full.subarray(0, length);
  }

  // ---- RSAES-OAEP ----

  async function oaepEncryptBlock(mBlock, n, exp, name) {
    const k = RSA.byteLen(n);
    const hLen = hashSize(name);
    if (mBlock.length > k - 2 * hLen - 2) throw new Error("OAEP: 消息块过长");
    const lHash = await hash(name, new Uint8Array(0));
    const ps = new Uint8Array(k - mBlock.length - 2 * hLen - 2);
    // db = lHash + ps + 0x01 + mBlock
    const sep = new Uint8Array([1]);
    const db = RSA.concat([lHash, ps, sep, mBlock]);      // k - hLen - 1 字节
    const seed = new Uint8Array(hLen);
    crypto.getRandomValues(seed);
    const dbMask = await mgf1(seed, k - hLen - 1, name);
    const maskedDb = xorBytes(db, dbMask);
    const seedMask = await mgf1(maskedDb, hLen, name);
    const maskedSeed = xorBytes(seed, seedMask);
    const em = RSA.concat([new Uint8Array([0]), maskedSeed, maskedDb]); // k 字节
    const c = RSA.modPow(RSA.bytesToBigInt(em), exp, n);
    return RSA.bigIntToBytes(c, k);
  }

  async function oaepDecryptBlock(cBlock, n, exp, name) {
    const k = RSA.byteLen(n);
    const hLen = hashSize(name);
    if (cBlock.length !== k || k < 2 * hLen + 2) throw new Error("OAEP: 密文块长度非法");
    const mInt = RSA.modPow(RSA.bytesToBigInt(cBlock), exp, n);
    const em = RSA.bigIntToBytes(mInt, k);
    const lHash = await hash(name, new Uint8Array(0));
    const y = em[0];
    const maskedSeed = em.subarray(1, 1 + hLen);
    const maskedDb = em.subarray(1 + hLen);
    const seed = xorBytes(maskedSeed, await mgf1(maskedDb, hLen, name));
    const db = xorBytes(maskedDb, await mgf1(seed, k - hLen - 1, name));
    const lHash2 = db.subarray(0, hLen);
    // 跳过全零 PS，找到 0x01 分隔符
    let i = hLen;
    while (i < db.length && db[i] === 0) i++;
    // 常量时间风格：所有错误统一抛出
    let ok = (y === 0);
    if (!lHashEqual(lHash, lHash2)) ok = false;
    if (i >= db.length || db[i] !== 1) ok = false;
    if (!ok) throw new Error("OAEP: 解密失败（填充校验未通过）");
    return db.subarray(i + 1);
  }
  function lHashEqual(a, b) {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
    return r === 0;
  }

  async function oaepEncrypt(data, n, exp, name) {
    const k = RSA.byteLen(n);
    const hLen = hashSize(name);
    const maxMsg = k - 2 * hLen - 2;
    if (maxMsg < 1) throw new Error("密钥/哈希组合下 OAEP 单块容量不足");
    const chunks = [];
    for (let i = 0; i < data.length; i += maxMsg) chunks.push(data.subarray(i, i + maxMsg));
    if (chunks.length === 0) chunks.push(new Uint8Array(0));
    const out = [];
    for (const ch of chunks) out.push(await oaepEncryptBlock(ch, n, exp, name));
    return RSA.concat(out);
  }

  async function oaepDecrypt(data, n, exp, name) {
    const k = RSA.byteLen(n);
    if (data.length === 0 || data.length % k !== 0) throw new Error("OAEP: 密文总长度与密钥不匹配");
    const out = [];
    for (let i = 0; i < data.length; i += k)
      out.push(await oaepDecryptBlock(data.subarray(i, i + k), n, exp, name));
    return RSA.concat(out);
  }

  // ---- RSASSA-PSS ----

  async function pssSign(message, priv, hashName = "sha256", saltLen = null) {
    const hLen = hashSize(hashName);
    if (saltLen === null || saltLen === undefined) saltLen = hLen;
    const n = priv.n, d = priv.d;
    const modBits = RSA.bitLength(n);
    const emBits = modBits - 1;
    const emLen = Math.ceil(emBits / 8);
    if (emLen < hLen + saltLen + 2) throw new Error("PSS: 密钥位数不足以容纳签名");
    const mHash = await hash(hashName, message);
    const salt = new Uint8Array(saltLen);
    crypto.getRandomValues(salt);
    const mPrime = RSA.concat([new Uint8Array(8), mHash, salt]);
    const h = await hash(hashName, mPrime);
    const ps = new Uint8Array(emLen - saltLen - hLen - 2);
    const db = RSA.concat([ps, new Uint8Array([1]), salt]);   // emLen - hLen - 1 字节
    const dbMask = await mgf1(h, emLen - hLen - 1, hashName);
    const maskedDb = xorBytes(db, dbMask);
    const bitsToZero = 8 * emLen - emBits;
    if (bitsToZero) maskedDb[0] &= 0xff >> bitsToZero;
    const em = RSA.concat([maskedDb, h, new Uint8Array([0xbc])]);
    const s = RSA.modPow(RSA.bytesToBigInt(em), d, n);
    return RSA.bigIntToBytes(s, RSA.byteLen(n));
  }

  async function pssVerify(message, signature, pub, hashName = "sha256", saltLen = null) {
    const hLen = hashSize(hashName);
    const n = pub.n, e = pub.e;
    const k = RSA.byteLen(n);
    if (signature.length !== k) return false;
    const s = RSA.bytesToBigInt(signature);
    if (s >= n) return false;
    const modBits = RSA.bitLength(n);
    const emBits = modBits - 1;
    const emLen = Math.ceil(emBits / 8);
    const mInt = RSA.modPow(s, e, n);
    const em = RSA.bigIntToBytes(mInt, emLen);
    const mHash = await hash(hashName, message);
    if (emLen < hLen + 2 || em[emLen - 1] !== 0xbc) return false;
    const maskedDb = em.subarray(0, emLen - hLen - 1);
    const h = em.subarray(emLen - hLen - 1, emLen - 1);
    const bitsToZero = 8 * emLen - emBits;
    if (bitsToZero && (maskedDb[0] & ((0xff << (8 - bitsToZero)) & 0xff))) return false;
    const dbMask = await mgf1(h, emLen - hLen - 1, hashName);
    const db = xorBytes(maskedDb, dbMask);
    const dbArr = new Uint8Array(db);
    if (bitsToZero) dbArr[0] &= 0xff >> bitsToZero;
    let salt;
    if (saltLen === null || saltLen === undefined) {
      let i = 0;
      while (i < dbArr.length && dbArr[i] === 0) i++;
      if (i >= dbArr.length || dbArr[i] !== 1) return false;
      salt = dbArr.subarray(i + 1);
    } else {
      const psLen = emLen - saltLen - hLen - 2;
      if (psLen < 0) return false;
      for (let i = 0; i < psLen; i++) if (dbArr[i] !== 0) return false;
      if (dbArr[psLen] !== 1) return false;
      salt = dbArr.subarray(psLen + 1);
    }
    const mPrime = RSA.concat([new Uint8Array(8), mHash, salt]);
    const h2 = await hash(hashName, mPrime);
    return lHashEqual(h, h2);
  }

  Object.assign(RSA, {
    HASHES, hash, hashSize, xorBytes, mgf1,
    oaepEncryptBlock, oaepDecryptBlock, oaepEncrypt, oaepDecrypt,
    pssSign, pssVerify,
  });
})(window);
