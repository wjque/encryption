// ============================================================
// encoding.js —— 字节/字符串/base64/hex 编码 + 密钥 JSON I/O
// 对应 rsa.py 中 base64、json、to_bytes/from_bytes 等逻辑
// ============================================================
(function (global) {
  "use strict";
  const RSA = (global.RSA = global.RSA || {});

  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: false });

  // --- UTF-8 文本 <-> 字节 ---
  function utf8ToBytes(s) { return enc.encode(s); }
  function bytesToUtf8(b) { return dec.decode(b); }

  // --- base64 ---
  function bytesToBase64(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }
  function base64ToBytes(str) {
    const bin = atob(str.trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // --- 十六进制 ---
  function bytesToHex(bytes) {
    let s = "";
    for (const b of bytes) s += b.toString(16).padStart(2, "0");
    return s;
  }
  function hexToBytes(hex) {
    hex = hex.length % 2 ? "0" + hex : hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  // --- BigInt <-> 大端字节 ---
  function bigIntToBytes(n, len) {
    if (len === undefined) len = Math.ceil(RSA.bitLength(n) / 8) || 1;
    const out = new Uint8Array(len);
    let v = n;
    for (let i = len - 1; i >= 0; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }
  function bytesToBigInt(bytes) {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    return n;
  }

  Object.assign(RSA, {
    utf8ToBytes, bytesToUtf8,
    bytesToBase64, base64ToBytes,
    bytesToHex, hexToBytes,
    bigIntToBytes, bytesToBigInt,
  });
})(window);
