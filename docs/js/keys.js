// ============================================================
// keys.js —— 密钥结构 + 密钥对生成
// 对应 rsa.py 第二节「密钥结构」+ generate_keypair
// JSON 格式与 Python 版完全一致，保证互通：
//   公钥 {kty:"RSA-pub", n:"0x...", e:65537}
//   私钥 {kty:"RSA-priv", n:"0x...", e:65537, d:"0x...", p:"0x...", q:"0x..."}
//   （n/d/p/q 为十六进制字符串，e 为十进制整数，与 Python hex()/int() 一致）
// ============================================================
(function (global) {
  "use strict";
  const RSA = (global.RSA = global.RSA || {});

  function hexStr(n) { return "0x" + n.toString(16); }
  // Python 端：n/d/p/q 以 hex 字符串存储（int(x,16) 解析），e 以十进制整数存储（int(x) 解析）。
  // BigInt("0x...") 与 BigInt("65537") 均可正确解析对应格式。
  function parseHexField(s) { return BigInt(String(s).trim()); }     // 形如 "0x..."
  function parseDecField(s) { return BigInt(String(s).trim()); }     // 形如 65537

  class RSAPublicKey {
    constructor(n, e) { this.n = n; this.e = e; }
    toJSON() {
      return { kty: "RSA-pub", n: hexStr(this.n), e: Number(this.e) };
    }
    static fromJSON(d) {
      return new RSAPublicKey(parseHexField(d.n), parseDecField(d.e));
    }
    get bits() { return RSA.bitLength(this.n); }
  }

  class RSAPrivateKey {
    constructor(n, e, d, p, q) {
      this.n = n; this.e = e; this.d = d; this.p = p; this.q = q;
    }
    public() { return new RSAPublicKey(this.n, this.e); }
    toJSON() {
      return {
        kty: "RSA-priv",
        n: hexStr(this.n), e: Number(this.e),
        d: hexStr(this.d), p: hexStr(this.p), q: hexStr(this.q),
      };
    }
    static fromJSON(d) {
      return new RSAPrivateKey(
        parseHexField(d.n), parseDecField(d.e),
        parseHexField(d.d), parseHexField(d.p), parseHexField(d.q)
      );
    }
    get bits() { return RSA.bitLength(this.n); }
  }

  // 自动识别公钥/私钥 JSON
  function keyFromJSON(obj) {
    if (typeof obj === "string") obj = JSON.parse(obj);
    if (obj.kty === "RSA-priv" || obj.d !== undefined) return RSAPrivateKey.fromJSON(obj);
    return RSAPublicKey.fromJSON(obj);
  }
  function keyToJSON(key) { return JSON.stringify(key.toJSON(), null, 2); }

  // --- 生成密钥对，返回 RSAPrivateKey ---
  // 异步：每轮让出事件循环，避免阻塞 UI（密钥生成耗时）
  async function generateKeyPair(bits = 1024, e = 65537n) {
    if (bits < 512) throw new Error("密钥位数过小，至少 512 位");
    const E = BigInt(e);
    const half = bits >> 1;
    while (true) {
      const p = RSA.genPrime(half);
      const q = RSA.genPrime(bits - half);
      if (p === q) continue;
      const n = p * q;
      if (RSA.bitLength(n) !== bits) continue;
      const phi = (p - 1n) * (q - 1n);
      if (RSA.egcd(E, phi)[0] !== 1n) continue;
      const d = RSA.modInv(E, phi);
      return new RSAPrivateKey(n, E, d, p, q);
    }
  }

  Object.assign(RSA, {
    RSAPublicKey, RSAPrivateKey,
    keyFromJSON, keyToJSON, generateKeyPair,
  });
})(window);
