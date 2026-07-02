// ============================================================
// bigint.js —— 大整数 / 数论工具
// 对应 rsa.py 第一节「大整数 / 数论工具」
// 全部挂在 window.RSA 下。BigInt 原生支持任意大整数。
// ============================================================
(function (global) {
  "use strict";
  const RSA = (global.RSA = global.RSA || {});

  // --- 位长度：等价 Python int.bit_length() ---
  function bitLength(n) {
    if (n < 0n) n = -n;
    if (n === 0n) return 0;
    return n.toString(2).length;
  }

  // --- 快速幂取模：BigInt 无原生 modpow，自实现 ---
  // a ** b mod m，b >= 0
  function modPow(base, exp, m) {
    if (m === 1n) return 0n;
    let result = 1n;
    base = base % m;
    if (base < 0n) base += m;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % m;
      exp >>= 1n;
      base = (base * base) % m;
    }
    return result;
  }

  // --- 密码学随机数 ---
  function randBits(bits) {
    const bytes = Math.ceil(bits / 8);
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    let n = 0n;
    for (const b of buf) n = (n << 8n) | BigInt(b);
    // 截断到指定位数
    return n & ((1n << BigInt(bits)) - 1n);
  }

  function randBelow(n) {
    // 返回 [0, n) 内均匀随机数
    const bits = bitLength(n);
    let x;
    do {
      x = randBits(bits);
    } while (x >= n);
    return x;
  }

  // --- Miller-Rabin 素性检测 ---
  function isProbablePrime(n, rounds = 40) {
    if (n < 2n) return false;
    // 小素数预筛
    for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
      if (n % p === 0n) return n === p;
    }
    // n-1 = d * 2^r
    let d = n - 1n;
    let r = 0n;
    while (d % 2n === 0n) {
      d >>= 1n;
      r += 1n;
    }
    for (let i = 0; i < rounds; i++) {
      const a = 2n + randBelow(n - 3n);
      let x = modPow(a, d, n);
      if (x === 1n || x === n - 1n) continue;
      let composite = true;
      for (let j = 0n; j < r - 1n; j++) {
        x = modPow(x, 2n, n);
        if (x === n - 1n) {
          composite = false;
          break;
        }
      }
      if (composite) return false;
    }
    return true;
  }

  // --- 生成指定位数的随机大素数 ---
  function genPrime(bits) {
    while (true) {
      // 最高位置 1 保证位数，最低位置 1 保证为奇数
      let cand = randBits(bits) | (1n << BigInt(bits - 1)) | 1n;
      if (isProbablePrime(cand)) return cand;
    }
  }

  // --- 扩展欧几里得（迭代版，避免深递归）---
  // 返回 [g, x, y] 满足 a*x + b*y = g
  function egcd(a, b) {
    let [oldR, r] = [a, b];
    let [oldS, s] = [1n, 0n];
    let [oldT, t] = [0n, 1n];
    while (r !== 0n) {
      const q = oldR / r;
      [oldR, r] = [r, oldR - q * r];
      [oldS, s] = [s, oldS - q * s];
      [oldT, t] = [t, oldT - q * t];
    }
    return [oldR, oldS, oldT];
  }

  // --- 模逆：a^{-1} mod m ---
  function modInv(a, m) {
    const [g, x] = egcd(((a % m) + m) % m, m);
    if (g !== 1n) throw new Error("模逆元不存在，e 与 φ(n) 不互素");
    return ((x % m) + m) % m;
  }

  Object.assign(RSA, {
    bitLength,
    modPow,
    randBits,
    randBelow,
    isProbablePrime,
    genPrime,
    egcd,
    modInv,
  });
})(window);
