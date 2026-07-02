// ============================================================
// vault/generator.js —— 强密码生成器
//
// 用 crypto.getRandomValues 生成密码，采用「拒绝采样」消除模偏：
// 直接 rand % charsetLen 会让靠前的字符出现频率略高，故丢弃超过
// 最大均匀区间的字节重新取。
// ============================================================
(function (global) {
  "use strict";
  const VAULT = (global.VAULT = global.VAULT || {});

  const SETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digit: "0123456789",
    symbol: "!@#$%^&*()-_=+[]{};:,.?/~",
  };
  const DEFAULT_SYMBOL = "!@#$%^&*-_=+?";

  // 从 charset 中取一个无偏随机字符
  function pickUnbiased(charset) {
    const n = charset.length;
    // 256 % n 为偏倚区间大小；上限为最后一个完整区间的末尾
    const limit = 256 - (256 % n);
    const buf = new Uint8Array(1);
    while (true) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) return charset[buf[0] % n];
    }
  }

  // 生成密码
  // opts: {length, lower, upper, digit, symbol, avoidAmbiguous, customSymbol}
  function generate(opts = {}) {
    const length = Math.max(4, opts.length || 20);
    let pools = [];
    if (opts.lower !== false) pools.push(SETS.lower);
    if (opts.upper !== false) pools.push(SETS.upper);
    if (opts.digit !== false) pools.push(SETS.digit);
    let symbols = opts.customSymbol || DEFAULT_SYMBOL;
    if (opts.symbol) pools.push(symbols);
    if (pools.length === 0) pools.push(SETS.lower); // 兜底

    // 易混淆字符（0/O/o, 1/I/l）可选剔除
    let ambiguous = opts.avoidAmbiguous ? "0Oo1Il" : "";
    pools = pools.map(p => p.split("").filter(c => !ambiguous.includes(c)).join(""));

    let charset = pools.join("");
    if (!charset) charset = SETS.lower;

    // 先从每个 pool 各取一个，保证类型齐全；再随机补足长度
    let chars = [];
    for (const p of pools) if (p.length) chars.push(pickUnbiased(p));
    while (chars.length < length) chars.push(pickUnbiased(charset));

    // Fisher-Yates 打乱（用无偏随机索引）
    for (let i = chars.length - 1; i > 0; i--) {
      const j = Math.floor(unbiasedInt(i + 1));
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.slice(0, length).join("");
  }

  // [0, n) 内无偏随机整数
  function unbiasedInt(n) {
    const limit = 0x100000000 - (0x100000000 % n);
    const buf = new Uint8Array(4);
    while (true) {
      crypto.getRandomValues(buf);
      const x = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
      if (x >>> 0 < limit) return (x >>> 0) % n;
    }
  }

  // 估算强度（熵位数）
  function entropyBits(opts = {}) {
    let size = 0;
    if (opts.lower !== false) size += 26;
    if (opts.upper !== false) size += 26;
    if (opts.digit !== false) size += 10;
    if (opts.symbol) size += (opts.customSymbol || DEFAULT_SYMBOL).length;
    const length = Math.max(4, opts.length || 20);
    return size > 0 ? Math.round(length * Math.log2(size)) : 0;
  }

  function strengthLabel(bits) {
    if (bits >= 128) return { label: "极强", cls: "excellent" };
    if (bits >= 80) return { label: "强", cls: "strong" };
    if (bits >= 50) return { label: "中等", cls: "medium" };
    return { label: "弱", cls: "weak" };
  }

  Object.assign(VAULT, {
    SETS, DEFAULT_SYMBOL, generate, entropyBits, strengthLabel,
  });
})(window);
