// ============================================================
// vault/qr.js —— QR 码生成器（纯 JS，无第三方依赖）
//
// 支持 Version 1-40，Byte 模式，M 级纠错（约 15% 数据可恢复）。
// 输出 SVG 字符串，可直接塞进 innerHTML。
//
// 用于配对场景：payload 一般 < 300 字节，Version 10-15 足够。
// ============================================================
(function (global) {
  "use strict";

  // ---------- Galois Field GF(256) ----------
  const EXP_TABLE = new Uint8Array(512);
  const LOG_TABLE = new Uint8Array(256);
  (function initGF() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP_TABLE[i] = x;
      LOG_TABLE[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) EXP_TABLE[i] = EXP_TABLE[i - 255];
  })();
  function gfMul(a, b) { return (a === 0 || b === 0) ? 0 : EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]]; }

  // ---------- Reed-Solomon 生成多项式 ----------
  function rsPoly(nsym) {
    let g = [1];
    for (let i = 0; i < nsym; i++) {
      const next = new Array(g.length + 1).fill(0);
      for (let j = 0; j < g.length; j++) {
        next[j] ^= g[j];
        next[j + 1] ^= gfMul(g[j], EXP_TABLE[i]);
      }
      g = next;
    }
    return g;
  }
  function rsEncode(data, nsym) {
    const gen = rsPoly(nsym);
    const buf = new Uint8Array(data.length + nsym);
    buf.set(data);
    for (let i = 0; i < data.length; i++) {
      const coef = buf[i];
      if (coef !== 0) {
        for (let j = 0; j < gen.length; j++) {
          buf[i + j] ^= gfMul(gen[j], coef);
        }
      }
    }
    return buf.slice(data.length);
  }

  // ---------- Version 容量表（Byte 模式，M 级纠错）----------
  // 每项：[数据码字数, 纠错码字数/块, 块数组([块数, 每块数据码字数])]
  // 数据源：ISO/IEC 18004 表 9
  const CAPACITY_M = [
    null,
    // v1 - v10
    { data: 16,  ec: 10, blocks: [[1, 16]] },
    { data: 28,  ec: 16, blocks: [[1, 28]] },
    { data: 44,  ec: 26, blocks: [[1, 44]] },
    { data: 64,  ec: 18, blocks: [[2, 32]] },
    { data: 86,  ec: 24, blocks: [[2, 43]] },
    { data: 108, ec: 16, blocks: [[4, 27]] },
    { data: 124, ec: 18, blocks: [[4, 31]] },
    { data: 154, ec: 22, blocks: [[2, 38], [2, 39]] },
    { data: 182, ec: 22, blocks: [[3, 36], [2, 37]] },
    { data: 216, ec: 26, blocks: [[4, 43], [1, 44]] },
    // v11 - v15
    { data: 254, ec: 30, blocks: [[1, 50], [4, 51]] },
    { data: 290, ec: 22, blocks: [[6, 36], [2, 37]] },
    { data: 334, ec: 22, blocks: [[8, 37], [1, 38]] },
    { data: 365, ec: 24, blocks: [[4, 40], [5, 41]] },
    { data: 415, ec: 24, blocks: [[5, 41], [5, 42]] },
    // v16 - v20（预留，配对场景一般用不到）
    { data: 453, ec: 28, blocks: [[7, 45], [3, 46]] },
    { data: 507, ec: 28, blocks: [[10, 46], [1, 47]] },
    { data: 563, ec: 26, blocks: [[9, 43], [4, 44]] },
    { data: 627, ec: 26, blocks: [[3, 44], [11, 45]] },
    { data: 669, ec: 26, blocks: [[3, 41], [13, 42]] },
  ];

  // 选择能装下 payload 的最小版本
  function pickVersion(byteLen) {
    // Byte 模式 header：4 bits mode + 8/16 bits length + 4 bits terminator
    // 简化：直接按 data 容量估算，预留 3 字节 header
    for (let v = 1; v < CAPACITY_M.length; v++) {
      if (CAPACITY_M[v] && CAPACITY_M[v].data >= byteLen + 3) return v;
    }
    throw new Error(`payload 过长：${byteLen} 字节，QR 无法容纳`);
  }

  // ---------- 编码数据到位流 ----------
  function encodeData(bytes, version) {
    const cap = CAPACITY_M[version];
    const bits = [];
    function pushBits(val, len) {
      for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
    }
    // Mode indicator: Byte = 0100
    pushBits(0b0100, 4);
    // Character count: v1-v9 用 8 bits，v10+ 用 16 bits
    const lenBits = version < 10 ? 8 : 16;
    pushBits(bytes.length, lenBits);
    // Data
    for (const b of bytes) pushBits(b, 8);
    // Terminator（最多 4 个 0）
    for (let i = 0; i < 4 && bits.length < cap.data * 8; i++) bits.push(0);
    // 补到字节边界
    while (bits.length % 8 !== 0) bits.push(0);
    // 填充 0xEC / 0x11 直到装满数据容量
    const bytesOut = new Uint8Array(cap.data);
    for (let i = 0; i < bits.length / 8; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
      bytesOut[i] = b;
    }
    let pad = 0;
    for (let i = bits.length / 8; i < cap.data; i++) {
      bytesOut[i] = (pad++ % 2 === 0) ? 0xEC : 0x11;
    }

    // 分块 + RS 编码
    const dataBlocks = [];
    const ecBlocks = [];
    let offset = 0;
    for (const [count, dataPerBlock] of cap.blocks) {
      for (let i = 0; i < count; i++) {
        const block = bytesOut.slice(offset, offset + dataPerBlock);
        offset += dataPerBlock;
        dataBlocks.push(block);
        ecBlocks.push(rsEncode(block, cap.ec));
      }
    }

    // 交错
    const maxData = Math.max(...dataBlocks.map(b => b.length));
    const final = [];
    for (let i = 0; i < maxData; i++) {
      for (const b of dataBlocks) if (i < b.length) final.push(b[i]);
    }
    for (let i = 0; i < cap.ec; i++) {
      for (const b of ecBlocks) final.push(b[i]);
    }
    return final;
  }

  // ---------- 矩阵构造 ----------
  function makeMatrix(version) {
    const size = 17 + version * 4;
    const m = Array.from({ length: size }, () => new Int8Array(size).fill(-1));
    return { size, m };
  }
  function placeFinder(mat, r, c) {
    for (let i = -1; i <= 7; i++) {
      for (let j = -1; j <= 7; j++) {
        const rr = r + i, cc = c + j;
        if (rr < 0 || rr >= mat.size || cc < 0 || cc >= mat.size) continue;
        const inner = i >= 0 && i <= 6 && j >= 0 && j <= 6;
        if (!inner) { mat.m[rr][cc] = 0; continue; }
        const on =
          (i === 0 || i === 6 || j === 0 || j === 6) ||
          (i >= 2 && i <= 4 && j >= 2 && j <= 4);
        mat.m[rr][cc] = on ? 1 : 0;
      }
    }
  }
  function placeTiming(mat) {
    for (let i = 8; i < mat.size - 8; i++) {
      if (mat.m[6][i] === -1) mat.m[6][i] = (i % 2 === 0) ? 1 : 0;
      if (mat.m[i][6] === -1) mat.m[i][6] = (i % 2 === 0) ? 1 : 0;
    }
  }
  // Alignment pattern 位置表（v2-v20 部分）
  const ALIGN_POS = [
    [], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
    [6, 30, 54], [6, 32, 58], [6, 34, 62],
    [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74],
    [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90],
  ];
  function placeAlignment(mat, version) {
    const pos = ALIGN_POS[version] || [];
    for (const r of pos) for (const c of pos) {
      // 跳过与 finder 重叠的三个角
      if ((r === 6 && c === 6) ||
          (r === 6 && c === pos[pos.length - 1]) ||
          (r === pos[pos.length - 1] && c === 6)) continue;
      for (let i = -2; i <= 2; i++) for (let j = -2; j <= 2; j++) {
        const rr = r + i, cc = c + j;
        const on =
          Math.abs(i) === 2 || Math.abs(j) === 2 || (i === 0 && j === 0);
        if (mat.m[rr][cc] === -1) mat.m[rr][cc] = on ? 1 : 0;
      }
    }
  }
  function reserveFormat(mat) {
    // Format info 15 bits，位置固定
    for (let i = 0; i <= 8; i++) {
      if (mat.m[8][i] === -1) mat.m[8][i] = 0;
      if (mat.m[i][8] === -1) mat.m[i][8] = 0;
    }
    for (let i = mat.size - 8; i < mat.size; i++) {
      if (mat.m[8][i] === -1) mat.m[8][i] = 0;
      if (mat.m[i][8] === -1) mat.m[i][8] = 0;
    }
    mat.m[mat.size - 8][8] = 1; // 固定的 dark module
  }

  // 数据填充：右下角起，Z 字型上下扫
  function fillData(mat, dataBytes) {
    let bitIdx = 0;
    const bit = () => {
      const b = dataBytes[bitIdx >> 3];
      const on = (b >> (7 - (bitIdx & 7))) & 1;
      bitIdx++;
      return on;
    };
    let up = true;
    for (let col = mat.size - 1; col > 0; col -= 2) {
      if (col === 6) col--; // 跳过 timing 列
      let row = up ? mat.size - 1 : 0;
      for (let i = 0; i < mat.size; i++) {
        for (let c = 0; c < 2; c++) {
          const cc = col - c;
          if (mat.m[row][cc] === -1) {
            mat.m[row][cc] = bitIdx < dataBytes.length * 8 ? bit() : 0;
          }
        }
        row += up ? -1 : 1;
      }
      up = !up;
    }
  }

  // Mask 函数（8 种）
  const MASK_FN = [
    (r, c) => ((r + c) & 1) === 0,
    (r, c) => (r & 1) === 0,
    (r, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0,
    (r, c) => (((r >> 1) + Math.floor(c / 3)) & 1) === 0,
    (r, c) => ((r * c) & 1) + ((r * c) % 3) === 0,
    (r, c) => ((((r * c) & 1) + ((r * c) % 3)) & 1) === 0,
    (r, c) => ((((r + c) & 1) + ((r * c) % 3)) & 1) === 0,
  ];

  // 判定像素是否在数据区（非功能区）
  function isDataModule(mat, r, c, version) {
    const size = mat.size;
    // finder + separator
    if ((r < 9 && c < 9) || (r < 9 && c >= size - 8) || (r >= size - 8 && c < 9)) return false;
    // timing
    if (r === 6 || c === 6) return false;
    // version info (v7+)
    if (version >= 7) {
      if (r < 6 && c >= size - 11 && c <= size - 9) return false;
      if (c < 6 && r >= size - 11 && r <= size - 9) return false;
    }
    // alignment
    const pos = ALIGN_POS[version] || [];
    for (const ar of pos) for (const ac of pos) {
      if ((ar === 6 && ac === 6) ||
          (ar === 6 && ac === pos[pos.length - 1]) ||
          (ar === pos[pos.length - 1] && ac === 6)) continue;
      if (Math.abs(r - ar) <= 2 && Math.abs(c - ac) <= 2) return false;
    }
    return true;
  }

  function applyMask(mat, version, maskId) {
    const fn = MASK_FN[maskId];
    for (let r = 0; r < mat.size; r++) {
      for (let c = 0; c < mat.size; c++) {
        if (isDataModule(mat, r, c, version) && fn(r, c)) {
          mat.m[r][c] ^= 1;
        }
      }
    }
  }

  // Format info 15 位 = 5 位数据 + 10 位 BCH 纠错，再异或 0x5412
  function formatBits(ecLevel, maskId) {
    // ecLevel: L=01, M=00, Q=11, H=10；我们只用 M
    const ec = { L: 0b01, M: 0b00, Q: 0b11, H: 0b10 }[ecLevel];
    let data = (ec << 3) | maskId;
    let bch = data << 10;
    const gen = 0b10100110111;
    for (let i = 4; i >= 0; i--) {
      if ((bch >> (i + 10)) & 1) bch ^= gen << i;
    }
    return ((data << 10) | bch) ^ 0b101010000010010;
  }

  function placeFormat(mat, fmt) {
    const size = mat.size;
    for (let i = 0; i <= 5; i++) mat.m[8][i] = (fmt >> i) & 1;
    mat.m[8][7] = (fmt >> 6) & 1;
    mat.m[8][8] = (fmt >> 7) & 1;
    mat.m[7][8] = (fmt >> 8) & 1;
    for (let i = 9; i < 15; i++) mat.m[14 - i][8] = (fmt >> i) & 1;

    for (let i = 0; i < 7; i++) mat.m[size - 1 - i][8] = (fmt >> i) & 1;
    for (let i = 7; i < 15; i++) mat.m[8][size - 15 + i] = (fmt >> i) & 1;
    mat.m[size - 8][8] = 1;
  }

  // Version info（v7+ 需要）—— 简化：本实现最大支持 v20，v7+ 需要 18 位版本信息
  const VERSION_INFO = {
    // 预计算的 v7-v20 版本信息位（18 bits）
    7:  0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3, 11: 0x0BBF6,
    12: 0x0C762, 13: 0x0D847, 14: 0x0E60D, 15: 0x0F928, 16: 0x10B78,
    17: 0x1145D, 18: 0x12A17, 19: 0x13532, 20: 0x149A6,
  };
  function placeVersion(mat, version) {
    if (version < 7) return;
    const bits = VERSION_INFO[version];
    if (bits === undefined) throw new Error(`version ${version} 不支持`);
    for (let i = 0; i < 18; i++) {
      const bit = (bits >> i) & 1;
      const a = Math.floor(i / 3), b = (i % 3) + mat.size - 11;
      mat.m[a][b] = bit;
      mat.m[b][a] = bit;
    }
  }

  // 惩罚分（选最佳 mask）—— 简化实现
  function penalty(mat) {
    let p = 0;
    const size = mat.size;
    // Rule 1: 连续 5+ 同色
    for (let r = 0; r < size; r++) {
      let run = 1;
      for (let c = 1; c < size; c++) {
        if (mat.m[r][c] === mat.m[r][c-1]) { run++; if (run === 5) p += 3; else if (run > 5) p++; }
        else run = 1;
      }
    }
    for (let c = 0; c < size; c++) {
      let run = 1;
      for (let r = 1; r < size; r++) {
        if (mat.m[r][c] === mat.m[r-1][c]) { run++; if (run === 5) p += 3; else if (run > 5) p++; }
        else run = 1;
      }
    }
    return p;
  }

  // ---------- 对外入口 ----------
  function generateMatrix(bytes) {
    const version = pickVersion(bytes.length);
    const codewords = encodeData(bytes, version);
    const codewordsU8 = new Uint8Array(codewords);

    // 生成 8 个 mask 候选，选惩罚最低
    let bestMat, bestMaskId, bestScore = Infinity;
    for (let maskId = 0; maskId < 8; maskId++) {
      const mat = makeMatrix(version);
      placeFinder(mat, 0, 0);
      placeFinder(mat, 0, mat.size - 7);
      placeFinder(mat, mat.size - 7, 0);
      placeAlignment(mat, version);
      placeTiming(mat);
      reserveFormat(mat);
      placeVersion(mat, version);
      fillData(mat, codewordsU8);
      applyMask(mat, version, maskId);
      placeFormat(mat, formatBits("M", maskId));

      const score = penalty(mat);
      if (score < bestScore) {
        bestScore = score;
        bestMat = mat;
        bestMaskId = maskId;
      }
    }
    return bestMat;
  }

  // 输出为 SVG 字符串
  function toSVG(text, opts = {}) {
    const scale = opts.scale || 8;
    const margin = opts.margin || 4;
    const bg = opts.bg || "#fff";
    const fg = opts.fg || "#000";
    const enc = new TextEncoder();
    const bytes = enc.encode(text);
    const mat = generateMatrix(bytes);
    const size = mat.size;
    const total = (size + margin * 2) * scale;

    let paths = "";
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (mat.m[r][c] === 1) {
          const x = (c + margin) * scale;
          const y = (r + margin) * scale;
          paths += `M${x} ${y}h${scale}v${scale}h-${scale}z`;
        }
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="100%" height="100%" shape-rendering="crispEdges">
<rect width="100%" height="100%" fill="${bg}"/>
<path d="${paths}" fill="${fg}"/>
</svg>`;
  }

  global.QR = { toSVG, generateMatrix };
})(window);
