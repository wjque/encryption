#!/usr/bin/env python3
"""
RSA 公钥-私钥加密程序（纯 Python 手写实现，无第三方依赖）。

支持两种加密语义，由 --mode 指定：

  public  （标准 RSA）
      加密：c = m^e mod n   用【公钥】加密
      解密：m = c^d mod n   用【私钥】解密

  private （私钥加密，数学上等价于签名）
      加密：c = m^d mod n   用【私钥】加密
      解密：m = c^e mod n   用【公钥】解密 / 验证

题目要求的流程 —— “给定私钥和明文，输出公钥和密文” —— 对应：
      python rsa.py encrypt --mode private --privkey priv.json --text "明文"
"""

import argparse
import base64
import hashlib
import json
import secrets
import sys
from typing import Callable, Tuple


# ============================================================
# 一、大整数 / 数论工具
# ============================================================

def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin 素性检测。"""
    if n < 2:
        return False
    # 小素数预筛，加速
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    # 把 n-1 写成 d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    """生成指定位数的随机大素数。"""
    while True:
        # 最高位置 1 保证位数，最低位置 1 保证为奇数
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得算法，返回 (g, x, y) 满足 a*x + b*y = g。"""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def _modinv(a: int, m: int) -> int:
    """求 a 在模 m 下的乘法逆元。"""
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("模逆元不存在，e 与 φ(n) 不互素")
    return x % m


# ============================================================
# 二、密钥结构
# ============================================================

class RSAPublicKey:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e

    def to_dict(self) -> dict:
        return {"kty": "RSA-pub", "n": hex(self.n), "e": self.e}

    @classmethod
    def from_dict(cls, d: dict) -> "RSAPublicKey":
        return cls(int(d["n"], 16), int(d["e"]))

    def __repr__(self):
        return f"RSAPublicKey(bits={self.n.bit_length()}, e={self.e})"


class RSAPrivateKey:
    def __init__(self, n: int, e: int, d: int, p: int, q: int):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q

    def public(self) -> RSAPublicKey:
        """从私钥派生公钥。"""
        return RSAPublicKey(self.n, self.e)

    def to_dict(self) -> dict:
        return {
            "kty": "RSA-priv",
            "n": hex(self.n),
            "e": self.e,
            "d": hex(self.d),
            "p": hex(self.p),
            "q": hex(self.q),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RSAPrivateKey":
        return cls(
            int(d["n"], 16), int(d["e"]), int(d["d"], 16),
            int(d["p"], 16), int(d["q"], 16),
        )

    def __repr__(self):
        return f"RSAPrivateKey(bits={self.n.bit_length()}, e={self.e})"


def generate_keypair(bits: int = 2048, e: int = 65537) -> RSAPrivateKey:
    """生成 RSA 密钥对，返回私钥（含可派生的公钥）。"""
    if bits < 512:
        raise ValueError("密钥位数过小，至少 512 位")
    half = bits // 2
    while True:
        p = _gen_prime(half)
        q = _gen_prime(bits - half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:           # 保证模数确切位数
            continue
        phi = (p - 1) * (q - 1)
        if _egcd(e, phi)[0] != 1:            # e 必须与 φ(n) 互素
            continue
        d = _modinv(e, phi)
        return RSAPrivateKey(n, e, d, p, q)


# ============================================================
# 三、分块加解密（处理任意长度明文）
# ============================================================

def _byte_len(n: int) -> int:
    return (n.bit_length() + 7) // 8


def _block_size(n: int) -> int:
    """明文每块的最多字节数，保证块整数 < n。"""
    sz = (n.bit_length() - 1) // 8
    return sz if sz >= 1 else 1


def _encrypt_bytes(data: bytes, exp: int, n: int) -> bytes:
    """用指数 exp 对 data 加密，输出定长拼接的密文字节。"""
    k = _byte_len(n)
    blk = _block_size(n)
    # 前 4 字节记录原始长度，便于解密时精确还原末尾短块
    framed = len(data).to_bytes(4, "big") + data
    # 右填充到 blk 整数倍：每个块都是完整 blk 字节，避免短块往返丢失长度信息。
    # 首块含长度前缀且为完整块 → 往返无信息丢失；尾部填充零被长度字段忽略。
    framed += b"\x00" * ((-len(framed)) % blk)
    out = bytearray()
    for i in range(0, len(framed), blk):
        m = int.from_bytes(framed[i:i + blk], "big")
        c = pow(m, exp, n)
        out += c.to_bytes(k, "big")          # 每块密文定长 k 字节
    return bytes(out)


def _decrypt_bytes(data: bytes, exp: int, n: int) -> bytes:
    """用指数 exp 对密文 data 解密，还原明文。"""
    k = _byte_len(n)
    blk = _block_size(n)
    if len(data) == 0 or len(data) % k != 0:
        raise ValueError("密文长度与密钥不匹配")
    out = bytearray()
    for i in range(0, len(data), k):
        c = int.from_bytes(data[i:i + k], "big")
        m = pow(c, exp, n)
        out += m.to_bytes(blk, "big")        # 还原成定长明文块
    framed = bytes(out)
    length = int.from_bytes(framed[:4], "big")
    if length > len(framed) - 4:
        raise ValueError("解密失败：长度字段非法")
    return framed[4:4 + length]


# ============================================================
# 四、标准填充：OAEP（加密）与 PSS（签名）
# ============================================================
#
# 教科书 RSA 不安全（确定性、对选择性明文/低指数攻击脆弱）。PKCS#1 v2.2
# 定义了两类标准填充，本节按 RFC 8017 用 hashlib 实现：
#   * RSAES-OAEP —— 加密填充，配 --mode public（公钥加密/私钥解密）
#   * RSASSA-PSS —— 签名方案，配 sign/verify（私钥签名/公钥验签）

_HASHES = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def _get_hash(name: str) -> Callable:
    try:
        return _HASHES[name]
    except KeyError:
        raise ValueError(f"不支持的哈希: {name}（可选: {', '.join(_HASHES)}）")


def _xor(a: bytes, b: bytes) -> bytes:
    """等长字节串按位异或。"""
    return bytes(x ^ y for x, y in zip(a, b))


def _mgf1(seed: bytes, length: int, hash_fn: Callable) -> bytes:
    """MGF1 掩码生成函数（RFC 8017 B.2.1）。"""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hash_fn(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


# ---- RSAES-OAEP ----

def _oaep_encrypt_block(m_block: bytes, n: int, exp: int, hash_fn: Callable) -> bytes:
    """对单个块做 OAEP 加密，返回 k 字节密文块（L 为空）。"""
    k = _byte_len(n)
    h_len = hash_fn().digest_size
    if len(m_block) > k - 2 * h_len - 2:
        raise ValueError("OAEP: 消息块过长")
    l_hash = hash_fn(b"").digest()
    ps = b"\x00" * (k - len(m_block) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + m_block            # k - hLen - 1 字节
    seed = secrets.token_bytes(h_len)
    db_mask = _mgf1(seed, k - h_len - 1, hash_fn)
    masked_db = _xor(db, db_mask)
    seed_mask = _mgf1(masked_db, h_len, hash_fn)
    masked_seed = _xor(seed, seed_mask)
    em = b"\x00" + masked_seed + masked_db          # k 字节
    c = pow(int.from_bytes(em, "big"), exp, n)
    return c.to_bytes(k, "big")


def _oaep_decrypt_block(c_block: bytes, n: int, exp: int, hash_fn: Callable) -> bytes:
    """对单个密文块做 OAEP 解密，返回明文块；失败抛 ValueError。"""
    k = _byte_len(n)
    h_len = hash_fn().digest_size
    if len(c_block) != k or k < 2 * h_len + 2:
        raise ValueError("OAEP: 密文块长度非法")
    m_int = pow(int.from_bytes(c_block, "big"), exp, n)
    em = m_int.to_bytes(k, "big")
    l_hash = hash_fn(b"").digest()
    y = em[0]
    masked_seed = em[1:1 + h_len]
    masked_db = em[1 + h_len:]
    seed = _xor(masked_seed, _mgf1(masked_db, h_len, hash_fn))
    db = _xor(masked_db, _mgf1(seed, k - h_len - 1, hash_fn))
    l_hash2 = db[:h_len]
    # 跳过全零 PS，找到 0x01 分隔符
    i = h_len
    while i < len(db) and db[i] == 0:
        i += 1
    # 常量时间风格：所有错误统一抛出，避免侧信道区分原因
    if y != 0 or l_hash != l_hash2 or i >= len(db) or db[i] != 1:
        raise ValueError("OAEP: 解密失败（填充校验未通过）")
    return db[i + 1:]


def _oaep_encrypt(data: bytes, n: int, exp: int, hash_fn: Callable) -> bytes:
    """对任意长度明文分块 OAEP 加密。每块独立填充（教学实现，非标准多块协议）。"""
    k = _byte_len(n)
    h_len = hash_fn().digest_size
    max_msg = k - 2 * h_len - 2
    if max_msg < 1:
        raise ValueError("密钥/哈希组合下 OAEP 单块容量不足")
    chunks = [data[i:i + max_msg] for i in range(0, len(data), max_msg)] or [b""]
    out = bytearray()
    for ch in chunks:
        out += _oaep_encrypt_block(ch, n, exp, hash_fn)
    return bytes(out)


def _oaep_decrypt(data: bytes, n: int, exp: int, hash_fn: Callable) -> bytes:
    """对 OAEP 密文分块解密并拼接。"""
    k = _byte_len(n)
    if len(data) == 0 or len(data) % k != 0:
        raise ValueError("OAEP: 密文总长度与密钥不匹配")
    out = bytearray()
    for i in range(0, len(data), k):
        out += _oaep_decrypt_block(data[i:i + k], n, exp, hash_fn)
    return bytes(out)


# ---- RSASSA-PSS ----

def pss_sign(message: bytes, priv: "RSAPrivateKey",
             hash_name: str = "sha256", salt_len: int | None = None) -> bytes:
    """RSASSA-PSS 签名，返回 k 字节签名。salt_len 默认等于哈希输出长度。"""
    hash_fn = _get_hash(hash_name)
    h_len = hash_fn().digest_size
    if salt_len is None:
        salt_len = h_len
    n, d = priv.n, priv.d
    mod_bits = n.bit_length()
    em_bits = mod_bits - 1
    em_len = (em_bits + 7) // 8
    if em_len < h_len + salt_len + 2:
        raise ValueError("PSS: 密钥位数不足以容纳签名")
    m_hash = hash_fn(message).digest()
    salt = secrets.token_bytes(salt_len)
    m_prime = b"\x00" * 8 + m_hash + salt
    h = hash_fn(m_prime).digest()
    ps = b"\x00" * (em_len - salt_len - h_len - 2)
    db = ps + b"\x01" + salt                         # em_len - h_len - 1 字节
    db_mask = _mgf1(h, em_len - h_len - 1, hash_fn)
    masked_db = bytearray(_xor(db, db_mask))
    bits_to_zero = 8 * em_len - em_bits
    if bits_to_zero:
        masked_db[0] &= 0xff >> bits_to_zero
    em = bytes(masked_db) + h + b"\xbc"
    s = pow(int.from_bytes(em, "big"), d, n)
    return s.to_bytes(_byte_len(n), "big")


def pss_verify(message: bytes, signature: bytes, pub: "RSAPublicKey",
               hash_name: str = "sha256", salt_len: int | None = None) -> bool:
    """RSASSA-PSS 验签。salt_len=None 时自动检测盐长度（扫描 0x01 分隔符）。"""
    hash_fn = _get_hash(hash_name)
    h_len = hash_fn().digest_size
    n, e = pub.n, pub.e
    k = _byte_len(n)
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    mod_bits = n.bit_length()
    em_bits = mod_bits - 1
    em_len = (em_bits + 7) // 8
    m_int = pow(s, e, n)
    em = m_int.to_bytes(em_len, "big")
    m_hash = hash_fn(message).digest()
    if em_len < h_len + 2 or em[-1] != 0xbc:
        return False
    masked_db = bytearray(em[:em_len - h_len - 1])
    h = em[em_len - h_len - 1:em_len - 1]
    bits_to_zero = 8 * em_len - em_bits
    if bits_to_zero and (masked_db[0] & (0xff << (8 - bits_to_zero) & 0xff)):
        return False
    db_mask = _mgf1(h, em_len - h_len - 1, hash_fn)
    db = bytearray(_xor(bytes(masked_db), db_mask))
    if bits_to_zero:
        db[0] &= 0xff >> bits_to_zero
    # 自动检测或固定盐长度
    if salt_len is None:
        i = 0
        while i < len(db) and db[i] == 0:
            i += 1
        if i >= len(db) or db[i] != 1:
            return False
        salt = bytes(db[i + 1:])
    else:
        ps_len = em_len - salt_len - h_len - 2
        if ps_len < 0 or db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 1:
            return False
        salt = bytes(db[ps_len + 1:])
    m_prime = b"\x00" * 8 + m_hash + salt
    return hash_fn(m_prime).digest() == h


# ============================================================
# 五、高层加解密接口
# ============================================================

def encrypt(plaintext: bytes, key, mode: str,
            padding: str = "none", hash_name: str = "sha256") -> bytes:
    """
    mode="public"  : 用公钥 (e) 加密，key 需为 RSAPublicKey 或 RSAPrivateKey
    mode="private" : 用私钥 (d) 加密，key 需为 RSAPrivateKey
    padding="none" : 教科书 RSA；padding="oaep" 仅用于 mode="public"
    """
    if mode == "public":
        exp = key.e
        n = key.n
    elif mode == "private":
        if not isinstance(key, RSAPrivateKey):
            raise ValueError("私钥加密需要提供 RSAPrivateKey")
        exp = key.d
        n = key.n
    else:
        raise ValueError(f"未知 mode: {mode}")

    if padding == "none":
        return _encrypt_bytes(plaintext, exp, n)
    if padding == "oaep":
        if mode != "public":
            raise ValueError("OAEP 仅用于公钥加密（--mode public）；私钥运算请用 sign 子命令(PSS)")
        return _oaep_encrypt(plaintext, n, exp, _get_hash(hash_name))
    raise ValueError(f"未知 padding: {padding}")


def decrypt(ciphertext: bytes, key, mode: str,
            padding: str = "none", hash_name: str = "sha256") -> bytes:
    """
    mode="public"  : 密文由公钥加密得到 → 用私钥 (d) 解密，key 需为 RSAPrivateKey
    mode="private" : 密文由私钥加密得到 → 用公钥 (e) 解密，key 需为 RSAPublicKey 或私钥
    """
    if mode == "public":
        if not isinstance(key, RSAPrivateKey):
            raise ValueError("公钥加密的密文需用 RSAPrivateKey 解密")
        exp = key.d
        n = key.n
    elif mode == "private":
        exp = key.e
        n = key.n
    else:
        raise ValueError(f"未知 mode: {mode}")

    if padding == "none":
        return _decrypt_bytes(ciphertext, exp, n)
    if padding == "oaep":
        if mode != "public":
            raise ValueError("OAEP 仅用于公钥加密的密文（--mode public）")
        return _oaep_decrypt(ciphertext, n, exp, _get_hash(hash_name))
    raise ValueError(f"未知 padding: {padding}")


# ============================================================
# 五、密钥文件 I/O
# ============================================================

def save_key(key, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(key.to_dict(), f, indent=2, ensure_ascii=False)


def load_key(path: str):
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    if d.get("kty") == "RSA-priv":
        return RSAPrivateKey.from_dict(d)
    if d.get("kty") == "RSA-pub":
        return RSAPublicKey.from_dict(d)
    # 兼容无 kty 字段的旧文件：有 d 视为私钥
    return RSAPrivateKey.from_dict(d) if "d" in d else RSAPublicKey.from_dict(d)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.strip())


# ============================================================
# 六、命令行
# ============================================================

def cmd_gen(args) -> None:
    priv = generate_keypair(args.bits)
    save_key(priv, args.privkey)
    pub_path = args.pubkey or args.privkey.replace(".json", ".pub.json")
    save_key(priv.public(), pub_path)
    print(f"[+] 已生成 {args.bits} 位密钥对")
    print(f"    私钥: {args.privkey}")
    print(f"    公钥: {pub_path}")
    print(f"    {priv}")


def cmd_encrypt(args) -> None:
    priv = load_key(args.privkey)
    if not isinstance(priv, RSAPrivateKey):
        sys.exit("错误：加密需要私钥文件（用于派生公钥 / 取用 d）")

    if args.text is not None:
        plaintext = args.text.encode("utf-8")
    elif args.infile:
        with open(args.infile, "rb") as f:
            plaintext = f.read()
    else:
        plaintext = sys.stdin.buffer.read()

    ciphertext = encrypt(plaintext, priv, args.mode, args.padding, args.hash)

    # 输出公钥（从私钥派生）
    pub = priv.public()
    if args.pubout:
        save_key(pub, args.pubout)
        print(f"[+] 公钥已写入: {args.pubout}")
    else:
        print("=== 公钥 ===")
        print(json.dumps(pub.to_dict(), indent=2, ensure_ascii=False))

    # 输出密文
    if args.outfile:
        with open(args.outfile, "wb") as f:
            f.write(ciphertext)
        print(f"[+] 密文已写入: {args.outfile} ({len(ciphertext)} 字节)")
    else:
        print("=== 密文 (base64) ===")
        print(_b64(ciphertext))

    pad_desc = "教科书RSA" if args.padding == "none" else f"OAEP/{args.hash}"
    print(f"[i] 模式: {args.mode} 加密 ({'私钥 d' if args.mode=='private' else '公钥 e'}), 填充: {pad_desc}")


def cmd_decrypt(args) -> None:
    key = load_key(args.key)

    if args.infile:
        with open(args.infile, "rb") as f:
            ciphertext = f.read()
    elif args.b64:
        ciphertext = _unb64(args.b64)
    else:
        ciphertext = _unb64(sys.stdin.read())

    plaintext = decrypt(ciphertext, key, args.mode, args.padding, args.hash)

    if args.outfile:
        with open(args.outfile, "wb") as f:
            f.write(plaintext)
        print(f"[+] 明文已写入: {args.outfile} ({len(plaintext)} 字节)")
    else:
        try:
            print("=== 明文 ===")
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print("[i] 明文非 UTF-8，以 base64 输出：")
            print(_b64(plaintext))


def _read_message(args) -> bytes:
    if args.text is not None:
        return args.text.encode("utf-8")
    if args.infile:
        with open(args.infile, "rb") as f:
            return f.read()
    return sys.stdin.buffer.read()


def cmd_sign(args) -> None:
    """PSS 签名：用私钥对消息签名，输出签名。"""
    priv = load_key(args.privkey)
    if not isinstance(priv, RSAPrivateKey):
        sys.exit("错误：签名需要私钥文件")
    message = _read_message(args)
    sig = pss_sign(message, priv, args.hash, args.salt_len)
    if args.outfile:
        with open(args.outfile, "wb") as f:
            f.write(sig)
        print(f"[+] 签名已写入: {args.outfile} ({len(sig)} 字节)")
    else:
        print("=== 签名 (base64) ===")
        print(_b64(sig))
    print(f"[i] PSS/{args.hash}, salt_len={args.salt_len if args.salt_len is not None else 'hLen'}")


def cmd_verify(args) -> None:
    """PSS 验签：用公钥验证消息与签名是否匹配。"""
    pub = load_key(args.key)
    if isinstance(pub, RSAPrivateKey):
        pub = pub.public()
    message = _read_message(args)
    if args.sigfile:
        with open(args.sigfile, "rb") as f:
            sig = f.read()
    elif args.sigb64:
        sig = _unb64(args.sigb64)
    else:
        sig = _unb64(sys.stdin.read())
    ok = pss_verify(message, sig, pub, args.hash, args.salt_len)
    print(f"[{'+'if ok else '-'}] 验签 {'通过' if ok else '失败'} (PSS/{args.hash})")
    sys.exit(0 if ok else 1)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="RSA 公钥-私钥加密程序（纯 Python 手写）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # gen
    g = sub.add_parser("gen", help="生成密钥对")
    g.add_argument("--bits", type=int, default=2048, help="密钥位数（默认 2048）")
    g.add_argument("--privkey", default="priv.json", help="私钥输出路径")
    g.add_argument("--pubkey", help="公钥输出路径（默认 priv 同名 .pub.json）")
    g.set_defaults(func=cmd_gen)

    # encrypt
    e = sub.add_parser("encrypt", help="加密：给定私钥 + 明文 → 公钥 + 密文")
    e.add_argument("--privkey", required=True, help="私钥文件（用于派生公钥）")
    e.add_argument("--mode", choices=["public", "private"], default="private",
                   help="public=公钥加密(标准), private=私钥加密(默认,符合题意)")
    e.add_argument("--padding", choices=["none", "oaep"], default="none",
                   help="none=教科书RSA(默认), oaep=OAEP填充(仅 mode=public,推荐)")
    e.add_argument("--hash", choices=list(_HASHES), default="sha256",
                   help="OAEP 使用的哈希（默认 sha256）")
    e.add_argument("--text", help="明文字符串（与 --infile 二选一，缺省读 stdin）")
    e.add_argument("--infile", help="明文输入文件")
    e.add_argument("--pubout", help="公钥输出文件（不指定则打印到屏幕）")
    e.add_argument("--outfile", help="密文输出文件（不指定则 base64 打印）")
    e.set_defaults(func=cmd_encrypt)

    # decrypt
    d = sub.add_parser("decrypt", help="解密")
    d.add_argument("--key", required=True, help="密钥文件（公钥或私钥，视 mode 而定）")
    d.add_argument("--mode", choices=["public", "private"], default="private",
                   help="与加密时相同的 mode：private=用公钥解私钥密文, public=用私钥解公钥密文")
    d.add_argument("--padding", choices=["none", "oaep"], default="none",
                   help="需与加密时一致：none 或 oaep")
    d.add_argument("--hash", choices=list(_HASHES), default="sha256",
                   help="OAEP 使用的哈希（默认 sha256）")
    d.add_argument("--b64", help="密文 base64 字符串")
    d.add_argument("--infile", help="密文输入文件")
    d.add_argument("--outfile", help="明文输出文件（不指定则打印到屏幕）")
    d.set_defaults(func=cmd_decrypt)

    # sign (PSS)
    s = sub.add_parser("sign", help="PSS 签名：私钥对消息签名")
    s.add_argument("--privkey", required=True, help="私钥文件")
    s.add_argument("--hash", choices=list(_HASHES), default="sha256", help="哈希算法")
    s.add_argument("--salt-len", type=int, default=None,
                   help="盐长度（默认等于哈希输出长度 hLen）")
    s.add_argument("--text", help="消息字符串（与 --infile 二选一，缺省读 stdin）")
    s.add_argument("--infile", help="消息输入文件")
    s.add_argument("--outfile", help="签名输出文件（不指定则 base64 打印）")
    s.set_defaults(func=cmd_sign)

    # verify (PSS)
    v = sub.add_parser("verify", help="PSS 验签：公钥验证消息与签名")
    v.add_argument("--key", required=True, help="公钥文件（或私钥，取其公钥部分）")
    v.add_argument("--hash", choices=list(_HASHES), default="sha256", help="哈希算法")
    v.add_argument("--salt-len", type=int, default=None,
                   help="盐长度（默认自动检测）")
    v.add_argument("--text", help="消息字符串（与 --infile 二选一，缺省读 stdin）")
    v.add_argument("--infile", help="消息输入文件")
    v.add_argument("--sigfile", help="签名输入文件")
    v.add_argument("--sigb64", help="签名 base64 字符串")
    v.set_defaults(func=cmd_verify)

    return ap


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
