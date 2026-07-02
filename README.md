# RSA 公钥-私钥加密程序

纯 Python 手写实现的 RSA 加解密程序，**无任何第三方依赖**（仅用标准库 `secrets`、`hashlib` 等）。
支持任意长度明文的分块处理、两种加密语义，以及 **OAEP / PSS** 标准填充。
OAEP/PSS 实现已与 `cryptography` 库做过双向互通测试，符合 RFC 8017（PKCS#1 v2.2）。

同一套算法另有**纯前端静态网页版**（`docs/`），可直接部署到 GitHub Pages。

## 文件

- `rsa.py` —— Python 实现，全部逻辑与命令行入口
- `docs/` —— 静态网页版（HTML/CSS/原生 JS + BigInt），见下文「网页版」
- `.github/workflows/deploy.yml` —— GitHub Pages 自动部署

## 两种加密语义

| `--mode` | 加密 | 解密 | 说明 |
|----------|------|------|------|
| `public`  | `c = m^e mod n`（公钥） | `m = c^d mod n`（私钥） | 标准 RSA，安全通信常用 |
| `private` | `c = m^d mod n`（私钥） | `m = c^e mod n`（公钥） | 私钥加密，数学上等价于签名 |

> **题意流程**（给定私钥 + 明文 → 输出公钥 + 密文）对应 `encrypt --mode private`：
> 用私钥 `d` 加密，并从私钥派生出公钥 `(n, e)` 一并输出。

## 标准填充：OAEP 与 PSS

教科书 RSA（`--padding none`）不安全：确定性、对选择性明文攻击和低指数攻击脆弱。
本程序实现了 PKCS#1 v2.2 的两类标准填充，对应标准里不同的用途：

| 填充 | 用途 | 对应命令 | 说明 |
|------|------|----------|------|
| **OAEP** | 加密 | `encrypt/decrypt --mode public --padding oaep` | RSAES-OAEP，公钥加密/私钥解密。随机化、CCA2 安全 |
| **PSS** | 签名 | `sign` / `verify` | RSASSA-PSS，私钥签名/公钥验签。即「私钥运算」的安全形态 |
| `none` | 教学 | 默认 | 教科书 RSA，仅用于对比演示 |

> 为什么 OAEP 只配 `public` 模式、PSS 单列 `sign`/`verify`？
> 因为 OAEP 是**加密**填充（可还原明文），PSS 是**签名**方案（验证真伪，不还原原文）。
> 标准（RFC 8017）正是这样分配的：加密用 OAEP，签名用 PSS。
> 题目里「用私钥加密」在数学上就是签名原语，其安全形态就是 PSS。

## 用法

### 1. 生成密钥对

```bash
python3 rsa.py gen --bits 2048 --privkey priv.json --pubkey pub.json
```

### 2. 加密（题意：私钥 + 明文 → 公钥 + 密文）

```bash
# 教科书模式（默认，符合题意字面流程）
python3 rsa.py encrypt --mode private --privkey priv.json \
    --text "需要加密的明文" --pubout pub_out.json --outfile cipher.bin

# OAEP 安全加密（公钥加密，标准做法）
python3 rsa.py encrypt --mode public --padding oaep --hash sha256 \
    --privkey priv.json --text "需要加密的明文" --outfile cipher.bin
```

- `--mode`：`private`（私钥加密，默认）/ `public`（公钥加密）
- `--padding`：`none`（默认）/ `oaep`（仅 `mode=public`，推荐）
- `--hash`：OAEP 哈希，默认 `sha256`，可选 sha1/224/256/384/512
- `--text` / `--infile` / stdin 三选一作为明文来源
- `--pubout`：从私钥派生的公钥写入文件；不指定则打印到屏幕
- `--outfile`：密文写入文件；不指定则 base64 打印

### 3. 解密

```bash
python3 rsa.py decrypt --key priv.json --mode public --padding oaep \
    --infile cipher.bin
```

`--mode`/`--padding`/`--hash` 须与加密时一致。

### 4. PSS 签名 / 验签

```bash
# 签名（私钥）
python3 rsa.py sign --privkey priv.json --text "需要签名的消息" --outfile sig.bin

# 验签（公钥）—— 通过返回 0，失败返回 1
python3 rsa.py verify --key pub.json --text "需要签名的消息" --sigfile sig.bin
```

- `--hash`：默认 `sha256`
- `--salt-len`：盐长度，签名时默认等于哈希输出长度（hLen）；验签时默认自动检测

## 密钥文件格式

JSON，公钥含 `n`、`e`；私钥额外含 `d`、`p`、`q`（大整数以十六进制存储）。例：

```json
{
  "kty": "RSA-priv",
  "n": "0xc72f...",
  "e": 65537,
  "d": "0x9a1b...",
  "p": "0xf3a0...",
  "q": "0xce78..."
}
```

## 实现要点

- **素性检测**：Miller-Rabin（40 轮），用 `secrets` 获取密码学随机数
- **模逆**：扩展欧几里得算法求 `d = e⁻¹ mod φ(n)`
- **分块（教科书模式）**：明文按 `(n.bit_length()-1)//8` 字节切块，保证每块整数 `< n`；
  采用「4 字节长度前缀 + 右填充至整块」的帧格式，精确还原末尾短块
- **OAEP**：MGF1 掩码 + 随机 seed，每块独立填充；多块时逐块 OAEP（教学实现）
- **PSS**：EMSA-PSS 编码，盐随机化；验签自动检测盐长度
- **公钥派生**：私钥文件已含 `n`、`e`，公钥即其子集

## 安全说明

- 启用 `--padding oaep` 与 `sign`/`verify`(PSS) 后，本程序实现了标准的安全填充，
  并已与 `cryptography` 库双向互通验证（OAEP 加解密、PSS 签验签均字节级一致）。
- 仍需注意：OAEP 多块是逐块独立填充的教学实现（标准 OAEP 本身只定义单块，
  生产中通常用 RSA-OAEP 包裹对称密钥 + 对称加密大消息的混合方案）。
- 私钥文件以明文 JSON 存储，生产环境应加口令加密保护。

---

## 网页版（`docs/`）

同一套算法的纯前端实现：原生 HTML/CSS/JS + `BigInt`，零框架、零构建、零依赖。
所有运算在浏览器本地完成，**密钥与明文不离开浏览器，不发起任何网络请求**。

功能与 `rsa.py` 一一对应：密钥生成、两种模式加解密、OAEP、PSS 签名/验签。
密钥 JSON 格式与 Python 版完全一致，**网页与 Python 端互通**（已三向验证：
网页 ↔ Python ↔ `cryptography` 库）。

> 限制：网页版哈希仅支持 SHA-1/256/384/512（WebCrypto 规范不含 SHA-224）。
> 因此 SHA-224 的密文/签名仅 Python 端可处理。

### 本地预览

```bash
python3 -m http.server -d docs 8000
# 浏览器打开 http://localhost:8000
```

> 需通过 `localhost` 或 HTTPS 访问——`crypto.subtle` 在 `file://` 协议下不可用。

### 部署到 GitHub Pages

1. 推送代码到 GitHub 仓库的 `main` 分支。
2. 仓库 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**。
3. 推送即自动部署（`.github/workflows/deploy.yml` 把 `docs/` 发布到 Pages）。
4. 访问 `https://<用户名>.github.io/<仓库名>/`。

也可以不配 workflow：Settings → Pages → Source 选 *Deploy from a branch*，
分支 `main` / 目录 `docs`。`docs/.nojekyll` 确保原样发布（不走 Jekyll）。

