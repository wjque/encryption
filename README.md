# 密码保险库

基于浏览器原生 WebCrypto API 的密码管理器。记住一个主密码，即可安全存储与取用所有站点密码。

## 安全模型

与 1Password / Bitwarden / KeePass 同类架构：

```
主密码 ──PBKDF2-SHA256(600,000 次迭代)──→ AES-256-GCM 密钥
                                              │
                                              ├── 派生后驻留内存，extractable=false
                                              ├── 锁定即丢弃，永不落盘
                                              └── 每条站点密码独立随机 nonce + GCM 认证标签
```

- **主密码永不落盘**。localStorage 只存：盐、验证器密文、各条目密文。
- **GCM 认证标签**：密文被改一字节、或主密码错一个字符都会解密失败。
- **按需解密**：仅在点击「显示/复制」时解密单条，不批量暴露明文。
- **复制后 30 秒清空剪贴板**。
- **闲置 5 分钟自动锁定**，锁定后内存密钥被丢弃，需重新输入主密码。
- **强密码生成器**：`crypto.getRandomValues` + 拒绝采样消除模偏，保证每种字符集至少出现一次。
- **导出/导入**：导出为加密 JSON 备份文件；导入后需用原主密码解锁。
- **修改主密码**：用旧密钥解密全部条目，用新密钥重新加密后原子写入。
- **可选云同步**：将加密后的保险库存到你自己的**私有 GitHub Gist**，实现跨设备同步。
  同步的内容始终是密文，GitHub 无法读取；PAT 本地也用主密钥加密保存。

## 文件结构

```
Encryption/
├── rsa.py                      # Python RSA 实现（密钥生成、加解密、OAEP/PSS）
├── docs/                       # GitHub Pages 部署根目录
│   ├── index.html              # 密码保险库主页
│   ├── .nojekyll
│   └── vault/
│       ├── crypto.js           # PBKDF2 + AES-256-GCM 封装
│       ├── generator.js        # 强密码生成器
│       ├── vault.js            # 保险库数据模型（localStorage 持久化）
│       ├── sync.js             # GitHub Gist 云同步
│       ├── ui.js               # UI 交互（锁定/解锁/条目管理/设置/同步）
│       └── vault.css           # 深色主题样式
└── .github/workflows/deploy.yml # GitHub Pages 自动部署
```

## 使用方法

### 1. 创建保险库

打开页面后，如果是首次使用，会看到「设置主密码」界面。

- 输入一个 **至少 12 个字符** 的主密码，并确认。
- 主密码决定了所有数据的加密密钥——**遗忘主密码 = 数据无法恢复**，请务必牢记。
- 点击「创建保险库」进入主界面。

### 2. 添加站点密码

点击工具栏的「+ 添加」按钮，弹出添加条目对话框：

| 字段 | 说明 |
|------|------|
| 站点名称 | 必填，如 `github.com`、`邮箱` |
| 用户名/邮箱 | 选填，登录名或邮箱地址 |
| 密码 | 可手动输入，或点击 🎲 按钮生成强密码 |

密码生成器选项（默认全部开启）：

| 选项 | 说明 |
|------|------|
| 长度 | 默认 20，范围 6–64 |
| A-Z / a-z / 0-9 / 符号 | 勾选哪些字符集参与生成 |
| 剔除易混淆 | 去除 `0Oo1Il` 等容易看错的字符 |

点击「保存」后，密码用 AES-256-GCM 加密存入浏览器 localStorage。

### 3. 查看与复制密码

在条目列表中，每条记录右侧有操作按钮：

- **显示**：解密并在页面展示密码明文；再次点击「隐藏」收起。
- **复制**：解密并写入系统剪贴板，30 秒后自动清空。
- **编辑**：修改站点名称、用户名或密码。
- **删除**：移除该条目（不可撤销）。

工具栏的搜索框可按站点名或用户名过滤条目。

### 4. 锁定与解锁

- **手动锁定**：点击工具栏「锁定」按钮，立即丢弃内存中的派生密钥。
- **自动锁定**：闲置（无点击/键盘/鼠标移动）5 分钟后自动锁定。
- **解锁**：输入主密码，系统重新派生密钥并校验；密码错误会提示「主密码错误」。

### 5. 修改主密码

点击工具栏 ⚙ →「修改主密码」：

1. 输入当前主密码进行验证。
2. 输入新主密码（至少 12 个字符）并确认。
3. 系统用旧密钥解密所有条目，用新密钥重新加密后存入 localStorage。

### 6. 导出备份

点击工具栏 ⚙ →「导出备份（密文）」，浏览器会下载一个 JSON 文件。

- 文件包含加密后的所有条目数据，**不是明文**。
- 建议定期导出并存放在安全位置。

### 7. 导入备份

点击工具栏 ⚙ →「导入备份」选择之前导出的 JSON 文件：

- 导入后当前会话自动锁定。
- 需用 **导出时使用的主密码** 解锁。如果主密码已在别处修改，导入文件用的是旧密码。

### 8. 重置保险库

点击工具栏 ⚙ →「重置保险库（清除全部）」→ 确认。

此操作会**彻底删除**浏览器 localStorage 中的所有数据，不可恢复。

## 云同步（GitHub Gist）

内置基于 GitHub Gist 的跨设备同步。加密后的保险库存到你自己的**私有 Gist**，Gist 内容始终是密文，GitHub 无法读取任何明文。

### 一次性准备：创建 GitHub Personal Access Token

1. 打开 [GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens**](https://github.com/settings/personal-access-tokens/new)。
2. 填写：
   - **Token name**：任意，如 `password-vault-sync`
   - **Expiration**：建议 1 年（到期需要重新生成）
   - **Repository access**：选 `Public Repositories (read-only)` 即可（Gist 权限与 repo 权限独立，此项不影响 Gist）
   - **Permissions → Account permissions → Gists**：设为 **Read and write**
3. 点击「Generate token」，**立即复制** 生成的 token（`github_pat_...` 开头）。GitHub 关闭页面后无法再看到。

> 该 token 只有 Gists 读写权限，最坏后果是你自己的 Gist 被读或改，不影响任何其他仓库或账号资料。

### 在首台设备启用

1. 解锁保险库后，点工具栏 ⚙ →「☁ 云同步设置」。
2. 粘贴刚才的 PAT，Gist ID 留空（**首次启用会自动创建新 Gist**）。
3. 点「启用同步」。程序会：
   - 验证 token 有效性
   - 创建一个私有 Gist，把当前保险库（密文）上传
   - 用当前主密钥对 PAT 做 AES-GCM 加密，存入 localStorage
4. 完成后主界面顶部出现「☁ ✓ 已同步 X 分钟前」徽章。
5. **记下 Gist ID**（在同步设置里显示），第二台设备需要用到。

之后每次添加/修改/删除条目，程序会自动在 **3 秒防抖** 后推送到 Gist。

### 在第二台设备接入

1. 打开保险库页面，出现「设置主密码」界面。
2. 点击底部「**从 GitHub Gist 恢复 →**」。
3. 填写三个字段：
   - **Personal Access Token**：一个有 Gists 权限的 PAT（可以复用同一个，也可以为该设备创建独立的 PAT）
   - **Gist ID**：首台设备启用时得到的 Gist ID
   - **主密码**：创建保险库时用的主密码
4. 点「恢复」。程序会：
   - 从 GitHub 拉取加密的 Gist 内容
   - 用你输入的主密码派生密钥，尝试解密验证器
   - 密码正确 → 用主密钥加密 PAT，写入本设备的 localStorage
   - 进入主界面

之后两台设备任何一方的变更都会自动同步。

### 冲突处理

如果两台设备**在同一时间段内都做了修改**，推送时会检测到远端 ETag 已变化，弹出冲突对话框：

- **拉取远端 → 覆盖本地**：放弃本设备的未同步变更，用远端版本覆盖
- **本地覆盖远端**：强制推送本地版本，覆盖远端的变更
- **稍后处理**：暂时保留本地，稍后重试

日常单人使用时（人不会同时在两处改），冲突极少发生。

### 关闭同步

点工具栏 ⚙ →「☁ 云同步设置」→「关闭同步」。

- 本地保存的 PAT 和 Gist ID 会被清除。
- GitHub 上的 Gist **不会**被删除——需要的话请手动到 [gist.github.com](https://gist.github.com) 删除。

### 云同步的安全边界

| 威胁 | 是否受影响 |
|------|-----------|
| GitHub 员工 / Gist 泄露 | 只能看到密文，不掌握主密码则无法解密 |
| PAT 被他人窃取 | 攻击者可读/改你的 Gist，但拿到密文仍需主密码；且 fine-grained token 只影响 Gist，不影响其他资源 |
| 中间人 | 全 HTTPS + GitHub 证书 |
| 主密码泄露 | 与本地场景相同——所有保护失效，请务必用强主密码 |
| 云盘/GitHub 服务不可用 | 本地 localStorage 副本仍可正常使用，恢复后自动补推 |

## 本地预览

```bash
python3 -m http.server -d docs 8000
# 浏览器打开 http://localhost:8000
```

> 需通过 `localhost` 或 HTTPS 访问——`crypto.subtle` 在 `file://` 协议下不可用。

## 部署到 GitHub Pages

1. 推送代码到 GitHub 仓库的 `main` 分支。
2. 仓库 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**。
3. 推送即自动部署（`.github/workflows/deploy.yml` 把 `docs/` 发布到 Pages）。
4. 访问 `https://<用户名>.github.io/<仓库名>/`。

也可以不配 workflow：Settings → Pages → Source 选 *Deploy from a branch*，分支 `main` / 目录 `docs`。`docs/.nojekyll` 确保原样发布。

## 技术说明

- **密钥派生**：PBKDF2-SHA256，600,000 次迭代（OWASP 2023 推荐值）。
- **对称加密**：AES-256-GCM，每条独立 96 位随机 nonce，密文含 128 位认证标签。
- **密码生成器**：拒绝采样消除模偏；Fisher-Yates 洗牌保证均匀分布。
- **存储**：localStorage，键名 `rsa-vault`（保险库）+ `rsa-vault-sync`（同步元数据）。
- **密钥不可导出**：WebCrypto `CryptoKey` 创建时 `extractable=false`，无法通过 `exportKey` 获取原始密钥字节。
- **同步冲突检测**：客户端乐观锁——推送前先 GET Gist etag，与上次记忆的 etag 比对；不一致则视为冲突交给用户处理。
- **PAT 保护**：Personal Access Token 用当前主密钥 AES-GCM 加密后存 localStorage；锁定后内存密钥丢弃，token 无法被解密。
- 无第三方依赖、无构建步骤；除可选的 GitHub Gist 同步外，无任何网络请求。

---

## Python CLI（`rsa.py`）

仓库同时包含一个纯 Python 的 RSA 实现，无第三方依赖：

```bash
# 生成 2048 位密钥对
python3 rsa.py gen --bits 2048 --privkey priv.json --pubkey pub.json

# 公钥加密 / 私钥解密（OAEP）
python3 rsa.py encrypt --mode public --padding oaep --hash sha256 \
    --privkey priv.json --text "Hello" --outfile cipher.bin
python3 rsa.py decrypt --key priv.json --mode public --padding oaep \
    --infile cipher.bin

# PSS 签名 / 验签
python3 rsa.py sign --privkey priv.json --text "message" --outfile sig.bin
python3 rsa.py verify --key pub.json --text "message" --sigfile sig.bin
```

详细用法见 `python3 rsa.py --help` 及各子命令的 `--help`。
