# steamguard-tg

在 Telegram 私聊里获取 Steam Guard 验证码、批准二维码登录，以及处理交易和市场确认。支持多个账号，按 Telegram 用户隔离，只有 `ALLOWED_USERS` 中的用户可以使用。

不同用户可同时操作；同一用户的输入和按钮按顺序处理。账号、登录流程、操作按钮和频率限制分别归属各自用户，加入白名单不会自动共享其他用户的账号。

## Docker Compose 部署

```sh
git clone https://github.com/hanakokoizumi/steamguard-tg.git
cd steamguard-tg
cp .env.example .env
docker compose build
```

填写 `.env`：

```dotenv
BOT_TOKEN=你的机器人令牌
ALLOWED_USERS=你的Telegram数字ID
ENCRYPTION_KEY=你的Fernet密钥
```

多个用户 ID 用逗号分隔。生成加密密钥：

```sh
docker compose run --rm --no-deps bot /app/.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

准备数据目录并启动：

```sh
mkdir -p data
docker compose run --rm --user 0 --entrypoint sh bot -c 'chown 10001:10001 /app/data && chmod 700 /app/data'
chmod 600 .env
docker compose up -d --wait
docker compose logs --tail 50 bot
```

容器以 UID 10001 运行，数据库保存在 `data/steam_accounts.db`。无需开放端口。健康检查会验证 Telegram 连接、数据库和事件循环；进程退出后自动重启。

更新代码后运行 `docker compose up -d --build --wait`。同一个机器人只能运行一个轮询实例。

## 使用

| 命令 | 用途 |
| --- | --- |
| `/start`、`/help` | 打开菜单和帮助 |
| `/code`、`/2fa` | 选择账号，获取和复制验证码 |
| `/confirm` | 查看待确认请求，逐项同意或拒绝 |
| `/list` | 查看账号 |
| `/addaccount` | 按提示添加账号 |
| `/login` | 用用户名、密码和验证码重新登录已添加的账号 |
| `/updatetoken` | 更新账号的移动端 Refresh Token |
| `/deleteaccount` | 选择账号，再次确认后删除 |
| `/cancel` | 取消输入，并使之前的操作按钮失效 |

添加账号需要 SteamID64、Shared Secret、Identity Secret、Device ID、移动端 Refresh Token 和账号名称。也可直接发送包含这些字段的 `.maFile` 文件；导入时会验证令牌，已有账号不会重复添加。

发送 Steam 登录二维码图片后，先选账号，再核对设备和位置，点击“确认登录”。图片可以作为照片或原图文件发送。

验证码显示生成时的剩余有效时间。输入流程和操作按钮 10 分钟后过期；重启后需要重新发送命令。

Refresh Token 失效时，使用 `/login`，选择账号后依次输入 Steam 登录用户名、密码和验证码。也可点击“使用已保存密钥验证”，由机器人生成验证码。成功后会核对 SteamID，更新加密保存的令牌。无需先在手机登录或手动复制 Token；若 Steam 仅允许设备确认，机器人会明确提示。

密码只用于当前登录请求，收到的密码和验证码消息会立即尝试删除。验证码可重试 5 次，登录会话 3 分钟后过期；`/cancel` 会取消当前流程。每个用户 10 分钟内最多提交 5 次用户名密码登录。登录期间不会修改原有凭据，成功后才一起更新两个 Token。

已有有效移动端 Refresh Token 时，也可用 `/updatetoken` 粘贴更新。获取验证码不依赖登录令牌。

## 数据和备份

Secret 和 Token 使用 Fernet 加密，密钥保存在 `.env`。账号名称、SteamID 和设备 ID 保留为普通字段。机器人会尝试删除收到的凭据消息和账号文件；Telegram 普通私聊并非端到端加密。

备份时先停止机器人，保存 `data/` 和 `.env`，再启动。恢复时两者必须配套，丢失或更换加密密钥会导致原有凭据无法读取。

旧版数据库位于项目根目录。迁移前先备份旧数据库和 `.env`，停止旧进程，将 `steam_accounts.db` 放到 `data/`，再按上面的步骤设置目录权限。首次启动会加密旧凭据。确认迁移成功后，将旧版明文数据库移至受限的备份目录，避免误用。

`.env`、数据库、账号文件和备份均不应提交到 Git，也不会进入 Docker 构建上下文。

## 接口与开发

密码登录使用 `IAuthenticationService` 的 `GetPasswordRSAPublicKey/v1`、`BeginAuthSessionViaCredentials/v1`、`UpdateAuthSessionWithSteamGuardCode/v1`、`PollAuthSessionStatus/v1`，请求的会话类型为 `MobileApp`，密码按 Steam 返回的 RSA 公钥加密。

令牌刷新和扫码批准使用 `GenerateAccessTokenForApp/v1`、`GetAuthSessionInfo/v1`、`UpdateAuthSessionWithMobileConfirmation/v1`；时间同步使用 `ITwoFactorService/QueryTime/v1`。交易和市场确认使用 Steam 移动端的 `mobileconf/getlist`、`mobileconf/multiajaxop`，签名标签分别为 `list`、`accept`、`reject`。

协议字段于 2026-10-20 对照 [SteamDatabase/Protobufs](https://github.com/SteamDatabase/Protobufs/blob/89b77382edac5f747bfc196c2edf8996a7fe92bc/steam/steammessages_auth.steamclient.proto) 和 [Steam 在线接口列表](https://api.steampowered.com/ISteamWebAPIUtil/GetSupportedAPIList/v1/)核对。使用到的字段保存在 `protobufs/steam_auth.proto`；这些移动端接口没有完整的公开稳定性保证。

本地需要 Python 3.12+、uv 和系统库 `libzbar`。复制并填写 `.env` 后：

```sh
uv sync --frozen
uv run python main.py
uv run pytest -q
uv run ruff check .
```

依赖以 `uv.lock` 为准；`requirements.txt` 由 `uv export --frozen --no-dev --no-hashes --output-file requirements.txt` 生成。
