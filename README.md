# Steam 账号管理机器人

这是一个基于 Telegram 的 Steam 账号管理机器人，可以帮助您管理多个 Steam 账号的 2FA 验证码、确认请求等功能。

## 主要功能

- 📱 生成 Steam 2FA 验证码
- ✅ 处理 Steam 交易/市场确认请求
- 🔄 扫描 Steam 二维码快速登录
- 👥 支持管理多个 Steam 账号
- 🔒 基于用户白名单的访问控制
- 🚫 请求频率限制保护

## 安装步骤

1. 克隆仓库：
```bash
git clone https://github.com/yourusername/steam-account-bot.git
cd steam-account-bot
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

3. 配置环境变量：
   
创建 `.env` 文件并填入以下内容：
```env
BOT_TOKEN=your_telegram_bot_token
ALLOWED_USERS=telegram_user_id1,telegram_user_id2
```

## 使用方法

启动机器人：
```bash
python main.py
```

### 可用命令

- `/help` - 显示帮助信息
- `/addaccount` - 添加新的 Steam 账号
- `/deleteaccount` - 删除已添加的账号
- `/2fa` - 获取账号的 2FA 验证码
- `/confirm` - 查看并处理确认请求
- `/list` - 查看已添加的所有账号
- `/cancel` - 取消当前操作

### 添加账号

使用 `/addaccount` 命令添加新账号时，您需要依次提供以下信息：

1. Steam ID
2. Shared Secret
3. Identity Secret
4. Device ID
5. Refresh Token
6. 账号别名

### 二维码登录

直接向机器人发送 Steam 登录二维码图片，选择要使用的账号即可快速完成登录。

## 安全说明

- 本机器人包含请求频率限制，防止暴力破解
- 仅允许白名单用户访问
- 敏感信息通过环境变量配置
- 所有账号信息均经过加密存储

## 依赖项目

- python-telegram-bot
- Pillow
- pyzbar
- SQLAlchemy
- python-dotenv

## 注意事项

- 请妥善保管您的 Steam 账号凭据
- 建议在可信任的环境中运行机器人
- 定期备份数据库文件
- 请勿将机器人 Token 泄露给他人

## 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目。

## 许可证

本项目采用 MIT 许可证。

## 免责声明

本项目仅供学习和研究使用，使用本项目所造成的任何损失由使用者自行承担。请遵守 Steam 服务条款和相关法律法规。