import logging
import os
import time

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackContext, filters, \
    CallbackQueryHandler
from PIL import Image
import io
from pyzbar.pyzbar import decode
from database import Session, SteamAccount
from utils import get_2fa_code, qr_login, refresh_access_token, AccessTokenExpired, get_confirmation_list, confirm_action

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)


class SteamAccountBot:
    def __init__(self, token, allowed_users):
        # 添加请求限制，防止暴力破解
        self.request_limits = {}
        self.MAX_REQUESTS = 5  # 每分钟最大请求数
        self.RESET_TIME = 60   # 重置时间（秒）
        
        self.application = ApplicationBuilder().token(token).build()
        self.allowed_users = allowed_users

        self.application.add_handler(CommandHandler("addaccount", self.add_account))
        self.application.add_handler(CommandHandler("deleteaccount", self.delete_account))
        self.application.add_handler(CommandHandler("2fa", self.request_2fa_code))
        self.application.add_handler(CommandHandler("confirm", self.confirm_request))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("cancel", self.cancel_command))
        self.application.add_handler(CommandHandler("list", self.list_accounts))
        self.application.add_handler(MessageHandler(filters.PHOTO, self.handle_photo))
        self.application.add_handler(CallbackQueryHandler(self.callback_query_handler))

    def run(self):
        self.application.run_polling()

    def check_rate_limit(self, user_id):
        current_time = time.time()
        if user_id not in self.request_limits:
            self.request_limits[user_id] = {
                'count': 1,
                'last_reset': current_time
            }
            return True
            
        if current_time - self.request_limits[user_id]['last_reset'] > self.RESET_TIME:
            self.request_limits[user_id] = {
                'count': 1,
                'last_reset': current_time
            }
            return True
            
        self.request_limits[user_id]['count'] += 1
        if self.request_limits[user_id]['count'] > self.MAX_REQUESTS:
            return False
        return True

    async def check_user(self, update: Update):
        user_id = update.message.from_user.id if update.message else update.callback_query.from_user.id
        
        # 检查用户权限
        if str(user_id) not in self.allowed_users:
            if update.message:
                await update.message.reply_text("权限不足，请联系管理员。")
            return False
            
        # 检查请求频率
        if not self.check_rate_limit(user_id):
            if update.message:
                await update.message.reply_text("请求过于频繁，请稍后再试。")
            return False
            
        return True

    def get_access_token(self, account):
        return account.access_token

    async def add_account(self, update: Update, context: CallbackContext):
        if not await self.check_user(update):
            return

        # 添加说明信息
        help_text = (
            "请按照以下步骤添加账号：\n\n"
            "1. 输入 SteamID\n"
            "2. 输入 Shared Secret\n"
            "3. 输入 Identity Secret\n"
            "4. 输入 Device ID\n"
            "5. 输入 Refresh Token\n"
            "6. 为账号设置一个名称\n\n"
            "您可以随时输入 /cancel 取消操作。"
        )
        
        user_id = update.message.from_user.id
        context.user_data['state'] = 'awaiting_steamid'
        context.user_data['user_id'] = user_id

        await update.message.reply_text(help_text)
        await update.message.reply_text("请输入 SteamID：")

    async def handle_account_input(self, update: Update, context: CallbackContext):
        try:
            user_id = context.user_data['user_id']
            step = context.user_data.get('state')
            text = update.message.text.strip()  # 去除输入的空白字符
            
            # 添加输入验证
            if not text:
                await update.message.reply_text("输入不能为空，请重新输入。")
                return
                
            with Session() as session:
                if step == 'awaiting_steamid':
                    context.user_data['steamid'] = text
                    context.user_data['state'] = 'awaiting_shared_secret'
                    await update.message.reply_text("请回复 Shared Secret：")
                elif step == 'awaiting_shared_secret':
                    context.user_data['shared_secret'] = text
                    context.user_data['state'] = 'awaiting_identity_secret'
                    await update.message.reply_text("请回复 Identity Secret：")
                elif step == 'awaiting_identity_secret':
                    context.user_data['identity_secret'] = text
                    context.user_data['state'] = 'awaiting_device_id'
                    await update.message.reply_text("请回复 Device ID：")
                elif step == 'awaiting_device_id':
                    context.user_data['device_id'] = text
                    context.user_data['state'] = 'awaiting_refresh_token'
                    await update.message.reply_text("请回复 Refresh Token：")
                elif step == 'awaiting_refresh_token':
                    context.user_data['refresh_token'] = text
                    context.user_data['state'] = 'awaiting_name'
                    await update.message.reply_text("请为该账号起个名字：")
                elif step == 'awaiting_name':
                    context.user_data['name'] = text

                    account = SteamAccount(
                        user_id=user_id,
                        steamid=context.user_data['steamid'],
                        shared_secret=context.user_data['shared_secret'],
                        identity_secret=context.user_data['identity_secret'],
                        device_id=context.user_data['device_id'],
                        refresh_token=context.user_data['refresh_token'],
                        steam_name=context.user_data['name']
                    )
                    session.add(account)
                    session.commit()

                    access_token = refresh_access_token(account.steamid, account.refresh_token)
                    account.access_token = access_token
                    session.commit()
                    del context.user_data['state']
                    del context.user_data['user_id']
                    await update.message.reply_text(f"账号 {account.steam_name} 已成功添加！")

        except Exception as e:
            logging.error(f"处理账号输入时发生错误: {str(e)}")
            await update.message.reply_text("处理您的请求时发生错误，请重试或联系管理员。")

    async def request_2fa_code(self, update: Update, context: CallbackContext):
        if not await self.check_user(update):
            return

        user_id = update.message.from_user.id

        with Session() as session:
            accounts = session.query(SteamAccount).filter_by(user_id=user_id).all()

            if not accounts:
                await update.message.reply_text(
                    "您还没有添加任何账号。\n"
                    "使用 /addaccount 命令来添加一个新账号。"
                )
                return
            
            # 改进按钮布局，每行显示一个账号
            keyboard = [[InlineKeyboardButton(f"{acc.steam_name} ({acc.steamid})", 
                        callback_data=f'2fa_{acc.id}')] for acc in accounts]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("请选择要获取 2FA 代码的账号：", reply_markup=reply_markup)

    async def handle_photo(self, update: Update, context: CallbackContext):
        if not await self.check_user(update):
            return

        user_id = update.message.from_user.id

        photo_file = await update.message.photo[-1].get_file()
        photo_byte = io.BytesIO()

        photo_byte.seek(0)
        image = Image.open(io.BytesIO(await photo_file.download_as_bytearray()))

        decoded_objects = decode(image)

        if decoded_objects:
            qr_url = decoded_objects[0].data.decode('utf-8')
            if qr_url.startswith("https://s.team/q"):
                with Session() as session:
                    accounts = session.query(SteamAccount).filter_by(user_id=user_id).all()

                    if not accounts:
                        await update.message.reply_text("你没有添加任何账号。")
                        return

                    keyboard = [[InlineKeyboardButton(f"{acc.steam_name} ({acc.steamid})",
                                                      callback_data=f'qr_{acc.id}_{qr_url}') for acc in accounts]]
                    reply_markup = InlineKeyboardMarkup(keyboard)
                    await update.message.reply_text("请选择要登录的账号：", reply_markup=reply_markup)
            else:
                await update.message.reply_text("未找到有效的二维码。")
        else:
            await update.message.reply_text("未识别到二维码。")

    async def delete_account(self, update: Update, context: CallbackContext):
        if not await self.check_user(update):
            return

        user_id = update.message.from_user.id

        with Session() as session:
            accounts = session.query(SteamAccount).filter_by(user_id=user_id).all()

            if not accounts:
                await update.message.reply_text("你没有添加任何账号。")
                return

            keyboard = [
                [InlineKeyboardButton(f"{acc.steam_name} ({acc.steamid})", 
                                    callback_data=f'delete_{acc.id}') for acc in accounts]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("请选择要删除的账号：", reply_markup=reply_markup)

    async def confirm_request(self, update: Update, context: CallbackContext):
        if not await self.check_user(update):
            return

        user_id = update.message.from_user.id

        with Session() as session:
            accounts = session.query(SteamAccount).filter_by(user_id=user_id).all()

            if not accounts:
                await update.message.reply_text("你没有添加任何账号。")
                return

            keyboard = [
                [InlineKeyboardButton(f"{acc.steam_name} ({acc.steamid})", 
                                    callback_data=f'confirm_list_{acc.id}') for acc in accounts]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("请选择要查看确认请求的账号：", reply_markup=reply_markup)

    async def show_confirmation_details(self, query, account, conf):
        keyboard = [
            [
                InlineKeyboardButton("同意", callback_data=f'confirm_action_{account.id}_{conf["id"]}_{conf["nonce"]}_1'),
                InlineKeyboardButton("拒绝", callback_data=f'confirm_action_{account.id}_{conf["id"]}_{conf["nonce"]}_0'),
            ],
            [InlineKeyboardButton("返回", callback_data=f'confirm_list_{account.id}')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        details = f"类型：{conf['type_name']}\n"
        details += f"标题：{conf['headline']}\n"
        if conf.get('summary'):
            details += f"描述：{', '.join(conf['summary'])}\n"
        if conf.get('warn'):
            details += f"警告：{conf['warn']}\n"

        await query.edit_message_text(text=details, reply_markup=reply_markup)

    async def callback_query_handler(self, update: Update, context: CallbackContext):
        query = update.callback_query
        await query.answer()

        if not await self.check_user(update):
            return

        callback_data = query.data.split('_')
        action = callback_data[0]

        if action == 'confirm':
            subaction = callback_data[1]
            account_id = int(callback_data[2])
            
            with Session() as session:
                account = session.query(SteamAccount).filter_by(id=account_id, user_id=query.from_user.id).first()
                if not account:
                    await query.edit_message_text(text="无法找到该账号。")
                    return

                if subaction == 'list':
                    try:
                        access_token = self.get_access_token(account)
                        conf_list = get_confirmation_list(account.steamid, account.identity_secret, 
                                                        access_token, account.device_id)
                        
                        if not conf_list:
                            await query.edit_message_text(text="没有待确认的请求。")
                            return

                        keyboard = []
                        for conf in conf_list:
                            button_text = f"{conf['type_name']} - {conf['headline']}"
                            keyboard.append([InlineKeyboardButton(
                                button_text, 
                                callback_data=f'confirm_detail_{account.id}_{conf["id"]}')]
                            )
                        reply_markup = InlineKeyboardMarkup(keyboard)
                        await query.edit_message_text(text="请选择要处理的确认请求：", reply_markup=reply_markup)
                        
                        if 'confirmations' not in context.user_data:
                            context.user_data['confirmations'] = {}
                        context.user_data['confirmations'][account.id] = conf_list

                    except AccessTokenExpired:
                        access_token = refresh_access_token(account.steamid, account.refresh_token)
                        account.access_token = access_token
                        session.commit()
                        # 刷新令牌后重试
                        conf_list = get_confirmation_list(account.steamid, account.identity_secret, 
                                                       access_token, account.device_id)
                        
                        if not conf_list:
                            await query.edit_message_text(text="没有待确认的请求。")
                            return

                        keyboard = []
                        for conf in conf_list:
                            button_text = f"{conf['type_name']} - {conf['headline']}"
                            keyboard.append([InlineKeyboardButton(
                                button_text, 
                                callback_data=f'confirm_detail_{account.id}_{conf["id"]}')]
                            )
                        reply_markup = InlineKeyboardMarkup(keyboard)
                        await query.edit_message_text(text="请选择要处理的确认请求：", reply_markup=reply_markup)
                        
                        if 'confirmations' not in context.user_data:
                            context.user_data['confirmations'] = {}
                        context.user_data['confirmations'][account.id] = conf_list
                    except Exception as e:
                        await query.edit_message_text(text=f"获取确认列表失败: {str(e)}")

                elif subaction == 'detail':
                    conf_id = callback_data[3]
                    conf_list = context.user_data.get('confirmations', {}).get(account.id, [])
                    conf = next((c for c in conf_list if c['id'] == conf_id), None)
                    
                    if conf:
                        await self.show_confirmation_details(query, account, conf)
                    else:
                        await query.edit_message_text(text="无法找到该确认请求。")

                elif subaction == 'action':
                    conf_id = callback_data[3]
                    conf_nonce = callback_data[4]
                    is_allow = callback_data[5] == '1'
                    
                    try:
                        access_token = self.get_access_token(account)
                        result = confirm_action(account.steamid, account.identity_secret, 
                                             access_token, account.device_id, conf_id, conf_nonce, is_allow)
                        
                        if result:
                            action_text = "已同意" if is_allow else "已拒绝"
                            await query.edit_message_text(text=f"确认请求{action_text}。")
                        else:
                            await query.edit_message_text(text="操作失败。")
                            
                    except AccessTokenExpired:
                        access_token = refresh_access_token(account.steamid, account.refresh_token)
                        account.access_token = access_token
                        session.commit()
                        # 刷新令牌后重试
                        result = confirm_action(account.steamid, account.identity_secret, 
                                             access_token, account.device_id, conf_id, conf_nonce, is_allow)
                        
                        if result:
                            action_text = "已同意" if is_allow else "已拒绝"
                            await query.edit_message_text(text=f"确认请求{action_text}。")
                        else:
                            await query.edit_message_text(text="操作失败。")
                    except Exception as e:
                        await query.edit_message_text(text=f"操作失败: {str(e)}")

        elif action == '2fa':
            account_id = int(callback_data[1])
            with Session() as session:
                account = session.query(SteamAccount).filter_by(id=account_id, user_id=query.from_user.id).first()
                if account:
                    try:
                        code = get_2fa_code(account.shared_secret)
                        await query.edit_message_text(
                            text=f"账号 {account.steam_name} ({account.steamid}) 的 2FA 代码是: {code}")
                    except Exception as e:
                        await query.edit_message_text(text=f"获取 2FA 代码失败: {str(e)}")
                else:
                    await query.edit_message_text(text="无法找到该账号。")

        elif action == 'qr':
            account_id = int(callback_data[1])
            qr_url = callback_data[2]
            with Session() as session:
                account = session.query(SteamAccount).filter_by(id=account_id, user_id=query.from_user.id).first()
                if account:
                    try:
                        access_token = self.get_access_token(account)
                        response = qr_login(account.steamid, account.shared_secret, access_token, qr_url)
                        if response:
                            await query.edit_message_text(text=f"账号 {account.steam_name} 登录成功！")
                        else:
                            await query.edit_message_text(text=f"账号 {account.steam_name} 登录失败：二维码已过期。")
                    except AccessTokenExpired:
                        access_token = refresh_access_token(account.steamid, account.refresh_token)
                        account.access_token = access_token
                        session.add(account)
                        session.commit()
                        response = qr_login(account.steamid, account.shared_secret, access_token, qr_url)
                        if response:
                            await query.edit_message_text(text=f"账号 {account.steam_name} 登录成功！")
                        else:
                            await query.edit_message_text(text=f"账号 {account.steam_name} 登录失败：二维码已过期。")
                    except Exception as e:
                        await query.edit_message_text(text=f"二维码登录失败: {str(e)}")
                else:
                    await query.edit_message_text(text="无法找到该账号。")

        elif action == 'delete':
            account_id = int(callback_data[1])
            with Session() as session:
                account = session.query(SteamAccount).filter_by(id=account_id, user_id=query.from_user.id).first()
                if account:
                    account_name = account.steam_name
                    session.delete(account)
                    session.commit()
                    await query.edit_message_text(text=f"账号 {account_name} 已成功删除！")
                else:
                    await query.edit_message_text(text="无法找到该账号。")

    async def help_command(self, update: Update, context: CallbackContext):
        help_text = (
            "可用命令列表：\n\n"
            "/addaccount - 添加新的 Steam 账号\n"
            "/deleteaccount - 删除已添加的账号\n"
            "/2fa - 获取账号的 2FA 验证码\n"
            "/confirm - 查看并处理确认请求\n"
            "/list - 查看已添加的所有账号\n"
            "/cancel - 取消当前操作\n"
            "/help - 显示此帮助信息\n\n"
            "您还可以发送 Steam 二维码图片来快速登录。"
        )
        await update.message.reply_text(help_text)

    async def cancel_command(self, update: Update, context: CallbackContext):
        if 'state' in context.user_data:
            del context.user_data['state']
            await update.message.reply_text("已取消当前操作。")
        else:
            await update.message.reply_text("没有正在进行的操作。")

    async def list_accounts(self, update: Update, context: CallbackContext):
        if not await self.check_user(update):
            return

        with Session() as session:
            accounts = session.query(SteamAccount).filter_by(user_id=update.message.from_user.id).all()
            
            if not accounts:
                await update.message.reply_text("您还没有添加任何账号。")
                return
                
            account_list = "您的账号列表：\n\n"
            for acc in accounts:
                account_list += f"• {acc.steam_name} (Steam ID: {acc.steamid})\n"
            
            await update.message.reply_text(account_list)


if __name__ == '__main__':
    import dotenv
    dotenv.load_dotenv()
    token = os.environ['BOT_TOKEN']
    allowed_users = os.environ['ALLOWED_USERS'].split(',')
    bot = SteamAccountBot(token, allowed_users)
    bot.run()
