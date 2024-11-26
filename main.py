import logging
import os

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackContext, filters, \
    CallbackQueryHandler
from PIL import Image
import io
from pyzbar.pyzbar import decode
from database import Session, SteamAccount
from utils import get_2fa_code, qr_login, refresh_access_token, AccessTokenExpired

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)


class SteamAccountBot:
    def __init__(self, token, allowed_users):
        self.application = ApplicationBuilder().token(token).build()
        self.allowed_users = allowed_users

        self.application.add_handler(CommandHandler("addaccount", self.add_account))
        self.application.add_handler(CommandHandler("2fa", self.request_2fa_code))
        self.application.add_handler(MessageHandler(filters.PHOTO, self.handle_photo))
        self.application.add_handler(CallbackQueryHandler(self.callback_query_handler))

    def run(self):
        self.application.run_polling()

    def check_user(self, update: Update):
        user_id = update.message.from_user.id if update.message else update.callback_query.from_user.id
        if str(user_id) not in self.allowed_users:
            update.message.reply_text("Permission Denied")
            return False
        return True

    def get_access_token(self, account):
        return account.access_token

    async def add_account(self, update: Update, context: CallbackContext):
        if not self.check_user(update):
            return

        user_id = update.message.from_user.id
        context.user_data['state'] = 'awaiting_steamid'
        context.user_data['user_id'] = user_id

        await update.message.reply_text("请回复 SteamID：")

        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_account_input))

    async def handle_account_input(self, update: Update, context: CallbackContext):
        user_id = context.user_data['user_id']
        step = context.user_data.get('state')
        text = update.message.text

        with Session() as session:
            if step == 'awaiting_steamid':
                context.user_data['steamid'] = text
                context.user_data['state'] = 'awaiting_shared_secret'
                await update.message.reply_text("请回复 Shared Secret：")
            elif step == 'awaiting_shared_secret':
                context.user_data['shared_secret'] = text
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

    async def request_2fa_code(self, update: Update, context: CallbackContext):
        if not self.check_user(update):
            return

        user_id = update.message.from_user.id

        with Session() as session:
            accounts = session.query(SteamAccount).filter_by(user_id=user_id).all()

            if not accounts:
                await update.message.reply_text("你没有添加任何账号。")
                return

            keyboard = [
                [InlineKeyboardButton(f"{acc.steam_name} ({acc.steamid})", callback_data=f'2fa_{acc.id}') for acc in
                 accounts]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("请选择要获取 2FA 代码的账号：", reply_markup=reply_markup)

    async def handle_photo(self, update: Update, context: CallbackContext):
        if not self.check_user(update):
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

    async def callback_query_handler(self, update: Update, context: CallbackContext):
        query = update.callback_query
        await query.answer()

        if not self.check_user(update):
            return

        callback_data = query.data.split('_')
        action = callback_data[0]

        if action == '2fa':
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


if __name__ == '__main__':
    import dotenv
    dotenv.load_dotenv()
    token = os.environ['BOT_TOKEN']
    allowed_users = os.environ['ALLOWED_USERS'].split(',')
    bot = SteamAccountBot(token, allowed_users)
    bot.run()
