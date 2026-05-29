# IG Cookie Bot — Telegram Bot
# Fetches Instagram session cookies via login
# Deploy on Railway — set BOT_TOKEN env variable

import os
import asyncio
import logging
import time
import hmac
import hashlib
import base64
import struct
import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    ConversationHandler, CallbackQueryHandler,
    filters, ContextTypes
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")

# ── Conversation states ────────────────────────────────────────────────────────
USERNAME, PASSWORD, TWOFA = range(3)

# ── TOTP ──────────────────────────────────────────────────────────────────────
def generate_totp(secret: str, digits=6, period=30) -> str:
    secret = secret.upper().replace(" ", "")
    missing = (8 - len(secret) % 8) % 8
    secret += "=" * missing
    key = base64.b32decode(secret)
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)

# ── Instagram login ────────────────────────────────────────────────────────────
IG = "https://www.instagram.com"

HEADERS_BASE = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "X-IG-App-ID": "936619743392459",
    "X-Instagram-AJAX": "1",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": IG,
    "Referer": IG + "/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}

def enc_password(password: str) -> str:
    ts = int(time.time())
    return f"#PWD_INSTAGRAM_BROWSER:10:{ts}:{password}"

async def ig_login(username: str, password: str, twofa_code: str = None):
    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Step 1: seed cookies
        await client.get(IG + "/", headers={**HEADERS_BASE, "Accept": "text/html"})

        # Step 2: get CSRF
        r = await client.get(IG + "/accounts/login/", headers={**HEADERS_BASE, "Accept": "text/html"})
        csrf = client.cookies.get("csrftoken") or ""
        if not csrf:
            import re
            m = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', r.text)
            csrf = m.group(1) if m else ""
        if not csrf:
            return {"ok": False, "error": "CSRF token পাওয়া যায়নি।"}

        # Step 3: login POST
        payload = {
            "username": username,
            "enc_password": enc_password(password),
            "queryParams": "{}",
            "optIntoOneTap": "false",
            "stopDeletionNonce": "",
            "trustedDeviceRecords": "{}",
        }
        headers = {
            **HEADERS_BASE,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRFToken": csrf,
        }
        r = await client.post(IG + "/api/v1/web/accounts/login/ajax/", data=payload, headers=headers)

        if r.status_code == 400:
            body = r.text
            return {"ok": False, "error": f"HTTP 400: {body[:300]}"}
        if r.status_code == 429:
            return {"ok": False, "error": "Rate limited — কিছুক্ষণ পরে try করো।"}
        if not r.is_success:
            return {"ok": False, "error": f"HTTP {r.status_code}"}

        data = r.json()

        # Checkpoint
        if data.get("checkpoint_url"):
            if "suspended" in data.get("checkpoint_url", ""):
                return {"ok": False, "error": "❌ Account suspended।"}
            return {"ok": False, "error": "⚠️ Instagram checkpoint চাইছে — আগে browser এ manually login করে verify করো।"}

        # 2FA required
        if data.get("two_factor_required"):
            if not twofa_code:
                return {"ok": False, "error": "2FA_NEEDED", "two_factor_info": data.get("two_factor_info")}
            csrf2 = client.cookies.get("csrftoken") or csrf
            info = data["two_factor_info"]
            r2 = await client.post(
                IG + "/api/v1/web/accounts/login/ajax/two_factor/",
                data={
                    "username": username,
                    "verificationCode": twofa_code.strip(),
                    "identifier": info["two_factor_identifier"],
                    "queryParams": "{}",
                    "trustThisDevice": "0",
                    "verificationMethod": "3",
                },
                headers={**headers, "X-CSRFToken": csrf2},
            )
            if not r2.is_success:
                return {"ok": False, "error": f"2FA HTTP {r2.status_code}"}
            data = r2.json()
            if not data.get("authenticated"):
                return {"ok": False, "error": "❌ 2FA code ভুল।"}

        if not data.get("authenticated"):
            reason = data.get("message") or "Invalid credentials"
            return {"ok": False, "error": f"❌ Login failed: {reason}"}

        # Collect cookies
        COOKIE_ORDER = ["datr", "ig_did", "mid", "ps_l", "ps_n", "wd",
                        "csrftoken", "ds_user_id", "sessionid", "rur"]
        jar = {c.name: c.value for c in client.cookies.jar}

        parts = []
        for name in COOKIE_ORDER:
            if name in jar:
                val = jar[name]
                if name == "rur" and not val.startswith('"'):
                    val = f'"{val}"'
                parts.append(f"{name}={val}")
        for k, v in jar.items():
            if k not in COOKIE_ORDER:
                parts.append(f"{k}={v}")

        cookie_str = "; ".join(parts)
        return {"ok": True, "cookies": cookie_str, "jar": jar}

# ── Bot handlers ───────────────────────────────────────────────────────────────

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 *IG Cookie Bot*\n\n"
        "Instagram session cookies বের করতে /login দাও।\n\n"
        "⚠️ শুধু নিজের account এ use করো।",
        parse_mode="Markdown"
    )

async def login_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📝 Instagram *username* দাও:", parse_mode="Markdown")
    return USERNAME

async def got_username(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["username"] = update.message.text.strip()
    await update.message.reply_text("🔑 *Password* দাও:", parse_mode="Markdown")
    return PASSWORD

async def got_password(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["password"] = update.message.text.strip()
    ctx.user_data["twofa_needed"] = False

    await update.message.reply_text("⏳ Login করছি...")

    result = await ig_login(ctx.user_data["username"], ctx.user_data["password"])

    if result.get("error") == "2FA_NEEDED":
        ctx.user_data["two_factor_info"] = result.get("two_factor_info")
        ctx.user_data["twofa_needed"] = True
        await update.message.reply_text("🔐 2FA দাও:

• Secret key হলে সেটা paste করো (auto-generate হবে)
• অথবা 6-digit code সরাসরি দাও")
        return TWOFA

    return await finish_login(update, ctx, result)

async def got_twofa(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    # If user sends a TOTP secret key (long, base32), auto-generate code
    if len(text) > 10 and text.replace(" ","").isalnum() and not text.isdigit():
        try:
            code = generate_totp(text)
            await update.message.reply_text(f"🔑 Secret key থেকে code তৈরি হলো: `{code}`", parse_mode="Markdown")
        except Exception as e:
            await update.message.reply_text(f"❌ Key থেকে code বানাতে পারিনি: {e}")
            return TWOFA
    else:
        code = text  # manual 6-digit code
    await update.message.reply_text("⏳ 2FA verify করছি...")
    result = await ig_login(ctx.user_data["username"], ctx.user_data["password"], code)
    return await finish_login(update, ctx, result)

async def finish_login(update: Update, ctx: ContextTypes.DEFAULT_TYPE, result: dict):
    if not result["ok"]:
        await update.message.reply_text(f"❌ *Error:*\n`{result['error']}`", parse_mode="Markdown")
        return ConversationHandler.END

    cookies = result["cookies"]
    jar = result["jar"]
    sessionid = jar.get("sessionid", "N/A")
    ds_user = jar.get("ds_user_id", "N/A")
    username = ctx.user_data.get("username", "?")

    # Send summary
    await update.message.reply_text(
        f"✅ *Login সফল!*\n\n"
        f"👤 User: `{username}`\n"
        f"🆔 User ID: `{ds_user}`\n"
        f"🍪 Cookies: {len(jar)} টা\n\n"
        f"নিচে full cookie string পাঠাচ্ছি 👇",
        parse_mode="Markdown"
    )

    # Send cookie string in chunks if needed
    chunk_size = 3800
    for i in range(0, len(cookies), chunk_size):
        await update.message.reply_text(f"`{cookies[i:i+chunk_size]}`", parse_mode="Markdown")

    ctx.user_data.clear()
    return ConversationHandler.END

async def cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text("❌ বাতিল করা হয়েছে।")
    return ConversationHandler.END

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN environment variable set করো!")

    app = Application.builder().token(BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[CommandHandler("login", login_start)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, got_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, got_password)],
            TWOFA:    [MessageHandler(filters.TEXT & ~filters.COMMAND, got_twofa)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(conv)

    logger.info("Bot চালু হয়েছে...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
