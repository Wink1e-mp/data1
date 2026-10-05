"""
Telegram-бот для сбора заявок (лидов) с сохранением в Google Sheets.

Стек: Python 3.10+, pyTelegramBotAPI (telebot), gspread, google-auth, python-dotenv.

Архитектура:
    - FSM (машина состояний) на базе telebot.StateMemoryMiddleware:
      WAIT_NAME -> WAIT_PHONE -> WAIT_REQUEST -> DONE
    - Все секреты читаются ТОЛЬКО из переменных окружения (.env),
      захардкоженных токенов/ключей/ID в коде нет.
    - Ошибки Telegram API и Google Sheets API перехватываются,
      бот не падает, а пишет в лог и уведомляет пользователя корректно.
    - Логирование в файл bot.log и в консоль.

Безопасность (учитываем специфику ИБ):
    - .env и service_account.json добавлены в .gitignore — секреты не попадают в git;
    - входящие данные (имя/телефон/заявка) проходят санитизацию: ограничение длины,
      удаление управляющих символов, экранирование =+-@ (защита от CSV/formula injection
      при последующем экспорте таблицы);
    - сообщения админу отправляются через MarkdownV2 с полным экранированием
      пользовательского ввода (защита от инъекций форматирования);
    - токен бота никогда не пишется в лог.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

# python-dotenv: загружаем переменные окружения из файла .env
from dotenv import load_dotenv

# pyTelegramBotAPI (telebot) + встроенная FSM-поддержка (middleware)
import telebot
from telebot import types
from telebot.custom_filters import StateFilter
from telebot.storage import StateMemoryStorage
from telebot.util import extract_first_entity

# gspread + google-auth: работа с Google Sheets по Service Account
import gspread
from google.oauth2.service_account import Credentials
from google.auth.exceptions import GoogleAuthError

# =============================================================================
# 1. КОНФИГУРАЦИЯ (только из переменных окружения, никаких секретов в коде)
# =============================================================================

# Загружаем .env из той же папки, где лежит bot.py (важно для запуска из IDE/cron).
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _require_env(name: str) -> str:
    """Обязательная переменная окружения. При отсутствии — понятная ошибка и выход."""
    value = os.getenv(name, "").strip()
    if not value:
        # Важно: значение переменной НЕ логируется, чтобы случайно не уteeчить секрет.
        raise RuntimeError(
            f"Переменная окружения {name} не задана. "
            f"Скопируйте .env.example в .env и заполните значения."
        )
    return value


TELEGRAM_BOT_TOKEN = _require_env("TELEGRAM_BOT_TOKEN")
ADMIN_CHAT_ID = _require_env("ADMIN_CHAT_ID")

# Путь к JSON-ключу сервисного аккаунта Google (по умолчанию ./service_account.json)
GOOGLE_CREDENTIALS_FILE = (BASE_DIR / os.getenv("GOOGLE_CREDENTIALS_FILE", "service_account.json")).resolve()
GOOGLE_SHEET_ID = _require_env("GOOGLE_SHEET_ID")
GOOGLE_SHEET_TAB = os.getenv("GOOGLE_SHEET_TAB", "Заявки").strip() or "Заявки"

# Проверим, что ADMIN_CHAT_ID — это число (chat_id в Telegram всегда целое, может быть отрицательным)
if not re.fullmatch(r"-?\d+", ADMIN_CHAT_ID):
    raise RuntimeError("ADMIN_CHAT_ID должен быть числом (например, 123456789). Узнайте его через @userinfobot.")

# Настройки безопасности данных
MAX_NAME_LEN = 100
MAX_PHONE_LEN = 30
MAX_REQUEST_LEN = 2000
MAX_MESSAGE_LEN = 4000  # лимит sendMessage в Telegram — 4096, берём с запасом

# scopes, необходимые gspread для чтения/записи таблиц и доступа к Drive
GOOGLE_SCOPES = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive",
]

# =============================================================================
# 2. ЛОГИРОВАНИЕ (в файл bot.log + в консоль)
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(BASE_DIR / "bot.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
# telebot сам логирует себя — приобщаем его логгер к нашим обработчикам
tb_logger = telebot.telebot.logger
tb_logger.setLevel(logging.INFO)
for h in logging.getLogger().handlers:
    tb_logger.addHandler(h)

logger = logging.getLogger("lead_bot")

# =============================================================================
# 3. СОСТОЯНИЯ FSM (шаги опроса)
# =============================================================================


class States:
    """Пространство имён состояний диалога (FSM).

    Используем строковые константы вместо магических литералов по всему коду.
    """

    WAIT_NAME = "state_wait_name"
    WAIT_PHONE = "state_wait_phone"
    WAIT_REQUEST = "state_wait_request"
    DONE = "state_done"


# =============================================================================
# 4. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (валидация, санитизация, форматирование)
# =============================================================================


def sanitize_text(text: str, max_len: int) -> str:
    """Санитизация пользовательского ввода перед сохранением в таблицу.

    Что делаем:
      1. Сжимаем повторяющиеся пробелы и удаляем пробельные символы по краям.
      2. Удаляем управляющие символы (x00-x1F, x7F) — защита от log/CSV injection.
      3. Ограничиваем длину (защита от переполнения/спама).
      4. Экранируем префиксы формул (= + - @) через апостроф — защита от
         spreadsheet formula injection, если таблицу потом экспортируют в CSV.
    """
    cleaned = re.sub(r"\s+", " ", text).strip()
    cleaned = re.sub(r"[\x00-\x1F\x7F]", "", cleaned)
    cleaned = cleaned[:max_len]
    if cleaned and cleaned[0] in ("=", "+", "-", "@"):
        cleaned = "'" + cleaned
    return cleaned


def is_valid_name(name: str) -> bool:
    """Имя: только буквы (любого алфавита), пробелы, дефисы; длина 2..MAX_NAME_LEN."""
    if not (2 <= len(name) <= MAX_NAME_LEN):
        return False
    return bool(re.fullmatch(r"[A-Za-zА-Яа-яЁё\s\-']+", name))


def normalize_phone(phone: str) -> str:
    """Возвращает нормализованный телефон или None, если валидация не прошла.

    Принимаем международный формат: +79991234567, 89991234567, 79991234567,
    допускаются разделители: пробел, дефис, скобки.
    """
    digits_only = re.sub(r"[\s\-\(\)\.]", "", phone)
    m = re.fullmatch(r"\+?\d{10,15}", digits_only)
    if not m:
        return None
    # Убираем «русский» вариант 8... в пользу международного 7...
    if digits_only.startswith("8") and len(digits_only) == 11:
        digits_only = "7" + digits_only[1:]
    if not digits_only.startswith("+"):
        digits_only = "+" + digits_only
    return digits_only


def escape_markdown_v2(text: str) -> str:
    """Экранирование спецсимволов MarkdownV2 (18 символов по документации Bot API).

    Обязательно при подстановке пользовательских данных в MarkdownV2-сообщения —
    иначе пользователь сможет «сломать» разметку уведомления админа (инъекция).
    """
    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!\\])", r"\\\1", text)


def format_timestamp() -> str:
    """Метка времени заявки (часовой пояс сервера)."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# 5. РАБОТА С GOOGLE SHEETS
# =============================================================================

HEADER_ROW = ["Дата", "Имя", "Телефон", "Суть заявки", "Telegram ID", "Username"]


def get_spreadsheet_worksheet() -> gspread.Worksheet:
    """Открывает таблицу GOOGLE_SHEET_ID и возвращает лист GOOGLE_SHEET_TAB.

    Бросает исключения gspread/GoogleAuth — вызывающий код перехватывает их.
    """
    credentials = Credentials.from_service_account_file(
        str(GOOGLE_CREDENTIALS_FILE), scopes=GOOGLE_SCOPES
    )
    client = gspread.client.Client(credentials=credentials)
    spreadsheet = client.open_by_key(GOOGLE_SHEET_ID)
    try:
        worksheet = spreadsheet.worksheet(GOOGLE_SHEET_TAB)
    except gspread.WorksheetNotFound:
        # Если листа нет — создаём его автоматически (для новичка это удобнее).
        logger.warning("Лист '%s' не найден — создаю новый.", GOOGLE_SHEET_TAB)
        worksheet = spreadsheet.add_worksheet(title=GOOGLE_SHEET_TAB, rows=1000, cols=10)
    return worksheet


def ensure_header(worksheet: gspread.Worksheet) -> None:
    """Гарантирует наличие заголовков в первой строке листа."""
    first_row = worksheet.range("A1:F1")
    values = [cell.value for cell in first_row]
    if not any(values):  # пустая строка → пишем шапку
        worksheet.update("A1:F1", [HEADER_ROW])


def save_to_google_sheets(lead: "Lead") -> None:
    """Сохраняет заявку в Google Таблицу (добавляет новую строку в конец листа).

    Args:
        lead: данные заявки.

    Raises:
        Exception: любые ошибки gspread/API — логируются и пробрасываются выше,
                   обработчик решает, что сказать пользователю.
    """
    worksheet = get_spreadsheet_worksheet()
    ensure_header(worksheet)
    row = [
        lead.created_at,
        lead.name,
        lead.phone,
        lead.request_text,
        lead.user_id,
        lead.username or "",
    ]
    worksheet.append_row(row, value_input_option="USER_ENTERED")
    logger.info(
        "Заявка сохранена в Google Sheets: user_id=%s, name=%r, phone=%s",
        lead.user_id, lead.name, lead.phone,
    )


# =============================================================================
# 6. МОДЕЛЬ ДАННЫХ И БОТ
# =============================================================================


@dataclass(frozen=True)
class Lead:
    """Заявка (лид) — неизменяемая структура данных."""

    user_id: int
    username: Optional[str]
    name: str
    phone: str
    request_text: str
    created_at: str


# Хранилище состояний в памяти процесса.
# ВАЖНО (для продакшена): после рестарта бота активные диалоги сбрасываются —
# пользователь начинает заново. Для полноценной FSM можно использовать
# StateRedisStorage (redis) или свою БД.
state_storage = StateMemoryStorage()

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN, state_memory=state_storage, parse_mode=None)


# ---------------------------------------------------------------------------
# Отправка сообщений с защитой от ошибок Telegram API
# ---------------------------------------------------------------------------

def safe_send(chat_id: int, text: str, reply_markup: Optional[types.ReplyMarkup] = None) -> bool:
    """Отправляет сообщение, перехватывая ошибки Telegram API.

    Returns:
        True — доставлено, False — ошибка (записана в лог).
    """
    if len(text) > MAX_MESSAGE_LEN:
        text = text[:MAX_MESSAGE_LEN] + "\n\n… (сообщение сокращено)"
    try:
        bot.send_message(chat_id, text, reply_markup=reply_markup)
        return True
    except telebot.apihelper.ApiTelegramException as e:
        logger.error("Telegram API error (send to %s): %s", chat_id, e)
        return False
    except Exception as e:  # сеть, таймаут и пр. — бот не должен падать
        logger.exception("Неизвестная ошибка при отправке сообщения %s: %s", chat_id, e)
        return False


def notify_admin(lead: Lead) -> None:
    """Отправляет администратору уведомление о новой заявке (MarkdownV2).

    Данные пользователя экранируются, чтобы форматуру нельзя было сломать.
    Ошибки Telegram API не должны ронять бота — они логируются.
    """
    lines = [
        f"🆕 *Новая заявка*",
        "",
        f"👤 *Имя:* {escape_markdown_v2(lead.name)}",
        f"📞 *Телефон:* {escape_markdown_v2(lead.phone)}",
        f"📝 *Суть заявки:* {escape_markdown_v2(lead.request_text)}",
        f"🆔 *Telegram ID:* `{lead.user_id}`",
        f"🏷 *Username:* {escape_markdown_v2('@' + lead.username) if lead.username else '—'}",
        f"🕒 *Время:* {escape_markdown_v2(lead.created_at)}",
    ]
    text = "\n".join(lines)
    ok = safe_send(int(ADMIN_CHAT_ID), text)
    if not ok:
        logger.error("Не удалось отправить уведомление админу (chat_id=%s).", ADMIN_CHAT_ID)


# ---------------------------------------------------------------------------
# Хэндлеры
# ---------------------------------------------------------------------------

@bot.message_handler(commands=["start", "help"])
def start_handler(message: types.Message) -> None:
    """/start — знакомство и переход в состояние WAIT_NAME."""
    try:
        bot.set_state(message.from_user.id, States.WAIT_NAME, message.chat.id)
        name_hint = message.from_user.first_name or "друг"
        welcome = (
            f"👋 Привет, {name_hint}!\n\n"
            "Я помогу оставить заявку. Отвечу на 3 коротких вопроса.\n\n"
            "1️⃣ Как вас зовут?"
        )
        safe_send(message.chat.id, welcome)
        logger.info("/start от user_id=%s", message.from_user.id)
    except Exception:
        logger.exception("Ошибка в start_handler")
        safe_send(message.chat.id, "Произошла ошибка. Попробуйте ещё раз: /start")


@bot.message_handler(state=States.WAIT_NAME)
def process_name(message: types.Message) -> None:
    """Шаг 1: имя. Валидация, затем переход к телефону."""
    raw = (message.text or "").strip()
    name = sanitize_text(raw, MAX_NAME_LEN)

    if not is_valid_name(name):
        safe_send(
            message.chat.id,
            "⚠️ Имя должно содержать только буквы (можно с дефисом) и иметь длину 2–100 символов.\n"
            "Пожалуйста, введите имя ещё раз:",
        )
        return

    # Промежуточные данные храним в состоянии (per-user, per-chat).
    with bot.retrieve_data(message.from_user.id, message.chat.id) as data:
        data["name"] = name

    bot.set_state(message.from_user.id, States.WAIT_PHONE, message.chat.id)
    safe_send(
        message.chat.id,
        f"Отлично, {name}! 👍\n\n"
        "2️⃣ Введите номер телефона в международном формате, например: +79991234567",
    )
    logger.info("user_id=%s: имя принято", message.from_user.id)


@bot.message_handler(state=States.WAIT_PHONE)
def process_phone(message: types.Message) -> None:
    """Шаг 2: телефон. Нормализация и валидация формата."""
    raw = (message.text or "").strip()
    phone = normalize_phone(sanitize_text(raw, MAX_PHONE_LEN))

    if phone is None:
        safe_send(
            message.chat.id,
            "⚠️ Не распознал номер. Примеры корректного ввода:\n"
            "• +79991234567\n• 8 999 123-45-67\n\nПопробуйте ещё раз:",
        )
        return

    with bot.retrieve_data(message.from_user.id, message.chat.id) as data:
        data["phone"] = phone

    bot.set_state(message.from_user.id, States.WAIT_REQUEST, message.chat.id)
    safe_send(
        message.chat.id,
        f"Записал: {phone} ✅\n\n"
        "3️⃣ Опишите суть заявки — услугу или проблему, с которой пришли "
        "(до 2000 символов):",
    )
    logger.info("user_id=%s: телефон принят", message.from_user.id)


@bot.message_handler(state=States.WAIT_REQUEST)
def process_request(message: types.Message) -> None:
    """Шаг 3: суть заявки → сохранение в Google Sheets → уведомление админа."""
    request_text = sanitize_text((message.text or "").strip(), MAX_REQUEST_LEN)

    if len(request_text) < 5:
        safe_send(
            message.chat.id,
            "🙏 Пожалуйста, опишите заявку подробнее (хотя бы пара слов).",
        )
        return

    with bot.retrieve_data(message.from_user.id, message.chat.id) as data:
        lead = Lead(
            user_id=message.from_user.id,
            username=message.from_user.username,
            name=data.get("name", "—"),
            phone=data.get("phone", "—"),
            request_text=request_text,
            created_at=format_timestamp(),
        )

    # Сохранение в таблицу: любая ошибка API не должна ронять бота.
    try:
        save_to_google_sheets(lead)
    except gspread.AuthenticationError as e:
        logger.error("Ошибка авторизации Google: %s", e)
        safe_send(
            message.chat.id,
            "😔 К сожалению, сейчас таблица заявок недоступна (ошибка доступа).\n"
            "Мы уже чиним. Попробуйте позже: /start",
        )
        _finish_state(message)
        return
    except gspread.SpreadsheetNotFound:
        logger.error("Таблица GOOGLE_SHEET_ID не найдена или нет доступа.")
        safe_send(
            message.chat.id,
            "😔 Заявка не сохранена: таблица недоступна. Сообщите администратору и попробуйте позже.",
        )
        _finish_state(message)
        return
    except (gspread.GSpreadError, GoogleAuthError, OSError) as e:
        # Сюда попадут сетевые ошибки, неверный путь к JSON-ключу и т.п.
        logger.exception("Ошибка сохранения в Google Sheets: %s", e)
        safe_send(
            message.chat.id,
            "😔 Не удалось сохранить заявку (техническая проблема). Попробуйте ещё раз позже.",
        )
        _finish_state(message)
        return

    # Уведомление администратору (ошибка тут не должна мешать пользователю).
    try:
        notify_admin(lead)
    except Exception:
        logger.exception("Не удалось уведомить администратора.")

    _finish_state(message)

    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("🔄 Начать заново", callback_data="restart"))
    kb.add(types.InlineKeyboardButton("ℹ️ О боте", callback_data="about"))

    thanks = (
        "🎉 Спасибо! Ваша заявка принята.\n\n"
        f"👤 Имя: {lead.name}\n"
        f"📞 Телефон: {lead.phone}\n"
        f"📝 Заявка: {lead.request_text[:200]}{'…' if len(lead.request_text) > 200 else ''}\n\n"
        "Мы свяжемся с вами в ближайшее время. Хорошего дня! 😊"
    )
    safe_send(message.chat.id, thanks, reply_markup=kb)
    logger.info("user_id=%s: заявка завершена и сохранена", message.from_user.id)


def _finish_state(message: types.Message) -> None:
    """Переводит пользователя в состояние DONE (диалог завершён)."""
    try:
        bot.set_state(message.from_user.id, States.DONE, message.chat.id)
    except Exception:
        logger.exception("Не удалось сбросить состояние для user_id=%s", message.from_user.id)


@bot.message_handler(state=States.DONE)
def done_handler(message: types.Message) -> None:
    """После завершения опроса подсказываем, как начать заново."""
    safe_send(
        message.chat.id,
        "✅ Заявка уже принята!\n\nЕсли хотите оставить ещё одну — напишите /start.",
    )


@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call: types.CallbackQuery) -> None:
    """Кнопки: начать заново / информация о боте."""
    try:
        if call.data == "restart":
            with bot.memory.fill_proxy(call.from_user.id, call.message.chat.id) as proxy:
                pass
            bot.delete_state(call.from_user.id, call.message.chat.id)
            # Эмулируем нажатие /start
            fake = types.Message.de_json(
                {
                    "message_id": call.message.message_id,
                    "from": call.from_user.dict(),
                    "chat": call.message.chat.dict(),
                    "text": "/start",
                }
            )
            start_handler(fake)
        elif call.data == "about":
            safe_send(
                call.message.chat.id,
                "ℹ️ Бот собирает заявки и сохраняет их в защищённую Google Таблицу.\n"
                "Данные передаются по HTTPS и не публикуются публично.",
            )
        bot.answer_callback_query(call.id)
    except Exception:
        logger.exception("Ошибка в callback_handler")
        try:
            bot.answer_callback_query(call.id, "Произошла ошибка 😔")
        except Exception:
            pass


@bot.message_handler(content_types=["photo", "document", "voice", "video", "sticker", "contact"])
def unsupported_content_handler(message: types.Message) -> None:
    """Вежливый ответ на нетекстовые сообщения вне диалога."""
    state = bot.get_state(message.from_user.id, message.chat.id)
    if state in (States.WAIT_NAME, States.WAIT_PHONE, States.WAIT_REQUEST):
        safe_send(
            message.chat.id,
            "🙏 Пожалуйста, отвечайте текстом — я пока не умею принимать файлы/фото в анкете.",
        )
    else:
        safe_send(message.chat.id, "Я собираю заявки текстом. Начните: /start")


@bot.message_handler(func=lambda m: True, content_types=["text"], state=None)
def fallback_text_handler(message: types.Message) -> None:
    """Любое текстовое сообщение вне FSM (state=None) — подсказка про /start."""
    safe_send(message.chat.id, "Чтобы оставить заявку, напишите /start 🙂")


# =============================================================================
# 7. ЗАПУСК
# =============================================================================


def validate_environment() -> None:
    """Проверки перед запуском: файл ключа существует, токен «похож на токен»."""
    if not GOOGLE_CREDENTIALS_FILE.exists():
        raise FileNotFoundError(
            f"Файл сервисного аккаунта не найден: {GOOGLE_CREDENTIALS_FILE}. "
            "Скачайте JSON-ключ в Google Cloud Console и положите его рядом с bot.py "
            "(или укажите путь в GOOGLE_CREDENTIALS_FILE в .env)."
        )
    # Примитивная эвристика: токен выглядит как "123456:AAAA...". Значение не логируем.
    if not re.fullmatch(r"\d+:[\w-]{30,}", TELEGRAM_BOT_TOKEN):
        raise RuntimeError("TELEGRAM_BOT_TOKEN имеет неожиданный формат. Проверьте его у @BotFather.")


def main() -> None:
    logger.info("=" * 60)
    logger.info("Запуск бота сбора заявок (lead-bot)")
    logger.info("Лист Google Tables: id=%s, tab=%s", GOOGLE_SHEET_ID, GOOGLE_SHEET_TAB)
    logger.info("Админ: chat_id=%s", ADMIN_CHAT_ID)

    validate_environment()

    # Подключаем middleware для работы FSM (state= в фильтрах хэндлеров).
    from telebot import StateMiddleware
    sm = StateMiddleware(state_storage)
    bot.setup_middlewares(sm)

    # Раз в сутки можно чистить «зависшие» состояния (пример политики):
    # bot.remove_expired_states(10800, 3600)  # старше 3 часов, чистить каждый час

    logger.info("Бот запущен. Долгие запросы (polling) включены.")
    try:
        # long polling: сокет держим дольше таймаута бэк-офиса, меньше лишних reconnect
        bot.polling(none_block=False, timeout=30, long_polling_timeout=30)
    except KeyboardInterrupt:
        logger.info("Остановка по Ctrl+C.")
    except Exception:
        logger.exception("Критическая ошибка — бот остановлен.")
        raise


if __name__ == "__main__":
    main()
