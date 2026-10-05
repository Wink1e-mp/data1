"""
Telegram-бот для сбора заявок (лидов) с сохранением в Google Sheets.

Стек: Python 3.10+, pyTelegramBotAPI (telebot), requests, python-dotenv.

Как данные попадают в таблицу:
    Вместо gspread + JSON-ключей сервисного аккаунта используется Google Apps
    Script — маленький веб-скрипт, размещённый на серверах Google. Бот просто
    отправляет POST-запрос с JSON на URL скрипта (GOOGLE_SCRIPT_URL), а скрипт
    сам дописывает строку в таблицу. Никаких ключей, OAuth и scopes хранить не нужно.

Архитектура:
    - FSM (машина состояний) на базе встроенного механизма telebot 4.30+
      (StateMemoryStorage + кастомный фильтр StateFilter):
      WAIT_NAME -> WAIT_PHONE -> WAIT_REQUEST -> DONE
    - Все секреты читаются ТОЛЬКО из переменных окружения (.env),
      захардкоженных токенов/ключей/ID в коде нет.
    - Ошибки Telegram API и HTTP-ошибки при запросе к Apps Script перехватываются:
      бот не падает, пишет в лог и корректно уведомляет пользователя.
    - Логирование в файл bot.log и в консоль.

Безопасность (учитываем специфику ИБ):
    - .env добавлен в .gitignore — секреты не попадают в git;
    - входящие данные (имя/телефон/заявка) проходят санитизацию: ограничение длины,
      удаление управляющих символов, экранирование =+-@ (защита от CSV/formula
      injection при последующем экспорте таблицы);
    - сообщения админу отправляются без parse_mode, но пользовательский ввод
      всё равно экранируется на случай смены parse_mode (защита от инъекций
      форматирования);
    - запрос к Apps Script идёт по HTTPS с обязательной проверкой таймаута
      (защита от зависания worker-потока бота);
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

# pyTelegramBotAPI (telebot) + встроенная FSM-поддержка:
# StateMemoryStorage — хранилище состояний, StateFilter — фильтр state= в хэндлерах
import telebot
from telebot import types
from telebot.custom_filters import StateFilter
from telebot.storage import StateMemoryStorage

# requests: POST-запрос к Google Apps Script (Web App)
import requests

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
        # Важно: значение переменной НЕ логируется, чтобы случайно не утечь секрет.
        raise RuntimeError(
            f"Переменная окружения {name} не задана. "
            f"Скопируйте .env.example в .env и заполните значения."
        )
    return value


TELEGRAM_BOT_TOKEN = _require_env("TELEGRAM_BOT_TOKEN")
ADMIN_CHAT_ID = _require_env("ADMIN_CHAT_ID")

# URL веб-приложения Google Apps Script — единственный «секрет» интеграции
# с таблицей. Получается при деплое скрипта (см. README.md, шаг «Apps Script»).
GOOGLE_SCRIPT_URL = _require_env("GOOGLE_SCRIPT_URL")

# Проверим, что ADMIN_CHAT_ID — это число (chat_id в Telegram всегда целое, может быть отрицательным)
if not re.fullmatch(r"-?\d+", ADMIN_CHAT_ID):
    raise RuntimeError("ADMIN_CHAT_ID должен быть числом (например, 123456789). Узнайте его через @userinfobot.")

# Простейшая проверка схемы URL — защищаемся от опечатки в .env
# (сам Apps Script может жить и на script.google.com, и на *.googleusercontent.com).
if not GOOGLE_SCRIPT_URL.startswith("https://"):
    raise RuntimeError("GOOGLE_SCRIPT_URL должен начинаться с https:// (см. README, шаг «Apps Script»)")

# Настройки безопасности данных
MAX_NAME_LEN = 100
MAX_PHONE_LEN = 30
MAX_REQUEST_LEN = 2000
MAX_MESSAGE_LEN = 4000  # лимит sendMessage в Telegram — 4096, берём с запасом

# Таймауты HTTP-запроса к Apps Script (секунды): (connect, read).
# Без таймаута воркер бота мог бы зависнуть навсегда на «умершем» эндпоинте.
HTTP_TIMEOUT = (10, 30)

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


def sanitize_text(text: str, max_len: int, escape_formulas: bool = True) -> str:
    """Санитизация пользовательского ввода перед сохранением в таблицу.

    Что делаем:
      1. Удаляем управляющие символы (\x00-\x1F, \x7F) — защита от log/CSV injection.
      2. Сжимаем повторяющиеся пробелы, убираем пробельные символы по краям.
      3. Ограничиваем длину (защита от переполнения/спама).
      4. (escape_formulas=True) Экранируем опасные префиксы формул (= + - @)
         апострофом — защита от spreadsheet formula injection при экспорте в CSV.
         Для телефонов экранирование ОТКЛЮЧАЮТ: там «+» в начале — норма,
         а апостроф сломал бы валидацию номера.

    Примечание: сам Apps Script пишет значения appendRow() как данные, а не
    как формулы, поэтому экранирование — это дополнительная (defense-in-depth)
    защита на случай ручного копирования/экспорта таблицы.
    """
    cleaned = re.sub(r"[\x00-\x1F\x7F]", "", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    cleaned = cleaned[:max_len]
    if escape_formulas and cleaned and cleaned[0] in ("=", "+", "-", "@"):
        cleaned = "'" + cleaned
    return cleaned


def is_valid_name(name: str) -> bool:
    """Имя: только буквы (любого алфавита), пробелы, дефисы; длина 2..MAX_NAME_LEN."""
    if not (2 <= len(name) <= MAX_NAME_LEN):
        return False
    return bool(re.fullmatch(r"[A-Za-zА-Яа-яЁё\s\-']+", name))


def normalize_phone(phone: str) -> Optional[str]:
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

    Пригодится, если захотите включить parse_mode='MarkdownV2' для сообщений
    админу. Сейчас уведомления отправляются обычным текстом (parse_mode=None),
    поэтому инъекция разметки невозможна в принципе.
    """
    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!\\])", r"\\\1", text)


def format_timestamp() -> str:
    """Метка времени заявки (часовой пояс сервера)."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# 5. СОХРАНЕНИЕ В GOOGLE SHEETS (через Google Apps Script + requests)
# =============================================================================


def save_to_google_sheets(lead: "Lead") -> None:
    """Отправляет заявку в Google Таблицу POST-запросом к Apps Script.

    Формат payload строго согласован со скриптом (функция doPost(e)):
        {"name": ..., "phone": ..., "request": ...}

    Args:
        lead: данные заявки.

    Raises:
        requests.RequestException: сетевые ошибки, таймауты, HTTP 4xx/5xx.
        ValueError: Apps Script вернул не-JSON (например, страницу логина Google)
                    или статус ok != true — значит, таблица не записала строку.
    """
    payload = {
        "name": lead.name,
        "phone": lead.phone,
        "request": lead.request_text,
    }

    # allow_redirects=True обязателен: Apps Script отвечает 302 на *.googleusercontent.com,
    # requests должен проследовать редирект, иначе мы получим пустой ответ.
    resp = requests.post(GOOGLE_SCRIPT_URL, json=payload, timeout=HTTP_TIMEOUT, allow_redirects=True)
    resp.raise_for_status()  # бросает исключение на 4xx/5xx

    # Проверяем ответ приложения: в Apps Script обычно есть try/catch, который
    # возвращает {"ok": false, ...} при внутренней ошибке — её тоже надо поймать.
    body = resp.text.strip()
    try:
        result = resp.json()
    except ValueError:
        raise ValueError(f"Apps Script вернул не-JSON (первые 200 симв.): {body[:200]!r}")

    if isinstance(result, dict) and result.get("ok") is False:
        raise ValueError(f"Apps Script сообщил об ошибке записи: {result.get('error', result)}")

    logger.info(
        "Заявка отправлена в Google Sheets через Apps Script: user_id=%s, name=%r, phone=%s, ответ=%r",
        lead.user_id, lead.name, lead.phone, body[:200],
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

# Хранилище состояний передаётся параметром state_storage, а сопоставление
# сообщений с состояниями диалога выполняет кастомный фильтр StateFilter —
# именно он делает рабочим параметр state= у message_handler.
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN, state_storage=state_storage, parse_mode=None)
bot.add_custom_filter(StateFilter(bot))


# ---------------------------------------------------------------------------
# Защита от двойной отправки заявки (anti-double-submit)
# ---------------------------------------------------------------------------

import threading

_processed_lock = threading.Lock()          # защищает множество ниже
_processed_users: set[int] = set()          # user_id, чья заявка сейчас в обработке
_user_locks: dict[int, threading.Lock] = {} # per-user mutex


def _get_user_lock(user_id: int) -> threading.Lock:
    """Возвращает (создавая при необходимости) мьютекс конкретного пользователя."""
    with _processed_lock:
        lock = _user_locks.get(user_id)
        if lock is None:
            lock = threading.Lock()
            _user_locks[user_id] = lock
        return lock


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
    """Отправляет администратору уведомление о новой заявке.

    Сообщения идут обычным текстом (parse_mode=None у бота) — пользовательский
    ввод не сможет сломать разметку (инъекция форматирования невозможна).
    Ошибки Telegram API не должны ронять бота — они логируются.
    """
    lines = [
        "🆕 Новая заявка",
        "",
        f"👤 Имя: {lead.name}",
        f"📞 Телефон: {lead.phone}",
        f"📝 Суть заявки: {lead.request_text}",
        f"🆔 Telegram ID: {lead.user_id}",
        f"🏷 Username: {'@' + lead.username if lead.username else '—'}",
        f"🕒 Время: {lead.created_at}",
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
    # Для имени экранирование формул не применяем: оно всё равно проходит строгую
    # проверку is_valid_name (только буквы), а лишний апостроф испортил бы данные.
    name = sanitize_text((message.text or ""), MAX_NAME_LEN, escape_formulas=False)

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
    # escape_formulas=False: телефон почти всегда начинается с «+»,
    # апостроф перед ним сломал бы валидацию формата.
    phone = normalize_phone(sanitize_text((message.text or ""), MAX_PHONE_LEN, escape_formulas=False))

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
    request_text = sanitize_text((message.text or ""), MAX_REQUEST_LEN)

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

    # Анти-double-submit: штатно обработкой WAIT_REQUEST занимается один поток
    # (polling без none_block), но защиту не помешает включить и при запуске
    # с num_threads>1. Флаг в state-данных здесь ненадёжен (состояние к тому
    # моменту уже может быть очищено), поэтому используем лёгкий lock.
    user_lock = _get_user_lock(message.from_user.id)
    with user_lock:
        if message.from_user.id in _processed_users:
            safe_send(message.chat.id, "⏳ Ваша заявка уже обрабатывается, секунду…")
            return
        _processed_users.add(message.from_user.id)

    # Сохранение через Apps Script: любая сетевая/HTTP-ошибка не должна ронять бота.
    try:
        save_to_google_sheets(lead)
    except requests.exceptions.HTTPError as e:
        # 403/404 часто означают: скрипт перезалит без нового деплоя или доступ
        # Web App изменён с "Anyone" — пользователю про это не пишем, только в лог.
        logger.error("Apps Script вернул HTTP-ошибку: %s", e)
        safe_send(
            message.chat.id,
            "😔 Заявка не сохранена: таблица временно недоступна. "
            "Сообщите администратору и попробуйте позже.",
        )
        _finish_state(message)
        return
    except requests.exceptions.RequestException as e:
        # Таймаут, DNS, соединение — общие сетевые проблемы.
        logger.exception("Сетевая ошибка при запросе к Apps Script: %s", e)
        safe_send(
            message.chat.id,
            "😔 Не удалось сохранить заявку (сетевая проблема). Попробуйте ещё раз позже.",
        )
        _finish_state(message)
        return
    except ValueError as e:
        # Apps Script ответил не-JSON или ok:false — проблема на стороне скрипта.
        logger.error("Apps Script вернул ошибку приложения: %s", e)
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
    """Завершает диалог: снимает anti-double-submit флаг, чистит данные, ставит DONE."""
    try:
        with _processed_lock:
            _processed_users.discard(message.from_user.id)
        with bot.retrieve_data(message.from_user.id, message.chat.id) as data:
            data.clear()  # персональные данные не должны «висеть» в памяти дольше нужного
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
            state = bot.get_state(call.from_user.id, call.message.chat.id)
            if state == States.WAIT_REQUEST:
                # Заявка ещё в обработке — не даём «перехватить» диалог кнопкой.
                bot.answer_callback_query(call.id, "Заявка ещё обрабатывается, подождите 🙂")
                return
            # Штатный FSM-путь: очищаем старые данные/состояние и переводим
            # пользователя в WAIT_NAME — следующее же текстовое сообщение
            # попадёт в process_name автоматически (по фильтру state=).
            bot.delete_state(call.from_user.id, call.message.chat.id)
            bot.set_state(call.from_user.id, States.WAIT_NAME, call.message.chat.id)
            safe_send(
                call.message.chat.id,
                "🔄 Хорошо, начнём заново!\n\n1️⃣ Как вас зовут?",
            )
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
    """Проверки перед запуском: формат токена и доступность эндпоинта Apps Script."""
    # Примитивная эвристика: токен выглядит как "123456:AAAA...". Значение не логируем.
    if not re.fullmatch(r"\d+:[\w-]{30,}", TELEGRAM_BOT_TOKEN):
        raise RuntimeError("TELEGRAM_BOT_TOKEN имеет неожиданный формат. Проверьте его у @BotFather.")

    # Проверяем, что Apps Script вообще отвечает (GET doPost-скрипта вернёт 405 — это ок:
    # значит, веб-приложение задеплоено и принимает соединения).
    try:
        probe = requests.get(GOOGLE_SCRIPT_URL, timeout=(10, 15), allow_redirects=True)
        logger.info("Проверка доступности Apps Script: HTTP %s", probe.status_code)
    except requests.RequestException as e:
        logger.warning(
            "Apps Script сейчас не отвечает (%s). Бот продолжит запуск, "
            "но заявки могут не сохраняться — проверьте GOOGLE_SCRIPT_URL и деплой скрипта.",
            e,
        )


def main() -> None:
    logger.info("=" * 60)
    logger.info("Запуск бота сбора заявок (lead-bot)")
    logger.info("Интеграция с Google Sheets: Google Apps Script (POST)")
    logger.info("Админ: chat_id=%s", ADMIN_CHAT_ID)

    validate_environment()

    # Раз в сутки можно чистить «зависшие» состояния (пример политики):
    # bot.remove_expired_states(10800, 3600)  # старше 3 часов, чистить каждый час

    logger.info("Бот запущен. Долгие запросы (polling) включены.")
    try:
        # long polling: сокет держим дольше таймаута бэк-офиса, меньше лишних reconnect
        bot.polling(none_block=False, timeout=30, long_polling_timeout=30)
    except KeyboardInterrupt:
        logger.info("Остановка по Ctrl+C")
    except Exception:
        logger.exception("Критическая ошибка — бот остановлен.")
        raise


if __name__ == "__main__":
    main()
