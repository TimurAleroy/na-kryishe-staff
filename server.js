// ─── Токен бота не должен попадать в логи ─────────
// При сетевой ошибке библиотека запросов кладёт в текст ошибки полный адрес, а в адресе Telegram — токен бота.
// Поэтому всё, что пишется в лог, сначала проходит через фильтр: любой токен вида bot123456:AA… заменяется
// на «bot<скрыт>». Работает для всех console.log / console.error во всём сервере и в модулях db/*.
(function hideSecretsInLogs() {
  const util = require('util');
  const TOKEN_RE = /bot\d{5,}:[A-Za-z0-9_-]{20,}/g;
  // плюс точные значения секретов из переменных окружения (и пароль из адреса базы)
  const secrets = ['TELEGRAM_BOT_TOKEN', 'INTERNAL_ADMIN_KEY', 'PIN_SECRET', 'TELEGRAM_WEBHOOK_SECRET', 'NOTION_TOKEN', 'FOUNDER_RECOVERY_PASSWORD']
    .map((k) => process.env[k]).filter((v) => typeof v === 'string' && v.length >= 8);
  try { const p = new URL(process.env.DATABASE_URL || '').password; if (p && p.length >= 6) secrets.push(p, decodeURIComponent(p)); } catch { /* адреса базы нет или он не разобрался */ }
  const hide = (text) => {
    let out = String(text).replace(TOKEN_RE, 'bot<скрыт>');
    for (const sec of secrets) if (out.includes(sec)) out = out.split(sec).join('<скрыто>');
    return out;
  };
  const clean = (v) => {
    try {
      if (typeof v === 'string') return hide(v);
      if (v && typeof v === 'object') return hide(util.inspect(v, { depth: 4, breakLength: 160 }));
    } catch { return '[не удалось показать]'; }
    return v;
  };
  for (const m of ['log', 'info', 'warn', 'error']) {
    const orig = console[m].bind(console);
    console[m] = (...args) => orig(...args.map(clean));
  }
})();

const express = require('express');
const cors = require('cors');
// Любой внешний запрос (Telegram, гостевой сервер, Notion) — не дольше 15 секунд, если не сказано иначе.
// Без этого зависший собеседник держал бы запрос вечно: рассылка навсегда оставалась «Отправляется»,
// а просьбы об отзыве молча переставали уходить до перезапуска.
const nodeFetch = require('node-fetch');
const fetch = (url, opts = {}) => nodeFetch(url, { timeout: 15000, ...opts });
const crypto = require('crypto');
// Данные гостей и броней — в Postgres (общий слой db/store.js, тот же, что у гостевого сервера)
const store = require('./db/store');
// Карточки гостей, теги и визиты — тоже в Postgres (db/cards.js)
const cardsDb = require('./db/cards');
// Отзывы гостей, eNPS и проблемы — в Postgres (db/feedback.js, общий с гостевым сервером)
const feedback = require('./db/feedback');
const employeesDb = require('./db/employees');
const permissionsDb = require('./db/permissions');
const work = require('./db/work');
// Афиша, меню, кандидаты и журнал рассылок — в Postgres (db/catalog.js, общий с гостевым сервером)
const catalog = require('./db/catalog');
const tvDb = require('./db/tv');
const tagsDb = require('./db/tags');
const standardsDb = require('./db/standards');
const checklistsDb = require('./db/checklists');
// Табак: справочник вкусов и учёт граммов (db/tobacco.js, миграции 038–039)
const tobaccoDb = require('./db/tobacco');
// Чаевые гостей сотрудникам (db/tips.js, миграция 042); оплата пока не подключена — всё идёт в тестовом режиме
const tipsDb = require('./db/tips');
const extRevDb = require('./db/extreviews');
// Угли: позиции и учёт в коробках (db/coals.js, миграция 040); право то же, что у табака — tobacco.manage
const coalsDb = require('./db/coals');
const auditDb = require('./db/audit');
const reviewRulesDb = require('./db/review-rules');
const authDb = require('./db/auth');
const mailings = require('./db/mailings');
const surveyForms = require('./db/surveys');
const ops = require('./db/ops'); // проверки устойчивости: версия схемы, размер базы, возраст копии, настройки (аудит 30.10)

const app = express();
app.disable('x-powered-by'); // не сообщаем, на чём работает сервер
app.set('trust proxy', 1); // за прокси хостинга: настоящий адрес посетителя нужен для защиты от подбора пароля
app.use(cors());
app.use(express.json());

// Если внутри обработчика что-то упало (например, база не ответила при проверке входа), запрос раньше оставался
// вообще без ответа и экран в приложении крутился бесконечно. Теперь любой обработчик обёрнут: ошибка уходит
// в общий обработчик в конце файла, и приложение получает понятный ответ.
for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
  const orig = app[method].bind(app);
  app[method] = (path, ...handlers) => {
    if (!handlers.length) return orig(path); // app.get('trust proxy') — чтение настройки, не маршрут
    return orig(path, ...handlers.map((h) => (typeof h !== 'function' || h.length >= 4 ? h : function wrapped(req, res, next) {
      try {
        const out = h(req, res, next);
        if (out && typeof out.catch === 'function') out.catch(next);
      } catch (e) { next(e); }
    })));
  };
}

// Доступ к разделам и действиям решают права сотрудника (can / checkPerm ниже), а не название роли:
// у роли есть набор по умолчанию, основатель может выдать или забрать любое право галочкой.
// isAdminRole остаётся только для подписи («admin» / «staff» при входе), совместимой со старым приложением.
const ADMIN_ROLES = ['Администратор', 'Основатель'];
function isAdminRole(role) {
  return ADMIN_ROLES.includes(role);
}

// Какое право нужно, чтобы снять/вернуть позицию категории со «В наличии» (стоп-лист).
// По умолчанию: бармен — напитки, повар — еда, КМ — кальян, администратор и основатель — всё;
// основатель может выдать это право любому сотруднику галочкой.
const MENU_CATEGORY_PERM = {
  'Напитки': 'menu.stoplist_drinks',
  'Коктейли': 'menu.stoplist_drinks',
  'Алкоголь': 'menu.stoplist_drinks',
  'Еда': 'menu.stoplist_food',
  'Кальян': 'menu.stoplist_hookah'
};
// Кто обычно отвечает за категорию — только для текста сообщения об отказе
const MENU_CATEGORY_EDIT_ROLE = {
  'Напитки': 'Бармен',
  'Коктейли': 'Бармен',
  'Алкоголь': 'Бармен',
  'Еда': 'Повар',
  'Кальян': 'КМ'
};
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID || '188483198';
// Переменная не задана — сообщения администрации (брони с именами, проблемы, итоги вечера) уходят на запасной адрес из кода.
// Сервер при этом работает (иначе из-за забытой переменной встало бы всё заведение), но в «Состоянии системы» строка «Админ-чат» станет красной.
const ADMIN_CHAT_FROM_ENV = !!String(process.env.ADMIN_CHAT_ID || '').trim();
if (!ADMIN_CHAT_FROM_ENV) console.error('ВНИМАНИЕ: не задана переменная ADMIN_CHAT_ID — сообщения администрации уходят на запасной адрес из кода. Задайте её в переменных сервиса.');
const WEBAPP_URL = 'https://timuraleroy.github.io/na-kryishe-staff';
const PORT = process.env.PORT || 3000;

// Сервер работает по UTC, а заведение — по владикавказскому времени (UTC+3, без перевода часов).
// Простое new Date().toISOString() примерно 3 часа в сутки (00:00–03:00 по-местному) даёт "вчера" вместо "сегодня".
// Эти хелперы всегда возвращают дату/время именно по Владикавказу.
const VENUE_TZ = 'Europe/Moscow'; // тот же часовой пояс, что и Владикавказ

function venueDateStr(date = new Date()) {
  // Возвращает "YYYY-MM-DD" по местному времени заведения
  return new Intl.DateTimeFormat('en-CA', { timeZone: VENUE_TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(date);
}
function venueMonthDay(date = new Date()) {
  // "MM-DD" — для сравнения дней рождения
  return venueDateStr(date).slice(5, 10);
}
function venueHour(date = new Date()) {
  // Час по местному времени заведения (0–23)
  return Number(new Intl.DateTimeFormat('en-GB', { timeZone: VENUE_TZ, hour: '2-digit', hour12: false }).format(date)) % 24;
}
function addDaysStr(dateStr, n) {
  const d = new Date(dateStr.slice(0, 10) + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}
// Первое число месяца со сдвигом: addMonthsStr('2026-10-01', -1) → '2026-09-01'
function addMonthsStr(monthStart, n) {
  const y = Number(monthStart.slice(0, 4)), m = Number(monthStart.slice(5, 7)) - 1 + n;
  const yy = y + Math.floor(m / 12), mm = ((m % 12) + 12) % 12;
  return `${yy}-${String(mm + 1).padStart(2, '0')}-01`;
}
// Часы, в которые можно писать гостям, из переменной вида "12-22" (с 12:00 до 22:00)
function hoursWindow(envValue, defFrom, defTo) {
  const m = String(envValue || '').match(/^(\d{1,2})-(\d{1,2})$/);
  return m ? { from: Number(m[1]), to: Number(m[2]) } : { from: defFrom, to: defTo };
}
function inHoursWindow(win, date = new Date()) {
  const h = venueHour(date);
  return h >= win.from && h < win.to;
}
// «День заведения»: вечер продолжается после полуночи (закрытие в 01:00), поэтому
// всё, что было до 06:00, относится к вечеру предыдущего дня — так же считает приложение
// (DAY_SPLIT_HOUR в na-kryishe-staff). Иначе гость, пришедший в 21:00, и кальян,
// записанный в 00:40, стали бы двумя визитами.
const DAY_SPLIT_HOUR = 6;
function venueDayStr(date = new Date()) {
  return venueDateStr(new Date(date.getTime() - DAY_SPLIT_HOUR * 60 * 60 * 1000));
}
// Текущее местное время заведения как 'YYYY-MM-DDTHH:MM' — сравнивать с временем брони
function venueNowIso(date = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: VENUE_TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
    .formatToParts(date).map(p => [p.type, p.value]));
  return `${parts.year}-${parts.month}-${parts.day}T${String(Number(parts.hour) % 24).padStart(2, '0')}:${parts.minute}`;
}
// День заведения для брони: бронь на 00:30 — это вечер предыдущего дня.
// Время 00:00 — «без времени» (мероприятия), дату не сдвигаем.
function bookingVenueDay(iso) {
  const day = String(iso || '').slice(0, 10);
  const m = /T(\d{2}):(\d{2})/.exec(String(iso || ''));
  if (!m || (m[1] === '00' && m[2] === '00')) return day;
  return Number(m[1]) < DAY_SPLIT_HOUR ? addDaysStr(day, -1) : day;
}

function venueTimeStr(date = new Date()) {
  // Человекочитаемое время для сообщений в Telegram
  return date.toLocaleString('ru-RU', { timeZone: VENUE_TZ, hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'long' });
}

// Приводим номер к единому виду для сравнения — только цифры, с ведущим +7
function normalizePhone(raw) {
  if (!raw) return '';
  let digits = raw.replace(/[^\d+]/g, '');
  digits = digits.replace(/^8/, '+7');
  if (digits.startsWith('7') && !digits.startsWith('+7')) digits = '+' + digits;
  if (!digits.startsWith('+')) digits = '+7' + digits.replace(/^\+?7?/, '');
  return digits;
}

// Короткий кэш в памяти для тяжёлых выборок (статистика, все гости).
// Одновременные запросы с одним ключом ждут одну и ту же загрузку, а не дёргают Notion дважды.
const memoCache = new Map();
// Поколение ключа: если данные сбросили (forgetMemo), пока шла загрузка, — её результат
// уже устарел и в кэш не кладём (иначе, например, только что созданная карточка
// «пропала» бы на 2 минуты и проверка дублей её не увидела).
const memoGen = new Map();
async function memo(key, ttlMs, loader) {
  const entry = memoCache.get(key);
  if (entry && entry.pending) return entry.pending;
  if (entry && Date.now() - entry.at < ttlMs) return entry.value;
  const gen = memoGen.get(key) || 0;
  const pending = loader()
    .then(value => {
      if ((memoGen.get(key) || 0) === gen) memoCache.set(key, { value, at: Date.now() });
      return value;
    })
    .catch(err => {
      if ((memoGen.get(key) || 0) === gen) memoCache.delete(key);
      throw err;
    });
  memoCache.set(key, { ...(entry || {}), pending });
  return pending;
}
function forgetMemo(prefix) {
  for (const key of [...memoCache.keys(), ...memoGen.keys()]) {
    if (!key.startsWith(prefix)) continue;
    memoCache.delete(key);
    memoGen.set(key, (memoGen.get(key) || 0) + 1);
  }
}

// Запись в журнал действий от имени сотрудника запроса. Журнал не должен ломать само действие,
// поэтому ждать его не нужно и ошибки наружу не идут (см. db/audit.js).
function auditNote(req, action, type, id, summary, details) {
  return auditDb.record({ actor: req.employee, action, type, id, summary, details });
}
// «Имя Фамилия» гостя по телефону — для строк журнала про брони; нет карточки — сам номер
async function guestLabelByPhone(phone) {
  const p = normalizePhone(typeof phone === 'string' ? phone : '');
  if (!p) return 'без номера';
  if (p === store.WALKIN_PHONE) return 'гость без брони';
  try {
    const r = await store.db.query('SELECT first_name, last_name FROM guests WHERE phone = $1 AND archived_at IS NULL ORDER BY created_at LIMIT 1', [p]);
    const name = r.rows[0] ? `${r.rows[0].first_name || ''} ${r.rows[0].last_name || ''}`.trim() : '';
    return name ? `${name} (${p})` : p;
  } catch { return p; }
}
function employeeNameById(id) {
  const e = employeesCache.find(x => x.id === id);
  return e ? e.name : 'сотрудник';
}
function ruShortDate(iso) {
  const m = String(iso || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
  return m ? `${m[3]}.${m[2]}` : String(iso || '');
}

// ─── ВИЗИТЫ ─────────────────────────────────────────
// Визиты лежат в Postgres (таблица visits). Функции отдают записи в прежнем виде:
// { id, guestId, date: 'ГГГГ-ММ-ДД', hookah: 'Мята + Персик', createdAt, reviewRequest }
// — по ним считаются сегменты, аналитика, просьбы об отзыве.
async function getAllVisits() {
  return cardsDb.allVisits();
}

// Для экранов, где визиты нужны только для сегмента (брони, именинники): ошибка базы
// не должна ломать весь экран — тогда просто пустой список.
async function getVisitsQuick() {
  return cardsDb.allVisits().catch(e => { console.error('Visits load failed:', e.message); return []; });
}

function daysSinceDate(dateStr) {
  if (!dateStr) return null;
  const today = new Date(venueDateStr() + 'T00:00:00Z');
  const then = new Date(dateStr.slice(0, 10) + 'T00:00:00Z');
  return Math.round((today - then) / (1000 * 60 * 60 * 24));
}

// ── Автотеги: «Время визита», «Продолжительность», «Риск оттока», «Негативный отзыв», «ДР», «Любимая позиция» ──
// Считаются без кассы: по отметкам «пришёл» / «ушёл» в бронях, визитам и отзывам. Настройки (пороги, часы окон, названия, цвета,
// подсказки, кому показывать) лежат в settings → autotags.config и правятся в приложении: «Сервис» → «Автотеги» (только основатель).
// Значения ниже — по умолчанию: ровно те, что стояли в коде до появления экрана.
const AUTOTAG_KEY = 'autotags.config';
const AUTOTAG_COLORS = ['red', 'amber', 'green', 'blue', 'purple', 'pink', 'gray'];
const AUTOTAG_DEFAULTS = Object.freeze({
  atRisk: { enabled: true, variants: { main: { name: 'Риск оттока', color: '', hint: '' } } },
  negativeReview: { enabled: true, variants: { main: { name: 'Негативный отзыв', color: '', hint: '' } } },
  birthday: { enabled: true, windowDays: 7, variants: {
    soon: { name: 'Скоро день рождения', color: '', hint: '' },
    recent: { name: 'Недавно был день рождения', color: '', hint: '' } } },
  visitTime: { enabled: true, minVisits: 2, minShare: 60, hours: { morning: 6, day: 12, evening: 18, night: 23 }, variants: {
    morning: { name: 'Время визита: утро', color: '', hint: '' },
    day: { name: 'Время визита: день', color: '', hint: '' },
    evening: { name: 'Время визита: вечер', color: '', hint: '' },
    night: { name: 'Время визита: ночь', color: '', hint: '' } } },
  stay: { enabled: true, minVisits: 2, quickMax: 90, longMin: 180, variants: {
    quick: { name: 'Заходит ненадолго', color: '', hint: '' },
    long: { name: 'Сидит долго', color: '', hint: '' } } },
  favorite: { enabled: true, minCount: 1, variants: { main: { name: 'Любимая позиция', color: '', hint: '' } } }
});
const AUTOTAG_TITLES = { atRisk: 'Риск оттока', negativeReview: 'Негативный отзыв', birthday: 'День рождения', visitTime: 'Время визита', stay: 'Продолжительность визита', favorite: 'Любимая позиция' };
const AUTOTAG_LIMITS = {
  birthday: { windowDays: { min: 1, max: 30 } },
  visitTime: { minVisits: { min: 1, max: 10 }, minShare: { min: 50, max: 95 }, hour: { min: 0, max: 23 } },
  stay: { minVisits: { min: 1, max: 10 }, quickMax: { min: 15, max: 240 }, longMin: { min: 60, max: 720 } },
  favorite: { minCount: { min: 1, max: 10 } },
  nameLen: 40, hintLen: 160
};
const autotagClone = (o) => JSON.parse(JSON.stringify(o));
let AUTOTAGS = autotagClone(AUTOTAG_DEFAULTS);
let autotagMeta = { updatedAt: null, updatedBy: '' };
// Проверка набора настроек: то, чего в запросе нет, берётся по умолчанию. Возвращает { config } или { error } — текст для человека.
function cleanAutotagConfig(input) {
  const inp = input && typeof input === 'object' ? input : {};
  const out = autotagClone(AUTOTAG_DEFAULTS);
  const L = AUTOTAG_LIMITS;
  const int = (v, lim, label) => {
    if (typeof v !== 'number' || !Number.isInteger(v)) return { error: `${label}: нужно целое число` };
    if (v < lim.min || v > lim.max) return { error: `${label}: от ${lim.min} до ${lim.max}` };
    return { v };
  };
  for (const k of Object.keys(AUTOTAG_DEFAULTS)) {
    const src = inp[k];
    if (src === undefined) continue;
    const title = AUTOTAG_TITLES[k];
    if (!src || typeof src !== 'object') return { error: `${title}: неверные данные` };
    const dst = out[k];
    // старое приложение могло прислать ещё и waiter («не показывать официантам») — этот выключатель убрали, тег видят все сотрудники; поле молча игнорируется
    if (src.enabled !== undefined) {
      if (typeof src.enabled !== 'boolean') return { error: `${title}: неверное значение переключателя` };
      dst.enabled = src.enabled;
    }
    const nums = {
      birthday: [['windowDays', L.birthday.windowDays, 'ДР: за сколько дней']],
      visitTime: [['minVisits', L.visitTime.minVisits, 'Время визита: минимум вечеров'], ['minShare', L.visitTime.minShare, 'Время визита: доля вечеров в одном окне']],
      stay: [['minVisits', L.stay.minVisits, 'Продолжительность: минимум вечеров'], ['quickMax', L.stay.quickMax, '«Быстро» — до'], ['longMin', L.stay.longMin, '«Долго» — от']],
      favorite: [['minCount', L.favorite.minCount, 'Любимая позиция: минимум раз']]
    }[k] || [];
    for (const [f, lim, label] of nums) {
      if (src[f] === undefined) continue;
      const c = int(src[f], lim, label);
      if (c.error) return c;
      dst[f] = c.v;
    }
    if (k === 'visitTime' && src.hours !== undefined) {
      if (!src.hours || typeof src.hours !== 'object') return { error: 'Время визита: неверные часы' };
      for (const h of ['morning', 'day', 'evening', 'night']) {
        if (src.hours[h] === undefined) continue;
        const c = int(src.hours[h], L.visitTime.hour, 'Время визита: час');
        if (c.error) return c;
        dst.hours[h] = c.v;
      }
    }
    if (src.variants !== undefined) {
      if (!src.variants || typeof src.variants !== 'object') return { error: `${title}: неверные варианты` };
      for (const vk of Object.keys(dst.variants)) {
        const sv = src.variants[vk];
        if (sv === undefined) continue;
        if (!sv || typeof sv !== 'object') return { error: `${title}: неверный вариант` };
        if (sv.name !== undefined) {
          const name = String(sv.name).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
          if (!name) return { error: `${title}: название не может быть пустым` };
          if (name.length > L.nameLen) return { error: `${title}: название длиннее ${L.nameLen} знаков` };
          dst.variants[vk].name = name;
        }
        if (sv.color !== undefined) {
          if (sv.color !== '' && !AUTOTAG_COLORS.includes(sv.color)) return { error: `${title}: неизвестный цвет` };
          dst.variants[vk].color = sv.color;
        }
        if (sv.hint !== undefined) {
          const hint = String(sv.hint).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
          if (hint.length > L.hintLen) return { error: `${title}: подсказка длиннее ${L.hintLen} знаков` };
          dst.variants[vk].hint = hint;
        }
      }
    }
  }
  const h = out.visitTime.hours;
  if (!(h.morning < h.day && h.day < h.evening && h.evening < h.night)) return { error: 'Время визита: часы окон должны идти по возрастанию — утро, день, вечер, ночь' };
  if (out.stay.quickMax >= out.stay.longMin) return { error: 'Продолжительность: «Долго» должно начинаться позже, чем кончается «Быстро»' };
  return { config: out };
}
// Окна «Время визита» из часов: ночь переходит через полночь (с «ночь» до «утро»)
function visitWindows(vt) {
  const h = vt.hours;
  return [
    { key: 'morning', name: 'Утро', from: h.morning, to: h.day },
    { key: 'day', name: 'День', from: h.day, to: h.evening },
    { key: 'evening', name: 'Вечер', from: h.evening, to: h.night },
    { key: 'night', name: 'Ночь', from: h.night, to: h.morning }
  ];
}
function hourInWindow(h, w) { return w.from < w.to ? h >= w.from && h < w.to : (h >= w.from || h < w.to); }
const pad2 = (n) => String(n).padStart(2, '0');
function visitTimeTag(arrivals, cfg = AUTOTAGS.visitTime) {
  const hs = (arrivals || []).map(a => a.h).filter(h => Number.isInteger(h));
  if (hs.length < cfg.minVisits) return null;
  let best = null;
  for (const w of visitWindows(cfg)) {
    const n = hs.filter(h => hourInWindow(h, w)).length;
    if (!best || n > best.n) best = { w, n };
  }
  if (!best || best.n / hs.length < cfg.minShare / 100) return null;
  return { key: best.w.key, name: best.w.name, n: best.n, total: hs.length, range: `${pad2(best.w.from)}:00–${pad2(best.w.to)}:00` };
}
function stayTag(arrivals, cfg = AUTOTAGS.stay) {
  const ms = (arrivals || []).map(a => a.mins).filter(m => Number.isFinite(m) && m >= STAY_MIN_MINUTES && m <= STAY_MAX_MINUTES);
  const series = ms.slice(-12);   // минуты за столом по последним вечерам — для графика в карточке
  if (ms.length < cfg.minVisits) return { tag: null, avgMin: ms.length ? Math.round(ms.reduce((a, b) => a + b, 0) / ms.length) : null, n: ms.length, series };
  const avg = Math.round(ms.reduce((a, b) => a + b, 0) / ms.length);
  const key = avg >= cfg.longMin ? 'long' : avg < cfg.quickMax ? 'quick' : null;
  return { tag: key ? { key, name: key === 'long' ? 'Долго' : 'Быстро', avgMin: avg, n: ms.length } : null, avgMin: avg, n: ms.length, series };
}
// Что из автотегов показывать сотрудникам: выключенные уходят в hidden; cfg — названия, цвета, подсказки вариантов. Все роли видят одно и то же.
function autotagView(employee) {
  const hidden = [], cfg = {};
  for (const k of Object.keys(AUTOTAGS)) {
    const c = AUTOTAGS[k];
    if (!c.enabled) hidden.push(k);
    cfg[k] = c.variants;
  }
  return { hidden, cfg };
}
async function loadAutotags() {
  try {
    const r = await store.db.query('SELECT value FROM settings WHERE key = $1', [AUTOTAG_KEY]);
    const v = r.rows[0] && r.rows[0].value;
    const chk = v && v.config ? cleanAutotagConfig(v.config) : null;
    AUTOTAGS = chk && chk.config ? chk.config : autotagClone(AUTOTAG_DEFAULTS);
    autotagMeta = { updatedAt: (v && v.updatedAt) || null, updatedBy: (v && v.updatedBy) || '' };
  } catch (e) {
    console.error('Настройки автотегов не прочитались, работаем по прежним:', e && e.message ? e.message : e);
  }
}
setTimeout(loadAutotags, 0);
setInterval(loadAutotags, 60 * 1000).unref();

// Возраст гостя на сегодня: по настоящему году рождения (пусто — год не знаем, возраста нет). Родившийся 29 февраля «взрослеет» 1 марта.
function guestAge(birthYear, birthdayStr, today = venueDateStr()) {
  const y = Number(birthYear);
  if (!y || !birthdayStr) return null;
  let age = Number(today.slice(0, 4)) - y;
  if (today.slice(5, 10) < String(birthdayStr).slice(5, 10)) age--;
  return age >= 0 && age < 120 ? age : null;
}

// Автотег «ДР»: сегодня / скоро (в ближайшие N дней) / был недавно (последние N дней); N — в настройках автотегов, по умолчанию 7.
// Считается по местной дате заведения. Родившихся 29 февраля в невисокосный год
// поздравляем 1 марта.
function birthdayInfo(birthdayStr, todayStr = venueDateStr(), windowDays = AUTOTAGS.birthday.windowDays) {
  if (!birthdayStr) return null;
  const mmdd = birthdayStr.slice(5, 10);
  const today = new Date(todayStr + 'T00:00:00Z');
  const year = today.getUTCFullYear();
  const at = y => {
    const d = new Date(`${y}-${mmdd}T00:00:00Z`);
    return isNaN(d) ? new Date(`${y}-03-01T00:00:00Z`) : d;
  };
  const dayMs = 24 * 60 * 60 * 1000;
  const candidates = [at(year - 1), at(year), at(year + 1)];
  let best = null;
  for (const d of candidates) {
    const diff = Math.round((d - today) / dayMs); // >0 — впереди, <0 — прошёл
    if (best === null || Math.abs(diff) < Math.abs(best)) best = diff;
  }
  if (best === 0) return { when: 'today', days: 0 };
  if (best > 0 && best <= windowDays) return { when: 'soon', days: best };
  if (best < 0 && -best <= windowDays) return { when: 'recent', days: -best };
  return null;
}

// ─── СЕГМЕНТЫ ГОСТЕЙ ПО ВИЗИТАМ (давность + частота) ──
// Как у CosmosResto: Чемпионы / Лояльные+ / Лояльные / Активные / Спящие / Потерянные,
// только без суммы чека (она появится с iiko). Сегмент считается по записанным визитам:
// давность — сколько дней с последнего визита, частота — сколько визитов за последний год.
// Пороги — в днях и визитах, а не «перцентили по базе»: так понятно, почему гость
// в этом сегменте, и сразу после открытия не получится, что гость, бывший 3 недели назад,
// уже «потерянный» только потому, что остальные были ещё позже.
// Сегмент на любую прошлую дату считается по тем же визитам — так видны переходы
// между сегментами за любой месяц без хранения снимков.
const SEGMENT_RULES = {
  windowDays: 365,   // частота — визиты за последний год
  recentDays: 30,    // «был недавно»
  sleepDays: 90,     // дольше — «спит» или «потерян»
  loyalVisits: 2,    // 2+ визитов за год — уже лояльный
  championVisits: 6  // 6+ визитов за год — чемпион (если был недавно)
};
const SEGMENTS = [
  { key: 'champions', name: 'Чемпионы', rank: 6, color: 'orange' },
  { key: 'loyalPlus', name: 'Лояльные+', rank: 5, color: 'green' },
  { key: 'loyal', name: 'Лояльные', rank: 4, color: 'blue' },
  { key: 'active', name: 'Активные', rank: 3, color: 'purple' },
  { key: 'sleeping', name: 'Спящие', rank: 2, color: 'yellow' },
  { key: 'lost', name: 'Потерянные', rank: 1, color: 'gray' }
];
// Границы можно менять в приложении («Сервис» → «Правила сегментов», только основатель): они лежат в settings →
// segments.rules и подменяют значения выше. Значения по умолчанию — те, что стояли в коде до появления экрана.
const SEGMENT_DEFAULTS = Object.freeze({ ...SEGMENT_RULES });
const SEGMENT_LIMITS = {
  recentDays: { min: 7, max: 180 },
  sleepDays: { min: 14, max: 730 },
  loyalVisits: { min: 2, max: 20 },
  championVisits: { min: 3, max: 100 },
  windowDays: { min: 30, max: 730 }
};
const windowText = (r) => r.windowDays === 365 ? 'за год' : `за ${r.windowDays} дней`;
function segmentTexts(r) {
  const w = windowText(r);
  const below = r.loyalVisits - 1; // сколько визитов ещё не «лояльный»
  const loyalRange = r.championVisits - 1 > r.loyalVisits ? `${r.loyalVisits}–${r.championVisits - 1}` : `${r.loyalVisits}`;
  return {
    champions: `От ${r.championVisits} визитов ${w}, последний — за ${r.recentDays} дней`,
    loyalPlus: `От ${r.championVisits} визитов ${w}, последний — ${r.recentDays + 1}–${r.sleepDays} дней назад`,
    loyal: `${loyalRange} визитов ${w}, последний — за ${r.sleepDays} дней`,
    active: `${below > 1 ? `1–${below} визита` : '1 визит'} ${w}, был за последние ${r.sleepDays} дней`,
    sleeping: `От ${r.loyalVisits} визитов ${w}, но не был больше ${r.sleepDays} дней`,
    lost: `Не был больше ${r.sleepDays} дней, ${w} — не больше ${below} ${below === 1 ? 'визита' : 'визитов'}`
  };
}
function describeSegments() {
  const text = segmentTexts(SEGMENT_RULES);
  for (const s of SEGMENTS) s.description = text[s.key];
}
describeSegments();
// Проверка набора границ. Возвращает { rules } или { error } — текст для человека.
function cleanSegmentRules(input) {
  const out = {};
  const names = { recentDays: '«Был недавно»', sleepDays: '«Давно не был»', loyalVisits: '«Лояльный»', championVisits: '«Чемпион»', windowDays: 'Период' };
  for (const k of Object.keys(SEGMENT_LIMITS)) {
    const v = input && input[k];
    if (typeof v !== 'number' || !Number.isInteger(v)) return { error: `${names[k]}: нужно целое число` };
    const lim = SEGMENT_LIMITS[k];
    if (v < lim.min || v > lim.max) return { error: `${names[k]}: от ${lim.min} до ${lim.max}` };
    out[k] = v;
  }
  if (out.sleepDays <= out.recentDays) return { error: '«Давно не был» должно быть больше, чем «Был недавно»' };
  if (out.championVisits <= out.loyalVisits) return { error: 'Для «Чемпиона» нужно больше визитов, чем для «Лояльного»' };
  if (out.windowDays < out.sleepDays) return { error: 'Период, за который считаются визиты, не может быть короче, чем «Давно не был»' };
  return { rules: out };
}
const SEGMENT_RULES_KEY = 'segments.rules';
let segmentRulesMeta = { updatedAt: null, updatedBy: '' };
function applySegmentRules(rules) {
  Object.assign(SEGMENT_RULES, rules);
  describeSegments();
  if (typeof refreshMarketingSegmentTexts === 'function') refreshMarketingSegmentTexts();
}
// Читаем сохранённые границы: при старте и раз в минуту (если серверов несколько, правка дойдёт до каждого)
async function loadSegmentRules() {
  try {
    const r = await store.db.query('SELECT value FROM settings WHERE key = $1', [SEGMENT_RULES_KEY]);
    const v = r.rows[0] && r.rows[0].value;
    const chk = v && v.rules ? cleanSegmentRules(v.rules) : null;
    const next = chk && chk.rules ? chk.rules : { ...SEGMENT_DEFAULTS };
    segmentRulesMeta = { updatedAt: (v && v.updatedAt) || null, updatedBy: (v && v.updatedBy) || '' };
    if (Object.keys(next).some(k => next[k] !== SEGMENT_RULES[k])) { applySegmentRules(next); forgetMemo(''); }
  } catch (e) {
    console.error('Правила сегментов не прочитались, работаем по прежним:', e && e.message ? e.message : e);
  }
}
setTimeout(loadSegmentRules, 0);
setInterval(loadSegmentRules, 60 * 1000).unref();
// без прототипа — чтобы ключ вроде «constructor» из запроса не находил ничего лишнего
const SEGMENT_BY_KEY = Object.assign(Object.create(null), Object.fromEntries(SEGMENTS.map(s => [s.key, s])));
const SEGMENT_BY_NAME = Object.assign(Object.create(null), Object.fromEntries(SEGMENTS.map(s => [s.name, s])));

// Настоящая дата 'YYYY-MM-DD' (а не 2026-13-45) — для параметров из запроса
function isRealDateStr(v) {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const d = new Date(v + 'T00:00:00Z');
  return !isNaN(d) && d.toISOString().slice(0, 10) === v;
}
// День рождения гостя: год настоящий (1995) или условный (2000 — «год не знаем»). День и месяц проверяем по високосному 2000-му,
// иначе у гостя с настоящим годом рождения «29 февраля» отклонялось (в 1995-м такого дня не было). 31 февраля, 31 апреля и т.п. — нет.
function isRealBirthdayStr(v) {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const year = Number(v.slice(0, 4));
  if (year < 1900 || year > Number(venueDateStr().slice(0, 4))) return false;
  return isRealDateStr(`2000-${v.slice(5, 10)}`);
}

// Даты визитов каждого гостя: Map(guestId → ['YYYY-MM-DD', ...] по возрастанию, без повторов)
function visitDatesByGuest(visits) {
  const sets = new Map();
  for (const v of visits) {
    if (!v.guestId || !v.date) continue;
    let s = sets.get(v.guestId);
    if (!s) sets.set(v.guestId, s = new Set());
    s.add(v.date.slice(0, 10));
  }
  const out = new Map();
  for (const [id, s] of sets) out.set(id, [...s].sort());
  return out;
}

// Сегмент гостя на дату asOf (по умолчанию — сегодня): учитываются только визиты до этой даты
function guestSegment(dates, asOf = venueDateStr(), rules = SEGMENT_RULES) {
  const r = rules;
  const windowStart = addDaysStr(asOf, -(r.windowDays - 1));
  let lastVisit = null, visitsYear = 0, visitsTotal = 0;
  for (const d of dates || []) {
    if (d > asOf) break;
    visitsTotal++;
    lastVisit = d;
    if (d >= windowStart) visitsYear++;
  }
  const daysSince = lastVisit ? daysBetween(lastVisit, asOf) : null;
  let key = null;
  if (lastVisit) {
    if (daysSince > r.sleepDays) key = visitsYear >= r.loyalVisits ? 'sleeping' : 'lost';
    else if (visitsYear >= r.championVisits) key = daysSince <= r.recentDays ? 'champions' : 'loyalPlus';
    else if (visitsYear >= r.loyalVisits) key = 'loyal';
    else key = 'active';
  }
  return { key, name: key ? SEGMENT_BY_KEY[key].name : '', lastVisit, daysSince, visitsYear, visitsTotal };
}
function segmentPublic(seg) {
  const s = seg.key ? SEGMENT_BY_KEY[seg.key] : null;
  return { ...seg, description: s ? s.description : 'Визитов пока нет', rank: s ? s.rank : 0 };
}

// VIP — ручной тег (ставит и снимает только администрация)
function hasVipTag(tags) {
  return (tags || []).some(t => String(t).trim().toLowerCase() === 'vip');
}

// Риск оттока: гость ходил (2+ визита за год), но не был больше 30 дней.
// VIP — даже если был один раз или визитов ещё не записано.
function isAtRisk(seg, vip) {
  const r = SEGMENT_RULES;
  const away = seg.daysSince === null || seg.daysSince > r.recentDays;
  if (vip) return away;
  return seg.daysSince !== null && seg.daysSince > r.recentDays && seg.visitsYear >= r.loyalVisits;
}

// ─── СОТРУДНИКИ (Postgres; кэш в памяти обновляется каждые 15 секунд) ──
// У каждого сотрудника личные логин и пароль (в базе — хэш). После входа сервер выдаёт длинный ключ на 30 дней,
// приложение присылает его в заголовке Authorization: Bearer … (хранится в таблице sessions только хэш).
// Уволили сотрудника, сменили пароль или «выйти на всех устройствах» — ключи стираются, телефоны вылетают сразу.
// Старый вход по 4-значному PIN закрыт (включается только переменной PIN_LOGIN=on и работает лишь у тех, у кого нет
// пароля). Логины и пароли выдаёт основатель на экране «Сотрудники».
// Сотрудников добавляет, меняет и увольняет основатель на экране «Сотрудники» в приложении.
// Правки через приложение сбрасывают кэш сразу; прямые правки в базе подхватятся за 15 секунд.

let employeesCache = [];
let employeesCacheTime = 0;
const EMPLOYEES_CACHE_TTL = 15 * 1000; // 15 секунд

async function refreshEmployees() {
  try {
    const list = await employeesDb.listForLogin();
    // права: набор роли ± личные исключения (галочки на экране «Сотрудники»), у основателя — все
    const matrix = await permissionsDb.loadMatrix();
    for (const e of list) e.perms = permissionsDb.effective(e.roleKey, matrix.defaults[e.roleKey], matrix.overrides[e.id]);
    employeesCache = list;
    employeesCacheTime = Date.now();
  } catch (err) {
    console.error('Не удалось обновить список сотрудников:', err.message);
  }
}

async function ensureEmployeesFresh() {
  if (Date.now() - employeesCacheTime > EMPLOYEES_CACHE_TTL) {
    await refreshEmployees();
  }
}

function findEmployeeByPin(pin) {
  const key = employeesDb.pinKeyOrNull(pin);
  // PIN действует только у тех, кто ещё не задал пароль
  const employee = key ? employeesCache.find(e => e.pinKey && e.pinKey === key && !e.hasPassword) : undefined;
  // перенесённому из Notion сотруднику сохраняем зашифрованную копию PIN, пока он входит по старому PIN
  if (employee && !employee.hasPinEnc) {
    employee.hasPinEnc = true;
    employeesDb.rememberPin(employee.id, String(pin)).catch(e => { employee.hasPinEnc = false; console.error('Не сохранили PIN для просмотра:', e.message); });
  }
  return employee;
}

const legacyPinAllowed = () => process.env.PIN_LOGIN === 'on'; // старый вход по PIN закрыт; включается только PIN_LOGIN=on

// Без секрета PIN_SECRET войти по старому PIN нельзя — говорим об этом прямо, а не «неверный PIN»
function authMisconfigured(res) {
  if (employeesDb.hasPinSecret()) return false;
  res.status(503).json({ error: 'Сервер не настроен: нет переменной PIN_SECRET' });
  return true;
}

// «Был в сети»: любое обращение приложения к серверу отмечает сотрудника; в базу пишем не чаще раза в 5 минут
const seenWrittenAt = new Map();
function noteSeen(employee) {
  if (!employee || !employee.id) return;
  const now = Date.now();
  if (now - (seenWrittenAt.get(employee.id) || 0) < 5 * 60 * 1000) return;
  seenWrittenAt.set(employee.id, now);
  employeesDb.touchSeen(employee.id);
}
function deviceFromRequest(req) {
  const ua = String(req.headers['user-agent'] || '');
  if (/iPad|Tablet/i.test(ua)) return 'планшет';
  if (/iPhone|Android|Mobile/i.test(ua)) return 'телефон';
  return 'компьютер';
}

function bearerToken(req) {
  const m = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization || ''));
  return m ? m[1] : '';
}
// Адрес посетителя — для защиты от подбора. Прокси хостинга должен писать его первым в заголовке X-Forwarded-For; берём оттуда
// (на Amvera это ещё не проверено: открыть /api/ip-check гостевого сервера с VPN и без), а если заголовка нет
// (тесты, локальный запуск) — адрес соединения.
function clientIp(req) {
  const first = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return (first || String(req.ip || req.socket?.remoteAddress || '')).slice(0, 64);
}
// Запасной адрес: то, что видит сам хостинг на входе (X-Real-IP или последний адрес цепочки). Нужен на случай,
// если первый адрес в X-Forwarded-For окажется подставным: по запасному адресу действует свой, широкий лимит.
function edgeIp(req) { return String(req.get('x-real-ip') || req.ip || req.socket?.remoteAddress || '').trim().slice(0, 64); }
const loginFlood = new Map(); // запасной адрес → { n, first }
const LOGIN_FLOOD_MAX = 300, LOGIN_FLOOD_MS = 10 * 60 * 1000;
function loginFlooded(req, res) {
  const key = edgeIp(req), now = Date.now();
  let r = loginFlood.get(key);
  if (!r || now - r.first > LOGIN_FLOOD_MS) { r = { n: 0, first: now }; loginFlood.set(key, r); }
  if (loginFlood.size > 5000) for (const [k, v] of loginFlood) if (now - v.first > LOGIN_FLOOD_MS) loginFlood.delete(k);
  if (++r.n <= LOGIN_FLOOD_MAX) return false;
  res.status(429).json({ error: 'Слишком много попыток входа. Попробуйте через несколько минут' });
  return true;
}

// Кто делает запрос: ключ входа (Authorization: Bearer …) или, пока пароля нет, старый PIN.
// Ответ 401 с кодом сообщает приложению, что нужно войти заново; 403 must_change_password — что сначала нужен новый пароль.
// opts.allowMustChange — для экранов «задайте пароль» (там человек ещё не сменил временный пароль).
async function authenticate(req, res, opts = {}) {
  await ensureEmployeesFresh();
  const token = bearerToken(req);
  if (token) {
    const sess = await authDb.resolveSession(token);
    let emp = sess && employeesCache.find(e => e.id === sess.employeeId);
    if (sess && !emp) { await refreshEmployees(); emp = employeesCache.find(e => e.id === sess.employeeId); }
    if (!sess || !emp) {
      if (sess && !emp) {
        const h8 = String(sess.tokenHash || '').slice(0, 8);
        authDb.sessLog('noemp:' + h8, `ключ ${h8}: вход есть, но сотрудника ${sess.employeeId} нет в списке доступа (в списке ${employeesCache.length}; не прочиталась база или сотрудник отключён)`);
      }
      res.status(401).json({ error: 'Вход истёк. Войдите заново', code: 'session_expired' });
      return null;
    }
    if (sess.mustChange && !opts.allowMustChange) {
      res.status(403).json({ error: 'Сначала задайте новый пароль', code: 'must_change_password' });
      return null;
    }
    req.session = sess;
    return emp;
  }
  // переходный вход: старый PIN в запросе (только у тех, кто ещё не задал пароль)
  const pin = req.query.pin || req.body?.pin;
  if (pin && legacyPinAllowed() && employeesDb.hasPinSecret()) {
    const wait = authDb.ipBlockedFor(clientIp(req));
    if (wait) { res.status(429).json({ error: `Слишком много неудачных попыток. Попробуйте через ${wait} мин.` }); return null; }
    const emp = findEmployeeByPin(String(pin));
    if (emp && !opts.allowMustChange) return emp;
    if (!emp) authDb.ipFail(clientIp(req));
  }
  res.status(401).json({ error: 'Войдите в приложение', code: 'login_required' });
  return null;
}

// Любой активный сотрудник — базовый доступ
async function checkPin(req, res) {
  const employee = await authenticate(req, res);
  if (!employee) return false;
  req.employee = employee;
  noteSeen(employee);
  return true;
}

// Строго роль "Основатель": сотрудники, логины и пароли, права, перенос данных. Это не настраивается галочками —
// иначе можно было бы по ошибке отдать управление всей командой. Остальные разделы (аналитика, рассылки,
// кандидаты и т.д.) основатель выдаёт сотрудникам правами.
async function checkFounderPin(req, res) {
  const employee = await authenticate(req, res);
  if (!employee) return false;
  if (employee.role !== 'Основатель') {
    res.status(403).json({ error: 'Доступно только основателю' });
    return false;
  }
  req.employee = employee;
  noteSeen(employee);
  return true;
}

// Есть ли у сотрудника право (набор роли ± личные исключения, см. db/permissions.js)
function can(employee, key) {
  return !!(employee && employee.perms && employee.perms.has(key));
}

// Нужен сотрудник с конкретным правом. Любое из списка: checkPerm(req, res, ['a', 'b']).
async function checkPerm(req, res, key) {
  const employee = await authenticate(req, res);
  if (!employee) return false;
  const keys = Array.isArray(key) ? key : [key];
  if (!keys.some(k => can(employee, k))) {
    res.status(403).json({ error: 'Нет доступа к этому действию. Если оно нужно для работы — попросите основателя открыть его в разделе «Сотрудники»' });
    return false;
  }
  req.employee = employee;
  noteSeen(employee);
  return true;
}

// Старт: загрузить сотрудников в кэш. Первого основателя на пустой базе создаёт аварийный вход
// (FOUNDER_RECOVERY_LOGIN + FOUNDER_RECOVERY_PASSWORD).
async function bootEmployees() {
  await refreshEmployees();
}

bootEmployees().then(() => authDb.recoverFounder()).then(() => authDb.wipeStalePins()).catch((e) => console.error('Подчистка старых PIN не удалась:', e.message)); // потом — аварийный пароль основателя, если он задан в переменных сервиса (FOUNDER_RECOVERY_PASSWORD)
setInterval(refreshEmployees, EMPLOYEES_CACHE_TTL);
authDb.cleanup();
setInterval(() => { authDb.cleanup(); }, 6 * 60 * 60 * 1000); // просроченные входы стираем раз в 6 часов

// ─── ЗАКРЫТИЕ ПРЕРВАННЫХ РАССЫЛОК ПРИ СТАРТЕ ─────
// Если сервер перезапустили посреди рассылки, её запись остаётся «идёт»: помечаем такие «Прервана».
async function bootAbortStale() {
  try {
    const aborted = await catalog.abortStaleBroadcasts();
    if (aborted) console.log(`Рассылок, прерванных перезапуском сервера: ${aborted}`);
  } catch (e) { console.error('Не удалось закрыть незавершённые рассылки:', e.message); }
  try {
    const stale = await mailings.abortStale();
    if (stale) console.log(`Отправок рассылок по событиям, прерванных перезапуском сервера: ${stale}`);
  } catch (e) { console.error('Не удалось закрыть незавершённые отправки рассылок:', e.message); }
}
bootAbortStale();

// ─── НАПОМИНАНИЯ О ПРОСРОЧЕННЫХ ПРОБЛЕМАХ ──────────
// Раз в несколько часов проверяем "В работе" с истёкшим сроком — шлём
// ответственному (по роли) и админу. Не чаще одного раза в день на проблему.

// Напоминания о просроченных проблемах и задачах: одно в день на каждую.
// «Уже напомнили сегодня» хранится в базе (settings → reminders.sent), а не в памяти сервера: раньше после
// каждого обновления сервера все напоминания уходили заново. И только днём — с 11:00 до 21:00 по времени
// заведения (окно меняется переменной REMINDER_HOURS, например "10-22"): ночью сотрудников не будим.
const REMINDER_HOURS = hoursWindow(process.env.REMINDER_HOURS, 11, 21);
const PROBLEM_UNTAKEN_HOURS = Math.max(1, Math.floor(Number(process.env.PROBLEM_UNTAKEN_HOURS) || 4));
async function remindersLoad(today) {
  const r = await store.db.query("SELECT value FROM settings WHERE key = 'reminders.sent'");
  const v = r.rows[0] && r.rows[0].value;
  return v && v.day === today ? { day: today, problems: v.problems || [], tasks: v.tasks || [], untaken: v.untaken || [] } : { day: today, problems: [], tasks: [], untaken: [] };
}
async function remindersSave(state) {
  await store.db.query(
    `INSERT INTO settings (key, value, updated_at) VALUES ('reminders.sent', $1::jsonb, now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [JSON.stringify(state)]);
}
let remindersRunning = false;
async function checkOverdue() {
  if (remindersRunning || !inHoursWindow(REMINDER_HOURS)) return;
  remindersRunning = true;
  try {
    await ensureEmployeesFresh();
    const today = venueDateStr();
    const state = await remindersLoad(today);

    for (const p of await feedback.overdueInProgress(today)) {
      if (state.problems.includes(p.id)) continue;
      // сначала запоминаем, потом пишем: если сервер перезапустится посреди отправки, напоминание не уйдёт дважды
      state.problems.push(p.id);
      await remindersSave(state);
      const text = `⏰ Просрочена проблема: «${p.title || 'Проблема'}»\nОтветственный: ${p.responsible}\nСрок был: ${p.deadline}\n\nПожалуйста, закройте или обновите срок.`;
      // Шлём каждому активному сотруднику с нужной ролью, у кого есть Telegram ID
      for (const emp of employeesCache.filter(e => e.role === p.responsible)) {
        if (emp.telegramId) await sendTelegramMessage(emp.telegramId, text);
      }
      const sent = await sendAdmin(text, 'просрочена проблема');
      if (!sent) { state.problems = state.problems.filter(x => x !== p.id); await remindersSave(state); } // не ушло — повторим через час
    }

    // Проблемы, которые никто не взял в работу: раньше напоминали только про «В работе» с истёкшим сроком.
    // Не раньше чем через PROBLEM_UNTAKEN_HOURS часов (по умолчанию 4: за 12 вечерняя смена успевает закончиться), одно напоминание в день на проблему,
    // не больше 5 за проход (чтобы при первом запуске не завалить чат старыми). PROBLEM_UNTAKEN_REMIND=off — выключить.
    if (process.env.PROBLEM_UNTAKEN_REMIND !== 'off') {
      state.untaken = state.untaken || [];
      let left = 5;
      for (const p of await feedback.untakenProblems(PROBLEM_UNTAKEN_HOURS)) {
        if (left <= 0) break;
        if (state.untaken.includes(p.id)) continue;
        left--;
        state.untaken.push(p.id);
        await remindersSave(state);
        const hrs = Math.floor((Date.now() - new Date(p.created)) / 3600e3);
        const age = hrs >= 48 ? `${Math.floor(hrs / 24)} дн.` : `${hrs} ч`;
        const text = `🆕 Проблему никто не взял в работу уже ${age}: «${p.title || 'Проблема'}»${p.responsible ? `\nОтветственный: ${p.responsible}` : ''}${p.severity ? `\nВажность: ${p.severity}` : ''}\n\nОткройте её в приложении и возьмите в работу.`;
        for (const emp of employeesCache.filter(e => p.responsible && e.role === p.responsible)) {
          if (emp.telegramId) await sendTelegramMessage(emp.telegramId, text);
        }
        const sent = await sendAdmin(text, 'проблему не взяли');
        if (!sent) { state.untaken = state.untaken.filter(x => x !== p.id); await remindersSave(state); }
      }
    }

    // Часовая сводка «Средних» проблем: срочные («Высокая») уходят сразу, а средние копятся и приходят одним сообщением.
    // Время прошлой сводки хранится в базе (settings → problems.digest). Если сводка не ушла, время не двигаем — войдёт в следующую.
    // Берём не больше суток назад: после долгого простоя сервера чат не заваливаем старым. PROBLEM_DIGEST=off — выключить.
    if (process.env.PROBLEM_DIGEST !== 'off') {
      const nowIso = new Date().toISOString();
      const dr = await store.db.query("SELECT value FROM settings WHERE key = 'problems.digest'");
      const lastIso = dr.rows[0] && dr.rows[0].value && dr.rows[0].value.at;
      const dayAgo = Date.now() - 24 * 3600e3;
      const since = new Date(Math.max(lastIso ? new Date(lastIso).getTime() : 0, dayAgo)).toISOString();
      const items = await feedback.mediumSince(since);
      let advance = true;
      if (items.length) {
        const shown = items.slice(0, 10).map(p => `• ${p.category || 'Проблема'}: ${String(p.comment || '—').replace(/\s+/g, ' ').slice(0, 90)}${p.responsible ? ` → ${p.responsible}` : ''}`);
        const more = items.length > shown.length ? `\n…и ещё ${items.length - shown.length}` : '';
        const text = `📋 Проблемы средней важности: ${items.length}\n\n${shown.join('\n')}${more}\n\nОни ждут в разделе «Проблемы» — возьмите в работу.`;
        advance = await sendAdmin(text, 'сводка проблем');
      }
      if (advance) {
        await store.db.query(
          `INSERT INTO settings (key, value, updated_at) VALUES ('problems.digest', $1::jsonb, now())
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [JSON.stringify({ at: nowIso })]);
      }
    }

    // Задачи: просроченной считается незавершённая задача со сроком раньше сегодняшнего дня; без срока сюда не попадают
    for (const t of await work.overdueTasks(today)) {
      if (state.tasks.includes(t.id)) continue;
      state.tasks.push(t.id);
      await remindersSave(state);
      const sent = await sendAdmin(`⏰ Просрочена задача: «${t.title || 'Задача'}»\nСрок был: ${t.deadline}\n\nОтметьте готовой или обновите срок в приложении.`, 'просрочена задача');
      if (!sent) { state.tasks = state.tasks.filter(x => x !== t.id); await remindersSave(state); }
    }
  } catch (err) {
    console.error('Overdue check failed:', err && err.message ? err.message : err);
  } finally {
    remindersRunning = false;
  }
}
setInterval(checkOverdue, 60 * 60 * 1000).unref(); // раз в час: в рабочее окно попадём в любой день, когда бы сервер ни запустили
setTimeout(checkOverdue, 30 * 1000).unref();       // и один раз вскоре после старта сервера

async function tgApi(method, payload) {
  if (!TELEGRAM_BOT_TOKEN) return null;
  try {
    // не дольше 10 секунд: иначе зависший Telegram держал бы запрос (и установку секрета вебхука) бесконечно
    const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      timeout: 10000
    });
    return await res.json();
  } catch (err) {
    // только суть ошибки: полный текст содержит адрес запроса с токеном бота
    console.error(`Telegram API ${method} failed: ${err && (err.code || err.type || err.name) || 'error'}`);
    return null;
  }
}

// Сравнение секретов без утечки по времени ответа
function safeEqual(a, b) {
  const x = Buffer.from(String(a == null ? '' : a));
  const y = Buffer.from(String(b == null ? '' : b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Названия, которые потом показываются в приложениях (теги, подразделы меню): без угловых скобок и служебных
// знаков. Приложения и так экранируют текст при показе — это вторая линия защиты от вставки кода в страницу.
function plainName(v) {
  return v === undefined || v === null ? v : String(v).replace(/[<>\u0000-\u001f\u007f\u2028\u2029]/g, '');
}

async function sendTelegramMessage(chatId, text) {
  return tgApi('sendMessage', { chat_id: chatId, text });
}

// Сообщение в админ-чат. Раньше результат отправки не проверялся: бота убрали из группы или Telegram не ответил —
// и никто об этом не узнавал. Теперь сбой записывается (kind 'admin') и виден в «Состоянии системы» в строке «Админ-чат».
// Возвращает true, если Telegram принял сообщение; сама не бросает ошибок.
async function sendAdmin(text, note) {
  let sent = null;
  try { sent = await sendTelegramMessage(ADMIN_CHAT_ID, text); } catch (e) { sent = null; }
  if (sent && sent.ok) return true;
  const reason = !sent ? 'network' : sent.error_code === 403 ? 'blocked' : sent.error_code === 429 ? 'limit' : 'error';
  try { await store.recordTgFailure({ at: new Date().toISOString(), kind: 'admin', reason, note: String(note || String(text).split('\n')[0].replace(/^[^\p{L}\p{N}]+/u, '')).slice(0, 60) }); }
  catch (e) { console.error('Не удалось записать сбой админ-чата:', e && e.message ? e.message : e); }
  return false;
}

// ─── ВХОД: ЛОГИН И ПАРОЛЬ ──────────────────────────
// Приложение входит по логину и паролю, получает ключ на 30 дней и присылает его в заголовке Authorization.
// Быстрый вход на своём телефоне: пароль один раз, дальше короткий PIN этого устройства (работает только вместе
// с ключом устройства, 5 неверных PIN — и устройство отключается).
// Все неверные попытки, блокировки, смены и сбросы паролей пишутся в журнал действий.

function sendAuthError(res, e, fallback) {
  if (e instanceof authDb.AuthError) return res.status(e.status).json({ error: e.message, ...(e.extra || {}) });
  if (e instanceof employeesDb.EmployeeError) return res.status(e.status).json({ error: e.message });
  console.error(e);
  res.status(500).json({ error: fallback });
}

// То, что приложение узнаёт о себе сразу после входа
function sessionReply(employee, extra = {}) {
  return {
    ok: true, name: employee.name, login: employee.login, jobRole: employee.role,
    role: isAdminRole(employee.role) ? 'admin' : 'staff', perms: [...employee.perms], ...extra
  };
}

async function employeeForSession(employeeId) {
  await ensureEmployeesFresh();
  let emp = employeesCache.find(e => e.id === employeeId);
  if (!emp) { await refreshEmployees(); emp = employeesCache.find(e => e.id === employeeId); }
  return emp;
}

async function finishLogin(req, res, r) {
  const emp = await employeeForSession(r.employeeId);
  if (!emp) return res.status(401).json({ error: 'Сотрудник не найден или уволен' });
  await employeesDb.recordLogin(emp.id, deviceFromRequest(req));
  seenWrittenAt.set(emp.id, Date.now());
  res.json(sessionReply(emp, { token: r.token, mustChange: !!r.mustChange }));
}

app.post('/api/auth/login', async (req, res) => {
  if (loginFlooded(req, res)) return;
  try {
    const r = await authDb.loginWithPassword({ login: req.body?.login, password: req.body?.password, device: deviceFromRequest(req), ip: clientIp(req) });
    await finishLogin(req, res, r);
  } catch (error) {
    sendAuthError(res, error, 'Не удалось войти');
  }
});

// Переходный вход по старому PIN — только пока у сотрудника нет пароля. Дальше он сразу задаёт пароль.
app.post('/api/staff/login', async (req, res) => {
  if (loginFlooded(req, res)) return;
  try {
    if (!legacyPinAllowed()) return res.status(401).json({ error: 'Вход по PIN закрыт. Войдите по логину и паролю', code: 'login_required' });
    if (authMisconfigured(res)) return;
    await ensureEmployeesFresh();
    const ip = clientIp(req);
    const wait = authDb.ipBlockedFor(ip);
    if (wait) return res.status(429).json({ error: `Слишком много неудачных попыток. Попробуйте через ${wait} мин.` });
    const employee = findEmployeeByPin(String(req.body?.pin == null ? '' : req.body.pin));
    if (!employee) {
      authDb.ipFail(ip);
      await authDb.logAuth(null, 'auth.login_failed', null, 'неудачный вход по старому PIN', { ip: ip.slice(0, 64) });
      return res.status(401).json({ error: 'Неверный PIN-код. Если вы уже задали пароль — войдите по логину и паролю', code: 'login_required' });
    }
    authDb.ipOk(ip);
    const token = await authDb.createSession(store.db.query, employee.id, deviceFromRequest(req));
    await authDb.logAuth({ id: employee.id, name: employee.name, role: employee.role }, 'auth.legacy_login', employee.id, `«${employee.name}» вошёл(ла) по старому PIN: нужно задать пароль`);
    await employeesDb.recordLogin(employee.id, deviceFromRequest(req));
    seenWrittenAt.set(employee.id, Date.now());
    res.json(sessionReply(employee, { token, mustChange: true }));
  } catch (error) {
    sendAuthError(res, error, 'Не удалось войти');
  }
});

app.post('/api/auth/device-login', async (req, res) => {
  try {
    const r = await authDb.deviceLogin({ deviceToken: req.body?.deviceToken, pin: req.body?.pin, device: deviceFromRequest(req), ip: clientIp(req) });
    await finishLogin(req, res, r);
  } catch (error) {
    sendAuthError(res, error, 'Не удалось войти');
  }
});

app.post('/api/auth/device-forget', async (req, res) => {
  try {
    const sess = await authDb.resolveSession(bearerToken(req)); // если запрос от вошедшего — его собственный вход не трогаем
    await authDb.forgetDeviceByToken(req.body?.deviceToken, sess ? sess.id : null);
    res.json({ ok: true });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось отключить устройство');
  }
});

// Кто я и что мне можно (в том числе когда ещё нужно сменить пароль)
app.get('/api/auth/me', async (req, res) => {
  const emp = await authenticate(req, res, { allowMustChange: true });
  if (!emp || !req.session) return;
  noteSeen(emp);
  res.json(sessionReply(emp, { mustChange: !!req.session.mustChange }));
});

app.post('/api/auth/logout', async (req, res) => {
  try { await authDb.logout(bearerToken(req)); } catch (error) { console.error(error); }
  res.json({ ok: true });
});

// «Выйти на всех устройствах»: стираются все ключи входа и быстрые входы, включая этот
app.post('/api/auth/logout-all', async (req, res) => {
  const emp = await authenticate(req, res, { allowMustChange: true });
  if (!emp || !req.session) return;
  try {
    const out = await authDb.revokeAll(emp.id);
    await authDb.logAuth({ id: emp.id, name: emp.name, role: emp.role }, 'auth.logout_all', emp.id, `«${emp.name}» вышел(ла) на всех устройствах (входов: ${out.sessions}, быстрых входов: ${out.devices})`);
    res.json({ ok: true, ...out });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось выйти на всех устройствах');
  }
});

// Смена своего пароля (и первый пароль после временного)
app.post('/api/auth/password', async (req, res) => {
  const emp = await authenticate(req, res, { allowMustChange: true });
  if (!emp || !req.session) return;
  try {
    await authDb.setOwnPassword(req.session, { currentPassword: req.body?.currentPassword, newPassword: req.body?.newPassword }, clientIp(req));
    await refreshEmployees();
    res.json({ ok: true });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось сменить пароль');
  }
});

// Быстрый вход на этом телефоне: короткий PIN (4 цифры) этого устройства
app.post('/api/auth/device', async (req, res) => {
  const emp = await authenticate(req, res);
  if (!emp || !req.session) return;
  try {
    res.json({ ok: true, ...(await authDb.addDevice(req.session, { pin: req.body?.pin, device: req.body?.device }, deviceFromRequest(req))) });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось включить быстрый вход');
  }
});

// «Мой вход»: где открыт мой аккаунт и на каких телефонах включён быстрый вход
app.get('/api/auth/sessions', async (req, res) => {
  const emp = await authenticate(req, res);
  if (!emp || !req.session) return;
  try {
    res.json({ ok: true, ...(await authDb.listMine(req.session)) });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось получить список входов');
  }
});

// Закрыть один из моих входов (не этот): забытый компьютер, чужой или потерянный телефон
app.delete('/api/auth/sessions/:id', async (req, res) => {
  const emp = await authenticate(req, res);
  if (!emp || !req.session) return;
  try {
    const out = await authDb.closeMySession(req.session, req.params.id);
    await authDb.logAuth({ id: emp.id, name: emp.name, role: emp.role }, 'auth.session_closed', emp.id, `«${emp.name}» закрыл(а) вход на другом устройстве («${out.device || 'устройство'}»${out.quickLogin ? ', быстрый вход там отключён' : ''})`, { ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось закрыть вход');
  }
});

// Закрыть все мои входы, кроме этого, — без выхода с текущего устройства (в отличие от «Выйти на всех устройствах»)
app.post('/api/auth/sessions/close-others', async (req, res) => {
  const emp = await authenticate(req, res);
  if (!emp || !req.session) return;
  try {
    const out = await authDb.closeOtherSessions(req.session);
    if (out.sessions || out.devices) await authDb.logAuth({ id: emp.id, name: emp.name, role: emp.role }, 'auth.sessions_closed', emp.id, `«${emp.name}» закрыл(а) входы на остальных устройствах (входов: ${out.sessions}, быстрых входов: ${out.devices})`, { ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось закрыть входы');
  }
});

app.delete('/api/auth/devices/:id', async (req, res) => {
  const emp = await authenticate(req, res);
  if (!emp || !req.session) return;
  try {
    await authDb.removeMyDevice(req.session, req.params.id);
    res.json({ ok: true });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось отключить устройство');
  }
});

// Временный пароль сотруднику задаёт только основатель; пароль основателя — только основатель.
// Пароль в ответе показывается один раз. Человек сменит его при первом входе; его старые входы стираются.
app.post('/api/auth/reset-password/:id', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  try {
    const out = await authDb.resetPassword(req.params.id, req.body?.tempPassword, { id: req.employee.id, name: req.employee.name, role: req.employee.role });
    await refreshEmployees();
    res.json({ ok: true, password: out.password, name: out.name });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось задать пароль');
  }
});

// Снять блокировку входа (после неверных паролей) — те же права
app.post('/api/auth/unlock/:id', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  try {
    await authDb.unlock(req.params.id, { id: req.employee.id, name: req.employee.name, role: req.employee.role });
    res.json({ ok: true });
  } catch (error) {
    sendAuthError(res, error, 'Не удалось снять блокировку');
  }
});

// Актуальные права вошедшего сотрудника: приложение перечитывает их, когда основатель что-то поменял
app.get('/api/staff/me', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const e = req.employee;
  res.json({ ok: true, name: e.name, jobRole: e.role, role: isAdminRole(e.role) ? 'admin' : 'staff', perms: [...e.perms] });
});

// ─── ИМЕНИННИКИ СЕГОДНЯ ─────────────────────────────

// Кого уже поздравили в этом году: settings → birthday.greeted = { <год>: { <id гостя>: { via, by, at } } }.
// via: 'bot' — поздравил бот в Telegram, 'manual' — сотрудник отметил «Поздравили» (звонок, WhatsApp и т.п.),
// 'failed' — бот не смог доставить (поздравить вручную).
async function greetedLoad() {
  const r = await store.db.query("SELECT value FROM settings WHERE key = 'birthday.greeted'");
  return (r.rows[0] && r.rows[0].value) || {};
}
// Запись точечная и атомарная (одним SQL), а не «прочитал всё — переписал всё»: при обновлении сервера на минуту
// работают два его экземпляра, и оба могли бы поздравить одного гостя.
async function greetedEnsure() {
  await store.db.query(`INSERT INTO settings (key, value, updated_at) VALUES ('birthday.greeted', '{}'::jsonb, now()) ON CONFLICT (key) DO NOTHING`);
}
const GREETED_SET_SQL = `jsonb_set(CASE WHEN value ? $1 THEN value ELSE jsonb_set(value, ARRAY[$1], '{}'::jsonb) END, ARRAY[$1, $2], $3::jsonb)`;
// Занять гостя, если отметки ещё нет. true — заняли мы.
async function greetedClaim(year, id, rec) {
  await greetedEnsure();
  const r = await store.db.query(
    `UPDATE settings SET value = ${GREETED_SET_SQL}, updated_at = now()
      WHERE key = 'birthday.greeted' AND NOT (COALESCE(value -> $1, '{}'::jsonb) ? $2) RETURNING 1`, [year, id, JSON.stringify(rec)]);
  return r.rows.length > 0;
}
async function greetedPut(year, id, rec) {
  await greetedEnsure();
  await store.db.query(`UPDATE settings SET value = ${GREETED_SET_SQL}, updated_at = now() WHERE key = 'birthday.greeted'`, [year, id, JSON.stringify(rec)]);
}
async function greetedDel(year, id) {
  await store.db.query(`UPDATE settings SET value = value #- ARRAY[$1, $2], updated_at = now() WHERE key = 'birthday.greeted'`, [year, id]);
}
// Telegram именинника — из его же карточки. По телефону ищем, только если номер не общий:
// иначе поздравление с именем гостя ушло бы другому человеку с тем же номером.
function birthdayTelegram(g, contacts) {
  if (g.telegramId) return g.telegramId;
  if (g.sharedPhone) return '';
  const c = contacts.get(normalizePhone(g.phone || ''));
  return (c && c.telegramId) || '';
}
async function birthdayTextLoad() {
  const r = await store.db.query("SELECT value FROM settings WHERE key = 'birthday.text'");
  const v = (r.rows[0] && r.rows[0].value) || {};
  // nameFirst — имя гостя ставится первой строкой само (по умолчанию включено); если в тексте есть {имя}, имя стоит там, где его написали
  return { text: typeof v.text === 'string' ? v.text : '', enabled: v.enabled !== false, nameFirst: v.nameFirst !== false };
}
// Имя для обращения в поздравлении: только настоящее имя. Пусто, «Гость», номер телефона, смайлики, инициалы — не имя (тогда обращения не будет).
// ВСЕ ЗАГЛАВНЫЕ и все строчные → «Анна»; смешанный регистр («Анна-Мария», McDonald) не трогаем.
const NOT_A_NAME = new Set(['гость', 'guest', 'unknown', 'неизвестно']);
function greetingName(g) {
  // первое слово, в котором есть буквы («😀 Алан» → Алан); если это инициал («Д. Петров») — имени нет, фамилией не обращаемся
  let w = String((g && (g.firstName || g.name)) || '').trim().split(/\s+/).find(x => /\p{L}/u.test(x)) || '';
  w = w.replace(/^[^\p{L}]+|[^\p{L}]+$/gu, '');
  if (w.length < 2 || w.length > 30 || !/^\p{L}[\p{L}'’-]*$/u.test(w) || NOT_A_NAME.has(w.toLowerCase())) return '';
  if (w === w.toUpperCase() || w === w.toLowerCase()) w = w.toLowerCase().replace(/(^|[-'’])(\p{L})/gu, (m, a, b) => a + b.toUpperCase());
  return w;
}
// Что уйдёт гостю: {имя} в тексте — имя ставится туда (нет имени — обращение аккуратно убирается, как в рассылках);
// иначе при включённом nameFirst — первой строкой «Анна!», дальше текст как есть, без правки букв.
function birthdayMessage(cfg, g) {
  const name = greetingName(g);
  if (/\{имя\}/i.test(cfg.text)) return personalize(cfg.text, name);
  return cfg.nameFirst && name ? `${name}!\n\n${cfg.text}` : cfg.text;
}
// Именинники дня с тем, что нужно администратору: есть ли Telegram (поздравит бот) и поздравлен ли уже
async function birthdayList(dateStr, greetedYear, contacts, dates) {
  const [year, month, day] = dateStr.split('-').map(Number);
  const list = await cardsDb.birthdaysOn(month, day, year);
  return list.map(g => {
    return {
      id: g.id, name: g.name, phone: g.phone, vip: g.vip,
      segment: guestSegment(dates.get(g.id)).name,
      telegram: !!birthdayTelegram(g, contacts),
      nonGrata: isNonGrata(g),
      greeted: (greetedYear && greetedYear[g.id]) || null
    };
  });
}

// Без параметров — список на сегодня (как раньше, для прежней версии приложения).
// ?days=2 — сегодня и завтра с отметками поздравления и признаком, будет ли поздравлять бот.
app.get('/api/staff/birthdays', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.birthdays'))) return;
  try {
    // по календарному дню заведения — так же, как подсказка «сегодня ДР» в карточке гостя
    const today = venueDateStr();
    const dates = visitDatesByGuest(await getVisitsQuick());
    if (req.query.days !== '2') {
      const [year, month, day] = today.split('-').map(Number);
      const birthdays = await cardsDb.birthdaysOn(month, day, year);
      return res.json(birthdays.map(g => ({ id: g.id, name: g.name, phone: g.phone, vip: g.vip, segment: guestSegment(dates.get(g.id)).name })));
    }
    const [greeted, contacts, cfg] = await Promise.all([greetedLoad(), getGuestContacts(), birthdayTextLoad()]);
    const tomorrow = addDaysStr(today, 1);
    res.json({
      today: await birthdayList(today, greeted[today.slice(0, 4)], contacts, dates),
      tomorrow: await birthdayList(tomorrow, greeted[tomorrow.slice(0, 4)], contacts, dates),
      // бот поздравляет сам, только если текст поздравления заполнен и поздравления включены
      botOn: !!(cfg.enabled && cfg.text.trim()),
      botHour: BIRTHDAY_HOUR
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch birthdays' });
  }
});

// «Поздравили» / снять отметку — чтобы двое не поздравили одного гостя и никто не остался без поздравления
app.post('/api/staff/birthdays/greet', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.birthdays'))) return;
  const id = String(req.body?.id || '');
  const undo = !!req.body?.undo;
  try {
    const card = await cardsDb.getCard(id);
    if (!card || card.archived) return res.status(404).json({ error: 'Гость не найден' });
    const today = venueDateStr();
    const year = today.slice(0, 4);
    // отмечаем только сегодняшних именинников
    const [, month, day] = today.split('-').map(Number);
    if (!(await cardsDb.birthdaysOn(month, day, Number(year))).some(g => g.id === id)) return res.status(400).json({ error: 'У этого гостя день рождения не сегодня' });
    const stuck = (r) => r && r.via === 'sending' && Date.now() - new Date(r.at) > 15 * 60 * 1000; // бот начал и не закончил
    const result = await withKeyLock('birthday:greeted', async () => {
      const cur = ((await greetedLoad())[year] || {})[id] || null;
      if (undo) {
        if (!cur) return { ok: true, greeted: null, already: true };
        if (cur.via !== 'manual') return { http: 409, error: cur.via === 'bot' ? 'Этого гостя поздравил бот — отметку не снять' : 'Отметку поставил не сотрудник', greeted: cur };
        // бот до этого не смог доставить — возвращаем «не смог», чтобы он не отправил поздравление повторно
        if (cur.botFailed) { const rec = { via: 'failed', by: 'Бот', at: cur.at }; await greetedPut(year, id, rec); return { ok: true, greeted: rec }; }
        await greetedDel(year, id);
        return { ok: true, greeted: null };
      }
      if (cur && cur.via !== 'failed' && !stuck(cur)) {
        if (cur.via === 'sending') return { http: 409, error: 'Бот как раз отправляет поздравление — проверьте через минуту', greeted: cur };
        return { ok: true, greeted: cur, already: true }; // уже поздравили — кто первый, тот и записан
      }
      const rec = { via: 'manual', by: employeeLabel(req.employee), at: new Date().toISOString(), ...(cur ? { botFailed: true } : {}) };
      await greetedPut(year, id, rec);
      return { ok: true, greeted: rec };
    });
    const { http, ...body } = result;
    if (result.ok && !result.already) auditNote(req, undo ? 'birthday.greet_undone' : 'birthday.greeted', 'guest', id, `${undo ? 'снята отметка «поздравили»' : 'гостя поздравили с днём рождения'}: ${String(card.name || '').slice(0, 80)}`);
    res.status(http || 200).json(body);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить отметку' });
  }
});

// Текст поздравления: {имя} подставляется. Пока текст пустой или поздравления выключены — бот никого не поздравляет.
app.get('/api/admin/birthday-text', async (req, res) => {
  if (!(await checkPerm(req, res, ['settings.manage', 'marketing.send']))) return;
  try { res.json({ ...(await birthdayTextLoad()), hour: BIRTHDAY_HOUR }); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось загрузить текст' }); }
});
app.put('/api/admin/birthday-text', async (req, res) => {
  if (!(await checkPerm(req, res, ['settings.manage', 'marketing.send']))) return;
  const text = String(req.body?.text || '').replace(/\r/g, '').trim().slice(0, 1500);
  const enabled = req.body?.enabled !== false;
  try {
    const before = await birthdayTextLoad();
    // не пришло (старое приложение сотрудников) — остаётся как было
    const nameFirst = typeof req.body?.nameFirst === 'boolean' ? req.body.nameFirst : before.nameFirst;
    await store.db.query(
      `INSERT INTO settings (key, value, updated_at) VALUES ('birthday.text', $1::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [JSON.stringify({ text, enabled, nameFirst })]);
    auditNote(req, 'birthday.text_saved', 'settings', 'birthday.text', `текст поздравления с днём рождения ${text ? 'изменён' : 'очищен'}${enabled ? '' : ' (поздравления выключены)'}${nameFirst !== before.nameFirst ? `; имя первой строкой ${nameFirst ? 'включено' : 'выключено'}` : ''}`);
    res.json({ ok: true, text, enabled, nameFirst, hour: BIRTHDAY_HOUR });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось сохранить текст' }); }
});

// Бот поздравляет именинников в 12:00 (BIRTHDAY_HOUR) — тех, у кого есть Telegram. «Нон-грата» не поздравляем.
// Отписка от рассылок на поздравление не влияет (решение Тимура). Проверяем раз в 10 минут с 12:00 до 21:00:
// сервер могли перезапустить в полдень — поздравление уйдёт позже, но в тот же день. Каждый гость — один раз в год:
// отметка ставится ДО отправки (перезапуск посреди отправки не поздравит дважды).
const BIRTHDAY_HOUR = Math.min(20, Math.max(8, Math.floor(Number(process.env.BIRTHDAY_HOUR) || 12)));
let birthdayRunning = false;
async function runBirthdayGreetings(force) {
  if (birthdayRunning || process.env.BIRTHDAY_GREETINGS === 'off') return { skipped: true };
  const h = venueHour();
  if (!force && (h < BIRTHDAY_HOUR || h >= 21)) return { skipped: true };
  birthdayRunning = true;
  const out = { sent: 0, failed: 0 };
  try {
    const cfg = await birthdayTextLoad();
    if (!cfg.enabled || !cfg.text.trim()) return { skipped: true };
    const today = venueDateStr();
    const year = today.slice(0, 4);
    const [, month, day] = today.split('-').map(Number);
    if (!INTERNAL_ADMIN_KEY) { console.error('Поздравления: нет ключа для гостевого сервера (INTERNAL_ADMIN_KEY)'); return { skipped: true }; }
    const contacts = await store.getGuestContactsByPhone();
    const usedChats = new Set(); // две карточки-дубля с одним Telegram — одно поздравление
    for (const g of await cardsDb.birthdaysOn(month, day, Number(year))) {
      if (isNonGrata(g)) continue;
      const chatId = birthdayTelegram(g, contacts);
      if (!chatId || usedChats.has(chatId)) continue;
      // отметка «отправляется» ставится ДО отправки и только если гостя ещё никто не поздравил
      if (!(await greetedClaim(year, g.id, { via: 'sending', by: 'Бот', at: new Date().toISOString() }))) continue;
      usedChats.add(chatId);
      const text = birthdayMessage(cfg, g);
      let r = null;
      try { r = await callGuestProxy('/api/internal/broadcast', { messages: [{ chatId, text }], kind: 'birthday' }, 1, 30000); } catch (e) { r = { reached: false }; }
      const now = new Date().toISOString();
      if (r && r.reached && !r.httpError && r.sent === 1) { await greetedPut(year, g.id, { via: 'bot', by: 'Бот', at: now }); out.sent++; continue; }
      out.failed++;
      if (r && r.reached && !r.httpError) await greetedPut(year, g.id, { via: 'failed', by: 'Бот', at: now });                  // Telegram отказал: гость заблокировал бота
      else if (r && r.maybeDelivered) await greetedPut(year, g.id, { via: 'failed', by: 'Бот', at: now, maybe: true });          // связь оборвалась после отправки: могло дойти
      else await greetedDel(year, g.id);                                                                                         // до гостевого сервера не достучались — повторим на следующем проходе
    }
    return out;
  } catch (e) {
    console.error('Поздравления с днём рождения:', e && e.message ? e.message : e);
    return out;
  } finally {
    birthdayRunning = false;
  }
}
// Ручной запуск (основатель): force — не ждать 12:00. Уже поздравленных не трогает.
app.post('/api/admin/birthdays/run', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  res.json({ ok: true, ...(await runBirthdayGreetings(!!req.body?.force)) });
});
setInterval(() => { runBirthdayGreetings(); }, Math.max(5000, Number(process.env.BIRTHDAY_TICK_MS) || 10 * 60 * 1000)).unref();

// ─── РЕЖИМ РАБОТЫ: часы по дням, закрытые даты, терраса ─────────────
// Видят все сотрудники (приложение предупреждает о закрытой дате и убирает столы террасы),
// меняют — основатель и те, кто ведёт афишу (закрытая дата — это чаще всего частное мероприятие).
async function venueConfigWithCounts() {
  const cfg = await store.getVenueConfig();
  const today = venueDateStr(new Date(Date.now() - 6 * 3600 * 1000)); // сутки заведения — до 06:00
  // считаем только брони, которые ещё ждут гостя или идут: отменённые, «не пришёл» и ушедшие — не в счёт
  const r = await store.db.query(
    `SELECT b.venue_day::text AS day, count(*)::int AS c, count(*) FILTER (WHERE b.table_label LIKE 'Терраса%')::int AS terrace
       FROM bookings b WHERE b.status <> 'cancelled' AND b.arrival IS DISTINCT FROM 'no_show' AND ${store.LEFT_AT_SQL} IS NULL
        AND b.venue_day >= $1::date GROUP BY b.venue_day`, [today]);
  const ver = await store.db.query("SELECT updated_at FROM settings WHERE key = 'venue.config'");
  const byDay = new Map(r.rows.map(x => [x.day, x]));
  return {
    ...cfg,
    closed: cfg.closed.map(c => ({ ...c, bookings: (byDay.get(c.date) || { c: 0 }).c })), // брони на закрытую дату — обзвонить
    terraceBookings: r.rows.reduce((a, x) => a + x.terrace, 0),
    reasons: store.CLOSED_REASONS,
    version: ver.rows[0] ? new Date(ver.rows[0].updated_at).toISOString() : '' // по ней сервер замечает, что настройки успел поменять другой сотрудник
  };
}
app.get('/api/staff/venue-config', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try { res.json(await venueConfigWithCounts()); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось загрузить режим работы' }); }
});
app.put('/api/admin/venue-config', async (req, res) => {
  if (!(await checkPerm(req, res, ['settings.manage', 'events.manage']))) return;
  try {
    const before = await store.getVenueConfig();
    // экран открыли давно, а настройки за это время изменил другой сотрудник — не затираем его правки своим старым экраном
    const cur = (await venueConfigWithCounts()).version;
    if (typeof req.body?.version === 'string' && req.body.version !== cur) {
      return res.status(409).json({ error: 'Режим работы уже изменил другой сотрудник. Экран обновится — внесите изменения ещё раз.' });
    }
    const saved = await store.saveVenueConfig(req.body || {});
    const notes = [];
    const dates = (c) => c.closed.map(x => x.date).join(',');
    if (dates(before) !== dates(saved)) notes.push(`закрытые даты: ${saved.closed.map(x => `${x.date} (${x.reason})`).join('; ') || 'нет'}`);
    if (JSON.stringify(before.hours) !== JSON.stringify(saved.hours)) notes.push('изменены часы работы');
    if (before.terrace !== saved.terrace) notes.push(saved.terrace ? 'терраса работает' : 'терраса закрыта');
    if (notes.length) auditNote(req, 'venue.config_saved', 'settings', 'venue.config', `режим работы: ${notes.join(' · ')}`.slice(0, 480));
    res.json({ ok: true, ...(await venueConfigWithCounts()) });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось сохранить режим работы' }); }
});

// ─── СПИСКИ ГОСТЕЙ: VIP И СЕГМЕНТЫ ──────────────────
// filter=vip — все с тегом VIP (по имени); filter=<сегмент> — гости сегмента
// (свежие визиты сверху); filter=none — карточки без единого визита.
// asOf=YYYY-MM-DD — сегмент на эту дату (для экрана «Сегменты» за прошлый месяц).
function guestListRow(c, seg) {
  return {
    id: c.id, name: c.name, phone: c.phone, vip: c.vip,
    segmentKey: seg.key, segment: seg.name,
    lastVisit: seg.lastVisit, daysSince: seg.daysSince, visitsYear: seg.visitsYear
  };
}

// VIP-список нужен тем, кто встречает гостей (право «VIP-гости»), списки сегментов — аналитика
// (право «Сегменты»). Телефоны в этих списках не отдаём.
app.get('/api/staff/guest-list', async (req, res) => {
  const filter = String(req.query.filter || '');
  if (filter !== 'vip' && filter !== 'none' && !SEGMENT_BY_KEY[filter]) {
    if (!(await checkPin(req, res))) return;
    return res.status(400).json({ error: 'Неизвестный список' });
  }
  if (!(await checkPerm(req, res, filter === 'vip' ? 'guests.vip_list' : 'segments.view'))) return;
  const today = venueDateStr();
  const asOfRaw = typeof req.query.asOf === 'string' ? req.query.asOf : '';
  const asOf = isRealDateStr(asOfRaw) && asOfRaw < today ? asOfRaw : today;
  try {
    const [cards, visits] = await Promise.all([getAllCards(), getAllVisits()]);
    const dates = visitDatesByGuest(visits);
    const rows = [];
    for (const c of cards) {
      const seg = guestSegment(dates.get(c.id), asOf);
      if (filter === 'vip' ? !c.vip : filter === 'none' ? seg.key !== null : seg.key !== filter) continue;
      const { phone, ...row } = guestListRow(c, seg);
      rows.push(row);
    }
    if (filter === 'vip') rows.sort((a, b) => a.name.localeCompare(b.name, 'ru'));
    else rows.sort((a, b) => (b.lastVisit || '').localeCompare(a.lastVisit || '') || a.name.localeCompare(b.name, 'ru'));
    res.json({ filter, asOf, title: filter === 'vip' ? 'VIP' : filter === 'none' ? 'Без визитов' : SEGMENT_BY_KEY[filter].name, guests: rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось загрузить список гостей' });
  }
});

// Старый адрес списка VIP (статус «VIP» стал ручным тегом) — чтобы не сломалось
// приложение, открытое до обновления.
app.get('/api/staff/guests-by-status', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.vip_list'))) return;
  if (req.query.status !== 'VIP') return res.status(400).json({ error: 'Статусов «Постоянный/Редкий» больше нет — теперь сегменты по визитам' });
  try {
    const cards = (await getAllCards()).filter(c => c.vip).sort((a, b) => a.name.localeCompare(b.name, 'ru'));
    res.json(cards.map(c => ({ id: c.id, name: c.name, phone: c.phone })));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch guests by status' });
  }
});

// ─── ГОСТИ, КОТОРЫХ ДАВНО НЕ БЫЛО (риск оттока) ─────
// Ходили (от 2 визитов за год) или с тегом VIP, но не были больше 30 дней.

app.get('/api/staff/inactive-guests', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.list_inactive'))) return;
  try {
    // Последний визит — по ВСЕМ визитам (копия базы в памяти), а не по последним 100
    const [cards, visits] = await Promise.all([getAllCards(), getAllVisits()]);
    const dates = visitDatesByGuest(visits);
    const inactive = [];
    for (const c of cards) {
      const seg = guestSegment(dates.get(c.id));
      if (!isAtRisk(seg, c.vip)) continue;
      inactive.push(guestListRow(c, seg));
    }
    // сначала те, у кого визитов не записано, потом — кого дольше всего не было
    inactive.sort((a, b) => (b.daysSince ?? 99999) - (a.daysSince ?? 99999));
    res.json(inactive);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch inactive guests' });
  }
});

// ─── БЫСТРАЯ ЗАМЕТКА О ПРОБЛЕМЕ (от любого сотрудника) ──

// «Сообщить о проблеме» доступно каждой роли, поэтому защищено от случайного и намеренного завала:
// категория и важность — только из списка, текст ограничен, частота ограничена, повтор того же текста подряд не заводит вторую проблему,
// а сообщений в админ-чат о «Высокой» — не больше трёх в час от одного сотрудника (проблема при этом сохраняется).
const PROBLEM_SEVERITIES = ['Низкая', 'Средняя', 'Высокая'];
const PROBLEM_COMMENT_MAX = 1000;
const PROBLEM_PER_HOUR = 8;
const PROBLEM_ADMIN_PINGS_PER_HOUR = 3;
const problemRate = new Map(); // id сотрудника → { at: [время], pings: [время], last: { text, at } }
function problemRateOf(id) {
  const now = Date.now();
  let r = problemRate.get(id);
  if (!r) { r = { at: [], pings: [], last: null }; problemRate.set(id, r); }
  r.at = r.at.filter(t => now - t < 3600e3);
  r.pings = r.pings.filter(t => now - t < 3600e3);
  if (problemRate.size > 2000) for (const [k, v] of problemRate) if (!v.at.length && !v.pings.length) problemRate.delete(k);
  return r;
}

app.post('/api/staff/problem', async (req, res) => {
  if (!(await checkPerm(req, res, 'problems.report'))) return;
  const category = typeof req.body?.category === 'string' ? req.body.category.trim() : '';
  const comment = (typeof req.body?.comment === 'string' ? req.body.comment : '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim();
  const severityIn = typeof req.body?.severity === 'string' ? req.body.severity.trim() : '';
  if (!category || !comment) return res.status(400).json({ error: 'Выберите категорию и опишите, что случилось' });
  if (!Object.prototype.hasOwnProperty.call(CATEGORY_ROLE_MAP, category)) return res.status(400).json({ error: 'Выберите категорию из списка' });
  if (comment.length > PROBLEM_COMMENT_MAX) return res.status(400).json({ error: `Слишком длинный текст — не больше ${PROBLEM_COMMENT_MAX} символов (сейчас ${comment.length})` });

  const rate = problemRateOf(req.employee.id);
  // двойное нажатие или повторная отправка того же текста: проблема уже заведена
  if (rate.last && rate.last.text === `${category}|${comment}` && Date.now() - rate.last.at < 10 * 60 * 1000) return res.json({ ok: true, already: true });
  if (rate.at.length >= PROBLEM_PER_HOUR) return res.status(429).json({ error: 'За последний час уже отправлено много сообщений о проблемах. Если что-то срочное — скажите администратору лично, остальное отправьте позже' });

  const responsibleRole = CATEGORY_ROLE_MAP[category] || 'Администратор';
  const finalSeverity = PROBLEM_SEVERITIES.includes(severityIn) ? severityIn : 'Средняя';
  const reporter = `${req.employee.name || 'Сотрудник'}${req.employee.role ? ` (${req.employee.role})` : ''}`;

  // занимаем место ДО записи: двойное нажатие шлёт два запроса почти одновременно, и оба не должны пройти проверку выше
  const stamp = Date.now(), prevLast = rate.last;
  rate.at.push(stamp);
  rate.last = { text: `${category}|${comment}`, at: stamp };
  try {
    await feedback.createStaffProblem({ category, comment, severity: finalSeverity, role: responsibleRole, reportedByLabel: reporter });
    forgetMemo('feedback:problems');
    // высокая критичность — сразу пишем администрации в Telegram, не дожидаясь, пока кто-то откроет приложение
    if (finalSeverity === 'Высокая' && rate.pings.length < PROBLEM_ADMIN_PINGS_PER_HOUR) {
      rate.pings.push(Date.now());
      sendAdmin(`🚨 Проблема · высокая критичность\n${category} — ${comment.slice(0, 500)}\n\nСообщил(а): ${reporter}, ${venueTimeStr()}`, 'проблема: высокая')
        .catch(() => {});
    }
    res.json({ ok: true });
  } catch (error) {
    const i = rate.at.indexOf(stamp); if (i >= 0) rate.at.splice(i, 1);
    if (rate.last && rate.last.at === stamp) rate.last = prevLast;
    console.error(error);
    res.status(500).json({ error: 'Проблема не сохранилась — попробуйте ещё раз' });
  }
});

// ─── СМЕНА: «открыл» и «закрыл» ─────────────────────
// Сотрудник нажимает «Открыть смену» и «Закрыть смену». Основатель и администратор на экране «Смена»
// видят, кто и во сколько открыл и закрыл (сегодня и вчера).
// Чек-листы (с 16.10.2026): у каждой роли свои пункты «Открытие» и «Закрытие» (раздел «Сервис» → «Чек-листы», db/checklists.js).
// Нажатие «Открыть смену» / «Закрыть смену» сначала проводит человека по пунктам своей роли. Пустой список — кнопка работает как раньше.
// Блокировки приложения до открытия смены нет.
// День заведения — до 06:00 утра ещё предыдущий день, поэтому закрытие в 01:30 относится к вечеру накануне.
// Открыл и не закрыл → при следующем открытии прошлая отметка получает статус «не закрыта» (forgot).

function hhmm(date) {
  return new Date(date).toLocaleTimeString('ru-RU', { timeZone: VENUE_TZ, hour: '2-digit', minute: '2-digit' });
}
function shiftDto(row) {
  return {
    id: Number(row.id),
    openedAt: new Date(row.opened_at).toISOString(),
    opened: hhmm(row.opened_at)
  };
}
// Открытые смены прошлых дней становятся «не закрыта»: человек ушёл и забыл нажать «Закрыть»
async function settleStaleShifts(employeeId) {
  await store.db.query(`UPDATE shift_marks SET status = 'forgot' WHERE employee_id = $1 AND status = 'open' AND day < $2::date`, [employeeId, venueDayStr()]);
}

// Моя смена: открыта сейчас или нет
app.get('/api/staff/shift', async (req, res) => {
  if (!(await checkPerm(req, res, 'shift.mark'))) return;
  try {
    await settleStaleShifts(req.employee.id);
    const r = await store.db.query(`SELECT id, opened_at FROM shift_marks WHERE employee_id = $1 AND status = 'open'`, [req.employee.id]);
    res.json({ open: r.rows[0] ? shiftDto(r.rows[0]) : null });
  } catch (error) {
    console.error('Смена: не удалось получить отметку:', error);
    res.status(500).json({ error: 'Не удалось получить смену' });
  }
});

// Пункты чек-листа для моей роли: kind=open или kind=close. Пусто — чек-листа нет, смену можно открывать или закрывать сразу.
app.get('/api/staff/shift/checklist', async (req, res) => {
  if (!(await checkPerm(req, res, 'shift.mark'))) return;
  const kind = String(req.query.kind || '');
  if (kind !== 'open' && kind !== 'close') return res.status(400).json({ error: 'kind: open или close' });
  try {
    res.json({ kind, items: await checklistsDb.itemsForRole(req.employee.roleKey, kind) });
  } catch (error) {
    console.error('Смена: не удалось получить чек-лист:', error);
    res.status(500).json({ error: 'Не удалось загрузить чек-лист' });
  }
});

function sendChecklistError(res, e) {
  if (e instanceof checklistsDb.ChecklistError) return res.status(e.status).json({ error: e.message, ...(e.extra || {}) });
  return false;
}

app.post('/api/staff/shift/open', async (req, res) => {
  if (!(await checkPerm(req, res, 'shift.mark'))) return;
  try {
    await settleStaleShifts(req.employee.id);
    // уже на смене (второе нажатие, второе устройство): чек-лист повторно не требуем, ничего не дублируем
    const cur0 = await store.db.query(`SELECT id, opened_at FROM shift_marks WHERE employee_id = $1 AND status = 'open'`, [req.employee.id]);
    if (cur0.rows[0]) return res.json({ ok: true, already: true, open: shiftDto(cur0.rows[0]) });
    const check = await checklistsDb.evaluate(req.employee, 'open', req.body);
    // два быстрых нажатия подряд: вторая вставка упирается в уникальность, открытой остаётся одна
    const ins = await store.db.query(
      `INSERT INTO shift_marks (employee_id, day, open_check) VALUES ($1, $2::date, $3::jsonb)
       ON CONFLICT (employee_id) WHERE status = 'open' DO NOTHING RETURNING id, opened_at`, [req.employee.id, venueDayStr(), check ? JSON.stringify(check) : null]);
    if (ins.rows[0]) {
      auditNote(req, 'shift.opened', 'shift', ins.rows[0].id, `открыл(а) смену в ${hhmm(ins.rows[0].opened_at)}${checklistsDb.checkNote(check)}`);
      return res.json({ ok: true, open: shiftDto(ins.rows[0]) });
    }
    const cur = await store.db.query(`SELECT id, opened_at FROM shift_marks WHERE employee_id = $1 AND status = 'open'`, [req.employee.id]);
    res.json({ ok: true, already: true, open: cur.rows[0] ? shiftDto(cur.rows[0]) : null });
  } catch (error) {
    if (sendChecklistError(res, error)) return;
    console.error('Смена: не удалось открыть:', error);
    res.status(500).json({ error: 'Смена не открылась — попробуйте ещё раз' });
  }
});

app.post('/api/staff/shift/close', async (req, res) => {
  if (!(await checkPerm(req, res, 'shift.mark'))) return;
  try {
    await settleStaleShifts(req.employee.id);
    const open = await store.db.query(`SELECT id FROM shift_marks WHERE employee_id = $1 AND status = 'open'`, [req.employee.id]);
    if (!open.rows[0]) return res.status(409).json({ error: 'Смена не открыта — сначала нажмите «Открыть смену».' });
    const check = await checklistsDb.evaluate(req.employee, 'close', req.body);
    const upd = await store.db.query(
      `UPDATE shift_marks SET status = 'closed', closed_at = now(), close_check = $2::jsonb
        WHERE employee_id = $1 AND status = 'open' RETURNING id, opened_at, closed_at`, [req.employee.id, check ? JSON.stringify(check) : null]);
    if (!upd.rows[0]) return res.status(409).json({ error: 'Смена не открыта — сначала нажмите «Открыть смену».' });
    const m = upd.rows[0];
    auditNote(req, 'shift.closed', 'shift', m.id, `закрыл(а) смену в ${hhmm(m.closed_at)}${checklistsDb.checkNote(check)}`);
    // Закрытие вечера: что осталось без отметки. Сама смена уже закрыта — сбой проверки её не отменяет.
    let dayClose = null;
    try { dayClose = await dayCloseOnShiftClose(req.employee); } catch (e) { console.error('Закрытие вечера: не удалось проверить:', e && e.message ? e.message : e); }
    res.json({ ok: true, open: null, closed: hhmm(m.closed_at), ...(dayClose ? { dayClose } : {}) });
  } catch (error) {
    if (sendChecklistError(res, error)) return;
    console.error('Смена: не удалось закрыть:', error);
    res.status(500).json({ error: 'Смена не закрылась — попробуйте ещё раз' });
  }
});

// ── Закрытие вечера ──
// При закрытии смены считаем, что осталось без отметки за этот вечер: брони без «Пришёл / Не пришёл» и столы без «Гость ушёл».
//  • тому, кто закрывает смену и может смотреть брони, список с именами приходит в ответе — приложение покажет его сразу, пока человек на месте;
//  • если это последняя открытая смена вечера, то же сообщение с именами уходит в админ-чат (одно и то же — не чаще одного раза);
//  • если смену закрыть забыли, то же сообщение уйдёт утром, после 06:00, за прошедший вечер (dayCloseMorning).
// Пусто — молчим. DAYCLOSE_REPORT=off — выключить сообщение в чат.
const DAYCLOSE_KEY = 'dayclose.state';
const DAYCLOSE_NAMES_MAX = 12;
function sitText(min) {
  if (min === null || min === undefined) return '';
  if (min < 60) return `${min} мин`;
  const h = Math.floor(min / 60), m = min % 60;
  return m ? `${h} ч ${m} мин` : `${h} ч`;
}
function ruLongDate(day) {
  const m = String(day || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return String(day || '');
  return `${Number(m[3])} ${['января', 'февраля', 'марта', 'апреля', 'мая', 'июня', 'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'][Number(m[2]) - 1]}`;
}
const placeText = (place) => !place ? '' : /^\d/.test(place) ? `стол ${place}` : place;
function dayCloseText(rep, title) {
  const cut = (list) => list.length > DAYCLOSE_NAMES_MAX ? [...list.slice(0, DAYCLOSE_NAMES_MAX), `и ещё ${list.length - DAYCLOSE_NAMES_MAX}`] : list;
  const wrap = (parts) => { const t = parts.filter(Boolean).join(', '); return t ? ` (${t})` : ''; };
  const unmarked = cut(rep.unmarked.map(x => `${x.name}${wrap([x.time, placeText(x.place)])}${x.pending ? ' — не подтверждена' : ''}`));
  const open = cut(rep.open.map(x => `${x.name}${wrap([placeText(x.place), x.sinceMin !== null ? `сидит ${sitText(x.sinceMin)}` : ''])}`));
  const lines = [`🌙 ${title} · ${ruLongDate(rep.day)}`, ''];
  lines.push(`Без отметки «Пришёл / Не пришёл»: ${rep.unmarked.length}${unmarked.length ? ` — ${unmarked.join('; ')}` : ''}`);
  lines.push(`Столы не закрыты (нет «Гость ушёл»): ${rep.open.length}${open.length ? ` — ${open.join('; ')}` : ''}`);
  lines.push('', 'Отметить можно в приложении: «Брони» → бронь → «Пришёл / Не пришёл» или «Гость ушёл».');
  return lines.join('\n');
}
const dayCloseEmpty = (rep) => !rep.unmarked.length && !rep.open.length;
// Подпись содержимого без «сидит N мин»: время идёт, а сообщение про тех же гостей повторять не нужно
const dayCloseSig = (rep) => crypto.createHash('sha1').update(JSON.stringify([rep.day, rep.unmarked.map(x => [x.name, x.time, x.place]), rep.open.map(x => [x.name, x.place])])).digest('hex').slice(0, 20);
async function dayCloseStateLoad() {
  const r = await store.db.query('SELECT value FROM settings WHERE key = $1', [DAYCLOSE_KEY]);
  return (r.rows[0] && r.rows[0].value) || {};
}
async function dayCloseStateSave(patch) {
  await store.db.query(
    `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
     ON CONFLICT (key) DO UPDATE SET value = settings.value || EXCLUDED.value, updated_at = now()`, [DAYCLOSE_KEY, JSON.stringify(patch)]);
}
// Отправить сообщение в админ-чат, если за вечер ещё не отправляли то же самое. true — отправлено.
async function dayCloseSend(rep, title) {
  if (process.env.DAYCLOSE_REPORT === 'off' || dayCloseEmpty(rep)) return false;
  const sig = dayCloseSig(rep);
  // под замком: две смены, закрытые одновременно, или закрытие вместе с утренней проверкой не должны слать одно и то же дважды
  return withKeyLock('dayclose:send', async () => {
    const st = await dayCloseStateLoad();
    if (st.sentDay === rep.day && st.sentSig === sig) return false;
    if (!(await sendAdmin(dayCloseText(rep, title), 'закрытие вечера'))) return false;
    await dayCloseStateSave({ sentDay: rep.day, sentSig: sig });
    return true;
  });
}
async function dayCloseOnShiftClose(employee) {
  const day = venueDayStr();
  const rep = await store.dayCloseReport(day);
  const others = await store.db.query(`SELECT 1 FROM shift_marks WHERE status = 'open' AND day = $1::date LIMIT 1`, [day]);
  if (!others.rows.length) await dayCloseSend(rep, 'Закрытие вечера');
  if (dayCloseEmpty(rep) || !can(employee, 'bookings.view') || !can(employee, 'bookings.mark_arrival')) return null; // список нужен тому, кто может отметить
  return {
    day,
    unmarked: rep.unmarked.map(x => ({ name: x.name, time: x.time, place: x.place })),
    open: rep.open.map(x => ({ name: x.name, place: x.place, sinceMin: x.sinceMin }))
  };
}
// Утренняя проверка: после 06:00 (до 14:00) один раз за прошедший вечер, если смену так и не закрыли или после закрытия что-то осталось
let dayCloseMorningRunning = false;
async function dayCloseMorning() {
  if (dayCloseMorningRunning || !inHoursWindow({ from: DAY_SPLIT_HOUR, to: 14 })) return;
  dayCloseMorningRunning = true;
  try {
    const day = addDaysStr(venueDayStr(), -1);
    const st = await dayCloseStateLoad();
    if (st.morningDay === day) return;
    const rep = await store.dayCloseReport(day);
    rep.open.forEach(x => { x.sinceMin = null; }); // утром «сидит 9 ч» вводило бы в заблуждение — гость мог уйти без отметки
    await dayCloseSend(rep, 'Итог вечера (утренняя проверка)');
    // вечер закрыт и пустой — отметку «проверили» ставим; не отправилось в Telegram — попробуем ещё раз при следующей проверке
    const st2 = await dayCloseStateLoad();
    if (dayCloseEmpty(rep) || (st2.sentDay === day && st2.sentSig === dayCloseSig(rep))) await dayCloseStateSave({ morningDay: day });
  } catch (e) {
    console.error('Утренняя проверка закрытия вечера:', e && e.message ? e.message : e);
  } finally {
    dayCloseMorningRunning = false;
  }
}
setInterval(dayCloseMorning, 10 * 60 * 1000).unref();
setTimeout(dayCloseMorning, 60 * 1000).unref();

// Экран «Смена» для основателя и администратора: сегодня и вчера (по дню заведения)
app.get('/api/staff/shifts', async (req, res) => {
  if (!(await checkPerm(req, res, 'shifts.review'))) return;
  try {
    const today = venueDayStr();
    const yesterday = addDaysStr(today, -1);
    const r = await store.db.query(
      `SELECT m.id, m.day::text AS day, m.opened_at, m.closed_at, m.status, m.open_check, m.close_check, e.name, ro.name AS role
       FROM shift_marks m
       JOIN employees e ON e.id = m.employee_id
       JOIN roles ro ON ro.id = e.role_id
       WHERE m.day IN ($1::date, $2::date)
       ORDER BY m.opened_at ASC LIMIT 500`, [yesterday, today]);
    const days = [{ day: yesterday, label: 'Вчера', shifts: [] }, { day: today, label: 'Сегодня', shifts: [] }];
    const byDay = Object.fromEntries(days.map(d => [d.day, d]));
    for (const m of r.rows) {
      // открыта, а день уже прошёл — человек не закрыл смену
      const status = m.status === 'open' && m.day < today ? 'forgot' : m.status;
      byDay[m.day].shifts.push({
        id: Number(m.id),
        employee: m.name,
        role: m.role,
        opened: hhmm(m.opened_at),
        closed: m.closed_at ? hhmm(m.closed_at) : null,
        minutes: m.closed_at ? Math.max(0, Math.round((new Date(m.closed_at) - new Date(m.opened_at)) / 60000)) : null,
        openCheck: checklistsDb.checkDto(m.open_check),
        closeCheck: checklistsDb.checkDto(m.close_check),
        status
      });
    }
    res.json({ days: days.reverse() });
  } catch (error) {
    console.error('Смена: список для основателя:', error);
    res.status(500).json({ error: 'Не удалось загрузить смены' });
  }
});

// ─── ПОИСК ГОСТЯ ───────────────────────────────────
// Гость = одна карточка в Postgres (раньше «Карточка Гостя» в Notion и «Общая база гостей» были двумя
// разными списками). Ищем сразу по всем.

// Строка поиска «с полной картиной» гостя, как в таблице Cosmos: сегмент, последний визит, число визитов, теги.
// Это то же, что гость видит в своей карточке (право «Гости»), нового не раскрываем. Не получилось дополнить — отдаём как было.
async function enrichSearchRows(rows) {
  if (!rows.length) return rows;
  try {
    const extras = await cardsDb.searchExtras(rows.map(r => r.id));
    return rows.map(r => {
      const e = extras.get(r.id);
      if (!e) return r;
      const seg = guestSegment(e.dates);
      const tags = (e.card.tagsSpecial || []).filter(t => { const k = String(t).trim().toLowerCase(); return k !== 'vip' && k !== 'нон-грата'; });
      return {
        ...r,
        vip: !!e.card.vip,
        nonGrata: isNonGrata(e.card),
        allergy: (e.card.tagsAllergy || []).length > 0,
        tags: tags.slice(0, 3),
        tagsMore: Math.max(0, tags.length - 3),
        segmentKey: seg.key,
        segment: seg.name,
        lastVisit: seg.lastVisit,
        daysSince: seg.daysSince,
        visitsTotal: seg.visitsTotal
      };
    });
  } catch (e) {
    console.error('Поиск: не удалось дополнить строки:', e.message);
    return rows;
  }
}

// ─── ПРЕДОХРАНИТЕЛЬ ПОИСКА ГОСТЕЙ ───────────────────
// Видимость телефонов всем ролям решена 8.10 и не меняется. Но поиск не ограничивался и не оставлял следа:
// 28 запросов за полсекунды выгружали 523 из 600 гостей с телефонами (аудит 30.10, Б1). Теперь:
//  • имя ищется от 2 знаков (приложение так и делает), знаки % и _ не работают как маски;
//  • на сотрудника не больше SEARCH_LIMIT_PER_MIN поисков в минуту (по умолчанию 30), дальше ответ 429;
//  • при серии (половина лимита за минуту) пишем в журнал действий и один раз в 10 минут сообщаем в админ-чат.
// Считаются только пропущенные запросы: отказы не продлевают паузу тому, кто просто нажал лишний раз.
const SEARCH_LIMIT_PER_MIN = Math.max(6, Number(process.env.SEARCH_LIMIT_PER_MIN) || 30);
const SEARCH_ALERT_AT = Math.ceil(SEARCH_LIMIT_PER_MIN / 2);
const SEARCH_ALERT_PAUSE_MS = 10 * 60 * 1000;
const searchWindow = new Map(); // id сотрудника → { hits: [время, ...], alertAt }
setInterval(() => {
  const old = Date.now() - 10 * 60 * 1000;
  for (const [id, w] of searchWindow) if (!w.hits.length || w.hits[w.hits.length - 1] < old) searchWindow.delete(id);
}, 10 * 60 * 1000).unref();

// Имя короче 2 знаков (не считая пробелов и масок) не ищем: такой запрос вернул бы сотню случайных гостей
function searchTooShort(q) {
  return String(q === undefined || q === null ? '' : q).replace(/[\s%_\\]/g, '').length < 2;
}

// true — можно искать. false — ответ 429 уже отправлен. Вызывать после checkPerm (нужен req.employee).
function searchAllowed(req, res) {
  const emp = req.employee;
  if (!emp) return true;
  const now = Date.now();
  const key = String(emp.id || emp.name || 'unknown');
  let w = searchWindow.get(key);
  if (!w) { w = { hits: [], alertAt: 0 }; searchWindow.set(key, w); }
  while (w.hits.length && w.hits[0] < now - 60000) w.hits.shift();
  if (w.hits.length >= SEARCH_LIMIT_PER_MIN) {
    res.setHeader('Retry-After', '30');
    res.status(429).json({ error: 'Слишком много поисков подряд. Подождите минуту и повторите.' });
    return false;
  }
  w.hits.push(now);
  if (w.hits.length >= SEARCH_ALERT_AT && now - w.alertAt > SEARCH_ALERT_PAUSE_MS) {
    w.alertAt = now;
    const who = `${emp.name || 'Сотрудник'}${emp.role ? ` (${emp.role})` : ''}`;
    auditNote(req, 'guest.search_burst', 'guest', null, `Много поисков гостей подряд: ${w.hits.length} за минуту`, { perMinute: w.hits.length, limit: SEARCH_LIMIT_PER_MIN });
    sendAdmin(`⚠️ ${who} ищет гостей слишком часто: ${w.hits.length} запросов за минуту. Больше ${SEARCH_LIMIT_PER_MIN} в минуту поиск не пропустит. Запись есть в журнале.`, 'Частый поиск гостей').catch(() => {});
  }
  return true;
}

app.get('/api/staff/search', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.view'))) return;
  const name = req.query.name;
  if (!name) return res.status(400).json({ error: 'name required' });
  if (searchTooShort(name)) return res.json([]);
  if (!searchAllowed(req, res)) return;

  try {
    res.json(await enrichSearchRows(await cardsDb.searchByName(name)));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// ─── ПРОВЕРКА ОБЩЕЙ БАЗЫ (гостевой мини-апп) ────────
// Используется когда в "Карточке Гостя" никого не нашли — вдруг человек уже бронировал через эп

app.get('/api/staff/check-general', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.view'))) return;
  const name = req.query.name;
  if (!name) return res.status(400).json({ error: 'name required' });
  if (searchTooShort(name)) return res.json([]);
  if (!searchAllowed(req, res)) return;

  try {
    // знаки % и _ в имени ищем как обычные буквы, а не как маски (раньше «%» отдавал последних 50 гостей)
    res.json(await store.searchGuestsByName(String(name).replace(/[\\%_]/g, '\\$&')));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Check failed' });
  }
});

// ─── ПОИСК ПО ТЕЛЕФОНУ ─────────────────────────────
// Надёжнее поиска по имени — имя гость мог указать неточно, а номер уникален

app.get('/api/staff/search-by-phone', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.view'))) return;
  const rawPhone = req.query.phone;
  if (!rawPhone) return res.status(400).json({ error: 'phone required' });
  if (!searchAllowed(req, res)) return;
  const phone = normalizePhone(rawPhone);

  try {
    const hit = await cardsDb.searchByPhone(phone);
    if (hit) return res.json({ inCardDb: true, id: hit.id, name: hit.name });
    // Карточка и «общая база» теперь одно и то же: нет карточки — значит гостя нет совсем
    res.json({ inCardDb: false, inGeneralDb: false });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Search by phone failed' });
  }
});

// ─── ПОИСК ПО ПОСЛЕДНИМ 4 ЦИФРАМ ───────────────────

app.get('/api/staff/search-last4', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.view'))) return;
  const digits = (req.query.digits || '').replace(/\D/g, '');
  if (digits.length !== 4) return res.status(400).json({ error: 'нужно ровно 4 цифры' });
  if (!searchAllowed(req, res)) return;

  try {
    const found = await cardsDb.searchLast4(digits);
    res.json(await enrichSearchRows(found.map(g => ({ source: 'card', id: g.id, name: g.name, phone: g.phone }))));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// ─── КАРТОЧКА ГОСТЯ + ВИЗИТЫ ───────────────────────

app.get('/api/staff/guest/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.view'))) return;
  try {
    const guest = await cardsDb.getCard(req.params.id);
    if (!guest) return res.status(404).json({ error: 'Карточка не найдена' });
    // карточку объединили с другой (или удалили) — подсказываем, какую открыть
    if (guest.archived) {
      return res.status(410).json({ error: 'Эта карточка объединена с другой или удалена', redirectId: await cardsDb.liveCardId(req.params.id) });
    }

    const phone = guest.phone;
    const tagsSpecial = guest.tagsSpecial;
    const vip = guest.vip;

    // Вся история визитов гостя (визиты не удаляются) — нужна и для списка "последние визиты",
    // и для расчёта риска оттока, и для подсчёта частоты кальянов (любимая позиция)
    const allVisits = await cardsDb.guestVisits(guest.id);
    const visits = allVisits.slice(0, 5);

    // ── Сегмент по визитам и автотег «Риск оттока» — те же формулы, что в таблице гостей ──
    const segment = guestSegment(visitDatesByGuest(allVisits.map(v => ({ guestId: guest.id, date: v.date }))).get(guest.id));
    const daysSince = segment.daysSince;
    const atRisk = isAtRisk(segment, vip);

    // ── Автотег «Негативный отзыв» — по карточке гостя (и по телефону для отзывов без карточки) ──
    let negativeReview = null;
    try {
      negativeReview = await feedback.latestNegativeReview({ guestId: guest.id, phone: phone || null });
    } catch (e) { console.error('Negative review check failed:', e); }

    // ── Любимая позиция — самый частый вкус кальяна среди всех визитов ──
    const hookahCounts = {};
    let visitsWithHookah = 0;
    for (const v of allVisits) {
      // за вечер могли взять два кальяна: «Мята + Персик» — считаем каждый
      const flavors = hookahParts(v.hookah);
      if (!flavors.length) continue;
      visitsWithHookah++;
      for (const flavor of flavors) {
        const key = flavor.toLowerCase();
        if (!hookahCounts[key]) hookahCounts[key] = { name: flavor, count: 0 };
        hookahCounts[key].count++;
      }
    }
    const topHookah = Object.values(hookahCounts).sort((a, b) => b.count - a.count)[0] || null;

    // ── Пол, возраст, «с нами», показатели (карточка в стиле Cosmos). Не получилось посчитать — карточка открывается без них ──
    let profile = null;
    try { profile = await cardsDb.guestProfile(guest.id); } catch (e) { console.error('Профиль гостя:', e.message); }
    const today = venueDateStr();
    const firstVisit = allVisits.length ? allVisits[allVisits.length - 1].date : null;   // визиты идут от свежих к старым
    const firstSeen = [profile && profile.createdDay, firstVisit].filter(Boolean).map(d => String(d).slice(0, 10)).sort()[0] || null;
    const sinceDays = firstSeen ? Math.max(0, daysBetween(firstSeen, today)) : null;
    const byMonthMap = new Map(((profile && profile.visitsByMonth) || []).map(m => [m.ym, m.n]));
    const visitsByMonth = [];
    { let y = Number(today.slice(0, 4)), mo = Number(today.slice(5, 7));
      for (let i = 0; i < 12; i++) {
        const ym = `${y}-${String(mo).padStart(2, '0')}`;
        visitsByMonth.unshift({ ym, n: byMonthMap.get(ym) || 0 });
        mo--; if (mo === 0) { mo = 12; y--; }
      } }
    const visits12 = visitsByMonth.reduce((a, m) => a + m.n, 0);
    const monthsOfHistory = firstVisit ? Math.min(12, Math.max(1, Math.ceil(daysBetween(String(firstVisit).slice(0, 10), today) / 30.4))) : 1;

    const stayInfo = stayTag(profile && profile.arrivals);
    const atView = autotagView(req.employee);
    const shownAt = (k) => !atView.hidden.includes(k);

    res.json({
      id: guest.id,
      name: guest.firstName,                // только имя — его правим в карточке
      surname: guest.surname,               // фамилия — необязательная
      fullName: guest.name,                 // «Имя Фамилия» — для показа
      vip,
      segment: segmentPublic(segment),
      segmentGuide: SEGMENTS.map(s => ({ key: s.key, name: s.name, description: s.description })),
      segmentRules: { ...SEGMENT_RULES },
      birthday: guest.birthday,
      birthYear: profile ? profile.birthYear : null,   // настоящий год рождения (пусто — не знаем); в birthday год тогда условный 2000
      age: guestAge(profile ? profile.birthYear : null, guest.birthday, today),
      gender: profile ? profile.gender : '',
      since: { day: firstSeen, days: sinceDays },
      stats: {
        visitsTotal: allVisits.length,
        visits12,
        perMonth: Math.round(visits12 / monthsOfHistory * 10) / 10,   // визитов в месяц: за последний год (или за всё время, если гость новее)
        byMonth: visitsByMonth,
        bookings: profile ? profile.bookings : null,
        stay: { avgMin: stayInfo.avgMin, n: stayInfo.n, series: stayInfo.series },
        arrivalsN: profile ? (profile.arrivals || []).length : 0
      },
      phone,
      important: guest.important,
      tagsSpecial,
      tagsAllergy: guest.tagsAllergy,
      tastesLike: guest.tastesLike,
      tastesDislike: guest.tastesDislike,
      // выключенные в «Сервис → Автотеги» (и скрытые от официантов) не отдаём; hidden и cfg нужны приложению для названий, цветов, подсказок
      autoTags: {
        atRisk: shownAt('atRisk') ? atRisk : false, daysSince,
        negativeReview: shownAt('negativeReview') ? negativeReview : null,
        birthday: shownAt('birthday') ? birthdayInfo(guest.birthday) : null,
        visitTime: shownAt('visitTime') ? visitTimeTag(profile && profile.arrivals) : null,
        stay: shownAt('stay') ? stayInfo.tag : null,
        hidden: atView.hidden, cfg: atView.cfg
      },
      favorites: { hookah: shownAt('favorite') && topHookah && topHookah.count >= AUTOTAGS.favorite.minCount ? topHookah : null, visitsWithHookah, totalVisits: allVisits.length },
      bookingStats: (await store.guestBookingStats([guest.id]).catch(() => new Map())).get(guest.id) || { noShows: 0, guestCancels: 0, came: 0, lastNoShow: null },
      // История изменений — только тем, у кого есть право guests.history (по умолчанию основатель и администратор)
      history: can(req.employee, 'guests.history') ? await cardsDb.guestHistory(guest.id, 30) : [],
      visits
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch guest' });
  }
});

// ─── ФОТО ГОСТЯ ИЗ TELEGRAM ─────────────────────────
// В "Карточке Гостя" (CRM) Telegram ID не хранится — его пишет гостевой мини-апп
// в "Общую базу гостей" при бронировании/заполнении профиля. Поэтому сначала находим
// гостя там же по телефону, а дальше — обычный Bot API: getUserProfilePhotos → getFile.
// Ссылка от Telegram живёт около часа, поэтому недолго кэшируем её в памяти,
// чтобы не дёргать Bot API на каждое открытие одной и той же карточки подряд.

const guestPhotoCache = new Map(); // telegramId -> { url, expiresAt }
const GUEST_PHOTO_FOUND_TTL = 5 * 60 * 1000;  // 5 минут — чтобы смена аватарки в Telegram быстро подхватывалась
const GUEST_PHOTO_EMPTY_TTL = 30 * 60 * 1000; // 30 минут — если фото нет вообще, не дёргаем Bot API так часто

async function fetchTelegramPhotoUrl(telegramId, force) {
  if (!telegramId || !TELEGRAM_BOT_TOKEN) return null;

  const cached = guestPhotoCache.get(telegramId);
  if (!force && cached && cached.expiresAt > Date.now()) return cached.url;

  const photos = await tgApi('getUserProfilePhotos', { user_id: telegramId, limit: 1 });
  const firstSet = photos?.result?.photos?.[0];
  if (!firstSet || !firstSet.length) {
    guestPhotoCache.set(telegramId, { url: null, expiresAt: Date.now() + GUEST_PHOTO_EMPTY_TTL });
    return null;
  }

  const fileId = firstSet[firstSet.length - 1].file_id; // последний элемент — самый крупный размер
  const fileInfo = await tgApi('getFile', { file_id: fileId });
  const filePath = fileInfo?.result?.file_path;
  if (!filePath) return null;

  // Раньше отдавали ссылку https://api.telegram.org/file/bot<ТОКЕН>/… — токен бота
  // оказывался на телефонах персонала. Теперь отдаём ключ, по которому наш же
  // сервер сам скачает картинку (см. /api/staff/photo-file/:key ниже).
  const key = crypto.randomBytes(16).toString('hex');
  photoFiles.set(key, { filePath, expiresAt: Date.now() + 60 * 60 * 1000 });
  if (photoFiles.size > 2000) photoFiles.delete(photoFiles.keys().next().value);
  guestPhotoCache.set(telegramId, { url: key, expiresAt: Date.now() + GUEST_PHOTO_FOUND_TTL });
  return key;
}
const photoFiles = new Map(); // случайный ключ -> { filePath, expiresAt }

// Картинка по ключу. Без PIN (её грузит <img>), но ключ случайный и живёт час.
app.get('/api/staff/photo-file/:key', async (req, res) => {
  const f = photoFiles.get(String(req.params.key || ''));
  if (!f || f.expiresAt < Date.now()) return res.status(404).end();
  try {
    const r = await fetch(`https://api.telegram.org/file/bot${TELEGRAM_BOT_TOKEN}/${f.filePath}`);
    if (!r.ok) return res.status(404).end();
    res.set('Content-Type', /\.png$/i.test(f.filePath) ? 'image/png' : 'image/jpeg');
    res.set('Cache-Control', 'private, max-age=3600');
    res.send(await r.buffer());
  } catch (e) {
    res.status(404).end();
  }
});
function photoFileUrl(req, key) {
  if (!key) return null;
  const proto = (req.get('x-forwarded-proto') || req.protocol || 'https').split(',')[0].trim();
  return `${proto}://${req.get('host')}/api/staff/photo-file/${key}`;
}

app.get('/api/staff/guest/:id/photo', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.view'))) return;
  try {
    const guest = await cardsDb.getCard(req.params.id);
    if (!guest || !guest.phone) return res.json({ photoUrl: null });

    const telegramId = guest.telegramId || (await store.telegramIdByPhone(guest.phone)) || null;
    if (!telegramId) return res.json({ photoUrl: null });


    const key = await fetchTelegramPhotoUrl(telegramId, req.query.force === '1');
    res.json({ photoUrl: photoFileUrl(req, key) });
  } catch (error) {
    console.error('Guest photo fetch failed:', error);
    res.json({ photoUrl: null }); // не критично — карточка просто останется с инициалами
  }
});

// ─── РЕДАКТИРОВАНИЕ КАРТОЧКИ ───────────────────────
// Все изменения пишутся в журнал карточки (кто, когда, что) — он виден в самой карточке.

// Полный номер — только российский: +7 и 10 цифр («8…» и «+7…» — один номер)
function isFullPhone(norm) {
  return /^\+7\d{10}$/.test(String(norm || ''));
}
function cleanNamePart(v, max = 100) {
  return String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, max);
}
function normName(name) {
  return String(name || '').toLowerCase().replace(/ё/g, 'е').replace(/\s+/g, ' ').trim();
}
const hookahParts = cardsDb.hookahParts;

// Карточки с их сегментами — чтобы по списку было понятно, какая из них «настоящая»
async function summarizeCards(list) {
  const dates = visitDatesByGuest(await getVisitsQuick());
  return list.map(c => {
    const seg = guestSegment(dates.get(c.id));
    return {
      id: c.id, name: c.name, phone: c.phone, vip: c.vip, created: c.created, sharedPhone: c.sharedPhone,
      birthday: c.birthday, important: c.important,
      segmentKey: seg.key, segment: seg.name, visitsTotal: seg.visitsTotal, lastVisit: seg.lastVisit,
      tagsSpecial: c.tagsSpecial, tagsAllergy: c.tagsAllergy, tastesLike: c.tastesLike, tastesDislike: c.tastesDislike
    };
  });
}

function afterCardChange() {
  forgetMemo('duplicates'); // счётчик групп дублей (точка на главной и плашки «Сервиса») пересчитается сразу
  forgetMemo('marketing'); // брони, рассылки и списки сразу покажут новые данные гостя
  forgetMemo('stats');
  forgetMemo('feedback:reviews'); // отзывы показываются у главной карточки после объединения
}

app.patch('/api/staff/guest/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.edit'))) return;
  const { field, value } = req.body;

  // Статуса «VIP / Постоянный / Редкий» больше нет: сегмент считается сам по визитам,
  // VIP — ручной тег (ставит только администрация, см. /tag).
  if (field === 'status') return res.status(400).json({ error: 'Статус теперь не меняется вручную: сегмент считается по визитам, VIP — тег в «Особых»' });
  if (!['name', 'birthday', 'phone', 'important', 'gender'].includes(field)) return res.status(400).json({ error: 'unknown field' });
  if (field === 'birthday' && value && !isRealBirthdayStr(value)) return res.status(400).json({ error: 'Неверная дата рождения' });
  if (field === 'gender' && value && value !== 'male' && value !== 'female') return res.status(400).json({ error: 'Неверное значение пола' });
  // Год рождения приходит отдельно (birthYear): так записывается и 2000-й, а «пусто» значит «год не знаем». Не прислали — как раньше.
  let birthYear;
  if (field === 'birthday' && Object.prototype.hasOwnProperty.call(req.body, 'birthYear')) {
    const by = req.body.birthYear;
    if (by === '' || by === null) birthYear = null;
    else {
      const n = Number(by);
      if (!Number.isInteger(n) || n < 1900 || n > Number(venueDateStr().slice(0, 4)) - 10) return res.status(400).json({ error: 'Неверный год рождения' });
      birthYear = n;
      const leap = (n % 4 === 0 && n % 100 !== 0) || n % 400 === 0;
      if (value && String(value).slice(5, 10) === '02-29' && !leap) return res.status(400).json({ error: `29 февраля бывает только в високосный год — ${n}-й таким не был` });
    }
  }

  try {
    // Телефон обязателен и один на карточку: занят другой карточкой — 409 со списком
    // (второй карточки на один номер нет — дубли объединяют на экране «Дубли»).
    if (field === 'phone') {
      const phoneNorm = normalizePhone(typeof value === 'string' ? value : '');
      if (!isFullPhone(phoneNorm)) return res.status(400).json({ error: 'Укажите телефон полностью — без телефона карточку не оставляем' });
      const result = await withKeyLock(`card-phone:${phoneNorm}`, () =>
        cardsDb.updateField(req.params.id, 'phone', phoneNorm, { actor: req.employee }));
      if (result.http === 409 && result.existing) {
        return res.status(409).json({ error: result.error, duplicates: await summarizeCards(result.existing), canForce: false });
      }
      if (result.http) return res.status(result.http).json({ error: result.error });
      afterCardChange();
      return res.json({ ok: true });
    }
    const result = await cardsDb.updateField(req.params.id, field, value, { surname: req.body.surname, actor: req.employee, birthYear });
    if (result.http) return res.status(result.http).json({ error: result.error });
    afterCardChange();
    res.json({ ok: true });
  } catch (error) {
    console.error('Guest update failed:', error.message);
    res.status(500).json({ error: 'Не удалось сохранить изменение — попробуйте ещё раз' });
  }
});

// ─── РУЧНЫЕ ТЕГИ — добавление и удаление по одному ──
// Группы: особые, аллергии и «Табак / вкусы» (что гость любит и что не любит —
// чтобы любой кальянный мастер, даже новый, сразу знал, что предлагать, а что нет).
// Теги — данные (таблицы tags / guest_tags): VIP, «Знаменитость» и «Нон-грата» ставят и снимают
// только выбранные роли (администратор, основатель), остальные — любой сотрудник.

app.post('/api/staff/guest/:id/tag', async (req, res) => {
  if (!(await checkPerm(req, res, 'tags.use'))) return;
  const { group, tag, action } = req.body;
  // при добавлении — без угловых скобок; при снятии название не трогаем, чтобы можно было убрать любой старый тег
  const tagName = String((action === 'add' ? plainName(tag) : tag) || '').replace(/,/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);

  try {
    const result = await cardsDb.setTag({ id: req.params.id, group, tag: tagName, action, actor: req.employee });
    if (result.http) return res.status(result.http).json({ error: result.error });
    afterCardChange();
    res.json({ ok: true, tags: result.tags, history: can(req.employee, 'guests.history') ? result.history : [] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update tag' });
  }
});

// ─── ТЕГИ: СПИСОК, ЦВЕТА, ПОДСКАЗКИ, ПРАВИЛА (Сервис → Теги) ──
// Каталог для карточки гостя читает любой сотрудник; менять список — право tags.manage (по умолчанию основатель).

function sendTagError(res, e, fallback) {
  if (e instanceof tagsDb.TagError) return res.status(e.status).json({ error: e.message });
  console.error(e);
  res.status(500).json({ error: fallback });
}

app.get('/api/staff/tags', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try {
    res.json(await tagsDb.catalog());
  } catch (error) {
    sendTagError(res, error, 'Не удалось загрузить теги');
  }
});

app.get('/api/admin/tags', async (req, res) => {
  if (!(await checkPerm(req, res, 'tags.manage'))) return;
  try {
    res.json(await tagsDb.adminList());
  } catch (error) {
    sendTagError(res, error, 'Не удалось загрузить теги');
  }
});

app.post('/api/admin/tags', async (req, res) => {
  if (!(await checkPerm(req, res, 'tags.manage'))) return;
  try {
    const tag = await tagsDb.createTag(req.body, req.employee);
    afterCardChange();
    res.json({ ok: true, tag });
  } catch (error) {
    sendTagError(res, error, 'Не удалось добавить тег');
  }
});

app.patch('/api/admin/tags/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'tags.manage'))) return;
  try {
    const tag = await tagsDb.updateTag(req.params.id, req.body, req.employee);
    afterCardChange();
    res.json({ ok: true, tag });
  } catch (error) {
    sendTagError(res, error, 'Не удалось сохранить тег');
  }
});

app.post('/api/admin/tags/:id/merge', async (req, res) => {
  if (!(await checkPerm(req, res, 'tags.manage'))) return;
  try {
    const result = await tagsDb.mergeTag(req.params.id, String(req.body?.intoId || ''), req.employee);
    afterCardChange();
    res.json(result);
  } catch (error) {
    sendTagError(res, error, 'Не удалось объединить теги');
  }
});

app.post('/api/admin/tags/:id/move', async (req, res) => {
  if (!(await checkPerm(req, res, 'tags.manage'))) return;
  try {
    res.json(await tagsDb.moveTag(req.params.id, req.body?.dir));
  } catch (error) {
    sendTagError(res, error, 'Не удалось сдвинуть тег');
  }
});

app.delete('/api/admin/tags/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'tags.manage'))) return;
  try {
    const result = await tagsDb.deleteTag(req.params.id, req.employee);
    afterCardChange();
    res.json(result);
  } catch (error) {
    sendTagError(res, error, 'Не удалось удалить тег');
  }
});

// ─── СТАНДАРТЫ СЕРВИСА И ОБУЧЕНИЕ ───────────────────
// Читает любой сотрудник (по своей роли), пишет и смотрит «кто прочитал» — право standards.manage.
// Правильные ответы теста сотруднику не отправляются: ответы проверяет сервер.
function sendStandardError(res, e, fallback) {
  if (e instanceof standardsDb.StandardError) return res.status(e.status).json({ error: e.message, ...(e.extra || {}) });
  console.error(e);
  res.status(500).json({ error: fallback });
}

app.get('/api/staff/standards', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try {
    res.json(await standardsDb.staffList(req.employee));
  } catch (error) {
    sendStandardError(res, error, 'Не удалось загрузить стандарты');
  }
});

app.post('/api/staff/standards/:id/ack', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try {
    res.json(await standardsDb.ack(req.employee, req.params.id, req.body));
  } catch (error) {
    sendStandardError(res, error, 'Не удалось сохранить отметку');
  }
});

app.get('/api/admin/standards', async (req, res) => {
  if (!(await checkPerm(req, res, 'standards.manage'))) return;
  try {
    res.json(await standardsDb.adminList());
  } catch (error) {
    sendStandardError(res, error, 'Не удалось загрузить стандарты');
  }
});

app.get('/api/admin/standards/:id/progress', async (req, res) => {
  if (!(await checkPerm(req, res, 'standards.manage'))) return;
  try {
    res.json(await standardsDb.progress(req.params.id));
  } catch (error) {
    sendStandardError(res, error, 'Не удалось загрузить, кто прочитал');
  }
});

app.post('/api/admin/standards', async (req, res) => {
  if (!(await checkPerm(req, res, 'standards.manage'))) return;
  try {
    res.json(await standardsDb.create(req.body, req.employee));
  } catch (error) {
    sendStandardError(res, error, 'Не удалось создать стандарт');
  }
});

app.patch('/api/admin/standards/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'standards.manage'))) return;
  try {
    res.json(await standardsDb.update(req.params.id, req.body, req.employee));
  } catch (error) {
    sendStandardError(res, error, 'Не удалось сохранить стандарт');
  }
});

app.delete('/api/admin/standards/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'standards.manage'))) return;
  try {
    res.json(await standardsDb.remove(req.params.id, req.employee));
  } catch (error) {
    sendStandardError(res, error, 'Не удалось удалить стандарт');
  }
});

// ─── ЧЕК-ЛИСТЫ СМЕНЫ: редактор ──────────────────────
// Пункты «Открытие» и «Закрытие» для каждой роли. Правит тот, у кого есть право checklists.manage.
// Сотрудник свой список получает через GET /api/staff/shift/checklist (см. раздел «Смена»).
app.get('/api/admin/checklists', async (req, res) => {
  if (!(await checkPerm(req, res, 'checklists.manage'))) return;
  try {
    res.json(await checklistsDb.adminList());
  } catch (error) {
    console.error('Чек-листы: не удалось загрузить:', error);
    res.status(500).json({ error: 'Не удалось загрузить чек-листы' });
  }
});

app.put('/api/admin/checklists/:roleKey', async (req, res) => {
  if (!(await checkPerm(req, res, 'checklists.manage'))) return;
  try {
    res.json(await checklistsDb.saveRole(req.params.roleKey, req.body, req.employee));
  } catch (error) {
    if (sendChecklistError(res, error)) return;
    console.error('Чек-листы: не удалось сохранить:', error);
    res.status(500).json({ error: 'Чек-лист не сохранился — попробуйте ещё раз' });
  }
});

// ─── ТАБАК: справочник вкусов и граммы ──────────────
// Справочник читают и пополняют все, кто отмечает визиты (visits.record); приход, списание, пересчёт и правки — право tobacco.manage.
// Расход на кальян пишется при сохранении визита (POST /api/staff/visit, поле tobacco). Подробности — db/tobacco.js.
function sendTobaccoError(res, e) {
  if (e instanceof tobaccoDb.TobaccoError) return res.status(e.status).json({ error: e.message, ...(e.extra || {}) });
  return false;
}

app.get('/api/staff/tobacco', async (req, res) => {
  if (!(await checkPerm(req, res, ['visits.record', 'tobacco.manage']))) return;
  try {
    res.json(await tobaccoDb.catalog({ withStock: can(req.employee, 'tobacco.manage') }));
  } catch (error) {
    console.error('Табак: не удалось загрузить справочник:', error);
    res.status(500).json({ error: 'Не удалось загрузить справочник табака' });
  }
});

app.post('/api/staff/tobacco/flavor', async (req, res) => {
  if (!(await checkPerm(req, res, ['visits.record', 'tobacco.manage']))) return;
  try {
    const r = await tobaccoDb.addFlavor(req.body, req.employee);
    // граммы и остаток — только тем, кто ведёт учёт
    if (!can(req.employee, 'tobacco.manage') && r.flavor) {
      const { grams, minGrams, used30, lastMovementAt, ...open } = r.flavor;
      r.flavor = open;
    }
    res.json(r);
  } catch (error) {
    if (sendTobaccoError(res, error)) return;
    console.error('Табак: вкус не добавился:', error);
    res.status(500).json({ error: 'Вкус не добавился — попробуйте ещё раз' });
  }
});

app.put('/api/staff/tobacco/flavor/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await tobaccoDb.updateFlavor(req.params.id, req.body, req.employee));
  } catch (error) {
    if (sendTobaccoError(res, error)) return;
    console.error('Табак: вкус не сохранился:', error);
    res.status(500).json({ error: 'Изменения не сохранились — попробуйте ещё раз' });
  }
});

app.put('/api/staff/tobacco/brand/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await tobaccoDb.renameBrand(req.params.id, (req.body || {}).name, req.employee));
  } catch (error) {
    if (sendTobaccoError(res, error)) return;
    console.error('Табак: бренд не переименован:', error);
    res.status(500).json({ error: 'Название не сохранилось — попробуйте ещё раз' });
  }
});

app.post('/api/staff/tobacco/move', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await tobaccoDb.move(req.body, req.employee));
  } catch (error) {
    if (sendTobaccoError(res, error)) return;
    console.error('Табак: запись граммов не сохранилась:', error);
    res.status(500).json({ error: 'Запись не сохранилась — попробуйте ещё раз' });
  }
});

app.get('/api/staff/tobacco/flavor/:id/history', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await tobaccoDb.history(req.params.id, req.query.limit));
  } catch (error) {
    if (sendTobaccoError(res, error)) return;
    console.error('Табак: история не загрузилась:', error);
    res.status(500).json({ error: 'Не удалось загрузить историю' });
  }
});

app.put('/api/staff/tobacco/bowl', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await tobaccoDb.setBowl(req.body || {}, req.employee));
  } catch (error) {
    if (sendTobaccoError(res, error)) return;
    console.error('Табак: граммы по чаше не сохранились:', error);
    res.status(500).json({ error: 'Не сохранилось — попробуйте ещё раз' });
  }
});

app.post('/api/staff/tobacco/import', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await tobaccoDb.importList((req.body || {}).items, req.employee));
  } catch (error) {
    if (sendTobaccoError(res, error)) return;
    console.error('Табак: список не загрузился:', error);
    res.status(500).json({ error: 'Список не загрузился — попробуйте ещё раз' });
  }
});

// ─── УГЛИ: позиции и коробки ────────────────────────
// Всё — по праву tobacco.manage (основатель, администратор, КМ). Подробности — db/coals.js.
function sendCoalsError(res, e) {
  if (e instanceof coalsDb.CoalError) return res.status(e.status).json({ error: e.message, ...(e.extra || {}) });
  return false;
}

app.get('/api/staff/coals', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await coalsDb.catalog());
  } catch (error) {
    console.error('Угли: не удалось загрузить список:', error);
    res.status(500).json({ error: 'Не удалось загрузить список углей' });
  }
});

app.post('/api/staff/coals/item', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await coalsDb.addItem(req.body, req.employee));
  } catch (error) {
    if (sendCoalsError(res, error)) return;
    console.error('Угли: позиция не добавилась:', error);
    res.status(500).json({ error: 'Не добавилось — попробуйте ещё раз' });
  }
});

app.put('/api/staff/coals/item/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await coalsDb.updateItem(req.params.id, req.body, req.employee));
  } catch (error) {
    if (sendCoalsError(res, error)) return;
    console.error('Угли: позиция не сохранилась:', error);
    res.status(500).json({ error: 'Не сохранилось — попробуйте ещё раз' });
  }
});

app.post('/api/staff/coals/move', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await coalsDb.move(req.body, req.employee));
  } catch (error) {
    if (sendCoalsError(res, error)) return;
    console.error('Угли: запись коробок не сохранилась:', error);
    res.status(500).json({ error: 'Запись не сохранилась — попробуйте ещё раз' });
  }
});

app.get('/api/staff/coals/item/:id/history', async (req, res) => {
  if (!(await checkPerm(req, res, 'tobacco.manage'))) return;
  try {
    res.json(await coalsDb.history(req.params.id, req.query.limit));
  } catch (error) {
    if (sendCoalsError(res, error)) return;
    console.error('Угли: история не загрузилась:', error);
    res.status(500).json({ error: 'Не удалось загрузить историю' });
  }
});

// ─── НОВЫЙ ГОСТЬ ────────────────────────────────────

app.post('/api/staff/guest', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.create'))) return;
  // Статус больше не задаётся: сегмент посчитается сам после первого визита,
  // VIP администратор ставит тегом. Старое приложение ещё может прислать status — игнорируем.
  const { birthday, phone, important } = req.body;
  const name = cleanNamePart(req.body.name);
  const surname = cleanNamePart(req.body.surname); // необязательная
  if (!name) return res.status(400).json({ error: 'name required' });
  // Карточку без телефона не создаём: по номеру она связывается с бронями, ботом и отзывами,
  // и по нему же ловим дубли.
  const phoneNorm = normalizePhone(typeof phone === 'string' ? phone : '');
  if (!isFullPhone(phoneNorm)) return res.status(400).json({ error: 'Укажите телефон гостя полностью — без телефона карточку не создаём', field: 'phone' });
  if (birthday && !isRealBirthdayStr(birthday)) return res.status(400).json({ error: 'Неверная дата рождения' });

  // Один номер — один гость. Уже есть — 409 со списком карточек (кнопки «создать отдельно» нет).
  // Очередь по номеру — чтобы два сотрудника одновременно не создали двух одинаковых гостей.
  try {
    const result = await withKeyLock(`card-phone:${phoneNorm}`, () =>
      cardsDb.createCard({ name, surname, birthday, phone: phoneNorm, important: typeof important === 'string' ? important : '', actor: req.employee }));
    if (result.http === 409) {
      return res.status(409).json({ error: result.error, duplicates: await summarizeCards(result.existing || []), canForce: false });
    }
    afterCardChange();
    res.json({ ok: true, id: result.id });
  } catch (error) {
    console.error('Create guest failed:', error.message);
    res.status(500).json({ error: 'Не удалось создать карточку — попробуйте ещё раз' });
  }
});

// ─── ДУБЛИ КАРТОЧЕК: ОДИН ГОСТЬ — ОДНА КАРТОЧКА ────
// Карточку без телефона не создаём, телефон в карточке один на гостя (база сама не даёт завести
// две обычные карточки на один номер). Дубли, которые всё же есть (карточка без полного номера
// с тем же именем), администратор объединяет на экране «Дубли»: визиты и брони переезжают
// в главную карточку (в один вечер — сливаются), теги и согласия объединяются, вторая
// карточка уходит в архив со ссылкой на главную.

async function buildDuplicates() {
    const summaries = await summarizeCards(await cardsDb.allCards());
    const byPhone = new Map();
    const noPhone = [];
    for (const c of summaries) {
      const norm = normalizePhone(c.phone || '');
      if (!isFullPhone(norm)) { noPhone.push(c); continue; }
      if (!byPhone.has(norm)) byPhone.set(norm, []);
      byPhone.get(norm).push(c);
    }
    // сначала больше визитов, при равенстве — раньше созданная
    const order = (a, b) => (b.visitsTotal - a.visitsTotal) || String(a.created || '').localeCompare(String(b.created || ''));
    // группа — дубль, если в ней хотя бы две карточки не помечены «Общий номер»
    // дубль — две и больше живые карточки на одном номере, если админ не отметил «это разные люди»
    const notDup = await cardsDb.notDuplicatePairs();
    const isPairMarked = (a, b) => notDup.has(a.id < b.id ? `${a.id}|${b.id}` : `${b.id}|${a.id}`);
    const hasUnmarkedPair = list => list.some((a, i) => list.slice(i + 1).some(b => !isPairMarked(a, b)));
    const groups = [...byPhone.entries()]
      .filter(([, list]) => list.length > 1 && hasUnmarkedPair(list))
      .map(([phone, list]) => ({
        phone,
        // «общий номер» в списке — только у тех, кого админ отметил «разные люди» со всеми остальными на номере
        cards: list.sort(order).map(c => ({ ...c, sharedPhone: list.every(o => o === c || isPairMarked(c, o)) }))
      }))
      .sort((a, b) => b.cards.length - a.cards.length || a.cards[0].name.localeCompare(b.cards[0].name, 'ru'));
    const withPhoneByName = new Map();
    for (const list of byPhone.values()) for (const c of list) {
      const k = normName(c.name);
      if (!k) continue;
      if (!withPhoneByName.has(k)) withPhoneByName.set(k, []);
      withPhoneByName.get(k).push(c);
    }
    return {
      groups,
      noPhone: noPhone
        .map(c => ({ card: c, sameName: (withPhoneByName.get(normName(c.name)) || []).sort(order) }))
        .sort((a, b) => b.sameName.length - a.sameName.length || a.card.name.localeCompare(b.card.name, 'ru'))
    };
}

// Сколько групп дублей — для точки на главном экране и плашек «Сервиса». Поиск дублей читает всех гостей и все визиты,
// а это число спрашивают при каждом входе на главную и в «Сервис» (раньше — каждый раз заново, и экран «зависал»).
// Держим ответ 20 секунд; любое изменение карточек (afterCardChange) сбрасывает его сразу. Сам экран «Дубли» всегда считает заново.
function duplicateGroupsCount() {
  return memo('duplicates:count', 20 * 1000, async () => (await buildDuplicates()).groups.length);
}

app.get('/api/admin/guests/duplicates', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.merge'))) return;
  try {
    res.json(await buildDuplicates());
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось найти дубли' });
  }
});

// «Это разные люди»: пометить карточки группы как «Общий номер» (кроме главной) — группа
// перестанет показываться в дублях.
app.post('/api/admin/guests/not-duplicates', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.merge'))) return;
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.filter(x => typeof x === 'string' && x).slice(0, 20) : [];
  if (!ids.length) return res.status(400).json({ error: 'Нет карточек' });
  try {
    const result = await cardsDb.markNotDuplicates(ids, req.employee);
    if (result.http) return res.status(result.http).json({ error: result.error });
    afterCardChange();
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить отметку' });
  }
});

// Объединить карточку otherId в mainId. fields — что взять, если в карточках по-разному:
// { name, phone, birthday, important } (строки; не указано — берём из главной, пустое — из второй).
app.post('/api/admin/guests/merge', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.merge'))) return;
  const { mainId, otherId, fields = {} } = req.body || {};
  if (typeof mainId !== 'string' || typeof otherId !== 'string' || !mainId || !otherId || mainId === otherId) {
    return res.status(400).json({ error: 'Нужны две разные карточки' });
  }
  try {
    // одно объединение за раз
    const result = await withKeyLock('guests-merge', () => cardsDb.mergeCards({ mainId, otherId, fields, actor: req.employee }));
    if (result.http) return res.status(result.http).json({ error: result.error });
    // «недавно спрашивали отзыв» — теперь про главную карточку
    const askedOther = reviewAskedAt.get(otherId);
    if (askedOther && (!reviewAskedAt.get(mainId) || askedOther > reviewAskedAt.get(mainId))) reviewAskedAt.set(mainId, askedOther);
    reviewAskedAt.delete(otherId);
    afterCardChange();
    res.json(result);
  } catch (error) {
    if (error && error.code === '23505') return res.status(409).json({ error: 'Этот номер уже записан у другой карточки — объединение отменено, ничего не изменилось' });
    console.error('Merge failed:', error.message);
    res.status(500).json({ error: 'Объединение прервалось — попробуйте ещё раз: всё сделанное откатилось целиком.' });
  }
});

// Удалить карточку гостя — только основатель. Карточка уходит в архив (визиты и брони остаются в аналитике).
app.post('/api/admin/guests/delete', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.delete'))) return;
  const id = typeof req.body?.id === 'string' ? req.body.id : '';
  if (!id) return res.status(400).json({ error: 'Нет карточки' });
  try {
    const result = await withKeyLock('guests-merge', async () => cardsDb.deleteCard({ id, actor: req.employee, serviceId: await store.walkInGuestId(false) }));
    if (result.http) return res.status(result.http).json({ error: result.error });
    reviewAskedAt.delete(id);
    forgetMemo('analytics:bookings');
    afterCardChange();
    const last4 = String(result.phone || '').replace(/\D/g, '').slice(-4);
    auditNote(req, 'guest.deleted', 'guest', id, `удалена карточка гостя: ${result.name}${last4 ? `, телефон …${last4}` : ''}`);
    res.json({ ok: true, name: result.name });
  } catch (error) {
    console.error('Guest delete failed:', error.message);
    res.status(502).json({ error: 'Не удалось удалить карточку — попробуйте ещё раз' });
  }
});

// ─── ДОБАВИТЬ / ДОПОЛНИТЬ ВИЗИТ ─────────────────────
// Визиты хранятся все. Визит — это «гость был в этот день», кальян не обязателен (гость мог
// прийти только в бар или на кухню). Один визит на гостя в сутки (это держит сама база):
// повторная запись дополняет его — второй кальян дописывается через « + », пустой кальян
// старый не стирает. Если запись не прошла — честно отвечаем ошибкой.

// Очередь по ключу: одновременные действия с одним гостем/бронью идут по одному,
// чтобы двойное нажатие не создало два визита или две карточки.
const keyLocks = new Map();
function withKeyLock(key, fn) {
  const prev = keyLocks.get(key) || Promise.resolve();
  const run = prev.then(fn, fn);
  const tail = run.catch(() => {});
  keyLocks.set(key, tail);
  tail.then(() => { if (keyLocks.get(key) === tail) keyLocks.delete(key); });
  return run;
}

// Кто создал визит: «Бронь» — отметка «Пришёл» у брони, «Сотрудник» — «Добавить визит»
// в карточке. Нужно, чтобы снятие отметки «Пришёл» убирало только визит, который создала
// сама отметка и который никто из персонала не подтвердил.

// Записать визит гостя за день. Возвращает { id, created }; бросает ошибку, если не записалось.
// source: 'staff' (по умолчанию) или 'booking'.
async function recordVisit({ guestId, date, hookah, notes, source = 'staff', employee }) {
  try {
    return await cardsDb.recordVisit({ guestId, day: date, hookah, notes, source, actor: employee });
  } finally {
    forgetMemo('stats');
  }
}

app.post('/api/staff/visit', async (req, res) => {
  if (!(await checkPerm(req, res, 'visits.record'))) return;
  const { guestId, hookah, notes, tobacco } = req.body || {};
  if (!guestId || typeof guestId !== 'string') return res.status(400).json({ error: 'guestId required' });

  // Визит всегда записывается на сегодняшний вечер (после полуночи — ещё вчерашний, до 06:00).
  // Задним числом визит не записать: КМ вносит заказ в тот же вечер. Дату из запроса
  // (её мог прислать старый экземпляр приложения) игнорируем.
  const day = venueDayStr();

  try {
    const v = await recordVisit({ guestId, date: day, hookah, notes, employee: req.employee });
    // визит записан → бронь гостя на сегодня («Не пришёл» или без отметки) становится «Пришёл»
    let booking = null;
    try {
      booking = await markBookingArrivedByVisit({ guestId, employee: req.employee });
    } catch (e) {
      console.error('Auto arrival mark failed:', e.message);
    }
    // Граммы табака (если КМ собрал кальян из справочника и указал граммы): списываем после записи визита.
    // Визит уже сохранён, поэтому ошибка списания визит не ломает — приложение покажет предупреждение.
    let tobaccoResult = null;
    if (tobacco && typeof tobacco === 'object' && Array.isArray(tobacco.items) && tobacco.items.length) {
      try {
        tobaccoResult = await tobaccoDb.recordUse({ visitId: v.id, key: tobacco.key, items: tobacco.items }, req.employee);
      } catch (e) {
        console.error('Табак: граммы не списались:', e.message);
        tobaccoResult = { error: e instanceof tobaccoDb.TobaccoError ? e.message : 'Граммы табака не списались' };
      }
    }
    res.json({ ok: true, created: v.created, date: day, bookingMarked: !!booking?.marked, bookingWas: booking?.marked ? booking.was : null, tobacco: tobaccoResult });
  } catch (error) {
    if (error.code === 'CARD_ARCHIVED') return res.status(409).json({ error: 'Эту карточку объединили с другой — откройте карточку гостя заново и запишите визит там' });
    if (error.code === 'CARD_NOT_FOUND') return res.status(404).json({ error: 'Карточка гостя не найдена' });
    console.error('Visit save failed:', error.message);
    res.status(502).json({ error: 'Визит не сохранился — попробуйте ещё раз.' });
  }
});

// ─── TELEGRAM WEBHOOK (бот для сотрудников) ────────

const WELCOME_TEXT =
  'Карточки гостей и визиты На Крыше.\n' +
  'Нажимай кнопку «Открыть», чтобы найти гостя, посмотреть карточку или добавить визит.';

const ENPS_WELCOME_TEXT =
  'Оцени нас — анонимно, займёт минуту.\n' +
  'Нажимай кнопку «Открыть», чтобы пройти опрос.';

// Секрет вебхука. Telegram с каждым обновлением присылает заголовок X-Telegram-Bot-Api-Secret-Token — так мы
// отличаем настоящие обновления от поддельных запросов на /telegram-webhook (иначе любой мог заставить бота
// писать в произвольный чат). При старте сервер сам переустанавливает вебхук с секретом (адрес не меняется)
// и повторяет попытку, пока Telegram не ответит. Запросы без верного секрета не обрабатываются никогда:
// настоящие обновления Telegram в таком случае пришлёт повторно.
// Свой секрет можно задать переменной TELEGRAM_WEBHOOK_SECRET (только латиница, цифры, _ и -, как требует Telegram);
// не задан или не подходит по формату — секрет выводится из токена бота.
const WEBHOOK_SECRET = (/^[A-Za-z0-9_-]{16,256}$/.test(process.env.TELEGRAM_WEBHOOK_SECRET || '') && process.env.TELEGRAM_WEBHOOK_SECRET) ||
  (TELEGRAM_BOT_TOKEN ? crypto.createHash('sha256').update(`webhook:${TELEGRAM_BOT_TOKEN}`).digest('hex').slice(0, 48) : '');
let webhookSecretActive = false;
async function ensureWebhookSecret(attempt = 0) {
  if (!TELEGRAM_BOT_TOKEN || !WEBHOOK_SECRET) return;
  let done = false;
  try {
    const info = await tgApi('getWebhookInfo', {});
    if (!info || !info.ok) console.error('Секрет вебхука: Telegram не ответил на getWebhookInfo —', info ? info.description : 'нет связи', '(повторю позже)');
    let url = info && info.ok ? info.result.url : null;
    // Переменная PUBLIC_BASE_URL (например https://имя.amvera.tech, без / на конце) — явный адрес этого сервера на любом хостинге.
    // Если она задана, вебхук ставится именно на него, даже если раньше стоял другой: так бот переезжает на новый хостинг сам.
    // Задавайте её ТОЛЬКО на боевом сервере: тестовая копия с тем же токеном перехватила бы бота.
    const publicBase = String(process.env.PUBLIC_BASE_URL || '').trim().replace(/\/+$/, '');
    if (publicBase && !/^https:\/\//i.test(publicBase)) console.error('PUBLIC_BASE_URL должна начинаться с https:// — игнорирую:', publicBase);
    else if (publicBase && info && info.ok) url = `${publicBase}/telegram-webhook`;
    if (info && info.ok && !url) { console.log('Вебхук бота не установлен, адрес сервера неизвестен — секрет не настраиваю'); return; }
    if (url) {
      const payload = { url, secret_token: WEBHOOK_SECRET };
      if (Array.isArray(info.result.allowed_updates)) payload.allowed_updates = info.result.allowed_updates;
      if (info.result.max_connections) payload.max_connections = info.result.max_connections;
      const r = await tgApi('setWebhook', payload);
      done = !!(r && r.ok);
      if (!done) console.error('Не удалось установить секрет вебхука:', r && r.description);
    }
  } catch (e) {
    console.error('Секрет вебхука:', e.message);
  }
  if (done) { webhookSecretActive = true; console.log('Секрет вебхука установлен'); return; }
  const t = setTimeout(() => ensureWebhookSecret(attempt + 1), Math.min(5 * 60 * 1000, 15000 * 2 ** Math.min(attempt, 5)));
  if (t.unref) t.unref();
}

app.post('/telegram-webhook', async (req, res) => {
  if (!WEBHOOK_SECRET || !safeEqual(req.get('X-Telegram-Bot-Api-Secret-Token'), WEBHOOK_SECRET)) return res.sendStatus(401);
  const update = req.body || {};
  try {
    if (update.message) {
      const chatId = update.message.chat.id;
      const text = update.message.text || '';

      // QR-код на служебном помещении ведёт на t.me/<bot>?start=enps — Telegram
      // присылает это как "/start enps". Открываем мини-апп сразу на опросе,
      // внутри Telegram (без видимого URL в браузере), а не как обычную ссылку.
      const isEnpsStart = /^\/start\s+enps\b/.test(text);

      await tgApi('sendMessage', {
        chat_id: chatId,
        text: isEnpsStart ? ENPS_WELCOME_TEXT : WELCOME_TEXT,
        reply_markup: {
          inline_keyboard: [[
            { text: 'Открыть', web_app: { url: isEnpsStart ? `${WEBAPP_URL}?enps=1` : WEBAPP_URL } }
          ]]
        }
      });
    }
  } catch (error) {
    console.error('Webhook error:', error);
  }
  res.sendStatus(200);
});

// ─── АДМИН: ОТКРЫТЫЕ ПРОБЛЕМЫ ───────────────────────

// Кто по умолчанию отвечает за проблему по категории
// Всё по умолчанию падает на администратора — он сам направляет конкретному
// ответственному через кнопку "Назначить" в приложении (endpoint /reassign ниже)
const CATEGORY_ROLE_MAP = {
  'Кальян': 'Администратор',
  'Напитки': 'Администратор',
  'Еда': 'Администратор',
  'Команда': 'Администратор',
  'Общее': 'Администратор'
};
const ASSIGNABLE_ROLES = ['КМ', 'Бармен', 'Повар', 'Официант', 'Администратор'];

// Список проблем — теперь доступен всем сотрудникам (не только админу), чтобы
// ответственный по категории тоже видел и мог взять в работу свою проблему
// Гость, оставивший отзыв, виден в проблеме только тем, кто и так может открывать карточки гостей
function problemsFor(employee, list) {
  return can(employee, 'guests.view') ? list : list.map(p => ({ ...p, guest: null }));
}

app.get('/api/staff/problems', async (req, res) => {
  if (!(await checkPerm(req, res, 'problems.view'))) return;
  try {
    res.json(problemsFor(req.employee, await feedback.listOpenProblems()));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch problems' });
  }
});

// ─── ОБРАЩЕНИЯ ГОСТЕЙ К УПРАВЛЯЮЩЕМУ ───────────────
// Гость пишет в гостевом приложении (сервер гостей кладёт запись в базу и пишет админу в Telegram).
// Здесь: список, ответ гостю (его отправляет гостевой бот), «обработано» без ответа и возврат в новые.
const empLabel = (e) => `${e.name || 'Сотрудник'}${e.role ? ` (${e.role})` : ''}`;

app.get('/api/staff/messages', async (req, res) => {
  if (!(await checkPerm(req, res, 'messages.view'))) return;
  try {
    const st = req.query.status;
    const [items, fresh] = await Promise.all([store.listGuestMessages(st === 'new' || st === 'done' ? st : 'all'), store.countNewMessages()]);
    res.json({ items, newCount: fresh });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось загрузить обращения' });
  }
});

app.get('/api/staff/messages/count', async (req, res) => {
  if (!(await checkPerm(req, res, 'messages.view'))) return;
  try { res.json({ newCount: await store.countNewMessages() }); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось загрузить' }); }
});

// Ответ гостю. Порядок: занять место в истории (с проверкой, что с момента, когда сотрудник открыл обращение, никто не
// ответил) → отправить боту → записать итог. Так ответ не уходит гостю дважды (второй сотрудник, повтор после потерянного
// подтверждения) и не пропадает из истории. Если связь оборвалась на отправке и неизвестно, дошло ли — запись остаётся
// с пометкой «не подтверждено», сотруднику говорим не отправлять вслепую.
app.post('/api/staff/messages/:id/reply', async (req, res) => {
  if (!(await checkPerm(req, res, 'messages.view'))) return;
  const body = req.body || {};
  const text = String(body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Напишите ответ' });
  if (text.length > 3500) return res.status(400).json({ error: 'Ответ слишком длинный: не больше 3500 знаков' });
  const seen = Number.isInteger(body.seen) && body.seen >= 0 && body.seen < 100000 ? body.seen : null; // сколько ответов видел сотрудник (старое приложение не шлёт — без проверки)
  const label = empLabel(req.employee);
  let claim = null, proxyCalled = false;
  try {
    const m = await store.getGuestMessage(req.params.id);
    if (!m) return res.status(404).json({ error: 'Обращение не найдено' });
    claim = await store.claimMessageReply(m.id, text, label, seen, body.key);
    if (claim.notFound) return res.status(404).json({ error: 'Обращение не найдено' });
    if (claim.conflict) {
      const last = claim.item.replies[claim.item.replies.length - 1] || {};
      if (!last.by && !last.at) return res.status(409).json({ error: 'Обращение изменилось, пока вы писали. Обновил его — проверьте историю и отправьте ответ ещё раз', code: 'changed', item: claim.item });
      const when = last.at ? new Date(last.at).toLocaleTimeString('ru-RU', { timeZone: VENUE_TZ, hour: '2-digit', minute: '2-digit' }) : '';
      const note = last.delivered === false ? ' Гостю оно не дошло.' : (last.delivered === null || last.delivered === undefined ? ' Оно ещё отправляется или не подтверждено.' : '');
      return res.status(409).json({
        error: `На это обращение уже ответили${last.by ? ': ' + last.by : ''}${when ? ' в ' + when : ''}.${note} Ваш ответ не отправлен — прочитайте ответ в истории и решите, нужен ли ещё один`,
        code: 'already_replied', item: claim.item });
    }
    proxyCalled = true; // с этого момента запись не снимаем: гость мог получить сообщение
    const r = await callGuestProxy('/api/internal/message/reply', { telegramId: m.telegramId, text }, 1, 20000);
    if (!r.reached || r.httpError) {
      if (!r.reached && (r.maybeDelivered || r.serverError)) {
        // запрос ушёл, но ответа не дождались (или шлюз ответил ошибкой сервера): гость мог получить сообщение.
        // Запись остаётся и помечается «не подтверждено», сотрудник не повторяет отправку вслепую
        await store.finishMessageReply(m.id, claim.key, null, label).catch(e => console.error('Не помечен неподтверждённый ответ:', e && e.message));
        auditNote(req, 'message.replied', 'guest_message', m.id, `ответ на обращение гостя ${m.name || 'без имени'} (отправка не подтверждена)`);
        return res.json({ ok: true, delivered: false, uncertain: true, reason: 'unconfirmed', item: await store.getGuestMessage(m.id).catch(() => null) });
      }
      await store.releaseMessageReply(m.id, claim.key).catch(e => console.error('Не снята запись ответа:', e && e.message));
      return res.status(502).json({ error: r.reached && r.httpError === 401
        ? 'Серверы не договорились (не совпадает внутренний ключ INTERNAL_ADMIN_KEY). Ответ не отправлен'
        : 'Не удалось отправить ответ, попробуйте ещё раз' });
    }
    const delivered = r.delivered === true;
    let updated = null;
    try {
      updated = await store.finishMessageReply(m.id, claim.key, delivered, label);
    } catch (e) {
      // гостю ответ уже ушёл (или бот сообщил об отказе); запись осталась «не подтверждено» — не повторяем отправку
      console.error('Не записан итог ответа гостю:', e && e.message ? e.message : e);
    }
    auditNote(req, 'message.replied', 'guest_message', m.id, `ответ на обращение гостя ${m.name || 'без имени'}${delivered ? '' : ' (не доставлен)'}`);
    res.json({ ok: true, delivered, reason: r.reason || null, recorded: !!updated, item: updated });
  } catch (error) {
    console.error(error);
    // место занято, а до отправки дело не дошло — снимаем, чтобы повтор не упёрся в собственную запись
    if (claim && claim.ok && !proxyCalled) await store.releaseMessageReply(req.params.id, claim.key).catch(() => {});
    res.status(500).json({ error: 'Не удалось отправить ответ' });
  }
});

// Обработано без ответа в приложении (например, перезвонили) / вернуть в новые
app.post('/api/staff/messages/:id/status', async (req, res) => {
  if (!(await checkPerm(req, res, 'messages.view'))) return;
  const status = (req.body || {}).status;
  if (status !== 'done' && status !== 'new') return res.status(400).json({ error: 'status: done или new' });
  try {
    const item = await store.setMessageStatus(req.params.id, status, empLabel(req.employee));
    if (!item) return res.status(404).json({ error: 'Обращение не найдено' });
    auditNote(req, status === 'done' ? 'message.done' : 'message.reopened', 'guest_message', item.id,
      `обращение гостя ${item.name || 'без имени'}: ${status === 'done' ? 'обработано' : 'возвращено в новые'}`);
    res.json({ ok: true, item });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить' });
  }
});

// Решённые (последние 60 дней): причина, кто и когда закрыл. Видят все, кто видит проблемы.
app.get('/api/staff/problems/resolved', async (req, res) => {
  if (!(await checkPerm(req, res, 'problems.view'))) return;
  try {
    res.json(problemsFor(req.employee, await feedback.listResolvedProblems(60, 100)));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch problems' });
  }
});

// Вернуть решённую проблему в работу — те же, кто может её закрывать
app.post('/api/staff/problem/:id/reopen', async (req, res) => {
  if (!(await checkPerm(req, res, ['problems.manage_all', 'problems.work_own_role']))) return;
  try {
    const problem = await feedback.getProblem(req.params.id);
    if (!problem) return res.status(404).json({ error: 'Проблема не найдена' });
    if (!canWorkProblem(req.employee, problem)) {
      return res.status(403).json({ error: `Вернуть в работу может только «${problem.responsible}» или администратор` });
    }
    const r = await feedback.reopenProblem(req.params.id);
    if (!r.ok) return res.status(r.notFound ? 404 : 409).json({ error: r.notFound ? 'Проблема не найдена' : 'Эта проблема не закрыта' });
    forgetMemo('feedback:problems');
    auditNote(req, 'problem.reopened', 'problem', req.params.id, `проблема возвращена в работу: ${String(problem.title || req.params.id).slice(0, 120)}`);
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось вернуть проблему в работу' });
  }
});

// Проблему берёт в работу и закрывает тот, у кого право на любые проблемы, либо ответственная роль
// проблемы (при праве «Брать в работу и закрывать проблемы своей роли»)
function canWorkProblem(employee, problem) {
  return can(employee, 'problems.manage_all') || (can(employee, 'problems.work_own_role') && employee.role === problem.responsible);
}

function employeeLabel(employee) {
  return `${employee.name || 'Сотрудник'}${employee.role ? ` (${employee.role})` : ''}`;
}

// Перевод "Задачи" → "В работе" — одним нажатием: посреди смены причина обычно ещё
// неизвестна, её спрашиваем при закрытии. Причину и срок можно передать и сразу.
// Разрешено только ответственному по категории (по его роли) или администратору.
app.post('/api/staff/problem/:id/take', async (req, res) => {
  if (!(await checkPerm(req, res, ['problems.manage_all', 'problems.work_own_role']))) return;
  const rootCause = (req.body?.rootCause || '').trim();
  const deadline = (req.body?.deadline || '').trim();

  try {
    const problem = await feedback.getProblem(req.params.id);
    if (!problem) return res.status(404).json({ error: 'Проблема не найдена' });
    const employee = req.employee;

    if (!canWorkProblem(employee, problem)) {
      return res.status(403).json({ error: `Взять в работу может только «${problem.responsible}» или администратор` });
    }
    const r = await feedback.takeProblem(req.params.id, { rootCause, deadline, byLabel: employeeLabel(employee) });
    if (!r.ok) return res.status(r.notFound ? 404 : 409).json({ error: r.notFound ? 'Проблема не найдена' : 'Эта проблема уже закрыта' });
    forgetMemo('feedback:problems');
    auditNote(req, 'problem.taken', 'problem', req.params.id, `проблема взята в работу: ${String(problem.title || req.params.id).slice(0, 120)}`);
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update problem' });
  }
});

// Перевод "В работе" → "Решена" — та же проверка прав. Здесь же спрашиваем коренную
// причину (если её не указали при взятии) — к концу работы она уже известна.
app.post('/api/staff/problem/:id/resolve', async (req, res) => {
  if (!(await checkPerm(req, res, ['problems.manage_all', 'problems.work_own_role']))) return;
  const rootCause = (req.body?.rootCause || '').trim();

  try {
    const problem = await feedback.getProblem(req.params.id);
    if (!problem) return res.status(404).json({ error: 'Проблема не найдена' });
    const employee = req.employee;

    if (!canWorkProblem(employee, problem)) {
      return res.status(403).json({ error: `Закрыть может только «${problem.responsible}» или администратор` });
    }
    if (!rootCause && !problem.rootCause) return res.status(400).json({ error: 'Напишите коренную причину — почему это случилось' });

    // Проблема из отзыва гостя: обязательно ответить, связались ли с гостем. У анонимного отзыва связаться не с кем.
    let contact = '', contactNote = '';
    if (problem.fromReview && !problem.anonymous) {
      contact = typeof req.body?.contact === 'string' ? req.body.contact.trim() : '';
      contactNote = (typeof req.body?.contactNote === 'string' ? req.body.contactNote : '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, 500);
      if (!['contacted', 'no_answer', 'not_needed'].includes(contact)) return res.status(400).json({ error: 'Ответьте, связались ли с гостем' });
      if (contact === 'not_needed' && !contactNote) return res.status(400).json({ error: 'Напишите, почему связываться с гостем не нужно' });
    }

    const r = await feedback.resolveProblem(req.params.id, { rootCause, byLabel: employeeLabel(employee), contact, contactNote });
    if (!r.ok) return res.status(404).json({ error: 'Проблема не найдена' });
    forgetMemo('feedback:problems');
    const CONTACT_LABEL = { contacted: 'связались с гостем', no_answer: 'с гостем связаться не удалось', not_needed: `с гостем связываться не нужно (${contactNote})` };
    auditNote(req, 'problem.resolved', 'problem', req.params.id, `проблема закрыта: ${String(problem.title || req.params.id).slice(0, 120)}${contact ? ` · ${CONTACT_LABEL[contact]}` : ''}`);
    res.json({ ok: true, ...(contact && r.contactSaved === false ? { warning: 'Ответ про связь с гостем не сохранён: не применена миграция 030' } : {}) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to resolve problem' });
  }
});

// Назначить конкретного ответственного по роли — только администратор
app.post('/api/staff/problem/:id/reassign', async (req, res) => {
  if (!(await checkPerm(req, res, 'problems.manage_all'))) return;
  const role = (req.body?.role || '').trim();
  const deadline = (req.body?.deadline || '').trim();
  if (!ASSIGNABLE_ROLES.includes(role)) {
    return res.status(400).json({ error: 'Неизвестная роль' });
  }

  try {
    const r = await feedback.reassignProblem(req.params.id, { role, deadline });
    if (!r.ok) return res.status(r.notFound ? 404 : 400).json({ error: r.notFound ? 'Проблема не найдена' : 'Неизвестная роль' });
    forgetMemo('feedback:problems');
    auditNote(req, 'problem.reassigned', 'problem', req.params.id, `проблема передана роли «${role}»${deadline ? `, срок ${deadline}` : ''}`);
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to reassign problem' });
  }
});

// Отдаём список ролей клиенту, чтобы не дублировать его в двух местах
app.get('/api/staff/assignable-roles', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  res.json(ASSIGNABLE_ROLES);
});

// ─── ОСНОВАТЕЛЬ: ЗАДАЧИ АДМИНУ ───────────────────────
// Простой отдельный задачник (таблица tasks), никак не связанный с «Проблемами».
// Никаких категорий/приоритетов/промежуточных статусов — только текст задачи,
// необязательный срок и галочка «Готово». В десктопном интерфейсе админа
// показывается отдельным блоком.

function sendWorkError(res, e, fallback) {
  if (e instanceof work.WorkError) return res.status(e.status).json({ error: e.message });
  console.error(e);
  res.status(500).json({ error: fallback });
}

// Поставить задачу может тот, у кого есть право «Ставить задачи» (по умолчанию — только основатель).
app.post('/api/founder/task', async (req, res) => {
  if (!(await checkPerm(req, res, 'founder_tasks.create'))) return;
  const employee = req.employee;

  const text = (req.body?.text || '').trim();
  const deadline = (req.body?.deadline || '').trim();
  if (!text) return res.status(400).json({ error: 'Укажите текст задачи' });

  try {
    await work.createTask({ text, deadline }, employee);
    auditNote(req, 'task.created', 'task', null, `поставлена задача: «${text.slice(0, 150)}»${deadline ? `, срок ${deadline}` : ''}`);
    await sendAdmin(`📌 Новая задача: «${text}»${deadline ? `\nСрок: ${deadline}` : ''}`, 'новая задача');
    res.json({ ok: true });
  } catch (error) {
    sendWorkError(res, error, 'Failed to create founder task');
  }
});

// Список задач — по умолчанию незавершённые; ?done=1 отдаёт выполненные
// (для раздела "Показать выполненные" на экране — чтобы было видно, что
// задача не потерялась, а реально закрыта). Видно администратору и основателю.
app.get('/api/admin/founder-tasks', async (req, res) => {
  if (!(await checkPerm(req, res, 'founder_tasks.manage'))) return;
  const wantDone = req.query.done === '1' || req.query.done === 'true';
  try {
    res.json(await work.listTasks({ done: wantDone }));
  } catch (error) {
    sendWorkError(res, error, 'Failed to fetch founder tasks');
  }
});

// Отметить готово / вернуть в работу — просто переключатель галочки "Готово".
// Доступно и администратору, и основателю.
app.post('/api/founder/task/:id/done', async (req, res) => {
  if (!(await checkPerm(req, res, 'founder_tasks.manage'))) return;
  const done = req.body?.done !== false; // по умолчанию true — отметить готовой
  try {
    const found = await work.setTaskDone(req.params.id, done);
    if (!found) return res.status(404).json({ error: 'Задача не найдена' });
    auditNote(req, done ? 'task.done' : 'task.reopened', 'task', req.params.id, done ? 'задача отмечена выполненной' : 'задача возвращена в работу');
    res.json({ ok: true });
  } catch (error) {
    sendWorkError(res, error, 'Failed to update founder task');
  }
});

// ─── ЗАМЕТКИ — быстрые записи админа/основателя вместо бумажек ─────
// Таблица notes, никак не связана с «Задачами»/«Проблемами». Только текст и автор —
// никаких статусов/сроков, это буквально стикер: записал — потом сам стёр, когда разобрался.
// Видно тем, у кого есть право «Быстрые заметки» (по умолчанию администратор и основатель), в
// отличие от «Задач» (там ставить может только основатель) — любой
// админ на смене может быстро что-то себе черкнуть.

app.post('/api/admin/note', async (req, res) => {
  if (!(await checkPerm(req, res, 'notes.manage'))) return;
  try {
    await work.createNote(req.body?.text, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendWorkError(res, error, 'Failed to create note');
  }
});

// Последние заметки, самые новые — сверху
app.get('/api/admin/notes', async (req, res) => {
  if (!(await checkPerm(req, res, 'notes.manage'))) return;
  try {
    res.json(await work.listNotes(30));
  } catch (error) {
    sendWorkError(res, error, 'Failed to fetch notes');
  }
});

// Удалить заметку — разобрались, записали куда нужно или сделали — стираем стикер.
app.delete('/api/admin/note/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'notes.manage'))) return;
  try {
    const found = await work.deleteNote(req.params.id);
    if (!found) return res.status(404).json({ error: 'Заметка не найдена' });
    res.json({ ok: true });
  } catch (error) {
    sendWorkError(res, error, 'Failed to delete note');
  }
});

// ─── eNPS ОТ СОТРУДНИКОВ — АНОНИМНО ─────────────────
// PIN проверяется только чтобы подтвердить что это реальный сотрудник —
// само имя/PIN/роль нигде не сохраняется вместе с ответом, только оценка и текст.

app.post('/api/staff/enps-review', async (req, res) => {
  if (!(await checkPin(req, res))) return; // подтверждаем сотрудника, но req.employee дальше не используем

  const score = Number(req.body?.score);
  const liked = (req.body?.liked || '').trim();
  const improve = (req.body?.improve || '').trim();

  if (!Number.isFinite(score) || score < 0 || score > 10) {
    return res.status(400).json({ error: 'Некорректная оценка' });
  }
  if (!liked) {
    return res.status(400).json({ error: 'Напиши что тебе нравится в работе здесь' });
  }
  if (!improve) {
    return res.status(400).json({ error: 'Напиши что можно улучшить' });
  }

  // Один ответ в месяц на сотрудника. Сам ответ с человеком не связан: в базе отдельно лежит только отметка
  // «в этом месяце уже отвечал» — необратимый отпечаток (по нему не узнать ни имя, ни что именно ответили).
  // Отметки хранятся отсортированными, а не в порядке ответов — по порядку их с ответами не сопоставить.
  // Раньше можно было отправлять сколько угодно ответов (и двойное касание давало два), и eNPS искажался.
  if (!process.env.PIN_SECRET) return res.status(503).json({ error: 'Сервер не настроен: нет переменной PIN_SECRET — опрос временно недоступен' });
  const month = venueDayStr().slice(0, 7);
  const markKey = `enps.voted.${month}`;
  const voter = crypto.createHmac('sha256', process.env.PIN_SECRET).update(`enps:${req.employee.id}:${month}`).digest('hex').slice(0, 32);
  try {
    // отметка и ответ — одной транзакцией: либо записаны оба, либо ничего
    const saved = await store.db.tx(async (q) => {
      const claimed = await q(
        `INSERT INTO settings (key, value, updated_at) VALUES ($1, jsonb_build_array($2::text), now())
         ON CONFLICT (key) DO UPDATE
           SET value = (SELECT jsonb_agg(x ORDER BY x) FROM jsonb_array_elements_text(settings.value || jsonb_build_array($2::text)) AS x),
               updated_at = now()
           WHERE NOT (settings.value ? $2)
         RETURNING key`, [markKey, voter]);
      if (!claimed.rows[0]) return false;
      // автора нет и не будет: пишем только оценку и два текста
      await q('INSERT INTO enps_responses (score, likes, improve) VALUES ($1, $2, $3)', [score, liked.slice(0, 4000), improve.slice(0, 4000)]);
      return true;
    });
    if (!saved) return res.status(409).json({ error: 'Вы уже проходили опрос в этом месяце — спасибо! Следующий раз — в следующем месяце.', code: 'already_voted' });
    forgetMemo('month-enps');
    forgetMemo('analytics:enps');
    forgetMemo('feedback:enps-texts'); // счётчик ответов месяца; сами тексты текущего месяца закрыты до его конца
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить ответ — попробуйте ещё раз' });
  }
});


app.get('/api/admin/problems', async (req, res) => {
  if (!(await checkPerm(req, res, 'problems.manage_all'))) return;
  try {
    res.json(problemsFor(req.employee, await feedback.listOpenProblems()));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch problems' });
  }
});

// ─── КАРТИНКИ (постеры афиши, фото блюд) ────────────
// Лежат в базе (таблица media_files). Приложение сжимает фото на телефоне/компьютере и присылает сюда
// сами байты картинки (Content-Type: image/jpeg|png|webp) — JSON для этого не годится (лимит 100 КБ).
// Публичная ссылка /api/media/<id> нужна сайту и приложениям гостей: при замене картинки id меняется,
// поэтому её можно кэшировать «навсегда». Отдаются только картинки, прикреплённые к живой афише/меню.
function publicBase(req) {
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
  return `${proto}://${req.get('host')}`;
}
const mediaUrl = (req, id) => (id ? `${publicBase(req)}/api/media/${id}` : '');
const imageUpload = express.raw({ type: ['image/jpeg', 'image/png', 'image/webp'], limit: '8mb' });
// Афиша принимает ещё и короткое видео (до 15 МБ)
// Фон ТВ и опросов: исходник может быть тяжёлым (до 40 МБ), сервер сам сожмёт его до лёгкого ролика
const tvBgUpload = express.raw({ type: ['image/jpeg', 'image/png', 'image/webp', 'video/mp4', 'video/quicktime', 'video/webm'], limit: '40mb' });
const posterUpload = express.raw({ type: ['image/jpeg', 'image/png', 'image/webp', 'video/mp4', 'video/quicktime', 'video/webm'], limit: '16mb' });
// Загрузка файла: СНАЧАЛА вход и право, и только потом чтение тела запроса.
// Раньше express.raw стоял первым и читал файл (8–40 МБ) в память до проверки входа: без входа шесть запросов
// по 15 МБ поднимали память сервера на 125 МБ (аудит 30.10, Б2). Теперь без входа или без права ответ уходит сразу,
// а файл не читается. После проверки в req.employee уже лежит сотрудник, повторно проверять в обработчике не нужно.
function uploadWith(perm, parser) {
  return [
    async (req, res, next) => {
      try { if (await checkPerm(req, res, perm)) next(); } catch (e) { next(e); }
    },
    parser
  ];
}

function sendCatalogError(res, e, fallback) {
  if (e instanceof catalog.CatalogError) return res.status(e.status).json({ error: e.message });
  console.error(e);
  // Нет колонки или таблицы — в базе не хватает миграции. Сотрудникам с доступом говорим об этом прямо, а не «ошибка»
  if (e && (e.code === '42703' || e.code === '42P01')) {
    return res.status(500).json({ error: `${fallback}: база данных не обновлена. Перезапустите сервис jarvis (он применяет миграции сам) и повторите` });
  }
  res.status(500).json({ error: fallback });
}

app.get('/api/media/:id', async (req, res) => {
  try {
    const m = await catalog.getPublicMedia(req.params.id);
    if (!m) return res.status(404).end();
    res.set('Content-Type', m.mime);
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.set('Accept-Ranges', 'bytes');
    // Видео телефон запрашивает кусками (Range) — без этого iPhone его не проигрывает
    const rg = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (rg && (rg[1] || rg[2]) && Buffer.isBuffer(m.data)) {
      const total = m.data.length;
      let start = rg[1] ? parseInt(rg[1], 10) : Math.max(0, total - parseInt(rg[2], 10));
      let end = rg[1] && rg[2] ? parseInt(rg[2], 10) : total - 1;
      if (end >= total) end = total - 1;
      if (start > end || start >= total) { res.set('Content-Range', `bytes */${total}`); return res.status(416).end(); }
      res.status(206);
      res.set('Content-Range', `bytes ${start}-${end}/${total}`);
      res.set('Content-Length', String(end - start + 1));
      return res.end(m.data.subarray(start, end + 1));
    }
    res.send(m.data);
  } catch (error) {
    console.error('Картинка:', error.message);
    res.status(502).end();
  }
});

// ─── АДМИН: МЕРОПРИЯТИЯ ────────────────────────────

app.get('/api/admin/events', async (req, res) => {
  if (!(await checkPerm(req, res, 'events.manage'))) return;
  try {
    const events = (await catalog.listEvents(venueDateStr())).map(e => ({
      id: e.id, name: e.name, format: e.format, date: e.date, description: e.description, poster: mediaUrl(req, e.posterId), posterType: e.posterType
    }));
    res.json(events);
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить афишу');
  }
});

app.post('/api/admin/events', async (req, res) => {
  if (!(await checkPerm(req, res, 'events.manage'))) return;
  const { name, format, date, description } = req.body || {};
  if (!name || !date) return res.status(400).json({ error: 'Укажите название и дату мероприятия' });
  try {
    const id = await catalog.createEvent({ name, format, date, description }, req.employee);
    res.json({ ok: true, id }); // id — чтобы сразу прикрепить постер
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось создать мероприятие');
  }
});

// Редактировать мероприятие — чтобы никто не заходил в Notion, всё через приложение
app.patch('/api/admin/events/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'events.manage'))) return;
  const { name, format, date, description } = req.body || {};
  try {
    await catalog.updateEvent(req.params.id, { name, format, date, description }, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось сохранить мероприятие');
  }
});

app.post('/api/admin/events/:id/poster', ...uploadWith('events.manage', posterUpload), async (req, res) => {
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  try {
    const mediaId = await catalog.setEventPoster(req.params.id, req.body, contentType, req.employee);
    res.json({ ok: true, poster: mediaUrl(req, mediaId) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить постер');
  }
});

// Убрать постер
app.delete('/api/admin/events/:id/poster', async (req, res) => {
  if (!(await checkPerm(req, res, 'events.manage'))) return;
  try {
    await catalog.clearEventPoster(req.params.id, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось убрать постер');
  }
});

// Удалить мероприятие (из афиши исчезает сразу; в журнале действий остаётся запись)
app.delete('/api/admin/events/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'events.manage'))) return;
  try {
    await catalog.deleteEvent(req.params.id, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось удалить мероприятие');
  }
});

// ─── БРОНИ (единый список — из бота и с сайта) ──────
// Брони хранятся в Postgres (таблица bookings), их же пишет гостевой сервер
// (мини-апп, бот, сайт). Для приложений каждая бронь отдаётся «записью» вида
// "ISO-дата|текст|тип|номер|гостей|комментарий|стол" (собирает db/store.js).
//
// Подтверждение/отмена/перенос идут через notion-proxy-na-kryishe (у него бот,
// которым можно написать гостю) — когда админ жмёт кнопку в панели, этот сервер
// просит его выполнить действие через внутренний эндпоинт (см. callGuestProxy ниже).
// Так гость получает то же автосообщение, что и при подтверждении через кнопку
// в Telegram, откуда бы админ ни нажал.

function stripBookingSuffix(raw) {
  return raw.replace(' (подтверждено)', '').replace(' (отменено)', '');
}
function parseBookingEntry(raw) {
  const clean = stripBookingSuffix(raw);
  const parts = clean.split('|');
  if (parts.length === 1) {
    return { iso: null, display: parts[0], kind: 'table', uid: null, guests: null, comment: '', table: '' };
  }
  return {
    iso: parts[0] || null,
    display: parts[1] || '',
    kind: parts[2] || 'table',
    uid: parts[3] || null,
    guests: parts[4] ? (Number(parts[4]) || null) : null,
    comment: parts[5] || '',
    // Физический стол, назначенный брони персоналом — 7-е поле; у записей без
    // назначенного стола (или у старых, ещё до этой возможности) — просто ''.
    table: parts[6] || ''
  };
}
function isBookingExpired(iso) {
  if (!iso) return true; // старые записи без даты считаем прошедшими
  return iso.slice(0, 10) < venueDateStr();
}

// ─── ОТМЕТКИ «ПРИШЁЛ / НЕ ПРИШЁЛ» У БРОНИ ───────────
// Хранятся прямо в брони в Postgres (bookings.arrival, arrival_at, arrival_by_label, arrival_visit_id).
// Бронь узнаём по номеру (uid) — он не меняется при переносе времени и смене стола.
const ARRIVAL_BACK_DAYS = 14; // отметить можно брони за последние 2 недели

function arrivalPublic(a) {
  return a ? { status: a.status, at: a.at, by: a.by, leftAt: a.leftAt || null, leftBy: a.leftBy || '' } : null;
}

// Сотрудник (КМ, официант) записал гостю визит — значит, гость пришёл. Если на сегодняшний
// вечер у него есть бронь без отметки или с «Не пришёл», ставим «Пришёл»: заказанный кальян
// важнее ошибочной отметки админа. Если у гостя уже есть бронь этого вечера с «Пришёл» —
// ничего не трогаем. Броней на вечер несколько — берём ближайшую по времени к «сейчас».
// visitId у такой отметки пустой: визит записал сотрудник, «Снять отметку» его не удалит.
// Ошибка не должна ломать запись визита — вызывающий её ловит и пишет в лог.
async function markBookingArrivedByVisit({ guestId, employee }) {
  const g = await cardsDb.getCard(guestId);
  const phone = normalizePhone(g?.phone || '');
  if (!phone) return { marked: false };
  const who = cardsDb.actorLabel(employee);
  return withKeyLock(`booking:${phone}`, async () => {
    const res = await store.markArrivedByVisit({ phone, who });
    if (res.marked) forgetMemo('analytics:bookings');
    return res;
  });
}

// Видит только администратор. ?past=N — ещё и брони за последние N дней (до 14),
// с пометкой past: true — для сверки «пришёл / не пришёл».
// ?cancelled=1 — ещё и брони, которые отменил сам гость (cancelled: true): на сегодня — до конца суток, на будущее —
// сутки после отмены. Отдаём только по просьбе: приложение прежней версии приняло бы их за действующие брони.
// Работать с бронями (подтверждать, отменять, менять, назначать стол, отмечать приход, записывать) — любое из этих прав.
// У кого есть только «Смотреть брони» (официант, бармен, повар, КМ), тот лишь смотрит: кто сейчас сидит и кто придёт сегодня.
const BOOKING_ACTION_PERMS = ['bookings.create', 'bookings.confirm', 'bookings.cancel', 'bookings.edit', 'bookings.assign_table', 'bookings.mark_arrival'];
const canWorkBookings = (employee) => BOOKING_ACTION_PERMS.some(k => can(employee, k));
// День заведения по времени брони «ГГГГ-ММ-ДДTЧЧ:ММ» (по Москве): до 06:00 это ещё прошлые сутки
function venueDayOfIso(iso) {
  const m = String(iso || '').match(/^(\d{4}-\d{2}-\d{2})T(\d{2})/);
  if (!m) return '';
  return Number(m[2]) < DAY_SPLIT_HOUR ? addDaysStr(m[1], -1) : m[1];
}
app.get('/api/staff/bookings', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.view'))) return;
  const viewOnly = !canWorkBookings(req.employee);
  const pastDays = viewOnly ? 0 : Math.min(Math.max(Math.floor(Number(req.query.past) || 0), 0), ARRIVAL_BACK_DAYS);
  const pastFrom = pastDays ? addDaysStr(venueDateStr(), -pastDays) : null;
  try {
    let rows = await store.listBookingsForStaff(pastFrom);
    if (viewOnly) {
      // только сегодняшний вечер и только подтверждённые: заявки, которые ещё ждут ответа, к приходу гостей не относятся
      const today = venueDayStr();
      rows = rows.filter(b => b.confirmed && venueDayOfIso(b.iso) === today);
    }
    if (req.query.cancelled === '1' && !viewOnly) {
      for (const c of await store.listGuestCancelledForStaff()) rows.push({ ...c, cancelled: true });
    }
    // Можно ли гостю написать из бота: бронь из приложения и у гостя есть Telegram. Бронь с сайта или по телефону —
    // админ связывается сам (звонок или сообщение), бот гостю ничего не пишет, поэтому при отмене причину не спрашиваем.
    // Если проверить не удалось, признак не отдаём: приложение тогда спрашивает причину, как раньше.
    const tgGuests = new Set();
    let tgKnown = false;
    try {
      const ids = [...new Set(rows.map(b => b.guestId).filter(Boolean))];
      if (ids.length) {
        const q = await store.db.query('SELECT id FROM guests WHERE id = ANY($1::uuid[]) AND telegram_id IS NOT NULL', [ids]);
        for (const x of q.rows) tgGuests.add(String(x.id));
      }
      tgKnown = true;
    } catch (e) { console.error('Не удалось проверить Telegram у гостей броней:', e.message); }
    const bookings = [];
    for (const b of rows) {
      let kindLabel = 'Стол';
      let eventName = null;
      if (b.kind === 'vip') kindLabel = b.room || 'ВИП-комната';
      else if (b.kind && b.kind.startsWith('event:')) { kindLabel = 'Мероприятие'; eventName = b.kind.slice(6); }

      // entry — запись брони без статуса, ей же панель ссылается на конкретную бронь
      // при подтверждении/отмене/переносе — как опаковый токен (внутри — номер брони).
      bookings.push({
        name: b.name || 'Гость', phone: b.phone, iso: b.iso, display: b.display, guests: b.guests, comment: b.comment, table: b.table,
        guestId: b.guestId, bookedNameRaw: b.bookedName,
        status: b.cancelled ? 'cancelled' : (b.confirmed ? 'confirmed' : 'pending'),
        kind: kindLabel, eventName,
        entry: b.entry,
        uid: b.uid || null,
        ...(b.walkIn ? { walkIn: true } : {}), // посадка без брони: нет гостя-карточки и телефона
        arrival: b.cancelled ? null : arrivalPublic(b.arrivalInfo),
        // ВИП-комната: «свободна до ЧЧ:ММ» (позвонить гостю), накладка с подтверждённой бронью, другие заявки на эту комнату
        ...(b.roomNote && !b.cancelled ? { roomNote: b.roomNote } : {}),
        lateAt: b.lateAt || null,       // гость нажал «Опаздываю»
        createdAt: b.createdAt || null, // когда бронь пришла — сколько она ждёт подтверждения
        ...(tgKnown ? { canNotify: b.source === 'app' && !!b.guestId && tgGuests.has(String(b.guestId)) } : {}), // боту есть кому написать
        ...(b.past ? { past: true } : {}),
        ...(b.cancelled ? { cancelled: true, cancelledAt: b.cancelledAt || null } : {})
      });
    }

    // Теги гостя прямо в брони: хостес/админ ещё до прихода видит аллергии, VIP,
    // особые пометки, вкусы и скорый ДР. Бронь и карточка — одна запись гостя в Postgres,
    // поэтому карточка берётся напрямую по гостю брони.
    try {
      const [cardList, visits] = await Promise.all([getAllCards(), getVisitsQuick()]);
      const dates = visitDatesByGuest(visits);
      const byId = new Map(cardList.map(c => [c.id, c]));
      const stats = await store.guestBookingStats(bookings.map(x => x.guestId).filter(Boolean)).catch(() => new Map()); // неявки и отмены гостем
      for (const b of bookings) {
        const c = byId.get(b.guestId);
        if (!c) continue;
        b.guestCard = {
          cardId: c.id,
          vip: c.vip,
          segment: guestSegment(dates.get(c.id)).name,
          tagsSpecial: c.tagsSpecial,
          tagsAllergy: c.tagsAllergy,
          tastesLike: c.tastesLike,
          tastesDislike: c.tastesDislike,
          important: c.important,
          // ДР считаем относительно дня брони, а не сегодняшнего
          birthday: birthdayInfo(c.birthday, (b.iso || '').slice(0, 10) || venueDateStr()),
          bookingStats: stats.get(b.guestId) || { noShows: 0, guestCancels: 0, came: 0, lastNoShow: null }
        };
      }
    } catch (e) {
      console.error('Не удалось подтянуть теги гостей к броням:', e.message); // брони всё равно отдаём
    }
    // Имя в брони — из карточки (персонал вписал полное). bookedName — как гость записался сам
    // (показываем мелко, если отличается).
    const sameName = (a, b2) => String(a || '').trim().toLowerCase() === String(b2 || '').trim().toLowerCase();
    for (const b of bookings) {
      if (b.bookedNameRaw && !sameName(b.bookedNameRaw, b.name)) b.bookedName = b.bookedNameRaw;
      delete b.bookedNameRaw;
      delete b.guestId;
    }

    bookings.sort((a, b) => (a.iso || '').localeCompare(b.iso || ''));
    res.json(bookings);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// ─── ДЕЙСТВИЯ НАД БРОНЬЮ (подтвердить / отменить / перенести) ──
// Сам этот сервис в Notion для этих действий не пишет — просит сделать это
// notion-proxy-na-kryishe через внутренний эндпоинт (у него бот, которым можно
// написать гостю; у стаф-бота — другого — такой возможности нет).
// Несколько попыток на случай временной недоступности; если совсем не достучались —
// честно возвращаем ошибку, а не тихий "успех" без реального результата.

// Запасного адреса нет. Раньше здесь стоял адрес старого приложения на Railway: потеряй сервер эту переменную,
// внутренний ключ и данные гостей ушли бы на адрес, которым больше никто не управляет. Теперь без переменной
// связь с гостевым сервером просто не работает, а «Состояние» и сообщение в админ-чат говорят об этом прямо.
const GUEST_PROXY_BASE = /^https?:\/\//i.test(String(process.env.GUEST_PROXY_BASE || '').trim())
  ? String(process.env.GUEST_PROXY_BASE).trim().replace(/\/+$/, '')
  : '';
const INTERNAL_ADMIN_KEY = process.env.INTERNAL_ADMIN_KEY;

// attempts = 1 — для рассылок и просьб об отзыве: повтор после обрыва связи
// мог бы прислать гостю одно и то же сообщение дважды.
// timeoutMs — сколько ждать ответа (рассылка пачкой идёт дольше обычного действия).
// maybeDelivered — связь оборвалась уже после отправки запроса: гостевой сервер мог успеть выполнить действие
// (написать гостю), мы просто не дождались ответа. Для сообщений гостям это значит «повторять нельзя».
async function callGuestProxy(path, payload, attempts = 3, timeoutMs = 15000) {
  if (!INTERNAL_ADMIN_KEY) return { reached: false, reason: 'no_key' };
  if (!GUEST_PROXY_BASE) return { reached: false, reason: 'no_base' };
  let maybeDelivered = false, serverError = false;
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(`${GUEST_PROXY_BASE}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-internal-key': INTERNAL_ADMIN_KEY },
        body: JSON.stringify(payload),
        timeout: timeoutMs
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok) return { reached: true, ...data };
      if (r.status < 500) return { reached: true, httpError: r.status, ...data }; // не временная ошибка — ретраить бессмысленно
      serverError = true; // 5xx: ошибка самого сервера или шлюза перед ним — мог ли запрос выполниться, неизвестно
    } catch (e) {
      // сетевая проблема — пробуем ещё раз. Не удалось даже соединиться — запрос точно не выполнен.
      const neverSent = e && ['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH'].includes(e.code);
      if (!neverSent) maybeDelivered = true;
    }
    if (i < attempts - 1) await new Promise(r2 => setTimeout(r2, 400 * (i + 1)));
  }
  return { reached: false, reason: 'unreachable', maybeDelivered, serverError };
}

// Если entry, с которым панель ушла подтверждать/отменять/редактировать, уже
// не совпадает с тем, что реально лежит в Notion (например, кто-то параллельно
// назначил стол этой же брони — теперь это устранено блокировкой на стороне
// notion-proxy, но сеть есть сеть, и бронь могли успеть поменять между тем как
// список открыли и тем как нажали кнопку) — говорим об этом прямо, а не молчим
// "успехом", который на деле ничего не изменил.
function bookingActionErrorMessage(result) {
  if (result.error === 'booking not found') {
    return 'Эта бронь уже изменилась (например, кто-то назначил стол или сохранил другое время) — обновите список броней и попробуйте снова';
  }
  return 'Гость не найден';
}

// Ответ гостевого сервера на действие с бронью. Любой отказ — это отказ: раньше при ответе, отличном от
// «не найдено» (например, разошёлся внутренний ключ между серверами), приложение получало «готово»,
// хотя бронь не менялась и гость ничего не получал. true — ответ приложению уже отправлен.
function bookingActionFailed(res, result, notFoundText) {
  if (!result.reached) {
    res.status(502).json({ error: result.reason === 'no_key'
      ? 'Сервер не настроен: нет переменной INTERNAL_ADMIN_KEY. Действие не выполнено'
      : result.reason === 'no_base'
        ? 'Сервер не настроен: нет переменной GUEST_PROXY_BASE. Действие не выполнено'
        : 'Не удалось выполнить действие, попробуйте ещё раз' });
    return true;
  }
  if (!result.httpError) return false;
  if (result.httpError === 404) { res.status(404).json({ error: notFoundText || bookingActionErrorMessage(result) }); return true; }
  if (result.httpError === 400) { res.status(400).json({ error: /[а-яё]/i.test(String(result.error || '')) ? result.error : 'Проверьте данные брони: дата, время, телефон' }); return true; }
  console.error(`Гостевой сервер отклонил действие с бронью: код ${result.httpError}`, result.error || '');
  res.status(502).json({ error: result.httpError === 401
    ? 'Серверы не договорились (не совпадает внутренний ключ INTERNAL_ADMIN_KEY). Бронь не изменена — сообщите разработчику'
    : `Сервер броней отклонил действие (код ${result.httpError}). Бронь не изменена — попробуйте ещё раз` });
  return true;
}
// Занятый стол — не запрет, а предупреждение: «Стол уже назначен брони Анны на 21:00»
function tableConflictText(table, c) {
  return c ? `Стол «${String(table).slice(0, 30)}» в этот вечер уже назначен брони ${c.name}${c.time ? ' на ' + c.time : ''}. Проверьте, нет ли накладки.` : null;
}

app.post('/api/staff/bookings/confirm', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.confirm'))) return;
  const { phone, entry } = req.body;
  if (!phone || !entry) return res.status(400).json({ error: 'phone and entry required' });

  const result = await callGuestProxy('/api/internal/booking/confirm', { phone, entry });
  if (bookingActionFailed(res, result)) return;
  if (!result.already) auditNote(req, 'booking.confirmed', 'booking', typeof entry === 'string' ? entry : null, `подтверждена бронь: ${await guestLabelByPhone(phone)}${result.notified ? '' : ' (сообщение гостю не ушло)'}`);
  res.json({ ok: true, notified: !!result.notified, already: !!result.already });
});

const CANCEL_REASON_LABEL = { changed_mind: 'гость передумал', no_seats: 'нет мест', closed: 'бар закрыт в этот день', other: 'другая причина' };
app.post('/api/staff/bookings/cancel', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.cancel'))) return;
  const { phone, entry, message } = req.body;
  if (!phone || !entry) return res.status(400).json({ error: 'phone and entry required' });
  // причина отмены от сотрудника; старое приложение причину не присылает — тогда работает прежнее правило
  const reasonIn = typeof req.body?.reason === 'string' ? req.body.reason : null;
  if (reasonIn !== null && !CANCEL_REASON_LABEL[reasonIn]) return res.status(400).json({ error: 'Выберите причину отмены из списка' });

  const result = await callGuestProxy('/api/internal/booking/cancel', { phone, entry, message, reason: reasonIn });
  if (bookingActionFailed(res, result)) return;
  if (!result.already) {
    forgetMemo('analytics:bookings');
    const tail = result.silent ? ' (гостю сообщение не отправлялось)' : result.notified ? ' (гостю отправлено сообщение)' : ' (сообщение гостю не ушло)';
    auditNote(req, 'booking.cancelled', 'booking', typeof entry === 'string' ? entry : null,
      `отменена бронь: ${await guestLabelByPhone(phone)}${reasonIn ? ` — причина: ${CANCEL_REASON_LABEL[reasonIn]}` : ''}${tail}`);
  }
  res.json({ ok: true, notified: !!result.notified, already: !!result.already, silent: !!result.silent });
});

app.post('/api/staff/bookings/edit', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.edit'))) return;
  const { phone, entry, dateISO, time, guests, comment } = req.body;
  if (!phone || !entry || !dateISO || !time) {
    return res.status(400).json({ error: 'phone, entry, dateISO and time required' });
  }

  const result = await callGuestProxy('/api/internal/booking/edit', { phone, entry, dateISO, time, guests, comment });
  if (bookingActionFailed(res, result)) return;
  auditNote(req, 'booking.edited', 'booking', typeof result.newEntry === 'string' ? result.newEntry : (typeof entry === 'string' ? entry : null),
    `изменена бронь: ${await guestLabelByPhone(phone)} → ${ruShortDate(dateISO)} ${time}${guests ? `, гостей: ${guests}` : ''}`);
  res.json({ ok: true, notified: !!result.notified, newEntry: result.newEntry, newDisplayText: result.newDisplayText, tableWarning: tableConflictText(result.table, result.conflict) });
});

// Внести бронь вручную (гость позвонил) — сразу подтверждённая, без похода
// гостя через мини-апп/бота. Источник в Notion помечается отдельно ("Телефон"),
// чтобы потом можно было посчитать долю броней по каналам.
app.post('/api/staff/bookings/add', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.create'))) return;
  const { name, phone, dateISO, time, guests, comment, table } = req.body || {};
  if (!name || !phone || !dateISO || !time) {
    return res.status(400).json({ error: 'Имя, телефон, дата и время обязательны' });
  }
  // Проверяем сами, не дожидаясь гостевого сервера: по неполному номеру бронь (и карточка гостя) не создаётся
  if (typeof name !== 'string' || !name.trim()) return res.status(400).json({ error: 'Укажите имя гостя' });
  if (!store.isFullPhone(normalizePhone(String(phone)))) return res.status(400).json({ error: 'Номер телефона — +7 и 10 цифр' });
  if (!store.isRealDate(String(dateISO))) return res.status(400).json({ error: 'Укажите дату брони' });
  if (!store.cleanTime(time)) return res.status(400).json({ error: 'Укажите время брони, например 21:00' });

  const result = await callGuestProxy('/api/internal/booking/create', { name, phone, dateISO, time, guests, comment, table });
  if (bookingActionFailed(res, result)) return;
  if (!result.deduped) auditNote(req, 'booking.created', 'booking', typeof result.entry === 'string' ? result.entry : null,
    `внесена бронь по телефону: ${String(name).slice(0, 60)} (${normalizePhone(String(phone)) || phone}), ${ruShortDate(dateISO)} ${store.cleanTime(time)}${guests ? `, гостей: ${guests}` : ''}${table ? `, стол ${table}` : ''}`);
  forgetMemo('analytics:bookings');
  res.json({ ok: true, entry: result.entry, display: result.display, tableWarning: tableConflictText(table, result.conflict) });
});

// Назначить/сменить стол у брони — внутренняя пометка для персонала (не
// уведомляет гостя и не трогает статус подтверждения).
app.post('/api/staff/bookings/table', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.assign_table'))) return;
  const { phone, entry, table } = req.body;
  if (!phone || !entry) return res.status(400).json({ error: 'phone and entry required' });

  const result = await callGuestProxy('/api/internal/booking/table', { phone, entry, table });
  if (bookingActionFailed(res, result, 'Бронь не найдена')) return;
  auditNote(req, 'booking.table_set', 'booking', typeof result.newEntry === 'string' ? result.newEntry : (typeof entry === 'string' ? entry : null),
    `${table ? `стол «${String(table).slice(0, 30)}»` : 'стол снят'} у брони: ${await guestLabelByPhone(phone)}`);
  res.json({ ok: true, newEntry: result.newEntry, tableWarning: tableConflictText(table, result.conflict) });
});

// Отметить бронь: status = arrived («пришёл»), noshow («не пришёл») или clear (снять отметку).
// «Пришёл» записывает визит в карточку гостя на день брони (нет карточки — создаёт её
// по брони: имя и телефон), чтобы гость попал в сегменты. Если отметку «пришёл» сняли
// или сменили на «не пришёл», а визит создала именно она и в нём ещё ничего не записали
// (кальян, заметки) — визит убираем (в корзину Notion).
app.post('/api/staff/bookings/arrival', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.mark_arrival'))) return;
  const { phone: rawPhone, uid, status, prev: expectedPrev } = req.body || {};
  const phone = normalizePhone(typeof rawPhone === 'string' ? rawPhone : '');
  if (!phone || typeof uid !== 'string' || !uid || !['arrived', 'noshow', 'clear'].includes(status)) {
    return res.status(400).json({ error: 'phone, uid и status обязательны' });
  }

  try {
    const result = await withKeyLock(`booking:${phone}`, async () => {
      // бронь по номеру; телефон должен совпасть с гостем брони
      const found = await store.getBookingForArrival(phone, uid);
      if (!found) return { http: 404, error: 'Бронь не найдена' };
      const { row, view } = found;
      if (row.status === 'cancelled') return { http: 409, error: 'Бронь отменена' };
      // посадка без брони: гость уже за столом, «не пришёл» и «снять отметку» к ней не относятся (ошибочную посадку убирают отдельной кнопкой)
      if (await store.isWalkInBooking(uid)) return { http: 409, error: 'Это посадка без брони. Если посадили по ошибке — нажмите «Убрать запись» в карточке', stale: true, arrival: arrivalPublic(found.arrival) };
      const today = venueDayStr();
      const day = row.venue_day; // бронь на 00:30 — вечер предыдущего дня
      if (!isRealDateStr(day)) return { http: 400, error: 'У брони нет даты' };
      if (status !== 'clear') {
        // снять отметку можно всегда (например, бронь потом перенесли), ставить — только в день брони и позже
        if (day > today) return { http: 400, error: 'Отметить приход можно в день брони или позже' };
        if (day < addDaysStr(today, -ARRIVAL_BACK_DAYS)) return { http: 400, error: 'Бронь слишком старая для отметки' };
        const hasTime = row.has_time && !/T00:00/.test(view.iso || '');
        if (status === 'noshow' && hasTime && String(view.iso).slice(0, 16) > venueNowIso()) {
          return { http: 400, error: '«Не пришёл» можно отметить, когда время брони уже наступило' };
        }
      }

      const prev = found.arrival;
      // защита от устаревшего экрана: приложение присылает, какую отметку оно видело
      if (['none', 'arrived', 'noshow'].includes(expectedPrev) && (prev?.status || 'none') !== expectedPrev) {
        return { http: 409, error: 'Отметку уже поменял кто-то другой — список обновлён', arrival: arrivalPublic(prev), stale: true };
      }
      const out = { cardId: null, cardCreated: false, visitCreated: false, visitRemoved: false, visitKept: false };
      // уже «Пришёл» — повтор ничего не меняет: иначе время прихода сдвинулось бы на «сейчас», а отметка «гость ушёл» стёрлась
      if (status === 'arrived' && prev?.status === 'arrived') return { ok: true, already: true, arrival: arrivalPublic(prev), ...out };
      const who = `${req.employee.name || 'Сотрудник'}${req.employee.role ? ` (${req.employee.role})` : ''}`;
      let visitId = prev?.status === 'arrived' ? prev.visitId : null;
      let write; // что записать в бронь: { status, visitId } или null (снять отметку)

      if (status === 'arrived') {
        if (prev?.status !== 'arrived') {
          // карточка гостя — владелец брони (бронь и карточка теперь одна запись гостя;
          // если карточку объединили с другой — берём главную)
          const cardId = await cardsDb.liveCardId(row.guest_id);
          if (!cardId) return { http: 502, error: 'Не удалось найти карточку гостя — попробуйте ещё раз' };
          out.cardId = cardId;
          const v = await recordVisit({ guestId: cardId, date: day, source: 'booking', employee: req.employee });
          out.visitCreated = v.created;
          visitId = v.created ? v.id : null; // визит, который уже был (записал официант), не наш — не удаляем его потом
        }
        write = { status: 'arrived', visitId };
      } else {
        // сняли «пришёл» — убираем визит, который создала отметка, если его никто не подтвердил
        if (visitId) {
          // у гостя в тот же вечер есть другая бронь с «Пришёл» — визит остаётся, теперь он её
          const sibling = await store.findSiblingArrived(row.guest_id, uid, day);
          if (sibling) {
            await store.setSiblingVisit(sibling.public_uid, visitId);
            out.visitKept = true;
          } else {
            const r = await cardsDb.removeVisitIfUntouched(visitId);
            out.visitRemoved = r.removed;
            out.visitKept = r.kept;
            if (r.removed) forgetMemo('stats');
          }
        }
        write = status === 'noshow' ? { status: 'noshow', visitId: null } : null;
      }

      try {
        await store.setBookingArrival(uid, write ? write.status : null, who, write ? write.visitId : null);
      } catch (e) {
        console.error('Arrival mark failed:', e.message);
        // отметка не записалась — визит, который мы только что создали, убираем, чтобы не остался «ничей»
        if (out.visitCreated && visitId) {
          const r = await cardsDb.removeVisitIfUntouched(visitId).catch(() => null);
          if (r?.removed) { out.visitCreated = false; forgetMemo('stats'); }
        }
        return { http: 502, error: 'Отметка не сохранилась — попробуйте ещё раз', ...out };
      }
      forgetMemo('analytics:bookings');
      const after = await store.getBookingForArrival(phone, uid);
      return { ok: true, arrival: arrivalPublic(after ? after.arrival : null), ...out };
    });
    const { http, ...body } = result;
    if (result.ok && !result.already) {
      auditNote(req, 'booking.arrival', 'booking', uid,
        `${status === 'arrived' ? 'отмечено: гость пришёл' : status === 'noshow' ? 'отмечено: гость не пришёл' : 'снята отметка прихода'} — ${await guestLabelByPhone(phone)}`);
    }
    res.status(http || 200).json(body);
  } catch (error) {
    if (error.code === 'CARD_ARCHIVED') return res.status(409).json({ error: 'Карточку гостя только что объединили с другой — нажмите ещё раз' });
    console.error('Arrival failed:', error.message);
    res.status(502).json({ error: 'Не удалось сохранить отметку — попробуйте ещё раз' });
  }
});

// ─── ПОСАДКА БЕЗ БРОНИ ─────────────────────────────
// Гость с улицы: на схеме его стол должен быть занят. Создаётся обычная бронь на «сейчас» (подтверждена, «Пришёл» с этой
// минуты, стол назначен) на служебную карточку «Гость без брони» — подробности в db/store.js. Имя и число гостей необязательны.
// Закрывается обычным «Гость ушёл». Занятый стол или бронь на него позже — предупреждение (force: true — посадить всё равно).
app.post('/api/staff/bookings/walkin', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.mark_arrival'))) return;
  const { table, guests, name, force } = req.body || {};
  const label = store.sanitizeTableLabel(typeof table === 'string' ? table : '');
  if (!label) return res.status(400).json({ error: 'Выберите стол' });
  // гость из базы: пришёл без брони, но карточка у него есть — посадка привязывается к ней, гостю записывается визит
  const knownId = typeof req.body?.guestId === 'string' && req.body.guestId ? req.body.guestId : null;
  if (knownId && !cardsDb.isUuid(knownId)) return res.status(400).json({ error: 'Гость не найден — выберите его из списка ещё раз' });
  if (knownId && !can(req.employee, 'guests.view')) return res.status(403).json({ error: 'Нет доступа к карточкам гостей' });
  const party = guests === undefined || guests === null || guests === '' ? null : Math.floor(Number(guests));
  if (party !== null && !(party >= 1 && party <= 50)) return res.status(400).json({ error: 'Число гостей — от 1 до 50' });
  const nm = typeof name === 'string' ? name.replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim() : '';
  if (nm.length > 60) return res.status(400).json({ error: 'Имя не длиннее 60 символов' });
  try {
    const result = await withKeyLock('booking:walkin', async () => {
      const day = venueDayStr();
      if (!force) {
        const conflicts = await store.tableConflicts(store.db.query, label, day, null);
        if (conflicts.length) return { http: 409, needConfirm: true, error: tableConflictText(label, conflicts[0]) };
      }
      const who = `${req.employee.name || 'Сотрудник'}${req.employee.role ? ` (${req.employee.role})` : ''}`;
      if (!knownId) {
        const made = await store.createWalkIn({ name: nm, guests: party, table: label, who });
        return { ok: true, uid: made.uid };
      }
      if (String(await store.walkInGuestId(false)) === knownId) return { http: 400, error: 'Гость не найден — выберите его из списка ещё раз' };
      const cardId = await cardsDb.liveCardId(knownId); // карточку объединили с другой — берём главную
      const card = cardId ? await cardsDb.getCard(cardId) : null;
      if (!card) return { http: 404, error: 'Карточка гостя не найдена — выберите гостя из списка ещё раз' };
      const guestLabel = card.name || 'Гость';
      // у гостя уже есть бронь на этот вечер — сажать «без брони» поверх неё не нужно: получились бы две записи про один стол
      const has = await store.guestBookingTonight(cardId, day);
      if (has) {
        const where = has.table_label ? ` (стол «${has.table_label}»)` : '';
        return { http: 409, error: has.arrival === 'arrived'
          ? `${guestLabel} уже сидит сегодня${where}. Вторая посадка не нужна`
          : `У гостя ${guestLabel} есть бронь на сегодня в ${has.hhmm}${where}. Откройте её в «Бронях» и нажмите «Пришёл»` };
      }
      const made = await store.createWalkIn({ guests: party, table: label, who, guestId: cardId });
      if (made.notFound) return { http: 404, error: 'Карточка гостя не найдена — выберите гостя из списка ещё раз' };
      if (made.noColumn) {
        // миграция 029 ещё не применена: сажаем безымянно под именем гостя, чтобы стол не остался «свободным»
        const anon = await store.createWalkIn({ name: guestLabel, guests: party, table: label, who });
        return { ok: true, uid: anon.uid, linked: false, guestName: guestLabel, warning: 'Гостей посадили, но посадка не привязана к карточке гостя: в базе не применена миграция 029. Визит запишите в карточке вручную' };
      }
      // визит гостю: один на вечер; если его уже записали — остаётся тот, к посадке не привязываем (тогда «убрать запись» его не тронет)
      let visitWarning = '';
      try {
        const v = await recordVisit({ guestId: cardId, date: made.day, source: 'booking', employee: req.employee });
        if (v.created) await store.setSiblingVisit(made.uid, v.id);
      } catch (e) {
        console.error('Walk-in visit failed:', e && e.message ? e.message : e);
        visitWarning = 'Гостей посадили, но визит в карточку не записался — добавьте его в карточке гостя';
      }
      return { ok: true, uid: made.uid, linked: true, guestId: cardId, guestName: guestLabel, ...(visitWarning ? { warning: visitWarning } : {}) };
    });
    const { http, ...body } = result;
    if (result.ok) {
      forgetMemo('analytics:bookings');
      if (result.linked) afterCardChange();
      const whoSat = result.guestName || nm;
      auditNote(req, 'booking.walkin', 'booking', result.uid, `посадили без брони: стол «${label}»${whoSat ? `, ${String(whoSat).slice(0, 60)}` : ''}${result.linked ? ' (гость из базы, визит записан)' : ''}${party ? `, гостей: ${party}` : ''}`);
    }
    res.status(http || 200).json(body);
  } catch (error) {
    console.error('Walk-in failed:', error.message);
    res.status(502).json({ error: 'Не удалось посадить гостей — попробуйте ещё раз' });
  }
});

// Убрать посадку без брони, сделанную по ошибке. Только такие посадки и только в тот же вечер.
app.post('/api/staff/bookings/walkin/remove', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.mark_arrival'))) return;
  const uid = typeof req.body?.uid === 'string' ? req.body.uid : '';
  if (!uid) return res.status(400).json({ error: 'uid обязателен' });
  try {
    const r = await withKeyLock('booking:walkin', () => store.removeWalkIn(uid, venueDayStr()));
    if (!r.ok) return res.status(404).json({ error: 'Такой посадки без брони сегодня нет — обновите список' });
    // посадка гостя из базы записала ему визит — убираем и его, если визит никто не дополнил (кальян, заметка)
    if (r.visitId) {
      const rv = await cardsDb.removeVisitIfUntouched(r.visitId).catch(() => null);
      if (rv && rv.removed) forgetMemo('stats');
      afterCardChange();
    }
    forgetMemo('analytics:bookings');
    auditNote(req, 'booking.walkin_removed', 'booking', uid, 'убрана посадка без брони (посадили по ошибке)');
    res.json({ ok: true });
  } catch (error) {
    console.error('Walk-in remove failed:', error.message);
    res.status(502).json({ error: 'Не удалось убрать запись — попробуйте ещё раз' });
  }
});

// ─── «ГОСТЬ УШЁЛ»: стол свободен ───────────────────
// У брони с отметкой «Пришёл» появляется конец: когда гость ушёл. С этой минуты стол на схеме зала и в проверке
// «стол занят» свободен, а в карточке видно, сколько гость просидел. action: 'leave' — отметить, 'undo' — вернуть за стол.
// Отмечают только в тот же вечер (день заведения до 06:00): задним числом время ухода было бы выдуманным.
// Брони прошлых дней без отметки считаются завершёнными без времени ухода.
// Поправить число гостей, пока гость за столом: пришло больше или меньше, чем в брони. Гостю ничего не уходит.
app.post('/api/staff/bookings/party', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.mark_arrival'))) return;
  const { phone: rawPhone, uid, guests } = req.body || {};
  const phone = normalizePhone(typeof rawPhone === 'string' ? rawPhone : '');
  if (!phone || typeof uid !== 'string' || !uid) return res.status(400).json({ error: 'phone и uid обязательны' });
  try {
    const result = await withKeyLock(`booking:${phone}`, async () => {
      const found = await store.getBookingForArrival(phone, uid);
      if (!found) return { http: 404, error: 'Бронь не найдена' };
      const was = found.row.party_size;
      const r = await store.setBookingParty(uid, guests);
      if (r.bad) return { http: 400, error: r.bad };
      if (!r.ok) return { http: 409, error: 'Число гостей можно поправить, пока гость за столом', stale: true };
      forgetMemo('analytics:bookings');
      return { ok: true, guests: r.guests, was: was == null ? null : was };
    });
    const { http, ...body } = result;
    if (result.ok) auditNote(req, 'booking.party_set', 'booking', uid, `число гостей за столом: ${result.was == null ? '—' : result.was} → ${result.guests} — ${await guestLabelByPhone(phone)}`);
    res.status(http || 200).json(body);
  } catch (error) {
    console.error('Party update failed:', error.message);
    res.status(502).json({ error: 'Не удалось сохранить — попробуйте ещё раз' });
  }
});

app.post('/api/staff/bookings/leave', async (req, res) => {
  if (!(await checkPerm(req, res, 'bookings.mark_arrival'))) return;
  const { phone: rawPhone, uid, action } = req.body || {};
  const phone = normalizePhone(typeof rawPhone === 'string' ? rawPhone : '');
  if (!phone || typeof uid !== 'string' || !uid || !['leave', 'undo'].includes(action)) {
    return res.status(400).json({ error: 'phone, uid и action обязательны' });
  }
  try {
    const result = await withKeyLock(`booking:${phone}`, async () => {
      const found = await store.getBookingForArrival(phone, uid);
      if (!found) return { http: 404, error: 'Бронь не найдена' };
      const { row } = found;
      if (row.status === 'cancelled') return { http: 409, error: 'Бронь отменена' };
      if (found.arrival?.status !== 'arrived') {
        return { http: 409, error: 'Сначала отметьте, что гость пришёл', arrival: arrivalPublic(found.arrival), stale: true };
      }
      if (String(row.venue_day).slice(0, 10) !== venueDayStr()) {
        return { http: 400, error: 'Отметить уход можно только в тот же вечер' };
      }
      const who = `${req.employee.name || 'Сотрудник'}${req.employee.role ? ` (${req.employee.role})` : ''}`;
      const had = !!found.arrival.leftAt;
      if (action === 'leave') {
        if (!had) await store.setBookingLeft(uid, who); // повторное нажатие время ухода не меняет
      } else if (had) {
        await store.clearBookingLeft(uid);
      }
      forgetMemo('analytics:bookings');
      const after = await store.getBookingForArrival(phone, uid);
      // вернули за стол, а его уже заняла другая бронь — говорим об этом (решает человек, как и при назначении стола)
      let conflict = null;
      if (action === 'undo' && row.table_label) {
        conflict = (await store.tableConflicts(store.db.query, row.table_label, String(row.venue_day).slice(0, 10), row.id))[0] || null;
      }
      return { ok: true, changed: action === 'leave' ? !had : had, arrival: arrivalPublic(after ? after.arrival : null), table: row.table_label || '', tableWarning: tableConflictText(row.table_label, conflict) };
    });
    const { http, ...body } = result;
    if (result.ok && result.changed) {
      const label = await guestLabelByPhone(phone);
      auditNote(req, action === 'leave' ? 'booking.left' : 'booking.left_undone', 'booking', uid,
        action === 'leave'
          ? `гость ушёл${result.table ? `, стол «${result.table}» свободен` : ''} — ${label}`
          : `отметка «гость ушёл» снята${result.table ? `, стол «${result.table}» снова занят` : ''} — ${label}`);
    }
    res.status(http || 200).json(body);
  } catch (error) {
    // колонки ещё нет: серверы выложили раньше, чем применилась миграция 022
    if (error.code === '42703') return res.status(503).json({ error: 'База ещё не обновлена — отметка ухода заработает после обновления (сервис jarvis).' });
    console.error('Leave mark failed:', error.message);
    res.status(502).json({ error: 'Не удалось сохранить отметку — попробуйте ещё раз' });
  }
});

// ─── ГРАФИК СМЕН (замена Supershift) ────────────────
// Видит весь график вся команда (кто с кем работает), а редактирует —
// только администратор. Одна запись = один сотрудник на одну дату.

// Список сотрудников — нужен всем, чтобы подписывать чужие смены в календаре,
// и админу отдельно — для выбора при назначении смены.
app.get('/api/staff/employees-list', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  await ensureEmployeesFresh();
  res.json(employeesCache.map(e => ({ id: e.id, name: e.name, role: e.role })));
});

// Смены за период (месяц для календаря) — вся команда видит всех.
app.get('/api/staff/schedule', async (req, res) => {
  if (!(await checkPerm(req, res, 'schedule.view'))) return;
  try {
    res.json(await work.listShifts(req.query.from, req.query.to));
  } catch (error) {
    sendWorkError(res, error, 'Failed to fetch schedule');
  }
});

// Создать/обновить смену — только администратор. Один сотрудник + одна дата = одна
// запись, при повторном сохранении просто обновляем её, а не плодим дубли.
// id — смена, которую правят: если в ней поменяли сотрудника или дату, переносим
// эту же запись. Если у нового сотрудника на новую дату уже есть запись — обновляем её,
// а старую убираем.
app.post('/api/admin/schedule', async (req, res) => {
  if (!(await checkPerm(req, res, 'schedule.edit'))) return;
  const { employeeId, date, status, time, note } = req.body || {};
  const editId = typeof req.body?.id === 'string' && req.body.id ? req.body.id : null;
  try {
    const id = await work.saveShift({ employeeId, date, status, time, note, editId });
    auditNote(req, editId ? 'schedule.shift_updated' : 'schedule.shift_saved', 'schedule', id,
      `${editId ? 'изменена' : 'записана'} смена на ${ruShortDate(date)}: ${employeeNameById(employeeId)}${status ? `, ${status}` : ''}${time ? `, ${time}` : ''}`);
    res.json({ ok: true, id });
  } catch (error) {
    sendWorkError(res, error, 'Failed to save shift');
  }
});

// Удалить смену (сбросить день сотрудника обратно в пустое состояние) — только администратор
app.delete('/api/admin/schedule/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'schedule.edit'))) return;
  try {
    const found = await work.deleteShift(req.params.id);
    if (!found) return res.status(404).json({ error: 'Смена не найдена' });
    auditNote(req, 'schedule.shift_deleted', 'schedule', req.params.id, 'удалена смена из графика');
    res.json({ ok: true });
  } catch (error) {
    sendWorkError(res, error, 'Failed to delete shift');
  }
});

// ─── ОСНОВАТЕЛЬ: СОТРУДНИКИ ──────────────────────────
// Экран «Сотрудники» в приложении: добавить (логин и временный пароль), поменять роль/имя/логин/Telegram, уволить и вернуть.
// Пароль сотрудника увидеть нельзя: в базе только хэш. Забыл пароль — задаётся новый временный (POST /api/auth/reset-password/:id),
// человек сменит его при первом входе. Уволили — все входы сотрудника стираются сразу.
// Себя уволить и поменять себе роль нельзя; последнего основателя убрать нельзя (проверяет сама база).

function sendEmployeeError(res, e, fallback) {
  if (e instanceof employeesDb.EmployeeError) return res.status(e.status).json({ error: e.message });
  if (e instanceof authDb.AuthError) return res.status(e.status).json({ error: e.message });
  console.error(e);
  res.status(500).json({ error: fallback });
}

// Список сотрудников, их логины, пароли и блокировки — только основатель.
app.get('/api/founder/employees', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  try {
    const list = await employeesDb.listAll();
    res.json({
      employees: list.map(e => ({ ...e, isSelf: e.id === req.employee.id })),
      roles: employeesDb.ROLE_NAMES, canManage: true, canReset: true
    });
  } catch (error) {
    sendEmployeeError(res, error, 'Failed to fetch employees');
  }
});

// Журнал входов сотрудника (последние 30): когда и с какого устройства
app.get('/api/founder/employees/:id/logins', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  try {
    res.json({ logins: await employeesDb.listLogins(req.params.id, 30) });
  } catch (error) {
    sendEmployeeError(res, error, 'Failed to fetch logins');
  }
});

app.post('/api/founder/employees', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  try {
    const out = await employeesDb.create({ name: req.body?.name, role: req.body?.role, login: req.body?.login, password: req.body?.tempPassword, telegramId: req.body?.telegramId }, req.employee);
    await refreshEmployees();
    res.json({ ok: true, id: out.id, login: out.login, password: out.password });
  } catch (error) {
    sendEmployeeError(res, error, 'Failed to create employee');
  }
});

app.patch('/api/founder/employees/:id', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  try {
    const { name, role, login, telegramId, active } = req.body || {};
    const changed = await employeesDb.update(req.params.id, { name, role, login, telegramId, active }, req.employee);
    await refreshEmployees();
    res.json({ ok: true, changed });
  } catch (error) {
    sendEmployeeError(res, error, 'Failed to update employee');
  }
});

// Конструктор прав: список галочек, наборы прав ролей и личные исключения всех сотрудников — одним запросом
app.get('/api/founder/permissions', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  try {
    res.json(await permissionsDb.describe(employeesDb.ROLE_NAMES));
  } catch (error) {
    sendEmployeeError(res, error, 'Failed to fetch permissions');
  }
});

// Сохранить галочки сотрудника: state — {право: true|false} по всем галочкам формы
app.put('/api/founder/employees/:id/permissions', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  try {
    const r = await permissionsDb.setForEmployee(req.params.id, req.body?.state, req.employee);
    await refreshEmployees();
    res.json({ ok: true, changed: r.changed, overrides: r.overrides });
  } catch (error) {
    if (error instanceof permissionsDb.PermissionError) return res.status(error.status).json({ error: error.message });
    sendEmployeeError(res, error, 'Failed to save permissions');
  }
});

// ─── МЕНЮ И СТОП-ЛИСТ ───────────────────────────────
// Меню хранится в Postgres: его же показывают гостевое приложение и сайт. Снял позицию со «В наличии» —
// гость её уже не видит. Смотреть список могут все сотрудники, стоп-лист меняет тот, чья категория
// (бармен — напитки, повар — еда, КМ — кальян), администратор и основатель — любую.
// Править само меню (добавить, переименовать, цена, фото, порядок, удалить) — администратор и основатель.

// Полное меню (включая позиции в стоп-листе) — видят все залогиненные сотрудники
app.get('/api/staff/menu', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.view'))) return;
  try {
    const items = (await catalog.listMenu()).map(i => ({
      id: i.id, name: i.name, category: i.category, subcategory: i.subcategory, price: i.price,
      description: i.description, composition: i.composition, volume: i.volume, available: i.available, hidden: i.hidden === true, photo: mediaUrl(req, i.photoId),
      showOnTv: i.showOnTv === true
    }));
    res.json(items);
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить меню');
  }
});

// Переключить "В наличии" одной позиции — роль проверяем строго по категории ЭТОЙ позиции в базе
// (не по тому, что прислал клиент), чтобы права нельзя было обойти подменой запроса.
app.patch('/api/staff/menu/:id', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const { available } = req.body || {};
  if (typeof available !== 'boolean') return res.status(400).json({ error: 'available (boolean) required' });
  try {
    const category = await catalog.getMenuItemCategory(req.params.id);
    if (category === null) return res.status(404).json({ error: 'Позиция не найдена' });
    if (!can(req.employee, MENU_CATEGORY_PERM[category] || 'menu.manage')) {
      return res.status(403).json({ error: `Эту категорию может менять только ${MENU_CATEGORY_EDIT_ROLE[category] || 'администратор'}` });
    }
    // quick: это переключатель на экране «Стоп-лист» — позиция в стопе «на смену» и утром вернётся в меню сама
    await catalog.updateMenuItem(req.params.id, { available }, req.employee, { quick: true });
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось сохранить позицию меню');
  }
});

app.get('/api/admin/menu/meta', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  res.json({ categories: catalog.MENU_CATEGORIES });
});

app.post('/api/admin/menu', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  const { name, category, subcategory, price, description, composition, volume, available, showOnTv } = req.body || {};
  try {
    const id = await catalog.createMenuItem({ name, category, subcategory: plainName(subcategory), price, description, composition, volume, available, showOnTv }, req.employee);
    // tvSkipped: отметку «на экранах ТВ» просили, но в базе нет миграции 041 — приложение скажет об этом сотруднику, а не промолчит
    const tvSkipped = showOnTv !== undefined && !(await catalog.hasShowOnTv().catch(() => true));
    res.json({ ok: true, id, tvSkipped }); // id — чтобы сразу прикрепить фото
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось создать позицию меню');
  }
});

app.patch('/api/admin/menu/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  const { name, category, subcategory, price, description, composition, volume, available, showOnTv } = req.body || {};
  try {
    await catalog.updateMenuItem(req.params.id, { name, category, subcategory: plainName(subcategory), price, description, composition, volume, available, showOnTv }, req.employee);
    const tvSkipped = showOnTv !== undefined && !(await catalog.hasShowOnTv().catch(() => true));   // см. комментарий у POST
    res.json({ ok: true, tvSkipped });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось сохранить позицию меню');
  }
});

app.delete('/api/admin/menu/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  try {
    await catalog.deleteMenuItem(req.params.id, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось удалить позицию меню');
  }
});

// Сдвинуть позицию вверх/вниз внутри её подраздела
// Сдвинуть подраздел целиком (должен стоять раньше маршрута /:id/move, иначе «subcategory» примется за id)
app.post('/api/admin/menu/subcategory/move', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  try {
    const { category, subcategory, dir } = req.body || {};
    res.json({ ok: true, moved: await catalog.moveMenuSubcategory(category, subcategory, dir) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось переместить подраздел');
  }
});

// Переименовать подраздел целиком (тоже до маршрутов с /:id)
app.post('/api/admin/menu/subcategory/rename', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  try {
    const { category, subcategory, name } = req.body || {};
    res.json({ ok: true, ...(await catalog.renameMenuSubcategory(category, subcategory, plainName(name), req.employee)) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось переименовать подраздел');
  }
});

app.post('/api/admin/menu/:id/copy', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  try {
    res.status(201).json({ ok: true, id: await catalog.copyMenuItem(req.params.id, req.employee) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось скопировать позицию');
  }
});

app.post('/api/admin/menu/:id/move', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  try {
    res.json({ ok: true, moved: await catalog.moveMenuItem(req.params.id, req.body && req.body.dir) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось переместить позицию');
  }
});

app.post('/api/admin/menu/:id/photo', ...uploadWith('menu.manage', imageUpload), async (req, res) => {
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  try {
    const mediaId = await catalog.setMenuPhoto(req.params.id, req.body, contentType, req.employee);
    res.json({ ok: true, photo: mediaUrl(req, mediaId) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить фото');
  }
});

app.delete('/api/admin/menu/:id/photo', async (req, res) => {
  if (!(await checkPerm(req, res, 'menu.manage'))) return;
  try {
    await catalog.clearMenuPhoto(req.params.id, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось убрать фото');
  }
});

// ─── СЕРВИС: СТОРИС ГОСТЕВОГО ПРИЛОЖЕНИЯ (фото бара и ВИП-комнат) ─────
// Гости листают эти фото на экранах «Бар» и «ВИП-комнаты» (/api/stories на гостевом сервере).
// Фото сжимает приложение; здесь хранится сама картинка и подпись. Порядок — стрелками.

function storySetsPayload(req, stories) {
  return Object.keys(catalog.STORY_SETS).map(key => ({
    key, title: catalog.STORY_SETS[key],
    slides: (stories[key] || []).map(x => ({ id: x.id, title: x.title, photo: mediaUrl(req, x.photoId) }))
  }));
}

app.get('/api/admin/stories', async (req, res) => {
  if (!(await checkPerm(req, res, 'stories.manage'))) return;
  try {
    res.json({ sets: storySetsPayload(req, await catalog.listPublicStories()), max: catalog.STORY_MAX });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить сторис');
  }
});

app.post('/api/admin/stories/:set', ...uploadWith('stories.manage', imageUpload), async (req, res) => {
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  try {
    const r = await catalog.addStory(req.params.set, req.body, contentType, req.query.title, req.employee);
    res.json({ ok: true, id: r.id, photo: mediaUrl(req, r.photoId) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось добавить фото');
  }
});

app.patch('/api/admin/stories/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'stories.manage'))) return;
  try {
    await catalog.updateStory(req.params.id, req.body, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось сохранить подпись');
  }
});

app.post('/api/admin/stories/:id/photo', ...uploadWith('stories.manage', imageUpload), async (req, res) => {
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  try {
    const mediaId = await catalog.replaceStoryPhoto(req.params.id, req.body, contentType, req.employee);
    res.json({ ok: true, photo: mediaUrl(req, mediaId) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось заменить фото');
  }
});

app.post('/api/admin/stories/:id/move', async (req, res) => {
  if (!(await checkPerm(req, res, 'stories.manage'))) return;
  try {
    res.json({ ok: true, ...(await catalog.moveStory(req.params.id, req.body && req.body.dir)) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось сдвинуть фото');
  }
});

app.delete('/api/admin/stories/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'stories.manage'))) return;
  try {
    await catalog.deleteStory(req.params.id, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось удалить фото');
  }
});

// ─── СЕРВИС: ОПРОСЫ (конструктор оформления: фон, ретушь, затемнение, тексты) ─────
// Вопросы и шкалы не меняются — от них зависят CSI, NPS и eNPS. Меняется только оформление.
// 'guest_review' показывает гостевой сервер (/api/review/config), 'staff_enps' — это приложение.

const surveyPayload = (req, v) => ({
  kind: v.kind, title: catalog.SURVEY_KINDS[v.kind], retouch: v.retouch, dim: v.dim,
  heading: v.title, intro: v.intro, thanksTitle: v.thanksTitle, thanksText: v.thanksText,
  background: mediaUrl(req, v.bgId), backgroundType: v.bgType   // 'image' | 'video' | ''
});

// Ссылки на опросы — для QR-кода на столе (гости) и в служебном помещении (команда).
// Имя бота узнаём у Telegram один раз и помним 10 минут; не вышло — отдаём null, ссылку тогда не показываем.
let botNameCache = { staff: null, guest: null, at: 0 };
async function surveyLinks() {
  if (Date.now() - botNameCache.at > 10 * 60 * 1000 || (!botNameCache.staff && !botNameCache.guest)) {
    let staff = null, guest = null;
    try {
      const me = await tgApi('getMe', {});
      staff = me?.result?.username || null;
    } catch (e) { /* без имени бота ссылку просто не показываем */ }
    try {
      if (!GUEST_PROXY_BASE) throw new Error('GUEST_PROXY_BASE не задана');
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 4000);
      const r = await fetch(`${GUEST_PROXY_BASE}/api/bot-info`, { signal: ctl.signal });
      clearTimeout(timer);
      if (r.ok) guest = (await r.json())?.username || null;
    } catch (e) { /* гостевой сервер недоступен — ссылка на гостевой опрос не покажется */ }
    botNameCache = { staff, guest, at: Date.now() };
  }
  return {
    guest_bot: botNameCache.guest || null,
    guest_review: botNameCache.guest ? `https://t.me/${botNameCache.guest}?start=review` : null,
    guest_tips: botNameCache.guest ? `https://t.me/${botNameCache.guest}?start=tips` : null,
    staff_enps: botNameCache.staff ? `https://t.me/${botNameCache.staff}?start=enps` : null
  };
}

// ─── ОПРОСЫ-КОНСТРУКТОР (как в CosmosResto: страницы, вопросы, условия, дизайн, ссылка и QR, ответы) ─────
// Таблицы survey_forms / survey_responses (миграция 047). Право то же, что у оформления старых опросов — surveys.manage.
// Гость открывает опрос по ссылке t.me/<бот>?start=survey_<код>: страницу и приём ответов отдаёт гостевой сервер (/api/survey/<код>).
function sendSurveyError(res, e, fallback) {
  if (e instanceof surveyForms.SurveyError) return res.status(e.status).json({ error: e.message, code: e.code || undefined });
  return sendCatalogError(res, e, fallback);
}
const GUEST_APP_URL = process.env.GUEST_APP_URL || 'https://timuraleroy.github.io/na-kryishe';
const surveyListItem = (s, bot) => ({
  id: s.id, slug: s.slug, title: s.title, status: s.status, state: surveyForms.availability(s), questions: s.questions, pagesCount: s.pages.length,
  responses: s.responses || 0, lastResponseAt: s.lastResponseAt || null, updatedAt: s.updatedAt, publishedAt: s.publishedAt, authorLabel: s.authorLabel,
  link: bot ? `https://t.me/${bot}?start=survey_${s.slug}` : null,
  preview: `${GUEST_APP_URL}?survey=${s.slug}&preview=1`          // страница опроса «как у гостя», без отправки ответов (работает и у черновика)
});
const surveyFull = (req, s, bot) => ({
  ...surveyListItem(s, bot),
  startText: s.startText, startButton: s.startButton, consent: s.consent, consentText: s.consentText, thanksTitle: s.thanksTitle, thanksText: s.thanksText,
  pages: s.pages, design: s.design, anonymous: s.anonymous, repeatDays: s.repeatDays, startsAt: s.startsAt, endsAt: s.endsAt, maxResponses: s.maxResponses,
  logo: mediaUrl(req, s.logoId) || null, background: mediaUrl(req, s.bgId) || null,
  problem: surveyForms.readyProblem(s), createdAt: s.createdAt, closedAt: s.closedAt
});
app.get('/api/admin/survey-forms', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try {
    const [list, links] = await Promise.all([surveyForms.list(), surveyLinks()]);
    res.json({ surveys: list.map((s) => surveyListItem(s, links.guest_bot)), types: surveyForms.TYPE_LABEL, bot: links.guest_bot || null, limits: surveyForms.LIM, colors: surveyForms.DEFAULT_COLORS });
  } catch (error) { sendSurveyError(res, error, 'Не удалось загрузить опросы'); }
});
app.post('/api/admin/survey-forms', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  try {
    const r = await surveyForms.create(req.body, req.employee);
    const [s, links] = await Promise.all([surveyForms.get(r.id), surveyLinks()]);
    res.json({ ok: true, survey: surveyFull(req, s, links.guest_bot), warnings: r.warnings });
  } catch (error) { sendSurveyError(res, error, 'Не удалось создать опрос'); }
});
app.get('/api/admin/survey-forms/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try {
    const [s, links] = await Promise.all([surveyForms.get(req.params.id), surveyLinks()]);
    if (!s) return res.status(404).json({ error: 'Опрос не найден' });
    res.json({ survey: surveyFull(req, s, links.guest_bot) });
  } catch (error) { sendSurveyError(res, error, 'Не удалось открыть опрос'); }
});
app.put('/api/admin/survey-forms/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  try {
    const r = await surveyForms.update(req.params.id, req.body, req.employee);
    const [s, links] = await Promise.all([surveyForms.get(req.params.id), surveyLinks()]);
    res.json({ ok: true, survey: surveyFull(req, s, links.guest_bot), warnings: r.warnings });
  } catch (error) { sendSurveyError(res, error, 'Не удалось сохранить опрос'); }
});
for (const [path, status] of [['publish', 'published'], ['unpublish', 'closed'], ['to-draft', 'draft']]) {
  app.post(`/api/admin/survey-forms/:id/${path}`, async (req, res) => {
    if (!(await checkPerm(req, res, 'surveys.manage'))) return;
    try {
      const s = await surveyForms.setStatus(req.params.id, status, req.employee);
      const links = await surveyLinks();
      res.json({ ok: true, survey: surveyFull(req, s, links.guest_bot) });
    } catch (error) { sendSurveyError(res, error, 'Не удалось изменить статус опроса'); }
  });
}
app.post('/api/admin/survey-forms/:id/duplicate', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  try {
    const id = await surveyForms.duplicate(req.params.id, req.employee);
    const [s, links] = await Promise.all([surveyForms.get(id), surveyLinks()]);
    res.json({ ok: true, survey: surveyFull(req, s, links.guest_bot) });
  } catch (error) { sendSurveyError(res, error, 'Не удалось сделать копию'); }
});
app.delete('/api/admin/survey-forms/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  try {
    await surveyForms.remove(req.params.id, req.employee);
    res.json({ ok: true });
  } catch (error) { sendSurveyError(res, error, 'Не удалось удалить опрос'); }
});
for (const [path, which] of [['logo', 'logo'], ['background', 'bg']]) {
  app.post(`/api/admin/survey-forms/:id/${path}`, ...uploadWith('surveys.manage', imageUpload), async (req, res) => {
    const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
    try {
      const mediaId = await surveyForms.setMedia(req.params.id, which, req.body, contentType, req.employee);
      res.json({ ok: true, url: mediaUrl(req, mediaId) });
    } catch (error) { sendSurveyError(res, error, 'Не удалось загрузить картинку'); }
  });
  app.delete(`/api/admin/survey-forms/:id/${path}`, async (req, res) => {
    if (!(await checkPerm(req, res, 'surveys.manage'))) return;
    try {
      await surveyForms.clearMedia(req.params.id, which, req.employee);
      res.json({ ok: true });
    } catch (error) { sendSurveyError(res, error, 'Не удалось убрать картинку'); }
  });
}
app.get('/api/admin/survey-forms/:id/results', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try { res.json(await surveyForms.results(req.params.id)); }
  catch (error) { sendSurveyError(res, error, 'Не удалось собрать итоги'); }
});
app.get('/api/admin/survey-forms/:id/responses', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try { res.json(await surveyForms.responses(req.params.id, { limit: req.query.limit, offset: req.query.offset })); }
  catch (error) { sendSurveyError(res, error, 'Не удалось загрузить ответы'); }
});
app.delete('/api/admin/survey-forms/:id/responses/:rid', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  try { await surveyForms.removeResponse(req.params.id, req.params.rid, req.employee); res.json({ ok: true }); }
  catch (error) { sendSurveyError(res, error, 'Не удалось удалить ответ'); }
});
app.get('/api/admin/survey-forms/:id/export', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  try {
    const csv = await surveyForms.exportCsv(req.params.id);
    res.set('Content-Type', 'text/csv; charset=utf-8');
    res.set('Cache-Control', 'no-store');
    res.send(csv);
  } catch (error) { sendSurveyError(res, error, 'Не удалось выгрузить ответы'); }
});

// ─── ЧАЕВЫЕ ─────────────────────────────────────────
// Сотрудник видит свои чаевые (tips.view): итоги за смену и месяц и ленту «пришло +300 ₽». Кто оставил — не показываем.
// Администрация (tips.manage): отчёт, настройки (включить, режим, суммы, должности), ссылка и QR, очистка тестовых чаевых.
// Оплата пока не подключена: чаевые идут в тестовом режиме, деньги не списываются (db/tips.js).
function sendTipsError(res, e, fallback) {
  if (e instanceof tipsDb.TipsError) return res.status(e.status).json({ error: e.message });
  console.error(fallback + ':', e);
  return res.status(500).json({ error: fallback });
}
app.get('/api/staff/tips/mine', async (req, res) => {
  if (!(await checkPerm(req, res, 'tips.view'))) return;
  res.set('Cache-Control', 'no-store');
  try {
    res.json(await tipsDb.mine(req.employee.id));
  } catch (error) { sendTipsError(res, error, 'Не удалось загрузить чаевые'); }
});
// Кто сегодня в графике (любой статус) или на открытой смене, но гость его не увидит, и почему.
// Чтобы на экране настроек было видно причину («бармена нет в списке — почему?»), а не приходилось гадать.
// Причины в порядке проверки: отключён → должность не может принимать чаевые → должность не отмечена в настройках →
// в графике не «Работает» → смену уже закрыл. Тот, кого onShift показывает гостю, сюда не попадает.
async function tipsNotShown(config, shownRows) {
  const shown = new Set(shownRows.map(e => e.id));
  const r = await store.db.query(
    `SELECT e.id, e.name, e.active, ro.key AS role_key, ro.name AS role_name,
            (SELECT s.status FROM shifts s WHERE s.employee_id = e.id AND s.shift_date = venue_day_of(now())) AS shift_status,
            EXISTS (SELECT 1 FROM shift_marks m WHERE m.employee_id = e.id AND m.status = 'open') AS is_open,
            EXISTS (SELECT 1 FROM shift_marks m WHERE m.employee_id = e.id AND m.day = venue_day_of(now()) AND m.status = 'closed') AS is_closed
       FROM employees e JOIN roles ro ON ro.id = e.role_id
      WHERE EXISTS (SELECT 1 FROM shifts s WHERE s.employee_id = e.id AND s.shift_date = venue_day_of(now()))
         OR EXISTS (SELECT 1 FROM shift_marks m WHERE m.employee_id = e.id AND m.status = 'open')
      ORDER BY e.name`);
  const out = [];
  for (const e of r.rows) {
    if (shown.has(e.id)) continue;
    let reason;
    if (!e.active) reason = 'сотрудник отключён';
    else if (!tipsDb.TIP_ROLES.includes(e.role_key)) reason = 'эта должность не принимает чаевые';
    else if (!config.roles.includes(e.role_key)) reason = `должность «${e.role_name}» не отмечена выше`;
    else if (e.shift_status && e.shift_status !== 'Работает' && !e.is_open) reason = `в графике: ${String(e.shift_status).toLowerCase()}`;
    else if (e.is_closed && !e.is_open) reason = 'смена уже закрыта';
    else reason = 'причину определить не удалось';
    out.push({ name: e.name, role: e.role_name, reason });
  }
  return out;
}
async function tipsSettingsPayload(req) {
  const [config, links, roster] = await Promise.all([tipsDb.loadConfig(), surveyLinks(), tipsDb.roster()]);
  const shownRows = await tipsDb.onShift(config);
  const shifted = shownRows.map(e => ({ name: e.name, role: e.role_name }));
  let notShown = [];
  try { notShown = await tipsNotShown(config, shownRows); } catch (e) { console.error('Чаевые: кого нет в списке:', e.message); }   // подсказка не должна ломать настройки
  return {
    config, demo: tipsDb.DEMO, link: links.guest_tips || null,
    roles: tipsDb.TIP_ROLES.map(k => ({ key: k, title: tipsDb.ROLE_TITLES[k] || k })),
    onShift: shifted, notShown, limits: { perHour: tipsDb.PER_HOUR_LIMIT },
    // фото сотрудников (миграция 043): кому можно загрузить фото для экрана чаевых
    staff: roster.map(e => ({ id: e.id, name: e.name, role: e.role_name, roleKey: e.role_key, photo: mediaUrl(req, e.photo_id) }))
  };
}
app.get('/api/admin/tips/settings', async (req, res) => {
  if (!(await checkPerm(req, res, 'tips.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try { res.json(await tipsSettingsPayload(req)); }
  catch (error) { sendTipsError(res, error, 'Не удалось загрузить настройки чаевых'); }
});
app.put('/api/admin/tips/settings', async (req, res) => {
  if (!(await checkPerm(req, res, 'tips.manage'))) return;
  try {
    const { before, after } = await tipsDb.saveConfig(req.body || {});
    const changes = [];
    if (before.enabled !== after.enabled) changes.push(after.enabled ? 'чаевые включены' : 'чаевые выключены');
    if (before.mode !== after.mode) changes.push(`режим: ${({ both: 'сотрудник или команда', person: 'только сотрудник', team: 'только команда' })[after.mode]}`);
    if (before.amounts.join() !== after.amounts.join()) changes.push(`суммы: ${after.amounts.join(', ')} ₽`);
    if (before.allowCustom !== after.allowCustom) changes.push(after.allowCustom ? 'своя сумма разрешена' : 'своя сумма запрещена');
    if (before.min !== after.min || before.max !== after.max) changes.push(`предел: ${after.min}–${after.max} ₽`);
    if (before.roles.join() !== after.roles.join()) changes.push(`принимают: ${after.roles.map(k => tipsDb.ROLE_TITLES[k] || k).join(', ')}`);
    if (changes.length) auditNote(req, 'tips.settings_saved', 'settings', 'tips.config', `Чаевые: ${changes.join('; ')}`);
    res.json(await tipsSettingsPayload(req));
  } catch (error) { sendTipsError(res, error, 'Не удалось сохранить настройки чаевых'); }
});
// Фото сотрудника для экрана чаевых (миграция 043): приложение сжимает его до квадрата и присылает сами байты картинки.
// Гость видит фото вместо инициалов; нет фото — инициалы, как раньше. Загружает администрация (tips.manage).
app.post('/api/admin/tips/staff/:id/photo', ...uploadWith('tips.manage', imageUpload), async (req, res) => {
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  try {
    const mediaId = await catalog.setEmployeePhoto(req.params.id, req.body, contentType, req.employee);
    res.json({ ok: true, photo: mediaUrl(req, mediaId) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить фото');
  }
});
app.delete('/api/admin/tips/staff/:id/photo', async (req, res) => {
  if (!(await checkPerm(req, res, 'tips.manage'))) return;
  try {
    await catalog.clearEmployeePhoto(req.params.id, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось убрать фото');
  }
});
app.get('/api/admin/tips/report', async (req, res) => {
  if (!(await checkPerm(req, res, 'tips.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try { res.json(await tipsDb.report({ from: req.query.from, to: req.query.to, period: req.query.period })); }
  catch (error) { sendTipsError(res, error, 'Не удалось собрать отчёт по чаевым'); }
});
// Перед открытием: убрать тестовые чаевые, чтобы в отчёте остались только настоящие
app.post('/api/admin/tips/clear-demo', async (req, res) => {
  if (!(await checkPerm(req, res, 'tips.manage'))) return;
  try {
    const out = await tipsDb.clearDemo();
    auditNote(req, 'tips.demo_cleared', 'tips', 'demo', `Чаевые: тестовые записи удалены (${out.removed})`);
    res.json({ ok: true, ...out });
  } catch (error) { sendTipsError(res, error, 'Не удалось удалить тестовые чаевые'); }
});

// ─── ВНЕШНИЕ ОТЗЫВЫ ─────────────────────────────────
// Отзывы с Яндекс Карт, 2ГИС, Google и др. администратор вносит вручную; по ним ведётся работа: статус, ответственный,
// срок, текст ответа, шаблоны ответов (db/extreviews.js, миграция 044). Право ext_reviews.manage (основатель и администратор).
function sendExtRevError(res, e, fallback) {
  if (e instanceof extRevDb.ExtReviewError) return res.status(e.status).json({ error: e.message });
  // миграция 044 ещё не применена: таблиц нет — понятное сообщение вместо «ошибка сервера»
  if (e && e.code === '42P01') return res.status(503).json({ error: 'Раздел заработает после обновления базы (миграция 044). Попробуйте через несколько минут.' });
  console.error(fallback + ':', e);
  return res.status(500).json({ error: fallback });
}
// Список с фильтрами и сводкой; при first=1 заодно справочники: площадки, статусы, шаблоны, кто может вести отзывы
app.get('/api/admin/ext-reviews', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try {
    const first = req.query.first === '1';
    const [page, summary, today, meta] = await Promise.all([
      extRevDb.list({ status: req.query.status, platform: req.query.platform, q: req.query.q, offset: req.query.offset, limit: req.query.limit }),
      extRevDb.summary(),
      extRevDb.today(),
      first ? Promise.all([extRevDb.templates(), extRevDb.assignees()]) : null
    ]);
    const out = { ...page, summary, today };
    if (meta) {
      out.templates = meta[0]; out.assignees = meta[1];
      out.platforms = extRevDb.PLATFORMS; out.statuses = extRevDb.STATUSES; out.tones = extRevDb.TONES;
      out.dueDays = { low: extRevDb.DUE_DAYS_LOW, other: extRevDb.DUE_DAYS_OTHER };
      out.me = req.employee.id;
    }
    res.json(out);
  } catch (error) { sendExtRevError(res, error, 'Не удалось загрузить внешние отзывы'); }
});
app.get('/api/admin/ext-reviews/templates', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try { res.json({ templates: await extRevDb.templates() }); }
  catch (error) { sendExtRevError(res, error, 'Не удалось загрузить шаблоны ответов'); }
});
app.post('/api/admin/ext-reviews/templates', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  try { res.json({ templates: await extRevDb.createTemplate(req.body, req.employee) }); }
  catch (error) { sendExtRevError(res, error, 'Не удалось сохранить шаблон'); }
});
app.patch('/api/admin/ext-reviews/templates/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  try { res.json({ templates: await extRevDb.updateTemplate(req.params.id, req.body, req.employee) }); }
  catch (error) { sendExtRevError(res, error, 'Не удалось сохранить шаблон'); }
});
app.delete('/api/admin/ext-reviews/templates/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  try { res.json({ templates: await extRevDb.archiveTemplate(req.params.id, req.employee) }); }
  catch (error) { sendExtRevError(res, error, 'Не удалось убрать шаблон'); }
});
app.get('/api/admin/ext-reviews/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  res.set('Cache-Control', 'no-store');
  try { res.json(await extRevDb.get(req.params.id)); }
  catch (error) { sendExtRevError(res, error, 'Не удалось загрузить отзыв'); }
});
app.post('/api/admin/ext-reviews', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  try { res.json({ item: await extRevDb.create(req.body, req.employee) }); }
  catch (error) { sendExtRevError(res, error, 'Не удалось сохранить отзыв'); }
});
app.patch('/api/admin/ext-reviews/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  try { res.json(await extRevDb.update(req.params.id, req.body, req.employee)); }   // { item, history }
  catch (error) { sendExtRevError(res, error, 'Не удалось сохранить отзыв'); }
});
app.delete('/api/admin/ext-reviews/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'ext_reviews.manage'))) return;
  try { await extRevDb.remove(req.params.id, req.employee); res.json({ ok: true }); }
  catch (error) { sendExtRevError(res, error, 'Не удалось удалить отзыв'); }
});

app.get('/api/admin/surveys', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  try {
    const [list, links] = await Promise.all([catalog.listSurveys(), surveyLinks()]);
    res.json({ surveys: list.map(v => ({ ...surveyPayload(req, v), link: links[v.kind] || null })) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить опросы');
  }
});

app.put('/api/admin/surveys/:kind', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  const b = req.body || {};
  try {
    const v = await catalog.updateSurvey(req.params.kind, {
      retouch: b.retouch, dim: b.dim, title: b.heading, intro: b.intro, thanksTitle: b.thanksTitle, thanksText: b.thanksText
    }, req.employee);
    res.json({ ok: true, survey: surveyPayload(req, v) });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось сохранить опрос');
  }
});

// Фон опроса — фото или видео (до 40 МБ и 60 секунд): видео сервер сам сжимает в лёгкий ролик
app.post('/api/admin/surveys/:kind/background', ...uploadWith('surveys.manage', tvBgUpload), async (req, res) => {
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  try {
    const r = await catalog.setSurveyBackground(req.params.kind, req.body, contentType, req.employee);
    const v = await catalog.getSurvey(req.params.kind);
    res.json({ ok: true, background: mediaUrl(req, r.mediaId), backgroundType: v.bgType, processed: r.processed, note: r.note });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить фон');
  }
});

app.delete('/api/admin/surveys/:kind/background', async (req, res) => {
  if (!(await checkPerm(req, res, 'surveys.manage'))) return;
  try {
    await catalog.clearSurveyBackground(req.params.kind, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось убрать фон');
  }
});

// ─── ТВ-ЭКРАНЫ В ВИП-КОМНАТАХ (db/tv.js) ───────────
// Фон (видео или картинка), размытие, тексты, сообщение на экран, ручная замена имени. Управляют администратор и основатель.
// Телевизор открывает страницу na-kryishe-tv (GitHub Pages) и спрашивает у гостевого сервера, что показывать.
const TV_PAGE_URL = process.env.TV_PAGE_URL || 'https://timuraleroy.github.io/na-kryishe-tv/';
function sendTvError(res, e, fallback) {
  if (e instanceof tvDb.TvError || e instanceof catalog.CatalogError) return res.status(e.status).json({ error: e.message });
  console.error(e);
  if (e && (e.code === '42703' || e.code === '42P01')) {
    return res.status(500).json({ error: `${fallback}: база данных не обновлена. Перезапустите сервис jarvis (он применяет миграции сам) и повторите` });
  }
  res.status(500).json({ error: fallback });
}
app.get('/api/admin/tv', async (req, res) => {
  if (!(await checkPerm(req, res, 'tv.manage'))) return;
  try { res.json({ rooms: await tvDb.tvList(publicBase(req), TV_PAGE_URL) }); }
  catch (error) { sendTvError(res, error, 'Не удалось загрузить экраны'); }
});
app.put('/api/admin/tv/:room', async (req, res) => {
  if (!(await checkPerm(req, res, 'tv.manage'))) return;
  try { res.json({ ok: true, room: await tvDb.tvSave(req.params.room, req.body, req.employee, publicBase(req), TV_PAGE_URL) }); }
  catch (error) { sendTvError(res, error, 'Не удалось сохранить экран'); }
});
app.post('/api/admin/tv/:room/background', ...uploadWith('tv.manage', tvBgUpload), async (req, res) => {
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  try {
    const r = await tvDb.tvSetBackground(req.params.room, req.body, contentType, req.employee);
    res.json({ ok: true, processed: r.processed, note: r.note, room: await tvDb.tvOne(Number(req.params.room), publicBase(req), TV_PAGE_URL) });
  } catch (error) { sendTvError(res, error, 'Не удалось загрузить фон'); }
});
app.delete('/api/admin/tv/:room/background', async (req, res) => {
  if (!(await checkPerm(req, res, 'tv.manage'))) return;
  try { await tvDb.tvClearBackground(req.params.room, req.employee); res.json({ ok: true }); }
  catch (error) { sendTvError(res, error, 'Не удалось убрать фон'); }
});
app.post('/api/admin/tv/:room/override', async (req, res) => {
  if (!(await checkPerm(req, res, 'tv.manage'))) return;
  try {
    await tvDb.tvSetOverride(req.params.room, req.body, req.employee);
    res.json({ ok: true, room: await tvDb.tvOne(Number(req.params.room), publicBase(req), TV_PAGE_URL) });
  } catch (error) { sendTvError(res, error, 'Не удалось изменить приветствие'); }
});
app.delete('/api/admin/tv/:room/override', async (req, res) => {
  if (!(await checkPerm(req, res, 'tv.manage'))) return;
  try { await tvDb.tvClearOverride(req.params.room, req.employee); res.json({ ok: true }); }
  catch (error) { sendTvError(res, error, 'Не удалось вернуть приветствие по брони'); }
});
app.post('/api/admin/tv/:room/token', async (req, res) => {
  if (!(await checkPerm(req, res, 'tv.manage'))) return;
  try {
    await tvDb.tvNewToken(req.params.room, req.employee);
    res.json({ ok: true, room: await tvDb.tvOne(Number(req.params.room), publicBase(req), TV_PAGE_URL) });
  } catch (error) { sendTvError(res, error, 'Не удалось выдать новую ссылку'); }
});

// Плашки на плитках «Сервиса»: сколько новых откликов, групп дублей, позиций меню без фото / без цены.
// Считаем только то, что сотрудник и так может открыть; сбой одного счётчика не ломает остальные.
app.get('/api/staff/service-badges', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const e = req.employee;
  const out = {};
  const jobs = [];
  if (can(e, 'candidates.view')) jobs.push(catalog.countNewCandidates().then(n => { out.candidates = n; }).catch(() => {}));
  if (can(e, 'guests.merge')) jobs.push(duplicateGroupsCount().then(n => { out.duplicates = n; }).catch(() => {}));
  if (can(e, 'ext_reviews.manage')) jobs.push(extRevDb.badges().then(b => { out.extReviews = b.open; out.extReviewsOverdue = b.overdue; }).catch(() => {}));
  if (can(e, 'menu.manage')) jobs.push(catalog.menuGaps().then(g => { out.menuNoPhoto = g.noPhoto; out.menuNoPrice = g.noPrice; out.menuAny = g.any; }).catch(() => {}));
  await Promise.all(jobs);
  res.json(out);
});

// Оформление опроса команды: его открывает любой сотрудник (по PIN), как и сам опрос
app.get('/api/staff/enps-config', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try {
    res.json(surveyPayload(req, await catalog.getSurvey('staff_enps')));
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить оформление опроса');
  }
});

// ─── ОСНОВАТЕЛЬ: КАНДИДАТЫ (отклики на вакансии) ─────
// Отклики приходят с сайта и из гостевого приложения (раздел «Работа у нас»). Видит только основатель.

app.get('/api/founder/candidates', async (req, res) => {
  if (!(await checkPerm(req, res, 'candidates.view'))) return;
  try {
    const [candidates, newCount] = await Promise.all([catalog.listCandidates({ status: req.query.status }), catalog.countNewCandidates()]);
    res.json({ candidates, newCount });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось загрузить отклики');
  }
});

app.patch('/api/founder/candidates/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'candidates.view'))) return;
  try {
    await catalog.setCandidateStatus(req.params.id, req.body && req.body.status, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось обновить отклик');
  }
});

app.delete('/api/founder/candidates/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'candidates.view'))) return;
  try {
    await catalog.deleteCandidate(req.params.id, req.employee);
    res.json({ ok: true });
  } catch (error) {
    sendCatalogError(res, error, 'Не удалось удалить отклик');
  }
});

// ─── АДМИН: СТАТИСТИКА (CSI/NPS, eNPS, визиты) ─────
// CSI/NPS и eNPS читаются из Postgres (db/feedback.js).

// ── eNPS сотрудников — из Postgres (анонимно) ──
// Опрос анонимный, а команда небольшая: если показывать оценку или число ответов текущего месяца, автор вычисляется
// сравнением «до и после» (кто-то прошёл опрос — счётчик вырос, а средняя сдвинулась ровно на его оценку). Поэтому наружу
// отдаётся только последний ЗАКОНЧИВШИЙСЯ месяц и только если в нём не меньше ENPS_MIN_ANSWERS ответов (три). Текущий месяц — «идёт сбор».
// Для «Обратной связи»: { month, closed: true, count, score, promoters, passives, detractors, hidden?, minAnswers, collecting: true }
function enpsStats(scores) {
  const promoters = scores.filter(n => n >= 9).length;
  const detractors = scores.filter(n => n <= 6).length;
  return {
    score: scores.length ? Math.round(((promoters - detractors) / scores.length) * 100) : null,
    promoters, passives: scores.length - promoters - detractors, detractors
  };
}
async function getMonthEnps() {
  const today = venueDayStr(); // день заведения, как у самих ответов: до 06:00 первого числа прошлый месяц ещё не закрыт
  const curStart = today.slice(0, 8) + '01';
  const prevStart = addMonthsStr(curStart, -1);
  const label = new Date(prevStart + 'T12:00:00Z').toLocaleDateString('ru-RU', { timeZone: 'UTC', month: 'long', year: 'numeric' });
  const base = { month: label, closed: true, collecting: true, minAnswers: feedback.ENPS_MIN_ANSWERS };
  try {
    const entries = await memo(`month-enps:${prevStart}`, 2 * 60 * 1000, () => feedback.listEnps(prevStart));
    const scores = entries.filter(e => e.date && String(e.date).slice(0, 10) < curStart && typeof e.score === 'number').map(e => e.score);
    if (!scores.length) return { ...base, count: 0, score: null, promoters: 0, passives: 0, detractors: 0 };
    if (scores.length < feedback.ENPS_MIN_ANSWERS) return { ...base, count: scores.length, hidden: true, score: null, promoters: null, passives: null, detractors: null };
    return { ...base, count: scores.length, ...enpsStats(scores) };
  } catch (e) {
    console.error('Month eNPS fetch failed:', e);
    return { ...base, count: 0, score: null, promoters: 0, passives: 0, detractors: 0, failed: true };
  }
}

// ─── ДЕСКТОП: ЕДИНАЯ ТАБЛИЦА ГОСТЕЙ (сегмент, VIP, риск оттока) ──
// Объединяет то, что на мобильном разнесено по отдельным карточкам
// (Недавние/VIP/Давно не было), в одну таблицу с фильтрами на клиенте.
app.get('/api/admin/guests-table', async (req, res) => {
  if (!(await checkPerm(req, res, 'guests.table'))) return;

  try {
    // Все гости и все визиты (раньше — первые 100 гостей по алфавиту и последние 100 визитов бара,
    // из-за чего таблица была неполной, а «Риск оттока» ставился и тем, кто недавно был).
    const [cards, allVisits] = await Promise.all([getAllCards(), getAllVisits()]);
    const dates = visitDatesByGuest(allVisits);

    const rows = cards
      .map(c => {
        const seg = guestSegment(dates.get(c.id));
        return { ...guestListRow(c, seg), atRisk: isAtRisk(seg, c.vip) };
      })
      .sort((a, b) => a.name.localeCompare(b.name, 'ru'));

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch guests table' });
  }
});

// ─── ОБЩЕЕ ДЛЯ ОТЗЫВОВ, РАССЫЛОК, АНАЛИТИКИ ─────────
// Карточка гостя в удобном виде + кому из гостей можно написать от гостевого бота.
function getAllCards() {
  return memo('marketing:cards', 20 * 1000, () => cardsDb.allCards());
}

// Telegram ID гостя пишет гостевое приложение в базу (Postgres), когда гость бронирует или
// заполняет профиль. Отказ от рассылок («Не присылать рассылки», /stop) — тоже там.
function getGuestContacts() {
  return memo('marketing:contacts', 2 * 60 * 1000, () => store.getGuestContactsByPhone());
}

function isNonGrata(card) {
  return !!card.nonGrata || card.tagsSpecial.some(t => t.trim().toLowerCase() === 'нон-грата');
}
function firstName(name) {
  return String(name || '').trim().split(/\s+/)[0] || '';
}

// ─── БОТ ПРОСИТ ГОСТЯ ОЦЕНИТЬ ВИЗИТ ─────────────────
// Не донимаем гостей: просьба приходит на СЛЕДУЮЩИЙ день после визита, днём (по умолчанию 13:00–15:00),
// и не после каждого визита. Правила (числа — в таблице settings, ключ review_request_v2, ниже значения по умолчанию):
//   • первый визит гостя — спрашиваем всегда; дальше — каждый 4-й визит и не чаще раза в 45 дней
//     (для Чемпионов и «Лояльных+» — не чаще раза в 90 дней);
//   • VIP ботом не спрашиваем — про вечер спрашивает администратор лично;
//   • по гостю есть незакрытая проблема из его отзыва — не пишем, пока её не закроют;
//   • две просьбы подряд остались без ответа — пауза 120 дней;
//   • гость сам оставил отзыв за последние 30 дней, отписался, нон-грата, нет телефона/Telegram — не пишем;
//   • потолок за день (по умолчанию 15), сначала новички; одно сообщение, без напоминаний;
//   • не успели в окно — просьбу не отправляем вовсе (лучше пропустить, чем написать через два дня).
// Причина пропуска и результат пишутся в визит («Запрос отзыва»), чтобы не оценивать визит дважды.
// Выключить: переменная окружения REVIEW_REQUESTS=off или enabled=false в настройках.
async function getReviewRules() {
  return memo('review-rules', 60 * 1000, async () => {
    const rules = await reviewRulesDb.load(); // правила из настроек (экран «Просьбы об отзыве»), иначе значения по умолчанию
    const win = hoursWindow(process.env.REVIEW_REQUEST_HOURS, rules.from, rules.to); // переменная окружения важнее настройки
    rules.from = win.from; rules.to = win.to;
    if (process.env.REVIEW_REQUESTS === 'off') rules.enabled = false;
    return rules;
  });
}
const REVIEW_REASON_STATUS = {
  no_telegram: 'Нет Telegram',
  opted_out: 'Отписан',
  review_opt_out: 'Отписан', // нажал «Не спрашивать об оценке»
  recent_review: 'Недавно оставил отзыв',
  blocked: 'Не доставлен',
  failed: 'Не доставлен'
};
const REGULAR_SEGMENT_KEYS = ['champions', 'loyalPlus'];

async function markVisitReviewRequest(visit, status) {
  await cardsDb.setVisitReviewRequest(visit.id, status || null);
  visit.reviewRequest = status || '';
}

// Кого уже просили (guestId → время) — в памяти: страховка от двойной отправки, если отметка в базе не записалась
const reviewAskedAt = new Map();
let reviewRequestsRunning = false;

// Подошла ли гостю очередь по правилу «первый визит, потом каждый N-й, не чаще раза в M дней».
// visitDates — отсортированные даты визитов гостя; asked — даты визитов, за которые просьбу уже отправляли.
function reviewTurn({ visitDate, visitDates, asked, rules, regular }) {
  const ordinal = visitDates.filter(d => d <= visitDate).length;
  const prevAsked = asked.filter(d => d < visitDate);
  if (!prevAsked.length) {
    const ok = (rules.first_visit_always && ordinal === 1) || ordinal >= rules.every_nth_visit;
    return { ok, reason: ok ? null : 'Не очередь', ordinal, first: ordinal === 1 };
  }
  const lastAsked = prevAsked[prevAsked.length - 1];
  const sinceLast = visitDates.filter(d => d > lastAsked && d <= visitDate).length;
  const minDays = regular ? rules.regular_min_days : rules.min_days;
  if (daysBetween(lastAsked, visitDate) < minDays) return { ok: false, reason: 'Недавно спрашивали', ordinal, first: false };
  if (sinceLast < rules.every_nth_visit) return { ok: false, reason: 'Не очередь', ordinal, first: false };
  return { ok: true, reason: null, ordinal, first: false };
}

// Просьбы, оставшиеся «Отправляется» дольше 10 минут (сервер перезапустили посреди отправки): дошло ли сообщение,
// уже не узнать. Второй раз гостю не пишем — помечаем «не доставлен», чтобы статус не висел вечно.
async function closeStaleReviewRequests() {
  try {
    const r = await store.db.query("UPDATE visits SET review_request_status = 'failed' WHERE review_request_status = 'sending' AND review_requested_at < now() - interval '10 minutes'");
    if (r.rowCount) { console.log(`Просьбы об отзыве: зависших «Отправляется» закрыто — ${r.rowCount}`); forgetMemo('visits'); }
  } catch (e) { console.error('Не удалось закрыть зависшие просьбы об отзыве:', e.message); }
}

async function processReviewRequests({ force = false } = {}) {
  const summary = { checked: 0, sent: 0, marked: {}, skippedReason: null };
  const rules = await getReviewRules();
  if (!rules.enabled) { summary.skippedReason = 'disabled'; return summary; }
  if (!force && !inHoursWindow({ from: rules.from, to: rules.to })) { summary.skippedReason = 'night'; return summary; }
  if (reviewRequestsRunning) { summary.skippedReason = 'running'; return summary; }
  reviewRequestsRunning = true;
  try {
    await closeStaleReviewRequests();
    const visits = await getAllVisits();
    const now = Date.now();
    const yesterday = addDaysStr(venueDayStr(), -1); // просим про вчерашний вечер; старые визиты, внесённые задним числом, не трогаем

    const datesByGuest = new Map();
    const askedByGuest = new Map();      // даты визитов, за которые просьба уже отправлена
    for (const v of visits) {
      if (!v.guestId || !v.date) continue;
      const d = v.date.slice(0, 10);
      if (!datesByGuest.has(v.guestId)) datesByGuest.set(v.guestId, []);
      datesByGuest.get(v.guestId).push(d);
      if (v.reviewRequest === 'Отправлен' || v.reviewRequest === 'Отправляется') {
        if (!askedByGuest.has(v.guestId)) askedByGuest.set(v.guestId, []);
        askedByGuest.get(v.guestId).push(d);
      }
    }
    for (const list of datesByGuest.values()) list.sort();
    for (const list of askedByGuest.values()) list.sort();

    const candidates = visits.filter(v => !v.reviewRequest && v.guestId && v.date && v.date.slice(0, 10) === yesterday);
    if (!candidates.length) return summary;

    // потолок за день: сколько просьб за вчерашние визиты уже ушло
    let sentToday = visits.filter(v => v.date && v.date.slice(0, 10) === yesterday && (v.reviewRequest === 'Отправлен' || v.reviewRequest === 'Отправляется')).length;

    // новички (первый визит) — первыми, остальные по времени записи
    const firstDate = g => (datesByGuest.get(g) || [])[0];
    candidates.sort((a, b) => {
      const fa = firstDate(a.guestId) === yesterday ? 0 : 1, fb = firstDate(b.guestId) === yesterday ? 0 : 1;
      return (fa - fb) || ((Date.parse(a.createdAt) || 0) - (Date.parse(b.createdAt) || 0));
    });

    const reviewDates = await feedback.reviewDatesByGuest([...new Set(candidates.map(v => v.guestId))]);
    const cards = await getAllCards();
    const cardById = new Map(cards.map(c => [c.id, c]));
    const bannedPhones = new Set(cards.filter(isNonGrata).map(c => normalizePhone(c.phone)).filter(Boolean));

    const mark = async (visit, status) => {
      await markVisitReviewRequest(visit, status);
      if (status) summary.marked[status] = (summary.marked[status] || 0) + 1;
    };

    const handledGuests = new Set();
    for (const visit of candidates) {
      if (summary.checked >= 200 || summary.sent >= rules.per_run) break;
      summary.checked++;
      try {
        const guestId = visit.guestId;
        const card = cardById.get(guestId) || await cardsDb.getCard(guestId);
        if (!card || card.archived) continue; // карточку не прочитали или объединили — не трогаем
        const visitDate = visit.date.slice(0, 10);
        const segKey = guestSegment(datesByGuest.get(guestId)).key;
        const regular = REGULAR_SEGMENT_KEYS.includes(segKey);

        if (handledGuests.has(guestId) || (reviewAskedAt.get(guestId) && now - reviewAskedAt.get(guestId) < 20 * 3600 * 1000)) { await mark(visit, 'Недавно спрашивали'); continue; }
        handledGuests.add(guestId);

        if (isNonGrata(card) || bannedPhones.has(normalizePhone(card.phone))) { await mark(visit, 'Нон-грата'); continue; }

        const turn = reviewTurn({ visitDate, visitDates: datesByGuest.get(guestId) || [visitDate], asked: askedByGuest.get(guestId) || [], rules, regular });
        if (!turn.ok) { await mark(visit, turn.reason); continue; }

        if (rules.skip_vip && card.vip) { await mark(visit, 'VIP'); continue; }
        if (!card.phone) { await mark(visit, 'Нет телефона'); continue; }

        // две последние просьбы остались без ответа — пауза: ответом считаем отзыв гостя в течение недели после просьбы
        const asked = (askedByGuest.get(guestId) || []).filter(d => d < visitDate);
        if (rules.ignored_in_row > 0 && asked.length >= rules.ignored_in_row) {
          const answered = d => (reviewDates.get(guestId) || []).some(rd => rd >= d && rd <= addDaysStr(d, 8));
          const lastN = asked.slice(-rules.ignored_in_row);
          const lastAsked = lastN[lastN.length - 1];
          if (lastN.every(d => !answered(d)) && daysBetween(lastAsked, visitDate) < rules.ignored_pause_days) { await mark(visit, 'Пауза'); continue; }
        }

        if (await feedback.hasOpenProblemForGuest(guestId)) { await mark(visit, 'Есть проблема'); continue; }
        if (await feedback.hasRecentReview({ guestId, phone: normalizePhone(card.phone), days: rules.recent_review_days })) { await mark(visit, 'Недавно оставил отзыв'); continue; }

        if (sentToday >= rules.daily_cap) { summary.skippedReason = 'daily_cap'; break; } // не помечаем: просьба просто не уйдёт

        // Сначала помечаем визит, потом пишем гостю. Не получилось пометить — не пишем.
        await mark(visit, 'Отправляется');
        reviewAskedAt.set(guestId, now);
        const result = await callGuestProxy('/api/internal/review-request', { phone: card.phone, name: firstName(card.name), recentReviewDays: rules.recent_review_days }, 1, 30000);
        if (!result.reached && result.maybeDelivered) {
          // Ответа не дождались, но запрос ушёл: гость мог получить сообщение. Повторять нельзя — иначе он
          // получит просьбу дважды. Помечаем «не доставлен» и больше за этот визит не пишем.
          await mark(visit, 'Не доставлен');
          continue;
        }
        if (!result.reached || result.httpError) {
          // до гостевого сервера не достучались вовсе — снимаем отметку, повторим при следующем проходе (окно ещё открыто)
          reviewAskedAt.delete(guestId);
          await mark(visit, null);
          continue;
        }
        if (result.sent) {
          await mark(visit, 'Отправлен');
          sentToday++;
          summary.sent++;
        } else {
          reviewAskedAt.delete(guestId);
          await mark(visit, REVIEW_REASON_STATUS[result.reason] || 'Не доставлен');
        }
      } catch (e) {
        // отметка в базе не записалась — останавливаем проход, чтобы не наделать дублей
        console.error('Review request for visit failed, stopping this run:', visit.id, e.message);
        summary.skippedReason = 'mark_failed';
        break;
      }
    }
    if (summary.sent) forgetMemo('feedback');
    return summary;
  } catch (e) {
    console.error('Review requests run failed:', e.message);
    summary.skippedReason = 'error';
    return summary;
  } finally {
    reviewRequestsRunning = false;
  }
}

setInterval(() => { processReviewRequests(); }, 10 * 60 * 1000);
setTimeout(() => { processReviewRequests(); }, 90 * 1000);

// Запустить проверку вручную (админ) — например, сразу после настройки
app.post('/api/admin/review-requests/run', async (req, res) => {
  if (!(await checkPerm(req, res, 'review_requests.run'))) return;
  const summary = await processReviewRequests({ force: req.body?.force === true });
  auditNote(req, 'settings.review_requests_run', 'settings', 'review_request_v2',
    `запущена проверка просьб об отзыве вручную${req.body?.force === true ? ' (вне окна отправки)' : ''}: отправлено ${summary.sent}`);
  res.json({ ok: true, ...summary });
});

// Экран «Просьбы об отзыве»: правила (когда и кому бот просит оценить визит) меняются здесь, без правки кода.
// Право settings.manage — только основатель (не выдаётся галочкой).
app.get('/api/admin/review-rules', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  try {
    const [rules, meta, stats] = await Promise.all([reviewRulesDb.load(), reviewRulesDb.meta(), reviewRulesDb.stats(7)]);
    const envHours = /^(\d{1,2})-(\d{1,2})$/.test(String(process.env.REVIEW_REQUEST_HOURS || ''));
    res.json({
      rules, defaults: reviewRulesDb.DEFAULTS, limits: Object.fromEntries(Object.entries(reviewRulesDb.SPEC).filter(([, v]) => v.type === 'int').map(([k, v]) => [k, { min: v.min, max: v.max }])),
      meta, stats,
      locked: { hours: envHours ? process.env.REVIEW_REQUEST_HOURS : null, off: process.env.REVIEW_REQUESTS === 'off' }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось загрузить правила' });
  }
});

app.put('/api/admin/review-rules', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  try {
    const result = await reviewRulesDb.save(req.body?.rules, req.employee);
    forgetMemo('review-rules');
    res.json({ ok: true, ...result });
  } catch (error) {
    if (error instanceof reviewRulesDb.RulesError) return res.status(error.status).json({ error: error.message });
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить правила' });
  }
});

// ─── ЖУРНАЛ ДЕЙСТВИЙ (Сервис → Система → Журнал) ─────
// Кто, когда и что менял. Смотреть может только основатель (право audit.view — не выдаётся галочкой).
// Записи: гости и теги, брони, меню и стоп-лист, сотрудники и права, сторис, опросы, афиша, задачи, график, проблемы, рассылки, настройки.
app.get('/api/admin/audit', async (req, res) => {
  if (!(await checkPerm(req, res, 'audit.view'))) return;
  try {
    const b = req.query.before;
    res.json(await auditDb.list({
      q: req.query.q, days: req.query.days === undefined ? null : req.query.days,
      who: req.query.who, type: req.query.type, before: b === undefined ? null : b,
      limit: req.query.limit, first: !b
    }));
  } catch (error) {
    console.error('Журнал действий не загрузился:', error.message);
    res.status(500).json({ error: 'Не удалось загрузить журнал' });
  }
});

// ─── МАРКЕТИНГ: СЕГМЕНТЫ И РАССЫЛКИ ЧЕРЕЗ ГОСТЕВОГО БОТА ──
// Готовые сегменты гостей из «Карточки Гостя» + визитов. Написать можно только тем,
// у кого есть Telegram (гость хоть раз открывал гостевое приложение) и кто не нажал
// «Не присылать рассылки». Гостей с тегом «Нон-грата» в рассылки не берём никогда.
// Отправляем только с 10:00 до 21:00, в сообщении можно писать {имя}.
const MARKETING_HOURS = hoursWindow(process.env.MARKETING_HOURS, 10, 21);
const MARKETING_TEXT_MAX = 3500;
// group: 'rfm' — сегменты по визитам (Чемпионы … Потерянные), 'other' — остальные подборки
const MARKETING_SEGMENTS = [
  ...SEGMENTS.map(s => ({ key: s.key, title: s.name, description: s.description, group: 'rfm' })),
  { key: 'all', title: 'Все гости', description: 'Все карточки гостей', group: 'other' },
  { key: 'vip', title: 'VIP', description: 'С тегом VIP', group: 'other' },
  { key: 'new', title: 'Новые', description: 'Первый визит за последние 30 дней', group: 'other' },
  { key: 'risk', title: 'Риск оттока', description: '', group: 'other' },
  { key: 'inactive60', title: 'Давно не были', description: 'Не были 60+ дней', group: 'other' },
  { key: 'birthday', title: 'Скоро день рождения', description: 'ДР сегодня или в ближайшие 7 дней', group: 'other' }
];
// Описания сегментов в рассылках идут за границами из «Правил сегментов»
function refreshMarketingSegmentTexts() {
  for (const m of MARKETING_SEGMENTS) {
    if (m.group === 'rfm' && SEGMENT_BY_KEY[m.key]) m.description = SEGMENT_BY_KEY[m.key].description;
    if (m.key === 'risk') m.description = `Ходили (от ${SEGMENT_RULES.loyalVisits} визитов ${windowText(SEGMENT_RULES)}) или VIP, но не были больше ${SEGMENT_RULES.recentDays} дней`;
  }
}
refreshMarketingSegmentTexts();

async function marketingContext() {
  const [cards, contacts, visits] = await Promise.all([getAllCards(), getGuestContacts(), getAllVisits()]);
  const dates = visitDatesByGuest(visits);
  const lastVisit = {}, firstVisit = {}, segOf = new Map();
  for (const c of cards) {
    const d = dates.get(c.id);
    if (d && d.length) { firstVisit[c.id] = d[0]; lastVisit[c.id] = d[d.length - 1]; }
    segOf.set(c.id, guestSegment(d));
  }
  return { cards, contacts, lastVisit, firstVisit, segOf };
}

// "like:Ягодные" → вкусы (любит), "special:Не любит шум" → особые
function parseTagKey(tagKey) {
  const m = String(tagKey || '').match(/^(like|special):(.+)$/);
  return m ? { group: m[1], name: m[2] } : null;
}

function segmentMatcher(key, tagKey, ctx) {
  const today = venueDateStr();
  switch (key) {
    case 'all': return () => true;
    case 'vip': return c => c.vip;
    case 'new': return c => !!ctx.firstVisit[c.id] && ctx.firstVisit[c.id] >= addDaysStr(today, -29);
    case 'risk': return c => isAtRisk(ctx.segOf.get(c.id), c.vip);
    case 'inactive60': return c => {
      const d = daysSinceDate(ctx.lastVisit[c.id]);
      return d !== null && d >= 60;
    };
    case 'birthday': return c => {
      const b = birthdayInfo(c.birthday, today);
      return !!b && (b.when === 'today' || b.when === 'soon');
    };
    case 'tag': {
      const t = parseTagKey(tagKey);
      if (!t) return null;
      const n = t.name.trim().toLowerCase();
      const list = c => (t.group === 'like' ? c.tastesLike : c.tagsSpecial);
      return c => list(c).some(x => x.trim().toLowerCase() === n);
    }
    default:
      if (SEGMENT_BY_KEY[key]) return c => ctx.segOf.get(c.id)?.key === key;
      return null;
  }
}

function segmentTitle(key, tagKey) {
  if (key === 'tag') {
    const t = parseTagKey(tagKey);
    return t ? `${t.group === 'like' ? 'Любит' : 'Тег'}: ${t.name}` : 'Тег';
  }
  return MARKETING_SEGMENTS.find(s => s.key === key)?.title || key;
}

// Гости сегмента: у каждого — можно ли написать и почему нет
// Нон-грата исключаем не только по самой карточке: если у гостя есть вторая карточка
// с тем же телефоном или тем же Telegram — ей тоже не пишем.
function bannedContacts(ctx) {
  if (ctx.banned) return ctx.banned;
  const phones = new Set(), telegramIds = new Set();
  for (const c of ctx.cards) {
    if (!isNonGrata(c)) continue;
    const phone = normalizePhone(c.phone);
    if (!phone) continue;
    phones.add(phone);
    const tgId = ctx.contacts.get(phone)?.telegramId;
    if (tgId) telegramIds.add(tgId);
  }
  return (ctx.banned = { phones, telegramIds });
}

function buildSegment(key, tagKey, ctx) {
  const match = segmentMatcher(key, tagKey, ctx);
  if (!match) return null;
  const banned = bannedContacts(ctx);
  const seenTelegram = new Set();
  const guests = [];
  for (const c of ctx.cards) {
    if (isNonGrata(c) || !match(c)) continue;
    const phone = normalizePhone(c.phone);
    const contact = phone ? ctx.contacts.get(phone) : null;
    if ((phone && banned.phones.has(phone)) || (contact?.telegramId && banned.telegramIds.has(contact.telegramId))) continue;
    let reason = null;
    if (!phone) reason = 'no_phone';
    else if (!contact?.telegramId) reason = 'no_telegram';
    else if (contact.optOut) reason = 'opted_out';
    else if (seenTelegram.has(contact.telegramId)) reason = 'duplicate';
    if (!reason) seenTelegram.add(contact.telegramId);
    guests.push({
      id: c.id,
      name: c.name,
      vip: c.vip,
      segment: ctx.segOf.get(c.id)?.name || '',
      lastVisit: ctx.lastVisit[c.id] || null,
      daysSince: daysSinceDate(ctx.lastVisit[c.id]),
      reachable: !reason,
      reason,
      telegramId: reason ? null : contact.telegramId
    });
  }
  return {
    key, tag: tagKey || null,
    title: segmentTitle(key, tagKey),
    total: guests.length,
    reachable: guests.filter(g => g.reachable).length,
    guests
  };
}

function personalize(text, name) {
  const first = firstName(name);
  if (first) return text.replace(/\{имя\}/gi, first);
  // имени нет — убираем обращение аккуратно: "Привет, {имя}!" → "Привет!"
  const cleaned = text.replace(/,?\s*\{имя\}/gi, '').replace(/^\s*[,!.]\s*/, '');
  return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}

app.get('/api/admin/marketing/segments', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    // Подсчёт сегментов и тегов проходит по всем гостям десятки раз подряд (на 6 000 гостей — около секунды, и всё это время
    // сервер никому не отвечает), поэтому держим готовый результат 20 секунд; изменение карточек (afterCardChange) сбрасывает его.
    const { segments, tags } = await memo('marketing:segments', 20 * 1000, async () => {
      const ctx = await marketingContext();
      const segments = MARKETING_SEGMENTS.map(s => {
        const seg = buildSegment(s.key, null, ctx);
        return { ...s, total: seg.total, reachable: seg.reachable };
      });

      // Теги для сегмента «по тегу»: вкусы (любит) и особые, самые частые сверху
      const tagCounts = new Map();
      for (const c of ctx.cards) {
        if (isNonGrata(c)) continue;
        for (const t of c.tastesLike) tagCounts.set(`like:${t}`, (tagCounts.get(`like:${t}`) || 0) + 1);
        for (const t of c.tagsSpecial) tagCounts.set(`special:${t}`, (tagCounts.get(`special:${t}`) || 0) + 1);
      }
      const tags = [...tagCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 40)
        .map(([key, total]) => {
          const seg = buildSegment('tag', key, ctx);
          return { key, label: segmentTitle('tag', key), total, reachable: seg.reachable };
        });
      return { segments, tags };
    });

    res.json({
      segments,
      tags,
      hours: MARKETING_HOURS,
      canSendNow: inHoursWindow(MARKETING_HOURS),
      running: broadcastJobs.find(j => j.status === 'Отправляется') ? publicJob(broadcastJobs.find(j => j.status === 'Отправляется')) : null
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось посчитать сегменты' });
  }
});

app.get('/api/admin/marketing/segment', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    const seg = buildSegment(req.query.key, req.query.tag, await marketingContext());
    if (!seg) return res.status(400).json({ error: 'Неизвестный сегмент' });
    const guests = seg.guests
      .sort((a, b) => Number(b.reachable) - Number(a.reachable) || a.name.localeCompare(b.name, 'ru'))
      .slice(0, 300)
      .map(({ telegramId, ...g }) => g);
    res.json({ ...seg, guests });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось загрузить сегмент' });
  }
});

// ── Журнал рассылок: таблица broadcasts в Postgres ──
// Запись создаётся в момент старта рассылки и обновляется по итогу. Идущая рассылка отслеживается в памяти
// сервера (там самые свежие счётчики). Если сервер перезапустили посреди отправки, при старте такие
// записи помечаются «Прервана» (см. bootAbortStale).
const broadcastJobs = []; // свежие сверху, до 50
let broadcastSeq = 0;
let broadcastStarting = false;

function publicJob(j) {
  return {
    id: j.dbId || j.id, createdAt: j.createdAt, finishedAt: j.finishedAt || null,
    segment: j.segmentTitle, text: j.text, author: j.author,
    total: j.total, sent: j.sent, failed: j.failed, blocked: j.blocked, status: j.status
  };
}

async function saveBroadcastLog(j) {
  try {
    if (!j.dbId) j.dbId = await catalog.createBroadcast(j, j.authorEmployee);
    else await catalog.updateBroadcast(j.dbId, j);
  } catch (e) {
    console.error('Не удалось записать рассылку в журнал:', e.message);
  }
}

async function runBroadcast(job, recipients) {
  const BATCH = 25;
  let errors = 0;
  for (let i = 0; i < recipients.length; i += BATCH) {
    const batch = recipients.slice(i, i + BATCH);
    // respectOptOut: гостевой сервер перед самой отправкой ещё раз сверяется со списком отписавшихся —
    // гость, нажавший «Не присылать рассылки» минуту назад или уже во время рассылки, сообщение не получит.
    const result = await callGuestProxy('/api/internal/broadcast', {
      respectOptOut: true,
      messages: batch.map(r => ({ chatId: r.telegramId, text: personalize(job.text, r.name) }))
    }, 1, 180000);
    if (!result.reached || result.httpError) {
      job.failed += batch.length;
      if (result.maybeDelivered) job.unknown = (job.unknown || 0) + batch.length; // ответа не дождались: часть могла дойти
      errors++;
      if (errors >= 3) { job.status = 'Прервана'; job.failed += recipients.length - (i + batch.length); break; }
      continue;
    }
    job.sent += result.sent || 0;
    job.failed += result.failed || 0;
    job.blocked += result.blocked || 0;
    job.skipped = (job.skipped || 0) + (result.skipped || 0);
  }
  if (job.status === 'Отправляется') job.status = 'Отправлена';
  job.finishedAt = new Date().toISOString();
  await saveBroadcastLog(job);
  if (job.campaignId) {
    try {
      await mailings.markMassDone(job.campaignId, { total: job.total, sent: job.sent, failed: job.failed, blocked: job.blocked, at: job.finishedAt, aborted: job.status === 'Прервана' });
    } catch (e) { console.error('Не удалось записать итог рассылки:', e.message); }
  }

  const report =
    `📣 Рассылка «${job.segmentTitle}» ${job.status === 'Прервана' ? 'прервана — гостевой бот не отвечает' : 'отправлена'}\n` +
    `Доставлено: ${job.sent} из ${job.total}` +
    (job.failed ? `\nНе доставлено: ${job.failed}${job.blocked ? ` (заблокировали бота: ${job.blocked})` : ''}` : '') +
    (job.skipped ? `\nОтписались перед отправкой: ${job.skipped}` : '') +
    (job.unknown ? `\n⚠️ По ${job.unknown} гостям ответа не дождались — часть из них могла получить сообщение` : '') +
    (job.status === 'Прервана' && job.sent ? `\n⚠️ Если отправить этот текст тому же сегменту ещё раз, ${job.sent} гостей получат его повторно` : '') +
    `\nАвтор: ${job.author}`;
  await sendAdmin(report, 'итог рассылки');
  if (job.authorTelegramId && String(job.authorTelegramId) !== String(ADMIN_CHAT_ID)) {
    await sendTelegramMessage(job.authorTelegramId, report);
  }
}

// Кому писать: один или несколько сегментов вместе (гость, попавший в два сегмента, и две карточки с одним Telegram — получатель один).
// Пустой список — все гости. null — какой-то из сегментов неизвестен.
function audienceOf(ctx, segments) {
  const list = segments && segments.length ? segments : [{ key: 'all' }];
  const seenTg = new Set(), seenId = new Set(), guests = [], titles = [];
  for (const s of list) {
    const seg = buildSegment(s.key, s.tag || null, ctx);
    if (!seg) return null;
    titles.push(seg.title);
    for (const g of seg.guests) {
      if (seenId.has(g.id)) continue;
      seenId.add(g.id);
      if (g.reachable) {
        if (seenTg.has(g.telegramId)) { guests.push({ ...g, reachable: false, reason: 'duplicate', telegramId: null }); continue; }
        seenTg.add(g.telegramId);
      }
      guests.push(g);
    }
  }
  return { title: titles.join(' + '), total: guests.length, reachable: guests.filter(g => g.reachable).length, guests };
}

// Запуск массовой отправки: из старого экрана (один сегмент) и из конструктора рассылок (несколько сегментов, в том числе по расписанию).
// Возвращает { job } или { http, error }. campaignId — если отправка идёт из рассылки конструктора: по её окончании итог запишется в неё.
async function launchMassBroadcast({ segments, text, author, employee, campaignId, campaignTitle }) {
  if (!inHoursWindow(MARKETING_HOURS)) {
    return { http: 400, error: `Рассылки отправляются с ${MARKETING_HOURS.from}:00 до ${MARKETING_HOURS.to}:00, чтобы не беспокоить гостей ночью` };
  }
  // Блокировка ставится сразу, до первого await: два почти одновременных нажатия
  // (двойной тап, два админа) не должны запустить одну и ту же рассылку дважды.
  if (broadcastStarting || broadcastJobs.some(j => j.status === 'Отправляется')) {
    return { http: 409, error: 'Предыдущая рассылка ещё отправляется — дождитесь её окончания' };
  }
  broadcastStarting = true;
  try {
    forgetMemo('marketing:contacts'); // список отписавшихся — свежий, а не двухминутной давности
    const aud = audienceOf(await marketingContext(), segments);
    if (!aud) return { http: 400, error: 'Неизвестный сегмент' };
    const recipients = aud.guests.filter(g => g.reachable);
    if (!recipients.length) {
      return { http: 400, error: `${segments && segments.length > 1 ? 'В выбранных сегментах' : 'В этом сегменте'} некому написать: ни у кого нет Telegram или все отписались` };
    }

    const job = {
      id: `b${Date.now()}${++broadcastSeq}`,
      createdAt: new Date().toISOString(),
      segmentTitle: campaignTitle ? `${campaignTitle} · ${aud.title}` : aud.title,
      text,
      author: author || 'Рассылка по расписанию',
      authorTelegramId: employee && employee.telegramId || null,
      authorEmployee: employee ? { id: employee.id, name: employee.name, role: employee.role } : null,
      campaignId: campaignId || null,
      total: recipients.length, sent: 0, failed: 0, blocked: 0,
      status: 'Отправляется'
    };
    broadcastJobs.unshift(job);
    if (broadcastJobs.length > 50) broadcastJobs.length = 50;
    await saveBroadcastLog(job);
    auditDb.record({ actor: employee || null, action: 'marketing.sent', type: 'marketing', id: job.dbId || job.id,
      summary: `запущена рассылка «${aud.title}»: ${recipients.length} получателей, текст «${text.slice(0, 80)}${text.length > 80 ? '…' : ''}»` });

    // Отправка идёт в фоне — итог придёт админу в Telegram и появится в журнале
    runBroadcast(job, recipients).catch(e => {
      console.error('Broadcast failed:', e);
      job.status = 'Прервана';
      saveBroadcastLog(job);
    });
    return { job, recipients: recipients.length, title: aud.title };
  } catch (error) {
    console.error(error);
    return { http: 500, error: 'Не удалось запустить рассылку' };
  } finally {
    broadcastStarting = false;
  }
}

app.post('/api/admin/marketing/send', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  const { key, tag, test } = req.body || {};
  const text = String(req.body?.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Напишите текст рассылки' });
  if (text.length > MARKETING_TEXT_MAX) return res.status(400).json({ error: `Слишком длинный текст — максимум ${MARKETING_TEXT_MAX} символов` });

  // Проверка «себе»: то же сообщение приходит только автору — от гостевого бота
  if (test) {
    if (!req.employee.telegramId) return res.status(400).json({ error: 'У вас в базе «Сотрудники» не указан Telegram ID — некуда отправить проверку' });
    const result = await callGuestProxy('/api/internal/broadcast', {
      messages: [{ chatId: req.employee.telegramId, text: personalize(text, req.employee.name) }]
    }, 1);
    if (!result.reached || result.httpError) return res.status(502).json({ error: 'Гостевой бот не отвечает, попробуйте ещё раз' });
    if (!result.sent) return res.status(400).json({ error: 'Гостевой бот не смог вам написать — откройте его в Telegram и нажмите «Старт», потом повторите' });
    return res.json({ ok: true, test: true });
  }

  const r = await launchMassBroadcast({
    segments: [{ key, tag }], text, employee: req.employee,
    author: `${req.employee.name}${req.employee.role ? ` (${req.employee.role})` : ''}`
  });
  if (r.error) return res.status(r.http || 500).json({ error: r.error });
  res.json({ ok: true, job: publicJob(r.job) });
});

app.get('/api/admin/marketing/log', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.log'))) return;
  try {
    const rows = await catalog.listBroadcasts(30);
    // Свежие счётчики идущей рассылки — из памяти (в базу пишем начало и итог)
    const live = new Map(broadcastJobs.filter(j => j.dbId).map(j => [j.dbId, publicJob(j)]));
    const merged = rows.map(r => live.get(r.id) || r);
    for (const j of broadcastJobs) if (!j.dbId) merged.push(publicJob(j)); // в базу записать не удалось — показываем из памяти
    merged.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
    res.json({ storedInNotion: true, stored: true, broadcasts: merged.slice(0, 30) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось загрузить журнал рассылок' });
  }
});

// ─── РАССЫЛКИ-КОНСТРУКТОР ───────────────────────────
// Рассылка — это шаги «Основные детали → Условия → Контент» (как в CosmosResto). Три типа:
//   • массовая — одна отправка выбранным сегментам: сразу или в назначенное время;
//   • маркетинговая — работает сама: по событию (визит, неявка, день рождения, гость попал в сегмент) с задержкой или по расписанию;
//     пишет только тем, кто не отписался; не чаще раза в сутки одному гостю (кроме рассылок с повышенным приоритетом);
//   • сервисная — по событию, как маркетинговая, но отписавшимся тоже приходит и окно отправки шире. Только по делу, не реклама.
// События ищет планировщик раз в минуту (mailingsTick): записывает в очередь «кому, когда», а в нужный час очередь уходит через гостевого бота.
// Данные — таблицы mailing_* (миграция 046). Кому можно писать, решают те же правила, что и для обычных рассылок: Telegram, отписка, «Нон-грата».
const SERVICE_HOURS = hoursWindow(process.env.MAILING_SERVICE_HOURS, 9, 22);
const MARKETING_GAP_HOURS = (() => {
  const raw = process.env.MARKETING_GAP_HOURS;
  const n = raw === undefined || raw === '' ? 24 : Number(raw);
  return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 24;
})();
const MAILINGS_ENABLED = process.env.MAILINGS !== 'off';
const MAILING_BATCH = 40;                  // не больше стольких сообщений за одну минуту
const MAILING_MASS_LATE_HOURS = 12;        // массовая, которую сервер не успел отправить вовремя больше чем на 12 часов, не уходит
function mailingWindow(kind) { return kind === 'service' ? SERVICE_HOURS : MARKETING_HOURS; }

// События, после которых можно отправлять. iiko: true — появятся после подключения кассы
const MAILING_TRIGGER_INFO = [
  { key: 'visit', title: 'После визита', hint: 'Гость побывал у нас — визит записан в карточке. Просьбу оценить визит бот присылает отдельно («Просьбы об отзыве»).' },
  { key: 'first_visit', title: 'После первого визита', hint: 'Гость пришёл впервые: поблагодарить и позвать снова.' },
  { key: 'no_show', title: 'Неявка по брони', hint: 'Бронь отмечена «не пришёл».' },
  { key: 'birthday_soon', title: 'Скоро день рождения', hint: 'За несколько дней до дня рождения. В сам день бот поздравляет отдельно («Поздравления»).' },
  { key: 'segment_enter', title: 'Гость попал в сегмент', hint: 'Например, стал «Лояльным» или «Давно не был». Тем, кто в сегменте уже сейчас, не пишем — только тем, кто войдёт после запуска.' },
  { key: 'check_closed', title: 'Закрыт чек', iiko: true, hint: 'Появится после подключения iiko.' },
  { key: 'bonus', title: 'Начислены или списаны бонусы', iiko: true, hint: 'Появится после подключения iiko.' },
  { key: 'loyalty_level', title: 'Изменился уровень лояльности', iiko: true, hint: 'Появится после подключения iiko.' }
];

function mailingSegmentValid(key, tag) {
  if (key === 'tag') return !!parseTagKey(tag);
  return MARKETING_SEGMENTS.some(s => s.key === key);
}
const mailingInput = (body) => mailings.normalizeInput(body, { validSegment: mailingSegmentValid });
const mailingAuthor = (employee) => `${employee.name}${employee.role ? ` (${employee.role})` : ''}`;
const MAILING_REASON = {
  no_guest: 'карточки гостя больше нет', non_grata: 'нон-грата', no_phone: 'нет телефона', no_telegram: 'нет Telegram', opted_out: 'отписался от рассылок',
  duplicate: 'тот же Telegram, что у другой карточки', not_in_segment: 'гость уже не в выбранных сегментах', left_segment: 'вышел из сегмента',
  event_gone: 'событие отменили', too_often: 'слишком часто', expired: 'опоздали больше чем на двое суток', unknown: 'связь оборвалась — часть могла дойти',
  interrupted: 'сервер перезапустили во время отправки', unreachable: 'гостевой бот не отвечал', telegram: 'Telegram не принял сообщение'
};

function mailingsMeta() {
  const running = broadcastJobs.find(j => j.status === 'Отправляется');
  return {
    triggers: MAILING_TRIGGER_INFO,
    hours: MARKETING_HOURS, serviceHours: SERVICE_HOURS, gapHours: MARKETING_GAP_HOURS,
    canSendNow: inHoursWindow(MARKETING_HOURS),
    running: running ? publicJob(running) : null,
    enabled: MAILINGS_ENABLED
  };
}

app.get('/api/admin/mailings', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    res.json({ campaigns: await mailings.list(), ...mailingsMeta() });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось загрузить рассылки' });
  }
});

// Сколько гостей в выбранных сегментах и скольким из них можно написать
app.post('/api/admin/mailings/audience', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    const segs = [];
    for (const s of (Array.isArray(req.body?.segments) ? req.body.segments : []).slice(0, 30)) {
      if (!s || !mailingSegmentValid(String(s.key || ''), s.tag ? String(s.tag) : null)) return res.status(400).json({ error: 'Неизвестный сегмент' });
      segs.push({ key: String(s.key), tag: s.tag ? String(s.tag) : null });
    }
    const aud = audienceOf(await marketingContext(), segs);
    if (!aud) return res.status(400).json({ error: 'Неизвестный сегмент' });
    const reasons = {};
    for (const g of aud.guests) if (!g.reachable) reasons[g.reason] = (reasons[g.reason] || 0) + 1;
    const sample = aud.guests.find(g => g.reachable)?.name || aud.guests[0]?.name || '';
    res.json({ title: aud.title, total: aud.total, reachable: aud.reachable, reasons, sample, all: !segs.length });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось посчитать получателей' });
  }
});

app.get('/api/admin/mailings/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    const campaign = await mailings.get(req.params.id);
    if (!campaign) return res.status(404).json({ error: 'Рассылка не найдена' });
    const sends = campaign.kind === 'mass' ? [] : await mailings.recentSends(campaign.id, 30);
    res.json({ campaign, sends: sends.map(x => ({ ...x, reasonText: MAILING_REASON[x.reason] || x.reason })), ...mailingsMeta() });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось загрузить рассылку' });
  }
});

app.post('/api/admin/mailings', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  const parsed = mailingInput(req.body);
  if (parsed.error) return res.status(400).json({ error: parsed.error });
  try {
    const id = await mailings.create(parsed.value, req.employee);
    auditNote(req, 'mailing.created', 'mailing', id, `создана рассылка «${parsed.value.title}»`);
    res.json({ ok: true, campaign: await mailings.get(id) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить рассылку' });
  }
});

app.put('/api/admin/mailings/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  const parsed = mailingInput(req.body);
  if (parsed.error) return res.status(400).json({ error: parsed.error });
  try {
    const cur = await mailings.get(req.params.id);
    if (!cur) return res.status(404).json({ error: 'Рассылка не найдена' });
    if (cur.status === 'active') return res.status(409).json({ error: 'Рассылка работает — поставьте её на паузу, чтобы изменить' });
    if (cur.status === 'finished') return res.status(409).json({ error: 'Рассылка завершена — сделайте копию и меняйте её' });
    await mailings.update(cur.id, parsed.value);
    auditNote(req, 'mailing.updated', 'mailing', cur.id, `изменена рассылка «${parsed.value.title}»`);
    res.json({ ok: true, campaign: await mailings.get(cur.id) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить рассылку' });
  }
});

// Запуск: для условия «гость попал в сегмент» запоминаем, кто в сегменте сейчас, — им не пишем
app.post('/api/admin/mailings/:id/activate', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    const c = await mailings.get(req.params.id);
    if (!c) return res.status(404).json({ error: 'Рассылка не найдена' });
    if (c.status === 'active') return res.status(409).json({ error: 'Рассылка уже работает' });
    if (c.status === 'finished') return res.status(409).json({ error: 'Рассылка завершена — сделайте копию' });
    if (!MAILINGS_ENABLED) return res.status(409).json({ error: 'Автоматические рассылки выключены на сервере (MAILINGS=off)' });
    const problem = mailings.readyProblem(c, mailingWindow(c.kind));
    if (problem) return res.status(400).json({ error: problem });
    let members = null;
    if (c.kind === 'mass') {
      if (!c.sendAt) return res.status(400).json({ error: 'Укажите, когда отправить (шаг 2), или нажмите «Отправить сейчас»' });
      if (new Date(c.sendAt).getTime() < Date.now() + 60 * 1000) return res.status(400).json({ error: 'Это время уже наступило — выберите время позже или нажмите «Отправить сейчас»' });
      const hh = mailings.localParts(new Date(c.sendAt)).hour;
      if (hh < MARKETING_HOURS.from || hh >= MARKETING_HOURS.to) return res.status(400).json({ error: `Рассылки отправляются с ${MARKETING_HOURS.from}:00 до ${MARKETING_HOURS.to}:00 — выберите время в эти часы` });
    } else if (c.trigger === 'segment_enter') {
      const sc = c.triggerCfg.segment;
      const seg = buildSegment(sc.key, sc.tag || null, await marketingContext());
      if (!seg) return res.status(400).json({ error: 'Выбранный сегмент больше не существует — выберите другой' });
      members = seg.guests.map(g => g.id);
    }
    await mailings.activate(c.id, members);
    auditNote(req, 'mailing.activated', 'mailing', c.id, `запущена рассылка «${c.title}»${c.kind === 'mass' ? ` на ${venueTimeStr(new Date(c.sendAt))}` : ''}`);
    res.json({ ok: true, campaign: await mailings.get(c.id) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось запустить рассылку' });
  }
});

app.post('/api/admin/mailings/:id/pause', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    const c = await mailings.get(req.params.id);
    if (!c) return res.status(404).json({ error: 'Рассылка не найдена' });
    if (c.status !== 'active') return res.status(409).json({ error: 'Рассылка не запущена' });
    await mailings.setStatus(c.id, 'paused');
    auditNote(req, 'mailing.paused', 'mailing', c.id, `рассылка «${c.title}» поставлена на паузу`);
    res.json({ ok: true, campaign: await mailings.get(c.id) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось поставить на паузу' });
  }
});

// Массовая: отправить сразу (из черновика, с паузы или отменив отложенную отправку)
app.post('/api/admin/mailings/:id/send-now', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    const c = await mailings.get(req.params.id);
    if (!c) return res.status(404).json({ error: 'Рассылка не найдена' });
    if (c.kind !== 'mass') return res.status(400).json({ error: 'Сразу можно отправить только массовую рассылку' });
    if (c.status === 'finished') return res.status(409).json({ error: 'Рассылка уже отправлена — сделайте копию' });
    const problem = mailings.readyProblem(c, MARKETING_HOURS);
    if (problem) return res.status(400).json({ error: problem });
    const r = await launchMassBroadcast({
      segments: c.segments, text: c.body, employee: req.employee, author: mailingAuthor(req.employee), campaignId: c.id, campaignTitle: c.title
    });
    if (r.error) return res.status(r.http || 500).json({ error: r.error });
    await mailings.markMassDone(c.id, { total: r.job.total, sent: 0, failed: 0, blocked: 0, at: r.job.createdAt, running: true });
    res.json({ ok: true, job: publicJob(r.job), campaign: await mailings.get(c.id) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось отправить рассылку' });
  }
});

// Копия: черновик с теми же настройками (запускать нужно заново)
app.post('/api/admin/mailings/:id/duplicate', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    const c = await mailings.get(req.params.id);
    if (!c) return res.status(404).json({ error: 'Рассылка не найдена' });
    const parsed = mailingInput({ ...c, title: `${c.title} (копия)`.slice(0, 80), sendAt: null });
    if (parsed.error) return res.status(400).json({ error: parsed.error });
    const id = await mailings.create(parsed.value, req.employee);
    auditNote(req, 'mailing.created', 'mailing', id, `сделана копия рассылки «${c.title}»`);
    res.json({ ok: true, campaign: await mailings.get(id) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сделать копию' });
  }
});

app.delete('/api/admin/mailings/:id', async (req, res) => {
  if (!(await checkPerm(req, res, 'marketing.send'))) return;
  try {
    const c = await mailings.get(req.params.id);
    if (!c) return res.status(404).json({ error: 'Рассылка не найдена' });
    if (c.status === 'active') return res.status(409).json({ error: 'Рассылка работает — сначала поставьте её на паузу' });
    await mailings.remove(c.id);
    auditNote(req, 'mailing.deleted', 'mailing', c.id, `удалена рассылка «${c.title}»`);
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось удалить рассылку' });
  }
});

// ── Планировщик: раз в минуту ──
// 1) массовые, время которых пришло → отправка; 2) новые события → очередь «кому и когда»; 3) очередь, чьё время пришло → гостям.
let mailingsRunning = false;
async function mailingsTick() {
  if (mailingsRunning || !MAILINGS_ENABLED || !INTERNAL_ADMIN_KEY) return;
  mailingsRunning = true;
  try {
    const camps = await mailings.activeCampaigns();
    if (!camps.length) return;
    forgetMemo('marketing:contacts'); // отписавшиеся и новые Telegram — свежие
    let ctx = null;
    const getCtx = async () => ctx || (ctx = await marketingContext());

    for (const c of camps.filter(x => x.kind === 'mass' && x.sendAt)) await mailingRunScheduledMass(c);
    const auto = camps.filter(x => x.kind !== 'mass');
    for (const c of auto) {
      try { await mailingScan(c, getCtx); } catch (e) { console.error(`Рассылка «${c.title}»: не удалось разобрать события:`, e.message); }
    }
    await mailingDispatch(auto, getCtx);
  } catch (e) {
    console.error('Планировщик рассылок:', e && e.message ? e.message : e);
  } finally {
    mailingsRunning = false;
  }
}

async function mailingRunScheduledMass(c) {
  const at = new Date(c.sendAt);
  if (at.getTime() > Date.now()) return;
  const finish = (note) => mailings.markMassDone(c.id, { total: 0, sent: 0, failed: 0, blocked: 0, at: new Date().toISOString(), note });
  if (Date.now() - at.getTime() > MAILING_MASS_LATE_HOURS * 3600 * 1000) {
    await finish('Не отправлена: сервер не успел отправить вовремя, а текст мог устареть');
    await sendAdmin(`⚠️ Рассылка «${c.title}» не ушла в назначенное время (${venueTimeStr(at)}) и уже устарела — отправьте её заново, если нужно.`, 'рассылка не отправлена');
    return;
  }
  if (!inHoursWindow(MARKETING_HOURS)) return; // подождём, когда откроется окно
  const r = await launchMassBroadcast({ segments: c.segments, text: c.body, author: `${c.author || 'Рассылка по расписанию'}`, campaignId: c.id, campaignTitle: c.title });
  if (r.job) { await mailings.markMassDone(c.id, { total: r.job.total, sent: 0, failed: 0, blocked: 0, at: r.job.createdAt, running: true }); return; }
  if (r.http === 409) return; // идёт другая рассылка — попробуем в следующую минуту
  await finish(r.error || 'Не отправлена');
  await sendAdmin(`⚠️ Рассылка «${c.title}» не ушла: ${r.error || 'ошибка'}`, 'рассылка не отправлена');
}

// Новые события → очередь. Каждая рассылка помнит, до какого момента события уже разобраны (scan_state).
async function mailingScan(c, getCtx) {
  const win = mailingWindow(c.kind);
  const now = new Date();
  const until = new Date(now.getTime() - 5000);                  // самые свежие секунды оставляем на следующий раз: запись могла ещё не завершиться
  const since = new Date(c.scanState.cursor || c.activatedAt || now);
  const queue = (list) => mailings.enqueue(c.id, list.map(e => ({
    guestId: e.guestId, ref: e.ref, eventAt: e.at, dueAt: mailings.computeDue(c, e.at, win)
  })));

  if (c.trigger === 'visit' || c.trigger === 'first_visit') {
    const events = await mailings.newVisits(since, until, c.trigger === 'first_visit');
    await queue(events.map(e => ({ ...e, at: new Date(e.at) })));
    await mailings.saveScanState(c.id, { cursor: until.toISOString() });
  } else if (c.trigger === 'no_show') {
    const events = await mailings.newNoShows(since, until);
    await queue(events.map(e => ({ ...e, at: new Date(e.at) })));
    await mailings.saveScanState(c.id, { cursor: until.toISOString() });
  } else if (c.trigger === 'birthday_soon') {
    const today = venueDateStr();
    if (c.scanState.birthdayDay === today) return;              // сегодня уже смотрели
    const target = addDaysStr(today, Number(c.triggerCfg.daysBefore) || 7);
    const [y, m, d] = target.split('-').map(Number);
    const cards = (await cardsDb.birthdaysOn(m, d, y)).filter(g => !isNonGrata(g));
    await queue(cards.map(g => ({ guestId: g.id, ref: `bd${y}`, at: now })));
    await mailings.saveScanState(c.id, { birthdayDay: today });
  } else if (c.trigger === 'segment_enter') {
    if (c.scanState.segmentAt && now.getTime() - new Date(c.scanState.segmentAt).getTime() < 10 * 60 * 1000) return; // сегменты считаем раз в 10 минут
    const sc = c.triggerCfg.segment;
    const seg = sc && buildSegment(sc.key, sc.tag || null, await getCtx());
    if (!seg) return;
    const nowIds = seg.guests.map(g => g.id), nowSet = new Set(nowIds);
    const known = await mailings.memberIds(c.id);
    const entered = nowIds.filter(id => !known.has(id));
    const left = [...known].filter(id => !nowSet.has(id));
    await queue(entered.map(id => ({ guestId: id, ref: `seg${venueDateStr()}`, at: now })));
    await mailings.addMembers(c.id, entered);
    await mailings.removeMembers(c.id, left);
    await mailings.saveScanState(c.id, { segmentAt: now.toISOString() });
  }
}

// Очередь → гостям. Перед каждой отправкой заново проверяем всё: карточка, нон-грата, Telegram, отписка, сегмент, лимиты.
async function mailingDispatch(camps, getCtx) {
  const open = camps.filter(c => inHoursWindow(mailingWindow(c.kind)));
  if (!open.length) return;
  const byId = new Map(open.map(c => [c.id, c]));
  const batch = await mailings.claimDue([...byId.keys()], MAILING_BATCH);
  if (!batch.length) return;

  const ctx = await getCtx();
  const info = new Map(buildSegment('all', null, ctx).guests.map(g => [g.id, g]));   // без «Нон-грата»
  const cardById = new Map(ctx.cards.map(c => [c.id, c]));
  const idsOf = (list) => [...new Set(list.map(b => b.guestId))];
  const recentMarketing = MARKETING_GAP_HOURS > 0 ? await mailings.marketingSentSince(idsOf(batch), MARKETING_GAP_HOURS) : new Set();
  const cooldown = new Map(), audience = new Map(), trigSet = new Map();
  for (const c of open) {
    const mine = batch.filter(b => b.campaignId === c.id);
    if (!mine.length) continue;
    if (c.limitDays > 0) cooldown.set(c.id, await mailings.sentSince(c.id, idsOf(mine), c.limitDays));  // дополняется по ходу отправки
    if (c.segments.length) {
      const aud = audienceOf(ctx, c.segments);
      audience.set(c.id, aud ? new Set(aud.guests.map(g => g.id)) : new Set());
    }
    if (c.trigger === 'segment_enter' && c.triggerCfg.segment) {
      const sc = c.triggerCfg.segment, seg = buildSegment(sc.key, sc.tag || null, ctx);
      trigSet.set(c.id, new Set(seg ? seg.guests.map(g => g.id) : []));
    }
  }

  const usedChat = new Set();
  let outage = 0;
  for (let i = 0; i < batch.length; i++) {
    const item = batch[i];
    const c = byId.get(item.campaignId);
    const skip = (reason) => mailings.finishSend(item.id, 'skipped', reason);
    if (outage >= 3) { await mailings.requeue(item.id, new Date(Date.now() + 5 * 60 * 1000), 'unreachable', true); continue; }

    const card = cardById.get(item.guestId);
    if (!card) { await skip('no_guest'); continue; }
    const g = info.get(item.guestId);
    if (!g) { await skip('non_grata'); continue; }
    let chatId = g.reachable ? g.telegramId : null;
    if (!chatId && c.kind === 'service' && g.reason === 'opted_out') chatId = ctx.contacts.get(normalizePhone(card.phone))?.telegramId || null; // сервисное приходит и отписавшимся
    if (!chatId) { await skip(g.reason || 'no_telegram'); continue; }
    const aud = audience.get(c.id);
    if (aud && !aud.has(item.guestId)) { await skip('not_in_segment'); continue; }
    const ts = trigSet.get(c.id);
    if (ts && !ts.has(item.guestId)) { await skip('left_segment'); continue; }
    if (!(await mailings.eventStillValid(c.trigger, item.ref))) { await skip('event_gone'); continue; }
    if (cooldown.get(c.id)?.has(item.guestId)) { await skip('too_often'); continue; }
    if (c.kind !== 'service' && !c.extraPriority && recentMarketing.has(item.guestId)) {
      // сегодня гостю уже писала другая рассылка — подождём; если ждать дольше трёх суток, уже не пишем
      if (Date.now() - new Date(item.eventAt).getTime() > 72 * 3600 * 1000) await skip('too_often');
      else await mailings.requeue(item.id, mailings.nextInWindow(new Date(Date.now() + 6 * 3600 * 1000), mailingWindow(c.kind)), 'gap', true);
      continue;
    }
    const chatKey = `${c.id}:${chatId}`;
    if (usedChat.has(chatKey)) { await skip('duplicate'); continue; }
    usedChat.add(chatKey);

    const r = await callGuestProxy('/api/internal/broadcast', {
      ...(c.kind === 'service' ? {} : { respectOptOut: true }),
      messages: [{ chatId, text: personalize(c.body, g.name) }]
    }, 1, 20000);
    if (!r.reached) {
      if (r.maybeDelivered) { await mailings.finishSend(item.id, 'failed', 'unknown'); outage++; }
      else { await mailings.requeue(item.id, new Date(Date.now() + 5 * 60 * 1000), 'unreachable', true); outage++; }
      continue;
    }
    outage = 0;
    if (r.httpError) await mailings.finishSend(item.id, 'failed', `http_${r.httpError}`);
    else if ((r.sent || 0) >= 1) {
      await mailings.finishSend(item.id, 'sent');
      // два события одного гостя в одну минуту не должны дать два письма: запоминаем и для лимитов
      if (c.kind !== 'service') recentMarketing.add(item.guestId);
      cooldown.get(c.id)?.add(item.guestId);
    }
    else if (r.blocked) await mailings.finishSend(item.id, 'blocked', 'blocked');
    else if (r.skipped) await mailings.finishSend(item.id, 'skipped', 'opted_out');
    else await mailings.finishSend(item.id, 'failed', 'telegram');
  }
}
setInterval(() => { mailingsTick(); }, Math.max(5000, Number(process.env.MAILINGS_TICK_MS) || 60 * 1000)).unref();


// ─── АНАЛИТИКА: СРАВНЕНИЕ ПЕРИОДОВ ──────────────────
// Любой показатель за выбранный период по дням/неделям/месяцам рядом с тем же показателем
// за предыдущий такой же период или за те же даты год назад. Фильтры (у каждого показателя свои, списком через запятую):
// день недели (dow=5,6), время брони (slot), сегмент гостя — сегодняшний, или VIP (segment), стол и зона (zone),
// размер компании (party), откуда бронь (source). Что из этого действует на показатель — в ответе, поле applied.
const ANALYTICS_METRICS = {
  visits: { title: 'Визиты', kind: 'count' },
  guests: { title: 'Гости (уникальные)', kind: 'unique' },
  newGuests: { title: 'Новые гости', kind: 'count' },
  returning: { title: 'Вернувшиеся гости', kind: 'unique' },
  bookings: { title: 'Брони', kind: 'count' },
  cancellations: { title: 'Отмены броней', kind: 'count' },
  cancelNoSeats: { title: 'Отмены: нет мест', kind: 'count' },
  cancelChangedMind: { title: 'Отмены: гость передумал', kind: 'count' },
  arrivals: { title: 'Пришли по брони', kind: 'count' },
  noShows: { title: 'Неявки по броням', kind: 'count' },
  unmarked: { title: 'Брони без отметки', kind: 'count' },
  walkIns: { title: 'Посадки без брони', kind: 'count' },
  guestsBooked: { title: 'Гостей по броням', kind: 'sum' },
  guestsArrived: { title: 'Пришло гостей', kind: 'sum' },
  partySize: { title: 'Размер компании', kind: 'avg' },
  noShowRate: { title: 'Доля неявок', kind: 'pct' },
  cancelRate: { title: 'Доля отмен', kind: 'pct' },
  stay: { title: 'Среднее время визита', kind: 'duration' },
  turnover: { title: 'Оборот столов', kind: 'ratio' },
  csi: { title: 'CSI (средняя оценка)', kind: 'avg' },
  nps: { title: 'NPS гостей', kind: 'score' },
  enps: { title: 'eNPS команды', kind: 'score' }
};
const AN_FILTER_VALUES = {
  slot: ['day', 'e1', 'e2', 'night'],          // до 18:00 · 18–20 · 20–22 · с 22:00 и до утра
  zone: ['hall', 'terrace', 'vip', 'none'],    // общий зал · терраса · VIP-комнаты · стол не назначен
  party: ['1-2', '3-4', '5-6', '7+'],
  source: ['site', 'app', 'bot', 'staff']      // сайт · приложение гостя · бот · сотрудник (в том числе по телефону)
};
const AN_FILTER_MAX = 12;
function parseAnFilters(q) {
  const list = (v, ok) => [...new Set(String(v || '').split(',').map(x => x.trim()).filter(ok))].slice(0, AN_FILTER_MAX);
  return {
    dows: list(q.dow, x => /^[1-7]$/.test(x)).map(Number).sort((a, b) => a - b),   // 1 = пн … 7 = вс
    slot: list(q.slot, x => AN_FILTER_VALUES.slot.includes(x)),
    segment: list(q.segment, x => x === 'vip' || !!SEGMENT_BY_KEY[x]),
    zone: list(q.zone, x => AN_FILTER_VALUES.zone.includes(x)),
    party: list(q.party, x => AN_FILTER_VALUES.party.includes(x)),
    source: list(q.source, x => AN_FILTER_VALUES.source.includes(x))
  };
}
function bookingZone(b) {
  const p = String(b.place || '').trim();
  if (b.kind === 'vip' || /^(?:vip|вип)(?![a-zа-яё])/i.test(p)) return 'vip';
  if (/^терраса/i.test(p)) return 'terrace';
  return p ? 'hall' : 'none';
}
const bookingTimeSlot = (h) => h === null || h === undefined ? null : h < 6 ? 'night' : h < 18 ? 'day' : h < 20 ? 'e1' : h < 22 ? 'e2' : 'night';
const bookingPartyBucket = (n) => !n ? null : n <= 2 ? '1-2' : n <= 4 ? '3-4' : n <= 6 ? '5-6' : '7+';
const bookingSourceKey = (s) => s === 'phone' ? 'staff' : (AN_FILTER_VALUES.source.includes(s) ? s : 'other');
// Строки броней для каждого показателя: какие брони берём и что считаем (по умолчанию 1 — «бронь»)
const ANALYTICS_BOOKING_ROWS = {
  bookings: { keep: b => !b.walkIn && !b.cancelled },
  guestsBooked: { keep: b => !b.walkIn && !b.cancelled && !!b.party, val: b => b.party },
  guestsArrived: { keep: b => !b.walkIn && !b.cancelled && b.arrival === 'arrived' && !!b.party, val: b => b.party },
  partySize: { keep: b => !b.walkIn && !b.cancelled && !!b.party, val: b => b.party },
  cancellations: { keep: b => !b.walkIn && b.cancelled },
  cancelNoSeats: { keep: b => !b.walkIn && b.cancelled && b.cancelReason === 'no_seats' },
  cancelChangedMind: { keep: b => !b.walkIn && b.cancelled && b.cancelReason === 'changed_mind' },
  arrivals: { keep: b => !b.walkIn && !b.cancelled && b.arrival === 'arrived' },
  noShows: { keep: b => !b.walkIn && !b.cancelled && b.arrival === 'noshow' },
  // «Без отметки» — брони прошедших вечеров, где так и не нажали «Пришёл» или «Не пришёл» (сегодняшний вечер ещё идёт;
  // мероприятия не считаем, как и в сообщении о закрытии вечера).
  unmarked: { keep: (b, today) => !b.walkIn && !b.cancelled && !b.arrival && b.kind !== 'event' && b.day < today },
  // Посадки без брони — не брони: в «Брони», «Приходы» и «Неявки» их нет, считаются отдельно.
  walkIns: { keep: b => b.walkIn && !b.cancelled },
  // Доли: каждая бронь — 0 или 1, значение — среднее в процентах
  noShowRate: { keep: b => !b.walkIn && !b.cancelled && (b.arrival === 'arrived' || b.arrival === 'noshow'), val: b => b.arrival === 'noshow' ? 1 : 0 },
  cancelRate: { keep: b => !b.walkIn, val: b => b.cancelled ? 1 : 0 }
};
const ANALYTICS_VISIT_METRICS = ['visits', 'guests', 'newGuests', 'returning'];
// Какие фильтры действуют на показатель (остальные игнорируются, и экран предупреждает об этом)
function analyticsApplied(metric) {
  if (metric === 'enps') return [];
  if (ANALYTICS_VISIT_METRICS.includes(metric)) return ['dows', 'segment'];
  if (ANALYTICS_BOOKING_ROWS[metric] || metric === 'stay') return ['dows', 'slot', 'segment', 'zone', 'party', 'source'];
  if (metric === 'turnover') return ['dows', 'zone'];
  return ['dows'];
}
// Гости выбранных сегментов (сегодняшних): Set id или null, если сегмент не выбран
async function analyticsSegmentSet(keys) {
  if (!keys || !keys.length) return null;
  const [cards, allVisits] = await Promise.all([getAllCards(), getAllVisits()]);
  const dates = visitDatesByGuest(allVisits.filter(v => v.date));
  return new Set(cards.filter(c => keys.some(k => k === 'vip' ? c.vip : guestSegment(dates.get(c.id)).key === k)).map(c => c.id));
}
// Подходит ли бронь под фильтры; only — какие из них учитывать
function bookingMatcher(f, segSet, only) {
  const on = (k) => !only || only.includes(k);
  return (b) => {
    if (on('zone') && f.zone.length && !f.zone.includes(bookingZone(b))) return false;
    if (on('party') && f.party.length && !f.party.includes(bookingPartyBucket(b.party))) return false;
    if (on('source') && f.source.length && !f.source.includes(bookingSourceKey(b.source))) return false;
    if (on('slot') && f.slot.length && !f.slot.includes(bookingTimeSlot(b.hour))) return false;
    if (on('segment') && segSet && !(b.guestId && segSet.has(b.guestId))) return false;
    return true;
  };
}
const STAY_MIN_MINUTES = 5;
const STAY_MAX_MINUTES = 16 * 60;
const MONTHS_SHORT = ['янв', 'фев', 'мар', 'апр', 'май', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'];

function isoWeekday(dateStr) { // 1 = пн … 7 = вс
  const d = new Date(dateStr + 'T00:00:00Z').getUTCDay();
  return d === 0 ? 7 : d;
}
function bucketStartOf(dateStr, group) {
  if (group === 'month') return dateStr.slice(0, 8) + '01';
  if (group === 'week') return addDaysStr(dateStr, -(isoWeekday(dateStr) - 1));
  return dateStr;
}
function nextBucketStart(start, group) {
  if (group === 'month') {
    const y = Number(start.slice(0, 4)), m = Number(start.slice(5, 7));
    return m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, '0')}-01`;
  }
  return addDaysStr(start, group === 'week' ? 7 : 1);
}
function shiftYears(dateStr, years) {
  const y = Number(dateStr.slice(0, 4)) + years;
  const md = dateStr.slice(5, 10) === '02-29' ? '02-28' : dateStr.slice(5, 10);
  return `${y}-${md}`;
}
function daysBetween(a, b) {
  return Math.round((new Date(b + 'T00:00:00Z') - new Date(a + 'T00:00:00Z')) / 86400000);
}
function bucketLabel(start, end, group) {
  const dm = s => `${s.slice(8, 10)}.${s.slice(5, 7)}`;
  if (group === 'month') return `${MONTHS_SHORT[Number(start.slice(5, 7)) - 1]} ${start.slice(0, 4)}`;
  if (group === 'week') return `${dm(start)}–${dm(end)}`;
  return dm(start);
}
function makeBuckets(from, to, group) {
  const out = [];
  let start = bucketStartOf(from, group);
  while (start <= to) {
    const next = nextBucketStart(start, group);
    const s = start < from ? from : start;
    const lastDay = addDaysStr(next, -1);
    const e = lastDay > to ? to : lastDay;
    out.push({ start: s, end: e, label: bucketLabel(s, e, group) });
    start = next;
    if (out.length > 400) break;
  }
  return out;
}
function npsOf(vals) {
  if (!vals.length) return null;
  const promoters = vals.filter(n => n >= 9).length;
  const detractors = vals.filter(n => n <= 6).length;
  return Math.round(((promoters - detractors) / vals.length) * 100);
}

// Все брони из базы: { date, cancelled, arrival: 'arrived' | 'noshow' | null }
function getAllBookingsFlat() {
  return memo('analytics:bookings', 5 * 60 * 1000, () => store.getAllBookingsFlat());
}

// Точки данных показателя: [{ date, value, guestId? }]. f — фильтры показателя (parseAnFilters): те, что на него не действуют, пропускаются.
async function analyticsRows(metric, minDate, f) {
  f = f || parseAnFilters({});
  if (ANALYTICS_VISIT_METRICS.includes(metric)) {
    const allVisits = await getAllVisits();
    const visits = allVisits.filter(v => v.date);
    const inFilter = await analyticsSegmentSet(f.segment); // гости, чьи визиты считаем (сегмент — на сегодня)
    const firstVisit = {};
    for (const v of visits) {
      if (!v.guestId) continue;
      const d = v.date.slice(0, 10);
      if (!firstVisit[v.guestId] || d < firstVisit[v.guestId]) firstVisit[v.guestId] = d;
    }
    return {
      firstVisit,
      rows: visits
        .filter(v => !inFilter || (v.guestId && inFilter.has(v.guestId)))
        .map(v => ({ date: v.date.slice(0, 10), guestId: v.guestId, value: 1 }))
    };
  }
  if (ANALYTICS_BOOKING_ROWS[metric]) {
    const all = await getAllBookingsFlat();
    const today = venueDayStr();
    const match = bookingMatcher(f, await analyticsSegmentSet(f.segment));
    const def = ANALYTICS_BOOKING_ROWS[metric];
    return { rows: all.filter(b => def.keep(b, today) && match(b)).map(b => ({ date: b.date, value: def.val ? def.val(b) : 1 })) };
  }
  // Время визита: брони, где отмечены и «Пришёл», и «Гость ушёл»; значение — минуты. Меньше 5 минут — отметка по ошибке,
  // больше 16 часов — забыли нажать вовремя: такие в среднее не идут. Дата — день заведения (уход в 01:30 — тот же вечер).
  if (metric === 'stay') {
    const all = await getAllBookingsFlat();
    const match = bookingMatcher(f, await analyticsSegmentSet(f.segment));
    return { rows: all.filter(b => !b.cancelled && b.stayMin !== null && b.stayMin >= STAY_MIN_MINUTES && b.stayMin <= STAY_MAX_MINUTES && match(b)).map(b => ({ date: b.day, value: b.stayMin })) };
  }
  // Оборот столов: сколько раз за вечер занимали один стол. Строка — один стол в один вечер, значение — сколько
  // броней с «Пришёл» за ним было. Среднее по строкам = сколько компаний в среднем проходит через занятый стол за вечер.
  // Из фильтров здесь действует только зона (строка — стол, а не бронь).
  if (metric === 'turnover') {
    const all = await getAllBookingsFlat();
    const match = bookingMatcher(f, null, ['zone']);
    const per = new Map();
    for (const b of all) {
      if (b.cancelled || b.arrival !== 'arrived' || !b.place || !b.day || !match(b)) continue;
      const k = `${b.day}|${b.place.trim().toLowerCase().replace(/\s+/g, ' ')}`;
      per.set(k, (per.get(k) || 0) + 1);
    }
    return { rows: [...per.entries()].map(([k, n]) => ({ date: k.slice(0, 10), value: n })) };
  }
  if (metric === 'csi' || metric === 'nps') {
    const reviews = await memo(`analytics:reviews:${minDate}`, 2 * 60 * 1000, () => feedback.listReviews(minDate));
    const rows = [];
    for (const r of reviews) {
      if (!r.date) continue;
      if (metric === 'nps') {
        if (typeof r.nps === 'number') rows.push({ date: r.date.slice(0, 10), value: r.nps });
      } else {
        const cats = Object.values(r.scores).filter(n => typeof n === 'number');
        if (cats.length) rows.push({ date: r.date.slice(0, 10), value: cats.reduce((a, c) => a + c, 0) / cats.length });
      }
    }
    return { rows };
  }
  if (metric === 'enps') {
    const entries = await memo(`analytics:enps:${minDate}`, 2 * 60 * 1000, () => feedback.listEnps(minDate));
    return { rows: entries.filter(e => e.date && typeof e.score === 'number').map(e => ({ date: e.date.slice(0, 10), value: e.score })) };
  }
  return { rows: [] };
}

function aggregate(metric, rows, from, to, firstVisit) {
  const kind = ANALYTICS_METRICS[metric].kind;
  const inRange = rows.filter(r => r.date >= from && r.date <= to);
  if (metric === 'guests') return new Set(inRange.map(r => r.guestId).filter(Boolean)).size;
  if (metric === 'newGuests') return new Set(inRange.filter(r => r.guestId && firstVisit[r.guestId] === r.date).map(r => r.guestId)).size;
  if (metric === 'returning') return new Set(inRange.filter(r => r.guestId && firstVisit[r.guestId] < from).map(r => r.guestId)).size;
  if (kind === 'count') return inRange.length;
  if (kind === 'sum') return inRange.reduce((a, r) => a + r.value, 0);
  if (!inRange.length) return null;
  if (kind === 'pct') return Math.round((inRange.reduce((a, r) => a + r.value, 0) / inRange.length) * 1000) / 10; // доля в процентах, один знак
  if (kind === 'duration') return Math.round(inRange.reduce((a, r) => a + r.value, 0) / inRange.length); // минуты, целые
  if (kind === 'avg' || kind === 'ratio') return Math.round((inRange.reduce((a, r) => a + r.value, 0) / inRange.length) * 10) / 10;
  return npsOf(inRange.map(r => r.value));
}

// Топ кальянов за период
async function topHookahsFor(from, to) {
  const hookahCounts = {};
  for (const v of await getAllVisits()) {
    if (!v.date) continue;
    const d = v.date.slice(0, 10);
    if (d < from || d > to) continue;
    for (const flavor of hookahParts(v.hookah)) hookahCounts[flavor] = (hookahCounts[flavor] || 0) + 1;
  }
  return Object.entries(hookahCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([flavor, count]) => ({ flavor, count }));
}

// eNPS по месяцам. Месяц виден только когда он закончился и в нём не меньше ENPS_MIN_ANSWERS ответов; иначе значение пустое.
// Период и сравнение выравниваются по целым месяцам: «прошлый период» — столько же месяцев перед первым, «год назад» — те же месяцы годом раньше.
async function enpsAnalytics({ from, to, compare }) {
  const min = feedback.ENPS_MIN_ANSWERS;
  const curMonth = venueDayStr().slice(0, 8) + '01';
  const first = from.slice(0, 8) + '01', last = to.slice(0, 8) + '01';
  const months = [];
  for (let m = first; m <= last && months.length < 30; m = addMonthsStr(m, 1)) months.push(m);
  const cmpOf = (m) => compare === 'prev' ? addMonthsStr(m, -months.length) : compare === 'year' ? addMonthsStr(m, -12) : null;
  const cmpFirst = cmpOf(first);
  const earliest = cmpFirst && cmpFirst < first ? cmpFirst : first;
  const entries = await memo(`analytics:enps:${earliest}`, 2 * 60 * 1000, () => feedback.listEnps(earliest));
  const byMonth = new Map();
  for (const e of entries) {
    if (!e.date || typeof e.score !== 'number') continue;
    const k = String(e.date).slice(0, 8) + '01';
    if (!byMonth.has(k)) byMonth.set(k, []);
    byMonth.get(k).push(e.score);
  }
  const shown = (m) => m < curMonth && (byMonth.get(m) || []).length >= min;
  const valueOf = (m) => shown(m) ? npsOf(byMonth.get(m)) : null;
  const totalOf = (list) => { const all = []; for (const m of list) if (shown(m)) all.push(...byMonth.get(m)); return all.length ? npsOf(all) : null; };
  const lastDay = (m) => addDaysStr(addMonthsStr(m, 1), -1);
  const buckets = months.map((m) => {
    const c = cmpOf(m);
    return {
      label: bucketLabel(m, lastDay(m), 'month'), start: m, end: lastDay(m), value: valueOf(m),
      compareLabel: c ? bucketLabel(c, lastDay(c), 'month') : null, compareStart: c || null, compareEnd: c ? lastDay(c) : null,
      compareValue: c ? valueOf(c) : null
    };
  });
  const total = totalOf(months);
  const cmpMonths = months.map(cmpOf).filter(Boolean);
  const compareTotal = cmpMonths.length ? totalOf(cmpMonths) : null;
  const delta = total !== null && compareTotal !== null ? Math.round((total - compareTotal) * 10) / 10 : null;
  return {
    group: 'month', compare, from: first, to: lastDay(last),
    compareFrom: cmpMonths.length ? cmpMonths[0] : null, compareTo: cmpMonths.length ? lastDay(cmpMonths[cmpMonths.length - 1]) : null,
    buckets, total, compareTotal, delta, deltaPct: null,
    enpsMinAnswers: min
  };
}

// ─── ПРОГНОЗ ЗАГРУЗКИ ─────
// Считает forecast.js по броням из базы: темп набора против прошлых таких же дней, гости без брони, доля пришедших,
// пик по часам и рискованные брони. Права те же, что у аналитики. Кэш сбрасывается вместе с аналитикой броней.
const forecastEngine = require('./forecast');
app.get('/api/admin/forecast', async (req, res) => {
  if (!(await checkPerm(req, res, 'analytics.view'))) return;
  const days = Math.min(14, Math.max(1, parseInt(req.query.days, 10) || 7));
  const seats = parseInt(req.query.seats, 10);
  try {
    const rows = await memo('analytics:bookings:forecast', 2 * 60 * 1000, () => store.getForecastRows());
    res.json(forecastEngine.computeForecast({
      rows, today: venueDayStr(), nowMs: Date.now(), days,
      seats: seats >= 10 && seats <= 500 ? seats : null, vipRooms: store.VIP_ROOM_COUNT
    }));
  } catch (e) {
    console.error('Не удалось посчитать прогноз:', e.message);
    res.status(500).json({ error: 'Не удалось посчитать прогноз' });
  }
});

app.get('/api/admin/analytics', async (req, res) => {
  if (!(await checkPerm(req, res, 'analytics.view'))) return;
  const metric = Object.prototype.hasOwnProperty.call(ANALYTICS_METRICS, req.query.metric) ? req.query.metric : 'visits';
  const group = ['day', 'week', 'month'].includes(req.query.group) ? req.query.group : 'day';
  const compare = ['prev', 'year', 'none'].includes(req.query.compare) ? req.query.compare : 'prev';
  const today = venueDateStr();
  const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(String(s || ''));
  const to = isDate(req.query.to) ? req.query.to : today;
  const from = isDate(req.query.from) ? req.query.from : addDaysStr(to, -29);
  const filters = parseAnFilters(req.query);   // списки через запятую; пусто — без фильтра
  const applied = analyticsApplied(metric);
  const dows = applied.includes('dows') ? filters.dows : [];

  if (from > to) return res.status(400).json({ error: 'Начало периода позже конца' });
  const lengthDays = daysBetween(from, to) + 1;
  if (lengthDays > 731) return res.status(400).json({ error: 'Период не больше двух лет' });
  const buckets = metric === 'enps' ? [] : makeBuckets(from, to, group); // у eNPS свои, помесячные точки
  if (buckets.length > 400) return res.status(400).json({ error: 'Слишком много точек — выберите группировку по неделям или месяцам' });

  let compareFrom = null, compareTo = null;
  if (compare === 'prev') { compareTo = addDaysStr(from, -1); compareFrom = addDaysStr(from, -lengthDays); }
  if (compare === 'year') { compareFrom = shiftYears(from, -1); compareTo = shiftYears(to, -1); }

  try {
    // eNPS — особый случай (анонимность): только закончившиеся месяцы, от трёх ответов, без разбивки по дням и неделям
    if (metric === 'enps') {
      const e = await enpsAnalytics({ from, to, compare });
      return res.json({ ...e, metric, title: ANALYTICS_METRICS.enps.title, kind: 'score', dow: null, dows: [], segment: null, filters, applied, samples: null, topHookahs: await topHookahsFor(from, to) });
    }
    const minDate = compareFrom && compareFrom < from ? compareFrom : from;
    const { rows: allRows, firstVisit = {} } = await analyticsRows(metric, minDate, filters);
    const rows = dows.length ? allRows.filter(r => dows.includes(isoWeekday(r.date))) : allRows;

    // Строка сравнения i — тот же отрезок, сдвинутый на длину периода (или на год назад),
    // чтобы в строке рядом стояли отрезки одинаковой длины: неделя против недели и т.д.
    const shiftDate = d => compare === 'year' ? shiftYears(d, -1) : addDaysStr(d, -lengthDays);
    const compareBuckets = compareFrom
      ? buckets.map(b => {
          const start = shiftDate(b.start), end = shiftDate(b.end);
          return { start, end, label: bucketLabel(start, end, group === 'month' && compare === 'prev' ? 'week' : group) };
        })
      : [];
    const series = buckets.map((b, i) => {
      const cb = compareBuckets[i];
      return {
        label: b.label, start: b.start, end: b.end,
        value: aggregate(metric, rows, b.start, b.end, firstVisit),
        compareLabel: cb ? cb.label : null,
        compareStart: cb ? cb.start : null,
        compareEnd: cb ? cb.end : null,
        compareValue: cb ? aggregate(metric, rows, cb.start, cb.end, firstVisit) : null
      };
    });

    const total = aggregate(metric, rows, from, to, firstVisit);
    const compareTotal = compareFrom ? aggregate(metric, rows, compareFrom, compareTo, firstVisit) : null;
    const kind = ANALYTICS_METRICS[metric].kind;
    let delta = null, deltaPct = null;
    if (total !== null && compareTotal !== null) {
      delta = Math.round((total - compareTotal) * 10) / 10;
      if ((kind === 'count' || kind === 'unique' || kind === 'sum') && compareTotal > 0) deltaPct = Math.round(((total - compareTotal) / compareTotal) * 100);
    }

    // Топ кальянов за выбранный период — независимо от того, какой metric выбран
    // (раньше жило в отдельном экране «Статистика», перенесли сюда).
    const topHookahs = await topHookahsFor(from, to);

    // для средних по отметкам — на скольких записях посчитано (визиты с отметкой ухода / занятые столы по вечерам)
    const samples = kind === 'duration' || kind === 'ratio' || kind === 'pct' ? rows.filter(r => r.date >= from && r.date <= to).length : null;
    res.json({
      metric, title: ANALYTICS_METRICS[metric].title, kind, group, compare,
      from, to, compareFrom, compareTo, dow: dows.length === 1 ? dows[0] : null, dows,
      segment: filters.segment.length === 1 ? filters.segment[0] : null, filters, applied,
      buckets: series, total, compareTotal, delta, deltaPct, samples,
      topHookahs
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось посчитать аналитику' });
  }
});

// ─── СЕГМЕНТЫ ГОСТЕЙ: РАСПРЕДЕЛЕНИЕ И ПЕРЕХОДЫ ЗА МЕСЯЦ ──
// Сколько гостей в каждом сегменте на начало месяца и сейчас (или на конец месяца),
// кто куда перешёл: «Лояльные → Спящие: 5», «новые гости → Активные: 12».
// Сегмент на начало месяца считается по визитам до 1-го числа — снимки не нужны,
// поэтому смотреть можно любой прошлый месяц.
const MONTHS_NOM = ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь'];
const SEGMENT_FLOW_GUESTS_MAX = 200;

app.get('/api/admin/segments', async (req, res) => {
  if (!(await checkPerm(req, res, 'segments.view'))) return;
  const today = venueDateStr();
  const currentMonth = today.slice(0, 7);
  const monthRaw = typeof req.query.month === 'string' ? req.query.month : '';
  const month = /^\d{4}-(0[1-9]|1[0-2])$/.test(monthRaw) && monthRaw <= currentMonth ? monthRaw : currentMonth;
  const monthStart = `${month}-01`;
  const monthEnd = addDaysStr(nextBucketStart(monthStart, 'month'), -1);
  const startAsOf = addDaysStr(monthStart, -1);          // состояние до 1-го числа
  const endAsOf = monthEnd < today ? monthEnd : today;   // конец месяца или сегодня

  try {
    const [cards, visits] = await Promise.all([getAllCards(), getAllVisits()]);
    const dates = visitDatesByGuest(visits);
    const rankOf = key => (key && SEGMENT_BY_KEY[key] ? SEGMENT_BY_KEY[key].rank : 0);

    const startCount = { none: 0 }, endCount = { none: 0 };
    for (const sg of SEGMENTS) { startCount[sg.key] = 0; endCount[sg.key] = 0; }
    const flows = new Map();
    const summary = { total: cards.length, up: 0, down: 0, newcomers: 0, same: 0 };

    for (const c of cards) {
      const from = guestSegment(dates.get(c.id), startAsOf).key || 'none';
      const to = guestSegment(dates.get(c.id), endAsOf).key || 'none';
      // карточки без визитов, созданной позже даты, тогда ещё не было — не считаем её «без визитов»
      const existedAtStart = from !== 'none' || !c.created || c.created <= startAsOf;
      const existedAtEnd = to !== 'none' || !c.created || c.created <= endAsOf;
      if (existedAtStart) startCount[from]++;
      if (existedAtEnd) endCount[to]++;
      if (!existedAtEnd) continue;
      if (from === to) { if (to !== 'none') summary.same++; continue; }
      if (from === 'none') summary.newcomers++;
      else if (rankOf(to) > rankOf(from)) summary.up++;
      else summary.down++;
      const k = `${from}>${to}`;
      let f = flows.get(k);
      if (!f) flows.set(k, f = { from, to, count: 0, guests: [] });
      f.count++;
      f.guests.push({ id: c.id, name: c.name, vip: c.vip });
    }

    const flowList = [...flows.values()]
      .map(f => ({
        ...f,
        direction: f.from === 'none' ? 'new' : rankOf(f.to) > rankOf(f.from) ? 'up' : 'down',
        guests: f.guests.sort((a, b) => a.name.localeCompare(b.name, 'ru')).slice(0, SEGMENT_FLOW_GUESTS_MAX)
      }))
      .sort((a, b) => b.count - a.count);

    // Месяцы для выбора: от первого записанного визита до текущего, не больше 24
    let firstDate = null;
    for (const d of dates.values()) if (d.length && (!firstDate || d[0] < firstDate)) firstDate = d[0];
    const months = [];
    let m = currentMonth;
    while (months.length < 24) {
      months.push({ value: m, label: `${MONTHS_NOM[Number(m.slice(5, 7)) - 1]} ${m.slice(0, 4)}` });
      if (!firstDate || m <= firstDate.slice(0, 7)) break;
      m = addDaysStr(`${m}-01`, -1).slice(0, 7);
    }

    res.json({
      month,
      monthLabel: `${MONTHS_NOM[Number(month.slice(5, 7)) - 1]} ${month.slice(0, 4)}`,
      isCurrent: month === currentMonth,
      startAsOf, endAsOf,
      rules: SEGMENT_RULES,
      insight: segmentInsight(dates, today),
      segments: SEGMENTS.map(sg => ({
        key: sg.key, name: sg.name, description: sg.description, rank: sg.rank,
        start: startCount[sg.key], end: endCount[sg.key], delta: endCount[sg.key] - startCount[sg.key]
      })),
      none: { start: startCount.none, end: endCount.none },
      summary,
      flows: flowList,
      months
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось посчитать сегменты' });
  }
});

// ─── «КАК ХОДЯТ ГОСТИ» И ПРАВИЛА СЕГМЕНТОВ ──────────
// Факты по записанным визитам за последний год: сколько гостей вернулось, через сколько дней возвращаются,
// сколько визитов у самых частых. По ним видно, какие границы сегментов подходят именно этому бару.
// Пока данных мало (меньше 30 вернувшихся гостей или история короче 6 недель), подсказку границ не даём.
const INSIGHT_MIN_RETURNED = 30;
const INSIGHT_MIN_SPAN_DAYS = 42;
function percentile(sorted, p) {
  if (!sorted.length) return null;
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1))];
}
function segmentInsight(datesByGuest, today = venueDateStr()) {
  const from = addDaysStr(today, -364);
  let guests = 0, oneTime = 0, firstDate = null;
  const perGuestGap = [], allGaps = [], visitCounts = [];
  for (const all of datesByGuest.values()) {
    const d = all.filter(x => x >= from && x <= today);
    if (!d.length) continue;
    guests++;
    visitCounts.push(d.length);
    if (!firstDate || d[0] < firstDate) firstDate = d[0];
    if (d.length === 1) { oneTime++; continue; }
    const gaps = [];
    for (let i = 1; i < d.length; i++) gaps.push(daysBetween(d[i - 1], d[i]));
    gaps.sort((a, b) => a - b);
    perGuestGap.push(percentile(gaps, 0.5));
    for (const g of gaps) allGaps.push(g);
  }
  perGuestGap.sort((a, b) => a - b); allGaps.sort((a, b) => a - b); visitCounts.sort((a, b) => a - b);
  const returned = guests - oneTime;
  const spanDays = firstDate ? daysBetween(firstDate, today) + 1 : 0;
  const enough = returned >= INSIGHT_MIN_RETURNED && spanDays >= INSIGHT_MIN_SPAN_DAYS;
  const typicalGap = percentile(perGuestGap, 0.5);   // обычный промежуток между визитами у вернувшегося гостя
  const gap80 = percentile(allGaps, 0.8);            // 8 из 10 возвращений укладываются в столько дней
  const top10Visits = percentile(visitCounts, 0.9);  // от стольких визитов — лучшие 10% гостей
  let suggestion = null;
  if (enough && typicalGap) {
    // «давно не был» — после двух обычных промежутков, «потерян» — после четырёх
    const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
    const recentDays = clamp(Math.round(typicalGap * 2), SEGMENT_LIMITS.recentDays.min, SEGMENT_LIMITS.recentDays.max);
    const sleepDays = clamp(Math.round(typicalGap * 4), recentDays + 1, 365);
    const championVisits = clamp(top10Visits || SEGMENT_RULES.championVisits, SEGMENT_RULES.loyalVisits + 1, SEGMENT_LIMITS.championVisits.max);
    const sug = cleanSegmentRules({ recentDays, sleepDays, loyalVisits: SEGMENT_RULES.loyalVisits, championVisits, windowDays: Math.max(SEGMENT_RULES.windowDays, sleepDays) });
    if (sug.rules) suggestion = sug.rules;
  }
  return {
    days: 365, guests, oneTime, returned, spanDays, enough,
    minReturned: INSIGHT_MIN_RETURNED, minSpanDays: INSIGHT_MIN_SPAN_DAYS,
    typicalGap: returned ? typicalGap : null, gap80: returned ? gap80 : null, top10Visits: guests ? top10Visits : null,
    suggestion
  };
}
// Сколько гостей в каждом сегменте по данным границам
function segmentCounts(cards, datesByGuest, rules, today = venueDateStr()) {
  const out = { none: 0 };
  for (const sg of SEGMENTS) out[sg.key] = 0;
  for (const c of cards) out[guestSegment(datesByGuest.get(c.id), today, rules).key || 'none']++;
  return out;
}
async function segmentRulesPayload() {
  const [cards, visits] = await Promise.all([getAllCards(), getAllVisits()]);
  const dates = visitDatesByGuest(visits);
  return {
    rules: { ...SEGMENT_RULES }, defaults: { ...SEGMENT_DEFAULTS }, limits: SEGMENT_LIMITS, meta: segmentRulesMeta,
    isDefault: Object.keys(SEGMENT_DEFAULTS).every(k => SEGMENT_DEFAULTS[k] === SEGMENT_RULES[k]),
    segments: SEGMENTS.map(s => ({ key: s.key, name: s.name, description: s.description })),
    counts: segmentCounts(cards, dates, SEGMENT_RULES),
    insight: segmentInsight(dates)
  };
}
// Право settings.manage — только основатель
app.get('/api/admin/segment-rules', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  try { res.json(await segmentRulesPayload()); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось загрузить правила сегментов' }); }
});
// Что получится с такими границами — до сохранения, ничего не меняет
app.post('/api/admin/segment-rules/preview', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  const chk = cleanSegmentRules(req.body?.rules);
  if (chk.error) return res.status(400).json({ error: chk.error });
  try {
    const [cards, visits] = await Promise.all([getAllCards(), getAllVisits()]);
    const dates = visitDatesByGuest(visits);
    const texts = segmentTexts(chk.rules);
    res.json({
      rules: chk.rules,
      counts: segmentCounts(cards, dates, chk.rules),
      current: segmentCounts(cards, dates, SEGMENT_RULES),
      segments: SEGMENTS.map(s => ({ key: s.key, name: s.name, description: texts[s.key] }))
    });
  } catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось посчитать' }); }
});
app.put('/api/admin/segment-rules', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  const chk = cleanSegmentRules(req.body?.rules);
  if (chk.error) return res.status(400).json({ error: chk.error });
  try {
    const before = { ...SEGMENT_RULES };
    const changed = Object.keys(chk.rules).filter(k => chk.rules[k] !== before[k]);
    if (!changed.length) return res.json({ ok: true, unchanged: true, ...(await segmentRulesPayload()) });
    const meta = { updatedAt: new Date().toISOString(), updatedBy: employeeLabel(req.employee) };
    await store.db.query(
      `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [SEGMENT_RULES_KEY, JSON.stringify({ rules: chk.rules, ...meta })]);
    segmentRulesMeta = meta;
    applySegmentRules(chk.rules);
    forgetMemo('');
    const label = { recentDays: 'был недавно, дней', sleepDays: 'давно не был, дней', loyalVisits: 'лояльный, визитов', championVisits: 'чемпион, визитов', windowDays: 'период, дней' };
    auditNote(req, 'segments.rules_changed', 'settings', SEGMENT_RULES_KEY, `изменены правила сегментов: ${changed.map(k => `${label[k]} ${before[k]} → ${chk.rules[k]}`).join('; ')}`);
    // Сегменты в карточках пересчитываем сразу. В историю гостей это не пишем: гость не менял поведение, поменялись правила.
    syncGuestSegments({ force: true, history: false }).catch(() => {});
    res.json({ ok: true, ...(await segmentRulesPayload()) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить правила сегментов' });
  }
});

// ─── АВТОТЕГИ: НАСТРОЙКИ (Сервис → Автотеги, право settings.manage — только основатель) ─────────
// Что получится у гостей: по каждому варианту — сколько гостей его получит. Считается по всем живым карточкам,
// ничего не меняет. Отметки прихода и ухода берутся из броней одним запросом и держатся в памяти полминуты.
let autotagArrivals = { at: 0, map: null, busy: null };
async function allArrivalsCached() {
  if (autotagArrivals.map && Date.now() - autotagArrivals.at < 30 * 1000) return autotagArrivals.map;
  if (!autotagArrivals.busy) {
    autotagArrivals.busy = cardsDb.allArrivals().then(map => { autotagArrivals = { at: Date.now(), map, busy: null }; return map; })
      .catch(e => { autotagArrivals.busy = null; throw e; });
  }
  return autotagArrivals.busy;
}
// Считает для каждого набора настроек из списка (так превью «было → станет» берёт карточки, визиты и отметки один раз)
async function autotagCountsFor(cfgs) {
  const [arrivals, cards, visits] = await Promise.all([allArrivalsCached(), getAllCards(), getAllVisits()]);
  const today = venueDateStr();
  const dates = visitDatesByGuest(visits);
  let withArrivals = 0;
  const riskNow = new Set();
  for (const c of cards) {
    if ((arrivals.get(c.id) || []).length) withArrivals++;
    if (isAtRisk(guestSegment(dates.get(c.id)), c.vip)) riskNow.add(c.id);
  }
  return cfgs.map(cfg => {
    const vt = { morning: 0, day: 0, evening: 0, night: 0, none: 0 };
    const stay = { quick: 0, long: 0, none: 0 };
    const bd = { today: 0, soon: 0, recent: 0 };
    let withStay = 0;
    for (const c of cards) {
      const arr = arrivals.get(c.id) || [];
      const t = visitTimeTag(arr, cfg.visitTime);
      vt[t ? t.key : 'none']++;
      const st = stayTag(arr, cfg.stay);
      if (st.n) withStay++;
      stay[st.tag ? st.tag.key : 'none']++;
      const b = birthdayInfo(c.birthday, today, cfg.birthday.windowDays);
      if (b) bd[b.when]++;
    }
    return { guests: cards.length, withArrivals, withStay, visitTime: vt, stay, birthday: bd, atRisk: riskNow.size };
  });
}
async function autotagPayload() {
  return {
    config: autotagClone(AUTOTAGS), defaults: autotagClone(AUTOTAG_DEFAULTS), limits: AUTOTAG_LIMITS, colors: AUTOTAG_COLORS,
    meta: autotagMeta,
    isDefault: JSON.stringify(AUTOTAGS) === JSON.stringify(AUTOTAG_DEFAULTS),
    counts: (await autotagCountsFor([AUTOTAGS]))[0]
  };
}
app.get('/api/admin/autotags', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  try { res.json(await autotagPayload()); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось загрузить настройки автотегов' }); }
});
// Что получится с такими настройками — до сохранения
app.post('/api/admin/autotags/preview', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  const chk = cleanAutotagConfig(req.body?.config);
  if (chk.error) return res.status(400).json({ error: chk.error });
  try { const [counts, current] = await autotagCountsFor([chk.config, AUTOTAGS]); res.json({ counts, current }); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось посчитать' }); }
});
app.put('/api/admin/autotags', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  const chk = cleanAutotagConfig(req.body?.config);
  if (chk.error) return res.status(400).json({ error: chk.error });
  try {
    const before = AUTOTAGS;
    if (JSON.stringify(chk.config) === JSON.stringify(before)) return res.json({ ok: true, unchanged: true, ...(await autotagPayload()) });
    const meta = { updatedAt: new Date().toISOString(), updatedBy: employeeLabel(req.employee) };
    await store.db.query(
      `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [AUTOTAG_KEY, JSON.stringify({ config: chk.config, ...meta })]);
    AUTOTAGS = chk.config;
    autotagMeta = meta;
    // что именно поменяли — в журнал: по названиям автотегов
    const changed = Object.keys(chk.config).filter(k => JSON.stringify(chk.config[k]) !== JSON.stringify(before[k])).map(k => AUTOTAG_TITLES[k]);
    auditNote(req, 'autotags.changed', 'settings', AUTOTAG_KEY, `изменены настройки автотегов: ${changed.join(', ')}`);
    res.json({ ok: true, ...(await autotagPayload()) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить настройки автотегов' });
  }
});

// ─── СЕЗОНЫ: ПРАЗДНИЧНАЯ АНИМАЦИЯ В ГОСТЕВОМ ПРИЛОЖЕНИИ ─────────
// Основатель сам задаёт, когда гостям показывать снег, сердечки или розы: список сезонов
// «эффект + даты с и по + включён». Хранится в settings → season.config; гостевой сервер читает тот же ключ
// и отдаёт приложению гостя только то, что действует сегодня (по Москве). Первый подходящий сезон в списке побеждает.
const SEASON_KEY = 'season.config';
const SEASON_EFFECTS = { newyear: 'Новый год: снег', valentine: 'Сердечки', march8: '8 Марта: лепестки роз', halloween: 'Хэллоуин: огоньки и летучие мыши' };
const SEASON_MAX_ITEMS = 20, SEASON_MAX_DAYS = 120;
function isRealDate(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(s || ''));
  if (!m) return false;
  const y = +m[1], mo = +m[2], d = +m[3], dt = new Date(Date.UTC(y, mo - 1, d));
  return y >= 2024 && y <= 2100 && dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d;
}
function cleanSeasons(items) {
  if (!Array.isArray(items)) return { error: 'Список сезонов не получен' };
  if (items.length > SEASON_MAX_ITEMS) return { error: `Сезонов не больше ${SEASON_MAX_ITEMS}` };
  const out = [], ids = new Set();
  for (let i = 0; i < items.length; i++) {
    const x = items[i] && typeof items[i] === 'object' ? items[i] : {};
    const n = i + 1;
    if (!Object.prototype.hasOwnProperty.call(SEASON_EFFECTS, x.effect)) return { error: `Сезон ${n}: выберите эффект из списка` };
    if (!isRealDate(x.from) || !isRealDate(x.to)) return { error: `Сезон ${n}: укажите даты «с» и «по»` };
    if (x.from > x.to) return { error: `Сезон ${n}: дата «с» позже даты «по»` };
    const days = Math.round((Date.parse(x.to) - Date.parse(x.from)) / 86400e3) + 1;
    if (days > SEASON_MAX_DAYS) return { error: `Сезон ${n}: не длиннее ${SEASON_MAX_DAYS} дней (сейчас ${days})` };
    let id = typeof x.id === 'string' && /^[a-z0-9-]{1,40}$/i.test(x.id) ? x.id : '';
    if (!id || ids.has(id)) id = `s${Date.now().toString(36)}${i}`;
    ids.add(id);
    out.push({ id, effect: x.effect, from: x.from, to: x.to, enabled: x.enabled !== false });
  }
  return { items: out };
}
async function moscowToday() {
  const r = await store.db.query(`SELECT to_char(now() AT TIME ZONE 'Europe/Moscow', 'YYYY-MM-DD') AS d`);
  return r.rows[0].d;
}
function activeSeasonOf(items, today) {
  return (items || []).find(x => x.enabled && x.from <= today && today <= x.to) || null;
}
// Где сезоны показываются: «В приложении гостя» (поле app) и «На ТВ» (поле tv) включаются отдельно. По умолчанию оба включены.
async function seasonPayload() {
  const r = await store.db.query('SELECT value FROM settings WHERE key = $1', [SEASON_KEY]);
  const v = r.rows[0] && r.rows[0].value;
  const chk = v && Array.isArray(v.items) ? cleanSeasons(v.items) : { items: [] };
  const items = chk.items || [];
  const today = await moscowToday();
  const act = activeSeasonOf(items, today);
  const targets = { app: !(v && v.app === false), tv: !(v && v.tv === false) };
  const name = act ? SEASON_EFFECTS[act.effect] : null;
  return {
    items, today, targets,
    effects: Object.keys(SEASON_EFFECTS).map(id => ({ id, name: SEASON_EFFECTS[id] })),
    active: act ? { id: act.id, effect: act.effect, name } : null,
    shown: { app: act && targets.app ? { effect: act.effect, name } : null, tv: act && targets.tv ? { effect: act.effect, name } : null },
    meta: { updatedAt: (v && v.updatedAt) || null, updatedBy: (v && v.updatedBy) || '' }
  };
}
app.get('/api/admin/season', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  try { res.json(await seasonPayload()); }
  catch (error) { console.error(error); res.status(500).json({ error: 'Не удалось загрузить сезоны' }); }
});
app.put('/api/admin/season', async (req, res) => {
  if (!(await checkPerm(req, res, 'settings.manage'))) return;
  const chk = cleanSeasons(req.body?.items);
  if (chk.error) return res.status(400).json({ error: chk.error });
  try {
    const before = await seasonPayload();
    // выключатели «В приложении» и «На ТВ»: не пришли (старое приложение) — остаются как были
    const targets = {
      app: typeof req.body?.app === 'boolean' ? req.body.app : before.targets.app,
      tv: typeof req.body?.tv === 'boolean' ? req.body.tv : before.targets.tv
    };
    const same = JSON.stringify(before.items.map(({ effect, from, to, enabled }) => ({ effect, from, to, enabled }))) ===
      JSON.stringify(chk.items.map(({ effect, from, to, enabled }) => ({ effect, from, to, enabled })))
      && before.targets.app === targets.app && before.targets.tv === targets.tv;
    if (same) return res.json({ ok: true, unchanged: true, ...before });
    await store.db.query(
      `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [SEASON_KEY, JSON.stringify({ items: chk.items, app: targets.app, tv: targets.tv, updatedAt: new Date().toISOString(), updatedBy: employeeLabel(req.employee) })]);
    const after = await seasonPayload();
    const list = chk.items.map(x => `${SEASON_EFFECTS[x.effect]} ${x.from}…${x.to}${x.enabled ? '' : ' (выключен)'}`).join('; ') || 'пусто';
    const flags = [];
    if (before.targets.app !== targets.app) flags.push(targets.app ? 'в приложении гостя включены' : 'в приложении гостя выключены');
    if (before.targets.tv !== targets.tv) flags.push(targets.tv ? 'на ТВ включены' : 'на ТВ выключены');
    auditNote(req, 'season.changed', 'settings', SEASON_KEY, `изменены сезоны: ${list}${flags.length ? `. Сезоны ${flags.join(', ')}` : ''}. Сегодня гости видят: ${after.shown.app ? after.shown.app.name : 'без анимации'}; на ТВ: ${after.shown.tv ? after.shown.tv.name : 'без анимации'}`);
    res.json({ ok: true, ...after });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось сохранить сезоны' });
  }
});

// ─── СЕГМЕНТ В КАРТОЧКЕ + ИСТОРИЯ ПЕРЕХОДОВ ─────────
// Приложение считает сегмент на лету, по визитам. Раз в час сервер ещё и записывает его в карточку
// (guests.segment — чтобы видеть и фильтровать в окне данных), а переход из сегмента в сегмент —
// строкой в журнал карточки («Система: сегмент Лояльные → Спящие»). Первое заполнение строк
// в журнале не добавляет.
// Выключить: SEGMENTS_SYNC=off. Запустить вручную: POST /api/admin/segments/sync.
const SEGMENT_SYNC = { enabled: process.env.SEGMENTS_SYNC !== 'off' };
let segmentSyncRunning = false;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function syncGuestSegments({ force = false, history = true } = {}) {
  if (!SEGMENT_SYNC.enabled && !force) return { skipped: true, skippedReason: 'disabled' };
  if (segmentSyncRunning) return { skipped: true, skippedReason: 'running' };
  segmentSyncRunning = true;
  const result = { checked: 0, changed: 0, written: 0, historyLines: 0, failed: 0, remaining: 0 };
  try {
    const [cardList, visits] = await Promise.all([cardsDb.allCards(), getAllVisits()]);
    const dates = visitDatesByGuest(visits);
    const today = venueDateStr();
    const next = new Map(cardList.map(c => [c.id, guestSegment(dates.get(c.id), today).name]));
    const done = await cardsDb.applySegments(next, { knownNames: new Set(SEGMENTS.map(s => s.name)), history });
    Object.assign(result, done);
    if (result.written) forgetMemo('marketing');
    if (result.written) console.log('Сегменты в карточках:', JSON.stringify(result));
    return result;
  } catch (e) {
    console.error('Segments sync failed:', e.message);
    return { ...result, error: e.message };
  } finally {
    segmentSyncRunning = false;
  }
}

setInterval(() => { syncGuestSegments(); }, 60 * 60 * 1000);

// Ручной запуск. По умолчанию отвечаем сразу, а итог пишется в лог сервера; с wait=1 ждём и отдаём итог в ответе.
app.post('/api/admin/segments/sync', async (req, res) => {
  if (!(await checkPerm(req, res, 'segments.view'))) return;
  const wait = req.query.wait === '1' || req.body?.wait === true;
  if (!wait) {
    if (segmentSyncRunning) return res.json({ started: false, running: true });
    syncGuestSegments({ force: true });
    return res.json({ started: true });
  }
  res.json(await syncGuestSegments({ force: true }));
});

// ─── ОБРАТНАЯ СВЯЗЬ: ВСЕ ОТЗЫВЫ ГОСТЕЙ В ОДНОМ МЕСТЕ ──
// Свежие отзывы (с оценками по категориям, NPS и комментарием) с привязкой к карточке
// гостя по телефону, сводка за период, открытые проблемы и сколько гостей бот попросил
// оценить визит.
const REVIEW_CATEGORIES = ['Вечер', 'Кальян', 'Напитки', 'Еда', 'Команда'];

app.get('/api/admin/feedback', async (req, res) => {
  if (!(await checkPerm(req, res, 'feedback.view'))) return;
  const days = Math.min(Math.max(Number(req.query.days) || 30, 1), 365);
  const since = addDaysStr(venueDateStr(), -(days - 1));
  try {
    const [reviewRows, cardPages, problemList, visits, enps] = await Promise.all([
      memo(`feedback:reviews:${since}`, 60 * 1000, () => feedback.listReviews(since)),
      getAllCards(),
      memo('feedback:problems', 60 * 1000, () => feedback.listOpenProblems()),
      getAllVisits(),
      getMonthEnps() // фиксированный текущий месяц, не зависит от ?days= — опросы раз в месяц
    ]);
    // Что сотрудники написали в опросе — только основателю: раньше тексты сохранялись, но прочитать их было негде.
    // Только за закончившиеся месяцы, без дня ответа и без оценки, в случайном порядке (почему так — см. db/feedback.js).
    let enpsTexts = null;
    if (req.employee.role === 'Основатель') {
      try {
        enpsTexts = { minAnswers: feedback.ENPS_MIN_ANSWERS, months: await memo('feedback:enps-texts', 2 * 60 * 1000, () => feedback.listEnpsTexts({ months: 6 })) };
      } catch (e) { console.error('Ответы опроса сотрудников не прочитались:', e.message); }
    }

    const visitDates = visitDatesByGuest(visits);
    const cardById = new Map(cardPages.map(c => [c.id, c]));
    const cardByPhone = new Map();
    for (const info of cardPages) {
      const key = normalizePhone(info.phone);
      if (key && !cardByPhone.has(key)) cardByPhone.set(key, info);
    }

    const reviews = reviewRows.map(p => {
      const scores = p.scores;
      const vals = Object.values(scores).filter(v => v !== null);
      const phone = p.phone || '';
      // карточка — по привязке отзыва к гостю; для старых отзывов без привязки — по телефону
      const card = (p.guestId && cardById.get(p.guestId)) || (phone ? cardByPhone.get(normalizePhone(phone)) : null);
      const nps = p.nps;
      const min = vals.length ? Math.min(...vals) : null;
      return {
        id: p.id,
        date: p.date,
        scores,
        avg: vals.length ? Math.round((vals.reduce((a, b) => a + b, 0) / vals.length) * 10) / 10 : null,
        nps,
        comment: p.comment,
        phone,
        telegramUsername: p.telegramUsername,
        guest: card ? { id: card.id, name: card.name, vip: card.vip, segment: guestSegment(visitDates.get(card.id)).name } : null,
        negative: (min !== null && min <= 3) || (nps !== null && nps <= 6)
      };
    });

    const npsVals = reviews.map(r => r.nps).filter(n => n !== null);
    const promoters = npsVals.filter(n => n >= 9).length;
    const detractors = npsVals.filter(n => n <= 6).length;
    const categories = {};
    for (const c of REVIEW_CATEGORIES) {
      const vals = reviews.map(r => r.scores[c]).filter(v => v !== null);
      categories[c] = vals.length ? Math.round((vals.reduce((a, b) => a + b, 0) / vals.length) * 10) / 10 : null;
    }
    const avgs = reviews.map(r => r.avg).filter(v => v !== null);

    // Просьбы оценить визит за тот же период
    const requests = { sent: 0, noTelegram: 0, optedOut: 0, other: 0 };
    for (const v of visits) {
      if (!v.reviewRequest || !v.date || v.date.slice(0, 10) < since) continue;
      if (v.reviewRequest === 'Отправлен') requests.sent++;
      else if (v.reviewRequest === 'Нет Telegram' || v.reviewRequest === 'Нет телефона') requests.noTelegram++;
      else if (v.reviewRequest === 'Отписан') requests.optedOut++;
      else requests.other++;
    }

    const today = venueDateStr();
    let contactStats = null;
    try { contactStats = await feedback.contactStats(days); } catch (e) { console.error('Связь с гостями по отзывам:', e && e.message ? e.message : e); }
    const openProblems = {
      total: problemList.length,
      overdue: problemList.filter(p => p.deadline && p.deadline.slice(0, 10) < today).length,
      guestContact: contactStats
    };

    res.json({
      days, since,
      summary: {
        count: reviews.length,
        csi: avgs.length ? Math.round((avgs.reduce((a, b) => a + b, 0) / avgs.length) * 10) / 10 : null,
        nps: npsOf(npsVals),
        promoters, passives: npsVals.length - promoters - detractors, detractors,
        categories,
        negative: reviews.filter(r => r.negative).length,
        withComment: reviews.filter(r => r.comment.trim()).length
      },
      requests,
      openProblems,
      enps,
      ...(enpsTexts ? { enpsTexts } : {}),
      reviews: reviews.slice(0, 200)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Не удалось загрузить обратную связь' });
  }
});

// Проверка живости: отвечает, доступна ли база Postgres
// ─── СЕРВИС: СОСТОЯНИЕ СИСТЕМЫ (только основатель) ─────────────────
// Что работает прямо сейчас: база, оба сервера, оба бота, версия схемы базы, настройки сервера, размер базы и журнала,
// и когда последний раз делали резервную копию.
// О копиях сервер сам ничего не знает: задача jarvis-backup записывает время в settings['backup.last_at'] и сведения в
// settings['backup.last_info']; пока записи нет, экран честно говорит «нет данных». Здесь ничего не стирается.
async function timed(fn) {
  const t0 = Date.now();
  try { const extra = await fn(); return { ok: true, ...extra, ms: Date.now() - t0 }; }
  catch (e) { return { ok: false, ms: Date.now() - t0, error: String(e && e.message || e).slice(0, 160) }; }
}
function withTimeout(promise, ms) {
  return Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error('нет ответа')), ms))]);
}

app.get('/api/founder/system-status', async (req, res) => {
  if (!(await checkFounderPin(req, res))) return;
  const [database, staffBot, guestServer, guestBot, backup, mig, tgFails, adminChat, storage, guestKey] = await Promise.all([
    timed(async () => { await withTimeout(store.db.ping(), 4000); return {}; }),
    timed(async () => {
      const me = await withTimeout(tgApi('getMe', {}), 5000);
      if (!me || !me.ok) throw new Error('Telegram не ответил');
      const wh = await withTimeout(tgApi('getWebhookInfo', {}), 5000);
      const info = (wh && wh.result) || {};
      return { username: me.result.username, webhookSet: !!info.url, pending: info.pending_update_count || 0, lastError: info.last_error_message || '' };
    }),
    timed(async () => {
      if (!GUEST_PROXY_BASE) throw new Error('не задана переменная GUEST_PROXY_BASE');
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 5000);
      try {
        const r = await fetch(`${GUEST_PROXY_BASE}/health`, { signal: ctl.signal });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.ok) throw new Error('сервер ответил ошибкой');
        return { db: j.db !== false };
      } finally { clearTimeout(timer); }
    }),
    timed(async () => {
      if (!GUEST_PROXY_BASE) throw new Error('не задана переменная GUEST_PROXY_BASE');
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 6000);
      try {
        const r = await fetch(`${GUEST_PROXY_BASE}/api/bot-info`, { signal: ctl.signal });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.username) throw new Error('бот не отвечает');
        return { username: j.username };
      } finally { clearTimeout(timer); }
    }),
    ops.readBackup((t, p) => store.db.query(t, p)).catch(() => ({ lastAt: null, info: null })),
    store.db.query('SELECT name FROM schema_migrations ORDER BY name DESC LIMIT 1').then(r => (r.rows[0] && r.rows[0].name) || null).catch(() => null),
    store.tgFailureStats(24).catch(() => null),
    // Админ-чат: бот видит чат (иначе сообщения о бронях и проблемах не доходят) и задана ли переменная ADMIN_CHAT_ID
    timed(async () => {
      const r = await withTimeout(tgApi('getChat', { chat_id: ADMIN_CHAT_ID }), 5000);
      if (!r || !r.ok) throw new Error(r && r.description ? `Telegram: ${r.description}` : 'Telegram не ответил');
      return { title: String(r.result.title || r.result.first_name || '').slice(0, 60) };
    }),
    // размер базы, фото/видео и журнала (null — не удалось прочитать)
    withTimeout(ops.storageStats((t, p) => store.db.query(t, p)), 8000).catch(() => null),
    // ключ связи двух серверов: одинаковый ли он на обоих. Проба безвредная: маршрут проверяет ключ первым делом, а при пустом
    // теле отвечает 400 «нужны телефон и бронь», ничего не делая. 400 = ключ принят, 401 = ключи разные.
    (async () => {
      if (!INTERNAL_ADMIN_KEY) return { state: 'no_key' };
      if (!GUEST_PROXY_BASE) return { state: 'unknown' };
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 5000);
      try {
        const r = await fetch(`${GUEST_PROXY_BASE}/api/internal/booking/confirm`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'x-internal-key': INTERNAL_ADMIN_KEY }, body: '{}', signal: ctl.signal
        });
        return { state: r.status === 400 ? 'ok' : r.status === 401 ? 'mismatch' : 'unknown' };
      } catch { return { state: 'unknown' }; } finally { clearTimeout(timer); }
    })()
  ]);
  const storageWarn = storage ? ops.storageWarnings(storage) : [];
  res.json({
    checkedAt: new Date().toISOString(),
    database: { ...database, migration: mig },
    // версия схемы: что в базе и что нужно этому коду (state: ok | behind | unknown)
    schema: ops.compareSchema(mig),
    // размер базы, фото и видео, журнала действий; warn — что вышло за порог (ничего не удаляется)
    storage: storage ? { ...storage, warn: storageWarn } : null,
    // что не так с настройками сервера (только названия переменных, значения не показываются)
    config: { problems: ops.checkConfig(process.env) },
    // совпадает ли ключ связи с гостевым сервером (state: ok | mismatch | no_key | unknown)
    guestKey,
    staffServer: { ok: true, uptimeSec: Math.round(process.uptime()), employees: employeesCache.length },
    staffBot,
    guestServer,
    guestBot,
    backup: ops.backupState(backup.lastAt, backup.info),
    adminChat: { ...adminChat, fromEnv: ADMIN_CHAT_FROM_ENV, failed24h: tgFails && tgFails.byKind && tgFails.byKind.admin ? tgFails.byKind.admin.failed : 0 },
    // сообщения гостям, которые не дошли за сутки (null — не удалось прочитать)
    sendFailures: tgFails
  });
});

// ─── ПРОВЕРКИ УСТОЙЧИВОСТИ: НАСТРОЙКИ, СХЕМА, ВОЗРАСТ КОПИИ (аудит 30.10: В4, Д1, Д3) ─────────────────
// После запуска сервер сверяет свои настройки и версию схемы базы, раз в час проверяет возраст последней копии.
// Всё серьёзное пишется в лог и один раз в сутки уходит в админ-чат (сервер перезапускается при каждой выкладке,
// поэтому «уже сообщали» хранится в базе: settings → ops.alerts). Ничего не чинится и не удаляется само.
// OPS_ALERTS=off — не писать в админ-чат (проверки в логе и на «Состоянии» остаются).
const opsQ = (t, p) => store.db.query(t, p);
let opsRunning = false;
function opsChatOn() { return process.env.OPS_ALERTS !== 'off' && !!TELEGRAM_BOT_TOKEN; }

async function opsStartupCheck() {
  try {
    const problems = ops.checkConfig(process.env);
    const mig = await opsQ('SELECT name FROM schema_migrations ORDER BY name DESC LIMIT 1').then(r => (r.rows[0] && r.rows[0].name) || null).catch(() => null);
    const schema = ops.compareSchema(mig);
    for (const p of problems) console.error(`[проверка настроек] ${p.level === 'bad' ? 'ОШИБКА' : 'внимание'}: ${p.key} — ${p.text}`);
    if (!problems.length) console.log('[проверка настроек] все нужные переменные заданы');
    if (schema.state === 'behind') console.error(`[проверка схемы] база отстаёт: в ней ${schema.actual}, коду нужна ${schema.required}. Запустите (перезапустите) сервис jarvis`);
    else if (schema.state === 'unknown') console.error('[проверка схемы] не удалось прочитать версию схемы базы');
    else console.log(`[проверка схемы] версия базы ${schema.actual}, коду нужна не ниже ${schema.required}: порядок`);
    const sig = ops.problemsSignature(problems, schema);
    if (!sig || !opsChatOn()) return;
    const alerts = await ops.readAlerts(opsQ);
    const prev = alerts.startup;
    if (prev && prev.sig === sig && Date.now() - Date.parse(prev.at) < 24 * 3600e3) return;
    const lines = problems.filter(p => p.level === 'bad').map(p => `• ${p.key}: ${p.text}`);
    if (schema.state === 'behind') lines.push(`• База отстаёт от кода: в ней ${schema.actual}, нужна ${schema.required}. Перезапустите сервис jarvis`);
    const sent = await sendAdmin(`⚠️ Сервер сотрудников запустился с проблемами:\n${lines.join('\n')}\n\nПодробности: «Состояние системы» в разделе «Сервис».`, 'проверка при запуске');
    if (sent) { alerts.startup = { sig, at: new Date().toISOString() }; await ops.saveAlerts(opsQ, alerts); }
  } catch (e) {
    console.error('Проверка при запуске:', e && e.message ? e.message : e);
  }
}

function opsAgeText(hours) {
  const h = Math.round(hours);
  return h >= 48 ? `${Math.floor(h / 24)} дн.` : `${h} ч`;
}

async function opsHourlyCheck() {
  if (opsRunning) return;
  opsRunning = true;
  try {
    const b = await ops.readBackup(opsQ).then(r => ops.backupState(r.lastAt, r.info));
    if (!opsChatOn()) return;
    const alerts = await ops.readAlerts(opsQ);
    // окно, когда можно писать в чат (по Москве), по умолчанию 9–22; OPS_ALERT_HOURS=8-23 меняет
    const win = /^(\d{1,2})-(\d{1,2})$/.exec(String(process.env.OPS_ALERT_HOURS || '').trim());
    if (!ops.backupAlertDue(b, alerts.backup, venueHour(), Date.now(), win ? { hourFrom: Number(win[1]), hourTo: Number(win[2]) } : {})) return;
    const when = new Intl.DateTimeFormat('ru-RU', { timeZone: VENUE_TZ, day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(b.lastAt));
    const sent = await sendAdmin(`⚠️ Резервная копия базы устарела: последняя сделана ${when} по Москве, ${opsAgeText(b.ageHours)} назад. Копии должны делаться раз в сутки.\n\nПроверьте задачу копирования на Amvera (сервис jarvis-backup). Напоминание повторится завтра, пока свежей копии нет.`, 'устарела копия базы');
    if (sent) { alerts.backup = { for: b.lastAt, at: new Date().toISOString() }; await ops.saveAlerts(opsQ, alerts); }
  } catch (e) {
    console.error('Проверка копий:', e && e.message ? e.message : e);
  } finally {
    opsRunning = false;
  }
}
setInterval(opsHourlyCheck, Math.max(1000, Number(process.env.OPS_TICK_MS) || 60 * 60 * 1000)).unref();
setTimeout(opsHourlyCheck, Math.max(1000, Number(process.env.OPS_FIRST_MS) || 5 * 60 * 1000)).unref();
setTimeout(opsStartupCheck, Math.max(1000, Number(process.env.OPS_STARTUP_MS) || 25 * 1000)).unref();

app.get('/health', async (req, res) => {
  try {
    await store.db.ping();
    // Без входа отдаём только «жив / база доступна»: число сотрудников и признак PIN_SECRET снаружи видеть не нужно (аудит 30.10, Б5).
    // Подробности для своих — на экране «Состояние» (нужен вход).
    res.json({ ok: true, db: true });
  } catch (e) {
    res.status(503).json({ ok: false, db: false });
  }
});

app.get('/', (req, res) => {
  res.send('Staff Proxy for На Крыше is running ✅');
});

// Общий обработчик ошибок: всегда JSON и всегда ответ
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (res.headersSent) { console.error(`Ошибка после ответа ${req.method} ${req.path}:`, err && err.message ? err.message : err); return; }
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Файл слишком большой' });
  if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) return res.status(400).json({ error: 'Запрос не разобрался — обновите приложение и попробуйте ещё раз' });
  console.error(`Ошибка в обработчике ${req.method} ${req.path}:`, err && err.message ? err.message : err);
  // база или сеть недоступны — «попробуйте через минуту»; всё остальное — обычная ошибка сервера
  const msg = String((err && err.message) || '');
  const down = !!err && (['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', '57P01', '57P03', '53300'].includes(err.code) || /timeout|terminat|connect/i.test(msg));
  if (down) return res.status(503).json({ error: 'Сервер сейчас не может ответить — попробуйте через минуту', code: 'server_unavailable' });
  res.status(500).json({ error: 'Не удалось выполнить запрос — попробуйте ещё раз' });
});

// Необработанная ошибка в фоновой задаче не должна ронять весь сервер
process.on('unhandledRejection', err => {
  console.error('Unhandled rejection:', err && err.message ? err.message : err);
});

// ─── СТОП-ЛИСТ: автосброс в новый рабочий день ─────
// Рабочий день меняется в 06:00 по Москве. Сразу после этого позиции, поставленные «в стоп» на смену (на экране «Стоп-лист»)
// до начала дня, возвращаются в меню: иначе забытая позиция на следующий день остаётся скрытой от гостей.
// Позиции, убранные из меню в редакторе («В стопе» в форме позиции), сами не возвращаются. STOPLIST_AUTO_RESET=off — выключить.
let stoplistRunning = false;
async function runStoplistReset() {
  if (stoplistRunning || process.env.STOPLIST_AUTO_RESET === 'off') return null;
  stoplistRunning = true;
  try {
    // рабочий день = московская дата минус 6 часов: до 06:00 это ещё вчерашний день, и он уже сброшен
    const day = venueDateStr(new Date(Date.now() - 6 * 3600 * 1000));
    const r = await catalog.resetStoplistForDay(day);
    if (!r.skipped && r.count) console.log(`Стоп-лист сброшен на ${day}: ${r.count} поз.`);
    return r;
  } catch (e) {
    console.error('Автосброс стоп-листа:', e && e.message ? e.message : e);
    return null;
  } finally {
    stoplistRunning = false;
  }
}
setInterval(runStoplistReset, 10 * 60 * 1000).unref();
setTimeout(runStoplistReset, 45 * 1000).unref();

const httpServer = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  // Сразу загружаем копию визитов в фоне, чтобы первый открывший «Давно не было»
  // или статистику не ждал полной выгрузки базы.
  store.db.ping().then(() => console.log('База Postgres доступна')).catch(e => console.error('База Postgres недоступна:', e.message));
  // сегменты в карточках: первая запись через пару минут после старта, потом раз в час
  setTimeout(() => { syncGuestSegments(); }, 2 * 60 * 1000);
  ensureWebhookSecret();
  closeStaleReviewRequests();
});

// ─── МЯГКАЯ ОСТАНОВКА ───────────────────────────────
// При каждой выкладке Amvera присылает сигнал остановки. Раньше сервер умирал сразу: запросы «на лету»
// (сохранение, бронь, ответ гостю) обрывались, соединения с базой не закрывались (аудит 30.10, В2).
// Теперь: перестаём принимать новые запросы, ждём текущие (не дольше 10 секунд), закрываем базу.
let shuttingDown = false;
function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[stop] получен ${signal}: новые запросы не принимаю, жду текущие до 10 секунд`);
  const force = setTimeout(() => { console.error('[stop] текущие запросы не завершились за 10 секунд, выхожу'); process.exit(0); }, 10000);
  force.unref();
  httpServer.close(async () => {
    try { await store.db.close(); } catch (e) { console.error('[stop] база закрылась с ошибкой:', e && e.message ? e.message : e); }
    clearTimeout(force);
    console.log('[stop] остановился чисто');
    process.exit(0);
  });
  if (typeof httpServer.closeIdleConnections === 'function') httpServer.closeIdleConnections();
}
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => gracefulShutdown(sig));
