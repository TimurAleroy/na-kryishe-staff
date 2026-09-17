const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

const NOTION_TOKEN = process.env.NOTION_TOKEN;
const NOTION_GUESTS_DB_ID = '35173a7166368022bf60d76141cca681'; // Карточка Гостя
const NOTION_VISITS_DB_ID = 'f384e676a0d7477bb45a34707bcb0dff'; // Визиты
const NOTION_PROBLEMS_DB_ID = '88be90a6768e4c9da2819565e1a69f62'; // Проблемы
const NOTION_REVIEWS_DB_ID = '994a20a76308436683487de6593747fb'; // Отзывы CSI (заполняется гостевым приложением)
const NOTION_ENPS_DB_ID = 'bb06232232d44950842790033109f8ba'; // Отзывы eNPS — полностью анонимно, без привязки к сотруднику
const NOTION_EVENTS_DB_ID = '35173a71663680999ebcf882ecea022d'; // Журнал Мероприятий
const NOTION_GENERAL_GUESTS_DB_ID = 'f25cd3eb7e8441f2ada6bdd20700c4d6'; // Общая база гостей (из гостевого мини-аппа)
const NOTION_EMPLOYEES_DB_ID = '56fb72e9a9244998828c1d8d3cb9b381'; // Сотрудники — именные PIN-коды
const NOTION_SCHEDULE_DB_ID = '34d1765f8cd64ed0abc3838096a22066'; // График смен — замена Supershift
const NOTION_MENU_DB_ID = '4640c3e50a71422e8d61830c060f52c8'; // Меню — тот же источник, что и в гостевом приложении

// Кто может снимать/возвращать позицию своей категории с "В наличии".
// Администратор — всегда, независимо от категории.
const MENU_CATEGORY_EDIT_ROLE = {
  'Напитки': 'Бармен',
  'Еда': 'Повар',
  'Кальян': 'КМ'
};
function canEditMenuCategory(employeeRole, category) {
  return employeeRole === 'Администратор' || MENU_CATEGORY_EDIT_ROLE[category] === employeeRole;
}
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID || '188483198';
const WEBAPP_URL = 'https://timuraleroy.github.io/na-kryishe-staff';
const PORT = process.env.PORT || 3000;

const NOTION_HEADERS = {
  'Authorization': `Bearer ${NOTION_TOKEN}`,
  'Notion-Version': '2022-06-28',
  'Content-Type': 'application/json'
};

// Сервер (Railway) работает по UTC, а заведение — по владикавказскому времени (UTC+3, без перевода часов).
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

// ─── ИМЕННЫЕ СОТРУДНИКИ (кэш в памяти, обновляется раз в 5 минут) ──
// Вместо общего PIN на всех — у каждого сотрудника свой код в базе "Сотрудники".
// Уволили/поменяли роль — просто правим строку в Notion, код обновится сам.

let employeesCache = [];
let employeesCacheTime = 0;
const EMPLOYEES_CACHE_TTL = 5 * 60 * 1000; // 5 минут

async function refreshEmployees() {
  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_EMPLOYEES_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ filter: { property: 'Активен', checkbox: { equals: true } } })
    });
    const data = await r.json();
    employeesCache = (data.results || [])
      .map(e => ({
        id: e.id,
        name: e.properties['Имя']?.title?.[0]?.plain_text || '',
        pin: e.properties['PIN']?.rich_text?.[0]?.plain_text || '',
        role: e.properties['Роль']?.select?.name || '',
        telegramId: e.properties['Telegram ID']?.rich_text?.[0]?.plain_text || ''
      }))
      .filter(e => e.pin); // без PIN сотрудник не может войти
    employeesCacheTime = Date.now();
  } catch (err) {
    console.error('Не удалось обновить список сотрудников:', err);
  }
}

async function ensureEmployeesFresh() {
  if (Date.now() - employeesCacheTime > EMPLOYEES_CACHE_TTL) {
    await refreshEmployees();
  }
}

function findEmployeeByPin(pin) {
  return employeesCache.find(e => e.pin === pin);
}

// Любой активный сотрудник — базовый доступ
async function checkPin(req, res) {
  await ensureEmployeesFresh();
  const pin = req.query.pin || req.body?.pin;
  const employee = findEmployeeByPin(pin);
  if (!employee) {
    res.status(401).json({ error: 'Неверный PIN-код' });
    return false;
  }
  req.employee = employee;
  return true;
}

// Только роль "Администратор" — функции управляющего
async function checkAdminPin(req, res) {
  await ensureEmployeesFresh();
  const pin = req.query.pin || req.body?.pin;
  const employee = findEmployeeByPin(pin);
  if (!employee || employee.role !== 'Администратор') {
    res.status(403).json({ error: 'Доступно только администратору' });
    return false;
  }
  req.employee = employee;
  return true;
}

refreshEmployees(); // загружаем список сразу при старте сервера
setInterval(refreshEmployees, EMPLOYEES_CACHE_TTL);

// ─── НАПОМИНАНИЯ О ПРОСРОЧЕННЫХ ПРОБЛЕМАХ ──────────
// Раз в несколько часов проверяем "В работе" с истёкшим сроком — шлём
// ответственному (по роли) и админу. Не чаще одного раза в день на проблему.

const remindedToday = new Set(); // "problemId_YYYY-MM-DD"

async function checkOverdueProblems() {
  try {
    await ensureEmployeesFresh();
    const today = venueDateStr();
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_PROBLEMS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: {
          and: [
            { property: 'Статус', select: { equals: 'В работе' } },
            { property: 'Срок исполнения', date: { before: today } }
          ]
        }
      })
    });
    const data = await r.json();

    for (const page of data.results || []) {
      const key = `${page.id}_${today}`;
      if (remindedToday.has(key)) continue;

      const props = page.properties;
      const title = props['Проблема']?.title?.[0]?.plain_text || 'Проблема';
      const responsibleRole = props['Ответственный']?.rich_text?.[0]?.plain_text || '';
      const deadline = props['Срок исполнения']?.date?.start || '';

      const text = `⏰ Просрочена проблема: «${title}»\nОтветственный: ${responsibleRole}\nСрок был: ${deadline}\n\nПожалуйста, закройте или обновите срок.`;

      // Шлём каждому активному сотруднику с нужной ролью, у кого есть Telegram ID
      const responsibleEmployees = employeesCache.filter(e => e.role === responsibleRole);
      for (const emp of responsibleEmployees) {
        if (emp.telegramId) await sendTelegramMessage(emp.telegramId, text);
      }
      await sendTelegramMessage(ADMIN_CHAT_ID, text);

      remindedToday.add(key);
    }
  } catch (err) {
    console.error('Overdue problems check failed:', err);
  }
}

setInterval(checkOverdueProblems, 6 * 60 * 60 * 1000); // каждые 6 часов
setTimeout(checkOverdueProblems, 30 * 1000); // и один раз вскоре после старта сервера

async function tgApi(method, payload) {
  if (!TELEGRAM_BOT_TOKEN) return null;
  try {
    const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return await res.json();
  } catch (err) {
    console.error(`Telegram API ${method} failed:`, err);
    return null;
  }
}

async function sendTelegramMessage(chatId, text) {
  return tgApi('sendMessage', { chat_id: chatId, text });
}

// ─── ПРОВЕРКА PIN ──────────────────────────────────

app.post('/api/staff/login', async (req, res) => {
  await ensureEmployeesFresh();
  const pin = req.body?.pin;
  const employee = findEmployeeByPin(pin);
  if (!employee) return res.status(401).json({ error: 'Неверный PIN-код' });

  const isAdmin = employee.role === 'Администратор';
  res.json({ ok: true, role: isAdmin ? 'admin' : 'staff', name: employee.name, jobRole: employee.role });
});

// ─── ИМЕНИННИКИ СЕГОДНЯ ─────────────────────────────

app.get('/api/staff/birthdays', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_GUESTS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ filter: { property: 'Дата рождения', date: { is_not_empty: true } } })
    });
    const data = await r.json();
    const todayMonthDay = venueMonthDay(); // MM-DD, по местному времени

    const birthdays = (data.results || [])
      .filter(g => {
        const bday = g.properties['Дата рождения']?.date?.start;
        return bday && bday.slice(5, 10) === todayMonthDay;
      })
      .map(g => ({
        id: g.id,
        name: g.properties['Имя Гостя']?.title?.[0]?.plain_text || '',
        phone: g.properties['Телефон']?.phone_number || '',
        status: g.properties['Частота визитов']?.select?.name || ''
      }));

    res.json(birthdays);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch birthdays' });
  }
});

// ─── ГОСТИ ПО СТАТУСУ (например все VIP) ────────────

app.get('/api/staff/guests-by-status', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const status = req.query.status;
  if (!status) return res.status(400).json({ error: 'status required' });

  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_GUESTS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: { property: 'Частота визитов', select: { equals: status } },
        sorts: [{ property: 'Имя Гостя', direction: 'ascending' }]
      })
    });
    const data = await r.json();
    const guests = (data.results || []).map(g => ({
      id: g.id,
      name: g.properties['Имя Гостя']?.title?.[0]?.plain_text || '',
      phone: g.properties['Телефон']?.phone_number || ''
    }));
    res.json(guests);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch guests by status' });
  }
});

// ─── ГОСТИ, КОТОРЫХ ДАВНО НЕ БЫЛО (30+ дней) ────────

app.get('/api/staff/inactive-guests', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  const thresholdDays = 30;

  try {
    // Берём только VIP и Постоянных — для "Редких" отсутствие визитов не сигнал
    const guestsRes = await fetch(`https://api.notion.com/v1/databases/${NOTION_GUESTS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: { or: [
          { property: 'Частота визитов', select: { equals: 'VIP' } },
          { property: 'Частота визитов', select: { equals: 'Постоянный' } }
        ]}
      })
    });
    const guestsData = await guestsRes.json();
    const guests = guestsData.results || [];

    // Один запрос по всем визитам, группируем по гостю локально — быстрее чем по одному запросу на гостя
    const visitsRes = await fetch(`https://api.notion.com/v1/databases/${NOTION_VISITS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ sorts: [{ property: 'Дата', direction: 'descending' }], page_size: 100 })
    });
    const visitsData = await visitsRes.json();
    const lastVisitByGuest = {};
    for (const v of visitsData.results || []) {
      const guestId = v.properties['Гость']?.relation?.[0]?.id;
      const date = v.properties['Дата']?.date?.start;
      if (guestId && date && !lastVisitByGuest[guestId]) lastVisitByGuest[guestId] = date;
    }

    const now = new Date();
    const inactive = [];
    for (const g of guests) {
      const lastVisit = lastVisitByGuest[g.id];
      const daysSince = lastVisit
        ? Math.floor((now - new Date(lastVisit)) / (1000 * 60 * 60 * 24))
        : null; // визитов вообще не было записано

      if (daysSince === null || daysSince >= thresholdDays) {
        inactive.push({
          id: g.id,
          name: g.properties['Имя Гостя']?.title?.[0]?.plain_text || '',
          phone: g.properties['Телефон']?.phone_number || '',
          status: g.properties['Частота визитов']?.select?.name || '',
          lastVisit: lastVisit || null,
          daysSince
        });
      }
    }

    inactive.sort((a, b) => (b.daysSince || 999) - (a.daysSince || 999));
    res.json(inactive);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch inactive guests' });
  }
});

// ─── БЫСТРАЯ ЗАМЕТКА О ПРОБЛЕМЕ (от любого сотрудника) ──

app.post('/api/staff/problem', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const { category, comment, severity } = req.body;
  if (!category || !comment) return res.status(400).json({ error: 'category and comment required' });

  const responsibleRole = CATEGORY_ROLE_MAP[category] || 'Администратор';
  const finalSeverity = severity || 'Средняя';

  try {
    await fetch('https://api.notion.com/v1/pages', {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        parent: { database_id: NOTION_PROBLEMS_DB_ID },
        properties: {
          'Проблема': { title: [{ text: { content: `${category} — сообщено сотрудником` } }] },
          'Категория': { select: { name: category } },
          'Комментарий гостя': { rich_text: [{ text: { content: comment } }] },
          'Дата отзыва': { date: { start: venueDateStr() } },
          'Статус': { select: { name: 'Задачи' } },
          'Критичность': { select: { name: finalSeverity } },
          'Ответственный': { rich_text: [{ text: { content: responsibleRole } }] },
          'Срок исполнения': { date: { start: defaultDeadline(finalSeverity) } }
        }
      })
    });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create problem' });
  }
});

// ─── ЧЕК-ЛИСТ СМЕНЫ (админ) ─────────────────────────

app.post('/api/staff/checklist-complete', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const { type, items } = req.body; // type: 'Открытие' | 'Закрытие'
  const employee = req.employee; // теперь известно кто именно заполнил, из PIN

  const time = venueTimeStr();
  const itemsList = (items || []).map(i => `✓ ${i}`).join('\n');

  await sendTelegramMessage(
    ADMIN_CHAT_ID,
    `📋 Чек-лист «${employee.role} · ${type}» выполнен — ${employee.name} — ${time}\n\n${itemsList}`
  );
  res.json({ ok: true });
});

// ─── ПОИСК ГОСТЯ ───────────────────────────────────

app.get('/api/staff/search', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const name = req.query.name;
  if (!name) return res.status(400).json({ error: 'name required' });

  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_GUESTS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ filter: { property: 'Имя Гостя', title: { contains: name } } })
    });
    const data = await r.json();
    const results = (data.results || []).map(g => ({
      id: g.id,
      name: g.properties['Имя Гостя']?.title?.[0]?.plain_text || '',
      phone: g.properties['Телефон']?.phone_number || ''
    }));
    res.json(results);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// ─── ПРОВЕРКА ОБЩЕЙ БАЗЫ (гостевой мини-апп) ────────
// Используется когда в "Карточке Гостя" никого не нашли — вдруг человек уже бронировал через эп

app.get('/api/staff/check-general', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const name = req.query.name;
  if (!name) return res.status(400).json({ error: 'name required' });

  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_GENERAL_GUESTS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ filter: { property: 'Имя', title: { contains: name } } })
    });
    const data = await r.json();
    const results = (data.results || []).map(g => ({
      name: g.properties['Имя']?.title?.[0]?.plain_text || '',
      phone: g.properties['Телефон']?.phone_number || '',
      bookingsCount: g.properties['Количество броней']?.number || 0,
      source: g.properties['Источник']?.select?.name || ''
    }));
    res.json(results);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Check failed' });
  }
});

// ─── ПОИСК ПО ТЕЛЕФОНУ (сразу по обеим базам) ──────
// Надёжнее поиска по имени — имя гость мог указать неточно, а номер уникален

app.get('/api/staff/search-by-phone', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const rawPhone = req.query.phone;
  if (!rawPhone) return res.status(400).json({ error: 'phone required' });
  const phone = normalizePhone(rawPhone);

  try {
    // 1. Ищем в "Карточке Гостя" — если найден, это самое ценное совпадение
    const cardRes = await fetch(`https://api.notion.com/v1/databases/${NOTION_GUESTS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ filter: { property: 'Телефон', phone_number: { equals: phone } } })
    });
    const cardData = await cardRes.json();
    const cardMatch = cardData.results?.[0];

    if (cardMatch) {
      return res.json({
        inCardDb: true,
        id: cardMatch.id,
        name: cardMatch.properties['Имя Гостя']?.title?.[0]?.plain_text || ''
      });
    }

    // 2. Не найден в карточках — проверяем общую базу (брони через мини-апп)
    const genRes = await fetch(`https://api.notion.com/v1/databases/${NOTION_GENERAL_GUESTS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ filter: { property: 'Телефон', phone_number: { equals: phone } } })
    });
    const genData = await genRes.json();
    const genMatch = genData.results?.[0];

    if (genMatch) {
      return res.json({
        inCardDb: false,
        inGeneralDb: true,
        name: genMatch.properties['Имя']?.title?.[0]?.plain_text || '',
        phone: genMatch.properties['Телефон']?.phone_number || phone,
        bookingsCount: genMatch.properties['Количество броней']?.number || 0
      });
    }

    res.json({ inCardDb: false, inGeneralDb: false });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Search by phone failed' });
  }
});

// Notion не умеет фильтровать телефон "оканчивается на" — выгружаем всех с телефоном
// постранично и сравниваем последние цифры на сервере
async function fetchAllWithPhone(dbId) {
  let all = [];
  let cursor = undefined;
  do {
    const body = {
      filter: { property: 'Телефон', phone_number: { is_not_empty: true } },
      page_size: 100
    };
    if (cursor) body.start_cursor = cursor;
    const r = await fetch(`https://api.notion.com/v1/databases/${dbId}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify(body)
    });
    const data = await r.json();
    all = all.concat(data.results || []);
    cursor = data.has_more ? data.next_cursor : undefined;
  } while (cursor && all.length < 500); // разумный предел на всякий случай
  return all;
}

// ─── ПОИСК ПО ПОСЛЕДНИМ 4 ЦИФРАМ (сразу по обеим базам) ──

app.get('/api/staff/search-last4', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const digits = (req.query.digits || '').replace(/\D/g, '');
  if (digits.length !== 4) return res.status(400).json({ error: 'нужно ровно 4 цифры' });

  try {
    const [cardGuests, generalGuests] = await Promise.all([
      fetchAllWithPhone(NOTION_GUESTS_DB_ID),
      fetchAllWithPhone(NOTION_GENERAL_GUESTS_DB_ID)
    ]);

    const matches = [];

    for (const g of cardGuests) {
      const phone = g.properties['Телефон']?.phone_number || '';
      if (phone.replace(/\D/g, '').endsWith(digits)) {
        matches.push({
          source: 'card',
          id: g.id,
          name: g.properties['Имя Гостя']?.title?.[0]?.plain_text || '',
          phone
        });
      }
    }

    for (const g of generalGuests) {
      const phone = g.properties['Телефон']?.phone_number || '';
      if (phone.replace(/\D/g, '').endsWith(digits)) {
        // Не дублируем если уже есть карточка с таким же номером
        const alreadyInCard = matches.some(m => m.source === 'card' && m.phone.replace(/\D/g, '') === phone.replace(/\D/g, ''));
        if (!alreadyInCard) {
          matches.push({
            source: 'general',
            name: g.properties['Имя']?.title?.[0]?.plain_text || '',
            phone,
            bookingsCount: g.properties['Количество броней']?.number || 0
          });
        }
      }
    }

    res.json(matches);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// ─── КАРТОЧКА ГОСТЯ + ВИЗИТЫ ───────────────────────

app.get('/api/staff/guest/:id', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try {
    const guestRes = await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, { headers: NOTION_HEADERS });
    const guest = await guestRes.json();
    const props = guest.properties;

    const visitsRes = await fetch(`https://api.notion.com/v1/databases/${NOTION_VISITS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: { property: 'Гость', relation: { contains: req.params.id } },
        sorts: [{ property: 'Дата', direction: 'descending' }],
        page_size: 5
      })
    });
    const visitsData = await visitsRes.json();
    const visits = (visitsData.results || []).map(v => {
      const vp = v.properties;
      return {
        date: vp['Дата']?.date?.start || '',
        hookah: vp['Кальян']?.rich_text?.[0]?.plain_text || '',
        notes: vp['Заметки']?.rich_text?.[0]?.plain_text || ''
      };
    });

    res.json({
      id: guest.id,
      name: props['Имя Гостя']?.title?.[0]?.plain_text || '',
      status: props['Частота визитов']?.select?.name || '',
      birthday: props['Дата рождения']?.date?.start || null,
      phone: props['Телефон']?.phone_number || '',
      important: props['Что важно для гостя']?.rich_text?.[0]?.plain_text || '',
      visits
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch guest' });
  }
});

// ─── РЕДАКТИРОВАНИЕ КАРТОЧКИ ───────────────────────

app.patch('/api/staff/guest/:id', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const { field, value } = req.body;

  const properties = {};
  if (field === 'status') properties['Частота визитов'] = { select: { name: value } };
  else if (field === 'birthday') properties['Дата рождения'] = { date: { start: value } };
  else if (field === 'phone') properties['Телефон'] = { phone_number: value };
  else if (field === 'important') properties['Что важно для гостя'] = { rich_text: [{ text: { content: value } }] };
  else return res.status(400).json({ error: 'unknown field' });

  try {
    await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, {
      method: 'PATCH',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ properties })
    });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Update failed' });
  }
});

// ─── НОВЫЙ ГОСТЬ ────────────────────────────────────

app.post('/api/staff/guest', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const { name, status, birthday, phone, important } = req.body;
  if (!name || !status) return res.status(400).json({ error: 'name and status required' });

  const properties = {
    'Имя Гостя': { title: [{ text: { content: name } }] },
    'Частота визитов': { select: { name: status } },
    'Что важно для гостя': { rich_text: [{ text: { content: important || '' } }] }
  };
  if (birthday) properties['Дата рождения'] = { date: { start: birthday } };
  if (phone) properties['Телефон'] = { phone_number: phone };

  try {
    const r = await fetch('https://api.notion.com/v1/pages', {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ parent: { database_id: NOTION_GUESTS_DB_ID }, properties })
    });
    const created = await r.json();

    // Дублируем контакт в общую базу гостей — чтобы она была полным списком, а не только "кто бронировал через эп"
    if (phone) {
      const normPhone = normalizePhone(phone);
      try {
        const checkRes = await fetch(`https://api.notion.com/v1/databases/${NOTION_GENERAL_GUESTS_DB_ID}/query`, {
          method: 'POST',
          headers: NOTION_HEADERS,
          body: JSON.stringify({ filter: { property: 'Телефон', phone_number: { equals: normPhone } } })
        });
        const checkData = await checkRes.json();

        if (!checkData.results?.length) {
          const genProps = {
            'Имя': { title: [{ text: { content: name } }] },
            'Телефон': { phone_number: normPhone },
            'Источник': { select: { name: 'Персонал' } },
            'Дата первого контакта': { date: { start: venueDateStr() } },
            'Количество броней': { number: 0 },
            'Перенесён в Карточку Гостя': { checkbox: true }
          };
          if (birthday) genProps['Дата рождения'] = { date: { start: birthday } };

          await fetch('https://api.notion.com/v1/pages', {
            method: 'POST',
            headers: NOTION_HEADERS,
            body: JSON.stringify({ parent: { database_id: NOTION_GENERAL_GUESTS_DB_ID }, properties: genProps })
          });
        } else {
          // Уже был в общей базе (например бронировал раньше) — просто отмечаем что теперь у него есть карточка
          await fetch(`https://api.notion.com/v1/pages/${checkData.results[0].id}`, {
            method: 'PATCH',
            headers: NOTION_HEADERS,
            body: JSON.stringify({ properties: { 'Перенесён в Карточку Гостя': { checkbox: true } } })
          });
        }
      } catch (syncError) {
        console.error('Sync to general DB failed (non-fatal):', syncError);
      }
    }

    res.json({ ok: true, id: created.id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create guest' });
  }
});

// ─── ДОБАВИТЬ / ДОПОЛНИТЬ ВИЗИТ ─────────────────────

async function cleanupOldVisits(guestId, keep = 5) {
  const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_VISITS_DB_ID}/query`, {
    method: 'POST',
    headers: NOTION_HEADERS,
    body: JSON.stringify({
      filter: { property: 'Гость', relation: { contains: guestId } },
      sorts: [{ property: 'Дата', direction: 'descending' }],
      page_size: 100
    })
  });
  const data = await r.json();
  const visits = data.results || [];
  if (visits.length > keep) {
    for (const old of visits.slice(keep)) {
      await fetch(`https://api.notion.com/v1/pages/${old.id}`, {
        method: 'PATCH',
        headers: NOTION_HEADERS,
        body: JSON.stringify({ archived: true })
      });
    }
  }
}

app.post('/api/staff/visit', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const { guestId, guestName, hookah, notes } = req.body;
  if (!guestId || !hookah) return res.status(400).json({ error: 'guestId and hookah required' });

  const today = venueDateStr();

  try {
    const existingRes = await fetch(`https://api.notion.com/v1/databases/${NOTION_VISITS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: {
          and: [
            { property: 'Гость', relation: { contains: guestId } },
            { property: 'Дата', date: { equals: today } }
          ]
        }
      })
    });
    const existingData = await existingRes.json();
    const existing = existingData.results?.[0];

    if (existing) {
      const existingNotes = existing.properties['Заметки']?.rich_text?.[0]?.plain_text || '';
      const combinedNotes = notes ? (existingNotes ? `${existingNotes} / ${notes}` : notes) : existingNotes;
      await fetch(`https://api.notion.com/v1/pages/${existing.id}`, {
        method: 'PATCH',
        headers: NOTION_HEADERS,
        body: JSON.stringify({
          properties: {
            'Кальян': { rich_text: [{ text: { content: hookah } }] },
            'Заметки': { rich_text: [{ text: { content: combinedNotes } }] }
          }
        })
      });
    } else {
      await fetch('https://api.notion.com/v1/pages', {
        method: 'POST',
        headers: NOTION_HEADERS,
        body: JSON.stringify({
          parent: { database_id: NOTION_VISITS_DB_ID },
          properties: {
            'Визит': { title: [{ text: { content: `${guestName || 'Гость'} — ${today}` } }] },
            'Гость': { relation: [{ id: guestId }] },
            'Дата': { date: { start: today } },
            'Кальян': { rich_text: [{ text: { content: hookah } }] },
            'Заметки': { rich_text: [{ text: { content: notes || '' } }] }
          }
        })
      });
      await cleanupOldVisits(guestId, 5);
    }

    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to save visit' });
  }
});

// ─── TELEGRAM WEBHOOK (бот для сотрудников) ────────

const WELCOME_TEXT =
  'Карточки гостей и визиты На Крыше.\n' +
  'Нажимай кнопку «Открыть», чтобы найти гостя, посмотреть карточку или добавить визит.';

const ENPS_WELCOME_TEXT =
  'Оцени нас — анонимно, займёт минуту.\n' +
  'Нажимай кнопку «Открыть», чтобы пройти опрос.';

app.post('/telegram-webhook', async (req, res) => {
  const update = req.body;
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

function defaultDeadline(severity) {
  const days = severity === 'Высокая' ? 3 : 7;
  const d = new Date();
  d.setDate(d.getDate() + days);
  return venueDateStr(d);
}

// Список проблем — теперь доступен всем сотрудникам (не только админу), чтобы
// ответственный по категории тоже видел и мог взять в работу свою проблему
app.get('/api/staff/problems', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_PROBLEMS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: { or: [
          { property: 'Статус', select: { equals: 'Задачи' } },
          { property: 'Статус', select: { equals: 'В работе' } }
        ]},
        sorts: [{ property: 'Дата отзыва', direction: 'descending' }]
      })
    });
    const data = await r.json();
    const problems = (data.results || []).map(p => {
      const props = p.properties;
      return {
        id: p.id,
        category: props['Категория']?.select?.name || '',
        score: props['Оценка гостя']?.number ?? null,
        comment: props['Комментарий гостя']?.rich_text?.[0]?.plain_text || '',
        responsible: props['Ответственный']?.rich_text?.[0]?.plain_text || '',
        deadline: props['Срок исполнения']?.date?.start || '',
        status: props['Статус']?.select?.name || '',
        severity: props['Критичность']?.select?.name || '',
        rootCause: props['Корневая причина']?.rich_text?.[0]?.plain_text || ''
      };
    });
    res.json(problems);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch problems' });
  }
});

// Перевод "Задачи" → "В работе" — обязательно с коренной причиной.
// Разрешено только ответственному по категории (по его роли) или администратору.
app.post('/api/staff/problem/:id/take', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const rootCause = (req.body?.rootCause || '').trim();
  const deadline = (req.body?.deadline || '').trim();
  if (!rootCause) return res.status(400).json({ error: 'Нужно указать коренную причину, прежде чем взять в работу' });
  if (!deadline) return res.status(400).json({ error: 'Нужно указать срок исполнения, прежде чем взять в работу' });

  try {
    const pageRes = await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, { headers: NOTION_HEADERS });
    const page = await pageRes.json();
    const responsible = page.properties['Ответственный']?.rich_text?.[0]?.plain_text || '';
    const employee = req.employee;

    if (employee.role !== 'Администратор' && employee.role !== responsible) {
      return res.status(403).json({ error: `Взять в работу может только «${responsible}» или администратор` });
    }

    await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, {
      method: 'PATCH',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        properties: {
          'Статус': { select: { name: 'В работе' } },
          'Корневая причина': { rich_text: [{ text: { content: rootCause } }] },
          'Срок исполнения': { date: { start: deadline } }
        }
      })
    });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update problem' });
  }
});

// Перевод "В работе" → "Решена" — та же проверка прав
app.post('/api/staff/problem/:id/resolve', async (req, res) => {
  if (!(await checkPin(req, res))) return;

  try {
    const pageRes = await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, { headers: NOTION_HEADERS });
    const page = await pageRes.json();
    const responsible = page.properties['Ответственный']?.rich_text?.[0]?.plain_text || '';
    const employee = req.employee;

    if (employee.role !== 'Администратор' && employee.role !== responsible) {
      return res.status(403).json({ error: `Закрыть может только «${responsible}» или администратор` });
    }

    await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, {
      method: 'PATCH',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ properties: { 'Статус': { select: { name: 'Решена' } } } })
    });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to resolve problem' });
  }
});

// Назначить конкретного ответственного по роли — только администратор
app.post('/api/staff/problem/:id/reassign', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  const role = (req.body?.role || '').trim();
  const deadline = (req.body?.deadline || '').trim();
  if (!ASSIGNABLE_ROLES.includes(role)) {
    return res.status(400).json({ error: 'Неизвестная роль' });
  }

  const properties = { 'Ответственный': { rich_text: [{ text: { content: role } }] } };
  if (deadline) properties['Срок исполнения'] = { date: { start: deadline } };

  try {
    await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, {
      method: 'PATCH',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ properties })
    });
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

  try {
    const today = venueDateStr();
    await fetch('https://api.notion.com/v1/pages', {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        parent: { database_id: NOTION_ENPS_DB_ID },
        properties: {
          'Запись': { title: [{ text: { content: `eNPS — ${today}` } }] },
          'Дата': { date: { start: today } },
          'Оценка': { number: score },
          'Что нравится': { rich_text: [{ text: { content: liked } }] },
          'Что улучшить': { rich_text: [{ text: { content: improve } }] }
        }
      })
    });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to save eNPS review' });
  }
});


app.get('/api/admin/problems', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_PROBLEMS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: { or: [
          { property: 'Статус', select: { equals: 'Задачи' } },
          { property: 'Статус', select: { equals: 'В работе' } }
        ]},
        sorts: [{ property: 'Дата отзыва', direction: 'descending' }]
      })
    });
    const data = await r.json();
    const problems = (data.results || []).map(p => {
      const props = p.properties;
      return {
        id: p.id,
        category: props['Категория']?.select?.name || '',
        score: props['Оценка гостя']?.number ?? null,
        comment: props['Комментарий гостя']?.rich_text?.[0]?.plain_text || '',
        responsible: props['Ответственный']?.rich_text?.[0]?.plain_text || '',
        deadline: props['Срок исполнения']?.date?.start || '',
        status: props['Статус']?.select?.name || ''
      };
    });
    res.json(problems);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch problems' });
  }
});

// ─── АДМИН: МЕРОПРИЯТИЯ (просмотр + добавление) ────

app.get('/api/admin/events', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  try {
    const today = venueDateStr();
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_EVENTS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: { property: 'Дата', date: { on_or_after: today } },
        sorts: [{ property: 'Дата', direction: 'ascending' }]
      })
    });
    const data = await r.json();
    const events = (data.results || []).map(e => ({
      id: e.id,
      name: e.properties['Название']?.title?.[0]?.plain_text || '',
      format: e.properties['Формат']?.select?.name || '',
      date: e.properties['Дата']?.date?.start || '',
      description: e.properties['Описание']?.rich_text?.[0]?.plain_text || ''
    }));
    res.json(events);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

app.post('/api/admin/events', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  const { name, format, date, description } = req.body;
  if (!name || !format || !date) return res.status(400).json({ error: 'name, format and date required' });

  try {
    const properties = {
      'Название': { title: [{ text: { content: name } }] },
      'Формат': { select: { name: format } },
      'Дата': { date: { start: date } }
    };
    if (description) properties['Описание'] = { rich_text: [{ text: { content: description } }] };

    await fetch('https://api.notion.com/v1/pages', {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ parent: { database_id: NOTION_EVENTS_DB_ID }, properties })
    });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create event' });
  }
});

// Редактировать мероприятие — чтобы никто не заходил в Notion, всё через приложение
app.patch('/api/admin/events/:id', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  const { name, format, date, description } = req.body;

  const properties = {};
  if (name !== undefined) properties['Название'] = { title: [{ text: { content: name } }] };
  if (format !== undefined) properties['Формат'] = { select: { name: format } };
  if (date !== undefined) properties['Дата'] = { date: { start: date } };
  if (description !== undefined) properties['Описание'] = { rich_text: [{ text: { content: description } }] };

  if (!Object.keys(properties).length) return res.status(400).json({ error: 'Нечего обновлять' });

  try {
    await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, {
      method: 'PATCH',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ properties })
    });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update event' });
  }
});

// Удалить мероприятие (архивируем в Notion — это их аналог удаления)
app.delete('/api/admin/events/:id', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  try {
    await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, {
      method: 'PATCH',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ archived: true })
    });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete event' });
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
  if (!(await checkPin(req, res))) return;
  const from = req.query.from;
  const to = req.query.to;
  if (!from || !to) return res.status(400).json({ error: 'from and to required' });

  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_SCHEDULE_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: {
          and: [
            { property: 'Дата', date: { on_or_after: from } },
            { property: 'Дата', date: { on_or_before: to } }
          ]
        },
        sorts: [{ property: 'Дата', direction: 'ascending' }]
      })
    });
    const data = await r.json();
    const shifts = (data.results || []).map(p => {
      const props = p.properties;
      return {
        id: p.id,
        employeeId: props['Сотрудник']?.relation?.[0]?.id || null,
        date: props['Дата']?.date?.start || '',
        status: props['Статус']?.select?.name || 'Работает',
        time: props['Время']?.rich_text?.[0]?.plain_text || '',
        note: props['Заметка']?.rich_text?.[0]?.plain_text || ''
      };
    });
    res.json(shifts);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch schedule' });
  }
});

// Создать/обновить смену — только администратор. Один сотрудник + одна дата = одна
// запись, при повторном сохранении просто обновляем её, а не плодим дубли.
app.post('/api/admin/schedule', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  const { employeeId, date, status, time, note } = req.body;
  if (!employeeId || !date) return res.status(400).json({ error: 'employeeId and date required' });

  await ensureEmployeesFresh();
  const employee = employeesCache.find(e => e.id === employeeId);
  const employeeName = employee?.name || 'Сотрудник';

  try {
    const properties = {
      'Запись': { title: [{ text: { content: `${employeeName} — ${date}` } }] },
      'Сотрудник': { relation: [{ id: employeeId }] },
      'Дата': { date: { start: date } },
      'Статус': { select: { name: status || 'Работает' } }
    };
    if (time !== undefined) properties['Время'] = { rich_text: time ? [{ text: { content: time } }] : [] };
    if (note !== undefined) properties['Заметка'] = { rich_text: note ? [{ text: { content: note } }] : [] };

    const existingRes = await fetch(`https://api.notion.com/v1/databases/${NOTION_SCHEDULE_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: {
          and: [
            { property: 'Дата', date: { equals: date } },
            { property: 'Сотрудник', relation: { contains: employeeId } }
          ]
        }
      })
    });
    const existingData = await existingRes.json();
    if (!existingRes.ok) {
      console.error('Notion query failed (schedule):', existingData);
      return res.status(502).json({ error: existingData?.message || 'Notion отклонил запрос — проверь доступ интеграции к базе "График смен"' });
    }
    const existing = existingData.results?.[0];

    if (existing) {
      const patchRes = await fetch(`https://api.notion.com/v1/pages/${existing.id}`, {
        method: 'PATCH',
        headers: NOTION_HEADERS,
        body: JSON.stringify({ properties })
      });
      const patchData = await patchRes.json();
      if (!patchRes.ok) {
        console.error('Notion update failed (schedule):', patchData);
        return res.status(502).json({ error: patchData?.message || 'Notion отклонил обновление смены' });
      }
      return res.json({ ok: true, id: existing.id });
    }

    const createRes = await fetch('https://api.notion.com/v1/pages', {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ parent: { database_id: NOTION_SCHEDULE_DB_ID }, properties })
    });
    const createData = await createRes.json();
    if (!createRes.ok) {
      console.error('Notion create failed (schedule):', createData);
      return res.status(502).json({ error: createData?.message || 'Notion отклонил создание смены — проверь доступ интеграции к базе "График смен"' });
    }
    res.json({ ok: true, id: createData.id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to save shift' });
  }
});

// Удалить смену (сбросить день сотрудника обратно в пустое состояние) — только администратор
app.delete('/api/admin/schedule/:id', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;
  try {
    const patchRes = await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, {
      method: 'PATCH',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ archived: true })
    });
    const patchData = await patchRes.json();
    if (!patchRes.ok) {
      console.error('Notion delete failed (schedule):', patchData);
      return res.status(502).json({ error: patchData?.message || 'Notion отклонил удаление смены' });
    }
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete shift' });
  }
});

// ─── СТОП-ЛИСТ (снятие позиций меню "В наличии") ────
// Один и тот же источник, что у гостя в приложении — снял здесь, гость уже
// не видит позицию в меню. Смотреть могут все, менять — только тот, чья категория.

// Полный список меню (включая недоступное) — видят все залогиненные сотрудники
app.get('/api/staff/menu', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  try {
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_MENU_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        sorts: [
          { property: 'Категория', direction: 'ascending' },
          { property: 'Подкатегория', direction: 'ascending' },
          { property: 'Порядок', direction: 'ascending' }
        ]
      })
    });
    const data = await r.json();
    if (!r.ok) {
      console.error('Notion menu query failed:', data);
      return res.status(502).json({ error: 'Не удалось загрузить меню' });
    }
    const items = (data.results || []).map(p => {
      const props = p.properties;
      return {
        id: p.id,
        name: props['Название']?.title?.[0]?.plain_text || '',
        category: props['Категория']?.select?.name || '',
        subcategory: props['Подкатегория']?.select?.name || '',
        price: props['Цена']?.number ?? null,
        available: props['В наличии']?.checkbox === true
      };
    });
    res.json(items);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

// Переключить "В наличии" одной позиции — проверяем роль строго по категории
// ЭТОЙ позиции в Notion (не по тому, что прислал клиент), чтобы права нельзя
// было обойти подменой запроса.
app.patch('/api/staff/menu/:id', async (req, res) => {
  if (!(await checkPin(req, res))) return;
  const { available } = req.body;
  if (typeof available !== 'boolean') return res.status(400).json({ error: 'available (boolean) required' });

  try {
    const pageRes = await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, { headers: NOTION_HEADERS });
    const page = await pageRes.json();
    if (!pageRes.ok) return res.status(404).json({ error: 'Позиция не найдена' });

    const category = page.properties?.['Категория']?.select?.name || '';
    if (!canEditMenuCategory(req.employee.role, category)) {
      return res.status(403).json({ error: `Эту категорию может менять только ${MENU_CATEGORY_EDIT_ROLE[category] || 'администратор'}` });
    }

    const patchRes = await fetch(`https://api.notion.com/v1/pages/${req.params.id}`, {
      method: 'PATCH',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ properties: { 'В наличии': { checkbox: available } } })
    });
    const patchData = await patchRes.json();
    if (!patchRes.ok) {
      console.error('Notion menu toggle failed:', patchData);
      return res.status(502).json({ error: 'Notion отклонил изменение' });
    }
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

// ─── АДМИН: СТАТИСТИКА (CSI/NPS, eNPS, визиты) ─────
// CSI/NPS теперь читаются из Notion "Отзывы CSI" (см. NOTION_REVIEWS_DB_ID выше).
// eNPS пока остаётся в Google-таблице — её мы не трогали.

const ENPS_SHEETS_ID = '1nKMCWGXsdQ-3KgMeFtPkIlmKlim4Ae6YFT-jEnZnLwY';

function parseCsv(text) {
  return text.trim().split('\n').map(line => {
    // простой CSV-парсер с поддержкой кавычек
    const cells = [];
    let cur = '', inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') inQuotes = !inQuotes;
      else if (ch === ',' && !inQuotes) { cells.push(cur); cur = ''; }
      else cur += ch;
    }
    cells.push(cur);
    return cells.map(c => c.trim());
  });
}

async function fetchSheetCsv(sheetId, sheetName) {
  const url = sheetName
    ? `https://docs.google.com/spreadsheets/d/${sheetId}/gviz/tq?tqx=out:csv&sheet=${encodeURIComponent(sheetName)}`
    : `https://docs.google.com/spreadsheets/d/${sheetId}/gviz/tq?tqx=out:csv`;
  const r = await fetch(url);
  if (!r.ok) return [];
  const text = await r.text();
  return parseCsv(text);
}

function isThisMonth(dateStr) {
  if (!dateStr) return false;
  // пробуем распознать DD.MM.YYYY или YYYY-MM-DD с временем
  let d = null;
  const dmy = dateStr.match(/(\d{1,2})\.(\d{1,2})\.(\d{4})/);
  const ymd = dateStr.match(/(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (dmy) d = new Date(+dmy[3], +dmy[2] - 1, +dmy[1]);
  else if (ymd) d = new Date(+ymd[1], +ymd[2] - 1, +ymd[3]);
  if (!d || isNaN(d)) return false;
  const now = new Date();
  return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
}

function avg(nums) {
  const valid = nums.filter(n => !isNaN(n));
  if (!valid.length) return null;
  return +(valid.reduce((a, b) => a + b, 0) / valid.length).toFixed(1);
}

app.get('/api/admin/stats', async (req, res) => {
  if (!(await checkAdminPin(req, res))) return;

  const result = {
    month: new Date().toLocaleDateString('ru-RU', { timeZone: VENUE_TZ, month: 'long', year: 'numeric' }),
    csi: null,
    enps: null,
    visits: null
  };

  // ── CSI + NPS гостей — теперь из Notion "Отзывы CSI" (раньше была Google-таблица) ──
  try {
    const monthStart = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}-01`;
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_REVIEWS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ filter: { property: 'Дата', date: { on_or_after: monthStart } } })
    });
    const data = await r.json();
    const reviews = data.results || [];

    if (reviews.length) {
      const col = (name) => reviews.map(p => p.properties[name]?.number).filter(n => typeof n === 'number');
      const nps = col('NPS');
      const promoters = nps.filter(n => n >= 9).length;
      const detractors = nps.filter(n => n <= 6).length;
      const npsScore = nps.length ? Math.round(((promoters - detractors) / nps.length) * 100) : null;

      result.csi = {
        count: reviews.length,
        vecher: avg(col('Вечер')),
        kalyan: avg(col('Кальян')),
        napitki: avg(col('Напитки')),
        eda: avg(col('Еда')),
        komanda: avg(col('Команда')),
        nps: npsScore
      };
    }
  } catch (e) { console.error('CSI fetch failed:', e); }

  // ── eNPS сотрудников — теперь из Notion "Отзывы eNPS" (анонимно, раньше была Google-таблица) ──
  try {
    const monthStart = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}-01`;
    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_ENPS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({ filter: { property: 'Дата', date: { on_or_after: monthStart } } })
    });
    const data = await r.json();
    const entries = data.results || [];

    if (entries.length) {
      const scores = entries.map(p => p.properties['Оценка']?.number).filter(n => typeof n === 'number');
      const promoters = scores.filter(n => n >= 9).length;
      const detractors = scores.filter(n => n <= 6).length;
      const enpsScore = scores.length ? Math.round(((promoters - detractors) / scores.length) * 100) : null;

      result.enps = {
        count: entries.length,
        score: enpsScore,
        promoters,
        passives: scores.length - promoters - detractors,
        detractors
      };
    }
  } catch (e) { console.error('eNPS fetch failed:', e); }

  // ── Визиты за месяц из Notion ──
  try {
    const now = new Date();
    const monthStart = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;

    const r = await fetch(`https://api.notion.com/v1/databases/${NOTION_VISITS_DB_ID}/query`, {
      method: 'POST',
      headers: NOTION_HEADERS,
      body: JSON.stringify({
        filter: { property: 'Дата', date: { on_or_after: monthStart } },
        page_size: 100
      })
    });
    const data = await r.json();
    const visits = data.results || [];

    const guestCounts = {};
    const hookahCounts = {};
    const weekHookahCounts = {};
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);

    for (const v of visits) {
      const guestRelId = v.properties['Гость']?.relation?.[0]?.id;
      if (guestRelId) guestCounts[guestRelId] = (guestCounts[guestRelId] || 0) + 1;
      const hookah = v.properties['Кальян']?.rich_text?.[0]?.plain_text;
      const visitDate = v.properties['Дата']?.date?.start;
      if (hookah) {
        hookahCounts[hookah] = (hookahCounts[hookah] || 0) + 1;
        if (visitDate && new Date(visitDate) >= weekAgo) {
          weekHookahCounts[hookah] = (weekHookahCounts[hookah] || 0) + 1;
        }
      }
    }

    const topHookah = Object.entries(hookahCounts).sort((a, b) => b[1] - a[1])[0];
    const weekTopHookahs = Object.entries(weekHookahCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([flavor, count]) => ({ flavor, count }));

    result.visits = {
      total: visits.length,
      uniqueGuests: Object.keys(guestCounts).length,
      topHookah: topHookah ? topHookah[0] : null,
      weekTopHookahs
    };
  } catch (e) { console.error('Visits stats failed:', e); }

  res.json(result);
});

app.get('/', (req, res) => {
  res.send('Staff Proxy for На Крыше is running ✅');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
