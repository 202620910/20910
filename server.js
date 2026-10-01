const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function loadEnvFile() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator < 1) continue;
    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

loadEnvFile();

const PORT = Number(process.env.PORT) || 3000;
const ALIGO_ENDPOINT = 'https://apis.aligo.in/send/';
const requestLimits = new Map();
const adminSessions = new Map();

function sendJson(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(body));
}

function getClientIp(req) {
  return req.socket.remoteAddress || 'unknown';
}

function withinDailyLimit(key, limit) {
  const day = new Date().toISOString().slice(0, 10);
  const record = requestLimits.get(key);
  if (!record || record.day !== day) {
    requestLimits.set(key, { day, count: 1 });
    return true;
  }
  if (record.count >= limit) return false;
  record.count += 1;
  return true;
}

function isSameOrigin(req) {
  const origin = req.headers.origin;
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const protocol = forwardedProto || (req.socket.encrypted ? 'https' : 'http');
  const expectedOrigin = process.env.APP_ORIGIN || `${protocol}://${req.headers.host}`;
  return Boolean(origin && origin.replace(/\/$/, '') === expectedOrigin.replace(/\/$/, ''));
}

async function readJson(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 8192) throw new Error('요청 내용이 너무 큽니다.');
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new Error('요청 형식이 올바르지 않습니다.');
  }
}

function secureTextEquals(input, expected) {
  const supplied = Buffer.from(String(input || ''));
  const configured = Buffer.from(String(expected || ''));
  return configured.length > 0 && supplied.length === configured.length && crypto.timingSafeEqual(supplied, configured);
}

async function handleAdminVerify(req, res) {
  if (!isSameOrigin(req)) return sendJson(res, 403, { error: '허용되지 않은 요청입니다.' });
  if (!withinDailyLimit(`admin:${getClientIp(req)}`, 20)) {
    return sendJson(res, 429, { error: '운영자 로그인 시도 횟수를 초과했습니다.' });
  }
  if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
    return sendJson(res, 503, { error: '서버 .env에 ADMIN_USERNAME과 ADMIN_PASSWORD를 설정해주세요.' });
  }

  let data;
  try {
    data = await readJson(req);
  } catch (error) {
    return sendJson(res, 400, { error: error.message });
  }
  const usernameMatches = secureTextEquals(data.username, process.env.ADMIN_USERNAME);
  const passwordMatches = secureTextEquals(data.password, process.env.ADMIN_PASSWORD);
  if (!usernameMatches || !passwordMatches) {
    return sendJson(res, 401, { error: '관리자 아이디 또는 비밀번호가 올바르지 않습니다.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, Date.now() + 8 * 60 * 60 * 1000);
  sendJson(res, 200, { token });
}

async function handleAdminValidate(req, res) {
  if (!isSameOrigin(req)) return sendJson(res, 403, { error: '허용되지 않은 요청입니다.' });
  let data;
  try {
    data = await readJson(req);
  } catch (error) {
    return sendJson(res, 400, { error: error.message });
  }
  const expiresAt = adminSessions.get(String(data.token || ''));
  if (!expiresAt || expiresAt <= Date.now()) {
    adminSessions.delete(String(data.token || ''));
    return sendJson(res, 401, { error: '운영자 로그인이 만료되었습니다.' });
  }
  sendJson(res, 200, { authorized: true });
}

function makeReservationTimes(date, slot) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('예약 날짜 형식이 올바르지 않습니다.');
  const match = /^(\d{2}):(\d{2})\s*~\s*(\d{2}):(\d{2})$/.exec(slot);
  if (!match) throw new Error('예약 시간 형식이 올바르지 않습니다.');
  const [year, month, day] = date.split('-').map(Number);
  const dateCheck = new Date(Date.UTC(year, month - 1, day));
  if (dateCheck.getUTCFullYear() !== year || dateCheck.getUTCMonth() !== month - 1 || dateCheck.getUTCDate() !== day) {
    throw new Error('예약 날짜가 올바르지 않습니다.');
  }
  const startHour = Number(match[1]);
  const startMinute = Number(match[2]);
  const endHour = Number(match[3]);
  const endMinute = Number(match[4]);
  if (startHour > 23 || startMinute > 59 || endHour > 23 || endMinute > 59 ||
      endHour * 60 + endMinute <= startHour * 60 + startMinute) {
    throw new Error('예약 시간이 올바르지 않습니다.');
  }

  const startsAt = new Date(`${date}T${match[1]}:${match[2]}:00+09:00`);
  if (Number.isNaN(startsAt.getTime()) || startsAt.getTime() <= Date.now()) {
    throw new Error('이미 시작했거나 올바르지 않은 예약 시간입니다.');
  }
  return { startsAt, reminderAt: new Date(startsAt.getTime() - 15 * 60 * 1000) };
}

function formatSeoulSchedule(date) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(date).reduce((result, part) => {
    result[part.type] = part.value;
    return result;
  }, {});
  return {
    rdate: `${parts.year}${parts.month}${parts.day}`,
    rtime: `${parts.hour}${parts.minute}`
  };
}

async function sendAligoSms({ phone, message, scheduledAt }) {
  const { ALIGO_API_KEY, ALIGO_USER_ID, ALIGO_SENDER } = process.env;
  if (!ALIGO_API_KEY || !ALIGO_USER_ID || !ALIGO_SENDER) {
    throw new Error('서버의 알리고 API 환경변수 설정이 필요합니다.');
  }

  const form = new URLSearchParams({
    key: ALIGO_API_KEY,
    user_id: ALIGO_USER_ID,
    sender: ALIGO_SENDER.replace(/\D/g, ''),
    receiver: phone,
    msg: message,
    msg_type: 'LMS',
    title: '체육시설 예약 알림'
  });
  if (scheduledAt) {
    const schedule = formatSeoulSchedule(scheduledAt);
    form.set('rdate', schedule.rdate);
    form.set('rtime', schedule.rtime);
  }

  const response = await fetch(ALIGO_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
    body: form,
    signal: AbortSignal.timeout(15000)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || Number(result.result_code) !== 1) {
    throw new Error(result.message || '알리고 문자 발송에 실패했습니다.');
  }
  return result;
}

async function handleReservationSms(req, res) {
  if (!isSameOrigin(req)) return sendJson(res, 403, { error: '허용되지 않은 요청입니다.' });
  if (!withinDailyLimit(`ip:${getClientIp(req)}`, 50)) {
    return sendJson(res, 429, { error: '오늘 문자 요청 한도를 초과했습니다.' });
  }

  let data;
  try {
    data = await readJson(req);
  } catch (error) {
    return sendJson(res, 400, { error: error.message });
  }

  const phone = String(data.phone || '').replace(/\D/g, '');
  const name = String(data.name || '').replace(/[\r\n<>]/g, '').trim().slice(0, 30);
  const facilityName = String(data.facilityName || '').replace(/[\r\n<>]/g, '').trim().slice(0, 50);
  const date = String(data.date || '');
  const slot = String(data.slot || '');
  if (!/^01[016789]\d{7,8}$/.test(phone) || !name || !facilityName) {
    return sendJson(res, 400, { error: '회원 정보 또는 전화번호가 올바르지 않습니다.' });
  }
  if (!withinDailyLimit(`phone:${phone}`, 10)) {
    return sendJson(res, 429, { error: '해당 번호의 오늘 문자 발송 한도를 초과했습니다.' });
  }

  let times;
  try {
    times = makeReservationTimes(date, slot);
  } catch (error) {
    return sendJson(res, 400, { error: error.message });
  }

  const confirmation = `[부산기계공고] ${name}님, ${date} ${slot} ${facilityName} 예약이 완료되었습니다.`;
  const reminder = `[부산기계공고] ${name}님, 15분 후 ${facilityName} 예약입니다. 예약 시간을 확인해주세요.`;
  const result = { confirmationSent: false, reminderScheduled: false, reminderSkipped: false };

  try {
    await sendAligoSms({ phone, message: confirmation });
    result.confirmationSent = true;
  } catch (error) {
    result.confirmationError = error.message;
  }

  if (times.reminderAt.getTime() > Date.now() + 2 * 60 * 1000) {
    try {
      await sendAligoSms({ phone, message: reminder, scheduledAt: times.reminderAt });
      result.reminderScheduled = true;
    } catch (error) {
      result.reminderError = error.message;
    }
  } else {
    result.reminderSkipped = true;
  }

  const status = result.confirmationSent || result.reminderScheduled ? 200 : 502;
  if (status !== 200) result.error = result.confirmationError || result.reminderError || '문자 발송에 실패했습니다.';
  return sendJson(res, status, result);
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/api/reservation-sms') {
    return handleReservationSms(req, res);
  }
  if (req.method === 'POST' && req.url === '/api/admin/verify') {
    return handleAdminVerify(req, res);
  }
  if (req.method === 'POST' && req.url === '/api/admin/validate') {
    return handleAdminValidate(req, res);
  }
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    const page = path.join(__dirname, 'index.html');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    });
    return fs.createReadStream(page).pipe(res);
  }
  sendJson(res, 404, { error: '요청한 경로를 찾을 수 없습니다.' });
});

server.listen(PORT, () => {
  console.log(`체육시설 예약 사이트가 http://localhost:${PORT} 에서 실행 중입니다.`);
});
