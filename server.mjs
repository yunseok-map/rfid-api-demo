js
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import pinoHttp from 'pino-http';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { totp } from 'otplib';
import { v4 as uuid } from 'uuid';

/* ========= 환경 ========= */
const PORT = process.env.PORT || 4000;
const ACCESS_SECRET = process.env.ACCESS_SECRET || 'dev-access';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'dev-refresh';
const DEMO_MODE = process.env.DEMO_MODE === '1';
const DEMO_API_KEY = process.env.DEMO_API_KEY || 'demo-123';
const OTP_REQUIRED = process.env.OTP_REQUIRED !== '0'; // 기본 ON

const SESSION_TTL_MS = { user: 24 * 60 * 60 * 1000, admin: 1 * 60 * 60 * 1000 };
const ACCESS_TTL_SEC = 10 * 60;

/* ========= 데모 저장소(실서비스: DB/Redis로 교체) ========= */
const OTP_VERIFIED = new Map();         // `${username}:${mode}` -> true
const REVOKED_REFRESH = new Set();      // refreshToken 블랙리스트
const IDEMP_STORE = new Map();          // idempotency 캐시

const USER_TOTP_SECRET = new Map([
  ['admin', 'JBSWY3DPEHPK3PXP'],
  ['user1', 'JBSWY3DPEHPK3PXP']
]);
const USERS = {
  admin: { id: 'U000', name: '관리자', role: 'admin', password: 'admin123' },
  user1: { id: 'U101', name: '홍길동', role: 'user',  password: 'user123'  }
};

/* ========= 유틸 ========= */
const issueAccess = (claims) => jwt.sign(claims, ACCESS_SECRET, { expiresIn: ACCESS_TTL_SEC });
const issueRefresh = ({ sub, name, role, mode, sessionExp, jti }) =>
  jwt.sign({ sub, name, role, mode, sessionExp, jti }, REFRESH_SECRET, {
    expiresIn: Math.ceil((sessionExp - Date.now()) / 1000)
  });
const verifyAccess = (t) => jwt.verify(t, ACCESS_SECRET);
const verifyRefresh = (t) => jwt.verify(t, REFRESH_SECRET);
const featuresByMode = (mode) => {
  const base = ['scan', 'asset_lookup', 'asset_update', 'assignee_lookup_basic'];
  if (mode === 'admin') base.push('user_assets_view', 'return_request');
  return base;
};
const idempKeyFrom = (req) => req.get('Idempotency-Key') || req.body?.idempotencyKey || null;

/* ========= RFID 어댑터(Mock) — 나중에 실제 브리지 REST로 교체 ========= */
const ASSETS = new Map([
  ['A-001', { ownerId: 'U101', type: '노트북', lastSeenAt: new Date().toISOString() }],
  ['A-002', { ownerId: 'U101', type: '모니터', lastSeenAt: new Date().toISOString() }]
]);

const rfidAdapter = {
  async resolveTag(rfidRaw) {
    if (rfidRaw === 'E2003412') return { managementNo: 'A-001', type: '노트북', lastOwner: ASSETS.get('A-001')?.ownerId };
    if (rfidRaw === 'E2009999') return { managementNo: 'A-002', type: '모니터', lastOwner: ASSETS.get('A-002')?.ownerId };
    return { managementNo: 'UNKNOWN', type: 'unknown', lastOwner: null };
  },
  async updateOwners(mNos, assigneeUserId) {
    const results = [];
    for (const mNo of mNos) {
      if (!ASSETS.has(mNo)) { results.push({ mNo, status: 'error', reason: 'not_found' }); continue; }
      ASSETS.get(mNo).ownerId = assigneeUserId;
      results.push({ mNo, status: 'updated' });
    }
    return results;
  },
  async verifyOwners(mNos, assigneeUserId) {
    const mismatches = [];
    for (const mNo of mNos) if (ASSETS.get(mNo)?.ownerId !== assigneeUserId) mismatches.push(mNo);
    return { ok: mismatches.length === 0, mismatches };
  },
  async findUserAssets(userId) {
    const list = [];
    for (const [mNo, v] of ASSETS.entries()) if (v.ownerId === userId) list.push({ mNo, ...v });
    return list;
  }
};

/* ========= 스키마 ========= */
const LoginSchema = z.object({
  username: z.string().min(2),
  password: z.string().min(3),
  otp: z.string().optional(),         // 최초 로그인에서만 요구
  mode: z.enum(['user', 'admin'])
});
const ResolveSchema = z.object({
  rfidRaw: z.string().min(3),
  idempotencyKey: z.string().optional()
});
const UpdateSchema = z.object({
  assigneeUserId: z.string().min(2),
  managementNos: z.array(z.string().min(2)).min(1),
  idempotencyKey: z.string().uuid()
});
const SearchSchema = z.object({ q: z.string().min(2) });
const ReturnReqSchema = z.object({
  items: z.array(z.object({ userId: z.string().min(2), mNo: z.string().min(2) })).min(1),
  idempotencyKey: z.string().uuid()
});

/* ========= 앱 부트 ========= */
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));
app.use(pinoHttp());
app.use(rateLimit({ windowMs: 30_000, max: 300 }));

// 데모 모드면 API 키 헤더로 간단 게이트 (인증 대체 아님)
if (DEMO_MODE) {
  app.use((req, res, next) => {
    const k = req.get('X-Api-Key');
    if (!k || k !== DEMO_API_KEY) return res.status(401).json({ ok:false, error:'invalid demo api key' });
    next();
  });
}

/* ========= 미들웨어 ========= */
function requireAuth(req, res, next) {
  const auth = req.get('authorization');
  if (!auth) return res.status(401).json({ ok:false, error:'unauthorized' });
  try {
    const token = auth.split(' ')[1];
    req.user = verifyAccess(token);
    if (Date.now() > req.user.sessionExp) return res.status(401).json({ ok:false, error:'session expired' });
    next();
  } catch {
    return res.status(401).json({ ok:false, error:'unauthorized' });
  }
}
function requireAdminMode(req, res, next) {
  if (req.user?.mode !== 'admin') return res.status(403).json({ ok:false, error:'admin mode only' });
  next();
}
function idempotency(handler) {
  return async (req, res, next) => {
    const key = idempKeyFrom(req);
    if (!key) return handler(req, res, next);
    const scope = `${req.user?.sub || 'anon'}:${req.method}:${req.path}:${key}`;
    if (IDEMP_STORE.has(scope)) {
      const prev = IDEMP_STORE.get(scope);
      return res.status(prev.status).json(prev.body);
    }
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      IDEMP_STORE.set(scope, { status: res.statusCode || 200, body });
      return originalJson(body);
    };
    return handler(req, res, next);
  };
}

/* ========= 라우트: 인증 ========= */
app.post('/auth/login', (req, res) => {
  const p = LoginSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok:false, error: p.error.flatten() });

  const { username, password, otp, mode } = p.data;
  const u = USERS[username];
  if (!u || u.password !== password) return res.status(401).json({ ok:false, error:'invalid credentials' });
  if (mode === 'admin' && u.role !== 'admin') return res.status(403).json({ ok:false, error:'not an admin account' });

  // 최초 로그인 시 OTP 요구 (환경변수로 끄기 가능)
  const key = `${username}:${mode}`;
  const needOtp = OTP_REQUIRED ? !OTP_VERIFIED.get(key) : false;
  if (needOtp) {
    const secret = USER_TOTP_SECRET.get(username);
    if (!secret || !otp || !totp.check(otp, secret))
      return res.status(401).json({ ok:false, error:'otp_required_or_invalid' });
    OTP_VERIFIED.set(key, true);
  }

  const sessionExp = Date.now() + SESSION_TTL_MS[mode];
  const claims = { sub: u.id, name: u.name, role: u.role, mode, sessionExp };
  const accessToken = issueAccess(claims);
  const refreshToken = issueRefresh({ ...claims, jti: uuid() });

  res.json({ ok:true, accessToken, refreshToken, user:{ id:u.id, name:u.name, role:u.role, mode }, sessionExp });
});

app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ ok:false, error:'missing refreshToken' });
  if (REVOKED_REFRESH.has(refreshToken)) return res.status(401).json({ ok:false, error:'revoked' });
  try {
    const c = verifyRefresh(refreshToken);
    if (Date.now() > c.sessionExp) return res.status(401).json({ ok:false, error:'session expired' });
    const accessToken = issueAccess({ sub: c.sub, name: c.name, role: c.role, mode: c.mode, sessionExp: c.sessionExp });
    res.json({ ok:true, accessToken, sessionExp: c.sessionExp });
  } catch {
    res.status(401).json({ ok:false, error:'invalid refresh' });
  }
});

app.post('/auth/logout', requireAuth, (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) REVOKED_REFRESH.add(refreshToken);
  res.json({ ok:true });
});

/* ========= 라우트: 권한/기능 ========= */
app.get('/me/permissions', requireAuth, (req, res) => {
  res.json({ ok:true, features: featuresByMode(req.user.mode) });
});

/* ========= 라우트: 공통(일반/관리자) ========= */
app.post('/assets/resolve', requireAuth, idempotency(async (req, res) => {
  const p = ResolveSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok:false, error: p.error.flatten() });
  const info = await rfidAdapter.resolveTag(p.data.rfidRaw);
  res.json({ ok:true, data: info, requestId: uuid() });
}));

app.post('/assets/update', requireAuth, idempotency(async (req, res) => {
  const p = UpdateSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok:false, error: p.error.flatten() });
  const { assigneeUserId, managementNos } = p.data;

  const results = await rfidAdapter.updateOwners(managementNos, assigneeUserId);
  const okList = results.filter(r => r.status === 'updated').map(r => r.mNo);
  const verify = await rfidAdapter.verifyOwners(okList, assigneeUserId);

  if (!verify.ok) for (const mNo of verify.mismatches) {
    const r = results.find(x => x.mNo === mNo);
    if (r) { r.status='error'; r.reason='verify_failed'; }
  }

  const allOk = results.every(r => r.status === 'updated');
  res.status(allOk ? 200 : 207).json({ ok: allOk, results, requestId: uuid() });
}));

// (공통) 대상자 간단 검색
app.get('/users/lookup-basic', requireAuth, (req, res) => {
  const p = SearchSchema.safeParse(req.query);
  if (!p.success) return res.status(400).json({ ok:false, error: p.error.flatten() });
  const { q } = p.data;
  const data = Object.values(USERS)
    .filter(u => u.name.includes(q) || u.id.includes(q))
    .map(u => ({ userId: u.id, name: u.name, empNo: u.id }));
  res.json({ ok:true, data });
});

/* ========= 라우트: 관리자 전용 ========= */
app.get('/admin/users/search', requireAuth, requireAdminMode, (req, res) => {
  const p = SearchSchema.safeParse(req.query);
  if (!p.success) return res.status(400).json({ ok:false, error: p.error.flatten() });
  const { q } = p.data;
  const data = Object.values(USERS)
    .filter(u => u.name.includes(q) || u.id.includes(q))
    .map(u => ({ userId: u.id, name: u.name, empNo: u.id, dept: u.role === 'admin' ? '관리' : '일반' }));
  res.json({ ok:true, data });
});

app.get('/admin/users/:userId/assets', requireAuth, requireAdminMode, async (req, res) => {
  const { userId } = req.params;
  const data = await rfidAdapter.findUserAssets(userId);
  res.json({ ok:true, data });
});

app.post('/admin/return-requests', requireAuth, requireAdminMode, idempotency(async (req, res) => {
  const p = ReturnReqSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok:false, error: p.error.flatten() });
  const { items } = p.data;
  const results = items.map(it => ({ ...it, status: 'queued' })); // 데모: 큐잉만
  res.json({ ok:true, results, requestId: uuid() });
}));

/* ========= 핸들러 ========= */
app.use((req, res) => res.status(404).json({ ok:false, error:'route_not_found' }));
app.use((err, req, res, _next) => { req.log?.error?.(err); res.status(500).json({ ok:false, error:'internal_error' }); });

/* ========= 시작 ========= */
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));