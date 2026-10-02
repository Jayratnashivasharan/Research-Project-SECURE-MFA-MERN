require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const helmet = require('helmet'), cors = require('cors'), rate = require('express-rate-limit');
const speakeasy = require('speakeasy'), QRCode = require('qrcode');
const { User, LoginAttempt } = require('./models');
const { scoreLogin } = require('./riskEngine');

const SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret_change_me';
const app = express();
app.use(helmet(), cors({ origin: process.env.CLIENT_URL || 'http://localhost:5173' }), express.json({ limit: '100kb' }));
app.use('/api/auth', rate({ windowMs: 60000, max: 30, standardHeaders: true }));
app.use(rate({ windowMs: 60000, max: 300 }));

const wrap = (f) => (req, res, next) => f(req, res).catch(next);
const s = (v, n = 150) => String(v ?? '').slice(0, n);
const sign = (u, type = 'access') => jwt.sign({ id: String(u._id), role: u.role, type },
  type === 'access' ? SECRET : REFRESH_SECRET, { expiresIn: type === 'access' ? '15m' : '7d' });
const authed = (req, res, next) => {
  try {
    const p = jwt.verify((req.headers.authorization || '').slice(7), SECRET);
    if (p.type !== 'access') throw new Error('wrong token type');
    req.user = p; next();
  } catch { res.status(401).json({ error: 'Login required' }); }
};
const admin = (req, res, next) => (req.user?.role === 'ADMIN' ? next() : res.status(403).json({ error: 'Admin only' }));
const genBackupCodes = () => Array.from({ length: 8 }, () => ({ code: Math.random().toString(36).slice(2, 10).toUpperCase() }));

app.get('/api/health', (_q, res) => res.json({ backend: 'ok', mongo: mongoose.connection.readyState === 1 ? 'connected' : 'down', riskEngine: 'active' }));

// ---- Registration / Login (password step) ----
app.post('/api/auth/register', wrap(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!/^\S+@\S+\.\S+$/.test(s(email)) || s(password, 200).length < 8 || !s(name)) return res.status(400).json({ error: 'Valid name, email and 8+ char password required' });
  if (await User.findOne({ email: s(email).toLowerCase() })) return res.status(409).json({ error: 'Email already registered' });
  const u = await User.create({ name: s(name), email: s(email).toLowerCase(), password: await bcrypt.hash(s(password, 200), 10) });
  res.status(201).json({ id: u._id, name: u.name, email: u.email });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const email = s(req.body?.email).toLowerCase(), device = s(req.body?.device, 80) || 'unknown-device', ip = req.ip;
  const u = await User.findOne({ email });
  const history = await LoginAttempt.find({ email }).sort({ ts: -1 }).limit(20).lean();
  const risk = scoreLogin(history, { device, ip, ts: new Date().toISOString() });

  if (!u || !(await bcrypt.compare(s(req.body?.password, 200), u.password))) {
    await LoginAttempt.create({ email, success: false, device, ip, risk: risk.risk, decision: risk.decision, reasons: risk.reasons });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (risk.decision === 'BLOCK') {
    await LoginAttempt.create({ email, success: false, device, ip, risk: risk.risk, decision: risk.decision, reasons: risk.reasons });
    return res.status(423).json({ error: 'Login blocked: unusual activity detected on this account', risk });
  }
  const mustMfa = u.mfaEnabled || risk.decision === 'REQUIRE_MFA';
  if (mustMfa) {
    const stepToken = jwt.sign({ id: String(u._id), step: 'mfa', device, ip }, SECRET, { expiresIn: '5m' });
    return res.json({ mfaRequired: true, stepToken, risk, mfaEnrolled: u.mfaEnabled });
  }
  await LoginAttempt.create({ email, success: true, device, ip, risk: risk.risk, decision: risk.decision, reasons: risk.reasons });
  res.json({ accessToken: sign(u), refreshToken: sign(u, 'refresh'), user: { id: u._id, name: u.name, role: u.role, mfaEnabled: u.mfaEnabled } });
}));

app.post('/api/auth/mfa/verify', wrap(async (req, res) => {
  let payload;
  try { payload = jwt.verify(s(req.body?.stepToken, 500), SECRET); } catch { return res.status(401).json({ error: 'Step session expired, please log in again' }); }
  if (payload.step !== 'mfa') return res.status(400).json({ error: 'Invalid step token' });
  const u = await User.findById(payload.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const code = s(req.body?.code, 12).replace(/\s/g, '');
  let ok = false, usedBackup = false;
  if (u.mfaEnabled && u.mfaSecret) ok = speakeasy.totp.verify({ secret: u.mfaSecret, encoding: 'base32', token: code, window: 1 });
  if (!ok && u.backupCodes?.length) {
    const bc = u.backupCodes.find((c) => c.code === code.toUpperCase() && !c.used);
    if (bc) { ok = true; usedBackup = true; bc.used = true; await u.save(); }
  }
  // Risk-only step-up (no TOTP enrolled yet, flagged purely by the risk engine): accept password-confirmed session.
  if (!ok && !u.mfaEnabled) ok = true;
  if (!ok) {
    await LoginAttempt.create({ email: u.email, success: false, device: payload.device, ip: payload.ip, decision: 'MFA_FAILED' });
    return res.status(401).json({ error: 'Incorrect verification code' });
  }
  await LoginAttempt.create({ email: u.email, success: true, device: payload.device, ip: payload.ip, decision: 'MFA_OK', mfaUsed: true });
  res.json({ accessToken: sign(u), refreshToken: sign(u, 'refresh'), user: { id: u._id, name: u.name, role: u.role, mfaEnabled: u.mfaEnabled }, usedBackup });
}));

app.post('/api/auth/refresh', wrap(async (req, res) => {
  try {
    const p = jwt.verify(s(req.body?.refreshToken, 500), REFRESH_SECRET);
    if (p.type !== 'refresh') throw new Error('bad type');
    const u = await User.findById(p.id);
    if (!u) return res.status(401).json({ error: 'Invalid session' });
    res.json({ accessToken: sign(u) });
  } catch { res.status(401).json({ error: 'Session expired, please log in again' }); }
}));

app.get('/api/auth/me', authed, wrap(async (req, res) => res.json(await User.findById(req.user.id).select('-password -mfaSecret -backupCodes'))));

// ---- MFA enrollment ----
app.post('/api/mfa/setup', authed, wrap(async (req, res) => {
  const u = await User.findById(req.user.id);
  const secret = speakeasy.generateSecret({ name: `SecureMERN (${u.email})` });
  u.mfaSecret = secret.base32; await u.save();
  const qr = await QRCode.toDataURL(secret.otpauth_url);
  res.json({ qr, secret: secret.base32 });
}));
app.post('/api/mfa/activate', authed, wrap(async (req, res) => {
  const u = await User.findById(req.user.id);
  if (!u.mfaSecret) return res.status(400).json({ error: 'Run setup first' });
  const ok = speakeasy.totp.verify({ secret: u.mfaSecret, encoding: 'base32', token: s(req.body?.code, 12), window: 1 });
  if (!ok) return res.status(400).json({ error: 'Incorrect code, scan the QR again and try the current 6-digit code' });
  u.mfaEnabled = true; u.backupCodes = genBackupCodes(); await u.save();
  res.json({ enabled: true, backupCodes: u.backupCodes.map((c) => c.code) });
}));
app.post('/api/mfa/disable', authed, wrap(async (req, res) => {
  await User.findByIdAndUpdate(req.user.id, { mfaEnabled: false, mfaSecret: undefined, backupCodes: [] });
  res.json({ enabled: false });
}));

// ---- Security dashboard ----
app.get('/api/security/my-activity', authed, wrap(async (req, res) => {
  const u = await User.findById(req.user.id).select('email');
  const rows = await LoginAttempt.find({ email: u.email }).sort({ ts: -1 }).limit(25).lean();
  res.json({ rows });
}));
app.get('/api/security/overview', authed, admin, wrap(async (req, res) => {
  const [total, blocked, mfaChallenges, failed] = await Promise.all([
    LoginAttempt.countDocuments({}), LoginAttempt.countDocuments({ decision: 'BLOCK' }),
    LoginAttempt.countDocuments({ decision: { $in: ['REQUIRE_MFA', 'MFA_OK'] } }), LoginAttempt.countDocuments({ success: false }),
  ]);
  const recent = await LoginAttempt.find({}).sort({ ts: -1 }).limit(30).lean();
  res.json({ total, blocked, mfaChallenges, failed, recent });
}));

app.use((err, _q, res, _n) => { console.error(err); res.status(500).json({ error: 'Something went wrong' }); });
if (require.main === module) mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/mern_mfa_security')
  .then(() => app.listen(process.env.PORT || 5000, () => console.log('API on', process.env.PORT || 5000)))
  .catch((e) => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
module.exports = app;
