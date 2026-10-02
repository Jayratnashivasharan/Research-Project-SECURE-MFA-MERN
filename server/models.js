const m = require('mongoose');
const User = m.model('User', new m.Schema({
  name: String, email: { type: String, unique: true, lowercase: true }, password: String,
  role: { type: String, enum: ['USER', 'ADMIN'], default: 'USER' },
  mfaEnabled: { type: Boolean, default: false }, mfaSecret: String,
  backupCodes: [{ code: String, used: { type: Boolean, default: false } }],
}, { timestamps: true }));

const LoginAttempt = m.model('LoginAttempt', new m.Schema({
  email: { type: String, index: true }, success: Boolean, device: String, ip: String,
  risk: Number, decision: String, reasons: [String], mfaUsed: { type: Boolean, default: false },
  ts: { type: Date, default: Date.now, index: true },
}));

module.exports = { User, LoginAttempt };
