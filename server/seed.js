require('dotenv').config();
const mongoose = require('mongoose'), bcrypt = require('bcryptjs'); const { User, LoginAttempt } = require('./models');
(async () => {
  await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/mern_mfa_security');
  await Promise.all([User.deleteMany({}), LoginAttempt.deleteMany({})]);
  const pw = await bcrypt.hash('Demo@1234', 10);
  await User.create({ name: 'Admin', email: 'admin@example.com', password: pw, role: 'ADMIN' });
  await User.create({ name: 'Demo User', email: 'user@example.com', password: pw });
  const rows = [];
  for (let i = 0; i < 40; i++) {
    const ok = Math.random() > 0.25;
    rows.push({ email: i % 3 === 0 ? 'user@example.com' : `visitor${i}@example.com`, success: ok,
      device: ok ? 'dev-known' : 'dev-unknown-' + i, ip: ok ? '10.0.0.5' : `203.0.113.${i % 250}`,
      risk: ok ? Math.random() * 0.3 : 0.4 + Math.random() * 0.5, decision: ok ? 'ALLOW' : 'REQUIRE_MFA',
      ts: new Date(Date.now() - i * 3600e3) });
  }
  await LoginAttempt.insertMany(rows);
  console.log('Seeded. Logins: admin@example.com / user@example.com, password Demo@1234');
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
