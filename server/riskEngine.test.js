const test = require('node:test'), assert = require('node:assert');
const { scoreLogin } = require('./riskEngine');

test('known device and IP with no failures scores low risk and allows', () => {
  const history = [{ success: true, device: 'dev-A', ip: '1.1.1.1', ts: new Date(Date.now() - 3600e3).toISOString() }];
  const r = scoreLogin(history, { device: 'dev-A', ip: '1.1.1.1', ts: new Date().toISOString() });
  assert.equal(r.decision, 'ALLOW');
});

test('new device plus new IP plus recent failures triggers at least MFA', () => {
  const history = [
    { success: false, device: 'dev-A', ip: '1.1.1.1', ts: new Date(Date.now() - 60e3).toISOString() },
    { success: false, device: 'dev-A', ip: '1.1.1.1', ts: new Date(Date.now() - 120e3).toISOString() },
    { success: true, device: 'dev-A', ip: '1.1.1.1', ts: new Date(Date.now() - 86400e3).toISOString() },
  ];
  const r = scoreLogin(history, { device: 'dev-B', ip: '9.9.9.9', ts: new Date().toISOString() });
  assert.notEqual(r.decision, 'ALLOW');
  assert.ok(r.reasons.includes('Unrecognized device fingerprint'));
});

test('rapid IP velocity is flagged', () => {
  const history = [{ success: true, device: 'dev-A', ip: '1.1.1.1', ts: new Date(Date.now() - 2 * 60e3).toISOString() }];
  const r = scoreLogin(history, { device: 'dev-A', ip: '8.8.8.8', ts: new Date().toISOString() });
  assert.ok(r.reasons.includes('Rapid location change between attempts'));
});

test('empty history (first-ever login) does not false-flag new device/IP', () => {
  const r = scoreLogin([], { device: 'dev-A', ip: '1.1.1.1', ts: new Date().toISOString() });
  assert.equal(r.decision, 'ALLOW');
});
