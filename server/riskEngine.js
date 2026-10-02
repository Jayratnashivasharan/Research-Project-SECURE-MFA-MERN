// AI risk-scoring engine for login attempts.
// Implemented as a weighted logistic model over behavioral features extracted from login history.
// This is a transparent, rule-weighted statistical model (logistic regression form), not a deep
// neural network — documented honestly rather than oversold as a black-box AI.
const WEIGHTS = { newDevice: 1.4, newIp: 1.1, recentFailures: 0.9, oddHour: 0.6, rapidVelocity: 1.6, bias: -2.2 };

function sigmoid(x) { return 1 / (1 + Math.exp(-x)); }

function extractFeatures(history, attempt) {
  const known = history.filter((h) => h.success);
  const knownDevices = new Set(known.map((h) => h.device));
  const knownIps = new Set(known.map((h) => h.ip));
  const now = new Date(attempt.ts || Date.now());
  const fifteenMinAgo = now.getTime() - 15 * 60 * 1000;
  const recentFailures = history.filter((h) => !h.success && new Date(h.ts).getTime() > fifteenMinAgo).length;
  const hour = now.getUTCHours();
  const oddHour = hour >= 1 && hour <= 5 ? 1 : 0;
  const lastAttempt = history[0];
  let rapidVelocity = 0;
  if (lastAttempt && lastAttempt.ip && lastAttempt.ip !== attempt.ip) {
    const gapMin = (now.getTime() - new Date(lastAttempt.ts).getTime()) / 60000;
    if (gapMin < 10) rapidVelocity = 1; // different IP within 10 minutes: flagged as "impossible travel" proxy
  }
  return {
    newDevice: knownDevices.size > 0 && !knownDevices.has(attempt.device) ? 1 : 0,
    newIp: knownIps.size > 0 && !knownIps.has(attempt.ip) ? 1 : 0,
    recentFailures: Math.min(recentFailures / 3, 1),
    oddHour,
    rapidVelocity,
  };
}

function scoreLogin(history, attempt) {
  const f = extractFeatures(history, attempt);
  const z = WEIGHTS.bias + WEIGHTS.newDevice * f.newDevice + WEIGHTS.newIp * f.newIp +
    WEIGHTS.recentFailures * f.recentFailures + WEIGHTS.oddHour * f.oddHour + WEIGHTS.rapidVelocity * f.rapidVelocity;
  const risk = sigmoid(z);
  let decision = 'ALLOW';
  if (risk >= 0.75) decision = 'BLOCK';
  else if (risk >= 0.4) decision = 'REQUIRE_MFA';
  const reasons = Object.entries(f).filter(([, v]) => v > 0).map(([k]) => ({
    newDevice: 'Unrecognized device fingerprint', newIp: 'Login from a new IP address',
    recentFailures: 'Multiple recent failed attempts', oddHour: 'Login at an unusual hour',
    rapidVelocity: 'Rapid location change between attempts',
  }[k]));
  return { risk: Math.round(risk * 1000) / 1000, decision, reasons, features: f };
}

module.exports = { scoreLogin, extractFeatures, sigmoid, WEIGHTS };
