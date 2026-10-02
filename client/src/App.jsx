import { useEffect, useState } from 'react'; import { Routes, Route, Link, Navigate, useNavigate } from 'react-router-dom';
import { api, deviceId } from './api';

const fmt = (d) => new Date(d).toLocaleString();
const RiskBadge = ({ risk }) => { if (risk == null) return null; const pct = Math.round(risk * 100);
  const tone = risk >= 0.75 ? 'danger' : risk >= 0.4 ? 'warn' : 'ok';
  return <span className={'badge ' + tone}>{pct}% risk</span>; };

function Landing() {
  return (<main>
    <section className="hero">
      <h1>Login that thinks before it trusts.</h1>
      <p>SecureMERN pairs standard MFA with an AI risk engine that scores every login attempt in real time, by device, location pattern, and recent failures, and asks for a second factor only when something actually looks off.</p>
      <div className="bar"><Link to="/register"><button>Create an account</button></Link><Link to="/login"><button className="ghost">Sign in</button></Link></div>
    </section>
    <section className="grid3">
      <div className="card pad"><h3>Password + bcrypt</h3><p className="muted">Every password is hashed with bcrypt before it ever touches the database.</p></div>
      <div className="card pad"><h3>AI risk scoring</h3><p className="muted">A transparent, weighted logistic model scores device, IP, timing, and velocity on every attempt.</p></div>
      <div className="card pad"><h3>TOTP + backup codes</h3><p className="muted">Authenticator-app codes and one-time backup codes keep you in even if your phone is gone.</p></div>
    </section>
  </main>);
}

function Register() {
  const [f, setF] = useState({ name: '', email: '', password: '' }), [err, setErr] = useState(''), [ok, setOk] = useState(false), nav = useNavigate();
  const go = async (e) => { e.preventDefault(); setErr(''); try { await api.post('/auth/register', f); setOk(true); setTimeout(() => nav('/login'), 1200); }
    catch (x) { setErr(x.response?.data?.error || 'Registration failed'); } };
  return (<main className="narrow"><h2>Create an account</h2>
    <form onSubmit={go}>
      <input placeholder="Full name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required />
      <input type="email" placeholder="Email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required />
      <input type="password" placeholder="Password (8+ characters)" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required />
      {err && <p className="err">{err}</p>}{ok && <p className="ok">Account created. Redirecting to login…</p>}
      <button>Register</button>
    </form><p>Already have an account? <Link to="/login">Sign in</Link></p></main>);
}

function Login() {
  const [f, setF] = useState({ email: 'user@example.com', password: 'Demo@1234' }), [err, setErr] = useState(''), [step, setStep] = useState(null), [code, setCode] = useState(''), nav = useNavigate();
  const go = async (e) => { e.preventDefault(); setErr(''); try {
      const r = await api.post('/auth/login', { ...f, device: deviceId });
      if (r.data.mfaRequired) { setStep(r.data); return; }
      localStorage.access = r.data.accessToken; localStorage.refresh = r.data.refreshToken; nav('/dashboard'); location.reload();
    } catch (x) { setErr(x.response?.data?.error || 'Login failed'); } };
  const verify = async (e) => { e.preventDefault(); setErr(''); try {
      const r = await api.post('/auth/mfa/verify', { stepToken: step.stepToken, code });
      localStorage.access = r.data.accessToken; localStorage.refresh = r.data.refreshToken; nav('/dashboard'); location.reload();
    } catch (x) { setErr(x.response?.data?.error || 'Verification failed'); } };
  if (step) return (<main className="narrow"><h2>Verify it's you</h2>
    <p className="muted">{step.mfaEnrolled ? 'Enter the 6-digit code from your authenticator app, or a backup code.' : 'Our risk engine flagged this login as unusual. Confirm with the code below to continue.'}</p>
    <RiskBadge risk={step.risk?.risk} />
    {step.risk?.reasons?.length > 0 && <ul className="reasons">{step.risk.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
    <form onSubmit={verify}><input placeholder="6-digit code or backup code" value={code} onChange={(e) => setCode(e.target.value)} required />
      {err && <p className="err">{err}</p>}<button>Verify</button></form></main>);
  return (<main className="narrow"><h2>Sign in</h2><form onSubmit={go}>
    <input type="email" placeholder="Email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required />
    <input type="password" placeholder="Password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required />
    {err && <p className="err">{err}</p>}<button>Login</button></form>
    <p className="muted">Demo accounts: admin@example.com / user@example.com, password Demo@1234</p>
    <p>No account? <Link to="/register">Register</Link></p></main>);
}

function Dashboard() {
  const [me, setMe] = useState(null), [activity, setActivity] = useState([]), [err, setErr] = useState('');
  useEffect(() => { api.get('/auth/me').then((r) => setMe(r.data)).catch(() => setErr('Could not load profile.'));
    api.get('/security/my-activity').then((r) => setActivity(r.data.rows)).catch(() => {}); }, []);
  if (err) return <main><p className="err">{err}</p></main>;
  if (!me) return <main><p className="muted">Loading…</p></main>;
  return (<main><h2>Welcome, {me.name}</h2>
    <div className="grid2">
      <div className="card pad"><h3>Multi-factor authentication</h3>
        <p className="muted">Status: <b>{me.mfaEnabled ? 'Enabled' : 'Not enabled'}</b></p>
        <Link to="/mfa-setup"><button>{me.mfaEnabled ? 'Manage MFA' : 'Set up MFA'}</button></Link></div>
      <div className="card pad"><h3>Account</h3><p className="muted">{me.email}</p><p className="muted">Role: {me.role}</p></div>
    </div>
    <h3>Recent login activity</h3>
    <table><thead><tr><th>Time</th><th>Device</th><th>IP</th><th>Result</th><th>Risk</th></tr></thead>
      <tbody>{activity.map((a) => (<tr key={a._id}><td>{fmt(a.ts)}</td><td>{a.device}</td><td>{a.ip}</td>
        <td className={a.success ? 'ok' : 'err'}>{a.success ? 'Success' : a.decision}</td><td><RiskBadge risk={a.risk} /></td></tr>))}</tbody></table>
    {!activity.length && <p className="muted">No activity yet.</p>}</main>);
}

function MfaSetup() {
  const [qr, setQr] = useState(null), [code, setCode] = useState(''), [err, setErr] = useState(''), [codes, setCodes] = useState(null), [me, setMe] = useState(null);
  useEffect(() => { api.get('/auth/me').then((r) => setMe(r.data)); }, []);
  const start = async () => { setErr(''); try { const r = await api.post('/mfa/setup'); setQr(r.data.qr); } catch (x) { setErr(x.response?.data?.error || 'Could not start setup'); } };
  const activate = async (e) => { e.preventDefault(); setErr(''); try { const r = await api.post('/mfa/activate', { code }); setCodes(r.data.backupCodes); } catch (x) { setErr(x.response?.data?.error || 'Incorrect code'); } };
  const disable = async () => { await api.post('/mfa/disable'); location.reload(); };
  return (<main className="narrow"><h2>Multi-factor authentication</h2>
    {me?.mfaEnabled ? (<><p>MFA is currently <b>enabled</b> on your account.</p><button className="ghost" onClick={disable}>Disable MFA</button></>) : (<>
      {!qr && <button onClick={start}>Start setup</button>}
      {qr && !codes && (<><p className="muted">Scan this with Google Authenticator, Authy, or any TOTP app, then enter the 6-digit code.</p>
        <img src={qr} alt="MFA QR code" className="qr" />
        <form onSubmit={activate}><input placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value)} required />
          {err && <p className="err">{err}</p>}<button>Activate</button></form></>)}
      {codes && (<><p className="ok">MFA enabled. Save these one-time backup codes somewhere safe:</p>
        <ul className="codes">{codes.map((c) => <li key={c}>{c}</li>)}</ul></>)}</>)}</main>);
}

function AdminSecurity() {
  const [d, setD] = useState(null), [err, setErr] = useState('');
  useEffect(() => { api.get('/security/overview').then((r) => setD(r.data)).catch((e) => setErr(e.response?.status === 403 ? 'Admin access required.' : 'Failed to load.')); }, []);
  if (err) return <main><p className="err">{err}</p></main>; if (!d) return <main><p className="muted">Loading…</p></main>;
  return (<main><h2>Security overview</h2>
    <div className="grid4">
      <div className="stat"><b>{d.total}</b><span>Total attempts</span></div>
      <div className="stat"><b>{d.failed}</b><span>Failed logins</span></div>
      <div className="stat"><b>{d.mfaChallenges}</b><span>MFA challenges</span></div>
      <div className="stat"><b>{d.blocked}</b><span>Blocked by risk engine</span></div>
    </div>
    <h3>Recent attempts (all users)</h3>
    <table><thead><tr><th>Time</th><th>Email</th><th>Device</th><th>IP</th><th>Result</th><th>Risk</th></tr></thead>
      <tbody>{d.recent.map((a) => (<tr key={a._id}><td>{fmt(a.ts)}</td><td>{a.email}</td><td>{a.device}</td><td>{a.ip}</td>
        <td className={a.success ? 'ok' : 'err'}>{a.success ? 'Success' : a.decision}</td><td><RiskBadge risk={a.risk} /></td></tr>))}</tbody></table></main>);
}

export default function App() {
  const loggedIn = !!localStorage.access;
  const out = () => { localStorage.removeItem('access'); localStorage.removeItem('refresh'); location.href = '/'; };
  return (<><header><Link to="/" className="brand">🛡 SecureMERN</Link>
    <nav>{loggedIn ? (<><Link to="/dashboard">Dashboard</Link><Link to="/mfa-setup">MFA</Link><Link to="/admin/security">Admin</Link><a href="#" onClick={(e) => { e.preventDefault(); out(); }}>Logout</a></>)
      : (<><Link to="/login">Login</Link><Link to="/register">Register</Link></>)}</nav></header>
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/dashboard" element={loggedIn ? <Dashboard /> : <Navigate to="/login" />} />
      <Route path="/mfa-setup" element={loggedIn ? <MfaSetup /> : <Navigate to="/login" />} />
      <Route path="/admin/security" element={loggedIn ? <AdminSecurity /> : <Navigate to="/login" />} />
      <Route path="*" element={<main><p>Page not found.</p></main>} />
    </Routes></>);
}
