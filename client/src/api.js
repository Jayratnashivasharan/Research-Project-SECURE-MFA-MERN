import axios from 'axios';
export const deviceId = localStorage.device || (localStorage.device = 'web-' + Math.random().toString(36).slice(2, 10));
export const api = axios.create({ baseURL: '/api' });
let refreshing = null;
api.interceptors.request.use((c) => { if (localStorage.access) c.headers.Authorization = 'Bearer ' + localStorage.access; return c; });
api.interceptors.response.use((r) => r, async (err) => {
  const orig = err.config;
  if (err.response?.status === 401 && localStorage.refresh && !orig._retry) {
    orig._retry = true;
    refreshing = refreshing || api.post('/auth/refresh', { refreshToken: localStorage.refresh }).then((r) => { localStorage.access = r.data.accessToken; return r; }).catch(() => { localStorage.removeItem('access'); localStorage.removeItem('refresh'); });
    await refreshing; refreshing = null;
    if (localStorage.access) { orig.headers.Authorization = 'Bearer ' + localStorage.access; return api(orig); }
  }
  return Promise.reject(err);
});
