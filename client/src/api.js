import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Requests that change data must prove they come from this app by echoing the
// anti-CSRF token. A forged cross-site form cannot read this token or set this
// header, so the server rejects it.
const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes run before a session exists, so the server does not check them.
const CSRF_EXEMPT = ['/auth/login', '/auth/register']

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method) || CSRF_EXEMPT.includes(config.url)) return config

  // Fetch a fresh token each time: the token is bound to the current session,
  // which changes on login/logout.
  const { data } = await api.get('/csrf-token')
  config.headers.set('x-csrf-token', data.csrfToken)
  return config
})
