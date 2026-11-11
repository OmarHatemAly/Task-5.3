import { doubleCsrf } from 'csrf-csrf';

// Routes that run before a session exists, so there is nothing to tie a token to.
const PRE_AUTH_ROUTES = ['/api/auth/login', '/api/auth/register'];

// Double-submit-cookie CSRF protection.
// The server hands out a random token (GET /api/csrf-token) and also stores a
// signed copy in a cookie. Every state-changing request must echo the token in
// the `x-csrf-token` header. A forged cross-site form can make the browser send
// the cookies, but it can neither read the token nor set a custom header, so it
// is rejected with 403.
export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  // Read lazily so the secret comes from the environment at request time.
  getSecret: () => process.env.CSRF_SECRET,
  // Bind each token to the logged-in session (the auth cookie), so a token
  // issued for one session is useless for another.
  getSessionIdentifier: (req) => req.cookies?.token || '',
  // A "__Host-" cookie (the library default) requires HTTPS; this app runs on
  // plain http://localhost in development.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  // GET, HEAD and OPTIONS are safe (they change nothing) and are ignored by default.
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // Login/register are exempt: no session exists yet.
  skipCsrfProtection: (req) => PRE_AUTH_ROUTES.includes(req.path)
});

// GET /api/csrf-token — the client calls this and sends the value back on writes.
export function sendCsrfToken(req, res) {
  res.json({ csrfToken: generateCsrfToken(req, res) });
}
