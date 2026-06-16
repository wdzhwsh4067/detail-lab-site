// DETAIL Lab — GitHub OAuth gatekeeper (Cloudflare Worker)
// Full-redirect variant of the Decap/netlify-cms OAuth provider pattern.
//
// Routes:
//   GET /auth      -> 302 to GitHub's authorize endpoint (sets CSRF state cookie)
//   GET /callback  -> verifies state, exchanges code for token, 302 to SITE_URL#access_token=...
//
// Secrets (set via `wrangler secret put`):  GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
// Vars (wrangler.toml):                     SITE_URL, SCOPE

const STATE_COOKIE = 'detail_oauth_state';

function randomState() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

function redirect(location, extraHeaders) {
  const headers = { Location: location };
  if (extraHeaders) Object.assign(headers, extraHeaders);
  return new Response(null, { status: 302, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const workerOrigin = url.origin;
    const siteUrl = env.SITE_URL || '/';
    const scope = env.SCOPE || 'repo';

    // ── GET /auth ───────────────────────────────────────────
    if (url.pathname === '/auth') {
      const state = randomState();
      const authorize = new URL('https://github.com/login/oauth/authorize');
      authorize.searchParams.set('client_id', env.GITHUB_CLIENT_ID || '');
      authorize.searchParams.set('redirect_uri', workerOrigin + '/callback');
      authorize.searchParams.set('scope', scope);
      authorize.searchParams.set('state', state);
      const cookie = `${STATE_COOKIE}=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
      return redirect(authorize.toString(), { 'Set-Cookie': cookie });
    }

    // ── GET /callback ───────────────────────────────────────
    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      const returnedState = url.searchParams.get('state');
      const cookies = parseCookies(request.headers.get('Cookie'));
      const expectedState = cookies[STATE_COOKIE];
      const clearCookie = `${STATE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

      if (!code) {
        return redirect(siteUrl + '#error=' + encodeURIComponent('missing_code'), { 'Set-Cookie': clearCookie });
      }
      if (!returnedState || !expectedState || returnedState !== expectedState) {
        return redirect(siteUrl + '#error=' + encodeURIComponent('state_mismatch'), { 'Set-Cookie': clearCookie });
      }

      try {
        const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({
            client_id: env.GITHUB_CLIENT_ID,
            client_secret: env.GITHUB_CLIENT_SECRET,
            code,
            redirect_uri: workerOrigin + '/callback',
          }),
        });
        const data = await tokenRes.json();
        if (data && data.access_token) {
          return redirect(siteUrl + '#access_token=' + encodeURIComponent(data.access_token), { 'Set-Cookie': clearCookie });
        }
        const msg = (data && (data.error_description || data.error)) || 'token_exchange_failed';
        return redirect(siteUrl + '#error=' + encodeURIComponent(msg), { 'Set-Cookie': clearCookie });
      } catch (e) {
        return redirect(siteUrl + '#error=' + encodeURIComponent('token_exchange_error'), { 'Set-Cookie': clearCookie });
      }
    }

    // ── Anything else ───────────────────────────────────────
    return new Response('DETAIL Lab OAuth gatekeeper. Endpoints: /auth, /callback', {
      status: 200,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  },
};
