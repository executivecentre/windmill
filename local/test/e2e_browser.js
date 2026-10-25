// TEST ONLY: real-browser check of the SPA sign-in and sign-out paths on the e2e project, which
// the stdlib driver cannot cover: they run client-side. Run through `local/test/e2e.sh browser`.
const { chromium } = require(process.env.PW_PATH)
const fs = require('fs')
const https = require('https')

const BASE = process.env.E2E_BASE
const MOCK_PORT = process.env.MOCK_PORT
const RUN = process.env.RUN_DIR
const SHOTS = process.env.RUN_DIR
const OID = '0e2e0000-0000-4000-8000-000000000b77'
const GROUP = '0e2e0000-0000-4000-8000-0000000000a1'
const mockCA = fs.readFileSync(`${RUN}/tls/ca.crt`)
let failed = 0
const check = (name, ok, detail = '') => {
	if (!ok) failed = 1
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  [${detail}]` : ''}`)
}
const mockCall = (method, path, body) =>
	new Promise((resolve, reject) => {
		const data = body ? JSON.stringify(body) : undefined
		const req = https.request(
			{ host: '127.0.0.1', port: MOCK_PORT, path, method, ca: mockCA, servername: 'mock-entra',
				headers: { Host: 'mock-entra:8443', ...(data ? { 'Content-Type': 'application/json' } : {}) } },
			(res) => { res.resume(); res.on('end', () => resolve(res.statusCode)) }
		)
		req.on('error', reject)
		if (data) req.write(data)
		req.end()
	})
const path = (u) => { const x = new URL(u); return (x.host + x.pathname).replace(/(login_link\/)[^/]+/, '$1***') }

;(async () => {
	await mockCall('PUT', `/_mock/users/${OID}`, { upn: 'pat@e2e.example.org', mail: 'pat@e2e.example.org',
		display_name: 'Pat', enabled: true, groups: [GROUP] })
	// Redirect targets bypass Playwright routing, so resolve mock-entra to 127.0.0.1 and forward
	// its port 8443 to the published mock port.
	const fwd = require('net').createServer((c) => {
		const up = require('net').connect(Number(MOCK_PORT), '127.0.0.1')
		c.pipe(up).pipe(c)
		c.on('error', () => up.destroy())
		up.on('error', () => c.destroy())
	})
	await new Promise((r) => fwd.listen(8443, '127.0.0.1', r))
	const browser = await chromium.launch({
		...(process.env.CHROME_EXE ? { executablePath: process.env.CHROME_EXE } : {}),
		args: ['--host-resolver-rules=MAP mock-entra 127.0.0.1']
	})
	const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
	const page = await ctx.newPage()
	const navs = []
	page.on('request', (r) => { if (r.isNavigationRequest() && r.frame() === page.mainFrame()) navs.push(r.url()) })
	const seen = (re) => navs.some((u) => re.test(u))

	// 1. Break-glass form still renders with ?local=1.
	await page.goto(`${BASE}/user/login?local=1`)
	await page.waitForLoadState('networkidle')
	check('/user/login?local=1 renders the password form', await page.locator('input[type=password]').count() > 0,
		path(page.url()))

	// 2. "/" without a session: the SPA's own client-side redirect must end at the gateway and sign in.
	await mockCall('POST', `/_mock/next/${OID}`)
	navs.length = 0
	await page.goto(`${BASE}/`)
	await page.waitForURL((u) => u.host === 'localhost:3443' && !u.pathname.startsWith('/sso') &&
		!u.pathname.startsWith('/api') && !u.pathname.startsWith('/user/login'), { timeout: 60000 })
	await page.waitForLoadState('networkidle')
	check('signed-out visit to / goes through /sso/login', seen(/\/sso\/login/), navs.map(path).join(' > '))
	check('…then the Entra authorize endpoint', seen(/mock-entra:8443\/.*\/oauth2\/v2\.0\/authorize/))
	check('…and back into Windmill signed in', (await page.context().cookies(BASE)).some((c) => c.name === 'token'),
		path(page.url()))
	await page.screenshot({ path: `${SHOTS}/1-signed-in.png` })

	// 3. Sign out from the user menu: must end the Entra session via /sso/logout.
	navs.length = 0
	// /user/workspaces offers "Log out", which calls the same logout() as the sidebar's "Sign out".
	await page.getByRole('button', { name: 'Log out', exact: true }).first().click({ timeout: 15000 })
	await page.waitForURL(/\/sso\/logged-out/, { timeout: 30000 })
	check('Sign out goes to /sso/logout', seen(/\/sso\/logout/), navs.map(path).join(' > '))
	check('…through the Entra end-session endpoint', seen(/mock-entra:8443\/.*logout/))
	check('…and the Windmill session cookie is gone',
		!(await page.context().cookies(BASE)).some((c) => c.name === 'token' && c.value))
	await page.screenshot({ path: `${SHOTS}/2-logged-out.png` })

	// 4. Expired session: an invalid token cookie on an app page must land on /sso/login with rd.
	await ctx.addCookies([{ name: 'token', value: 'expired-session-token', url: BASE }])
	navs.length = 0
	await mockCall('POST', `/_mock/next/${OID}`)
	await page.goto(`${BASE}/resources`)
	await page.waitForURL((u) => navs.some((n) => /\/sso\/login/.test(n)), { timeout: 60000 }).catch(() => {})
	const ssoNav = navs.find((u) => /\/sso\/login/.test(u))
	check('an expired session reaches /sso/login', !!ssoNav, navs.map(path).join(' > '))
	check('…keeping the page as rd', !!ssoNav && new URL(ssoNav).searchParams.get('rd') === '/resources',
		ssoNav ? `rd=${new URL(ssoNav).searchParams.get('rd')}` : '')
	await browser.close()
	process.exit(failed)
})().catch((e) => { console.log(`FAIL  browser run: ${e.message.split('\n')[0]}`); process.exit(1) })
