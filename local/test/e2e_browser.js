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

	const onLoginPage = () => page.waitForURL((u) => u.pathname === '/user/login', { timeout: 30000 })
	const ssoSeen = () => seen(/\/sso\//)

	// 1. "/" without a session: Windmill's own login page, with no hop through the gateway.
	navs.length = 0
	await page.goto(`${BASE}/`)
	await onLoginPage()
	await page.waitForLoadState('networkidle')
	const msButton = page.getByText('Continue with Microsoft')
	await msButton.waitFor({ timeout: 15000 }).catch(() => {})
	check('signed-out visit to / shows the login page, no SSO redirect', !ssoSeen(), navs.map(path).join(' > '))
	check('…with the password form', await page.locator('input[type=password]').count() > 0)
	check('…and a "Continue with Microsoft" button', await msButton.count() === 1)
	await page.screenshot({ path: `${SHOTS}/0-login-page.png` })

	// 2. The Microsoft button signs in through the gateway and Entra.
	await mockCall('POST', `/_mock/next/${OID}`)
	navs.length = 0
	await msButton.click()
	await page.waitForURL((u) => u.host === 'localhost:3443' && !u.pathname.startsWith('/sso') &&
		!u.pathname.startsWith('/api') && !u.pathname.startsWith('/user/login'), { timeout: 60000 })
	await page.waitForLoadState('networkidle')
	check('the button goes through /sso/login', seen(/\/sso\/login/), navs.map(path).join(' > '))
	check('…then the Entra authorize endpoint', seen(/mock-entra:8443\/.*\/oauth2\/v2\.0\/authorize/))
	check('…and back into Windmill signed in', (await page.context().cookies(BASE)).some((c) => c.name === 'token'),
		path(page.url()))
	await page.screenshot({ path: `${SHOTS}/1-signed-in.png` })

	// 3. Log out lands on the login page, not on the gateway.
	navs.length = 0
	// /user/workspaces offers "Log out", which calls the same logout() as the sidebar's "Sign out".
	await page.getByRole('button', { name: 'Log out', exact: true }).first().click({ timeout: 15000 })
	await onLoginPage()
	check('Log out lands on the login page, no SSO redirect', !ssoSeen(), navs.map(path).join(' > '))
	check('…and the Windmill session cookie is gone',
		!(await page.context().cookies(BASE)).some((c) => c.name === 'token' && c.value))
	await page.screenshot({ path: `${SHOTS}/2-logged-out.png` })

	// 4. Expired session: an invalid token cookie on an app page lands on the login page with rd.
	await ctx.addCookies([{ name: 'token', value: 'expired-session-token', url: BASE }])
	navs.length = 0
	await page.goto(`${BASE}/resources`)
	await onLoginPage().catch(() => {})
	check('an expired session lands on the login page, no SSO redirect',
		new URL(page.url()).pathname === '/user/login' && !ssoSeen(), navs.map(path).join(' > '))
	check('…keeping the page as rd', new URL(page.url()).searchParams.get('rd') === '/resources',
		`rd=${new URL(page.url()).searchParams.get('rd')}`)

	// 5. Instance settings SSO tab (AuthSettings.svelte patch): the gateway notice, not upstream's
	// provider forms. Signs in as the break-glass admin; this host is in ADMIN_ALLOWED_CIDRS.
	const admin = await browser.newContext({ ignoreHTTPSErrors: true })
	const adminPw = fs.readFileSync(`${RUN}/secrets/windmill_admin_password`, 'utf8').trim()
	const login = await admin.request.post(`${BASE}/api/auth/login`,
		{ data: { email: 'admin@windmill.dev', password: adminPw } })
	check('break-glass admin signs in from an allowed address', login.status() === 200, `${login.status()}`)
	const settings = await admin.newPage()
	await settings.goto(`${BASE}/user/instance_settings`)
	await settings.getByRole('button', { name: 'Advanced setup' }).click()
	await settings.getByText(/^SSO$/).first().click()
	await settings.getByText('SSO is provided by the Microsoft Entra ID gateway').waitFor({ timeout: 15000 })
		.catch(() => {})
	const ssoTab = await settings.locator('body').innerText()
	check('SSO settings tab shows the Entra gateway notice',
		ssoTab.includes('SSO is provided by the Microsoft Entra ID gateway'))
	check('…and not the CE SSO-user limit or upstream provider forms',
		!ssoTab.includes('Limited to 10 SSO users') && !/Okta/.test(ssoTab))
	await browser.close()
	process.exit(failed)
})().catch((e) => { console.log(`FAIL  browser run: ${e.message.split('\n')[0]}`); process.exit(1) })
