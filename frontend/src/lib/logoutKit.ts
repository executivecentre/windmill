// SvelteKit-specific logout utilities
// These functions depend on $lib/navigation which requires SvelteKit

import { goto } from '$lib/navigation'
import { clearUser } from './logout'

export async function logoutWithRedirect(rd?: string): Promise<void> {
	console.log('logoutWithRedirect', rd)
	await clearUser()
	const splitted = rd?.split('?')[0]
	if (rd && rd != '/' && splitted != '/user/login' && splitted != '/user/logout') {
		const error = document.cookie.includes('token')
			? `error=${encodeURIComponent('You have been logged out because your session has expired.')}&`
			: ''
		console.log('login redirect with error', error, rd)
		goto(`/user/login?${error}${rd ? 'rd=' + encodeURIComponent(rd) : ''}`, { replaceState: true })
	} else {
		console.log('login redirect vanilla')
		goto('/user/login', { replaceState: true })
	}
}

// A full page load: the gateway's /sso/logout also ends the Entra session, without which the
// next visit would sign the user straight back in.
export async function logout(): Promise<void> {
	await clearUser()
	window.location.replace('/sso/logout')
}
