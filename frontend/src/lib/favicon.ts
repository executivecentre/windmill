import type { Job } from '$lib/gen'
import { BRAND_COLOR, BRAND_MARK_PATH, BRAND_MARK_SIZE } from '$lib/branding'

export type JobStatusKind = 'running' | 'success' | 'failure' | 'canceled'

const STATUS_COLORS: Record<JobStatusKind, string> = {
	running: '#eab308',
	success: '#22c55e',
	failure: '#ef4444',
	canceled: '#6b7280'
}

const DEFAULT_FAVICON = '/logo.svg'

// The brand mark scaled to the 256-unit canvas, with its fill inlined so the SVG is
// self-contained as a data URI; white under a dark colour scheme, as `static/logo.svg` is.
const LOGO_MARK =
	'<style>@media (prefers-color-scheme:dark){.mark{fill:#fff}}</style>' +
	`<path class="mark" fill="${BRAND_COLOR}" transform="scale(${256 / BRAND_MARK_SIZE})" d="${BRAND_MARK_PATH}"/>`

function faviconLink(): HTMLLinkElement {
	let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
	if (!link) {
		link = document.createElement('link')
		link.rel = 'icon'
		document.head.appendChild(link)
	}
	return link
}

/** Maps a job to one of the favicon status colors, following the same
 * discrimination as JobStatusIcon (`'success' in job` => completed). A job that
 * is still running while being canceled stays 'running' until it completes. */
export function getJobStatusKind(job: Job | undefined): JobStatusKind | undefined {
	if (!job) return undefined
	if (job.canceled && 'success' in job) return 'canceled'
	if ('success' in job) return job.success ? 'success' : 'failure'
	return 'running'
}

export function setStatusFavicon(status: JobStatusKind): void {
	const color = STATUS_COLORS[status]
	const svg =
		'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">' +
		`<g>${LOGO_MARK}</g>` +
		'<circle cx="196" cy="196" r="70" fill="#ffffff"/>' +
		`<circle cx="196" cy="196" r="54" fill="${color}"/>` +
		'</svg>'
	faviconLink().href = `data:image/svg+xml,${encodeURIComponent(svg)}`
}

export function resetFavicon(): void {
	faviconLink().href = DEFAULT_FAVICON
}
