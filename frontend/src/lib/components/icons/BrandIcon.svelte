<script lang="ts">
	import { BRAND_COLOR, BRAND_MARK_PATH, BRAND_MARK_SIZE } from '$lib/branding'
	import { twMerge } from 'tailwind-merge'

	// `width`, `height` and `white` are accepted so it can stand in wherever WindmillIcon's props
	// are passed; the colour follows the theme instead of `white`.
	interface Props {
		size?: number
		width?: string
		height?: string
		white?: boolean
		spin?: 'slow' | 'medium' | 'fast' | 'veryfast' | undefined
		class?: string
	}

	let {
		size = undefined,
		width = '24px',
		height = '24px',
		spin = undefined,
		class: classNames = ''
	}: Props = $props()
</script>

<!-- Brand colour inline, white in the dark theme: `!` lets the dark rule beat the inline style and
     any text colour a caller passes in `class`. -->
<svg
	class={twMerge(classNames, 'dark:!text-white motion-reduce:animate-none')}
	class:animate-[spin_2s_linear_infinite]={spin === 'veryfast'}
	class:animate-[spin_5s_linear_infinite]={spin === 'fast'}
	class:animate-[spin_15s_linear_infinite]={spin === 'medium'}
	class:animate-[spin_50s_linear_infinite]={spin === 'slow'}
	style:color={BRAND_COLOR}
	width={size ? `${size}px` : width}
	height={size ? `${size}px` : height}
	viewBox="0 0 {BRAND_MARK_SIZE} {BRAND_MARK_SIZE}"
	fill="currentColor"
	xmlns="http://www.w3.org/2000/svg"
	aria-hidden="true"
>
	<path d={BRAND_MARK_PATH} />
</svg>
