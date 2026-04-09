/** @type {import('tailwindcss').Config} */
export default {
	content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
	darkMode: 'class',
	theme: {
		extend: {
			fontFamily: {
				sans: ['Poppins', 'system-ui', 'sans-serif'],
			},
			colors: {
				// Dynamic palette: values mapped to CSS variables in index.css
				background: {
					DEFAULT: 'rgb(var(--color-bg) / <alpha-value>)',
					soft: 'rgb(var(--color-bg-soft) / <alpha-value>)',
				},
				surface: {
					DEFAULT: 'rgb(var(--color-surface) / <alpha-value>)',
					subtle: 'rgb(var(--color-surface-subtle) / <alpha-value>)',
				},
				accent: {
					DEFAULT: 'rgb(var(--color-accent) / <alpha-value>)',
					soft: 'rgb(var(--color-accent-soft) / <alpha-value>)',
					dark: 'rgb(var(--color-accent-dark) / <alpha-value>)',
				},
				text: {
					DEFAULT: 'rgb(var(--color-text) / <alpha-value>)',
					muted: 'rgb(var(--color-text-muted) / <alpha-value>)',
				},
				border: {
					DEFAULT: 'rgb(var(--color-border) / <alpha-value>)',
				},
			},
		},
	},
	plugins: [],
}

