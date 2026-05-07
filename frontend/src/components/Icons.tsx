import type { ReactNode, SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement>

function BaseIcon({ children, ...props }: IconProps & { children: ReactNode }) {
	return (
		<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
			{children}
		</svg>
	)
}

export function LayoutDashboard(props: IconProps) {
	return <BaseIcon {...props}><rect x="3" y="3" width="8" height="8" rx="2" /><rect x="13" y="3" width="8" height="5" rx="2" /><rect x="13" y="10" width="8" height="11" rx="2" /><rect x="3" y="13" width="8" height="8" rx="2" /></BaseIcon>
}

export function Network(props: IconProps) {
	return <BaseIcon {...props}><circle cx="6" cy="6" r="2" /><circle cx="18" cy="6" r="2" /><circle cx="12" cy="18" r="2" /><path d="M8 7.5l2.6 2.1" /><path d="M16 7.5l-2.6 2.1" /><path d="M11 15.8l-1.8-2.8" /><path d="M13 15.8l1.8-2.8" /></BaseIcon>
}

export function ListTree(props: IconProps) {
	return <BaseIcon {...props}><path d="M7 6h14" /><path d="M7 12h14" /><path d="M7 18h14" /><circle cx="4" cy="6" r="1" /><circle cx="4" cy="12" r="1" /><circle cx="4" cy="18" r="1" /></BaseIcon>
}

export function BrainCircuit(props: IconProps) {
	return <BaseIcon {...props}><path d="M9 4a3 3 0 0 0-3 3v1a3 3 0 0 0 0 6v1a3 3 0 0 0 3 3" /><path d="M15 4a3 3 0 0 1 3 3v1a3 3 0 0 1 0 6v1a3 3 0 0 1-3 3" /><path d="M9 12h6" /><path d="M12 6v12" /></BaseIcon>
}

export function ActivitySquare(props: IconProps) {
	return <BaseIcon {...props}><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M7 13h2l2-5 2 8 2-4h2" /></BaseIcon>
}

export function Settings(props: IconProps) {
	return <BaseIcon {...props}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a7.8 7.8 0 0 0 .1-6l2-1.2-2-3.4-2.3 1a8 8 0 0 0-5.2-3l-.3-2.4H9l-.3 2.4a8 8 0 0 0-5.2 3l-2.3-1-2 3.4 2 1.2a7.8 7.8 0 0 0 0 6l-2 1.2 2 3.4 2.3-1a8 8 0 0 0 5.2 3l.3 2.4h3l.3-2.4a8 8 0 0 0 5.2-3l2.3 1 2-3.4z" /></BaseIcon>
}

export function Bell(props: IconProps) {
	return <BaseIcon {...props}><path d="M15 17H9a3 3 0 0 1-3-3v-3a6 6 0 1 1 12 0v3a3 3 0 0 1-3 3Z" /><path d="M10 17a2 2 0 0 0 4 0" /></BaseIcon>
}

export function Sun(props: IconProps) {
	return <BaseIcon {...props}><circle cx="12" cy="12" r="4" /><path d="M12 2v2" /><path d="M12 20v2" /><path d="M4.9 4.9l1.4 1.4" /><path d="M17.7 17.7l1.4 1.4" /><path d="M2 12h2" /><path d="M20 12h2" /><path d="M4.9 19.1l1.4-1.4" /><path d="M17.7 6.3l1.4-1.4" /></BaseIcon>
}

export function Moon(props: IconProps) {
	return <BaseIcon {...props}><path d="M20 14.5A8.5 8.5 0 1 1 9.5 4 7 7 0 0 0 20 14.5Z" /></BaseIcon>
}

export function ShieldCheck(props: IconProps) {
	return <BaseIcon {...props}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" /><path d="m9 12 2 2 4-4" /></BaseIcon>
}

export function Clock(props: IconProps) {
	return <BaseIcon {...props}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></BaseIcon>
}

export function Zap(props: IconProps) {
	return <BaseIcon {...props}><path d="M13 2 3 14h7l-1 8 10-12h-7z" /></BaseIcon>
}

export function Activity(props: IconProps) {
	return <BaseIcon {...props}><path d="M3 12h4l2-6 4 12 2-6h6" /></BaseIcon>
}