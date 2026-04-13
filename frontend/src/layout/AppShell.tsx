import type { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
	LayoutDashboard,
	Network,
	ListTree,
	BrainCircuit,
	ActivitySquare,
	Settings,
	Bell,
	Menu,
	Sun,
	Moon
} from 'lucide-react'

const navItems = [
	{ label: 'Dashboard', path: '/', icon: LayoutDashboard },
	{ label: 'Network Graph', path: '/network-graph', icon: Network },
	{ label: 'Threat Logs', path: '/threat-logs', icon: ListTree },
	{ label: 'Security Rules', path: '/xai', icon: BrainCircuit },
	{ label: 'AI Engine Status', path: '/engine-status', icon: ActivitySquare },
	{ label: 'System Settings', path: '/settings', icon: Settings },
]

interface AppShellProps {
	children: ReactNode
}

export function AppShell({ children }: AppShellProps) {
	const location = useLocation()
	const [systemStatus, setSystemStatus] = useState<any>({
		node_status: 'Connecting...',
		core_model: 'Loading...',
		threats_detected: 0,
	})
	
	// Check initial theme preference
	const [isDark, setIsDark] = useState(() => {
		if (typeof window !== 'undefined') {
			return document.documentElement.classList.contains('dark') ||
				(!('theme' in localStorage) && window.matchMedia?.('(prefers-color-scheme: dark)').matches)
		}
		return false
	})

	// Toggle theme
	useEffect(() => {
		const root = document.documentElement
		if (isDark) {
			root.classList.add('dark')
			localStorage.setItem('theme', 'dark')
		} else {
			root.classList.remove('dark')
			localStorage.setItem('theme', 'light')
		}
	}, [isDark])

	// Fetch backend status
	useEffect(() => {
		const fetchStatus = async () => {
			try {
				const response = await fetch('http://127.0.0.1:8000/api/status')
				if (response.ok) {
					const data = await response.json()
					setSystemStatus(data)
				}
			} catch (error) {
				setSystemStatus({ node_status: 'Offline', core_model: 'Unreachable' })
				console.error('Failed to fetch status:', error)
			}
		}

		// Initial fetch
		fetchStatus()

		// Poll every 2 seconds to keep it live
		const interval = setInterval(fetchStatus, 2000)
		return () => clearInterval(interval)
	}, [])

	return (
		<div className="flex min-h-screen bg-background text-text">
			<aside className="w-64 bg-surface/80 backdrop-blur-md flex flex-col shadow-lg">
				<div className="h-16 px-6 border-b border-border/80 flex items-center gap-2 text-accent-dark font-semibold">
					<span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-accent-soft border border-accent font-bold">
						S
					</span>
					<span>SENTRi-X</span>
				</div>
				<nav className="flex-1 px-3 py-4 space-y-1 text-sm">
					{navItems.map((item) => {
						const active = location.pathname === item.path
						return (
							<Link
								key={item.path}
								to={item.path}
								className={
									'flex items-center gap-3 rounded-xl px-3 py-2.5 ml-1 mr-4 transition-all duration-200 ' +
									(active
										? 'bg-accent-soft text-accent-dark font-medium shadow-sm'
										: 'text-text-muted hover:bg-background-soft hover:text-text')
								}
							>
								<item.icon className="w-5 h-5" />
								<span>{item.label}</span>
							</Link>
						)
					})}
				</nav>
		</aside>
			<main className="flex-1 flex flex-col">
				<header className="h-16 border-b border-border/80 flex items-center justify-between px-8 bg-surface/80 backdrop-blur-md shadow-sm">
					<div className="flex items-center gap-3 text-sm">
						<span
							className={`px-2 py-0.5 rounded-full text-xs font-medium border ${
								systemStatus.node_status === 'Active'
									? 'bg-accent-soft text-accent-dark border-accent'
									: 'bg-red-100 text-red-600 border-red-300 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800'
							}`}
						>
							● {systemStatus.node_status === 'Active' ? 'NODE ACTIVE' : systemStatus.node_status.toUpperCase()}
						</span>
						<span className="text-text-muted">Core Model</span>
						<span className="text-accent-dark font-semibold">{systemStatus.core_model}</span>
					</div>
					<div className="flex items-center gap-4 text-text-muted">
						<button
							onClick={() => setIsDark(!isDark)}
							className="h-9 w-9 rounded-full bg-background flex items-center justify-center border border-border/60 hover:bg-background-soft transition-colors shadow-sm"
							aria-label="Toggle dark mode"
						>
							{isDark ? <Sun className="w-4 h-4 text-accent-dark" /> : <Moon className="w-4 h-4 text-accent-dark" />}
						</button>
						<Link 
							to="/threat-logs" 
							className="relative h-9 w-9 rounded-full bg-background flex items-center justify-center border border-border/60 hover:bg-background-soft transition-colors shadow-sm"
							title="View Threat Logs"
						>
							<Bell className="w-4 h-4" />
							{systemStatus.threats_detected > 0 && (
								<span className="absolute top-0 right-0 -mt-1 -mr-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white shadow-sm ring-2 ring-background">
									{systemStatus.threats_detected > 99 ? '99+' : systemStatus.threats_detected}
								</span>
							)}
						</Link>
						<div className="h-9 w-9 rounded-full bg-accent text-white flex items-center justify-center shadow-sm font-semibold text-sm">
							JD
						</div>
					</div>
				</header>
				<section className="flex-1 px-8 py-6 overflow-auto bg-background">
					{children}
				</section>
			</main>
		</div>
	)
}
