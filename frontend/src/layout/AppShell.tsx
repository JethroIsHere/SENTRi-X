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
	Sun,
	Moon
} from '../components/Icons.tsx'

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
		current_dataset: 'omni',
		current_model: 'omni',
		execution_mode: 'hybrid',
		is_hardware_live: false,
		threats_detected: 0,
	})
	
	const [isSwitching, setIsSwitching] = useState(false)

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
	const fetchStatus = async () => {
		try {
			const response = await fetch('http://127.0.0.1:8000/api/status')
			if (response.ok) {
				const data = await response.json()
				setSystemStatus(data)
			}
		} catch (error) {
			setSystemStatus((prev: any) => ({ ...prev, node_status: 'Offline', core_model: 'Unreachable' }))
		}
	}

	useEffect(() => {
		fetchStatus()
		const interval = setInterval(fetchStatus, 2000)
		return () => clearInterval(interval)
	}, [])

	// Quick Switch Handler
	const handleSwitch = async (domain: string, mode: string) => {
		setIsSwitching(true)
		try {
			const res = await fetch('http://127.0.0.1:8000/api/switch', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					model_type: domain,
					dataset: domain,
					mode: mode
				})
			})
			if (res.ok) {
				await fetchStatus()
			}
		} catch (err) {
			console.error('Failed to switch engine:', err)
		} finally {
			setIsSwitching(false)
		}
	}

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
				<header className="h-16 border-b border-border/80 flex items-center justify-between px-6 bg-surface/80 backdrop-blur-md shadow-sm gap-4">
					{/* Left status badge */}
					<div className="flex items-center gap-3 text-sm">
						<span
							className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border flex items-center gap-1.5 ${
								systemStatus.node_status.includes('Active') || systemStatus.node_status.includes('Live')
									? 'bg-accent-soft text-accent-dark border-accent'
									: 'bg-red-100 text-red-600 border-red-300 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800'
							}`}
						>
							<span className={`w-2 h-2 rounded-full ${systemStatus.is_hardware_live ? 'bg-emerald-500 animate-pulse' : 'bg-accent'}`} />
							{systemStatus.is_hardware_live ? 'RPI 3B+ (LIVE)' : 'SIM REPLAY'}
						</span>
					</div>

					{/* Center: Quick Model & Architecture Switcher */}
					<div className="flex items-center gap-2 bg-background-soft/80 border border-border/80 rounded-xl p-1 shadow-inner text-xs">
						{/* Domain Selector */}
						<select
							value={systemStatus.current_model || 'omni'}
							disabled={isSwitching}
							onChange={(e) => handleSwitch(e.target.value, systemStatus.execution_mode || 'hybrid')}
							className="bg-surface text-text font-medium text-xs rounded-lg px-2.5 py-1 border border-border focus:outline-none focus:ring-1 focus:ring-accent cursor-pointer"
						>
							<option value="omni">🌐 Omni Global Defense</option>
							<option value="ton_iot">📡 ToN-IoT (Baseline)</option>
							<option value="bot_iot">🤖 BoT-IoT (Transfer)</option>
							<option value="cic_ids2017">🏢 CIC-IDS2017 (Enterprise)</option>
						</select>

						{/* Architecture Mode Buttons */}
						<div className="flex items-center bg-surface rounded-lg p-0.5 border border-border">
							<button
								type="button"
								onClick={() => handleSwitch(systemStatus.current_model || 'omni', 'hybrid')}
								disabled={isSwitching}
								className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
									(systemStatus.execution_mode || 'hybrid') === 'hybrid'
										? 'bg-accent text-white shadow-sm'
										: 'text-text-muted hover:text-text'
								}`}
							>
								Hybrid (RF+CNN)
							</button>
							<button
								type="button"
								onClick={() => handleSwitch(systemStatus.current_model || 'omni', 'rf')}
								disabled={isSwitching}
								className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
									systemStatus.execution_mode === 'rf'
										? 'bg-emerald-600 text-white shadow-sm'
										: 'text-text-muted hover:text-text'
								}`}
							>
								RF Only
							</button>
							<button
								type="button"
								onClick={() => handleSwitch(systemStatus.current_model || 'omni', 'cnn')}
								disabled={isSwitching}
								className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
									systemStatus.execution_mode === 'cnn'
										? 'bg-fuchsia-600 text-white shadow-sm'
										: 'text-text-muted hover:text-text'
								}`}
							>
								1D CNN Only
							</button>
						</div>
					</div>

					{/* Right controls */}
					<div className="flex items-center gap-3 text-text-muted">
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
								<span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white shadow">
									{systemStatus.threats_detected > 99 ? '99+' : systemStatus.threats_detected}
								</span>
							)}
						</Link>
					</div>
				</header>
				<div className="flex-1 p-8 overflow-y-auto">
					{children}
				</div>
			</main>
		</div>
	)
}
