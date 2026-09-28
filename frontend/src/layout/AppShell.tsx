import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { LayoutDashboard, Network, ListTree, BrainCircuit, ActivitySquare, Settings, Bell, Sun, Moon } from '../components/Icons'
import { DOMAINS, MODES } from '../lib/api'
import type { Domain } from '../lib/api'
import { SystemProvider, useSystem } from '../context/SystemContext'

const navItems = [
  { label: 'Dashboard', path: '/', icon: LayoutDashboard },
  { label: 'Network Graph', path: '/network-graph', icon: Network },
  { label: 'Threat Logs', path: '/threat-logs', icon: ListTree },
  { label: 'Attack Guide & Rules', path: '/xai', icon: BrainCircuit },
  { label: 'AI Engine Status', path: '/engine-status', icon: ActivitySquare },
  { label: 'System Settings', path: '/settings', icon: Settings },
]

export function AppShell({ children }: { children: ReactNode }) {
  return <SystemProvider><ShellContent>{children}</ShellContent></SystemProvider>
}

function ShellContent({ children }: { children: ReactNode }) {
  const location = useLocation()
  const { status, online, error, busy, actionError, switchEngine } = useSystem()
  const [isDark, setIsDark] = useState(() => localStorage.getItem('theme') === 'dark' ||
    (!localStorage.getItem('theme') && !!window.matchMedia?.('(prefers-color-scheme: dark)')?.matches))
  useEffect(() => {
    document.documentElement.classList.toggle('dark', isDark)
    localStorage.setItem('theme', isDark ? 'dark' : 'light')
  }, [isDark])
  const disabled = !online || busy || !!status?.switching
  const badge = !online ? error ? 'BACKEND UNAVAILABLE' : 'CONNECTING' : status?.is_hardware_live ? 'PI CONNECTED' : 'SIMULATION MODE'
  return <div className="min-h-screen bg-background text-text flex flex-col lg:flex-row">
    <aside className="lg:w-64 shrink-0 border-r border-border bg-surface">
      <Link to="/" className="h-16 flex items-center gap-3 px-6 font-bold text-accent-dark"><span className="rounded-full border border-accent px-3 py-2">S</span>SENTRi-X</Link>
      <nav className="flex lg:flex-col gap-1 overflow-x-auto p-3 text-sm">{navItems.map(item => <Link key={item.path} to={item.path}
        className={`flex items-center gap-3 whitespace-nowrap rounded-xl px-4 py-3 ${location.pathname === item.path ? 'bg-accent-soft text-accent-dark font-semibold' : 'text-text-muted hover:bg-background-soft'}`}>
        <item.icon className="h-5 w-5 shrink-0" />{item.label}</Link>)}</nav>
    </aside>
    <main className="flex-1 min-w-0">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-surface px-5 py-4">
        <span role="status" className={`rounded-full border px-3 py-1 text-xs font-bold ${online && status?.is_hardware_live ? 'border-emerald-500/50 text-emerald-600 dark:text-emerald-400' : 'border-amber-500/50 text-amber-600 dark:text-amber-400'}`}>{badge}</span>
        <div className="flex flex-wrap items-center gap-2">
          <select aria-label="Active model" value={status?.current_model || ''} disabled={disabled}
            onChange={event => status && void switchEngine(event.target.value as Domain, status.execution_mode)}
            className="rounded-lg border border-border bg-background px-3 py-2 text-xs disabled:opacity-60">
            <option value="" disabled>Waiting for backend</option>{DOMAINS.map(domain => <option key={domain.id} value={domain.id}>{domain.name}</option>)}
          </select>
          {MODES.map(mode => <button key={mode.id} disabled={disabled} type="button" aria-pressed={online && status?.execution_mode === mode.id}
            onClick={() => status && void switchEngine(status.current_model, mode.id)}
            className={`rounded-lg border px-3 py-2 text-xs disabled:opacity-60 ${online && status?.execution_mode === mode.id ? 'bg-accent border-accent text-white' : 'border-border text-text-muted'}`}>{mode.name}</button>)}
          {busy && <span className="text-xs text-text-muted">Loading model…</span>}
        </div>
        <div className="flex items-center gap-3">
          <button type="button" aria-label="Toggle dark mode" onClick={() => setIsDark(value => !value)} className="rounded-full border border-border p-2">{isDark ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}</button>
          <Link to="/threat-logs" aria-label="View threat logs" className="flex items-center gap-1"><Bell className="h-5 w-5" /><span className="text-xs">{online ? status?.threats_detected ?? 0 : '—'}</span></Link>
        </div>
      </header>
      {(error || actionError) && <div role="alert" className="border-b border-amber-500/30 bg-amber-500/10 px-5 py-3 text-sm">{error || actionError}</div>}
      <div className="p-4 md:p-8">{children}</div>
    </main>
  </div>
}
