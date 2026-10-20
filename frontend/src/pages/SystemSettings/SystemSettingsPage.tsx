import { useEffect, useState } from 'react'
import { useSystem } from '../../context/SystemContext'
import { api, DOMAINS, MODES, getAdminKey, setAdminKey, formatTime } from '../../lib/api'
import type { Settings, AuditLog } from '../../lib/api'
import { panelClass, RequestState } from '../../components/LiveTelemetry'

interface MonitoredDevice { mac: string; name: string; added_at: string }
interface WhitelistedDest { ip: string; label: string; reason: string; added_at: string }
interface WhitelistedDomain { domain: string; label: string; reason: string; added_at: string }

function MonitoredDevices({ online }: { online: boolean }) {
  const [devices, setDevices] = useState<MonitoredDevice[]>([])
  const [mac, setMac] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function load() {
    if (!online) return
    try {
      const res = await api<{ devices: MonitoredDevice[] }>('/api/monitored-devices')
      setDevices(res.devices)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load devices') }
  }
  useEffect(() => { void load() }, [online])

  async function add() {
    if (!mac.trim() || !name.trim()) { setError('MAC and name are required'); return }
    setBusy(true); setError(null)
    try {
      const res = await api<{ devices: MonitoredDevice[] }>('/api/monitored-devices', {
        method: 'POST', body: JSON.stringify({ mac: mac.trim(), name: name.trim() }),
      })
      setDevices(res.devices); setMac(''); setName('')
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not add device') }
    finally { setBusy(false) }
  }

  async function remove(target: string) {
    setBusy(true); setError(null)
    try {
      const res = await api<{ devices: MonitoredDevice[] }>(
        `/api/monitored-devices/${encodeURIComponent(target)}`, { method: 'DELETE' })
      setDevices(res.devices)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not remove device') }
    finally { setBusy(false) }
  }

  return <div>
    <h2 className="mb-3 text-lg font-semibold">Monitored IoT Devices</h2>
    <p className="text-xs text-text-muted mb-4">The Pi sensor only captures traffic for these MAC addresses. Changes take effect on the next heartbeat (removals are immediate; new devices need a sensor restart for the capture filter).</p>
    {devices.length === 0
      ? <p className="text-sm text-text-muted">No devices monitored. Add your IoT devices below.</p>
      : <ul className="space-y-2 mb-4">{devices.map(d => (
        <li key={d.mac} className="flex items-center justify-between rounded-lg border border-border px-3 py-2 text-sm">
          <span><span className="font-medium">{d.name}</span> <span className="text-text-muted font-mono">{d.mac}</span></span>
          <button disabled={!online || busy} onClick={() => void remove(d.mac)}
            className="rounded-lg border border-border px-3 py-1 text-xs disabled:opacity-50 hover:bg-red-50">Remove</button>
        </li>))}</ul>}
    <div className="flex flex-wrap gap-2 items-end">
      <label className="text-sm">MAC address<input value={mac} onChange={e => setMac(e.target.value)}
        placeholder="aa:bb:cc:dd:ee:ff" className="ml-2 rounded-lg border border-border px-3 py-2 font-mono text-sm" /></label>
      <label className="text-sm">Name<input value={name} onChange={e => setName(e.target.value)}
        placeholder="smart_bulb" className="ml-2 rounded-lg border border-border px-3 py-2 text-sm" /></label>
      <button disabled={!online || busy} onClick={() => void add()}
        className="rounded-xl bg-accent px-4 py-2 text-sm text-white disabled:opacity-50">{busy ? 'Working…' : 'Add Device'}</button>
    </div>
    <RequestState error={error} />
  </div>
}

function WhitelistedDestinations({ online }: { online: boolean }) {
  const [dests, setDests] = useState<WhitelistedDest[]>([])
  const [ip, setIp] = useState('')
  const [label, setLabel] = useState('')
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function load() {
    if (!online) return
    try {
      const res = await api<{ destinations: WhitelistedDest[] }>('/api/whitelisted-destinations')
      setDests(res.destinations)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load whitelist') }
  }
  useEffect(() => { void load() }, [online])

  async function add() {
    if (!ip.trim() || !label.trim()) { setError('IP and label are required'); return }
    setBusy(true); setError(null)
    try {
      const res = await api<{ destinations: WhitelistedDest[] }>('/api/whitelisted-destinations', {
        method: 'POST', body: JSON.stringify({ ip: ip.trim(), label: label.trim(), reason: reason.trim() }),
      })
      setDests(res.destinations); setIp(''); setLabel(''); setReason('')
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not add destination') }
    finally { setBusy(false) }
  }

  async function remove(target: string) {
    setBusy(true); setError(null)
    try {
      const res = await api<{ destinations: WhitelistedDest[] }>(
        `/api/whitelisted-destinations/${encodeURIComponent(target)}`, { method: 'DELETE' })
      setDests(res.destinations)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not remove destination') }
    finally { setBusy(false) }
  }

  return <div>
    <h2 className="mb-3 text-lg font-semibold">Whitelisted Destinations</h2>
    <p className="text-xs text-text-muted mb-4">Flows to these IPs are still classified and stored, but <strong>never trigger alerts</strong>. Use this to suppress false positives from known IoT cloud endpoints (e.g. Tuya, SmartLife).</p>
    {dests.length === 0
      ? <p className="text-sm text-text-muted">No destinations whitelisted. Alerts fire for all classified attack flows.</p>
      : <ul className="space-y-2 mb-4">{dests.map(d => (
        <li key={d.ip} className="flex items-center justify-between rounded-lg border border-border px-3 py-2 text-sm">
          <span>
            <span className="font-medium">{d.label}</span>{' '}
            <span className="text-text-muted font-mono">{d.ip}</span>
            {d.reason && <span className="ml-2 text-xs text-text-muted">— {d.reason}</span>}
          </span>
          <button disabled={!online || busy} onClick={() => void remove(d.ip)}
            className="rounded-lg border border-border px-3 py-1 text-xs disabled:opacity-50 hover:bg-red-50">Remove</button>
        </li>))}</ul>}
    <div className="flex flex-wrap gap-2 items-end">
      <label className="text-sm">Destination IP<input value={ip} onChange={e => setIp(e.target.value)}
        placeholder="47.236.105.163" className="ml-2 rounded-lg border border-border px-3 py-2 font-mono text-sm" /></label>
      <label className="text-sm">Label<input value={label} onChange={e => setLabel(e.target.value)}
        placeholder="Tuya Cloud (SG)" className="ml-2 rounded-lg border border-border px-3 py-2 text-sm" /></label>
      <label className="text-sm">Reason<input value={reason} onChange={e => setReason(e.target.value)}
        placeholder="Smart plug heartbeat" className="ml-2 rounded-lg border border-border px-3 py-2 text-sm" /></label>
      <button disabled={!online || busy} onClick={() => void add()}
        className="rounded-xl bg-accent px-4 py-2 text-sm text-white disabled:opacity-50">{busy ? 'Working…' : 'Add to Whitelist'}</button>
    </div>
    <RequestState error={error} />
  </div>
}

function WhitelistedDomains({ online }: { online: boolean }) {
  const [domains, setDomains] = useState<WhitelistedDomain[]>([])
  const [domain, setDomain] = useState('')
  const [label, setLabel] = useState('')
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function load() {
    if (!online) return
    try {
      const res = await api<{ domains: WhitelistedDomain[] }>('/api/whitelisted-domains')
      setDomains(res.domains)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load domain whitelist') }
  }
  useEffect(() => { void load() }, [online])

  async function add() {
    if (!domain.trim() || !label.trim()) { setError('Domain and label are required'); return }
    setBusy(true); setError(null)
    try {
      const res = await api<{ domains: WhitelistedDomain[] }>('/api/whitelisted-domains', {
        method: 'POST', body: JSON.stringify({ domain: domain.trim(), label: label.trim(), reason: reason.trim() }),
      })
      setDomains(res.domains); setDomain(''); setLabel(''); setReason('')
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not add domain') }
    finally { setBusy(false) }
  }

  async function remove(target: string) {
    setBusy(true); setError(null)
    try {
      const res = await api<{ domains: WhitelistedDomain[] }>(
        `/api/whitelisted-domains/${encodeURIComponent(target)}`, { method: 'DELETE' })
      setDomains(res.domains)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not remove domain') }
    finally { setBusy(false) }
  }

  return <div>
    <h2 className="mb-3 text-lg font-semibold">Whitelisted Domains</h2>
    <p className="text-xs text-text-muted mb-4">Flows with matching TLS SNI are still classified and stored, but <strong>never trigger alerts</strong>. Supports wildcards (e.g. *.tuyaeu.com). Use this to suppress false positives from known IoT cloud domains.</p>
    {domains.length === 0
      ? <p className="text-sm text-text-muted">No domains whitelisted. SNI-based suppression is inactive.</p>
      : <ul className="space-y-2 mb-4">{domains.map(d => (
        <li key={d.domain} className="flex items-center justify-between rounded-lg border border-border px-3 py-2 text-sm">
          <span>
            <span className="font-medium">{d.label}</span>{' '}
            <span className="text-text-muted font-mono">{d.domain}</span>
            {d.reason && <span className="ml-2 text-xs text-text-muted">— {d.reason}</span>}
          </span>
          <button disabled={!online || busy} onClick={() => void remove(d.domain)}
            className="rounded-lg border border-border px-3 py-1 text-xs disabled:opacity-50 hover:bg-red-50">Remove</button>
        </li>))}</ul>}
    <div className="flex flex-wrap gap-2 items-end">
      <label className="text-sm">Domain<input value={domain} onChange={e => setDomain(e.target.value)}
        placeholder="*.tuyaeu.com" className="ml-2 rounded-lg border border-border px-3 py-2 font-mono text-sm" /></label>
      <label className="text-sm">Label<input value={label} onChange={e => setLabel(e.target.value)}
        placeholder="Tuya EU Cloud" className="ml-2 rounded-lg border border-border px-3 py-2 text-sm" /></label>
      <label className="text-sm">Reason<input value={reason} onChange={e => setReason(e.target.value)}
        placeholder="IoT cloud API" className="ml-2 rounded-lg border border-border px-3 py-2 text-sm" /></label>
      <button disabled={!online || busy} onClick={() => void add()}
        className="rounded-xl bg-accent px-4 py-2 text-sm text-white disabled:opacity-50">{busy ? 'Working…' : 'Add to Whitelist'}</button>
    </div>
    <RequestState error={error} />
  </div>
}

function WhitelistedDevicePorts({ online }: { online: boolean }) {
  const [combos, setCombos] = useState<any[]>([])
  const [mac, setMac] = useState('')
  const [port, setPort] = useState('')
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function load() {
    if (!online) return
    try {
      const res = await api<{ device_ports: any[] }>('/api/whitelisted-device-ports')
      setCombos(res.device_ports)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load whitelist') }
  }
  useEffect(() => { void load() }, [online])

  async function add() {
    if (!mac.trim() || !port.trim()) { setError('MAC and port are required'); return }
    setBusy(true); setError(null)
    try {
      const res = await api<{ device_ports: any[] }>('/api/whitelisted-device-ports', {
        method: 'POST', body: JSON.stringify({ mac: mac.trim(), port: parseInt(port), reason: reason.trim() }),
      })
      setCombos(res.device_ports); setMac(''); setPort(''); setReason('')
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not add combination') }
    finally { setBusy(false) }
  }

  async function remove(m: string, p: number) {
    setBusy(true); setError(null)
    try {
      const res = await api<{ device_ports: any[] }>(
        `/api/whitelisted-device-ports/${encodeURIComponent(m)}/${p}`, { method: 'DELETE' })
      setCombos(res.device_ports)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not remove combination') }
    finally { setBusy(false) }
  }

  return <div>
    <h2 className="mb-3 text-lg font-semibold">Whitelisted Device Ports</h2>
    <p className="text-xs text-text-muted mb-4">Flows from these specific MAC addresses to these destination ports will <strong>never trigger alerts</strong>. Use this for devices with proprietary unparseable protocols (e.g. Tuya on 443, 8883, 20443).</p>
    {combos.length === 0
      ? <p className="text-sm text-text-muted">No device ports whitelisted.</p>
      : <ul className="space-y-2 mb-4">{combos.map(c => (
        <li key={`${c.mac}-${c.port}`} className="flex items-center justify-between rounded-lg border border-border px-3 py-2 text-sm">
          <span>
            <span className="font-medium font-mono">{c.mac}</span>{' '}
            <span className="text-text-muted">Port {c.port}</span>
            {c.reason && <span className="ml-2 text-xs text-text-muted">— {c.reason}</span>}
          </span>
          <button disabled={!online || busy} onClick={() => void remove(c.mac, c.port)}
            className="rounded-lg border border-border px-3 py-1 text-xs disabled:opacity-50 hover:bg-red-50">Remove</button>
        </li>))}</ul>}
    <div className="flex flex-wrap gap-2 items-end">
      <label className="text-sm">Device MAC<input value={mac} onChange={e => setMac(e.target.value)}
        placeholder="68:57:2d:db:39:7d" className="ml-2 rounded-lg border border-border px-3 py-2 font-mono text-sm" /></label>
      <label className="text-sm">Port<input type="number" value={port} onChange={e => setPort(e.target.value)}
        placeholder="443" className="ml-2 rounded-lg border border-border px-3 py-2 w-24 text-sm" /></label>
      <label className="text-sm">Reason<input value={reason} onChange={e => setReason(e.target.value)}
        placeholder="Tuya heartbeat bypass" className="ml-2 rounded-lg border border-border px-3 py-2 text-sm" /></label>
      <button disabled={!online || busy} onClick={() => void add()}
        className="rounded-xl bg-accent px-4 py-2 text-sm text-white disabled:opacity-50">{busy ? 'Working…' : 'Add to Whitelist'}</button>
    </div>
    <RequestState error={error} />
  </div>
}

function AdminSecurityCard({ online }: { online: boolean }) {
  const [apiKey, setApiKeyState] = useState(getAdminKey())
  const [showKey, setShowKey] = useState(false)
  const [statusText, setStatusText] = useState<string | null>(null)
  const [verified, setVerified] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)

  async function checkAuth() {
    if (!online) return
    setBusy(true)
    try {
      const res = await api<{ auth_required: boolean; authenticated: boolean; key_valid: boolean; client_ip: string }>('/api/admin/auth-status')
      setVerified(res.key_valid || (!res.auth_required && res.authenticated))
      setStatusText(res.key_valid ? 'Admin key verified & active' : res.auth_required ? 'Admin key required to save changes' : 'Authentication optional (test mode)')
    } catch {
      setVerified(false)
      setStatusText('Could not verify key with backend')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    void checkAuth()
  }, [online])

  function handleSave() {
    setAdminKey(apiKey)
    void checkAuth()
  }

  function handleClear() {
    setAdminKey('')
    setApiKeyState('')
    void checkAuth()
  }

  return <div>
    <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
      <h2 className="text-lg font-semibold">Admin Authentication & Access Control</h2>
      {verified !== null && (
        <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${
          verified ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20'
        }`}>
          <span className={`h-1.5 w-1.5 rounded-full ${verified ? 'bg-emerald-500' : 'bg-amber-500'}`} />
          {verified ? 'Admin Privileges Active' : 'Key Required for Changes'}
        </span>
      )}
    </div>
    <p className="text-xs text-text-muted mb-4 leading-relaxed">
      An Administrator API Key (<code className="font-mono text-xs">X-API-Key</code>) is required to apply configuration changes (model switching, threshold adjustments, monitored devices, and suppression whitelists). All administrative modifications are permanently logged to the attributable audit trail below.
    </p>
    <div className="flex flex-wrap gap-2 items-center">
      <div className="relative flex-1 min-w-[260px] max-w-md">
        <input
          type={showKey ? 'text' : 'password'}
          value={apiKey}
          placeholder="Enter Admin API Key"
          onChange={e => setApiKeyState(e.target.value)}
          className="w-full rounded-xl border border-border bg-surface px-3 py-2 text-sm font-mono pr-16"
        />
        <button
          type="button"
          onClick={() => setShowKey(!showKey)}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-text-muted hover:text-text px-1.5 py-0.5"
        >
          {showKey ? 'Hide' : 'Show'}
        </button>
      </div>
      <button
        onClick={handleSave}
        disabled={!online || busy}
        className="rounded-xl bg-accent px-4 py-2 text-sm text-white disabled:opacity-50"
      >
        {busy ? 'Checking…' : 'Save Key'}
      </button>
      {apiKey && (
        <button
          onClick={handleClear}
          disabled={!online || busy}
          className="rounded-xl border border-border px-3 py-2 text-sm text-text-muted hover:bg-surface-soft disabled:opacity-50"
        >
          Clear
        </button>
      )}
    </div>
    {statusText && <p className="mt-2 text-xs text-text-muted">{statusText}</p>}
  </div>
}

function AdminAuditTrail({ online }: { online: boolean }) {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function loadLogs() {
    if (!online) return
    setLoading(true)
    setError(null)
    try {
      const res = await api<{ logs: AuditLog[] }>('/api/admin/audit-logs?limit=30')
      setLogs(res.logs)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not retrieve audit logs (Admin Key required)')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadLogs()
  }, [online])

  return <div>
    <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
      <div>
        <h2 className="text-lg font-semibold">Attributable Administration Audit Trail</h2>
        <p className="text-xs text-text-muted mt-1">
          Immutable event record of administrative mutations and access denials. Retained for 90 days (up to 10,000 records) per Chapter 5 recommendations.
        </p>
      </div>
      <button
        onClick={() => void loadLogs()}
        disabled={!online || loading}
        className="rounded-lg border border-border px-3 py-1.5 text-xs text-text-muted hover:bg-surface-soft disabled:opacity-50"
      >
        {loading ? 'Refreshing…' : 'Refresh Audit Trail'}
      </button>
    </div>

    <RequestState error={error} />

    {logs.length === 0 ? (
      <p className="text-sm text-text-muted py-4">No administrative audit events recorded yet.</p>
    ) : (
      <div className="mt-3 overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-border text-text-muted">
              <th className="py-2 pr-3 font-medium">Timestamp (UTC)</th>
              <th className="py-2 px-3 font-medium">Action</th>
              <th className="py-2 px-3 font-medium">Actor</th>
              <th className="py-2 px-3 font-medium">Resource</th>
              <th className="py-2 px-3 font-medium">Status</th>
              <th className="py-2 pl-3 font-medium">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50">
            {logs.map(log => {
              const isDenied = log.status === 'DENIED'
              const isFailed = log.status === 'FAILED'
              return (
                <tr key={log.id} className="hover:bg-surface-soft/40">
                  <td className="py-2 pr-3 font-mono text-[11px] whitespace-nowrap">{formatTime(log.timestamp)}</td>
                  <td className="py-2 px-3 font-mono font-medium">{log.action}</td>
                  <td className="py-2 px-3 text-text-muted">
                    <span>{log.actor}</span>
                    {log.client_ip && <span className="block text-[10px] font-mono text-text-muted/80">{log.client_ip}</span>}
                  </td>
                  <td className="py-2 px-3 font-mono text-text-muted">{log.resource}</td>
                  <td className="py-2 px-3">
                    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-medium uppercase ${
                      isDenied ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20' :
                      isFailed ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20' :
                      'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                    }`}>
                      {log.status}
                    </span>
                  </td>
                  <td className="py-2 pl-3 text-text-muted max-w-[240px] truncate" title={log.details || ''}>
                    {log.details || '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    )}
  </div>
}

export function SystemSettingsPage() {
  const { status, online, busy, refresh, switchEngine } = useSystem()
  const [draft, setDraft] = useState<Settings | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState('')
  useEffect(() => { if (status) setDraft(previous => previous || { ...status.settings }) }, [status])
  async function save() {
    if (!draft) return
    setSaving(true); setError(null); setMessage('')
    try {
      const saved = await api<Settings>('/api/settings', { method: 'PUT', body: JSON.stringify(draft) })
      setDraft({ active_alerting: saved.active_alerting, alert_threshold: saved.alert_threshold })
      setMessage('Alert settings saved.'); refresh()
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Settings could not be saved.') }
    finally { setSaving(false) }
  }
  return <div className="max-w-6xl space-y-6">
    <header><h1 className="text-3xl font-bold">System & Model Settings</h1><p className="mt-2 text-sm text-text-muted">Choose model weights, execution mode, and persisted alert settings.</p></header>
    <section className={panelClass}><AdminSecurityCard online={online} /></section>
    <section className={panelClass}><h2 className="mb-4 text-lg font-semibold">Execution Mode</h2><div className="flex flex-wrap gap-3">{MODES.map(mode => <button key={mode.id} disabled={!online || busy || status?.switching} onClick={() => status && void switchEngine(status.current_model, mode.id)} aria-pressed={online && status?.execution_mode === mode.id} className={`rounded-xl border px-4 py-3 text-sm disabled:opacity-50 ${online && status?.execution_mode === mode.id ? 'border-accent bg-accent-soft text-accent-dark' : 'border-border'}`}>{mode.name}</button>)}</div>
      <p className="mt-4 text-xs text-text-muted">RF uses tabular flow features. The 1D CNN processes the ordered 28-feature vector. Hybrid mode averages their attack probabilities.</p>
    </section>
    <section className={panelClass}><h2 className="mb-4 text-lg font-semibold">Model Domain</h2><div className="grid gap-3 sm:grid-cols-2">{DOMAINS.map(domain => <button key={domain.id} disabled={!online || busy || status?.switching} onClick={() => status && void switchEngine(domain.id, status.execution_mode)} aria-pressed={online && status?.current_model === domain.id} className={`rounded-xl border p-4 text-left text-sm disabled:opacity-50 ${online && status?.current_model === domain.id ? 'border-accent bg-accent-soft text-accent-dark' : 'border-border'}`}>{domain.name}</button>)}</div>
      <p className="mt-4 text-xs text-text-muted">A switch is applied only when the requested weights are available. The active selection follows the backend response.</p>
    </section>
    <section className={panelClass}><h2 className="mb-3 text-lg font-semibold">Raspberry Pi Sensor</h2><p className="text-sm">{!online ? 'Backend unavailable' : status?.is_hardware_live ? 'Pi connected' : 'Waiting for a recent Pi heartbeat'}</p>
      <p className="mt-3 text-xs text-text-muted">sentrix_sensor.py captures mirrored traffic and uploads flow windows. A connected Pi can be idle between uploads. Device observations are listed on the dashboard.</p>
    </section>
    <section className={panelClass}>
      <p className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-400 leading-relaxed">
        <span className="font-semibold">Note on trusted and whitelisted devices:</span> A trusted or whitelisted device can still generate suspicious traffic. Whitelisting only suppresses alert notifications for matching traffic — the flows are still captured, classified, and stored, and remain visible as suppressed entries. If a trusted device starts behaving unusually, review its suppressed flows before extending its whitelist entries.
      </p>
      <MonitoredDevices online={online} />
    </section>
    <section className={panelClass}><WhitelistedDestinations online={online} /></section>
    <section className={panelClass}><WhitelistedDomains online={online} /></section>
    <section className={panelClass}><WhitelistedDevicePorts online={online} /></section>
    <section className={panelClass}><h2 className="mb-3 text-lg font-semibold">Alert Settings</h2>
      <p className="text-sm">Classification boundary: attack probability ≥ 50%.</p>
      <p className="mt-2 text-xs text-text-muted">Saved alert policy: {online && status ? status.settings.active_alerting ? `enabled; attack confidence must exceed ${(status.settings.alert_threshold * 100).toFixed(0)}%` : 'disabled' : 'unavailable'}.</p>
      {draft && <div className="mt-5 space-y-4"><label className="flex items-center gap-3 text-sm"><input type="checkbox" checked={draft.active_alerting} disabled={!online || saving} onChange={event => { setDraft({ ...draft, active_alerting: event.target.checked }); setMessage('') }} />Record alerts for qualifying attack predictions</label>
        <label className="block text-sm">Alert confidence threshold: {(draft.alert_threshold * 100).toFixed(0)}%<input className="mt-3 block w-full max-w-md accent-accent" type="range" min="50" max="99" step="1" value={Math.round(draft.alert_threshold * 100)} disabled={!online || saving} onChange={event => { setDraft({ ...draft, alert_threshold: Number(event.target.value) / 100 }); setMessage('') }} /></label>
        <p className="text-xs text-text-muted">A flow must first be predicted as an attack and then exceed this threshold. Disabling alert recording does not stop capture, inference, or flow storage. Changes apply to live alerts.</p>
        <button disabled={!online || saving} onClick={() => void save()} className="rounded-xl bg-accent px-4 py-2 text-sm text-white disabled:opacity-50">{saving ? 'Saving…' : 'Save Alert Settings'}</button>
      </div>}
      <RequestState error={error} />{message && <p role="status" className="mt-3 text-sm text-accent-dark">{message}</p>}
    </section>
    <section className={panelClass}><AdminAuditTrail online={online} /></section>
  </div>
}
