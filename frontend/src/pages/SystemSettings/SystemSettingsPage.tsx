import { useEffect, useState } from 'react'
import { useSystem } from '../../context/SystemContext'
import { api, DOMAINS, MODES } from '../../lib/api'
import type { Settings } from '../../lib/api'
import { panelClass, RequestState } from '../../components/LiveTelemetry'

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
    <section className={panelClass}><h2 className="mb-4 text-lg font-semibold">Execution Mode</h2><div className="flex flex-wrap gap-3">{MODES.map(mode => <button key={mode.id} disabled={!online || busy || status?.switching} onClick={() => status && void switchEngine(status.current_model, mode.id)} aria-pressed={online && status?.execution_mode === mode.id} className={`rounded-xl border px-4 py-3 text-sm disabled:opacity-50 ${online && status?.execution_mode === mode.id ? 'border-accent bg-accent-soft text-accent-dark' : 'border-border'}`}>{mode.name}</button>)}</div>
      <p className="mt-4 text-xs text-text-muted">RF uses tabular flow features. The 1D CNN processes the ordered 28-feature vector. Hybrid mode averages their attack probabilities.</p>
    </section>
    <section className={panelClass}><h2 className="mb-4 text-lg font-semibold">Model Domain</h2><div className="grid gap-3 sm:grid-cols-2">{DOMAINS.map(domain => <button key={domain.id} disabled={!online || busy || status?.switching} onClick={() => status && void switchEngine(domain.id, status.execution_mode)} aria-pressed={online && status?.current_model === domain.id} className={`rounded-xl border p-4 text-left text-sm disabled:opacity-50 ${online && status?.current_model === domain.id ? 'border-accent bg-accent-soft text-accent-dark' : 'border-border'}`}>{domain.name}</button>)}</div>
      <p className="mt-4 text-xs text-text-muted">A switch is applied only when the requested weights are available. The active selection follows the backend response.</p>
    </section>
    <section className={panelClass}><h2 className="mb-3 text-lg font-semibold">Raspberry Pi Sensor</h2><p className="text-sm">{!online ? 'Backend unavailable' : status?.is_hardware_live ? 'Pi connected' : 'Waiting for a recent Pi heartbeat'}</p>
      <p className="mt-3 text-xs text-text-muted">sentrix_sensor.py captures mirrored traffic and uploads flow windows. A connected Pi can be idle between uploads. Device observations are listed on the dashboard.</p>
    </section>
    <section className={panelClass}><h2 className="mb-3 text-lg font-semibold">Alert Settings</h2>
      <p className="text-sm">Classification boundary: attack probability ≥ 50%.</p>
      <p className="mt-2 text-xs text-text-muted">Saved alert policy: {online && status ? status.settings.active_alerting ? `enabled; attack confidence must exceed ${(status.settings.alert_threshold * 100).toFixed(0)}%` : 'disabled' : 'unavailable'}.</p>
      {draft && <div className="mt-5 space-y-4"><label className="flex items-center gap-3 text-sm"><input type="checkbox" checked={draft.active_alerting} disabled={!online || saving} onChange={event => { setDraft({ ...draft, active_alerting: event.target.checked }); setMessage('') }} />Record alerts for qualifying attack predictions</label>
        <label className="block text-sm">Alert confidence threshold: {(draft.alert_threshold * 100).toFixed(0)}%<input className="mt-3 block w-full max-w-md accent-accent" type="range" min="50" max="99" step="1" value={Math.round(draft.alert_threshold * 100)} disabled={!online || saving} onChange={event => { setDraft({ ...draft, alert_threshold: Number(event.target.value) / 100 }); setMessage('') }} /></label>
        <p className="text-xs text-text-muted">A flow must first be predicted as an attack and then exceed this threshold. Disabling alert recording does not stop capture, inference, or flow storage. Changes apply to live and simulation alerts.</p>
        <button disabled={!online || saving} onClick={() => void save()} className="rounded-xl bg-accent px-4 py-2 text-sm text-white disabled:opacity-50">{saving ? 'Saving…' : 'Save Alert Settings'}</button>
      </div>}
      <RequestState error={error} />{message && <p role="status" className="mt-3 text-sm text-accent-dark">{message}</p>}
    </section>
  </div>
}
