import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useSystem } from '../../context/SystemContext'
import { api, formatTime, sourceLabel, useApiPoll } from '../../lib/api'
import type { Alert, Device, Flow } from '../../lib/api'
import { DeviceCards, FlowTable, panelClass, RequestState } from '../../components/LiveTelemetry'
import { XaiPreviewModal } from '../../components/XaiPreviewModal'

export function DashboardPage() {
  const { status, online, rates, refresh } = useSystem()
  const flows = useApiPoll<{ flows: Flow[] }>('/api/flows?limit=10')
  const devices = useApiPoll<{ devices: Device[] }>('/api/devices')
  const alerts = useApiPoll<{ logs: Alert[] }>('/api/threat-logs?limit=20')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [notice, setNotice] = useState<Alert | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [message, setMessage] = useState('')
  const [clearing, setClearing] = useState(false)
  const previousAlert = useRef<string | null | undefined>(undefined)
  const latest = alerts.data?.logs[0] || null
  useEffect(() => {
    if (!alerts.data || alerts.error) return
    const id = alerts.data.logs[0]?.id || null
    if (previousAlert.current !== undefined && id && id !== previousAlert.current) setNotice(alerts.data.logs[0])
    previousAlert.current = id
  }, [alerts.data, alerts.error])
  useEffect(() => {
    if (!notice) return
    const timer = setTimeout(() => setNotice(null), 9000)
    return () => clearTimeout(timer)
  }, [notice])
  async function clear() {
    const prompt = 'Delete all saved alerts and reset counters? Stored network flows and device history are retained.'
    if (!window.confirm(prompt)) return
    setClearing(true); setActionError(null); setMessage('')
    try {
      await api('/api/clear', { method: 'POST', body: JSON.stringify({ scope: 'all' }) })
      setSelected(null); setNotice(null); previousAlert.current = undefined
      setMessage('Alerts and counters reset. Stored flows retained.')
      refresh(); alerts.refresh(); flows.refresh(); devices.refresh()
    } catch (error) { setActionError(error instanceof Error ? error.message : 'Reset failed.') }
    finally { setClearing(false) }
  }
  const live = online && !!status?.is_hardware_live
  const latestRate = rates.at(-1) ?? null
  const rateMax = Math.max(1, ...rates)
  const cards = [
    ['Live Flows Received', status?.processed_flows.toLocaleString() ?? '—', 'Flow windows since counter reset or backend restart'],
    ['Alerts Recorded', status?.threats_detected.toLocaleString() ?? '—', 'Saved alerts across live, simulation and older records'],
    ['Backend Host CPU', online && status?.cpu_usage != null ? `${status.cpu_usage.toFixed(1)}%` : '—', 'CPU of the environment running the backend'],
    ['Backend Host Memory', online && status?.memory_usage != null ? `${status.memory_usage.toFixed(1)}%` : '—', 'Host memory usage; not Pi memory or packet buffers'],
  ]
  return <div className="space-y-6">
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div><h1 className="text-3xl font-bold">Overview & AI Analysis</h1><p className="mt-2 text-sm text-text-muted">Observed IoT flows, model status, and recorded alerts.</p></div>
      <div className="flex flex-wrap gap-2">
        <button disabled={clearing || !online} onClick={() => void clear()} className="rounded-xl border border-rose-500/40 px-4 py-2 text-xs text-rose-500 disabled:opacity-50">Reset Counters & Alerts</button>
      </div>
    </header>
    <RequestState error={actionError} />{message && <p role="status" className="text-sm text-accent-dark">{message}</p>}
    {!online && status && <p className="text-sm text-amber-600">Counts below are from the last successful status request.</p>}
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{cards.map(([label, value, detail]) => <article key={label} className={panelClass}>
      <h2 className="text-sm font-semibold">{label}</h2><p className="my-4 text-3xl font-bold">{value}</p><p className="text-xs text-text-muted">{detail}</p>
    </article>)}</div>
    <div className="flex flex-wrap gap-3 text-xs text-text-muted">
      <span>Live alerts: {status?.alert_counts.live_hardware ?? '—'}</span>
      <span>Connection: {online ? status?.node_status ?? (live ? 'Pi connected' : 'Waiting for Pi') : 'Offline'}</span>
      <span>RF: {online ? status?.rf_online ? 'enabled and loaded' : 'inactive' : 'unknown'}</span>
      <span>CNN: {online ? status?.cnn_online ? 'enabled and loaded' : 'inactive' : 'unknown'}</span>
    </div>
    {status?.engine_error && <RequestState error={`Inference issue: ${status.engine_error}`} />}
    {status?.ingest_error && <RequestState error={status.ingest_error} />}
    {!!status?.inference_errors && <p className="text-sm text-amber-600">Live inference failures since reset: {status.inference_errors}. Received-flow counts include these unclassified flows.</p>}
    <section className={panelClass}>
      <h2 className="text-lg font-semibold">Live Flow Arrival Rate</h2><p className="mt-1 text-xs text-text-muted">Flow windows per second between status samples. Up to 10 intervals; gaps in received flows are normal.</p>
      {live && rates.length > 0 ? <>
        <div className="mt-5 flex h-32 items-end gap-2" role="img" aria-label={`Live flow rates: ${rates.map(value => value.toFixed(2)).join(', ')} flows per second`}>
          {rates.map((rate, index) => <div key={index} className="flex h-full flex-1 flex-col justify-end" title={`${rate.toFixed(2)} flows/s`}><div className="rounded-t bg-accent" style={{ height: `${rate / rateMax * 100}%` }} /></div>)}
        </div><p className="mt-2 text-xs text-text-muted">Latest: {latestRate?.toFixed(2)} flows/s · scale maximum: {rateMax.toFixed(2)} flows/s</p>
      </> : <p className="py-8 text-sm text-text-muted">{live ? 'Waiting for two live counter samples.' : 'Live measurements appear when the backend confirms the Pi connection.'}</p>}
      <p className="mt-3 text-sm">{!online ? 'Backend unavailable.' : !live ? (status?.node_status === 'Pi disconnected' ? 'Pi disconnected. Retaining last recorded observations while waiting to reconnect.' : 'Waiting for Pi sensor connection...') : latestRate === 0 ? 'Pi connected; no additional flow windows in the latest interval.' : 'Pi connected. Flow arrivals are measured above.'}</p>
      <p className="mt-1 text-xs text-text-muted">Last live flow: {formatTime(status?.last_flow_at)}</p>
    </section>
    <section className={panelClass}><h2 className="mb-2 text-lg font-semibold">Observed IoT Devices</h2><p className="mb-4 text-xs text-text-muted">Identity and last observation from saved live flows. Stored totals persist across counter resets; a quiet device is not necessarily offline.</p>
      <RequestState error={devices.error} loading={devices.loading} /><DeviceCards devices={devices.data?.devices || []} />
    </section>
    <section className={panelClass}><div className="mb-3 flex items-center justify-between"><h2 className="text-lg font-semibold">Recent Live Flows</h2><Link className="text-xs text-accent-dark" to="/network-graph">View connections</Link></div>
      <p className="mb-3 text-xs text-text-muted">Latest 10 saved windows, including benign traffic. RF/CNN values are attack scores; confidence refers to the predicted class.</p>
      <RequestState error={flows.error} loading={flows.loading} /><FlowTable flows={flows.data?.flows || []} />
    </section>
    <section className={panelClass}><h2 className="mb-3 text-lg font-semibold">Latest Saved Alert</h2>
      <RequestState error={alerts.error} loading={alerts.loading} />
      {latest ? <div><p className="font-semibold">{latest.attack_type}</p><p className="my-2 text-sm text-text-muted">{sourceLabel(latest.data_source)} · {formatTime(latest.timestamp)} · {latest.source_ip} → {latest.dest_ip}</p>
        <button onClick={() => setSelected(latest)} className="rounded-lg border border-border px-3 py-2 text-xs">View recorded explanation</button></div>
        : <p className="text-sm text-text-muted">No saved alerts. Benign flows still appear in Recent Live Flows.</p>}
      <Link to="/threat-logs" className="mt-4 inline-block text-xs text-accent-dark">Open all threat logs</Link>
    </section>
    {notice && <div role="status" className="fixed bottom-5 right-5 z-30 max-w-sm rounded-xl border border-rose-500/40 bg-surface p-4 shadow-xl"><p className="font-semibold">New recorded alert</p><p className="text-xs">{sourceLabel(notice.data_source)} · {notice.attack_type}</p><button className="mt-2 text-xs text-accent-dark" onClick={() => { setSelected(notice); setNotice(null) }}>Review alert</button><button aria-label="Dismiss alert notification" className="ml-4 text-xs" onClick={() => setNotice(null)}>Dismiss</button></div>}
    {selected && <XaiPreviewModal alert={selected} onClose={() => setSelected(null)} />}
  </div>
}
