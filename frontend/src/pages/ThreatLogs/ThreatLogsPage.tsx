import { useMemo, useState } from 'react'
import { formatTime, percent, sourceLabel, useApiPoll } from '../../lib/api'
import type { Alert } from '../../lib/api'
import { panelClass, RequestState } from '../../components/LiveTelemetry'
import { XaiPreviewModal } from '../../components/XaiPreviewModal'
import { threatLevelTone } from '../../utils/threatLevel'

export function ThreatLogsPage() {
  const logs = useApiPoll<{ logs: Alert[] }>('/api/threat-logs?limit=500')
  const [query, setQuery] = useState('')
  const [source, setSource] = useState('all')
  const [attack, setAttack] = useState('all')
  const [confidence, setConfidence] = useState(0)
  const [selected, setSelected] = useState<Alert | null>(null)
  const [autoModal, setAutoModal] = useState(() => new URLSearchParams(window.location.search).get('modal') === 'true')
  const displayedAlert = selected || (autoModal ? logs.data?.logs[0] : null)
  const filtered = useMemo(() => (logs.data?.logs || []).filter(row =>
    (source === 'all' || (row.data_source || 'unknown') === source) && (attack === 'all' || row.attack_type === attack) && row.confidence >= confidence / 100 &&
    [row.source_ip, row.dest_ip, row.attack_type, row.device_name, row.timestamp, row.model_type, row.status].some(value => value?.toLowerCase().includes(query.toLowerCase()))
  ), [logs.data, source, attack, confidence, query])
  const types = [...new Set((logs.data?.logs || []).map(row => row.attack_type))]
  function exportCsv() {
    const quote = (value: unknown) => {
      const text = String(value ?? '')
      // Keep exported text as text when opened in a spreadsheet.
      return `"${(/^[=+\-@\t\r]/.test(text) ? "'" + text : text).replace(/"/g, '""')}"`
    }
    const rows: unknown[][] = [['Timestamp', 'Origin', 'Device', 'Source IP', 'Destination IP', 'Alert label', 'Label source', 'Confidence', 'Level', 'Model', 'Mode']]
    filtered.forEach(row => rows.push([row.timestamp, sourceLabel(row.data_source), row.device_name, row.source_ip, row.dest_ip, row.attack_type, row.attack_type_source || 'unknown', row.confidence, row.threat_level, row.model_type, row.execution_mode]))
    const url = URL.createObjectURL(new Blob([rows.map(row => row.map(quote).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }))
    const link = document.createElement('a'); link.href = url; link.download = `sentrix-alerts-${new Date().toISOString().slice(0, 10)}.csv`; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return <div className="space-y-5">
    <header><h1 className="text-3xl font-bold">Threat Logs</h1><p className="mt-2 text-sm text-text-muted">Latest 500 saved alerts, newest first. Live hardware and historical records retain their origin. Benign flows are shown on the dashboard.</p></header>
    <div className="flex flex-wrap gap-3 items-end text-xs">
      <label className="flex flex-col gap-1">Search<input value={query} onChange={event => setQuery(event.target.value)} placeholder="Device, address, model or label" className="rounded-lg border border-border bg-surface px-3 py-2" /></label>
      <label className="flex flex-col gap-1">Origin<select value={source} onChange={event => setSource(event.target.value)} className="rounded-lg border border-border bg-surface px-3 py-2"><option value="all">All origins</option><option value="live_hardware">Live hardware</option><option value="simulation">Simulation</option><option value="unknown">Origin unknown</option></select></label>
      <label className="flex flex-col gap-1">Alert label<select value={attack} onChange={event => setAttack(event.target.value)} className="rounded-lg border border-border bg-surface px-3 py-2"><option value="all">All labels</option>{types.map(type => <option key={type}>{type}</option>)}</select></label>
      <label className="flex flex-col gap-1">Minimum confidence: {confidence}%<input type="range" min="0" max="100" value={confidence} onChange={event => setConfidence(Number(event.target.value))} /></label>
      <button onClick={() => { setQuery(''); setSource('all'); setAttack('all'); setConfidence(0) }} className="rounded-lg border border-border px-3 py-2">Reset filters</button>
      <button disabled={!filtered.length} onClick={exportCsv} className="rounded-lg bg-accent px-3 py-2 text-white disabled:opacity-50">Export displayed rows</button>
    </div>
    <RequestState error={logs.error} loading={logs.loading} />
    <p className="text-xs text-text-muted">Showing {filtered.length} of {logs.data?.logs.length || 0} retrieved alerts. Older records may have unknown origin or explanation method.</p>
    <div className={`${panelClass} overflow-x-auto`}><table className="w-full text-left text-xs"><thead><tr>{['Time', 'Origin / device', 'Endpoints', 'Alert label', 'Confidence', 'Category', 'Review'].map(label => <th key={label} className="p-3 whitespace-nowrap">{label}</th>)}</tr></thead>
      <tbody>{filtered.map(row => <tr key={row.id} className="border-t border-border"><td className="p-3 whitespace-nowrap">{formatTime(row.timestamp)}</td><td className="p-3">{sourceLabel(row.data_source)}<p className="text-text-muted">{row.device_name?.replace(/_/g, ' ')}</p></td>
        <td className="p-3 font-mono whitespace-nowrap">{row.source_ip} → {row.dest_ip}</td><td className="p-3">{row.attack_type}{row.attack_type_source === 'heuristic_behavioral' && <p className="text-xs text-text-muted">Heuristic assessment · unverified subtype</p>}</td><td className="p-3">{percent(row.confidence)}</td><td className="p-3"><span className={`rounded border px-2 py-1 ${threatLevelTone(row.threat_level)}`}>{row.threat_level}</span></td><td className="p-3"><button onClick={() => setSelected(row)} className="text-accent-dark underline">Explanation</button></td></tr>)}</tbody></table>
      {!filtered.length && !logs.loading && !logs.error && <p className="py-6 text-sm text-text-muted">{logs.data?.logs.length ? 'No alerts match the filters.' : 'No saved alerts. Live traffic may still be arriving normally.'}</p>}
    </div>
    {displayedAlert && <XaiPreviewModal alert={displayedAlert} onClose={() => { setSelected(null); setAutoModal(false) }} />}
  </div>
}

