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
  function escapeHtml(str?: string | null) {
    if (!str) return ''
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
  }

  function exportCsv() {
    const quote = (value: unknown) => {
      const text = String(value ?? '')
      // Keep exported text as text when opened in a spreadsheet.
      return `"${(/^[=+\-@\t\r]/.test(text) ? "'" + text : text).replace(/"/g, '""')}"`
    }
    const headers = [
      'Timestamp (UTC)',
      'Origin',
      'Device Name',
      'Device MAC',
      'Source IP',
      'Destination IP',
      'Alert Label',
      'Label Source',
      'Confidence',
      'Threat Level',
      'Model Domain',
      'Execution Mode',
      'XAI Narrative Explanation',
      'Top LIME Contributing Features',
      'Top SHAP Contributing Features',
      'Alert ID',
      'Flow ID'
    ]
    const rows: unknown[][] = [headers]
    filtered.forEach(row => {
      const limeStr = (row.lime_values || [])
        .map(f => `${f.f}: ${f.v >= 0 ? '+' : ''}${f.v.toFixed(4)}`)
        .join('; ')
      const shapStr = (row.shap_values || [])
        .map(f => `${f.f}: ${f.v >= 0 ? '+' : ''}${f.v.toFixed(4)}`)
        .join('; ')
      rows.push([
        row.timestamp,
        sourceLabel(row.data_source),
        row.device_name || '—',
        row.device_mac || '—',
        row.source_ip,
        row.dest_ip,
        row.attack_type,
        row.attack_type_source || 'unknown',
        (row.confidence * 100).toFixed(2) + '%',
        row.threat_level,
        row.model_type,
        row.execution_mode,
        row.explanation_meta?.reason || 'No narrative generated',
        limeStr || '—',
        shapStr || '—',
        row.id,
        row.flow_id || '—'
      ])
    })
    const url = URL.createObjectURL(new Blob([rows.map(row => row.map(quote).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `sentrix-threat-intelligence-${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  function exportJson() {
    const dataStr = JSON.stringify(filtered, null, 2)
    const url = URL.createObjectURL(new Blob([dataStr], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `sentrix-threat-intelligence-${new Date().toISOString().slice(0, 10)}.json`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  function exportPrintableReport() {
    const printWindow = window.open('', '_blank')
    if (!printWindow) {
      alert('Please allow popups to open the printable incident report.')
      return
    }
    const typeCounts: Record<string, number> = {}
    const levelCounts: Record<string, number> = {}
    filtered.forEach(r => {
      typeCounts[r.attack_type] = (typeCounts[r.attack_type] || 0) + 1
      levelCounts[r.threat_level] = (levelCounts[r.threat_level] || 0) + 1
    })

    const rowsHtml = filtered.map(row => `
      <tr>
        <td style="font-family: monospace; font-size: 10px; white-space: nowrap;">${formatTime(row.timestamp)}</td>
        <td>
          <span style="font-weight: 600;">${escapeHtml(row.device_name || 'Generic Device')}</span><br/>
          <span style="font-family: monospace; font-size: 10px; color: #475569;">${row.source_ip} &rarr; ${row.dest_ip}</span>
        </td>
        <td>
          <strong>${escapeHtml(row.attack_type)}</strong>
          <div style="font-size: 9.5px; color: #64748b;">${escapeHtml(row.attack_type_source || 'hybrid_assessment')}</div>
        </td>
        <td style="white-space: nowrap;">
          <strong>${(row.confidence * 100).toFixed(1)}%</strong>
          <div style="margin-top: 2px;"><span class="badge ${row.threat_level.toLowerCase()}">${row.threat_level}</span></div>
        </td>
        <td style="font-size: 10px; white-space: nowrap;">
          ${row.model_type}<br/>
          <span style="color: #64748b;">(${row.execution_mode})</span>
        </td>
        <td style="font-size: 10.5px; line-height: 1.4; max-width: 440px;">
          ${row.explanation_meta?.reason ? `
            <div class="xai-box">
              ${escapeHtml(row.explanation_meta.reason)}
            </div>` : '<div style="color: #94a3b8; font-style: italic; font-size: 10px;">No natural-language narrative generated</div>'}
          ${row.lime_values && row.lime_values.length > 0 ? `
            <div style="margin-top: 3px;">
              <span style="font-size: 9px; font-weight: 700; color: #475569; margin-right: 3px;">LIME:</span>
              ${row.lime_values.slice(0, 3).map(f => `
                <span class="chip ${f.v >= 0 ? 'chip-pos' : 'chip-neg'}">
                  ${escapeHtml(f.f.replace(/_/g, ' '))}: ${f.v >= 0 ? '+' : ''}${f.v.toFixed(3)}
                </span>
              `).join('')}
            </div>` : ''}
          ${row.shap_values && row.shap_values.length > 0 ? `
            <div style="margin-top: 3px;">
              <span style="font-size: 9px; font-weight: 700; color: #475569; margin-right: 3px;">SHAP:</span>
              ${row.shap_values.slice(0, 3).map(f => `
                <span class="chip chip-shap">
                  ${escapeHtml(f.f.replace(/_/g, ' '))}: ${f.v >= 0 ? '+' : ''}${f.v.toFixed(3)}
                </span>
              `).join('')}
            </div>` : ''}
        </td>
      </tr>
    `).join('')

    const docHtml = `<!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8" />
        <title>SENTRi-X Threat Intelligence & Incident Report</title>
        <style>
          @page { size: landscape; margin: 10mm; }
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; padding: 14px; font-size: 11px; }
          .header { border-bottom: 2px solid #0f172a; padding-bottom: 10px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: flex-end; }
          .title { font-size: 18px; font-weight: 700; color: #0f172a; margin: 0 0 3px 0; }
          .subtitle { font-size: 11px; color: #64748b; margin: 0; }
          .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px; margin-bottom: 14px; font-size: 11px; }
          .meta-item strong { display: block; color: #475569; font-size: 10px; text-transform: uppercase; margin-bottom: 2px; }
          .stats-grid { display: flex; gap: 12px; margin-bottom: 14px; }
          .stat-card { flex: 1; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px; background: #ffffff; }
          .stat-card h4 { margin: 0 0 4px 0; font-size: 10px; text-transform: uppercase; color: #64748b; }
          .stat-pills { display: flex; flex-wrap: wrap; gap: 6px; }
          .pill { font-size: 10px; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; border: 1px solid #cbd5e1; }
          table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 10.5px; }
          th { background: #f1f5f9; color: #334155; text-align: left; padding: 6px 8px; border: 1px solid #cbd5e1; font-weight: 600; white-space: nowrap; }
          td { padding: 6px 8px; border: 1px solid #e2e8f0; vertical-align: top; }
          tr:nth-child(even) { background: #fafafa; }
          .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-weight: 600; font-size: 10px; }
          .badge.critical { background: #ffe4e6; color: #e11d48; border: 1px solid #fecdd3; }
          .badge.high { background: #ffedd5; color: #ea580c; border: 1px solid #fed7aa; }
          .badge.medium { background: #fef3c7; color: #d97706; border: 1px solid #fde68a; }
          .badge.low { background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }
          .xai-box { background: #f8fafc; border-left: 3px solid #0284c7; padding: 5px 8px; margin-bottom: 4px; border-radius: 0 4px 4px 0; font-size: 10px; color: #334155; line-height: 1.4; }
          .chip { display: inline-block; font-size: 9px; padding: 1px 5px; border-radius: 3px; font-family: monospace; margin-right: 4px; margin-bottom: 2px; }
          .chip-pos { background: #ffe4e6; color: #be123c; border: 1px solid #fecdd3; }
          .chip-neg { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
          .chip-shap { background: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; }
          .disclaimer { margin-top: 16px; border-top: 1px solid #e2e8f0; padding-top: 8px; font-size: 9.5px; color: #64748b; line-height: 1.4; }
          .no-print { margin-bottom: 14px; }
          @media print {
            .no-print { display: none; }
            body { padding: 0; }
            tr { page-break-inside: avoid; }
          }
        </style>
      </head>
      <body>
        <div class="no-print" style="background: #eff6ff; border: 1px solid #bfdbfe; padding: 10px 14px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center;">
          <span><strong>Executive Threat & XAI Dossier:</strong> Ready for printing or export to PDF.</span>
          <button onclick="window.print()" style="background: #2563eb; color: #fff; border: none; padding: 6px 14px; border-radius: 4px; font-weight: bold; cursor: pointer;">Print / Save as PDF</button>
        </div>
        <div class="header">
          <div>
            <h1 class="title">SENTRi-X Edge NIDS — Threat Intelligence & XAI Report</h1>
            <p class="subtitle">Generated on ${new Date().toUTCString()} · Explainable Threat Incident Dossier</p>
          </div>
        </div>
        <div class="meta-grid">
          <div class="meta-item"><strong>Report Scope</strong>${filtered.length} alert records</div>
          <div class="meta-item"><strong>Active Filter</strong>Query: "${query || 'None'}", Origin: ${source}</div>
          <div class="meta-item"><strong>Confidence Filter</strong>&ge; ${confidence}%</div>
          <div class="meta-item"><strong>Classification Threshold</strong>0.50 (Standard operating point)</div>
        </div>
        <div class="stats-grid">
          <div class="stat-card">
            <h4>Attacks by Category</h4>
            <div class="stat-pills">
              ${Object.entries(typeCounts).map(([k, v]) => `<span class="pill"><strong>${escapeHtml(k)}:</strong> ${v}</span>`).join('')}
            </div>
          </div>
          <div class="stat-card">
            <h4>Severity Breakdown</h4>
            <div class="stat-pills">
              ${Object.entries(levelCounts).map(([k, v]) => `<span class="pill"><strong>${k}:</strong> ${v}</span>`).join('')}
            </div>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Device & Endpoints</th>
              <th>Alert Label</th>
              <th>Confidence</th>
              <th>Model (Mode)</th>
              <th>XAI Assessment & Feature Attribution</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
        <div class="disclaimer">
          <strong>Notice:</strong> Alert records represent flow windows evaluated by machine learning models that exceeded the alert threshold. High confidence indicates strong resemblance to training attack patterns and does not guarantee verified malicious compromise. Ground-truth verification requires correlation with host-level event logs.
        </div>
      </body>
      </html>`
    printWindow.document.open()
    printWindow.document.write(docHtml)
    printWindow.document.close()
  }

  return <div className="space-y-5">
    <header><h1 className="text-3xl font-bold">Threat Logs</h1><p className="mt-2 text-sm text-text-muted">Latest 500 saved alerts, newest first. Live hardware and historical records retain their origin. Benign flows are shown on the dashboard.</p></header>
    <section className="rounded-xl border border-border/50 bg-surface/50 p-4 text-xs text-text-muted leading-relaxed">
      <p className="font-medium text-text mb-1">How a flow becomes what you see here, in three stages:</p>
      <p><span className="font-medium text-text">(1) Classification</span> — every captured flow is scored by the active model.</p>
      <p className="mt-1"><span className="font-medium text-text">(2) Alert</span> — flows scoring at or above the threshold are recorded as alerts and appear here.</p>
      <p className="mt-1"><span className="font-medium text-text">(3) Suppression</span> — alerts matching your whitelist rules (destination IP, domain, or device and port) are still classified and stored, but shown as ‘Attack (Suppressed)’ instead of raising notifications. Suppressed does not mean benign — it means you told the system to stay quiet about this traffic.</p>
    </section>
    <div className="flex flex-wrap gap-3 items-end text-xs">
      <label className="flex flex-col gap-1">Search<input value={query} onChange={event => setQuery(event.target.value)} placeholder="Device, address, model or label" className="rounded-lg border border-border bg-surface px-3 py-2" /></label>
      <label className="flex flex-col gap-1">Origin<select value={source} onChange={event => setSource(event.target.value)} className="rounded-lg border border-border bg-surface px-3 py-2"><option value="all">All origins</option><option value="live_hardware">Live hardware</option><option value="simulation">Simulation</option><option value="unknown">Origin unknown</option></select></label>
      <label className="flex flex-col gap-1">Alert label<select value={attack} onChange={event => setAttack(event.target.value)} className="rounded-lg border border-border bg-surface px-3 py-2"><option value="all">All labels</option>{types.map(type => <option key={type}>{type}</option>)}</select></label>
      <label className="flex flex-col gap-1">Minimum confidence: {confidence}%<input type="range" min="0" max="100" value={confidence} onChange={event => setConfidence(Number(event.target.value))} /></label>
      <button onClick={() => { setQuery(''); setSource('all'); setAttack('all'); setConfidence(0) }} className="rounded-lg border border-border px-3 py-2">Reset filters</button>
      <div className="flex flex-wrap gap-2">
        <button disabled={!filtered.length} onClick={exportCsv} title="Export CSV spreadsheet containing all flow metrics, natural language explanations, and LIME/SHAP feature weights" className="rounded-lg bg-accent px-3 py-2 text-white font-medium hover:bg-accent/90 disabled:opacity-50">Export CSV (with XAI)</button>
        <button disabled={!filtered.length} onClick={exportPrintableReport} title="Open printable executive dossier with explanations, feature badges, and direct Save to PDF" className="rounded-lg border border-accent/40 bg-accent/10 text-accent-dark px-3 py-2 font-medium hover:bg-accent/20 disabled:opacity-50">Export PDF / Print Dossier</button>
        <button disabled={!filtered.length} onClick={exportJson} title="Export complete structured JSON payload with full model and XAI metadata" className="rounded-lg border border-border bg-surface px-3 py-2 text-text font-medium hover:bg-surface/80 disabled:opacity-50">Export JSON</button>
      </div>
    </div>
    <RequestState error={logs.error} loading={logs.loading} />
    <p className="text-xs text-text-muted">Showing {filtered.length} of {logs.data?.logs.length || 0} retrieved alerts. Older records may have unknown origin or explanation method.</p>
    <div className={`${panelClass} overflow-x-auto`}><table className="w-full text-left text-xs"><thead><tr>{[
      { label: 'Time', tip: '' },
      { label: 'Origin / device', tip: '' },
      { label: 'Endpoints', tip: '' },
      { label: 'Alert label', tip: '' },
      { label: 'Confidence', tip: 'Confidence is the model’s estimated attack probability for this flow. Flows scoring at or above the alert threshold — currently 0.50, adjustable in Settings — are recorded as alerts. A high score means the flow strongly resembled attack traffic in the model’s training data; it is not a verified attack.' },
      { label: 'Category', tip: '' },
      { label: 'Review', tip: '' },
    ].map(({ label, tip }) => <th key={label} className="p-3 whitespace-nowrap" title={tip || undefined}>{label}{tip && <span className="ml-1 cursor-help text-text-muted" aria-label={tip}>ⓘ</span>}</th>)}</tr></thead>
      <tbody>{filtered.map(row => <tr key={row.id} className="border-t border-border"><td className="p-3 whitespace-nowrap">{formatTime(row.timestamp)}</td><td className="p-3">{sourceLabel(row.data_source)}<p className="text-text-muted">{row.device_name?.replace(/_/g, ' ')}</p></td>
        <td className="p-3 font-mono whitespace-nowrap">{row.source_ip} → {row.dest_ip}</td><td className="p-3">{row.attack_type}{row.attack_type_source === 'heuristic_behavioral' && <p className="text-xs text-text-muted">Heuristic assessment · unverified subtype</p>}</td><td className="p-3">{percent(row.confidence)}</td><td className="p-3"><span className={`rounded border px-2 py-1 ${threatLevelTone(row.threat_level)}`}>{row.threat_level}</span></td><td className="p-3"><button onClick={() => setSelected(row)} className="text-accent-dark underline">Explanation</button></td></tr>)}</tbody></table>
      {!filtered.length && !logs.loading && !logs.error && <p className="py-6 text-sm text-text-muted">{logs.data?.logs.length ? 'No alerts match the filters.' : 'No saved alerts. Live traffic may still be arriving normally.'}</p>}
    </div>
    {displayedAlert && <XaiPreviewModal alert={displayedAlert} onClose={() => { setSelected(null); setAutoModal(false) }} />}
  </div>
}

