import type { Device, Flow } from '../lib/api'
import { formatTime, percent } from '../lib/api'

export const panelClass = 'rounded-2xl bg-surface border border-border/70 p-5 shadow-sm'

export function RequestState({ error, loading }: { error: string | null; loading?: boolean }) {
  if (error) return <p role="alert" className="my-3 rounded-xl border border-amber-500/40 p-3 text-sm text-amber-600 dark:text-amber-300">{error} Any displayed records are from the last successful request.</p>
  if (loading) return <p className="my-3 text-sm text-text-muted">Loading…</p>
  return null
}

export function DeviceCards({
  devices,
  onResetDevice,
  onRemoveDevice,
  resettingMac,
  removingMac,
}: {
  devices: Device[]
  onResetDevice?: (mac: string, name: string) => void
  onRemoveDevice?: (mac: string, name: string) => void
  resettingMac?: string | null
  removingMac?: string | null
}) {
  if (!devices.length) return <p className="text-sm text-text-muted">No device flows recorded with device identity yet. Keep sentrix_sensor.py running and wait for a flow window to arrive.</p>
  return <div className="grid gap-4 md:grid-cols-2">{devices.map(device => {
    const isBusy = resettingMac === device.device_mac || removingMac === device.device_mac
    return <article key={device.device_mac} className="rounded-xl border border-border bg-background-soft p-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="font-semibold text-text">{device.device_name?.replace(/_/g, ' ') || 'Observed device'}</h3>
          <p className="mt-1 font-mono text-xs text-text-muted">{device.device_mac}</p>
        </div>
        <div className="flex items-center gap-1.5">
          {onResetDevice && (
            <button
              disabled={isBusy}
              onClick={() => onResetDevice(device.device_mac, device.device_name?.replace(/_/g, ' ') || device.device_mac)}
              className="rounded-lg border border-amber-500/30 px-2 py-1 text-xs text-amber-600 dark:text-amber-400 hover:bg-amber-500/10 disabled:opacity-50"
              title={`Reset flow counts for ${device.device_name || device.device_mac} (keep device)`}
            >
              {resettingMac === device.device_mac ? 'Resetting…' : 'Reset'}
            </button>
          )}
          {onRemoveDevice && (
            <button
              disabled={isBusy}
              onClick={() => onRemoveDevice(device.device_mac, device.device_name?.replace(/_/g, ' ') || device.device_mac)}
              className="rounded-lg border border-rose-500/30 px-2 py-1 text-xs text-rose-500 hover:bg-rose-500/10 disabled:opacity-50"
              title={`Remove ${device.device_name || device.device_mac} completely (unenroll and clear flows)`}
            >
              {removingMac === device.device_mac ? 'Removing…' : 'Remove'}
            </button>
          )}
        </div>
      </div>
      <p className="mt-3 text-sm">Last address: <span className="font-mono">{device.last_ip}</span></p>
      <p className="text-sm">Stored flows: {device.flow_count.toLocaleString()} · Packets in those flows: {device.packet_count.toLocaleString()}</p>
      <p className="mt-2 text-xs text-text-muted">Last observed: {formatTime(device.last_seen)}</p>
    </article>
  })}</div>
}

export function FlowTable({ flows }: { flows: Flow[] }) {
  if (!flows.length) return <p className="text-sm text-text-muted">No live flow records available yet.</p>
  return <div className="overflow-x-auto"><table className="w-full text-left text-xs">
    <thead className="text-text-muted"><tr>{[
      { label: 'Time', tip: '' },
      { label: 'Device / endpoints', tip: '' },
      { label: 'Protocol', tip: '' },
      { label: 'Packets', tip: '' },
      { label: 'Prediction', tip: '' },
      { label: 'Confidence', tip: 'Confidence is the model’s estimated attack probability for this flow. Flows scoring at or above the alert threshold — currently 0.50, adjustable in Settings — are recorded as alerts. A high score means the flow strongly resembled attack traffic in the model’s training data; it is not a verified attack.' },
      { label: 'RF / CNN attack scores', tip: '' },
      { label: 'Model', tip: '' },
    ].map(({ label, tip }) => <th className="p-3 whitespace-nowrap" key={label} title={tip || undefined}>{label}{tip && <span className="ml-1 cursor-help text-text-muted" aria-label={tip}>ⓘ</span>}</th>)}</tr></thead>
    <tbody>{flows.map(flow => <tr key={flow.id} className="border-t border-border/60">
      <td className="p-3 whitespace-nowrap">{formatTime(flow.timestamp)}</td>
      <td className="p-3"><p className="font-medium">{flow.device_name?.replace(/_/g, ' ') || flow.sensor_id}</p><p className="font-mono whitespace-nowrap text-text-muted">{flow.src_ip}:{flow.src_port ?? '—'} → {flow.dst_ip}:{flow.dst_port ?? '—'}</p></td>
      <td className="p-3">{flow.proto}</td><td className="p-3">{flow.src_pkts + flow.dst_pkts}</td>
      <td className="p-3"><span className={flow.prediction === 1 ? (flow.is_anomaly === 1 ? 'text-rose-500 font-medium' : 'text-amber-500') : flow.prediction === 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-500'} title={flow.prediction == null ? 'Unavailable means this data was not recorded for the flow — not that the value was zero or normal. Older records may predate the feature; live flows may lack data the sensor could not extract.' : undefined}>{flow.prediction == null ? 'Unavailable' : flow.prediction === 1 ? (flow.is_anomaly === 1 ? 'Attack' : 'Attack (Suppressed)') : 'Benign'}</span>{flow.inference_error && <p className="mt-1 max-w-xs text-amber-600">{flow.inference_error}</p>}{flow.is_anomaly === 1 && <p className="text-xs text-rose-500/80 mt-0.5">Alert criteria met</p>}</td>
      <td className="p-3">{percent(flow.confidence)}</td><td className="p-3 whitespace-nowrap">{percent(flow.p_rf)} / {percent(flow.p_cnn)}</td>
      <td className="p-3">{flow.model_used} · {flow.execution_mode || 'Unknown mode'}</td>
    </tr>)}</tbody></table></div>
}
