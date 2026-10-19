import { useMemo, useState } from 'react'
import { formatTime, useApiPoll } from '../../lib/api'
import type { Device, Flow } from '../../lib/api'
import { DeviceCards, FlowTable, panelClass, RequestState } from '../../components/LiveTelemetry'

export function NetworkGraphPage() {
  const flowPoll = useApiPoll<{ flows: Flow[] }>('/api/flows?limit=100')
  const devicePoll = useApiPoll<{ devices: Device[] }>('/api/devices')
  const [selected, setSelected] = useState<string | null>(null)
  const graph = useMemo(() => {
    const flows = flowPoll.data?.flows || []
    const addresses = [...new Set(flows.flatMap(flow => [flow.src_ip, flow.dst_ip]))].sort()
    const shown = addresses.slice(0, 20)
    const nodes = shown.map((ip, index) => {
      const angle = index / Math.max(1, shown.length) * Math.PI * 2 - Math.PI / 2
      return { ip, x: 400 + 300 * Math.cos(angle), y: 240 + 175 * Math.sin(angle) }
    })
    const edges = new Map<string, { src: string; dst: string; windows: number; alert: boolean }>()
    for (const flow of flows) {
      if (!shown.includes(flow.src_ip) || !shown.includes(flow.dst_ip)) continue
      const key = [flow.src_ip, flow.dst_ip].sort().join('|')
      const old = edges.get(key)
      edges.set(key, { src: flow.src_ip, dst: flow.dst_ip, windows: (old?.windows || 0) + 1, alert: !!old?.alert || !!flow.is_anomaly })
    }
    return { nodes, edges: [...edges.values()], omitted: addresses.length - shown.length }
  }, [flowPoll.data])
  const related = (flowPoll.data?.flows || []).filter(flow => flow.src_ip === selected || flow.dst_ip === selected)
  const devices = devicePoll.data?.devices || []
  const selectedDevice = devices.find(device => device.last_ip === selected)
  return <div className="space-y-6">
    <header><h1 className="text-3xl font-bold">Observed Network Connections</h1><p className="mt-2 text-sm text-text-muted">Connections in the latest 100 saved live flow windows, including benign traffic. This is an observation graph, not the physical switch topology.</p></header>
    <RequestState error={flowPoll.error} loading={flowPoll.loading} />
    <div className="grid gap-5 xl:grid-cols-3"><section className={`${panelClass} xl:col-span-2`}>
      {graph.nodes.length ? <svg viewBox="0 0 800 480" className="w-full" role="img" aria-label="Connections between observed IP addresses with shape and pattern indicators">
        {graph.edges.map(edge => {
          const from = graph.nodes.find(node => node.ip === edge.src)!
          const to = graph.nodes.find(node => node.ip === edge.dst)!
          const midX = (from.x + to.x) / 2
          const midY = (from.y + to.y) / 2
          return <g key={`${edge.src}-${edge.dst}`}>
            <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
              stroke={edge.alert ? '#f43f5e' : '#64748b'}
              strokeWidth={Math.min(5, 1.5 + edge.windows / 10)}
              strokeDasharray={edge.alert ? '6 3' : undefined}
              opacity={edge.alert ? '0.9' : '0.5'}>
              <title>{edge.src} ↔ {edge.dst}: {edge.windows} flow windows {edge.alert ? '(ALERT QUALIFIED)' : '(Normal)'}</title>
            </line>
            {edge.alert && <g transform={`translate(${midX}, ${midY})`}>
              <polygon points="0,-7 7,0 0,7 -7,0" fill="#f43f5e" stroke="#ffffff" strokeWidth="1" />
              <text y="3" textAnchor="middle" fill="#ffffff" fontSize="9" fontWeight="bold">!</text>
              <title>Alert criteria met on this link</title>
            </g>}
          </g>
        })}
        {graph.nodes.map(node => {
          const device = devices.find(item => item.last_ip === node.ip)
          return <g key={node.ip} role="button" tabIndex={0} aria-label={`Inspect ${node.ip}`} onClick={() => setSelected(node.ip)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelected(node.ip) } }} className="cursor-pointer">
            {device ? (
              <rect x={node.x - 16} y={node.y - 16} width="32" height="32" rx="6"
                fill="#14b8a6" stroke={selected === node.ip ? '#f59e0b' : '#0f766e'} strokeWidth={selected === node.ip ? '4' : '2'} />
            ) : (
              <circle cx={node.x} cy={node.y} r="12"
                fill="#64748b" stroke={selected === node.ip ? '#f59e0b' : '#475569'} strokeWidth={selected === node.ip ? '4' : '2'} />
            )}
            {device && <text x={node.x} y={node.y + 4} textAnchor="middle" fill="#ffffff" fontSize="10" fontWeight="bold" pointerEvents="none">IoT</text>}
            <text x={node.x} y={node.y + 28} textAnchor="middle" fill="currentColor" fontSize="11" fontWeight={device ? 'bold' : 'normal'}>
              {node.ip}{device ? ' [IoT]' : ''}
            </text>
            <title>{device ? `IoT Device: ${device.device_name?.replace(/_/g, ' ') || 'Unnamed'}` : 'External / Observed Endpoint'}</title>
          </g>
        })}
      </svg> : <p className="py-12 text-sm text-text-muted">Waiting for saved live flows.</p>}
      <div className="mt-4 rounded-lg border border-border/60 bg-surface/40 p-3 text-xs text-text-muted">
        <p className="font-semibold text-text mb-2">Accessibility Legend (shapes, patterns & colors):</p>
        <div className="flex flex-wrap gap-4 items-center">
          <span className="inline-flex items-center gap-1.5"><span className="inline-flex h-4 w-4 items-center justify-center rounded bg-[#14b8a6] text-[9px] font-bold text-white">IoT</span> <strong className="text-text">Rounded Square:</strong> Monitored IoT Device</span>
          <span className="inline-flex items-center gap-1.5"><span className="inline-block h-3.5 w-3.5 rounded-full bg-[#64748b]" /> <strong className="text-text">Circle:</strong> Other Observed Endpoint</span>
          <span className="inline-flex items-center gap-1.5"><span className="inline-block w-6 border-t-2 border-dashed border-[#f43f5e]" /><span className="text-rose-500 font-bold">!</span> <strong className="text-text">Dashed Red Line + Diamond:</strong> Alert Traffic</span>
          <span className="inline-flex items-center gap-1.5"><span className="inline-block w-6 border-t-2 border-solid border-[#64748b]" /> <strong className="text-text">Solid Line:</strong> Benign / Normal Traffic</span>
        </div>
      </div>
      {graph.omitted > 0 && <p className="mt-2 text-xs text-text-muted">{graph.omitted} additional addresses are omitted from the diagram; their records remain in the table.</p>}
    </section><section className={panelClass}><h2 className="text-lg font-semibold">Selected Endpoint</h2>
      {selected ? <div className="mt-4 space-y-3 text-sm"><p className="font-mono break-all">{selected}</p><p>{selectedDevice?.device_name?.replace(/_/g, ' ') || 'Observed address; device identity unconfirmed'}</p>
        <p>{related.length} windows in the displayed sample</p><p className="text-xs text-text-muted">Last observation in this sample: {formatTime(related[0]?.timestamp)}</p><p className="text-xs text-text-muted">Traffic is passively monitored. No connection blocking is performed.</p></div>
        : <p className="mt-4 text-sm text-text-muted">Select an address in the graph.</p>}
    </section></div>
    <section className={panelClass}><h2 className="mb-4 text-lg font-semibold">Observed Devices</h2><RequestState error={devicePoll.error} loading={devicePoll.loading} /><DeviceCards devices={devices} /></section>
    <section className={panelClass}><h2 className="mb-4 text-lg font-semibold">Saved Live Flow Windows</h2><FlowTable flows={flowPoll.data?.flows || []} /></section>
  </div>
}
