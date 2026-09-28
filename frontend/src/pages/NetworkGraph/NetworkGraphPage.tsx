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
      {graph.nodes.length ? <svg viewBox="0 0 800 480" className="w-full" role="img" aria-label="Connections between observed IP addresses">
        {graph.edges.map(edge => {
          const from = graph.nodes.find(node => node.ip === edge.src)!
          const to = graph.nodes.find(node => node.ip === edge.dst)!
          return <line key={`${edge.src}-${edge.dst}`} x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke={edge.alert ? '#f43f5e' : '#64748b'} strokeWidth={Math.min(5, 1 + edge.windows / 10)} opacity="0.65"><title>{edge.src} ↔ {edge.dst}: {edge.windows} flow windows</title></line>
        })}
        {graph.nodes.map(node => {
          const device = devices.find(item => item.last_ip === node.ip)
          return <g key={node.ip} role="button" tabIndex={0} aria-label={`Inspect ${node.ip}`} onClick={() => setSelected(node.ip)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelected(node.ip) } }} className="cursor-pointer">
            <circle cx={node.x} cy={node.y} r={device ? 16 : 11} fill={device ? '#14b8a6' : '#64748b'} stroke={selected === node.ip ? '#f59e0b' : 'transparent'} strokeWidth="4" />
            <text x={node.x} y={node.y + 32} textAnchor="middle" fill="currentColor" fontSize="13">{node.ip}</text>
            <title>{device?.device_name?.replace(/_/g, ' ') || 'Observed endpoint'}</title>
          </g>
        })}
      </svg> : <p className="py-12 text-sm text-text-muted">Waiting for saved live flows.</p>}
      <p className="text-xs text-text-muted">Teal: identified IoT device. Gray: other observed address. Red edge: a flow that met the active alert criteria. Node position is for readability.</p>
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
