import { useEffect, useMemo, useState } from 'react'
import {
  clearObservedDevices,
  deleteEndpointLabel,
  formatTime,
  removeObservedDevice,
  setEndpointLabel,
  useApiPoll,
} from '../../lib/api'
import type { Device, Flow } from '../../lib/api'
import { DeviceCards, FlowTable, panelClass, RequestState } from '../../components/LiveTelemetry'

interface Destination {
  ip: string
  label: string
  reason?: string
}

export interface EndpointInfo {
  role: 'iot' | 'gateway' | 'sensor' | 'host' | 'cloud' | 'broadcast' | 'endpoint'
  badge: string
  friendlyName: string
  category: string
  color: string
  strokeColor: string
  textColor: string
  isCustom: boolean
}

export function classifyEndpoint(
  ip: string,
  devices: Device[] = [],
  customLabels: Record<string, string> = {},
  whitelistedDests: Destination[] = []
): EndpointInfo {
  // 1. Observed IoT device from sensor telemetry
  const device = devices.find(d => d.last_ip === ip)
  if (device) {
    const rawName = device.device_name?.replace(/_/g, ' ') || 'IoT Device'
    const custom = customLabels[ip]
    return {
      role: 'iot',
      badge: 'IoT',
      friendlyName: custom || rawName,
      category: 'Monitored IoT Device',
      color: '#14b8a6',
      strokeColor: '#0f766e',
      textColor: '#2dd4bf',
      isCustom: !!custom,
    }
  }

  // 2. Custom or predefined label from database
  const custom = customLabels[ip]
  const lowerCustom = (custom || '').toLowerCase()

  // 3. Raspberry Pi Sensor / IDS
  if (
    ip === '192.168.254.184' ||
    lowerCustom.includes('sensor') ||
    lowerCustom.includes('raspy') ||
    lowerCustom.includes('rpi')
  ) {
    return {
      role: 'sensor',
      badge: 'Pi',
      friendlyName: custom || 'Raspberry Pi 3B+ Sensor',
      category: 'Edge IDS Sensor',
      color: '#8b5cf6',
      strokeColor: '#6d28d9',
      textColor: '#a78bfa',
      isCustom: !!custom,
    }
  }

  // 4. Local Gateway / Router
  if (
    ip === '192.168.254.254' ||
    ip.endsWith('.254') ||
    ip.endsWith('.1') ||
    lowerCustom.includes('gateway') ||
    lowerCustom.includes('router')
  ) {
    return {
      role: 'gateway',
      badge: 'GW',
      friendlyName: custom || 'Local Gateway / Router',
      category: 'Network Gateway',
      color: '#06b6d4',
      strokeColor: '#0e7490',
      textColor: '#22d3ee',
      isCustom: !!custom,
    }
  }

  // 5. Defender Workstation / Laptop Host
  if (
    ip === '192.168.254.156' ||
    lowerCustom.includes('defender') ||
    lowerCustom.includes('laptop') ||
    lowerCustom.includes('workstation') ||
    lowerCustom.includes('pc')
  ) {
    return {
      role: 'host',
      badge: 'PC',
      friendlyName: custom || 'Defender Host (Laptop)',
      category: 'Defender / Workstation',
      color: '#3b82f6',
      strokeColor: '#1d4ed8',
      textColor: '#60a5fa',
      isCustom: !!custom,
    }
  }

  // 6. Whitelisted Cloud Destination (e.g. Tuya, AWS, NTP)
  const whitelisted = whitelistedDests.find(w => w.ip === ip)
  if (whitelisted) {
    return {
      role: 'cloud',
      badge: 'Cloud',
      friendlyName: custom || whitelisted.label || 'Whitelisted Cloud Service',
      category: 'Cloud / Remote Broker',
      color: '#0284c7',
      strokeColor: '#0369a1',
      textColor: '#38bdf8',
      isCustom: !!custom,
    }
  }

  // 7. Broadcast / Multicast
  if (ip === '255.255.255.255' || ip.startsWith('224.') || ip.startsWith('239.')) {
    return {
      role: 'broadcast',
      badge: 'BC',
      friendlyName: custom || (ip === '255.255.255.255' ? 'Subnet Broadcast' : 'Multicast Group'),
      category: 'Broadcast / Multicast',
      color: '#94a3b8',
      strokeColor: '#475569',
      textColor: '#cbd5e1',
      isCustom: !!custom,
    }
  }

  // 8. Custom labeled endpoint without a specific category match
  if (custom) {
    return {
      role: 'endpoint',
      badge: 'Node',
      friendlyName: custom,
      category: 'Custom Labeled Endpoint',
      color: '#f59e0b',
      strokeColor: '#b45309',
      textColor: '#fbbf24',
      isCustom: true,
    }
  }

  // 9. External WAN destination
  const isPrivate = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)/.test(ip)
  if (!isPrivate) {
    return {
      role: 'cloud',
      badge: 'WAN',
      friendlyName: 'External Cloud / Remote Host',
      category: 'External Destination',
      color: '#64748b',
      strokeColor: '#475569',
      textColor: '#94a3b8',
      isCustom: false,
    }
  }

  // 10. Default Local Observed Endpoint
  return {
    role: 'endpoint',
    badge: 'Host',
    friendlyName: 'Observed Local Endpoint',
    category: 'Local Network Endpoint',
    color: '#64748b',
    strokeColor: '#475569',
    textColor: '#94a3b8',
    isCustom: false,
  }
}

export function NetworkGraphPage() {
  const flowPoll = useApiPoll<{ flows: Flow[] }>('/api/flows?limit=100')
  const devicePoll = useApiPoll<{ devices: Device[] }>('/api/devices')
  const labelsPoll = useApiPoll<{ labels: Record<string, string> }>('/api/endpoint-labels', 3000)
  const whitelistPoll = useApiPoll<{ destinations: Destination[] }>('/api/whitelisted-destinations', 6000)

  const [selected, setSelected] = useState<string | null>(null)
  const [customLabelInput, setCustomLabelInput] = useState('')
  const [isSavingLabel, setIsSavingLabel] = useState(false)
  const [labelStatus, setLabelStatus] = useState<string | null>(null)
  const [copiedIp, setCopiedIp] = useState(false)
  const [resettingMac, setResettingMac] = useState<string | null>(null)
  const [removingMac, setRemovingMac] = useState<string | null>(null)

  const devices = useMemo(() => devicePoll.data?.devices || [], [devicePoll.data])
  const customLabels = useMemo(() => labelsPoll.data?.labels || {}, [labelsPoll.data])
  const whitelistedDests = useMemo(() => whitelistPoll.data?.destinations || [], [whitelistPoll.data])

  // Sync label input when selected IP changes
  useEffect(() => {
    if (selected) {
      setCustomLabelInput(customLabels[selected] || '')
      setLabelStatus(null)
      setCopiedIp(false)
    }
  }, [selected, customLabels])

  const graph = useMemo(() => {
    const flows = flowPoll.data?.flows || []
    const addresses = [...new Set(flows.flatMap(flow => [flow.src_ip, flow.dst_ip]))].sort()
    const shown = addresses.slice(0, 20)
    const nodes = shown.map((ip, index) => {
      const angle = (index / Math.max(1, shown.length)) * Math.PI * 2 - Math.PI / 2
      return {
        ip,
        x: 430 + 310 * Math.cos(angle),
        y: 250 + 175 * Math.sin(angle),
      }
    })
    const edges = new Map<string, { src: string; dst: string; windows: number; alert: boolean }>()
    for (const flow of flows) {
      if (!shown.includes(flow.src_ip) || !shown.includes(flow.dst_ip)) continue
      const key = [flow.src_ip, flow.dst_ip].sort().join('|')
      const old = edges.get(key)
      edges.set(key, {
        src: flow.src_ip,
        dst: flow.dst_ip,
        windows: (old?.windows || 0) + 1,
        alert: !!old?.alert || !!flow.is_anomaly,
      })
    }
    return { nodes, edges: [...edges.values()], omitted: addresses.length - shown.length }
  }, [flowPoll.data])

  const related = useMemo(
    () => (flowPoll.data?.flows || []).filter(flow => flow.src_ip === selected || flow.dst_ip === selected),
    [flowPoll.data, selected]
  )

  const relatedAlertCount = useMemo(
    () => related.filter(f => f.is_anomaly === 1).length,
    [related]
  )

  const selectedInfo = useMemo(() => {
    if (!selected) return null
    return classifyEndpoint(selected, devices, customLabels, whitelistedDests)
  }, [selected, devices, customLabels, whitelistedDests])

  const handleSaveLabel = async () => {
    if (!selected) return
    const trimmed = customLabelInput.trim()
    if (!trimmed) return
    setIsSavingLabel(true)
    setLabelStatus(null)
    try {
      await setEndpointLabel(selected, trimmed)
      setLabelStatus('Label saved!')
      setTimeout(() => setLabelStatus(null), 3000)
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to save label'
      setLabelStatus(errorMsg)
    } finally {
      setIsSavingLabel(false)
    }
  }

  const handleClearLabel = async () => {
    if (!selected) return
    setIsSavingLabel(true)
    setLabelStatus(null)
    try {
      await deleteEndpointLabel(selected)
      setCustomLabelInput('')
      setLabelStatus('Custom label cleared')
      setTimeout(() => setLabelStatus(null), 3000)
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to clear label'
      setLabelStatus(errorMsg)
    } finally {
      setIsSavingLabel(false)
    }
  }

  const handleCopyIp = () => {
    if (!selected) return
    navigator.clipboard?.writeText(selected)
    setCopiedIp(true)
    setTimeout(() => setCopiedIp(false), 2000)
  }

  const handleResetDevice = async (mac: string, name: string) => {
    if (!confirm(`Reset flow and packet observations for "${name}"? The device will remain enrolled.`)) return
    setResettingMac(mac)
    try {
      await clearObservedDevices(mac)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Reset failed')
    } finally {
      setResettingMac(null)
    }
  }

  const handleRemoveDevice = async (mac: string, name: string) => {
    if (!confirm(`Remove "${name}" completely? All flow records for MAC ${mac} will be deleted.`)) return
    setRemovingMac(mac)
    try {
      await removeObservedDevice(mac)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Removal failed')
    } finally {
      setRemovingMac(null)
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-3xl font-bold">Observed Network Connections</h1>
        <p className="mt-2 text-sm text-text-muted">
          Active network communication topology synthesized from the latest 100 live flow windows. Devices are
          automatically categorized with distinctive shapes, role badges, and human-readable names.
        </p>
      </header>

      <RequestState error={flowPoll.error} loading={flowPoll.loading} />

      <div className="grid gap-5 xl:grid-cols-3">
        {/* SVG Network Graph Canvas */}
        <section className={`${panelClass} xl:col-span-2 flex flex-col justify-between`}>
          <div>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-lg font-semibold text-text">Connection Topology</h2>
              <span className="text-xs text-text-muted font-mono">
                {graph.nodes.length} nodes · {graph.edges.length} active links
              </span>
            </div>

            {graph.nodes.length ? (
              <div className="relative w-full overflow-hidden rounded-xl bg-background/50 border border-border/40 p-2">
                <svg
                  viewBox="0 0 860 520"
                  className="w-full h-auto select-none"
                  role="img"
                  aria-label="Observed connection topology between network devices with role badges and alert highlights"
                >
                  {/* Connection Lines */}
                  {graph.edges.map(edge => {
                    const from = graph.nodes.find(node => node.ip === edge.src)!
                    const to = graph.nodes.find(node => node.ip === edge.dst)!
                    if (!from || !to) return null
                    const midX = (from.x + to.x) / 2
                    const midY = (from.y + to.y) / 2
                    return (
                      <g key={`${edge.src}-${edge.dst}`}>
                        <line
                          x1={from.x}
                          y1={from.y}
                          x2={to.x}
                          y2={to.y}
                          stroke={edge.alert ? '#f43f5e' : '#475569'}
                          strokeWidth={Math.min(6, 1.8 + edge.windows / 10)}
                          strokeDasharray={edge.alert ? '6 3' : undefined}
                          opacity={edge.alert ? '0.95' : '0.45'}
                        >
                          <title>
                            {edge.src} ↔ {edge.dst}: {edge.windows} flow windows{' '}
                            {edge.alert ? '(ALERT QUALIFIED)' : '(Normal)'}
                          </title>
                        </line>
                        {edge.alert && (
                          <g transform={`translate(${midX}, ${midY})`}>
                            <polygon points="0,-8 8,0 0,8 -8,0" fill="#f43f5e" stroke="#ffffff" strokeWidth="1.2" />
                            <text y="3" textAnchor="middle" fill="#ffffff" fontSize="9" fontWeight="bold">
                              !
                            </text>
                            <title>Threat alert criteria met on this link</title>
                          </g>
                        )}
                      </g>
                    )
                  })}

                  {/* Device / Host Nodes */}
                  {graph.nodes.map(node => {
                    const info = classifyEndpoint(node.ip, devices, customLabels, whitelistedDests)
                    const isSelected = selected === node.ip

                    return (
                      <g
                        key={node.ip}
                        role="button"
                        tabIndex={0}
                        aria-label={`Inspect ${info.friendlyName} (${node.ip})`}
                        onClick={() => setSelected(node.ip)}
                        onKeyDown={event => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            setSelected(node.ip)
                          }
                        }}
                        className="cursor-pointer transition-transform duration-150 hover:scale-105"
                      >
                        {/* Selected Outer Glow / Indicator */}
                        {isSelected && (
                          <circle
                            cx={node.x}
                            cy={node.y}
                            r="28"
                            fill="none"
                            stroke="#f59e0b"
                            strokeWidth="2.5"
                            strokeDasharray="4 3"
                            opacity="0.8"
                          />
                        )}

                        {/* Distinct Role Shape */}
                        {info.role === 'iot' && (
                          <rect
                            x={node.x - 18}
                            y={node.y - 18}
                            width="36"
                            height="36"
                            rx="8"
                            fill={info.color}
                            stroke={isSelected ? '#f59e0b' : info.strokeColor}
                            strokeWidth={isSelected ? '3.5' : '2'}
                          />
                        )}

                        {info.role === 'gateway' && (
                          <polygon
                            points={`${node.x},${node.y - 21} ${node.x + 21},${node.y} ${node.x},${node.y + 21} ${node.x - 21},${node.y}`}
                            fill={info.color}
                            stroke={isSelected ? '#f59e0b' : info.strokeColor}
                            strokeWidth={isSelected ? '3.5' : '2'}
                          />
                        )}

                        {info.role === 'sensor' && (
                          <rect
                            x={node.x - 22}
                            y={node.y - 15}
                            width="44"
                            height="30"
                            rx="12"
                            fill={info.color}
                            stroke={isSelected ? '#f59e0b' : info.strokeColor}
                            strokeWidth={isSelected ? '3.5' : '2'}
                          />
                        )}

                        {info.role === 'host' && (
                          <rect
                            x={node.x - 19}
                            y={node.y - 16}
                            width="38"
                            height="32"
                            rx="5"
                            fill={info.color}
                            stroke={isSelected ? '#f59e0b' : info.strokeColor}
                            strokeWidth={isSelected ? '3.5' : '2'}
                          />
                        )}

                        {info.role === 'cloud' && (
                          <g>
                            <circle
                              cx={node.x}
                              cy={node.y}
                              r="20"
                              fill="none"
                              stroke={info.color}
                              strokeWidth="1.5"
                              strokeDasharray="3 2"
                              opacity="0.8"
                            />
                            <circle
                              cx={node.x}
                              cy={node.y}
                              r="15"
                              fill={info.color}
                              stroke={isSelected ? '#f59e0b' : info.strokeColor}
                              strokeWidth={isSelected ? '3.5' : '2'}
                            />
                          </g>
                        )}

                        {info.role === 'broadcast' && (
                          <circle
                            cx={node.x}
                            cy={node.y}
                            r="16"
                            fill={info.color}
                            stroke={isSelected ? '#f59e0b' : info.strokeColor}
                            strokeWidth={isSelected ? '3.5' : '2'}
                            strokeDasharray="4 2"
                          />
                        )}

                        {info.role === 'endpoint' && (
                          <circle
                            cx={node.x}
                            cy={node.y}
                            r="15"
                            fill={info.color}
                            stroke={isSelected ? '#f59e0b' : info.strokeColor}
                            strokeWidth={isSelected ? '3.5' : '2'}
                          />
                        )}

                        {/* Central Badge Text */}
                        <text
                          x={node.x}
                          y={node.y + 4}
                          textAnchor="middle"
                          fill="#ffffff"
                          fontSize="10"
                          fontWeight="700"
                          pointerEvents="none"
                          style={{ letterSpacing: '0.02em' }}
                        >
                          {info.badge}
                        </text>

                        {/* Line 1: IP Address */}
                        <text
                          x={node.x}
                          y={node.y + 27}
                          textAnchor="middle"
                          fill="currentColor"
                          fontSize="10.5"
                          fontWeight={isSelected ? '700' : '600'}
                          className="font-mono text-text"
                        >
                          {node.ip}
                        </text>

                        {/* Line 2: Device / Role Label */}
                        <text
                          x={node.x}
                          y={node.y + 40}
                          textAnchor="middle"
                          fill={info.textColor}
                          fontSize="9.5"
                          fontWeight="600"
                        >
                          {info.friendlyName.length > 22
                            ? `${info.friendlyName.slice(0, 20)}…`
                            : info.friendlyName}
                        </text>

                        <title>{`${info.friendlyName} (${node.ip}) — ${info.category}`}</title>
                      </g>
                    )
                  })}
                </svg>
              </div>
            ) : (
              <p className="py-16 text-center text-sm text-text-muted">Waiting for saved live flows.</p>
            )}
          </div>

          {/* Interactive Accessibility Legend */}
          <div className="mt-4 rounded-xl border border-border/60 bg-surface/40 p-3.5 text-xs text-text-muted">
            <p className="font-semibold text-text mb-2.5">Device Types & Network Role Legend:</p>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
              <span className="inline-flex items-center gap-2">
                <span className="inline-flex h-4 w-4 items-center justify-center rounded bg-[#14b8a6] text-[8px] font-bold text-white shadow-xs">
                  IoT
                </span>
                <span className="truncate">
                  <strong className="text-text">Square:</strong> Monitored IoT
                </span>
              </span>

              <span className="inline-flex items-center gap-2">
                <span className="inline-flex h-3.5 w-5 items-center justify-center rounded-full bg-[#8b5cf6] text-[8px] font-bold text-white shadow-xs">
                  Pi
                </span>
                <span className="truncate">
                  <strong className="text-text">Capsule:</strong> Raspberry Pi IDS
                </span>
              </span>

              <span className="inline-flex items-center gap-2">
                <span className="inline-flex h-4 w-4 rotate-45 items-center justify-center bg-[#06b6d4] text-[8px] font-bold text-white shadow-xs">
                  <span className="-rotate-45">GW</span>
                </span>
                <span className="truncate">
                  <strong className="text-text">Diamond:</strong> Local Gateway
                </span>
              </span>

              <span className="inline-flex items-center gap-2">
                <span className="inline-flex h-4 w-4 items-center justify-center rounded-sm bg-[#3b82f6] text-[8px] font-bold text-white shadow-xs">
                  PC
                </span>
                <span className="truncate">
                  <strong className="text-text">Rect:</strong> Defender Host
                </span>
              </span>

              <span className="inline-flex items-center gap-2">
                <span className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-dashed border-[#0284c7] bg-[#0284c7] text-[7.5px] font-bold text-white">
                  WAN
                </span>
                <span className="truncate">
                  <strong className="text-text">Cloud Ring:</strong> Remote Broker
                </span>
              </span>

              <span className="inline-flex items-center gap-2">
                <span className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-dashed border-[#94a3b8] bg-[#94a3b8] text-[8px] font-bold text-white">
                  BC
                </span>
                <span className="truncate">
                  <strong className="text-text">Dashed:</strong> Broadcast
                </span>
              </span>

              <span className="inline-flex items-center gap-2">
                <span className="inline-block w-5 border-t-2 border-dashed border-[#f43f5e]" />
                <span className="text-rose-500 font-bold">!</span>
                <span className="truncate">
                  <strong className="text-text">Dashed Red:</strong> Alert Flow
                </span>
              </span>

              <span className="inline-flex items-center gap-2">
                <span className="inline-block w-5 border-t-2 border-solid border-[#475569]" />
                <span className="truncate">
                  <strong className="text-text">Solid Line:</strong> Normal Flow
                </span>
              </span>
            </div>
          </div>

          {graph.omitted > 0 && (
            <p className="mt-2 text-xs text-text-muted">
              {graph.omitted} additional addresses are omitted from the diagram; their records remain in the table.
            </p>
          )}
        </section>

        {/* Selected Endpoint Sidebar & Label Editor */}
        <section className={`${panelClass} flex flex-col justify-between`}>
          <div>
            <h2 className="text-lg font-semibold text-text">Selected Endpoint</h2>

            {selected && selectedInfo ? (
              <div className="mt-4 space-y-4 text-sm">
                {/* Category & Role Header */}
                <div className="flex items-start justify-between gap-2 border-b border-border pb-3">
                  <div>
                    <span
                      className="inline-block px-2 py-0.5 rounded text-[11px] font-semibold tracking-wide uppercase border mb-1.5"
                      style={{
                        backgroundColor: `${selectedInfo.color}15`,
                        color: selectedInfo.color,
                        borderColor: `${selectedInfo.color}40`,
                      }}
                    >
                      {selectedInfo.category}
                    </span>
                    <h3 className="text-base font-bold text-text">{selectedInfo.friendlyName}</h3>
                  </div>
                  <span
                    className="inline-flex h-7 w-7 items-center justify-center rounded-lg text-xs font-bold text-white shrink-0 shadow-xs"
                    style={{ backgroundColor: selectedInfo.color }}
                  >
                    {selectedInfo.badge}
                  </span>
                </div>

                {/* IP Address Card with Copy */}
                <div className="rounded-xl border border-border bg-background-soft p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs text-text-muted">IP Address</p>
                      <p className="font-mono text-sm font-semibold text-text mt-0.5">{selected}</p>
                    </div>
                    <button
                      onClick={handleCopyIp}
                      className="rounded-lg border border-border bg-surface px-2.5 py-1 text-xs text-text-muted hover:text-text hover:bg-surface/80"
                      title="Copy IP address"
                    >
                      {copiedIp ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>

                {/* Telemetry Statistics */}
                <div className="space-y-2 rounded-xl border border-border bg-background-soft p-3 text-xs">
                  <div className="flex justify-between">
                    <span className="text-text-muted">Flows in sample:</span>
                    <span className="font-semibold text-text">{related.length} windows</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-text-muted">Alert occurrences:</span>
                    <span className={relatedAlertCount > 0 ? 'font-bold text-rose-500' : 'text-emerald-500 font-medium'}>
                      {relatedAlertCount > 0 ? `${relatedAlertCount} alerts` : '0 (Benign)'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-text-muted">Last observed:</span>
                    <span className="text-text">{formatTime(related[0]?.timestamp)}</span>
                  </div>
                </div>

                {/* Custom Labeling Section */}
                <div className="rounded-xl border border-border bg-background-soft p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <label htmlFor="endpoint-label-input" className="text-xs font-semibold text-text">
                      Customize Device Label
                    </label>
                    {selectedInfo.isCustom && (
                      <span className="text-[10px] text-amber-500 font-medium">Custom Label Active</span>
                    )}
                  </div>
                  <p className="text-[11px] text-text-muted leading-tight">
                    Assign a friendly name (e.g. "Smart TV", "Office Switch", "Kali Attacker VM") to identify this device
                    across the network graph.
                  </p>
                  <div className="flex gap-2">
                    <input
                      id="endpoint-label-input"
                      type="text"
                      value={customLabelInput}
                      onChange={e => setCustomLabelInput(e.target.value)}
                      placeholder="Enter friendly device name"
                      className="flex-1 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-text placeholder-text-muted focus:border-primary focus:outline-none"
                    />
                    <button
                      onClick={handleSaveLabel}
                      disabled={isSavingLabel || !customLabelInput.trim()}
                      className="rounded-lg bg-primary px-3 py-1.5 text-xs font-semibold text-white hover:bg-primary/90 disabled:opacity-50"
                    >
                      {isSavingLabel ? 'Saving…' : 'Save'}
                    </button>
                  </div>
                  {customLabels[selected] && (
                    <button
                      onClick={handleClearLabel}
                      disabled={isSavingLabel}
                      className="w-full text-center text-xs text-rose-500 hover:underline pt-1"
                    >
                      Reset to default label
                    </button>
                  )}
                  {labelStatus && (
                    <p
                      className={`text-xs ${
                        labelStatus.includes('saved') || labelStatus.includes('cleared')
                          ? 'text-emerald-500'
                          : 'text-rose-500'
                      }`}
                    >
                      {labelStatus}
                    </p>
                  )}
                </div>

                <p className="text-xs text-text-muted leading-relaxed">
                  Traffic is passively captured by the Raspberry Pi sensor via ARP cache and port mirroring. No
                  connection blocking is performed.
                </p>
              </div>
            ) : (
              <div className="py-12 text-center text-sm text-text-muted">
                <p>Click any device node in the graph to inspect its properties or assign a custom label.</p>
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Observed Devices List */}
      <section className={panelClass}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">Observed IoT Devices</h2>
          <span className="text-xs text-text-muted">Telemetry registered via sensor MAC inspection</span>
        </div>
        <RequestState error={devicePoll.error} loading={devicePoll.loading} />
        <DeviceCards
          devices={devices}
          onResetDevice={handleResetDevice}
          onRemoveDevice={handleRemoveDevice}
          resettingMac={resettingMac}
          removingMac={removingMac}
        />
      </section>

      {/* Saved Live Flow Windows Table */}
      <section className={panelClass}>
        <h2 className="mb-4 text-lg font-semibold">Saved Live Flow Windows</h2>
        <FlowTable flows={flowPoll.data?.flows || []} />
      </section>
    </div>
  )
}
