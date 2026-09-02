import { useState, useEffect, useRef } from 'react'
import { ShieldCheck, Clock, Zap, Activity } from '../../components/Icons.tsx'
import { XaiPreviewModal } from '../../components/XaiPreviewModal'
import { classifyThreatLevel, threatLevelTone, type ThreatLevel } from '../../utils/threatLevel'

interface SystemStatus {
        node_status: string;
        core_model: string;
        processed_packets: number;
        threats_detected: number;
        cpu_usage: number;
        memory_usage: number;
        chart_data: number[];
        latest_shap: { f: string; v: number }[];
}

interface ThreatLog {
        id: string;
        timestamp: string;
        source_ip: string;
        dest_ip: string;
        attack_type: string;
        confidence: number;
        threat_level?: ThreatLevel;
        status: string;
        shap_values?: { f: string; v: number }[];
        lime_values?: { f: string; v: number }[];
}

const FEATURE_NAMES: Record<string, string> = {
    'src_bytes': 'Data sent (Source Bytes)',
    'dst_pkts': 'Packets received (Destination)',
    'duration': 'Connection Time (Duration)',
    'src_ip_bytes': 'Total Source IP Data',
    'dst_ip_bytes': 'Total Destination IP Data',
    'conn_state_SF': 'Normal Connection Finished',
    'conn_state_': 'Abnormal Connection State',
    'proto_tcp': 'TCP Protocol',
    'proto_udp': 'UDP Protocol'
}

const getFeatureName = (f: string) => FEATURE_NAMES[f] || f.replace(/_/g, ' ')

const classifyLiveTrafficLevel = (features: { v: number }[]) => {
        const strongest = features.reduce((max, feature) => Math.max(max, Math.abs(feature.v)), 0)
        if (strongest >= 0.15) return 'Critical' as ThreatLevel
        if (strongest >= 0.1) return 'High' as ThreatLevel
        if (strongest >= 0.05) return 'Medium' as ThreatLevel
        return 'Monitoring' as ThreatLevel
}

export function DashboardPage() {
        const [status, setStatus] = useState<SystemStatus>({
                node_status: 'Connecting...',
                core_model: 'Loading...',
                processed_packets: 0,
                threats_detected: 0,
                cpu_usage: 0,
                memory_usage: 0,
                chart_data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                latest_shap: [
                        { f: 'src_bytes', v: 0.0 },
                        { f: 'dst_pkts', v: 0.0 }
                ]
        })
        const [threats, setThreats] = useState<ThreatLog[]>([])
        const [attackNotice, setAttackNotice] = useState<ThreatLog | null>(null)
	const [selectedThreat, setSelectedThreat] = useState<ThreatLog | null>(null)
	const [hoveredThreat, setHoveredThreat] = useState<ThreatLog | null>(null)
	const [mousePos, setMousePos] = useState({ x: 0, y: 0 })
        const [ripperRules, setRipperRules] = useState('')
        const hasLoadedThreatsRef = useRef(false)
        const lastNotifiedThreatIdRef = useRef<string | null>(null)

        const latestThreat = threats[threats.length - 1] || null
        const liveTrafficShap = status.latest_shap
        const liveTrafficLevel = classifyLiveTrafficLevel(liveTrafficShap)
        const liveTopFeature = liveTrafficShap[0]
        const liveSecondFeature = liveTrafficShap[1]

        const latestAttackThreat = latestThreat
        const latestAttackLevel = latestAttackThreat?.threat_level || (latestAttackThreat ? classifyThreatLevel(latestAttackThreat.confidence) : 'Monitoring')
        const latestAttackShap = latestAttackThreat?.shap_values || []
        const latestAttackTopFeature = latestAttackShap[0]
        const latestAttackSecondFeature = latestAttackShap[1]

        let liveHumanSummary = 'The live stream is being monitored right now.'
        if (liveTopFeature) {
                const leadAction = liveTopFeature.v >= 0 ? 'points to risky traffic' : 'points to normal traffic'
                liveHumanSummary = liveTrafficLevel === 'Monitoring'
                        ? `Current traffic looks calm. The strongest live signal is "${getFeatureName(liveTopFeature.f)}".`
                        : `Current traffic is ${liveTrafficLevel}. The strongest live clue ${leadAction}: "${getFeatureName(liveTopFeature.f)}"${liveSecondFeature ? ` and "${getFeatureName(liveSecondFeature.f)}"` : ''}.`
        }

        let latestAttackSummary = 'No attack packet has been captured yet.'
        if (latestAttackThreat && latestAttackTopFeature) {
                const leadAction = latestAttackTopFeature.v >= 0 ? 'pointed to possible attack behavior' : 'looked more normal than risky'
                latestAttackSummary = `Latest saved attack packet: ${latestAttackLevel} risk at ${(latestAttackThreat.confidence * 100).toFixed(1)}% certainty. The main warning signs were "${getFeatureName(latestAttackTopFeature.f)}"${latestAttackSecondFeature ? ` and "${getFeatureName(latestAttackSecondFeature.f)}"` : ''}. The strongest clue ${leadAction}.`
        }

        useEffect(() => {
                const fetchData = async () => {
                        try {
                                const [statusRes, threatsRes, ripperRes] = await Promise.all([
                                        fetch('http://127.0.0.1:8000/api/status'),
                                        fetch('http://127.0.0.1:8000/api/threat-logs'),
                                        fetch('http://127.0.0.1:8000/api/explainability/ripper')
                                ])

                                if (statusRes.ok) {
                                        const data = await statusRes.json()
                                        setStatus(prev => ({ ...prev, ...data }))
                                }
                                if (threatsRes.ok) {
                                        const threatsData = await threatsRes.json()
                                        const incomingThreats = threatsData.logs || []
                                        const newestThreat = incomingThreats[incomingThreats.length - 1] || null

                                        if (!hasLoadedThreatsRef.current) {
                                                hasLoadedThreatsRef.current = true
                                                lastNotifiedThreatIdRef.current = newestThreat?.id || null
                                        } else if (newestThreat && newestThreat.id !== lastNotifiedThreatIdRef.current) {
                                                setAttackNotice(newestThreat)
                                                lastNotifiedThreatIdRef.current = newestThreat.id
                                        }

                                        setThreats(incomingThreats)
                                }
                                if (ripperRes.ok) {
                                        const ripperData = await ripperRes.json()
                                        setRipperRules(ripperData.rules || '')
                                }
                        } catch (error) {
                                console.error('Failed to fetch dashboard data:', error)
                        }
                }

                fetchData()
                const interval = setInterval(fetchData, 2000)
                return () => clearInterval(interval)
        }, [])

        useEffect(() => {
                if (!attackNotice) return
                const timer = setTimeout(() => setAttackNotice(null), 9000)
                return () => clearTimeout(timer)
        }, [attackNotice])

        const handleClearData = async () => {
                try {
                        await fetch('http://127.0.0.1:8000/api/clear', { method: 'POST' })
                        setStatus(prev => ({
                                ...prev,
                                processed_packets: 0,
                                threats_detected: 0,
                                chart_data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                                latest_shap: [
                                    { f: 'src_bytes', v: 0.0 },
                                    { f: 'duration', v: 0.0 },
                                    { f: 'dst_pkts', v: 0.0 }
                                ]
                        }))
                        setThreats([])
                } catch (e) {
                        console.error('Failed to clear data:', e)
                }
        }

        return (
		<>
                <div className="flex flex-col gap-6 bg-background-soft rounded-3xl border border-border/60 shadow-lg px-8 py-7 relative overflow-hidden">
                        <div className="absolute -top-40 -right-40 w-96 h-96 bg-accent/10 rounded-full blur-3xl pointer-events-none" />

                        <header className="relative z-10 flex justify-between items-start">
                                <div>
                                        <h1 className="text-3xl font-bold tracking-tight text-text">Overview & AI Analysis</h1>
                                        <p className="text-text-muted mt-1 font-medium">Unified Security Posture across live intercepts and Explainable AI.</p>
                                </div>
                                <button 
                                        onClick={handleClearData}
                                        className="flex items-center gap-2 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 border border-rose-500/30 px-5 py-2.5 rounded-xl transition-colors font-semibold text-sm shadow-sm"
                                >
                                        <ShieldCheck className="w-5 h-5" />
                                        Clear Simulation Data
                                </button>
                        </header>

                        <div className="grid grid-cols-1 md:grid-cols-4 gap-5 relative z-10">
                                {[
                                        { label: 'Total Packets Scanned', value: status.processed_packets.toLocaleString(), icon: Activity, metric: 'Simulated stream matching' },
                                        { label: 'Detected Attacks', value: status.threats_detected.toLocaleString(), icon: ShieldCheck, metric: 'Total alerts flagged as malicious' },
                                        { label: 'CPU Usage', value: `${status.cpu_usage}%`, icon: Zap, metric: 'Inference engine load' },
                                        { label: 'Memory Usage', value: `${status.memory_usage}%`, icon: Clock, metric: 'Buffer utilization' },
                                ].map((card) => (
                                        <div
                                                key={card.label}
                                                className="col-span-1 rounded-2xl bg-surface backdrop-blur-md shadow-md border border-border/80 px-5 py-5 flex flex-col gap-3 transition-transform hover:-translate-y-1 hover:shadow-lg"
                                        >
                                                <div className="flex items-center gap-3 text-text font-semibold">
                                                        <div className="bg-accent-soft p-2 rounded-xl text-accent-dark">
                                                                <card.icon className="w-5 h-5" />
                                                        </div>
                                                        <span>{card.label}</span>
                                                </div>
                                                <div className="mt-2">
                                                        <div className="text-3xl font-bold tracking-tight text-text">{card.value}</div>
                                                        <div className="text-xs text-text-muted mt-1.5">{card.metric}</div>
                                                </div>
                                        </div>
                                ))}
                        </div>

                        {/* Intrusion Alerts Chart */}
                        <div className="rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-5 shadow-md relative z-10 flex flex-col justify-center">
                                <h2 className="text-xl font-bold tracking-tight text-text mb-2">Intrusion Alerts</h2>
                                <p className="text-sm text-text-muted mb-4">Traffic volume over the last 10 scan cycles.</p>
                                <div className="h-28 flex items-end gap-3 pb-1">
                                        {status.chart_data.map((h, idx) => (
                                                <div key={idx} className="flex-1 bg-background-soft rounded-t-lg overflow-hidden group hover:bg-background transition-colors h-full relative">
                                                        <div className="absolute bottom-0 w-full min-h-[4px] bg-accent/90 transition-all duration-500 ease-in-out group-hover:bg-accent group-hover:-translate-y-1" style={{ height: `${h}%` }} />
                                                </div>
                                        ))}
                                </div>
                        </div>

                        {/* Live traffic + latest attack panels */}
                        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 relative z-10">
                                <div className="xl:col-span-2 rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md transition-shadow hover:shadow-lg flex flex-col justify-center">
                                        <h2 className="text-xl font-bold tracking-tight text-text mb-4">Live Traffic Snapshot</h2>
                                        <div className={"p-5 rounded-xl border mb-2 " + threatLevelTone(liveTrafficLevel)}>
                                                <div className="text-sm font-medium mb-2">
                                                        Current Traffic Status: <span className={liveTrafficLevel === 'Critical' ? 'text-rose-500 font-bold' : liveTrafficLevel === 'High' ? 'text-orange-500 font-bold' : liveTrafficLevel === 'Medium' ? 'text-amber-500 font-bold' : liveTrafficLevel === 'Low' ? 'text-emerald-500 font-bold' : 'text-slate-500 font-bold'}>{liveTrafficLevel}</span>
                                                </div>
                                                <p className="text-[14px] text-text-muted leading-relaxed font-semibold">{liveHumanSummary}</p>
                                        </div>
                                        <p className="text-xs text-text-muted mt-2">
                                                This panel reflects the current traffic stream, even when there is no attack packet to review.
                                        </p>
                                </div>

                                <div className="rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md transition-shadow hover:shadow-lg flex flex-col">
                                        <h2 className="text-xl font-bold tracking-tight text-text mb-2">Latest Attack Packet</h2>
                                        <p className="text-xs text-text-muted mb-4">The newest detected attack, saved for review in Threat Logs.</p>

                                        {latestAttackThreat ? (
                                                <div className={"p-4 rounded-xl border mb-4 " + threatLevelTone(latestAttackLevel)}>
                                                        <div className="flex items-start justify-between gap-3 mb-3">
                                                                <div>
                                                                        <div className="text-sm font-semibold text-text">{latestAttackThreat.attack_type}</div>
                                                                        <div className="text-xs text-text-muted">{latestAttackThreat.timestamp}</div>
                                                                </div>
                                                                <button
                                                                        onClick={() => setSelectedThreat(latestAttackThreat)}
                                                                        className="px-3 py-1.5 rounded-lg bg-background-soft border border-border/50 text-xs font-semibold text-text hover:bg-background transition-colors"
                                                                >
                                                                        Open XAI
                                                                </button>
                                                        </div>
                                                        <p className="text-[13px] text-text-muted leading-relaxed font-medium mb-3">{latestAttackSummary}</p>
                                                        <div className="grid grid-cols-2 gap-3 text-xs">
                                                                <div className="bg-background-soft rounded-lg p-2 border border-border/40">
                                                                        <div className="text-text-muted uppercase tracking-wider text-[10px] mb-1">Source</div>
                                                                        <div className="font-mono text-text break-all">{latestAttackThreat.source_ip}</div>
                                                                </div>
                                                                <div className="bg-background-soft rounded-lg p-2 border border-border/40">
                                                                        <div className="text-text-muted uppercase tracking-wider text-[10px] mb-1">Destination</div>
                                                                        <div className="font-mono text-text break-all">{latestAttackThreat.dest_ip}</div>
                                                                </div>
                                                        </div>
                                                </div>
                                        ) : (
                                                <div className="flex-1 rounded-xl border border-border/40 bg-background-soft p-4 text-sm text-text-muted flex items-center">
                                                        No attack packet has been detected yet. You’ll see the latest one here when it arrives.
                                                </div>
                                        )}

                                        <p className="text-xs text-text-muted mt-auto pt-4 border-t border-border/30">
                                                Detailed explanations for attacks are stored in <strong>Threat Logs</strong>.
                                        </p>
                                </div>
                        </div>

                        {/* Live Intrusion Intercept Table */}
                        <div className="rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md relative z-10 transition-shadow hover:shadow-lg">
                                <div className="flex items-center justify-between mb-4">
                                        <div>
                                                <h2 className="text-xl font-bold tracking-tight text-text mb-2">Live Intrusion Intercepts</h2>
                                                <p className="text-sm text-text-muted">Recent flows classified as attacks and mitigated.</p>
                                        </div>
                                        <button
                                                onClick={handleClearData}
                                                className="px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 hover:bg-red-500/20 hover:border-red-500/50 transition-colors font-medium text-sm"
                                                title="Clear threat log table (server + UI)"
                                        >
                                                Clear Table
                                        </button>
                                </div>
                                <div className="overflow-x-auto max-h-72 mt-4">
                                        <table className="min-w-full border-separate border-spacing-y-2">
                                                <thead className="sticky top-0 bg-surface z-10">
                                                        <tr className="text-text-muted text-sm font-medium border-b border-border">
                                                                <th className="text-left px-4 py-2 font-semibold">Timestamp</th>
                                                                <th className="text-left px-4 py-2 font-semibold">Source &rarr; Destination</th>
                                                                <th className="text-left px-4 py-2 font-semibold">Threat Class</th>
                                                                <th className="text-left px-4 py-2 font-semibold">Confidence</th>
                                                                <th className="text-left px-4 py-2 font-semibold">Severity</th>
                                                        </tr>
                                                </thead>
                                                <tbody className="text-sm font-medium">
                                                        {threats.length > 0 ? ( 
                                                                [...threats].reverse().map((row) => (
                                                                <tr key={row.id} className="bg-surface-subtle hover:bg-background-soft transition-colors shadow-sm rounded-lg overflow-hidden group cursor-pointer hover:border-accent/50 relative"
                                                        onClick={() => setSelectedThreat(row)}
                                                        onMouseEnter={(e) => {
                                                        	setHoveredThreat(row)
                                                        	setMousePos({ x: e.clientX, y: e.clientY })
                                                        }}
                                                        onMouseMove={(e) => setMousePos({ x: e.clientX, y: e.clientY })}
                                                        onMouseLeave={() => setHoveredThreat(null)}
                                                >
                                                                               <td className="px-4 py-3 text-text border-y border-l border-border/40 group-hover:border-border">{row.timestamp.split(' ')[1]}</td>
                                                                               <td className="px-4 py-3 border-y border-border/40 group-hover:border-border font-mono">{row.source_ip} &rarr; {row.dest_ip}</td>
                                                                               <td className="px-4 py-3 border-y border-border/40 group-hover:border-border">   
                                                                               <span className="px-2.5 py-1 rounded-md bg-red-100 text-red-700 font-bold border border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800">       
                                                                               {row.attack_type}
                                                                               </span>
                                                                               </td>
                                                                               <td className="px-4 py-3 text-accent-dark font-bold border-y border-border/40 group-hover:border-border">{(row.confidence * 100).toFixed(1)}%</td>
                                                                               <td className="px-4 py-3 border-y border-r border-border/40 group-hover:border-border rounded-r-lg">
                                                                                        <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold tracking-widest ${row.confidence > 0.95 ? 'bg-rose-500/10 text-rose-500 border border-rose-500/30' : 'bg-amber-500/10 text-amber-500 border border-amber-500/30'}`}>
                                                                                                {row.confidence > 0.95 ? 'CRITICAL' : 'WARNING'}
                                                                                        </span>
                                                                                </td>
                                                                        </tr>
                                                                ))
                                                        ) : (
                                                                <tr>
                                                                        <td colSpan={5} className="text-center py-8 text-text-muted italic">
                                                                               No recent intrusions intercepted... monitoring active stream.
                                                                        </td>   
                                                                </tr>
                                                        )}
                                                </tbody>
                                        </table>
                                </div>
                        </div>
                </div>

				{/* XAI Preview Modal */}
				{selectedThreat && (
					<XaiPreviewModal
						threatId={selectedThreat.id}
						threatType={selectedThreat.attack_type}
						confidence={selectedThreat.confidence}
                                                                        threatLevel={selectedThreat.threat_level || classifyThreatLevel(selectedThreat.confidence)}
						sourceIp={selectedThreat.source_ip}
						destIp={selectedThreat.dest_ip}
						timestamp={selectedThreat.timestamp}
                                                                        shafeatures={selectedThreat.shap_values || status.latest_shap}
                                                limefeatures={selectedThreat.lime_values || []}
                                                                        ripperRules={ripperRules}
						isOpen={true}
						onClose={() => setSelectedThreat(null)}
					/>
				)}
		{/* Hover Tooltip */}
		{hoveredThreat && (
			<div 
				className="fixed z-[100] pointer-events-none bg-surface/95 backdrop-blur-xl border border-border/80 shadow-2xl p-4 rounded-xl w-72 transition-opacity"
				style={{ 
					left: Math.min(mousePos.x + 16, window.innerWidth - 300), 
					top: Math.min(mousePos.y + 16, window.innerHeight - 150) 
				}}
			>
				<div className="flex items-center justify-between mb-2">
					<span className="font-bold text-text">{hoveredThreat.attack_type}</span>
					<span className={`px-2 py-0.5 rounded-md text-[10px] font-bold ${hoveredThreat.confidence > 0.95 ? 'bg-rose-500/20 text-rose-500' : 'bg-amber-500/20 text-amber-500'}`}>
						{(hoveredThreat.confidence * 100).toFixed(1)}% Conf
					</span>
				</div>
				<p className="text-xs text-text-muted mb-2">
					Flow from <span className="font-mono text-text">{hoveredThreat.source_ip}</span>
				</p>
				<div className="text-[11px] bg-background-soft p-2 rounded-lg border border-border/40 text-text/90 italic">
					"Click to view full XAI analysis and SHAP feature breakdowns."
				</div>
			</div>
		)}

                {attackNotice && (
                        <div className="fixed bottom-6 right-6 z-[120] w-full max-w-sm bg-surface/95 backdrop-blur-xl border border-rose-500/30 shadow-2xl rounded-2xl p-5">
                                <div className="flex items-start justify-between gap-4 mb-3">
                                        <div>
                                                <div className="text-xs uppercase tracking-widest font-bold text-rose-500 mb-1">Attack detected</div>
                                                <div className="text-lg font-bold text-text">{attackNotice.attack_type}</div>
                                        </div>
                                        <button
                                                onClick={() => setAttackNotice(null)}
                                                className="text-text-muted hover:text-text transition-colors px-2 py-1 rounded-lg hover:bg-background-soft"
                                        >
                                                ×
                                        </button>
                                </div>
                                <p className="text-sm text-text-muted leading-relaxed mb-4">
                                        Your device or network may be under attack. Please secure your devices, review Threat Logs, and isolate any suspicious activity right away.
                                </p>
                                <div className="grid grid-cols-2 gap-2">
                                        <button
                                                onClick={() => {
                                                        setSelectedThreat(attackNotice)
                                                        setAttackNotice(null)
                                                }}
                                                className="px-3 py-2 rounded-xl bg-rose-500 text-white text-sm font-semibold hover:bg-rose-600 transition-colors"
                                        >
                                                View Analysis
                                        </button>
                                        <button
                                                onClick={() => setAttackNotice(null)}
                                                className="px-3 py-2 rounded-xl bg-background-soft border border-border/50 text-sm font-semibold text-text hover:bg-background transition-colors"
                                        >
                                                Dismiss
                                        </button>
                                </div>
                        </div>
                )}
		</>
        )
}
