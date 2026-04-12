import { ShieldCheck, Clock, Zap, Activity } from 'lucide-react'
import { useState, useEffect } from 'react'

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
        status: string;
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

        // XAI Merged Compute
        const topFeature = status.latest_shap[0];
        const secondFeature = status.latest_shap[1];
        const outputScore = status.latest_shap.reduce((acc, val) => acc + val.v, 0.15);
        const isHigh = outputScore > 0.6;
        const threatLevel = isHigh ? 'High' : (outputScore > 0.4 ? 'Medium' : 'Low');
        
        let humanSummary = 'Analyzing network traffic...';
        if (topFeature && secondFeature) {
            if (isHigh) {
                humanSummary = `SENTRi-X classified the recent traffic as a Severe Threat because "${getFeatureName(topFeature.f)}" and "${getFeatureName(secondFeature.f)}" were highly abnormal.`;
            } else {
                humanSummary = `Recent traffic looks relatively safe. The primary defining factor was standard "${getFeatureName(topFeature.f)}", aligning with normal baselines.`;
            }
        }

        useEffect(() => {
                const fetchData = async () => {
                        try {
                                const [statusRes, threatsRes] = await Promise.all([
                                        fetch('http://127.0.0.1:8000/api/status'),
                                        fetch('http://127.0.0.1:8000/api/threat-logs')
                                ])

                                if (statusRes.ok) {
                                        const data = await statusRes.json()
                                        setStatus(prev => ({ ...prev, ...data }))
                                }
                                if (threatsRes.ok) {
                                        const threatsData = await threatsRes.json()
                                        setThreats(threatsData.logs)
                                }
                        } catch (error) {
                                console.error('Failed to fetch dashboard data:', error)
                        }
                }

                fetchData()
                const interval = setInterval(fetchData, 2000)
                return () => clearInterval(interval)
        }, [])

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

                        {/* Merged XAI Panel */}
                        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 relative z-10">
                                {/* Human Readable XAI */}
                                <div className="xl:col-span-2 rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md transition-shadow hover:shadow-lg flex flex-col justify-center">
                                    <h2 className="text-xl font-bold tracking-tight text-text mb-4">Explainable AI (XAI) Security Summary</h2>
                                    <div className={"p-5 rounded-xl border mb-2 " + (threatLevel === 'High' ? 'bg-rose-500/10 border-rose-500/30' : threatLevel === 'Medium' ? 'bg-amber-500/10 border-amber-500/30' : 'bg-emerald-500/10 border-emerald-500/30')}>
                                        <div className="text-sm font-medium mb-2">
                                            Current Scan Status: <span className={threatLevel === 'High' ? 'text-rose-500 font-bold' : threatLevel === 'Medium' ? 'text-amber-500 font-bold' : 'text-emerald-500 font-bold'}>{threatLevel}</span>
                                        </div>
                                        <p className="text-[14px] text-text-muted leading-relaxed font-semibold">{humanSummary}</p>
                                    </div>
                                    <p className="text-xs text-text-muted mt-2">
                                        SENTRi-X transparently translates underlying mathematical Random Forest logic into plain English context for analysts.
                                    </p>
                                </div>
                                
                                {/* XAI Top Triggers */}
                                <div className="rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md transition-shadow hover:shadow-lg">
                                        <h2 className="text-xl font-bold tracking-tight text-text mb-2">Key AI Triggers</h2>
                                        <p className="text-xs text-text-muted mb-6">Which traffic properties the AI is fixated on right now.</p>
                                        <div className="space-y-4">
                                                {status.latest_shap.slice(0,4).map((x, idx) => (
                                                        <div key={idx}>
                                                                <div className="flex justify-between mb-2 text-sm font-medium text-text">
                                                                        <span>{getFeatureName(x.f)}</span>
                                                                        <span className={x.v >= 0.3 ? 'text-rose-500 font-bold' : 'text-emerald-500'}>{x.v >= 0.3 ? 'Suspicious' : 'Normal'}</span>
                                                                </div>
                                                                <div className="h-2.5 bg-background-soft rounded-full overflow-hidden shadow-inner">
                                                                        <div className={"h-full transition-all duration-700 ease-in-out rounded-full " + (x.v >= 0.3 ? 'bg-rose-500' : 'bg-emerald-500')} style={{ width: `${Math.min(Math.abs(x.v) * 100, 100)}%` }} />
                                                                </div>
                                                        </div>
                                                ))}
                                        </div>
                                </div>
                        </div>

                        {/* Live Intrusion Intercept Table */}
                        <div className="rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md relative z-10 transition-shadow hover:shadow-lg">
                                <h2 className="text-xl font-bold tracking-tight text-text mb-2">Live Intrusion Intercepts</h2>
                                <p className="text-sm text-text-muted mb-5">Recent flows classified as attacks and mitigated.</p>
                                <div className="overflow-x-auto max-h-72">
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
                                                                        <tr key={row.id} className="bg-surface-subtle hover:bg-background-soft transition-colors shadow-sm rounded-lg overflow-hidden group">
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
        )
}
