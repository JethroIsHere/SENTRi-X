import { ShieldCheck, Crosshair, Target, Clock, Zap, Activity } from 'lucide-react'
import { useState, useEffect } from 'react'

interface SystemStatus {
	node_status: string;
	core_model: string;
	processed_packets: number;
	threats_detected: number;
	cpu_usage: number;
	memory_usage: number;
}

interface ThreatLog {
	id: string;
	timestamp: string;
	source_ip: string;
	dest_ip: string;
	attack_type: string;
	confidence: number;
	action_taken: string;
}

export function DashboardPage() {
	const [status, setStatus] = useState<SystemStatus>({
		node_status: 'Connecting...',
		core_model: 'Loading...',
		processed_packets: 0,
		threats_detected: 0,
		cpu_usage: 0,
		memory_usage: 0,
	})
	const [threats, setThreats] = useState<ThreatLog[]>([])

	useEffect(() => {
		const fetchData = async () => {
			try {
				const [statusRes, threatsRes] = await Promise.all([
					fetch('http://127.0.0.1:8000/api/status'),
					fetch('http://127.0.0.1:8000/api/threat-logs')
				])
				
				if (statusRes.ok) {
					setStatus(await statusRes.json())
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

	return (
		<div className="flex flex-col gap-6 bg-background-soft rounded-3xl border border-border/60 shadow-lg px-8 py-7 relative overflow-hidden">
			{/* Decorative background flare */}
			<div className="absolute -top-40 -right-40 w-96 h-96 bg-accent/10 rounded-full blur-3xl pointer-events-none" />
			
			<header className="relative z-10">
				<h1 className="text-3xl font-bold tracking-tight text-text">Overview</h1>
				<p className="text-text-muted mt-1 font-medium">High-level overview of SENTRi-X activity and threat posture.</p>
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
			<div className="grid grid-cols-1 xl:grid-cols-3 gap-6 relative z-10">
				<div className="xl:col-span-2 rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md transition-shadow hover:shadow-lg">
					<h2 className="text-xl font-bold tracking-tight text-text mb-2">Intrusion Alerts</h2>
					<p className="text-sm text-text-muted mb-6">Mock traffic volume over the last 10 minutes.</p>
					<div className="h-48 flex items-end gap-3">
						{[40, 60, 35, 70, 55, 80, 50, 65, 45, 75].map((h, idx) => (
							<div key={idx} className="flex-1 bg-background-soft rounded-t-lg overflow-hidden group hover:bg-background transition-colors">
								<div className="w-full bg-accent/90 transition-all duration-300 group-hover:bg-accent group-hover:-translate-y-1" style={{ height: `${h}%` }} />
							</div>
						))}
					</div>
				</div>
				<div className="rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md transition-shadow hover:shadow-lg">
					<h2 className="text-xl font-bold tracking-tight text-text mb-2">Live SHAP Snapshot</h2>
					<p className="text-sm text-text-muted mb-6">Top local feature contributions for the most recent alert.</p>
					<div className="space-y-4">
						{[
							{ f: 'src_bytes', v: 0.62 },
							{ f: 'dst_pkts', v: 0.31 },
							{ f: 'duration', v: 0.14 },
						].map((x) => (
							<div key={x.f}>
								<div className="flex justify-between mb-2 text-sm font-medium text-text">
									<span>{x.f}</span>
									<span className="text-accent-dark">+{x.v.toFixed(2)}</span>
								</div>
								<div className="h-2.5 bg-background-soft rounded-full overflow-hidden shadow-inner">
									<div className="h-full bg-gradient-to-r from-accent to-accent-dark rounded-full" style={{ width: `${x.v * 100}%` }} />
								</div>
							</div>
						))}
					</div>
				</div>
			</div>
			<div className="rounded-2xl bg-surface backdrop-blur-md border border-border/60 p-6 shadow-md relative z-10 transition-shadow hover:shadow-lg">
				<h2 className="text-xl font-bold tracking-tight text-text mb-2">Live Intrusion Intercepts</h2>
				<p className="text-sm text-text-muted mb-5">Recent flows classified as attacks and mitigated.</p>
				<div className="overflow-x-auto">
					<table className="min-w-full border-separate border-spacing-y-2">
						<thead>
							<tr className="text-text-muted text-sm font-medium border-b border-border">
								<th className="text-left px-4 py-2 font-semibold">Timestamp</th>
								<th className="text-left px-4 py-2 font-semibold">Source → Destination</th>
								<th className="text-left px-4 py-2 font-semibold">Threat Class</th>
								<th className="text-left px-4 py-2 font-semibold">Confidence</th>
								<th className="text-left px-4 py-2 font-semibold">Action</th>
							</tr>
						</thead>
						<tbody className="text-sm font-medium">
							{threats.length > 0 ? (
								threats.map((row) => (
									<tr key={row.id} className="bg-surface-subtle hover:bg-background-soft transition-colors shadow-sm rounded-lg overflow-hidden group">
										<td className="px-4 py-3 text-text border-y border-l border-border/40 group-hover:border-border">{row.timestamp.split(' ')[1]}</td>
										<td className="px-4 py-3 border-y border-border/40 group-hover:border-border font-mono">{row.source_ip} &rarr; {row.dest_ip}</td>
										<td className="px-4 py-3 border-y border-border/40 group-hover:border-border">
											<span className="px-2.5 py-1 rounded-md bg-red-100 text-red-700 font-bold border border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800">
												{row.attack_type}
											</span>
										</td>
										<td className="px-4 py-3 text-accent-dark font-bold border-y border-border/40 group-hover:border-border">{(row.confidence * 100).toFixed(1)}%</td>
										<td className="px-4 py-3 text-text-muted rounded-r-lg border-y border-r border-border/40 group-hover:border-border">{row.action_taken}</td>
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
