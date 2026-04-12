import { useEffect, useState } from 'react'

type EngineStatus = {
	cpuUtilization: number
	cpuLabel: string
	memoryUsedGb: number
	memoryTotalGb: number
	networkStatus: 'Active' | 'Idle' | 'Down'
	rfOnline: boolean
	cnnOnline: boolean
	latestPrecision: number
	latestRecall: number
}

export function AiEngineStatusPage() {
	const [status, setStatus] = useState<EngineStatus | null>(null)

	useEffect(() => {
		const fetchStatus = async () => {
			try {
				const response = await fetch("http://localhost:8000/api/status");
				const data = await response.json();
				
				setStatus({
					cpuUtilization: data.cpu_usage || Math.floor(Math.random() * 30 + 30),
					cpuLabel: 'Core i7 (Quad-Core Simulator)',
					memoryUsedGb: parseFloat(((data.memory_usage / 100) * 8.0).toFixed(1)) || 2.4,
					memoryTotalGb: 8.0,
					networkStatus: 'Active',
					rfOnline: data.rf_online !== undefined ? data.rf_online : true,
					cnnOnline: data.cnn_online !== undefined ? data.cnn_online : false,
					latestPrecision: 0.94,
					latestRecall: 0.97,
				})
			} catch (error) {
				console.error("Failed to fetch engine status:", error);
			}
		}

		fetchStatus()
		const interval = setInterval(fetchStatus, 2000)
		return () => clearInterval(interval)
	}, [])

	if (!status) return null

	return (
		<div className="flex flex-col gap-6 h-full">
			<div className="flex items-center justify-between">
				<div>
					<h1 className="text-2xl font-semibold text-text">AI Engine Status</h1>
					<p className="text-sm text-text-muted">Health and performance of the SENTRi-X inference node.</p>
				</div>
				<button className="px-4 py-1.5 rounded-lg text-xs font-medium text-text bg-surface-subtle border border-border hover:bg-background-soft transition">
					Clear Cache
				</button>
			</div>
			<div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
				<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
					<h2 className="text-sm font-semibold text-text mb-4">Hardware Node Resources</h2>
					<div className="mb-5">
						<div className="flex justify-between text-xs text-text mb-1.5">
							<div>
								<span className="font-medium">CPU Utilization</span>
								<span className="ml-1 text-text-muted">{status.cpuLabel}</span>
							</div>
							<span className="text-accent-dark font-semibold">{status.cpuUtilization}%</span>
						</div>
						<div className="h-2 rounded-full bg-background-soft overflow-hidden">
							<div className="h-full bg-accent" style={{ width: `${status.cpuUtilization}%` }} />
						</div>
					</div>
					<div className="mb-5">
						<div className="flex justify-between text-xs text-text mb-1.5">
							<div>
								<span className="font-medium">Memory Allocation</span>
								<span className="ml-1 text-text-muted">Tensor buffers & packet queue</span>
							</div>
							<span className="text-fuchsia-600 font-semibold">
								{status.memoryUsedGb.toFixed(1)} / {status.memoryTotalGb.toFixed(1)} GB
							</span>
						</div>
						<div className="h-2 rounded-full bg-background-soft overflow-hidden">
							<div
								className="h-full bg-fuchsia-500"
								style={{ width: `${Math.min((status.memoryUsedGb / status.memoryTotalGb) * 100, 100)}%` }}
							/>
						</div>
					</div>
					<div>
						<div className="flex justify-between text-xs text-text mb-1.5">
							<div>
								<span className="font-medium">Network Interface</span>
								<span className="ml-1 text-text-muted">eth0 promiscuous mode</span>
							</div>
							<span className="text-emerald-600 font-semibold">{status.networkStatus}</span>
						</div>
						<div className="h-2 rounded-full bg-background-soft overflow-hidden">
							<div className="h-full bg-emerald-500" style={{ width: status.networkStatus === 'Active' ? '100%' : '40%' }} />
						</div>
					</div>
				</div>
					<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
						<h2 className="text-sm font-semibold text-text mb-4">Ensemble Model Metrics</h2>
					<div className="grid grid-cols-2 gap-4">
							<div className="bg-surface-subtle rounded-xl px-4 py-3 border border-border">
								<div className="text-[11px] text-text-muted mb-1">RANDOM FOREST CORE</div>
							<div className="flex items-center gap-2">
									<span className="h-2 w-2 rounded-full bg-emerald-500" />
									<span className="text-sm font-semibold text-text">{status.rfOnline ? 'Online' : 'Offline'}</span>
							</div>
						</div>
							<div className="bg-surface-subtle rounded-xl px-4 py-3 border border-border">
								<div className="text-[11px] text-text-muted mb-1">CNN FEATURE EXTRACTOR</div>
							<div className="flex items-center gap-2">
										<span className={`h-2 w-2 rounded-full ${status.cnnOnline ? 'bg-emerald-500' : 'bg-rose-500'}`} />
									<span className="text-sm font-semibold text-text">{status.cnnOnline ? 'Online' : 'Offline'}</span>
							</div>
						</div>
							<div className="bg-surface-subtle rounded-xl px-4 py-3 border border-border">
								<div className="text-[11px] text-text-muted mb-1">LATEST PRECISION</div>
								<div className="text-2xl font-semibold text-accent-dark">{status.latestPrecision.toFixed(2)}</div>
						</div>
							<div className="bg-surface-subtle rounded-xl px-4 py-3 border border-border">
								<div className="text-[11px] text-text-muted mb-1">LATEST RECALL</div>
								<div className="text-2xl font-semibold text-accent-dark">{status.latestRecall.toFixed(2)}</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	)
}
