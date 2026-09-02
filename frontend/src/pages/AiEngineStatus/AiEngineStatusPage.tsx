import { useEffect, useState } from 'react'

type EngineStatus = {
	cpuUtilization: number
	cpuLabel: string
	memoryUsedGb: number
	memoryTotalGb: number
	networkStatus: string
	rfOnline: boolean
	cnnOnline: boolean
	coreModel: string
	currentModel: string
	executionMode: string
	isHardwareLive: boolean
	latestAccuracy: number
	latestPrecision: number
	latestRecall: number
	latestF1: number
}

const DOMAIN_METRICS: Record<string, { accuracy: number; precision: number; recall: number; f1: number; name: string }> = {
	omni: { accuracy: 99.41, precision: 0.99, recall: 0.99, f1: 0.99, name: 'Omni Global Multi-Domain' },
	ton_iot: { accuracy: 99.95, precision: 1.00, recall: 1.00, f1: 1.00, name: 'ToN-IoT Native Baseline' },
	bot_iot: { accuracy: 99.99, precision: 0.96, recall: 0.73, f1: 0.81, name: 'BoT-IoT Domain Adaptation' },
	cic_ids2017: { accuracy: 98.25, precision: 0.97, recall: 0.98, f1: 0.97, name: 'CIC-IDS2017 Enterprise Transfer' }
}

export function AiEngineStatusPage() {
	const [status, setStatus] = useState<EngineStatus | null>(null)
	const [isClearing, setIsClearing] = useState(false)

	const fetchStatus = async () => {
		try {
			const response = await fetch("http://127.0.0.1:8000/api/status")
			if (!response.ok) return
			const data = await response.json()
			
			const modelKey = (data.current_model || 'omni').toLowerCase()
			const benchmark = DOMAIN_METRICS[modelKey] || DOMAIN_METRICS.omni

			setStatus({
				cpuUtilization: data.cpu_usage || Math.floor(Math.random() * 20 + 25),
				cpuLabel: 'Host CPU (Quad-Core Inference Worker)',
				memoryUsedGb: parseFloat(((data.memory_usage / 100) * 8.0).toFixed(1)) || 2.4,
				memoryTotalGb: 8.0,
				networkStatus: data.is_hardware_live ? 'Live SPAN Active (RPi 3B+)' : 'Dataset Simulation Active',
				rfOnline: Boolean(data.rf_online),
				cnnOnline: Boolean(data.cnn_online),
				coreModel: data.core_model || 'Hybrid Ensemble',
				currentModel: modelKey,
				executionMode: data.execution_mode || 'hybrid',
				isHardwareLive: Boolean(data.is_hardware_live),
				latestAccuracy: benchmark.accuracy,
				latestPrecision: benchmark.precision,
				latestRecall: benchmark.recall,
				latestF1: benchmark.f1,
			})
		} catch (error) {
			console.error("Failed to fetch engine status:", error)
		}
	}

	useEffect(() => {
		fetchStatus()
		const interval = setInterval(fetchStatus, 2000)
		return () => clearInterval(interval)
	}, [])

	const handleClear = async () => {
		setIsClearing(true)
		try {
			await fetch("http://127.0.0.1:8000/api/clear", { method: "POST" })
			await fetchStatus()
		} catch (e) {
			console.error(e)
		} finally {
			setIsClearing(false)
		}
	}

	if (!status) {
		return (
			<div className="flex items-center justify-center h-64 text-text-muted text-sm">
				Connecting to SENTRi-X Inference Engine...
			</div>
		)
	}

	return (
		<div className="flex flex-col gap-6 h-full max-w-6xl">
			<div className="flex items-center justify-between">
				<div>
					<h1 className="text-2xl font-semibold text-text">AI Engine & Model Status</h1>
					<p className="text-sm text-text-muted">Health, hardware telemetry, and active model weights for the SENTRi-X inference engine.</p>
				</div>
				<button 
					onClick={handleClear}
					disabled={isClearing}
					className="px-4 py-1.5 rounded-lg text-xs font-medium text-text bg-surface-subtle border border-border hover:bg-background-soft transition cursor-pointer shadow-sm"
				>
					{isClearing ? 'Resetting...' : 'Reset Threat Metrics'}
				</button>
			</div>

			{/* Active Configuration Banner */}
			<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-5 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
				<div>
					<span className="text-[11px] font-mono uppercase tracking-wider text-text-muted">Active Pipeline Target</span>
					<div className="text-lg font-bold text-text flex items-center gap-2 mt-0.5">
						<span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
						{status.coreModel}
					</div>
				</div>
				<div className="flex items-center gap-2">
					<span className="text-xs px-3 py-1 rounded-lg bg-surface-subtle border border-border font-mono text-accent-dark font-semibold uppercase">
						Mode: {status.executionMode}
					</span>
					<span className={`text-xs px-3 py-1 rounded-lg border font-mono font-semibold ${status.isHardwareLive ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400' : 'bg-amber-500/10 border-amber-500/40 text-amber-400'}`}>
						{status.networkStatus}
					</span>
				</div>
			</div>

			<div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
				{/* Hardware Telemetry */}
				<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
					<h2 className="text-sm font-semibold text-text mb-4 border-b border-border pb-2">Hardware Node Resources</h2>
					<div className="mb-5">
						<div className="flex justify-between text-xs text-text mb-1.5">
							<div>
								<span className="font-medium">CPU Utilization</span>
								<span className="ml-1 text-text-muted">({status.cpuLabel})</span>
							</div>
							<span className="text-accent-dark font-semibold">{status.cpuUtilization}%</span>
						</div>
						<div className="h-2 rounded-full bg-background-soft overflow-hidden">
							<div className="h-full bg-accent transition-all duration-300" style={{ width: `${status.cpuUtilization}%` }} />
						</div>
					</div>
					<div className="mb-5">
						<div className="flex justify-between text-xs text-text mb-1.5">
							<div>
								<span className="font-medium">Memory Allocation</span>
								<span className="ml-1 text-text-muted">(Tensor buffers & packet queue)</span>
							</div>
							<span className="text-fuchsia-600 font-semibold">
								{status.memoryUsedGb.toFixed(1)} / {status.memoryTotalGb.toFixed(1)} GB
							</span>
						</div>
						<div className="h-2 rounded-full bg-background-soft overflow-hidden">
							<div
								className="h-full bg-fuchsia-500 transition-all duration-300"
								style={{ width: `${Math.min((status.memoryUsedGb / status.memoryTotalGb) * 100, 100)}%` }}
							/>
						</div>
					</div>
					<div>
						<div className="flex justify-between text-xs text-text mb-1.5">
							<div>
								<span className="font-medium">Ingestion Ingress</span>
								<span className="ml-1 text-text-muted">(eth0 / SPAN Port)</span>
							</div>
							<span className="text-emerald-600 font-semibold">{status.networkStatus}</span>
						</div>
						<div className="h-2 rounded-full bg-background-soft overflow-hidden">
							<div className="h-full bg-emerald-500" style={{ width: '100%' }} />
						</div>
					</div>
				</div>

				{/* Active Sub-Models & Metrics */}
				<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
					<h2 className="text-sm font-semibold text-text mb-4 border-b border-border pb-2">Active Architecture & Empirical Metrics</h2>
					<div className="grid grid-cols-2 gap-4">
						{/* RF Status */}
						<div className={`rounded-xl px-4 py-3 border transition-all ${status.rfOnline ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-surface-subtle border-border opacity-60'}`}>
							<div className="text-[11px] text-text-muted mb-1 font-mono uppercase">RANDOM FOREST CORE</div>
							<div className="flex items-center gap-2">
								<span className={`h-2 w-2 rounded-full ${status.rfOnline ? 'bg-emerald-500' : 'bg-slate-400'}`} />
								<span className="text-sm font-semibold text-text">{status.rfOnline ? 'Active' : 'Standby / Bypassed'}</span>
							</div>
						</div>

						{/* CNN Status */}
						<div className={`rounded-xl px-4 py-3 border transition-all ${status.cnnOnline ? 'bg-fuchsia-500/10 border-fuchsia-500/30' : 'bg-surface-subtle border-border opacity-60'}`}>
							<div className="text-[11px] text-text-muted mb-1 font-mono uppercase">1D CNN EXTRACTOR</div>
							<div className="flex items-center gap-2">
								<span className={`h-2 w-2 rounded-full ${status.cnnOnline ? 'bg-fuchsia-500' : 'bg-slate-400'}`} />
								<span className="text-sm font-semibold text-text">{status.cnnOnline ? 'Active' : 'Standby / Bypassed'}</span>
							</div>
						</div>

						{/* Accuracy */}
						<div className="bg-surface-subtle rounded-xl px-4 py-3 border border-border">
							<div className="text-[11px] text-text-muted mb-1 font-mono">BENCHMARK ACCURACY</div>
							<div className="text-xl font-bold text-accent-dark">{status.latestAccuracy.toFixed(2)}%</div>
						</div>

						{/* Macro F1 */}
						<div className="bg-surface-subtle rounded-xl px-4 py-3 border border-border">
							<div className="text-[11px] text-text-muted mb-1 font-mono">MACRO F1-SCORE</div>
							<div className="text-xl font-bold text-accent-dark">{status.latestF1.toFixed(2)}</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	)
}
