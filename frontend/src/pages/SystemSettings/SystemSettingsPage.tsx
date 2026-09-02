import { useState, useEffect } from 'react'

type Settings = {
	activeAlerting: boolean
	confidenceThreshold: number
}

const DOMAINS = [
	{
		id: 'omni',
		title: 'Omni Global Defense',
		dataset: 'Omni (Unified Multi-Domain)',
		desc: 'Universal model trained on 150,000 samples across ToN-IoT, BoT-IoT, and CIC-IDS2017.',
		rfFile: 'rf_model_omni.joblib',
		cnnFile: 'cnn_model_omni.h5',
		tag: 'Phase 4 - Production',
		color: 'purple'
	},
	{
		id: 'ton_iot',
		title: 'ToN-IoT Native Baseline',
		dataset: 'ToN-IoT Telemetry',
		desc: 'Baseline environment trained on modern IoT sensors, Linux systems, and cloud telemetry.',
		rfFile: 'rf_model_ton_iot.joblib',
		cnnFile: 'cnn_model_ton_iot.h5',
		tag: 'Phase 1 - Baseline',
		color: 'blue'
	},
	{
		id: 'bot_iot',
		title: 'BoT-IoT Transfer Model',
		dataset: 'BoT-IoT (2018 Botnets)',
		desc: 'Domain-adapted model fine-tuned on legacy botnet probing, DoS, and data theft attacks.',
		rfFile: 'rf_model_bot_iot_finetuned.joblib',
		cnnFile: 'cnn_model_bot_iot_finetuned.h5',
		tag: 'Phase 3A - Transfer',
		color: 'emerald'
	},
	{
		id: 'cic_ids2017',
		title: 'CIC-IDS2017 Enterprise Model',
		dataset: 'CIC-IDS2017 (Enterprise IT)',
		desc: 'Domain-adapted model fine-tuned on complex enterprise corporate network intrusions.',
		rfFile: 'rf_model_cic_ids2017_finetuned.joblib',
		cnnFile: 'cnn_model_cic_ids2017_finetuned.h5',
		tag: 'Phase 3B - Transfer',
		color: 'amber'
	}
]

export function SystemSettingsPage() {
	const [activeDomain, setActiveDomain] = useState('omni')
	const [activeMode, setActiveMode] = useState('hybrid')
	const [isHardwareLive, setIsHardwareLive] = useState(false)
	const [isLoading, setIsLoading] = useState(false)
	const [message, setMessage] = useState<string | null>(null)

	const [settings, setSettings] = useState<Settings>({
		activeAlerting: true,
		confidenceThreshold: 87,
	})

	const fetchStatus = async () => {
		try {
			const res = await fetch('http://127.0.0.1:8000/api/status')
			if (res.ok) {
				const data = await res.json()
				if (data.current_model) setActiveDomain(data.current_model)
				if (data.execution_mode) setActiveMode(data.execution_mode)
				setIsHardwareLive(Boolean(data.is_hardware_live))
			}
		} catch (e) {
			console.error(e)
		}
	}

	useEffect(() => {
		fetchStatus()
	}, [])

	const handleSwitch = async (domain: string, mode: string) => {
		setIsLoading(true)
		setMessage(null)
		try {
			const res = await fetch('http://127.0.0.1:8000/api/switch', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					model_type: domain,
					dataset: domain,
					mode: mode
				})
			})
			if (res.ok) {
				const data = await res.json()
				setActiveDomain(domain)
				setActiveMode(mode)
				setMessage(`Successfully switched to ${data.core_model}`)
				setTimeout(() => setMessage(null), 4000)
			}
		} catch (err) {
			setMessage('Error switching models. Backend may be offline.')
		} finally {
			setIsLoading(false)
		}
	}

	const handleToggle = () => {
		setSettings((s) => ({ ...s, activeAlerting: !s.activeAlerting }))
	}

	const handleSlider = (e: React.ChangeEvent<HTMLInputElement>) => {	
		const value = Number(e.target.value)
		setSettings((s) => ({ ...s, confidenceThreshold: value }))	
	}

	return (
		<div className="flex flex-col gap-6 max-w-5xl">
			<div>
				<h1 className="text-2xl font-semibold text-text">System & Model Settings</h1>
				<p className="text-sm text-text-muted">Configure active machine learning architectures, domain environments, and hardware ingestion.</p>
			</div>

			{message && (
				<div className="p-4 rounded-xl bg-accent-soft border border-accent text-accent-dark font-medium text-sm flex items-center justify-between shadow-sm animate-fadeIn">
					<span>{message}</span>
					<button onClick={() => setMessage(null)} className="text-xs hover:underline">Dismiss</button>
				</div>
			)}

			{/* 1. Architecture Execution Mode Switcher */}
			<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
				<div className="flex items-center justify-between mb-4 border-b border-border pb-3">
					<div>
						<h2 className="text-base font-semibold text-text">1. Architecture Execution Mode</h2>
						<p className="text-xs text-text-muted mt-0.5">Choose whether to run inference using individual standalone models or the fused hybrid ensemble.</p>
					</div>
					<span className="text-xs font-mono px-2.5 py-1 rounded bg-surface-subtle border border-border text-accent-dark font-bold uppercase">
						Active Mode: {activeMode}
					</span>
				</div>

				<div className="grid grid-cols-1 md:grid-cols-3 gap-4">
					{/* Hybrid Ensemble */}
					<button
						type="button"
						disabled={isLoading}
						onClick={() => handleSwitch(activeDomain, 'hybrid')}
						className={`p-4 rounded-xl border text-left transition-all relative ${
							activeMode === 'hybrid'
								? 'border-cyan-500 bg-cyan-500/10 shadow-md ring-1 ring-cyan-500/50'
								: 'border-border bg-surface-subtle/50 hover:bg-surface-subtle hover:border-border-hover'
						}`}
					>
						<div className="flex items-center justify-between mb-1">
							<span className="text-sm font-bold text-text">Hybrid Ensemble (RF + CNN)</span>
							{activeMode === 'hybrid' && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />}
						</div>
						<p className="text-xs text-text-muted mb-2">Soft-voting probability fusion combining high-speed tabular precision with spatial tensor extraction.</p>
						<div className="text-[10px] text-cyan-400 font-mono">P = (P_rf + P_cnn) / 2</div>
					</button>

					{/* Standalone RF */}
					<button
						type="button"
						disabled={isLoading}
						onClick={() => handleSwitch(activeDomain, 'rf')}
						className={`p-4 rounded-xl border text-left transition-all relative ${
							activeMode === 'rf'
								? 'border-emerald-500 bg-emerald-500/10 shadow-md ring-1 ring-emerald-500/50'
								: 'border-border bg-surface-subtle/50 hover:bg-surface-subtle hover:border-border-hover'
						}`}
					>
						<div className="flex items-center justify-between mb-1">
							<span className="text-sm font-bold text-text">Random Forest Core Only</span>
							{activeMode === 'rf' && <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />}
						</div>
						<p className="text-xs text-text-muted mb-2">Evaluates pure tabular flow features via 200 decision trees. Ultra-low latency & CPU efficient.</p>
						<div className="text-[10px] text-emerald-400 font-mono">Standalone RF Predict Proba</div>
					</button>

					{/* Standalone CNN */}
					<button
						type="button"
						disabled={isLoading}
						onClick={() => handleSwitch(activeDomain, 'cnn')}
						className={`p-4 rounded-xl border text-left transition-all relative ${
							activeMode === 'cnn'
								? 'border-fuchsia-500 bg-fuchsia-500/10 shadow-md ring-1 ring-fuchsia-500/50'
								: 'border-border bg-surface-subtle/50 hover:bg-surface-subtle hover:border-border-hover'
						}`}
					>
						<div className="flex items-center justify-between mb-1">
							<span className="text-sm font-bold text-text">1D CNN Core Only</span>
							{activeMode === 'cnn' && <span className="w-2 h-2 rounded-full bg-fuchsia-400 animate-pulse" />}
						</div>
						<p className="text-xs text-text-muted mb-2">Evaluates flow tensor patterns using 1D convolutional layers for spatial feature representations.</p>
						<div className="text-[10px] text-fuchsia-400 font-mono">Standalone Keras 1D CNN</div>
					</button>
				</div>
			</div>

			{/* 2. Domain / Dataset Environment Switcher */}
			<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
				<div className="flex items-center justify-between mb-4 border-b border-border pb-3">
					<div>
						<h2 className="text-base font-semibold text-text">2. Target Domain Models (All 8 Model Weights)</h2>
						<p className="text-xs text-text-muted mt-0.5">Select which domain-trained model weights to deploy in the active inference pipeline.</p>
					</div>
				</div>

				<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
					{DOMAINS.map((d) => {
						const isActive = activeDomain === d.id
						return (
							<div
								key={d.id}
								onClick={() => handleSwitch(d.id, activeMode)}
								className={`p-5 rounded-2xl border transition-all cursor-pointer relative flex flex-col justify-between ${
									isActive
										? 'border-accent bg-accent-soft/30 shadow-lg ring-1 ring-accent'
										: 'border-border bg-surface-subtle/40 hover:bg-surface-subtle hover:border-border-hover'
								}`}
							>
								<div>
									<div className="flex items-center justify-between mb-2">
										<span className="text-xs font-semibold px-2 py-0.5 rounded bg-background border border-border text-text-muted">
											{d.tag}
										</span>
										{isActive ? (
											<span className="flex items-center gap-1.5 text-xs font-bold text-emerald-500">
												<span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
												ACTIVE
											</span>
										) : (
											<span className="text-xs text-text-muted group-hover:text-text">Click to Activate</span>
										)}
									</div>
									<h3 className="text-base font-bold text-text mb-1">{d.title}</h3>
									<p className="text-xs text-text-muted mb-3">{d.desc}</p>
								</div>

								<div className="pt-3 border-t border-border/60 flex flex-wrap gap-2 text-[10px] font-mono text-accent-dark">
									<span className="px-2 py-0.5 bg-background rounded border border-border">🌲 {d.rfFile}</span>
									<span className="px-2 py-0.5 bg-background rounded border border-border">🧠 {d.cnnFile}</span>
								</div>
							</div>
						)
					})}
				</div>
			</div>

			{/* 3. Hardware & Ingestion Node Status */}
			<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
				<h2 className="text-base font-semibold text-text mb-2">3. Physical Hardware Edge Sensor</h2>
				<p className="text-xs text-text-muted mb-4">Status of the Raspberry Pi 3 Model B+ sensor listening on the mirrored switch SPAN port.</p>

				<div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl bg-surface-subtle border border-border gap-4">
					<div className="flex items-center gap-3">
						<div className={`p-3 rounded-xl border ${isHardwareLive ? 'bg-emerald-500/10 border-emerald-500 text-emerald-500' : 'bg-amber-500/10 border-amber-500 text-amber-500'}`}>
							<span className="text-xl">🍓</span>
						</div>
						<div>
							<div className="text-sm font-bold text-text flex items-center gap-2">
								Raspberry Pi 3 Model B+ Edge Node
								<span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${isHardwareLive ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'}`}>
									{isHardwareLive ? 'CONNECTED & STREAMING' : 'STANDBY / SIMULATION ACTIVE'}
								</span>
							</div>
							<div className="text-xs text-text-muted mt-0.5">
								{isHardwareLive 
									? 'Receiving live flow vectors via SPAN mirrored eth0 interface.' 
									: 'Waiting for flow ingestion from edge_sensor.py (Replaying baseline dataset).'}
							</div>
						</div>
					</div>
					<div className="text-xs font-mono px-3 py-1.5 rounded-lg bg-background border border-border text-text-muted">
						Endpoint: /api/ingest-flow
					</div>
				</div>
			</div>

			{/* 4. Detection & Confidence Configuration */}
			<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
				<h2 className="text-base font-semibold text-text mb-4">4. Detection Threshold Configuration</h2>
				<div className="py-4 border-b border-border flex items-center justify-between gap-4">
					<div>
						<div className="text-sm font-medium text-text">Active Alerting Mode</div>
						<div className="text-xs text-text-muted mt-1">
							Automatically push suspected malicious traffic events to the SOC dashboard.
						</div>
					</div>
					<button
						type="button"
						onClick={handleToggle}
						className={`relative w-12 h-6 rounded-full transition-colors ${settings.activeAlerting ? 'bg-accent' : 'bg-surface-subtle'}`}
					>
						<span
							className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white shadow transform transition-transform ${settings.activeAlerting ? 'translate-x-6' : 'translate-x-0'}`}
						/>
					</button>
				</div>
				<div className="pt-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
					<div className="max-w-md">
						<div className="text-sm font-medium text-text">Confidence Threshold</div>
						<div className="text-xs text-text-muted mt-1">
							Minimum AI probability required to classify a flow as an attack and raise an alert.
						</div>
					</div>
					<div className="flex items-center gap-4 w-full sm:w-80">
						<input
							type="range"
							min={50}
							max={99}
							value={settings.confidenceThreshold}
							onChange={handleSlider} 
							className="flex-1 accent-accent"
						/>
						<div className="px-3 py-1 rounded-lg bg-surface-subtle border border-border text-sm font-semibold text-accent-dark">
							{settings.confidenceThreshold}%
						</div>
					</div>
				</div>
			</div>
		</div>
	)
}
