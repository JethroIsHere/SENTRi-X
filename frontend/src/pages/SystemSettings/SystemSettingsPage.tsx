import { useState } from 'react'

type Settings = {
	activePrevention: boolean
	confidenceThreshold: number
}

export function SystemSettingsPage() {
	const [settings, setSettings] = useState<Settings>({
		activePrevention: true,
		confidenceThreshold: 85,
	})

	const handleToggle = () => {
		setSettings((s) => ({ ...s, activePrevention: !s.activePrevention }))
	}

	const handleSlider = (e: React.ChangeEvent<HTMLInputElement>) => {
		const value = Number(e.target.value)
		setSettings((s) => ({ ...s, confidenceThreshold: value }))
	}

	return (
		<div className="flex flex-col gap-6 h-full">
			<div>
				<h1 className="text-2xl font-semibold text-text">System Settings</h1>
				<p className="text-sm text-text-muted">Configure SENTRi-X defense behavior and decision thresholds.</p>
			</div>
			<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 max-w-4xl shadow-md">
				<h2 className="text-sm font-semibold text-text mb-4">Defense Configuration</h2>
				<div className="py-4 border-b border-border flex items-center justify-between gap-4">
					<div>
						<div className="text-sm font-medium text-text">Active Prevention Mode</div>
						<div className="text-xs text-text-muted mt-1">
							Automatically drop packets and block IPs flagged by the AI engine.
						</div>
					</div>
					<button
						onClick={handleToggle}
						className={`relative w-12 h-6 rounded-full transition-colors ${
							settings.activePrevention ? 'bg-accent' : 'bg-border'
						}`}
					>
						<span
							className={`absolute top-0.5 h-5 w-5 rounded-full bg-surface shadow transform transition-transform ${
								settings.activePrevention ? 'translate-x-6' : 'translate-x-1'
							}`}
						/>
					</button>
				</div>
				<div className="pt-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
					<div className="max-w-md">
						<div className="text-sm font-medium text-text">Confidence Threshold</div>
						<div className="text-xs text-text-muted mt-1">
							Minimum AI probability required to classify a flow as an attack and execute mitigation.
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
