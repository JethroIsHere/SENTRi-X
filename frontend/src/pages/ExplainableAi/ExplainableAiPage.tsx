import { useEffect, useState } from 'react'

type LocalXai = {
	packetId: string
	baseValue: number
	output: number
	shapContributions: { feature: string; value: number }[]
}

type LimeWeight = { feature: string; weight: number }

type RipperRule = { text: string; meta: string }

type GlobalImportance = { feature: string; importance: number }

export function ExplainableAiPage() {
	const [localXai, setLocalXai] = useState<LocalXai | null>(null)
	const [limeWeights, setLimeWeights] = useState<LimeWeight[]>([])
	const [ripperRules, setRipperRules] = useState<RipperRule[]>([])
	const [globalImp, setGlobalImp] = useState<GlobalImportance[]>([])

	useEffect(() => {
		setLocalXai({
			packetId: 'TX-8829 (DoS Hulk)',
			baseValue: 0.15,
			output: 0.98,
			shapContributions: [
				{ feature: 'CONN_S...', value: -0.05 },
				{ feature: 'SRC_BYTES', value: 0.6 },
				{ feature: 'DST_PKTS', value: 0.22 },
				{ feature: 'DURATION', value: 0.06 },
			],
		})
		setLimeWeights([
			{ feature: 'src_bytes >', weight: 0.42 },
			{ feature: 'conn_state_', weight: -0.25 },
			{ feature: 'dst_pkts >', weight: 0.28 },
			{ feature: 'duration <', weight: 0.18 },
		])
		setRipperRules([
			{
				text: "IF src_bytes > 12500 AND duration < 0.45 THEN Class = Attack (DoS)",
				meta: '# Support: 14,203 | Precision: 0.99',
			},
			{
				text: "IF dst_pkts > 150 AND conn_state == 'REJ' THEN Class = Attack (PortScan)",
				meta: '# Support: 8,401 | Precision: 0.96',
			},
			{ text: 'DEFAULT THEN Class = Normal', meta: '# Base condition fallback' },
		])
		setGlobalImp([
			{ feature: 'src_bytes', importance: 2.41 },
			{ feature: 'dst_pkts', importance: 1.85 },
			{ feature: 'duration', importance: 1.22 },
			{ feature: 'src_ip_bytes', importance: 0.88 },
			{ feature: 'conn_state_SF', importance: -0.95 },
		])
	}, [])

	return (
		<div className="flex flex-col gap-6 h-full">
			<div className="flex items-center justify-between">
				<div>
					<h1 className="text-2xl font-semibold text-text">Explainable AI (XAI)</h1>
					<p className="text-sm text-text-muted">Visualizing how SENTRi-X made this decision.</p>
				</div>
				<div className="flex items-center gap-2">
					<span className="text-sm text-text-muted">Packet</span>
					<select className="bg-surface border border-border text-text text-sm px-3 py-1.5 rounded-lg">
						<option>{localXai?.packetId ?? 'Select packet'}</option>
					</select>
				</div>
			</div>

			<div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
				<div className="xl:col-span-2 bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-5 shadow-md">
					<div className="flex items-center justify-between mb-4">
						<div>
							<h2 className="text-sm font-semibold text-text">SHAP: Local Interpretability Force Plot</h2>
							<p className="text-xs text-text-muted">Push and pull of features for this prediction.</p>
						</div>
						<div className="text-xs text-text-muted">
							Output:{' '}
							<span className="text-emerald-600 font-semibold">
								{localXai ? localXai.output.toFixed(2) : '--'}
							</span>
						</div>
					</div>
					<div className="mt-4 bg-background-soft rounded-xl px-4 py-6">
						<div className="flex gap-2">
							{localXai?.shapContributions.map((c) => (
								<div
									key={c.feature}
									className={`flex-1 rounded-lg px-3 py-2 text-xs font-medium text-white ${
										c.value >= 0 ? 'bg-rose-500' : 'bg-emerald-500'
									}`}
								>
									<div className="truncate">{c.feature}</div>
									<div className="text-[11px] opacity-80">
										{c.value >= 0 ? '+' : ''}
										{c.value.toFixed(2)}
									</div>
								</div>
							))}
						</div>
						<div className="mt-4 flex justify-between text-[11px] text-text-muted">
							<span>P(Attack) = 0.0</span>
							<span>Base value = {localXai?.baseValue ?? '--'}</span>
							<span>P(Attack) = 1.0</span>
						</div>
					</div>
				</div>
				<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-5 shadow-md">
					<h2 className="text-sm font-semibold text-text mb-1">LIME: Surrogate Weights</h2>
					<p className="text-xs text-text-muted mb-4">Local linear approximation for this packet.</p>
					<div className="space-y-3">
						{limeWeights.map((w) => (
							<div key={w.feature} className="space-y-1">
								<div className="flex justify-between text-xs text-text">
									<span className="truncate">{w.feature}</span>
									<span className={w.weight >= 0 ? 'text-rose-500' : 'text-emerald-600'}>
										{w.weight >= 0 ? '+' : ''}
										{w.weight.toFixed(2)}
									</span>
								</div>
								<div className="h-1.5 bg-background-soft rounded-full overflow-hidden">
									<div
										className={`h-full ${w.weight >= 0 ? 'bg-rose-500' : 'bg-emerald-500'}`}
										style={{ width: `${Math.min(Math.abs(w.weight) * 40, 100)}%` }}
									/>
								</div>
							</div>
						))}
					</div>
				</div>
			</div>

			<div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
				<div className="xl:col-span-2 bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-5 shadow-md">
					<h2 className="text-sm font-semibold text-text mb-1">RIPPER: Symbolic Rule Extraction</h2>
					<p className="text-xs text-text-muted mb-4">Human-readable Boolean logic derived from the Random Forest.</p>
					<div className="space-y-3">
						{ripperRules.map((r, idx) => (
							<div key={idx} className="bg-background-soft rounded-xl px-4 py-3 border border-border">
								<div className="text-xs text-text font-mono">{r.text}</div>
								<div className="mt-1 text-[11px] text-text-muted">{r.meta}</div>
							</div>
						))}
					</div>
				</div>
				<div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-5 shadow-md">
					<h2 className="text-sm font-semibold text-text mb-1">Global Feature Importance</h2>
					<p className="text-xs text-text-muted mb-4">Aggregated impact on model output over the last 24 hours.</p>
					<div className="space-y-3">
						{globalImp.map((g) => (
							<div key={g.feature} className="space-y-1">
								<div className="flex justify-between text-xs text-text">
									<span className="truncate">{g.feature}</span>
									<span className={g.importance >= 0 ? 'text-rose-500' : 'text-emerald-600'}>
										{g.importance >= 0 ? '+' : ''}
										{g.importance.toFixed(2)}
									</span>
								</div>
								<div className="h-1.5 bg-background-soft rounded-full overflow-hidden">
									<div
										className={`h-full ${g.importance >= 0 ? 'bg-rose-500' : 'bg-emerald-500'}`}
										style={{ width: `${Math.min(Math.abs(g.importance) * 25, 100)}%` }}
									/>
								</div>
							</div>
						))}
					</div>
				</div>
			</div>
		</div>
	)
}
