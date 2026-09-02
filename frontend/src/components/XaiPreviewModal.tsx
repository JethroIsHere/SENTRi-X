import { X } from './Icons'
import { classifyThreatLevel, threatLevelTone, type ThreatLevel } from '../utils/threatLevel'

interface XaiPreviewModalProps {
	threatId: string
	threatType: string
	confidence: number
	threatLevel?: ThreatLevel
	sourceIp: string
	destIp: string
	timestamp: string
	shafeatures?: Array<{ f: string; v: number }>
	limefeatures?: Array<{ f: string; v: number }>
	ripperRules?: string
	isOpen: boolean
	onClose: () => void
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
	'proto_udp': 'UDP Protocol',
	'src_pkts': 'Packets sent (Source)',
	'dst_bytes': 'Data received (Destination)',
	'missed_bytes': 'Missed Bytes',
}

const getFeatureName = (f: string) => FEATURE_NAMES[f] || f.replace(/_/g, ' ')

export function XaiPreviewModal({
	threatId,
	threatType,
	confidence,
	threatLevel,
	sourceIp,
	destIp,
	timestamp,
	shafeatures = [],
	limefeatures = [],
	ripperRules = '',
	isOpen,
	onClose,
}: XaiPreviewModalProps) {
	if (!isOpen) return null

	const resolvedThreatLevel = threatLevel || classifyThreatLevel(confidence)
	const ripperPreview = ripperRules.trim()
		? ripperRules
				.trim()
				.split(/\r?\n/)
				.map(line => line.trim())
				.filter(Boolean)
				.slice(0, 3)
				.join(' ')
				.slice(0, 220)
		: ''

	let humanSummary = 'Analyzing network traffic...'
	if (shafeatures.length > 0) {
		const topFeature = shafeatures[0]
		const secondFeature = shafeatures[1]
		const riskDirection = topFeature.v >= 0 ? 'looks risky' : 'looks normal'
		humanSummary = `This traffic was marked as ${resolvedThreatLevel} risk with ${(confidence * 100).toFixed(1)}% certainty. The biggest warning signs were "${getFeatureName(topFeature.f)}"${secondFeature ? ` and "${getFeatureName(secondFeature.f)}"` : ''}. In simple terms, red factors make the AI think "possible attack," while green factors make it think "likely normal traffic." The strongest factor right now ${riskDirection}.`

		if (limefeatures.length > 0) {
			const topLime = limefeatures[0]
			humanSummary += ` A second explanation method (LIME) also highlighted "${getFeatureName(topLime.f)}" as an important reason for this decision.`
		}

		if (ripperRules.trim().length > 0) {
			humanSummary += ' A rule-based cross-check (RIPPER) is also available below for comparison.'
		}
	}

	return (
		<>
			{/* Backdrop */}
			<div
				className="fixed inset-0 bg-black/50 z-40 transition-opacity"
				onClick={onClose}
			/>

			{/* Modal */}
			<div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-xl max-h-[85vh] flex flex-col">
				<div className="rounded-2xl bg-surface/95 backdrop-blur-xl border border-border/60 shadow-2xl p-6 mx-4 flex flex-col overflow-hidden">
					{/* Header */}
					<div className="flex items-start justify-between mb-5 shrink-0">
						<div>
							<h2 className="text-xl font-bold tracking-tight text-text">
								XAI Threat Analysis
							</h2>
							<p className="text-xs text-text-muted mt-0.5">
								Explainable AI breakdown for flow {threatId.slice(-6)}
							</p>
						</div>
						<button
							onClick={onClose}
							className="text-text-muted hover:text-text transition-colors p-1 hover:bg-background-soft rounded-lg"
						>
							<X className="w-5 h-5" />
						</button>
					</div>

					{/* Scrollable Content */}
					<div className="overflow-y-auto overflow-x-hidden pr-2 -mr-2 space-y-5 custom-scrollbar">
						{/* Threat Info Grid */}
						<div className="grid grid-cols-2 gap-3">
							<div className="bg-background-soft rounded-xl p-3 border border-border/40 hover:border-accent/40 transition-colors">
								<div className="text-[10px] text-text-muted uppercase tracking-wider font-semibold mb-1">
									Threat Type
								</div>
								<div className="text-base font-bold text-text truncate">{threatType}</div>
							</div>
							<div className="bg-background-soft rounded-xl p-3 border border-border/40 hover:border-accent/40 transition-colors">
								<div className="text-[10px] text-text-muted uppercase tracking-wider font-semibold mb-1">
									AI Confidence
								</div>
								<div className="flex items-center gap-2">
									<div className="text-base font-bold text-accent-dark">
										{(confidence * 100).toFixed(1)}%
									</div>
									<div className="flex-1 h-2 bg-surface rounded-full overflow-hidden">
										<div
											className="h-full bg-accent-dark transition-all"
											style={{
												width: `${Math.min(confidence * 100, 100)}%`,
											}}
										/>
									</div>
								</div>
							</div>
							<div className="bg-background-soft rounded-xl p-3 border border-border/40 hover:border-accent/40 transition-colors">
								<div className="text-[10px] text-text-muted uppercase tracking-wider font-semibold mb-1">
									Source IP
								</div>
								<div className="text-xs font-mono text-text break-all">{sourceIp}</div>
							</div>
							<div className="bg-background-soft rounded-xl p-3 border border-border/40 hover:border-accent/40 transition-colors">
								<div className="text-[10px] text-text-muted uppercase tracking-wider font-semibold mb-1">
									Destination IP
								</div>
								<div className="text-xs font-mono text-text break-all">{destIp}</div>
							</div>
						</div>

						{/* Human Readable XAI Summary */}
						<div
							className={
								'p-4 rounded-xl border shadow-inner ' +
								threatLevelTone(resolvedThreatLevel)
							}
						>
							<div className="text-xs font-semibold mb-1.5 flex items-center gap-2">
								Threat Level:
								<span
									className={`px-2 py-0.5 rounded-md text-[10px] uppercase tracking-wider font-bold ${
										resolvedThreatLevel === 'Critical'
											? 'bg-rose-500/20 text-rose-500'
											: resolvedThreatLevel === 'High'
												? 'bg-orange-500/20 text-orange-500'
												: resolvedThreatLevel === 'Medium'
													? 'bg-amber-500/20 text-amber-500'
													: 'bg-emerald-500/20 text-emerald-500'
									}`}
								>
									{resolvedThreatLevel}
								</span>
							</div>
							<p className="text-[13px] text-text leading-relaxed font-medium">
								{humanSummary}
							</p>
						</div>

						{/* Key Triggers */}
						{shafeatures.length > 0 && (
							<div>
								<div className="flex items-center justify-between mb-3">
									<h3 className="text-sm font-bold tracking-tight text-text">
										Key AI Triggers (SHAP Values)
									</h3>
									<span className="text-[10px] text-text-muted font-medium px-2 py-0.5 bg-background-soft rounded-md">
										Top Factors
									</span>
								</div>
								<div className="space-y-3">
									{shafeatures.slice(0, 5).map((feature, idx) => (
										<div key={idx} className="group cursor-default">
											<div className="flex justify-between mb-1.5 text-[13px]">
												<span className="font-semibold text-text group-hover:text-accent-dark transition-colors">
													{getFeatureName(feature.f)}
												</span>
												<span
													className={
														feature.v >= 0
															? 'text-rose-500 font-bold'
															: 'text-emerald-500 font-semibold'
													}
												>
													{feature.v >= 0 ? 'Looks Dangerous' : 'Looks Safe'}
												</span>
											</div>
											<div className="h-2 bg-background-soft rounded-full overflow-hidden shadow-inner flex items-center relative">
												{/* Zero baseline indicator */}
												<div className="absolute left-[50%] h-full w-[1px] bg-border/80 z-10" />
												
												{/* Bar */}
												<div
													className={
														'h-full transition-all duration-300 rounded-full relative z-0 ' +
														(feature.v >= 0 ? 'bg-rose-500' : 'bg-emerald-500')
													}
													style={{
														width: `${Math.min(Math.abs(feature.v) * 50, 50)}%`,
														marginLeft: feature.v >= 0 ? '50%' : `${50 - Math.min(Math.abs(feature.v) * 50, 50)}%`
													}}
												/>
											</div>
											<div className="flex justify-between items-center text-[10px] text-text-muted mt-1 opacity-70 group-hover:opacity-100 transition-opacity">
												<span>Neutral Point</span>
												<span>Influence: {feature.v.toFixed(3)}</span>
											</div>
										</div>
									))}
								</div>
							</div>
						)}

						{limefeatures.length > 0 && (
							<div>
								<div className="flex items-center justify-between mb-3">
									<h3 className="text-sm font-bold tracking-tight text-text">
										LIME Check (Second Opinion)
									</h3>
									<span className="text-[10px] text-text-muted font-medium px-2 py-0.5 bg-background-soft rounded-md">
										Top Factors
									</span>
								</div>
								<div className="space-y-3">
									{limefeatures.slice(0, 3).map((feature, idx) => (
										<div key={idx} className="group cursor-default">
											<div className="flex justify-between mb-1.5 text-[13px]">
												<span className="font-semibold text-text group-hover:text-accent-dark transition-colors">
													{getFeatureName(feature.f)}
												</span>
												<span
													className={
														feature.v >= 0
															? 'text-rose-500 font-bold'
															: 'text-emerald-500 font-semibold'
													}
												>
													{feature.v >= 0 ? 'Raises Risk' : 'Lowers Risk'}
												</span>
											</div>
											<div className="h-2 bg-background-soft rounded-full overflow-hidden shadow-inner">
												<div
													className={
														'h-full transition-all duration-300 rounded-full ' +
														(feature.v >= 0 ? 'bg-rose-500' : 'bg-emerald-500')
													}
													style={{ width: `${Math.min(Math.abs(feature.v) * 100, 100)}%` }}
												/>
											</div>
										</div>
									))}
								</div>
							</div>
						)}

						{ripperRules.trim().length > 0 && (
							<div>
								<div className="flex items-center justify-between mb-3">
									<h3 className="text-sm font-bold tracking-tight text-text">
										RIPPER Rule Check
									</h3>
									<span className="text-[10px] text-text-muted font-medium px-2 py-0.5 bg-background-soft rounded-md">
										Rule-Based
									</span>
								</div>
								<div className="rounded-xl border border-border/40 bg-background-soft p-3 text-[12px] text-text-muted leading-relaxed">
									<p className="font-medium text-text mb-1">
										Rule-based summary
									</p>
									<p>
										RIPPER is loaded as a static rule set for cross-checking. Sample excerpt: <span className="font-mono text-text">{ripperPreview || 'rule text unavailable'}</span>{ripperPreview.length >= 220 ? '...' : ''}
									</p>
								</div>
							</div>
						)}
					</div>

					{/* Footer */}
					<div className="mt-5 pt-3 border-t border-border/40 text-[11px] text-text-muted shrink-0 flex justify-between items-center bg-background-soft/30 -mx-6 -mb-6 px-6 py-4">
						<p>
							Timestamp: <span className="font-mono bg-background-soft px-1 py-0.5 rounded border border-border/40">{timestamp}</span>
						</p>
						<p className="font-medium text-text-muted/80">
							Hybrid Ensemble Model
						</p>
					</div>
				</div>
			</div>
		</>
	)
}
