export type ThreatLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Monitoring'

export function classifyThreatLevel(confidence: number): ThreatLevel {
	if (confidence >= 0.98) return 'Critical'
	if (confidence >= 0.95) return 'High'
	if (confidence >= 0.90) return 'Medium'
	return 'Low'
}

export function threatLevelTone(level: ThreatLevel) {
	switch (level) {
		case 'Critical':
			return 'bg-rose-500/10 text-rose-500 border-rose-500/30'
		case 'High':
			return 'bg-orange-500/10 text-orange-500 border-orange-500/30'
		case 'Medium':
			return 'bg-amber-500/10 text-amber-500 border-amber-500/30'
		case 'Low':
			return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30'
		default:
			return 'bg-slate-500/10 text-slate-500 border-slate-500/30'
	}
}