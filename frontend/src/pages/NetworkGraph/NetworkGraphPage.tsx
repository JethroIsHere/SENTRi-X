export function NetworkGraphPage() {
	return (
		<div className="flex flex-col gap-6">
				<header>
					<h1 className="text-2xl font-semibold text-text">Network Graph</h1>
					<p className="text-sm text-text-muted">Visual map of nodes monitored by SENTRi-X.</p>
				</header>
				<div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
					<div className="xl:col-span-2 rounded-2xl bg-surface/80 backdrop-blur-md border border-border/80 shadow-md p-5 flex items-center justify-center text-text-muted text-sm">
					<span>Graph canvas placeholder — later replace with real topology / force-directed graph.</span>
				</div>
					<div className="rounded-2xl bg-surface/80 backdrop-blur-md border border-border/80 shadow-md p-5 space-y-3 text-sm">
						<h2 className="text-sm font-semibold text-text">Node Properties</h2>
						<div className="text-xs text-text-muted">Selected Node: 192.168.1.105</div>
						<div className="space-y-2 text-xs text-text">
							<div className="flex justify-between"><span>Outbound Volume</span><span className="text-accent-dark">842 KB/s</span></div>
							<div className="flex justify-between"><span>Threat Association Score</span><span className="text-rose-500">0.92</span></div>
							<div className="flex justify-between"><span>Last Seen</span><span className="text-text-muted">10:14:32</span></div>
					</div>
						<button className="mt-4 inline-flex items-center justify-center rounded-lg bg-accent text-accent-dark text-xs font-medium px-3 py-2 border border-accent">
						Block Node
					</button>
				</div>
			</div>
				<div className="rounded-2xl bg-surface/80 backdrop-blur-md border border-border/80 shadow-md px-5 py-3 text-xs text-text flex items-center justify-between">
					<span>Target: 192.168.1.105 → 10.0.0.5 (DoS Hulk)</span>
					<span className="text-emerald-600 font-medium">Mitigation: Active (iptables PREROUTING)</span>
			</div>
		</div>
	)
}
