import { useEffect, useRef, useState } from 'react'

type LogLevel = 'system' | 'info' | 'alert' | 'action'

type LogLine = { level: LogLevel; text: string }

export function TerminalCliPage() {
	const [lines, setLines] = useState<LogLine[]>([])
	const [input, setInput] = useState('')
	const scrollRef = useRef<HTMLDivElement | null>(null)

	useEffect(() => {
		setLines([
			{ level: 'system', text: 'Initializing Hybrid Ensemble Engine (SENTRi-X v1.0.0)...' },
			{ level: 'system', text: 'Loaded Random Forest Checkpoint: rf_model_ton_iot.joblib' },
			{ level: 'system', text: 'Loaded CNN Checkpoint: cnn_model_ton_iot.h5' },
			{ level: 'system', text: 'Models synchronized. Awaiting packet stream on interface eth0...' },
			{ level: 'info', text: 'Analyzing Flow: 192.168.1.50 → 8.8.8.8 | Prediction: Normal' },
			{
				level: 'alert',
				text: 'Intrusion Detected! Flow: 192.168.1.105 → 10.0.0.5 | Type: DoS Hulk | Conf: 98.1%',
			},
			{
				level: 'action',
				text: 'Executing mitigation. Dropping packets from 192.168.1.105 via iptables PREROUTING.',
			},
			{ level: 'info', text: 'Analyzing Flow: 192.168.1.110 → 10.0.0.5 | Prediction: Normal' },
		])
	}, [])

	useEffect(() => {
		if (scrollRef.current) {
			scrollRef.current.scrollTop = scrollRef.current.scrollHeight
		}
	}, [lines])

	const handleSubmit = (e: React.FormEvent) => {
		e.preventDefault()
		if (!input.trim()) return
		const cmd = input.trim()
		setLines((prev) => [
			...prev,
			{ level: 'action', text: `sentri-x@edge-node:~$ ${cmd}` },
			{ level: 'info', text: `Echo: ${cmd}` },
		])
		setInput('')
	}

	const colorForLevel = (level: LogLevel) => {
		switch (level) {
			case 'system':
				return 'text-emerald-400'
			case 'info':
				return 'text-sky-400'
			case 'alert':
				return 'text-rose-400'
			case 'action':
				return 'text-amber-300'
			default:
				return 'text-slate-100'
		}
	}

	const labelForLevel = (level: LogLevel) => {
		switch (level) {
			case 'system':
				return '[SYSTEM]'
			case 'info':
				return '[INFO]'
			case 'alert':
				return '[ALERT]'
			case 'action':
				return '[ACTION]'
		}
	}

	return (
		<div className="flex flex-col gap-4 h-full">
			<div>
				<h1 className="text-2xl font-semibold text-text">Terminal CLI</h1>
				<p className="text-sm text-text-muted">Remote shell view into the SENTRi-X edge node.</p>
			</div>
			<div className="flex-1 bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl overflow-hidden flex flex-col shadow-md">
				<div className="flex items-center gap-2 px-4 py-2 bg-surface-subtle border-b border-border text-xs text-text-muted">
					<div className="flex gap-1">
						<span className="h-2.5 w-2.5 rounded-full bg-rose-500" />
						<span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
						<span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
					</div>
					<span className="ml-3">sentri-x@edge-node: ~/core</span>
				</div>
				<div
					ref={scrollRef}
					className="flex-1 px-4 py-3 font-mono text-xs text-slate-100 overflow-y-auto space-y-1 bg-black"
				>
					{lines.map((line, idx) => (
						<div key={idx} className="whitespace-pre-wrap">
							<span className={colorForLevel(line.level)}>{labelForLevel(line.level)} </span>
							<span>{line.text}</span>
						</div>
					))}
					<div className="text-emerald-400 mt-2">
						root@sentri-x:~/core$
						<span className="inline-block w-2 h-4 bg-emerald-400 ml-1 animate-pulse" />
					</div>
				</div>
				<form onSubmit={handleSubmit} className="border-t border-slate-900 px-4 py-2 bg-slate-950/90">
					<div className="flex items-center gap-2 font-mono text-xs text-slate-300">
						<span>sentri-x@edge-node:~/core$</span>
						<input
							className="flex-1 bg-transparent outline-none border-none text-slate-100 placeholder:text-slate-600"
							value={input}
							onChange={(e) => setInput(e.target.value)}
							placeholder="type a command (e.g., status, tail logs)..."
						/>
					</div>
				</form>
			</div>
		</div>
	)
}
