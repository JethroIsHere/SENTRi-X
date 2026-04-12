import { useState } from 'react'

type Settings = {
        activeAlerting: boolean
        confidenceThreshold: number
}

export function SystemSettingsPage() {
        const [settings, setSettings] = useState<Settings>({
                activeAlerting: true,
                confidenceThreshold: 85,
        })
        const [switchStatus, setSwitchStatus] = useState<string | null>(null)
        const [isSwitching, setIsSwitching] = useState(false)
        const [activeModel, setActiveModel] = useState("ton_iot")

        const handleToggle = () => {
                setSettings((s) => ({ ...s, activeAlerting: !s.activeAlerting }))
        }

        const handleSlider = (e: React.ChangeEvent<HTMLInputElement>) => {      
                const value = Number(e.target.value)
                setSettings((s) => ({ ...s, confidenceThreshold: value }))      
        }

        const triggerModelSwitch = async (model: string, dataset: string) => {
                setIsSwitching(true)
                setSwitchStatus('Swapping core engine to ...')
                try {
                        const response = await fetch('http://127.0.0.1:8000/api/switch', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ model_type: model, dataset: dataset })
                        })
                        const data = await response.json()
                        setSwitchStatus(data.message)
                        setActiveModel(model)
                } catch (error) {
                        setSwitchStatus('Error contacting local API server.')
                        console.error(error)
                } finally {
                        setIsSwitching(false)
                        setTimeout(() => setSwitchStatus(null), 5000)
                }
        }

        return (
                <div className="flex flex-col gap-6 h-full">
                        <div>
                                <h1 className="text-2xl font-semibold text-text">System Settings</h1>
                                <p className="text-sm text-text-muted">Configure SENTRi-X monitoring behavior and active deployment models.</p>
                        </div>
                        
                        <div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 max-w-4xl shadow-md">
                                <h2 className="text-sm font-semibold text-text mb-4 border-b border-border pb-2 text-blue-500">Academic Deployment Controls (50% Defense)</h2>
                                <p className="text-xs text-text-muted mb-4">Dynamically toggle active data streams and inference models to demonstrate Domain Adaptation & Transfer Learning.</p>
                                
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                                        <button
                                                onClick={() => triggerModelSwitch('ton_iot', 'ton_iot')}
                                                disabled={isSwitching}
                                                className={`p-4 rounded-xl border text-left transition-all ${activeModel === 'ton_iot' ? 'border-blue-500 bg-blue-500/10' : 'border-border/50 bg-background-soft hover:bg-surface-subtle'}`}
                                        >
                                                <div className="text-sm font-medium text-text mb-1">Baseline Model</div>
                                                <div className="text-xs text-text-muted">Source: ToN_IoT</div>
                                                <div className="text-[10px] text-blue-400 mt-2 font-mono">rf_model_ton_iot</div>
                                        </button>

                                        <button
                                                onClick={() => triggerModelSwitch('bot_iot', 'bot_iot')}
                                                disabled={isSwitching}
                                                className={`p-4 rounded-xl border text-left transition-all ${activeModel === 'bot_iot' ? 'border-rose-500 bg-rose-500/10' : 'border-border/50 bg-background-soft hover:bg-surface-subtle'}`}
                                        >
                                                <div className="text-sm font-medium text-text mb-1">Zero-Day Variant A</div>
                                                <div className="text-xs text-text-muted">Source: BoT-IoT</div>
                                                <div className="text-[10px] text-rose-400 mt-2 font-mono">rf_model_bot_iot_finetuned</div>
                                        </button>

                                        <button
                                                onClick={() => triggerModelSwitch('cic_ids2017', 'cic_ids2017')}
                                                disabled={isSwitching}
                                                className={`p-4 rounded-xl border text-left transition-all ${activeModel === 'cic_ids2017' ? 'border-emerald-500 bg-emerald-500/10' : 'border-border/50 bg-background-soft hover:bg-surface-subtle'}`}
                                        >
                                                <div className="text-sm font-medium text-text mb-1">Zero-Day Variant B</div>
                                                <div className="text-xs text-text-muted">Source: CIC-IDS2017</div>
                                                <div className="text-[10px] text-emerald-400 mt-2 font-mono">rf_model_cic_finetuned</div>
                                        </button>
                                </div>
                                {switchStatus && (
                                        <div className="px-4 py-3 rounded-lg bg-background-soft border border-border text-xs text-text-muted animate-pulse">
                                                {switchStatus}
                                        </div>
                                )}
                        </div>

                        <div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 max-w-4xl shadow-md">
                                <h2 className="text-sm font-semibold text-text mb-4">Detection Configuration</h2>
                                <div className="py-4 border-b border-border flex items-center justify-between gap-4">
                                        <div>
                                                <div className="text-sm font-medium text-text">Active Alerting Mode</div>
                                                <div className="text-xs text-text-muted mt-1">
                                                        Automatically push suspected malicious traffic events to the SOC dashboard.
                                                </div>
                                        </div>
                                        <button
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
