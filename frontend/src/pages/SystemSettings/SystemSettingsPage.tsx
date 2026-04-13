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

        const handleToggle = () => {
                setSettings((s) => ({ ...s, activeAlerting: !s.activeAlerting }))
        }

        const handleSlider = (e: React.ChangeEvent<HTMLInputElement>) => {      
                const value = Number(e.target.value)
                setSettings((s) => ({ ...s, confidenceThreshold: value }))      
        }

        return (
                <div className="flex flex-col gap-6 h-full">
                        <div>
                                <h1 className="text-2xl font-semibold text-text">System Settings</h1>
                                <p className="text-sm text-text-muted">Configure SENTRi-X monitoring behavior and active deployment models.</p>
                        </div>
                        
                        <div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 max-w-4xl shadow-md">
                                <h2 className="text-sm font-semibold text-text mb-4 border-b border-border pb-2 text-blue-500">Active Defense Engine</h2>
                                <p className="text-xs text-text-muted mb-4">SENTRi-X is currently running in its unified global state, leveraging Transfer Learning to process heterogeneous networks simultaneously.</p>
                                
                                <div className="grid grid-cols-1 gap-4 mb-4">
                                        <div className="p-4 rounded-xl border border-purple-500 bg-purple-500/10 text-left transition-all">
                                                <div className="text-sm font-bold text-text mb-1 flex items-center gap-2">
                                                        <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                                                        Omni Defense Mode (Global Model) - Active
                                                </div>
                                                <div className="text-xs text-text-muted">Source: All Datasets Combined (ToN-IoT, BoT-IoT, CIC-IDS2017)</div>
                                                <div className="text-[10px] text-purple-400 mt-2 font-mono">rf_model_omni & cnn_model_omni</div>
                                        </div>
                                </div>
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
