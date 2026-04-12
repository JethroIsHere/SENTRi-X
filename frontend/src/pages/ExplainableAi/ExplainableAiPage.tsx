import { useState } from 'react'

type RipperRule = { text: string; meta: string }

export function ExplainableAiPage() {
    const [ripperRules] = useState<RipperRule[]>([
        {
            text: "IF 'Data sent (Source Bytes)' is abnormally high AND 'Connection Time' is suspiciously short THEN Flag as Attack",
            meta: 'Matches typical Denial of Service (DoS) behavior',
        },
        {
            text: "IF 'Packets received' > Threshold AND 'Connection State' is Rejected THEN Flag as Port Scan",
            meta: 'Matches automated scanning (Nmap/ZMap) behavior',
        },
        {
            text: "IF 'Total Destination IP Data' spikes AND 'Normal Connection Finished' is FALSE THEN Flag as Malicious",
            meta: 'Matches incomplete handshake patterns of Botnet activity',   
        },
        {
            text: "IF 'Data sent' > 'Packets received' AND 'Abnormal Connection State' is TRUE THEN Flag as Infiltration Attempt",
            meta: 'Matches initial reconnaissance and remote exploitation phases',
        },
        {
            text: "IF 'Connection Time' is severely prolonged AND 'Data sent' is unusually uniform THEN Flag as Data Exfiltration",
            meta: 'Matches attempts to stealthily siphon internal network asset data',
        },
        {
            text: "IF 'Abnormal Connection State' occurs consecutively > 100 times THEN Flag as DDoS",
            meta: 'Matches intense UDP/TCP flooding characteristics',
        }
    ])

    return (
        <div className="flex flex-col gap-6 h-full">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold text-text">Extracted Attack Rules</h1>
                    <p className="text-sm text-text-muted">Boolean rule-sets reverse-engineered from the active Random Forest classifier.</p>
                </div>
            </div>

            <div className="grid grid-cols-1 gap-6">
                {/* Behavioral Rules Only */}
                <div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md">
                    <h2 className="text-lg font-semibold text-text mb-2">Known Attack Behaviors Observed</h2>
                    <p className="text-sm text-text-muted mb-6">When the AI categorizes traffic, it implicitly checks for these behavioral patterns.</p>    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">     
                        {ripperRules.map((r, idx) => (
                            <div key={idx} className="bg-background-soft rounded-xl px-5 py-5 border border-border/50">
                                <div className="text-sm font-medium text-blue-400 mb-3">{r.text}</div>
                                <div className="text-xs text-text-muted bg-surface/50 p-2.5 rounded-lg border border-border/30">{r.meta}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    )
}
