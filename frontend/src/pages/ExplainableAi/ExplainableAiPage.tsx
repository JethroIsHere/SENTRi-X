import { useState } from 'react'

type RipperRule = { text: string; meta: string }

export function ExplainableAiPage() {
    const [ripperRules] = useState<RipperRule[]>([
        {
            text: "When a device rapidly blasts huge amounts of data but the connection closes almost instantly, the AI flags it as a flood.",
            meta: 'Denial of Service (DoS / DDoS) attacks overload services with heavy, rapid-fire requests.',
        },
        {
            text: "If an external IP triggers consecutive rejected or disconnected attempts across multiple ports, it is flagged as reconnaissance.",
            meta: 'Automated Port Scanning (like Nmap or ZMap) probing for vulnerabilities.',
        },
        {
            text: "When a device starts making rhythmic, incomplete handshakes and sending irregular data spikes outward, it suggests a compromised host.",
            meta: 'Botnet Command & Control (C2) malware phoning home.',   
        },
        {
            text: "If a small incoming web request generates an unusually massive response body, or frequently triggers HTTP error codes, it points to an exploit.",
            meta: 'Web Application Attacks (SQL Injection, XSS) attempting to dump databases.',
        },
        {
            text: "When an external attacker sends a massive payload inward but the server barely responds, the system suspects a remote code execution payload.",
            meta: 'Network Infiltration and initial exploitation phases.',
        },
        {
            text: "If an internal connection stays open for an unnaturally long time while slowly and steadily streaming data outward, it is flagged as theft.",
            meta: 'Data Exfiltration by an insider threat or persistent malware.',
        },
        {
            text: "Repeated, identical small-packet requests fired at a service that constantly drop before fully completing are categorized as password guessing.",
            meta: 'Brute Force Authentication attacks on SSH, FTP, or Telnet.',
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
