import { useState } from 'react'

type SecurityRule = { title: string; description: string }

export function ExplainableAiPage() {
    const [rules] = useState<SecurityRule[]>([
        {
            title: "Flood Attack (DDoS)",
            description: "Someone sends tons of data at super-high speed to crash a service. The AI spots sudden huge amounts of traffic that come and go quickly.",
        },
        {
            title: "Port Scanning",
            description: "Someone tries to find open doors on a computer by testing many ports really fast. The AI sees lots of connection attempts that all fail.",
        },
        {
            title: "Botnet Activity",
            description: "A hacked computer keeps sending weird little messages on a repeating pattern, trying to contact its master. The AI notices strange rhythmic patterns.",
        },
        {
            title: "Web Attack (Hacking Website)",
            description: "Someone tries to trick a website into giving them data or letting them run code. The AI spots tiny requests that cause huge strange responses.",
        },
        {
            title: "Attempted Break-In",
            description: "Someone tries to send harmful code to run on a computer. The AI watches for big messy data coming in that the server doesn't properly handle.",
        },
        {
            title: "Data Theft",
            description: "A connection stays open for way too long while data slowly leaks out in a steady stream. The AI flags connections that stay alive unnaturally long.",
        },
        {
            title: "Password Guessing",
            description: "Someone rapidly tries thousands of password combinations to break in. The AI sees the exact same tiny failed requests happening over and over.",
        }
    ])

    return (
        <div className="flex flex-col gap-6 h-full">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold text-text">Security Attack Rules</h1>
                    <p className="text-base text-text-muted mt-2">Here's what the AI looks for. These are the types of attacks it can recognize:</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {rules.map((rule, idx) => (
                    <div key={idx} className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md hover:shadow-lg transition-shadow">
                        <h3 className="text-lg font-bold text-text mb-3 flex items-start gap-3">
                            <span className="text-2xl font-bold text-accent-dark min-w-[2rem]">{idx + 1}.</span>
                            {rule.title}
                        </h3>
                        <p className="text-base text-text-muted leading-relaxed">{rule.description}</p>
                    </div>
                ))}
            </div>

            <div className="bg-surface/80 backdrop-blur-md border border-border/80 rounded-2xl p-6 shadow-md mt-4">
                <h2 className="text-lg font-semibold text-text mb-3">How It Works</h2>
                <p className="text-base text-text-muted leading-relaxed">
                    The AI watches network traffic and looks for suspicious patterns. When it sees something that matches one of these attack behaviors, it raises an alert and shows you what it found. Each alert includes a confidence score (how sure the AI is) and an explanation of what features triggered the alarm.
                </p>
            </div>
        </div>
    )
}
