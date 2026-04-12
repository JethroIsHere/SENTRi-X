import { useEffect, useState, useMemo } from 'react';

type Threat = {
    id: string;
    timestamp: string;
    source_ip: string;
    target_ip: string;
    attack_type: string;
    confidence: number;
    status: string;
};

type Node = {
    id: string;
    x: number;
    y: number;
    ip: string;
    isCore: boolean;
    threats: number;
    lastSeen: string;
};

export function NetworkGraphPage() {
    const [threats, setThreats] = useState<Threat[]>([]);
    const [selectedNode, setSelectedNode] = useState<Node | null>(null);

    useEffect(() => {
        const fetchThreats = async () => {
            try {
                const response = await fetch('http://127.0.0.1:8000/api/threat-logs');
                const data = await response.json();
                setThreats(data.slice(0, 15));
            } catch (err) {
                console.error(err);
            }
        };
        fetchThreats();
        const interval = setInterval(fetchThreats, 3000);
        return () => clearInterval(interval);
    }, []);

    const nodes = useMemo(() => {
        const core: Node = { id: 'core', x: 50, y: 50, ip: '10.0.0.X (Gateway)', isCore: true, threats: 0, lastSeen: 'Now' };
        const map = new Map<string, Node>();
        map.set('core', core);

        threats.forEach((t, i) => {
            if (!map.has(t.source_ip)) {
                // Randomish position around center
                const angle = (i * 137.5) * (Math.PI / 180);
                const radius = 25 + Math.random() * 20;
                map.set(t.source_ip, {
                    id: t.source_ip,
                    ip: t.source_ip,
                    x: 50 + radius * Math.cos(angle),
                    y: 50 + radius * Math.sin(angle),
                    isCore: false,
                    threats: 1,
                    lastSeen: t.timestamp
                });
            } else {
                map.get(t.source_ip)!.threats += 1;
                map.get(t.source_ip)!.lastSeen = t.timestamp;
            }
        });
        return Array.from(map.values());
    }, [threats]);

    const activeThreat = threats.length > 0 ? threats[0] : null;

    return (
        <div className="flex flex-col gap-6 h-full">
            <header>
                <h1 className="text-2xl font-semibold text-text">Network Graph</h1>
                <p className="text-sm text-text-muted">Live topology of interacting endpoint identifiers.</p>
            </header>

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 flex-1">
                <div className="xl:col-span-2 rounded-2xl bg-surface/80 backdrop-blur-md border border-border/80 shadow-md p-5 relative overflow-hidden min-h-[400px] flex items-center justify-center">
                    <svg className="absolute inset-0 w-full h-full pointer-events-none">
                        {nodes.filter(n => !n.isCore).map(n => (
                            <line 
                                key={"line-" + n.id}
                                x1="50%" y1="50%"
                                x2={n.x + "%"} y2={n.y + "%"}
                                className={"stroke-[1.5] " + (n.threats > 2 ? 'stroke-rose-500/50' : 'stroke-blue-500/30')}
                                strokeDasharray={n.threats > 2 ? "4" : undefined}
                            />
                        ))}
                    </svg>

                    {nodes.map(n => (
                        <div
                            key={n.id}
                            onClick={() => setSelectedNode(n)}
                            className={"absolute transform -translate-x-1/2 -translate-y-1/2 rounded-full flex items-center justify-center cursor-pointer transition-all hover:scale-110 " + (
                                n.isCore ? 'w-16 h-16 bg-blue-600/20 border-2 border-blue-500 shadow-[0_0_20px_rgba(59,130,246,0.5)] z-20' :
                                n.threats > 2 ? 'w-10 h-10 bg-rose-500/20 border-2 border-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.5)] z-10' :
                                'w-8 h-8 bg-surface-subtle border border-border z-10'
                            )}
                            style={{ left: n.x + "%", top: n.y + "%" }}
                        >
                            {!n.isCore && <span className="text-[10px] absolute -bottom-5 text-text-muted whitespace-nowrap bg-background/80 px-1 rounded">{n.ip}</span>}
                            {n.isCore && <span className="text-xs font-bold text-blue-400">IDS</span>}
                        </div>
                    ))}
                </div>

                <div className="rounded-2xl bg-surface/80 backdrop-blur-md border border-border/80 shadow-md p-5 space-y-3 text-sm">
                    <h2 className="text-sm font-semibold text-text">Node Properties</h2>
                    <div className="text-xs text-text-muted">
                        Selected Node: {selectedNode ? selectedNode.ip : 'Click a node on map'}
                    </div>
                    {selectedNode && (
                        <>
                            <div className="space-y-2 text-xs text-text mt-4">
                                <div className="flex justify-between">
                                    <span>Type</span>
                                    <span className="text-accent-dark">{selectedNode.isCore ? 'IDS Core Gateway' : 'External Host'}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span>Recent Traces</span>
                                    <span className="text-text-muted">{selectedNode.threats}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span>Last Seen</span>
                                    <span className="text-text-muted">{selectedNode.lastSeen}</span>
                                </div>
                            </div>
                            {!selectedNode.isCore && (
                                <button className="w-full mt-4 inline-flex items-center justify-center rounded-lg bg-rose-500/10 text-rose-500 hover:bg-rose-500/20 text-xs font-medium px-3 py-2 border border-rose-500/50 transition-colors">
                                    Simulate Connection Drop for {selectedNode.ip}
                                </button>
                            )}
                        </>
                    )}
                </div>
            </div>

            {activeThreat && (
                <div className="rounded-2xl bg-surface/80 backdrop-blur-md border border-border/80 shadow-md px-5 py-4 text-xs text-text flex flex-col md:flex-row items-start md:items-center justify-between gap-2 border-l-4 border-l-rose-500">
                    <div>
                        <span className="text-text-muted">Target: </span> 
                        <span className="font-mono">{activeThreat.source_ip} &rarr; {activeThreat.target_ip} ({activeThreat.attack_type})</span>
                    </div>
                    <span className="text-rose-500 font-medium bg-rose-500/10 px-3 py-1 rounded-full uppercase tracking-widest text-[10px]">
                        {activeThreat.status}: {Math.round(activeThreat.confidence * 100)}% Confidence
                    </span>
                </div>
            )}
        </div>
    );
}
