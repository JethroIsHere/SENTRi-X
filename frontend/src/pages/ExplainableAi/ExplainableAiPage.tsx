import { panelClass } from '../../components/LiveTelemetry'

const guide = [
  ['Denial of service / DDoS', 'Large traffic volumes or repeated requests can exhaust a service. Flow counts and byte totals provide context, but a traffic spike alone does not establish an attack.'],
  ['Port scanning', 'Repeated attempts to reach different ports may indicate service discovery. Investigating it requires examining the related connections, timing, and endpoints.'],
  ['Password guessing', 'Repeated authentication attempts can indicate brute force. Network flow statistics alone do not reveal whether a password was accepted.'],
  ['Botnet communication', 'Compromised devices may contact remote infrastructure. A remote connection by itself is not proof of compromise.'],
]

export function ExplainableAiPage() {
  return <div className="space-y-6 max-w-6xl">
    <header><h1 className="text-3xl font-bold">Attack Guide & Reference Rules</h1><p className="mt-2 text-sm text-text-muted">Background information and stored explanation artifacts for reviewing alerts.</p></header>
    <section className={panelClass}><h2 className="mb-3 text-lg font-semibold">What the Live Classifier Reports</h2><p className="text-sm text-text-muted">The RF and CNN models predict benign or attack. A separate heuristic component describes observed flow patterns, such as a high packet rate or rejected connection. These labels are review cues, not verified attack subtypes or model subtype predictions. Scanning, password guessing, and service exhaustion require correlated traffic and independent evidence. Simulation labels may come from the replay dataset.</p></section>
    <div className="grid gap-4 md:grid-cols-2">{guide.map(([title, detail]) => <article key={title} className={panelClass}><h2 className="mb-3 font-semibold">{title}</h2><p className="text-sm text-text-muted">{detail}</p></article>)}</div>
    <section className={panelClass}><h2 className="mb-3 font-semibold">Reviewing an Alert</h2><p className="text-sm text-text-muted">Open an alert in Threat Logs to inspect its origin, addresses, model, confidence, and saved explanation. Reference-sample SHAP, global RF importance, and local RF LIME are labelled separately. Missing explanations remain unavailable.</p></section>
  </div>
}

