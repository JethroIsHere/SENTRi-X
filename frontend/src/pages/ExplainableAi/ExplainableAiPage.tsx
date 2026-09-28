import { useApiPoll } from '../../lib/api'
import { panelClass, RequestState } from '../../components/LiveTelemetry'

const guide = [
  ['Denial of service / DDoS', 'Large traffic volumes or repeated requests can exhaust a service. Flow counts and byte totals provide context, but a traffic spike alone does not establish an attack.'],
  ['Port scanning', 'Repeated attempts to reach different ports may indicate service discovery. Investigating it requires examining the related connections, timing, and endpoints.'],
  ['Password guessing', 'Repeated authentication attempts can indicate brute force. Network flow statistics alone do not reveal whether a password was accepted.'],
  ['Botnet communication', 'Compromised devices may contact remote infrastructure. A remote connection by itself is not proof of compromise.'],
]

export function ExplainableAiPage() {
  const rules = useApiPoll<{ rules: string; scope: string; evaluated_on_live_flow: boolean }>('/api/explainability/ripper', 10000)
  return <div className="space-y-6 max-w-6xl">
    <header><h1 className="text-3xl font-bold">Attack Guide & Reference Rules</h1><p className="mt-2 text-sm text-text-muted">Background information and stored explanation artifacts for reviewing alerts.</p></header>
    <section className={panelClass}><h2 className="mb-3 text-lg font-semibold">What the Live Classifier Reports</h2><p className="text-sm text-text-muted">The current live models classify a flow as benign or attack. They do not produce the attack subtypes listed below. A live alert is recorded as a malicious flow anomaly; simulation labels may come from the replay dataset.</p></section>
    <div className="grid gap-4 md:grid-cols-2">{guide.map(([title, detail]) => <article key={title} className={panelClass}><h2 className="mb-3 font-semibold">{title}</h2><p className="text-sm text-text-muted">{detail}</p></article>)}</div>
    <section className={panelClass}><h2 className="text-lg font-semibold">Stored RIPPER Rules</h2><p className="my-3 text-xs text-text-muted">Reference text loaded by the backend. These rules are not an enforced firewall policy and are not evaluated against each arriving flow.</p><RequestState error={rules.error} loading={rules.loading} />
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl bg-background-soft p-4 text-xs">{rules.data?.rules || 'No RIPPER rule artifact is available.'}</pre>
    </section>
    <section className={panelClass}><h2 className="mb-3 font-semibold">Reviewing an Alert</h2><p className="text-sm text-text-muted">Open an alert in Threat Logs to inspect its origin, addresses, model, confidence, and saved explanation. Reference-sample SHAP, global RF importance, and local RF LIME are labelled separately. Missing explanations remain unavailable.</p></section>
  </div>
}
