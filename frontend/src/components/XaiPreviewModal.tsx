import { useEffect, useRef } from 'react'
import type { Alert, Feature } from '../lib/api'
import { formatTime, percent, sourceLabel, useApiPoll } from '../lib/api'
import { threatLevelTone } from '../utils/threatLevel'

function Features({ values, signed, target }: { values: Feature[]; signed: boolean; target: string }) {
  const largest = Math.max(...values.map(value => Math.abs(value.v)), 0.001)
  return <div className="space-y-3">{values.filter(item => Number.isFinite(item.v)).map((feature, index) => <div key={`${feature.f}-${index}`}>
    <div className="flex justify-between gap-3 text-xs"><span>{feature.f.replace(/_/g, ' ')}</span><span className="font-mono">{feature.v.toFixed(4)}</span></div>
    <div className="mt-1 h-2 overflow-hidden rounded bg-background-soft"><div className={signed ? feature.v >= 0 ? 'h-full bg-rose-500' : 'h-full bg-emerald-500' : 'h-full bg-accent'} style={{ width: `${Math.abs(feature.v) / largest * 100}%` }} /></div>
    {signed && <p className="mt-1 text-xs text-text-muted">{feature.v > 0 ? 'Supports' : feature.v < 0 ? 'Opposes' : 'Neutral contribution to'} the {target} class in this explanation.</p>}
  </div>)}</div>
}

export function XaiPreviewModal({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const closeButton = useRef<HTMLButtonElement>(null)
  const closeAction = useRef(onClose)
  closeAction.current = onClose
  const rules = useApiPoll<{ rules: string }>('/api/explainability/ripper', 0)
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'; closeButton.current?.focus()
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeAction.current()
      if (event.key === 'Tab') { event.preventDefault(); closeButton.current?.focus() }
    }
    window.addEventListener('keydown', keydown)
    return () => { document.body.style.overflow = overflow; window.removeEventListener('keydown', keydown); previous?.focus() }
  }, [])
  const meta = alert.explanation_meta || {}
  const method = meta.shap_method
  const title = method === 'global_rf_importance' ? 'Global Random Forest Feature Importance'
    : method === 'reference_sample_shap' ? 'SHAP from a Stored Reference Sample' : 'Stored Feature Values — Method Unverified'
  const shap = alert.shap_values || []
  const lime = alert.lime_values || []
  const limeVerified = meta.lime_method === 'local_rf_lime' && meta.lime_target_class != null
  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
    <div role="dialog" aria-modal="true" aria-labelledby="explanation-title" onClick={event => event.stopPropagation()} className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-border bg-surface p-6 text-text shadow-xl">
      <div className="flex items-start justify-between gap-3"><div><h2 id="explanation-title" className="text-xl font-bold">Recorded Alert Explanation</h2><p className="mt-1 text-xs text-text-muted">{sourceLabel(alert.data_source)} · {formatTime(alert.timestamp)}</p></div><button ref={closeButton} aria-label="Close explanation" onClick={onClose} className="rounded-lg border border-border px-3 py-1">Close</button></div>
      <div className="my-5 grid grid-cols-2 gap-3 text-sm"><div><p className="text-xs text-text-muted">Alert label</p>{alert.attack_type}</div><div><p className="text-xs text-text-muted">Prediction confidence</p>{percent(alert.confidence)}</div><div className="break-all"><p className="text-xs text-text-muted">Source</p>{alert.source_ip}</div><div className="break-all"><p className="text-xs text-text-muted">Destination</p>{alert.dest_ip}</div></div>
      <p className={`mb-5 rounded-lg border p-3 text-xs ${threatLevelTone(alert.threat_level)}`}>{alert.threat_level} — confidence-based alert category. Confidence is a model score, not measured detection accuracy.</p>
      {alert.attack_type_source === 'dataset_label' && <p className="mb-4 text-xs text-text-muted">The attack name comes from the replay dataset. The classifier's prediction is binary.</p>}
      <section className="mb-6"><h3 className="font-semibold">{shap.length ? title : 'Feature explanation unavailable'}</h3>
        {method === 'global_rf_importance' && <p className="my-2 text-xs text-text-muted">Overall feature importance in the RF model. These values are not per-flow SHAP and do not indicate an attack direction.</p>}
        {method === 'reference_sample_shap' && <p className="my-2 text-xs text-text-muted">A nearby stored sample was selected (index {meta.reference_index}). This is a reference explanation, not SHAP calculated for this flow. The artifact's model identity is unverified.</p>}
        {shap.length > 0 && !method && <p className="my-2 text-xs text-text-muted">This older record does not identify its explanation method. No class direction can be established.</p>}
        {shap.length > 0 ? <Features values={shap} signed={false} target="unknown" /> : <p className="mt-2 text-sm text-text-muted">No feature explanation was saved with this alert.</p>}
      </section>
      <section className="mb-6"><h3 className="font-semibold">{limeVerified ? 'Local LIME Explanation of the RF' : 'LIME Explanation'}</h3>
        {limeVerified && <p className="my-2 text-xs text-text-muted">Explains the Random Forest's {meta.lime_target_class === 1 ? 'attack' : 'benign'} class. It does not explain the CNN or the fused hybrid output.</p>}
        {!limeVerified && lime.length > 0 && <p className="my-2 text-xs text-text-muted">The explained model and target class were not recorded for these legacy values.</p>}
        {lime.length ? <Features values={lime} signed={limeVerified} target={meta.lime_target_class === 1 ? 'attack' : 'benign'} /> : <p className="mt-2 text-sm text-text-muted">No local LIME explanation was saved.</p>}
      </section>
      <section className="mb-5"><h3 className="font-semibold">RIPPER Reference Rules</h3><p className="my-2 text-xs text-text-muted">Stored rules for reference. No rule match was evaluated for this alert.</p>
        {rules.error ? <p className="text-xs text-amber-600">Rules unavailable: {rules.error}</p> : <pre className="max-h-36 overflow-auto whitespace-pre-wrap rounded-lg bg-background-soft p-3 text-xs">{rules.data?.rules || 'No stored rules available.'}</pre>}
      </section>
      <p className="border-t border-border pt-3 text-xs text-text-muted">Recorded model: {alert.model_type || 'Unknown'} · Mode: {alert.execution_mode || 'Unknown'} · Alert ID: {alert.id}</p>
    </div>
  </div>
}
