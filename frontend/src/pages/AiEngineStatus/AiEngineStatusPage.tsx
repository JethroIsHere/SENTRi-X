import { useSystem } from '../../context/SystemContext'
import { formatTime, useApiPoll } from '../../lib/api'
import type { Benchmark } from '../../lib/api'
import { panelClass, RequestState } from '../../components/LiveTelemetry'

export function AiEngineStatusPage() {
  const { status, online } = useSystem()
  const benchmark = useApiPoll<Benchmark>(`/api/model-metrics?selection=${status?.current_model || ''}:${status?.execution_mode || ''}`, 10000)
  const validBenchmark = online && benchmark.data?.available && benchmark.data.model === status?.current_model && benchmark.data.mode === status?.execution_mode && !benchmark.error
  const memory = online && status?.memory_total_bytes != null && status.memory_used_bytes != null
    ? `${(status.memory_used_bytes / 1024 ** 3).toFixed(2)} / ${(status.memory_total_bytes / 1024 ** 3).toFixed(2)} GiB` : 'Unavailable'
  return <div className="space-y-6 max-w-6xl">
    <header><h1 className="text-3xl font-bold">AI Engine Status</h1><p className="mt-2 text-sm text-text-muted">Backend resources, active models, and documented offline evaluation results.</p></header>
    <section className={panelClass}><h2 className="text-xl font-semibold">{online ? status?.core_model : 'Backend status unavailable'}</h2><p className="mt-2 text-sm text-text-muted">Mode: {online ? status?.execution_mode : 'Unknown'} · {online ? status?.node_status ?? (status?.is_hardware_live ? 'Pi connected' : 'Waiting for Pi') : 'Connection unavailable'}</p>
      {online && status?.engine_error && <RequestState error={`Inference issue: ${status.engine_error}`} />}
    </section>
    <div className="grid gap-5 md:grid-cols-2"><section className={panelClass}><h2 className="mb-4 text-lg font-semibold">Backend Host Resources</h2>
      <p className="text-sm">CPU usage: <strong>{online && status?.cpu_usage != null ? `${status.cpu_usage.toFixed(1)}%` : 'Unavailable'}</strong></p>
      <p className="mt-3 text-sm">Memory usage: <strong>{online && status?.memory_usage != null ? `${status.memory_usage.toFixed(1)}%` : 'Unavailable'}</strong></p>
      <p className="mt-2 text-sm">Used / total memory: {memory}</p><p className="mt-2 text-sm">Logical CPU count: {online ? status?.cpu_count ?? 'Unavailable' : 'Unavailable'}</p>
      <p className="mt-4 text-xs text-text-muted">These measurements come from the backend runtime, including its WSL or container environment when applicable. Pi resource telemetry is not collected.</p>
      {status?.resource_error && <RequestState error="Host resource telemetry is unavailable." />}
    </section><section className={panelClass}><h2 className="mb-4 text-lg font-semibold">Models & Sensor Connection</h2>
      <p className="text-sm">Random Forest: {online ? status?.rf_online ? 'Loaded and enabled' : 'Inactive or unavailable' : 'Unknown'}</p>
      <p className="mt-3 text-sm">1D CNN: {online ? status?.cnn_online ? 'Loaded and enabled' : 'Inactive or unavailable' : 'Unknown'}</p>
      <p className="mt-3 text-sm">Pi connection: {online ? status?.is_hardware_live ? 'Recent heartbeat or flow received' : 'No recent heartbeat' : 'Unknown'}</p>
      <p className="mt-3 text-xs text-text-muted">Last contact: {formatTime(status?.last_heartbeat_at)}</p><p className="mt-2 text-xs text-text-muted">Last live flow: {formatTime(status?.last_flow_at)}</p>
      <p className="mt-3 text-xs text-text-muted">Loaded models and received heartbeats are availability signals. Detection quality requires labelled evaluation.</p>
    </section></div>
    <section className={panelClass}><h2 className="mb-3 text-lg font-semibold">Offline Evaluation Metrics</h2><RequestState error={benchmark.error} loading={benchmark.loading} />
      {validBenchmark ? <><p className="mb-4 text-xs text-text-muted">Dataset: {benchmark.data?.dataset} · Split: {benchmark.data?.evaluation_split} · Source: {benchmark.data?.source}</p>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">{['accuracy', 'precision', 'recall', 'f1', 'roc_auc'].map(key => <div key={key} className="rounded-lg bg-background-soft p-3"><p className="text-xs uppercase text-text-muted">{key.replace(/_/g, ' ')}</p><p className="mt-2 font-bold">{benchmark.data?.metrics?.[key] == null ? 'Unavailable' : `${(benchmark.data.metrics[key] * 100).toFixed(2)}%`}</p></div>)}</div>
      </> : <p className="text-sm text-text-muted">No documented evaluation result is available for the current model and mode. Live prediction confidence is not an accuracy measurement.</p>}
    </section>
  </div>
}
