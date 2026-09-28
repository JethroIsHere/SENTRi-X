import { useCallback, useEffect, useState } from 'react'

export const API_BASE_URL = (import.meta.env?.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
export type Source = 'live_hardware' | 'simulation' | 'unknown'
export type Mode = 'hybrid' | 'rf' | 'cnn'
export type Domain = 'omni' | 'ton_iot' | 'bot_iot' | 'cic_ids2017'
export const DOMAINS: { id: Domain; name: string }[] = [
  { id: 'omni', name: 'Omni (combined datasets)' }, { id: 'ton_iot', name: 'ToN-IoT' },
  { id: 'bot_iot', name: 'BoT-IoT' }, { id: 'cic_ids2017', name: 'CIC-IDS2017' },
]
export const MODES: { id: Mode; name: string }[] = [
  { id: 'hybrid', name: 'Hybrid (RF + CNN)' }, { id: 'rf', name: 'RF only' }, { id: 'cnn', name: '1D CNN only' },
]
export interface Settings { active_alerting: boolean; alert_threshold: number }
export interface SystemStatus {
  api_version: number; node_status: string; core_model: string; current_model: Domain; current_dataset: string
  execution_mode: Mode; data_source: Source; is_hardware_live: boolean; simulation_active: boolean
  processed_flows: number; simulated_events: number; inference_errors: number; counter_epoch: string
  threats_detected: number; alert_counts: Record<Source, number>; rf_online: boolean; cnn_online: boolean
  cpu_usage: number | null; memory_usage: number | null; memory_total_bytes: number | null
  memory_used_bytes: number | null; cpu_count: number | null; resource_error: string | null
  settings: Settings; classification_threshold: number; engine_error: string | null; ingest_error: string | null; switching: boolean
  last_flow_at: string | null; last_heartbeat_at: string | null; started_at: string
}
export interface Feature { f: string; v: number }
export interface Alert {
  id: string; timestamp: string; source_ip: string; dest_ip: string; attack_type: string
  confidence: number; threat_level: 'Critical' | 'High' | 'Medium' | 'Low'; status: string
  model_type: string; execution_mode: string; data_source: Source; device_name?: string | null
  sensor_id?: string | null; device_mac?: string | null; flow_id?: number | null
  attack_type_source?: string; shap_values?: Feature[]; lime_values?: Feature[]
  explanation_meta?: { shap_method?: string; shap_model?: string; shap_target_class?: number | null
    reference_index?: number; lime_method?: string; lime_model?: string; lime_target_class?: number | null }
}
export interface Flow {
  id: number; timestamp: string; sensor_id: string; device_name: string | null; device_mac: string | null
  src_ip: string; dst_ip: string; src_port: number | null; dst_port: number | null; proto: string
  duration: number; src_pkts: number; dst_pkts: number; src_bytes: number; dst_bytes: number
  prediction: number | null; confidence: number | null; p_rf: number | null; p_cnn: number | null
  is_anomaly: number; model_used: string; execution_mode: string; data_source: Source; inference_error: string | null
}
export interface Device {
  device_name: string | null; device_mac: string; sensor_id: string; last_ip: string
  last_seen: string; flow_count: number; packet_count: number
}
export interface Benchmark {
  available: boolean; model?: string; mode?: string; dataset?: string; evaluation_split?: string
  source?: string; metrics?: Record<string, number>
}
export const sourceLabel = (source?: string) => source === 'live_hardware' ? 'Live hardware' : source === 'simulation' ? 'Simulation' : 'Origin unknown'
export const percent = (value: number | null | undefined) => value == null ? 'Unavailable' : `${(value * 100).toFixed(1)}%`
export const formatTime = (value?: string | null) => {
  if (!value) return 'Not observed'
  if (!/(Z|[+-]\d\d:\d\d)$/.test(value)) return `${value} (legacy time)`
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const controller = new AbortController()
  const cancel = () => controller.abort()
  options.signal?.addEventListener('abort', cancel, { once: true })
  if (options.signal?.aborted) controller.abort()
  const timer = setTimeout(cancel, options.method && options.method !== 'GET' ? 60000 : 8000)
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
      signal: controller.signal,
    })
    const body = await response.json().catch(() => null)
    if (!response.ok) {
      const detail = typeof body?.detail === 'string' ? body.detail : `Request failed (HTTP ${response.status}).`
      throw new Error(detail)
    }
    if (body === null) throw new Error('The backend returned an invalid response.')
    if (path === '/api/status' && body.api_version !== 2) {
      throw new Error('Backend update required. Replace backend/main.py and database.py, then restart the backend.')
    }
    return body as T
  } catch (error) {
    if (controller.signal.aborted && !options.signal?.aborted) {
      throw new Error(options.method && options.method !== 'GET'
        ? 'Request timed out; the change is unconfirmed. Refresh before trying again.'
        : 'The backend did not respond in time.')
    }
    throw error
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener('abort', cancel)
  }
}

export function useApiPoll<T>(path: string, interval = 2500) {
  const [state, setState] = useState<{ data: T | null; error: string | null; updated: number }>({ data: null, error: null, updated: 0 })
  const [revision, setRevision] = useState(0)
  const refresh = useCallback(() => setRevision(value => value + 1), [])
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const controller = new AbortController()
    async function poll() {
      try {
        const data = await api<T>(path, { signal: controller.signal })
        if (!cancelled) setState({ data, error: null, updated: Date.now() })
      } catch (error) {
        if (!cancelled) setState(previous => ({ ...previous, error: error instanceof Error ? error.message : 'Backend unavailable.' }))
      } finally {
        if (!cancelled && interval > 0) timer = setTimeout(poll, interval)
      }
    }
    void poll()
    return () => { cancelled = true; controller.abort(); clearTimeout(timer) }
  }, [path, interval, revision])
  return { ...state, refresh, loading: state.data === null && state.error === null }
}
