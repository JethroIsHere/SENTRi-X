import { createContext, useContext, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { api, useApiPoll } from '../lib/api'
import type { Domain, Mode, SystemStatus } from '../lib/api'

interface SystemContextValue {
  status: SystemStatus | null; online: boolean; error: string | null; updated: number
  rates: number[]; busy: boolean; actionError: string | null; refresh: () => void
  switchEngine: (domain: Domain, mode: Mode) => Promise<void>
}
const Context = createContext<SystemContextValue | null>(null)

export function SystemProvider({ children }: { children: ReactNode }) {
  const poll = useApiPoll<SystemStatus>('/api/status', 2000)
  const [rates, setRates] = useState<number[]>([])
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const previous = useRef<{ count: number; time: number; epoch: string } | null>(null)
  const online = !!poll.data && !poll.error
  useEffect(() => {
    if (!online || !poll.data?.is_hardware_live) {
      previous.current = null
      setRates([])
      return
    }
    const sample = { count: poll.data.processed_flows, time: performance.now(), epoch: poll.data.counter_epoch }
    const old = previous.current
    if (old && old.epoch === sample.epoch && sample.count >= old.count && sample.time > old.time) {
      const rate = (sample.count - old.count) / ((sample.time - old.time) / 1000)
      setRates(values => [...values.slice(-9), rate])
    } else setRates([])
    previous.current = sample
  }, [poll.updated, poll.data, online])
  async function switchEngine(domain: Domain, mode: Mode) {
    if (busy || !online) return
    setBusy(true)
    setActionError(null)
    try {
      await api('/api/switch', { method: 'POST', body: JSON.stringify({ model_type: domain, dataset: domain, mode }) })
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Model change failed.')
    } finally {
      poll.refresh()
      setBusy(false)
    }
  }
  return <Context.Provider value={{ status: poll.data, online, error: poll.error, updated: poll.updated,
    rates, busy, actionError, refresh: poll.refresh, switchEngine }}>{children}</Context.Provider>
}

export function useSystem() {
  const context = useContext(Context)
  if (!context) throw new Error('The page must be rendered inside AppShell.')
  return context
}
