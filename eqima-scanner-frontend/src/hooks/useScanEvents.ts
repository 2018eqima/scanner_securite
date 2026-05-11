import { useEffect, useRef, useState } from 'react'
import keycloak from '../auth/keycloak'
import { ScanEvent } from '../types'

const BASE = import.meta.env.VITE_API_URL || 'https://preprod.api.scanner.eqima.org'
const RECONNECT_DELAY_MS = 3000

export function useScanEvents(sessionId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [done, setDone]     = useState(false)
  const esRef       = useRef<EventSource | null>(null)
  const doneRef     = useRef(false)
  const retryTimer  = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!sessionId) return
    doneRef.current = false
    setDone(false)
    setEvents([])

    function connect() {
      if (doneRef.current) return
      // Toujours utiliser le token courant (auto-refresh Keycloak)
      keycloak.updateToken(30).catch(() => {})
      const url = `${BASE}/v1/scans/${sessionId}/events?token=${keycloak.token}`
      const es = new EventSource(url)
      esRef.current = es

      es.onmessage = (e) => {
        const event: ScanEvent = JSON.parse(e.data)
        setEvents(prev => [...prev, event])
        if (event.type === 'COMPLETED' || event.type === 'ERROR') {
          doneRef.current = true
          setDone(true)
          es.close()
        }
      }

      es.onerror = () => {
        es.close()
        // Si le scan n'est pas terminé, on reconnecte après un délai
        if (!doneRef.current) {
          retryTimer.current = setTimeout(connect, RECONNECT_DELAY_MS)
        }
      }
    }

    connect()

    return () => {
      doneRef.current = true
      esRef.current?.close()
      if (retryTimer.current) clearTimeout(retryTimer.current)
    }
  }, [sessionId])

  return { events, done }
}