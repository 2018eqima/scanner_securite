import { useEffect, useRef, useState } from 'react'
import keycloak from '../auth/keycloak'
import { ScanEvent } from '../types'

const BASE = import.meta.env.VITE_API_URL || 'https://api-scanner.eqima.org'

export function useScanEvents(sessionId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [done, setDone]     = useState(false)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!sessionId) return

    const url = `${BASE}/v1/scans/${sessionId}/events?token=${keycloak.token}`
    const es = new EventSource(url)
    esRef.current = es

    es.onmessage = (e) => {
      const event: ScanEvent = JSON.parse(e.data)
      setEvents(prev => [...prev, event])
      if (event.type === 'COMPLETED' || event.type === 'ERROR') {
        setDone(true)
        es.close()
      }
    }

    es.onerror = () => {
      setDone(true)
      es.close()
    }

    return () => {
      es.close()
      esRef.current = null
    }
  }, [sessionId])

  return { events, done }
}